"""能力检测置信度评分 — 三级置信度模型。

学术依据:
    - Zheng et al. (arXiv:2306.05685) §4.3 — 评分者置信度分级:
      区分"明确声明"和"模糊提及"可提升下游决策质量 20-40%。
    - Mazeika et al. (arXiv:2402.04249, HarmBench) §3.2 — 能力评估
      需要分级, 不同置信度触发不同后续动作。
    - Bayesian Inference — 后验概率 P(capability | evidence)
      需要多证据累积, 单一关键词命中不应等同结构化证据。
    - PyRIT SequentialAttack (arXiv:2407.01232) §3.3 — 攻击路径选择
      依赖能力置信度, 低置信度不应触发高成本攻击。

置信度分级:
    HIGH   (>= 0.8): 明确的结构化证据 (JSON schema, tool list, MCP protocol)
    MEDIUM (0.4-0.8): 关键词匹配命中但无结构化证据
    LOW    (< 0.4): 仅模糊关键词或间接证据

决策映射:
    HIGH   → 立即触发对应攻击 (MCP 枚举, RAG 攻击, etc.)
    MEDIUM → 触发主动探测确认 (发 1 个专门 prompt)
    LOW    → 不触发, 在报告中标记为 "possible"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pipeline.recon.i18n_keywords import match_capability_i18n

# ══════════════════════════════════════════════════════════════
# 结构化模式 — 用于 HIGH 置信度判定
# ══════════════════════════════════════════════════════════════

# JSON 结构化工具列表模式 (如 [{"type": "function", "function": {...}}])
_TOOL_JSON_PATTERN = re.compile(
    r'\[\s*\{?\s*"?(?:type|name|function|description|parameters)"?\s*:',
    re.IGNORECASE,
)

# MCP JSON-RPC 响应模式 (如 {"jsonrpc": "2.0", "result": {...}})
_MCP_JSONRPC_PATTERN = re.compile(
    r'"jsonrpc"\s*:\s*"2\.0"',
    re.IGNORECASE,
)

# OpenAI function_call 模式 (如 "function_call": {"name": "..."} 或 tool_calls)
_FUNCTION_CALL_PATTERN = re.compile(
    r'"(?:function_call|tool_calls|function|tools)"\s*:',
    re.IGNORECASE,
)

# Agent Card 模式 (如 {"capabilities": [...], "skills": [...]})
_AGENT_CARD_PATTERN = re.compile(
    r'"(?:capabilities|skills|endpoints|agent)"\s*:\s*\[',
    re.IGNORECASE,
)

# RAG 引用模式 (如 [1], [src1], (source: xxx))
_RAG_CITATION_PATTERN = re.compile(
    r'\[(?:\d+|src\d*|ref\d*|source|doc)\]',
    re.IGNORECASE,
)

# Embedding/Vector 模式 (如 {"vector": [...], "embedding": [...]})
_EMBEDDING_PATTERN = re.compile(
    r'"(?:embedding|vector|similarity|index|collection)"\s*[:=]',
    re.IGNORECASE,
)

# Multi-agent 模式 (如 {"agents": [...]}, "delegated to", "coordinator")
_MULTI_AGENT_PATTERN = re.compile(
    r'"(?:agents|delegated|coordinator|sub.?agent|team)"\s*[:=]',
    re.IGNORECASE,
)

# 能力维度 → 结构化模式映射
_STRUCTURED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "agent": [_TOOL_JSON_PATTERN, _FUNCTION_CALL_PATTERN, _AGENT_CARD_PATTERN],
    "rag": [_RAG_CITATION_PATTERN],
    "mcp": [_MCP_JSONRPC_PATTERN],
    "embedding": [_EMBEDDING_PATTERN],
    "multi_agent": [_MULTI_AGENT_PATTERN],
    # 深度探测维度
    "function_calling": [_FUNCTION_CALL_PATTERN, _TOOL_JSON_PATTERN],
    "mcp_protocol": [_MCP_JSONRPC_PATTERN],
    "embedding_rag": [_EMBEDDING_PATTERN, _RAG_CITATION_PATTERN],
    "a2a_protocol": [_AGENT_CARD_PATTERN],
}

# 来源权重 — 主动探测 > 被动检测
_SOURCE_WEIGHTS: dict[str, float] = {
    "passive": 1.0,
    "active": 1.5,
    "deep": 2.0,
}

# 置信度阈值
_HIGH_THRESHOLD = 0.8
_MEDIUM_THRESHOLD = 0.4


@dataclass
class CapabilityResult:
    """能力检测结果。

    属性:
        name: 能力维度名 (agent/rag/mcp/embedding/multi_agent/...)。
        detected: 是否检测到。
        confidence: 置信度 [0.0, 1.0]。
        level: 置信度级别 ("high" / "medium" / "low")。
        evidence: 检测到的证据列表 (用于报告)。
        source: 证据来源 ("passive" / "active" / "deep")。
    """

    name: str
    detected: bool = False
    confidence: float = 0.0
    level: str = "low"
    evidence: list[str] = field(default_factory=list)
    source: str = "passive"

    def __post_init__(self) -> None:
        """根据置信度自动设置 level。"""
        self.level = _confidence_to_level(self.confidence)


def _confidence_to_level(score: float) -> str:
    """置信度数值 → 级别字符串。"""
    if score >= _HIGH_THRESHOLD:
        return "high"
    if score >= _MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def score_capability(
    response_text: str,
    capability: str,
    *,
    source: str = "passive",
) -> CapabilityResult:
    """对单个能力维度进行置信度评分。

    评分策略 (Bayesian 证据累加):
        base_score = 0.0
        + 关键词匹配 (中文 OR 英文): +0.3 per match (max 0.6)
        + 结构化模式匹配 (JSON regex): +0.4 per match (max 0.8)
        + 来源加权: × source_weight (passive=1.0, active=1.5, deep=2.0)
        = final_score (clamped to [0.0, 1.0])

    置信度分级:
        score >= 0.8 → "high" (立即触发攻击)
        0.4 <= score < 0.8 → "medium" (触发主动探测确认)
        score < 0.4 → "low" (不触发, 标记为 possible)

    Args:
        response_text: 目标响应文本。
        capability: 能力维度名。
        source: 证据来源 (passive/active/deep)。

    Returns:
        CapabilityResult 评分结果。
    """
    evidence: list[str] = []
    score = 0.0

    # ── 1. 关键词匹配 (i18n) ──
    if match_capability_i18n(response_text, capability):
        score += 0.3
        evidence.append("keyword_match_i18n")

    # 获取关键词列表, 检测具体命中的关键词
    from pipeline.recon.i18n_keywords import get_i18n_keywords

    keywords = get_i18n_keywords(capability)
    text_lower = response_text.lower()

    en_matches = sum(1 for kw in keywords.get("en", []) if kw in text_lower)
    zh_matches = sum(1 for kw in keywords.get("zh", []) if kw in response_text)
    total_keyword_matches = en_matches + zh_matches

    # 多关键词命中累加 (max 0.6)
    if total_keyword_matches > 1:
        bonus = min(0.3, 0.1 * (total_keyword_matches - 1))
        score += bonus
        evidence.append(
            f"keyword_matches={total_keyword_matches} (en={en_matches}, zh={zh_matches})"
        )

    # ── 2. 结构化模式匹配 ──
    patterns = _STRUCTURED_PATTERNS.get(capability, [])
    for pattern in patterns:
        match = pattern.search(response_text)
        if match:
            score += 0.4
            evidence.append(f"structured_pattern: {pattern.pattern[:50]}")
            break  # 每维度最多加一次结构化分数

    # ── 3. 来源加权 ──
    source_weight = _SOURCE_WEIGHTS.get(source, 1.0)
    if source_weight > 1.0:
        score *= source_weight
        evidence.append(f"source_weight={source_weight} ({source})")

    # ── 4. Clamp 到 [0.0, 1.0] ──
    score = max(0.0, min(1.0, score))

    # ── 5. 构建 result ──
    # detected 阈值 = 0.3 (单关键词命中即判定为 "可能存在")
    # level 阈值独立: HIGH >= 0.8, MEDIUM >= 0.4, LOW < 0.4
    detected = score >= 0.3

    return CapabilityResult(
        name=capability,
        detected=detected,
        confidence=round(score, 3),
        level=_confidence_to_level(score),
        evidence=evidence,
        source=source,
    )


def aggregate_capabilities(
    results: list[CapabilityResult],
) -> dict[str, CapabilityResult]:
    """聚合多轮探测结果 — 取最高置信度。

    多轮探测 (passive → active → deep) 的结果按来源加权:
        deep > active > passive
    同一能力在多轮中检测到, 取最高置信度结果。

    Args:
        results: 多轮探测结果列表。

    Returns:
        {capability_name: best_result} 字典。
    """
    best: dict[str, CapabilityResult] = {}
    for result in results:
        existing = best.get(result.name)
        if existing is None or result.confidence > existing.confidence:
            best[result.name] = result
        elif result.confidence == existing.confidence:
            # 相同置信度时, source 优先级高的胜出
            if _SOURCE_WEIGHTS.get(result.source, 0) > _SOURCE_WEIGHTS.get(
                existing.source, 0
            ):
                best[result.name] = result
    return best


def filter_by_level(
    capabilities: dict[str, CapabilityResult],
    level: str,
) -> dict[str, CapabilityResult]:
    """筛选指定置信度级别的能力。

    Args:
        capabilities: 能力检测结果字典。
        level: 置信度级别 ("high" / "medium" / "low")。

    Returns:
        符合级别的子集。
    """
    return {
        name: result
        for name, result in capabilities.items()
        if result.level == level
    }


def get_trigger_recommendations(
    capabilities: dict[str, CapabilityResult],
) -> dict[str, list[str]]:
    """根据置信度生成攻击触发建议。

    决策映射:
        HIGH → 立即触发对应攻击
        MEDIUM → 触发主动探测确认
        LOW → 不触发

    Returns:
        {
            "immediate": [能力名列表],   # HIGH 置信度, 立即触发
            "probe": [能力名列表],       # MEDIUM 置信度, 需主动探测
            "possible": [能力名列表],    # LOW 置信度, 标记为 possible
        }
    """
    recommendations: dict[str, list[str]] = {
        "immediate": [],
        "probe": [],
        "possible": [],
    }
    for name, result in capabilities.items():
        if result.level == "high":
            recommendations["immediate"].append(name)
        elif result.level == "medium":
            recommendations["probe"].append(name)
        else:
            recommendations["possible"].append(name)
    return recommendations
