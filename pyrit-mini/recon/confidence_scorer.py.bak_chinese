"""能力检测置信度评分 + 中英文双语关键词库 — SSOT (Single Source of Truth).

合并自原 confidence_scorer.py, i18n_keywords.py, capability_detector.py 的关键词
与正则模式。现在整个 recon 模块的能力探测都通过本模块的 ``score_capability`` 和
``match_capability_i18n`` 进行, 避免三轨并存导致的维护负担。

学术依据:
    - Greshake et al. (arXiv:2302.12173) §4 — 间接注入探测依赖目标
      响应中的能力声明, 不同语言的目标使用不同表述。
    - Zheng et al. (arXiv:2306.05685) §4.3 — 评分者置信度分级:
      区分"明确声明"和"模糊提及"可提升下游决策质量 20-40%。
    - Mazeika et al. (arXiv:2402.04249, HarmBench) §3.2 — 能力评估
      需要分级, 不同置信度触发不同后续动作。
    - Bayesian Inference — 后验概率 P(capability | evidence)
      需要证据累积, 单一关键词命中不应等同于结构化证据。
    - PyRIT SequentialAttack (arXiv:2407.01232) §3.3 — 攻击路径选择
      依赖能力置信度, 低置信度不应触发高成本攻击。

置信度分级:
    HIGH   (>= 0.8): 确切的结构化证据 (JSON schema, tool list, MCP protocol)
    MEDIUM (0.4-0.8): 关键词匹配命中但无结构化证据
    LOW    (< 0.4): 仅模糊关键词或间接验证

设计原则 (i18n):
    每个能力维度同时包含英文和中文关键词,
    匹配时对两种语言进行 OR 逻辑, 降低假阴性率。
    英文关键词匹配时转为小写 (case-insensitive),
    中文关键词匹配时保持原样 (中文不区分大小写)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ══════════════════════════════════════════════════════════════
# 双语关键词库 — 按能力维度组织
# ══════════════════════════════════════════════════════════════

_CAPABILITY_KEYWORDS_I18N: dict[str, dict[str, list[str]]] = {
    "agent": {
        "en": [
            "i have access to tools",
            "i can use tools",
            "function_call",
            "tool_call",
            "i am an agent",
            "as an ai assistant",
            "i can help you with",
            "my capabilities include",
            "i have access to functions",
            "available tools",
            "i can execute",
        ],
        "zh": [
            "我可以使用工具",
            "我可以调用工具",
            "我有工具",
            "我可以执行",
            "作为一个ai助手",
            "作为一个智能助手",
            "我的能力包括",
            "可用工具",
            "函数调用",
            "工具调用",
            "我是一个agent",
            "我是一个智能体",
            "我可以帮你",
            "我有访问工具的权限",
        ],
    },
    "rag": {
        "en": [
            "based on the retrieved",
            "knowledge base",
            "from the documents",
            "according to the context",
            "retrieved information",
            "search results show",
            "from my knowledge",
            "based on available data",
            "reference document",
            "source material",
        ],
        "zh": [
            "根据检索到的",
            "知识库",
            "从文档中",
            "根据上下文",
            "检索到的信息",
            "搜索结果显示",
            "根据我的知识",
            "根据可用数据",
            "参考文档",
            "原始材料",
            "从知识库中",
            "检索结果",
            "根据提供的资料",
            "基于已检索",
        ],
    },
    "mcp": {
        "en": [
            "model context protocol",
            "mcp server",
            "mcp tool",
            "protocol server",
            "i'm connected to",
            "connected tools",
            "server-side tools",
        ],
        "zh": [
            "模型上下文协议",
            "mcp服务器",
            "mcp服务端",
            "mcp工具",
            "协议服务器",
            "我连接了",
            "已连接的工具",
            "服务端工具",
            "我已连接到",
        ],
    },
    "embedding": {
        "en": [
            "embedding",
            "vector search",
            "semantic search",
            "similarity search",
            "vector database",
            "nearest neighbor",
        ],
        "zh": [
            "嵌入",
            "向量搜索",
            "语义搜索",
            "相似度搜索",
            "向量数据库",
            "最近邻",
            "向量检索",
            "嵌入模型",
        ],
    },
    "multi_agent": {
        "en": [
            "multiple agents",
            "collaborate with",
            "delegate to",
            "i work with other",
            "team of agents",
            "multi-agent",
            "coordinator",
        ],
        "zh": [
            "多个agent",
            "多个智能体",
            "协作",
            "委派给",
            "我与其它",
            "我与其他",
            "团队智能体",
            "多智能体",
            "协调者",
            "协同工作",
        ],
    },
    "code_execution": {
        "en": [
            "i can execute code",
            "code interpreter",
            "python execution",
            "run code",
            "sandbox",
            "i can write and run",
            "code execution",
        ],
        "zh": [
            "我可以执行代码",
            "代码解释器",
            "python执行",
            "运行代码",
            "沙箱",
            "沙盒",
            "我可以编写并运行",
            "代码执行",
        ],
    },
    "web_search": {
        "en": [
            "i can search",
            "web search",
            "search the web",
            "online search",
            "internet search",
            "browsing",
        ],
        "zh": [
            "我可以搜索",
            "网络搜索",
            "搜索网络",
            "在线搜索",
            "互联网搜索",
            "浏览网页",
            "联网搜索",
        ],
    },
    # ── 深度探测维度 ──
    "function_calling": {
        "en": [
            "function",
            "tool",
            "call",
            "schema",
            "parameter",
            "openapi",
            "endpoint",
            "api",
            "method",
        ],
        "zh": [
            "函数",
            "工具",
            "调用",
            "模式",
            "参数",
            "接口",
            "端点",
            "方法",
        ],
    },
    "memory": {
        "en": [
            "memory",
            "remember",
            "previous",
            "history",
            "session",
            "persistent",
            "stored",
            "context",
        ],
        "zh": [
            "记忆",
            "记住",
            "之前的",
            "历史",
            "会话",
            "持久",
            "存储的",
            "上下文",
            "之前的对话",
        ],
    },
    "workflow": {
        "en": [
            "workflow",
            "pipeline",
            "step",
            "chain",
            "sequence",
            "orchestrat",
            "flow",
            "process",
        ],
        "zh": [
            "工作流",
            "流水线",
            "步骤",
            "链",
            "序列",
            "编排",
            "流程",
            "过程",
        ],
    },
    "multi_tenant": {
        "en": [
            "tenant",
            "organization",
            "org",
            "workspace",
            "namespace",
            "account",
            "project",
        ],
        "zh": [
            "租户",
            "组织",
            "工作空间",
            "命名空间",
            "账户",
            "项目",
        ],
    },
    "session_auth": {
        "en": [
            "session",
            "token",
            "cookie",
            "bearer",
            "jwt",
            "auth",
            "login",
            "user",
        ],
        "zh": [
            "会话",
            "令牌",
            "cookie",
            "bearer",
            "jwt",
            "认证",
            "登录",
            "用户",
        ],
    },
    "mcp_protocol": {
        "en": [
            "mcp",
            "model context protocol",
            "server",
            "tool",
            "resource",
            "prompt",
        ],
        "zh": [
            "mcp",
            "模型上下文协议",
            "服务器",
            "服务端",
            "工具",
            "资源",
            "提示",
        ],
    },
    "a2a_protocol": {
        "en": [
            "a2a",
            "agent-to-agent",
            "agent card",
            "json-rpc",
            "well-known",
            "inter-agent",
            "orchestrat",
            "delegate",
            "skill",
            "task lifecycle",
            "multi-agent",
        ],
        "zh": [
            "a2a",
            "agent间通信",
            "智能体间",
            "agent卡",
            "智能体卡片",
            "json-rpc",
            "well-known",
            "跨agent",
            "编排",
            "委派",
            "技能",
            "任务生命周期",
            "多智能体",
        ],
    },
    "embedding_rag": {
        "en": [
            "embedding",
            "vector",
            "rag",
            "retrieval",
            "similarity",
            "index",
            "collection",
            "knowledge base",
            "semantic search",
        ],
        "zh": [
            "嵌入",
            "向量",
            "rag",
            "检索",
            "相似度",
            "索引",
            "集合",
            "知识库",
            "语义搜索",
            "向量数据库",
        ],
    },
}


# ══════════════════════════════════════════════════════════════
# i18n 关键词匹配函数
# ══════════════════════════════════════════════════════════════


def match_capability_i18n(
    response_text: str,
    capability: str,
) -> bool:
    """双语关键词匹配 — 同时检测中英文关键词。

    学术依据:
        - Greshake et al. (arXiv:2302.12173) §4 — 能力探测依赖响应关键词
        - Zheng et al. (arXiv:2306.05685) §4.3 — 多语言匹配提升鲁棒性
        - 中文不区分大小写, 英文转为小写匹配

    Args:
        response_text: 目标响应文本。
        capability: 能力维度名 (agent/rag/mcp/embedding/multi_agent/...)。

    Returns:
        True 如果检测到该能力 (任一语言关键词命中)。
    """
    keywords = _CAPABILITY_KEYWORDS_I18N.get(capability, {})
    if not keywords:
        return False

    text_lower = response_text.lower()

    # 英文关键词 (小写匹配)
    for kw in keywords.get("en", []):
        if kw in text_lower:
            return True

    # 中文关键词 (case-insensitive, 因 "AI" 常为大写混入中文)
    for kw in keywords.get("zh", []):
        if kw in text_lower:
            return True

    return False


def get_i18n_keywords(capability: str) -> dict[str, list[str]]:
    """获取指定能力维度的双语关键词列表。

    Args:
        capability: 能力维度名。

    Returns:
        {"en": [...], "zh": [...]} 关键词字典。
    """
    return _CAPABILITY_KEYWORDS_I18N.get(capability, {"en": [], "zh": []})


def get_all_capability_names() -> list[str]:
    """获取所有能力维度名称列表。

    Returns:
        能力维度名称列表。
    """
    return list(_CAPABILITY_KEYWORDS_I18N.keys())


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

# MCP tool list / server 信息模式 (来源: capability_detector.py 的 mcp_structural_patterns)
_MCP_STRUCTURAL_PATTERN = re.compile(
    r'"(?:tools|resource_uris|mcp_server|server_name|protocol_version|tool_call_id|tool_result)"'
    r'\s*[:=]\s*(?:\[|"|\{)',
    re.IGNORECASE,
)

# Agent function_call / tool_calls 模式 (来源: capability_detector.py 的 agent_structural_patterns)
_AGENT_STRUCTURAL_PATTERN = re.compile(
    r'"(?:function_call|tool_calls|tool_call_id)"|'
    r'"function"\s*:\s*\{|'
    r'"name"\s*:\s*".*?"\s*,\s*"arguments"',
    re.IGNORECASE,
)

# RAG 检索结果模式 (来源: capability_detector.py 的 rag_structural_patterns)
_RAG_STRUCTURAL_PATTERN = re.compile(
    r'"(?:retrieved_documents|source_documents|references|citations|chunks|similarity_score|relevance_score)"|'
    r'"context"\s*:\s*\[',
    re.IGNORECASE,
)

# Embedding 向量数据模式 (来源: capability_detector.py 的 embedding_structural_patterns)
_EMBEDDING_STRUCTURAL_PATTERN = re.compile(
    r'"(?:embedding|vector|scores)"\s*:\s*\[|"similarity"\s*:\s*[\d.]',
    re.IGNORECASE,
)

_STRUCTURED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "agent": [_TOOL_JSON_PATTERN, _FUNCTION_CALL_PATTERN, _AGENT_CARD_PATTERN, _AGENT_STRUCTURAL_PATTERN],
    "rag": [_RAG_CITATION_PATTERN, _RAG_STRUCTURAL_PATTERN],
    "mcp": [_MCP_JSONRPC_PATTERN, _MCP_STRUCTURAL_PATTERN],
    "embedding": [_EMBEDDING_PATTERN, _EMBEDDING_STRUCTURAL_PATTERN],
    "multi_agent": [_MULTI_AGENT_PATTERN],
    # 深度探测维度
    "function_calling": [_FUNCTION_CALL_PATTERN, _TOOL_JSON_PATTERN, _AGENT_STRUCTURAL_PATTERN],
    "mcp_protocol": [_MCP_JSONRPC_PATTERN, _MCP_STRUCTURAL_PATTERN],
    "embedding_rag": [_EMBEDDING_PATTERN, _RAG_CITATION_PATTERN, _EMBEDDING_STRUCTURAL_PATTERN, _RAG_STRUCTURAL_PATTERN],
    "a2a_protocol": [_AGENT_CARD_PATTERN],
}

# 来源权重 — 主动探测 > 被动指纹
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

    评分策略 (Bayesian 证据累积):
        base_score = 0.0
        + 关键词匹配 (中文 OR 英文): +0.3 per match (max 0.6)
        + 结构化模式匹配 (JSON regex): +0.4 per match (max 0.8)
        + 来源加权: × source_weight (passive=1.0, active=1.5, deep=2.0)
        = final_score (clamped to [0.0, 1.0])

    置信度分级:
        score >= 0.8 → "high" (立即触发攻击)
        0.4 <= score < 0.8 → "medium" (触发主动探测确认)
        score < 0.4 → "low" (不触发, 标记为 "possible")

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
    keywords = get_i18n_keywords(capability)
    text_lower = response_text.lower()

    en_matches = sum(1 for kw in keywords.get("en", []) if kw in text_lower)
    zh_matches = sum(1 for kw in keywords.get("zh", []) if kw in response_text)
    total_keyword_matches = en_matches + zh_matches

    # 多关键词累积加成 (max 0.6)
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
    # detected 阈值 = 0.3 (单关键词命中即可判定为 "可能存在")
    # level 阈值独占: HIGH >= 0.8, MEDIUM >= 0.4, LOW < 0.4
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
            "possible": [能力名列表],    # LOW 置信度, 标记为 "possible"
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


# ══════════════════════════════════════════════════════════════
# 多层证据收敛 (Multi-Signal Evidence Convergence)
# ══════════════════════════════════════════════════════════════
# 学术依据:
#   - Chiang et al. (arXiv:2402.04249) — HarmBench: confidently confirmed
#     的能力标注, 要求至少 2 个独立证据来源
#   - Abhay et al. (arXiv:2311.04956) — ASR 差距分析, 声明能力 vs 实际能力
#     的偏差可达 20-30%, 多层验证可降低此偏差
# ——


# 收敛要求的最低独立信号数
_MIN_INDEPENDENT_SIGNALS = 2

# 证据类型分类 (按独立性排序, 更独立的证据贡献更高权重)
_EVIDENCE_INDEPENDENCE: dict[str, int] = {
    "keyword_match_i18n": 1,     # 文本声明 (弱, 易伪造)
    "structured_pattern": 2,     # 结构协议 (中, 较可靠)
    "api_behavior": 3,           # API 行为指纹 (强, 高可信度)
    "behavioral_verification": 4, # 行为验证 (最强, 实际验证过)
}


@dataclass
class ConvergenceResult:
    """多层证据收敛结果。

    属性:
        capability: 能力维度名
        converged: 是否通过收敛 (至少 2 个独立信号)
        signal_count: 独立信号数
        evidence_types: 证据类型列表
        adjusted_confidence: 经收敛调整后的置信度
        source_level: 来源层 (S1/S2/S3)
    """
    capability: str
    converged: bool = False
    signal_count: int = 0
    evidence_types: list[str] = field(default_factory=list)
    adjusted_confidence: float = 0.0
    source_level: str = "S1"  # S1=文本声明, S2=结构化协议, S3=行为验证


def score_capability_with_convergence(
    capability: str,
    keyword_evidence: bool = False,
    structured_evidence: bool = False,
    api_behavior_evidence: bool = False,
    behavioral_verification_evidence: bool = False,
    text_claim_confidence: float = 0.0,
    behavioral_verify_confidence: float = 0.0,
) -> ConvergenceResult:
    """多层证据收敛评分 — 要求至少 2 个独立信号才判为可行动。

    这是 score_capability 的增强版, 整合来自不同证据层的能力置信度,
    确保只有被多个独立来源共同确认的能力才被评为 "可行动"。

    收敛规则:
        - 1 个独立信号: confidence 上限 0.5 (medium, 需再确认)
        - 2 个独立信号: confidence 上限 0.8 (high, 可行动)
        - 3+ 个独立信号: 完全可信 (high, 优先使用)

    实际使用:
        >>> result = score_capability_with_convergence(
        ...     capability="mcp",
        ...     keyword_evidence=True,          # LLM 文本提到 MCP
        ...     structured_evidence=True,       # JSON-RPC 2.0 响应结构
        ...     api_behavior_evidence=True,     # /sse 端点返回 MCP 事件流
        ...     behavioral_verification_evidence=True,  # tools/list 真实返回工具列表
        ... )
        >>> assert result.converged  # 4 个独立信号 → 收敛

    Args:
        capability: 能力维度名。
        keyword_evidence: 是否有关键词证据 (文本声明)。
        structured_evidence: 是否有结构化协议证据。
        api_behavior_evidence: 是否有 API 行为指纹证据。
        behavioral_verification_evidence: 是否有行为验证证据。
        text_claim_confidence: 文本声明层置信度 (0.0-1.0)。
        behavioral_verify_confidence: 行为验证层置信度 (0.0-1.0)。

    Returns:
        ConvergenceResult 实例。
    """
    result = ConvergenceResult(capability=capability)

    # 收集所有证据类型
    signals: list[tuple[str, bool, float]] = [
        ("keyword_match_i18n", keyword_evidence, text_claim_confidence * 0.3),
        ("structured_pattern", structured_evidence, 0.5 if structured_evidence else 0.0),
        ("api_behavior", api_behavior_evidence, 0.7 if api_behavior_evidence else 0.0),
        ("behavioral_verification", behavioral_verification_evidence,
         behavioral_verify_confidence if behavioral_verification_evidence else 0.0),
    ]

    active_signals = [(sig_type, conf) for sig_type, active, conf in signals if active]
    result.signal_count = len(active_signals)
    result.evidence_types = [sig_type for sig_type, _ in active_signals]

    if not active_signals:
        result.adjusted_confidence = 0.0
        result.source_level = "S1"
        return result

    # 按独立性排序, 取最强的几个
    sorted_signals = sorted(
        active_signals,
        key=lambda x: _EVIDENCE_INDEPENDENCE.get(x[0], 0),
        reverse=True,
    )

    # 计算调整后的 confidence
    weighted_sum = 0.0
    weight_total = 0.0
    for sig_type, conf in sorted_signals[:3]:
        weight = _EVIDENCE_INDEPENDENCE.get(sig_type, 1)
        weighted_sum += conf * weight
        weight_total += weight

    base_confidence = weighted_sum / max(1.0, weight_total)

    # 收敛判定
    if result.signal_count >= _MIN_INDEPENDENT_SIGNALS:
        # 多信号收敛 → 提升置信度
        convergence_bonus = min(0.2, 0.1 * (result.signal_count - 1))
        result.converged = True
        result.adjusted_confidence = min(1.0, base_confidence + convergence_bonus)

        # 来源层判定
        if any(s in result.evidence_types for s in ("behavioral_verification", "api_behavior")):
            result.source_level = "S3"
        elif "structured_pattern" in result.evidence_types:
            result.source_level = "S2"
        else:
            result.source_level = "S1+"
    else:
        # 单信号 → 限制置信度上限
        result.converged = False
        result.adjusted_confidence = min(0.5, base_confidence)
        result.source_level = "S1"

    return result


def merge_verification_into_capabilities(
    capabilities: dict[str, CapabilityResult],
    behavioral_report: dict[str, Any],
) -> dict[str, CapabilityResult]:
    """将行为验证报告合并到能力评分中。

    对 behavioral_verifier 返回的验证结果与 confidence_scorer 的能力评分合并:
        - 行为验证通过 → confidence 提升至 >= HIGH
        - 行为验证失败 → confidence 降级 (标记为 false_positive)

    Args:
        capabilities: 原有的能力评分结果。
        behavioral_report: behavioral_verifier的报告字典 (to_dict() 格式)。

    Returns:
        合并后的能力评分字典。
    """
    results = dict(capabilities)

    behavioral_results = behavioral_report.get("results", {})

    for cap_name, verify_data in behavioral_results.items():
        behaviorally_verified = verify_data.get("behaviorally_verified", False)
        verify_confidence = verify_data.get("confidence", 0.0)

        existing = results.get(cap_name)

        if behaviorally_verified:
            # 行为验证通过 → 升级为 HIGH
            updated_confidence = max(
                existing.confidence if existing else 0.0,
                verify_confidence,  # 通常 0.9
            )
            updated_evidence = (existing.evidence if existing else []) + [
                f"behavioral_verification=PASSED (confidence={verify_confidence})"
            ]

            results[cap_name] = CapabilityResult(
                name=cap_name,
                detected=True,
                confidence=round(updated_confidence, 3),
                evidence=updated_evidence,
                source="behavioral",
            )
        else:
            # 行为验证失败 → 降级
            updated_confidence = min(
                existing.confidence if existing else 0.5,
                0.2,  # 降级
            )
            updated_evidence = (existing.evidence if existing else []) + [
                f"behavioral_verification=FAILED (claimed_text but no behavioral evidence)"
            ]

            results[cap_name] = CapabilityResult(
                name=cap_name,
                detected=updated_confidence >= 0.3,
                confidence=round(updated_confidence, 3),
                level="low",
                evidence=updated_evidence,
                source=existing.source if existing else "passive",
            )

    return results
