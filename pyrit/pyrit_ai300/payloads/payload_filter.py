# -*- coding: utf-8 -*-
"""
AI-300 Framework - Payload Filter (REV-1 / GAP-1)
载荷过滤器：基于侦察画像过滤不相关载荷

核心功能：
1. 基于攻击面（surfaces）过滤 OWASP 类别
   - 目标无 RAG 攻击面时，跳过 LLM04/LLM08 载荷
   - 目标无 Agent 攻击面时，跳过 ASI01-10 载荷
2. 基于上下文窗口过滤超长载荷
   - 载荷 context_required > 目标 context_window 时跳过
3. 基于模型能力过滤不兼容载荷
   - 无 vision 能力时跳过多模态载荷

设计原则：
- 纯过滤，不修改载荷内容
- 无侦察画像时不过滤（向后兼容）
- 保留日志记录过滤决策

对齐文档：docs/architecture_review.md §5.2 GAP-1
预期收益：减少 30-50% 无效 API 调用
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# OWASP ID → 所需攻击面映射表
# ──────────────────────────────────────────────────────────────────────────────

OWASP_SURFACE_MAP: Dict[str, Set[str]] = {
    # LLM Top 10
    "LLM01": {"prompt"},            # Prompt Injection — 基础攻击面，几乎所有目标都有
    "LLM02": {"prompt"},            # Sensitive Info Disclosure — 基础攻击面
    "LLM03": {"prompt", "api"},     # Supply Chain — 可能需要 API/模型访问
    "LLM04": {"rag"},               # RAG Poison — 需要 RAG 检索端点
    "LLM05": {"prompt", "api"},     # Insecure Output — 输出处理
    "LLM06": {"agent", "mcp"},      # Excessive Agency — 需要 Agent/MCP
    "LLM07": {"prompt"},            # System Prompt Leak — 基础攻击面
    "LLM08": {"rag", "vector"},     # Vector Weakness — 需要向量 DB
    "LLM09": {"prompt"},            # Misinformation — 基础攻击面
    "LLM10": {"prompt", "api"},     # Unbounded Consumption — 资源消耗

    # Agentic Top 10 (ASI01-ASI10) — 全部需要 Agent 攻击面
    "ASI01": {"agent"},             # Agent Goal Hijack
    "ASI02": {"agent", "mcp"},      # Tool Misuse & Exploitation
    "ASI03": {"agent", "mcp"},      # Agent Identity & Privilege Abuse
    "ASI04": {"agent"},             # Agentic Supply Chain
    "ASI05": {"agent", "mcp"},      # Unexpected Code Execution
    "ASI06": {"agent"},             # Memory & Context Poisoning
    "ASI07": {"agent"},             # Insecure Inter-Agent Communication
    "ASI08": {"agent"},             # Cascading Failures
    "ASI09": {"agent"},             # Human-Agent Trust Exploitation
    "ASI10": {"agent"},             # Rogue Agents
}

# 攻击面别名映射（侦察可能用不同名称）
SURFACE_ALIASES: Dict[str, str] = {
    "llm": "prompt",
    "chat": "prompt",
    "completion": "prompt",
    "embeddings": "vector",
    "embedding": "vector",
    "vectordb": "vector",
    "vector_db": "vector",
    "chromadb": "vector",
    "weaviate": "vector",
    "pinecone": "vector",
    "tool": "mcp",
    "tools": "mcp",
    "function_calling": "mcp",
    "langgraph": "agent",
    "autogen": "agent",
    "crewai": "agent",
    "dify": "agent",
}

# ── 靶机类型 → 默认攻击面映射 ──
# 用于无侦察画像时从目标配置类型推断攻击面
TARGET_TYPE_SURFACES: Dict[str, Set[str]] = {
    # OWASP DonkAI: REST API，规则引擎，系统提示词含敏感信息
    "rest_api": {"prompt", "api"},
    # AIVP: SSE 流式聊天，含 Agent/RAG/MCP 多阶段
    "sse_chat": {"prompt", "agent", "rag", "mcp"},
    # LLM API (Ollama/OpenAI)
    "ollama": {"prompt", "api"},
    "openai": {"prompt", "api"},
    # HTTP 自定义端点
    "http": {"prompt", "api"},
    # SPA 浏览器自动化
    "spa_chat": {"prompt"},
    "playwright": {"prompt"},
}


def infer_surfaces_from_target_type(target_type: str) -> List[str]:
    """
    从目标配置类型推断可用攻击面

    当没有侦察画像时，使用目标类型推断攻击面，
    使 PayloadFilter 仍能进行基本过滤。

    Args:
        target_type: 目标类型（rest_api / sse_chat / ollama / openai / http / spa_chat）

    Returns:
        攻击面列表
    """
    surfaces = TARGET_TYPE_SURFACES.get(target_type.lower(), set())
    return list(surfaces)


def normalize_surfaces(surfaces: List[str]) -> Set[str]:
    """
    归一化攻击面列表

    将侦察检测到的各种攻击面名称统一为标准名称：
    prompt / api / rag / mcp / agent / vector

    Args:
        surfaces: 侦察检测到的攻击面列表

    Returns:
        归一化后的攻击面集合
    """
    normalized = set()
    for s in surfaces:
        s_lower = s.lower().strip()
        # 直接匹配
        if s_lower in OWASP_SURFACE_MAP.get("LLM01", set()):
            normalized.add(s_lower)
        # 别名匹配
        elif s_lower in SURFACE_ALIASES:
            normalized.add(SURFACE_ALIASES[s_lower])
        # 未知攻击面，保留原值
        else:
            normalized.add(s_lower)
    return normalized


class PayloadFilter:
    """
    载荷过滤器 (REV-1)

    基于侦察画像（TargetProfile）过滤不相关的载荷和攻击配置。

    过滤维度：
    1. 攻击面匹配：OWASP ID 所需攻击面 ∩ 目标可用攻击面
    2. 上下文窗口：载荷所需 context ≤ 目标 context_window
    3. 模型能力：载荷所需 capabilities ⊆ 目标 capabilities

    使用方式：
        filter = PayloadFilter()
        if filter.should_skip_attack(owasp_id="LLM04", surfaces=["prompt"]):
            logger.info("Skipping LLM04: no RAG surface detected")
        payloads = filter.filter_by_context(payloads, context_window=8192)
    """

    def __init__(self, min_asr: float = 0.0):
        """
        Args:
            min_asr: 最低 ASR 阈值（0.0 = 不过滤，0.3 = 过滤低 ASR 载荷）
        """
        self.min_asr = min_asr
        self._filter_stats = {
            "total_attacks": 0,
            "skipped_by_surface": 0,
            "skipped_by_context": 0,
            "skipped_by_capability": 0,
            "skipped_by_asr": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        """获取过滤统计"""
        return self._filter_stats

    def reset_stats(self) -> None:
        """重置统计"""
        self._filter_stats = {k: 0 for k in self._filter_stats}

    # ──────────────────────────────────────────────────────────────────────────
    # 攻击面过滤（OWASP 类别级别）
    # ──────────────────────────────────────────────────────────────────────────

    def should_skip_attack(
        self,
        owasp_id: str,
        surfaces: Optional[List[str]] = None,
    ) -> bool:
        """
        检查攻击配置是否应被跳过（基于攻击面匹配）

        核心过滤逻辑：
        - 如果 surfaces 为空/None（未做侦察），返回 False（不跳过）
        - 如果 OWASP ID 不在映射表中，返回 False（保守不跳过）
        - 如果 OWASP 所需攻击面与目标可用攻击面有交集，返回 False
        - 否则返回 True（跳过此攻击）

        Args:
            owasp_id: OWASP ID (如 "LLM04", "ASI01")
            surfaces: 目标可用攻击面列表（来自 TargetProfile.surfaces）

        Returns:
            bool: True 表示应跳过此攻击，False 表示保留
        """
        self._filter_stats["total_attacks"] += 1

        if not surfaces:
            # 未做侦察，不过滤
            return False

        owasp_id_upper = owasp_id.upper().strip()
        required_surfaces = OWASP_SURFACE_MAP.get(owasp_id_upper)

        if not required_surfaces:
            # 未知 OWASP ID，保守不跳过
            logger.debug("Unknown OWASP ID '%s', not filtering", owasp_id)
            return False

        available = normalize_surfaces(surfaces)

        # 检查交集
        if required_surfaces & available:
            return False

        # 无交集，应跳过
        self._filter_stats["skipped_by_surface"] += 1
        logger.info(
            "Filter SKIP: %s requires surfaces %s, but target only has %s",
            owasp_id_upper,
            required_surfaces,
            available,
        )
        return True

    def filter_attacks_by_surface(
        self,
        attacks: List[Dict[str, Any]],
        surfaces: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        批量过滤攻击列表（基于攻击面）

        Args:
            attacks: 攻击配置列表（每个含 owasp_id 或 asi_category）
            surfaces: 目标可用攻击面列表

        Returns:
            List[Dict]: 过滤后的攻击列表
        """
        if not surfaces:
            return attacks

        filtered = []
        skipped = []
        for attack in attacks:
            owasp_id = attack.get("owasp_id", attack.get("asi_category", ""))
            if self.should_skip_attack(owasp_id, surfaces):
                skipped.append(attack.get("name", owasp_id))
            else:
                filtered.append(attack)

        if skipped:
            logger.info(
                "Surface filter: %d/%d attacks retained, skipped %d (%s)",
                len(filtered), len(attacks), len(skipped),
                ", ".join(skipped[:5]),
            )

        return filtered

    # ──────────────────────────────────────────────────────────────────────────
    # 上下文窗口过滤（载荷级别）
    # ──────────────────────────────────────────────────────────────────────────

    def filter_by_context(
        self,
        payloads: List[Any],
        context_window: Optional[int] = None,
    ) -> List[Any]:
        """
        基于上下文窗口过滤载荷

        过滤掉 context_required > context_window 的载荷。
        主要影响 Many-Shot Jailbreak（128/256-shot 需要超长上下文）。

        Args:
            payloads: 载荷列表（字符串或字典）
            context_window: 目标模型上下文窗口大小

        Returns:
            List[Any]: 过滤后的载荷列表
        """
        if not context_window or context_window <= 0:
            return payloads

        filtered = []
        for payload in payloads:
            if isinstance(payload, dict):
                required = payload.get("context_required", 0)
                if required and required > context_window:
                    self._filter_stats["skipped_by_context"] += 1
                    name = payload.get("name", payload.get("technique", ""))
                    logger.debug(
                        "Context filter SKIP: '%s' requires %d tokens, target has %d",
                        name, required, context_window,
                    )
                    continue
            filtered.append(payload)

        if len(filtered) < len(payloads):
            logger.info(
                "Context filter: %d/%d payloads retained (window=%d)",
                len(filtered), len(payloads), context_window,
            )

        return filtered

    # ──────────────────────────────────────────────────────────────────────────
    # 模型能力过滤（载荷级别）
    # ──────────────────────────────────────────────────────────────────────────

    def filter_by_capabilities(
        self,
        payloads: List[Any],
        capabilities: Optional[List[str]] = None,
    ) -> List[Any]:
        """
        基于模型能力过滤载荷

        过滤掉需要目标不支持的能力的载荷。
        例如：无 vision 能力时跳过多模态载荷。

        Args:
            payloads: 载荷列表
            capabilities: 目标模型支持的能力列表

        Returns:
            List[Any]: 过滤后的载荷列表
        """
        if not capabilities:
            return payloads

        cap_set = set(c.lower() for c in capabilities)
        filtered = []

        for payload in payloads:
            if isinstance(payload, dict):
                required_caps = payload.get("required_capabilities", [])
                if required_caps:
                    required_set = set(c.lower() for c in required_caps)
                    if not required_set.issubset(cap_set):
                        self._filter_stats["skipped_by_capability"] += 1
                        name = payload.get("name", payload.get("technique", ""))
                        logger.debug(
                            "Capability filter SKIP: '%s' requires %s, target has %s",
                            name, required_set, cap_set,
                        )
                        continue
            filtered.append(payload)

        return filtered

    # ──────────────────────────────────────────────────────────────────────────
    # 综合过滤入口
    # ──────────────────────────────────────────────────────────────────────────

    def filter_payloads(
        self,
        payloads: List[Any],
        profile_params: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        """
        综合过滤载荷（应用所有过滤维度）

        按顺序应用：
        1. 上下文窗口过滤
        2. 模型能力过滤
        3. ASR 阈值过滤（如果设置了 min_asr）

        注意：攻击面过滤在攻击配置级别（should_skip_attack），
        不在载荷级别，因为同一攻击配置内所有载荷属于同一 OWASP ID。

        Args:
            payloads: 载荷列表
            profile_params: 侦察画像参数（来自 ProfileLoader）

        Returns:
            List[Any]: 过滤后的载荷列表
        """
        if not profile_params:
            return payloads

        result = payloads

        # 1. 上下文窗口过滤
        context_window = profile_params.get("context_window")
        result = self.filter_by_context(result, context_window)

        # 2. 模型能力过滤
        capabilities = profile_params.get("capabilities", [])
        result = self.filter_by_capabilities(result, capabilities)

        # 3. ASR 阈值过滤（可选）
        if self.min_asr > 0:
            target_model = profile_params.get("target_model", "")
            result = self._filter_by_asr_threshold(result, target_model, self.min_asr)

        return result

    def _filter_by_asr_threshold(
        self,
        payloads: List[Any],
        target_model: str,
        min_asr: float,
    ) -> List[Any]:
        """基于 ASR 阈值过滤载荷"""
        from .asr_ranker import ASRRanker

        filtered = []
        for payload in payloads:
            if isinstance(payload, dict):
                asr = ASRRanker.get_payload_asr(payload, target_model)
                if asr < min_asr:
                    self._filter_stats["skipped_by_asr"] += 1
                    name = payload.get("name", payload.get("technique", ""))
                    logger.debug(
                        "ASR filter SKIP: '%s' ASR=%.2f < %.2f",
                        name, asr, min_asr,
                    )
                    continue
            filtered.append(payload)

        return filtered

    def get_filter_report(self) -> Dict[str, Any]:
        """生成过滤报告（供 tracker 使用）

        Returns:
            Dict[str, Any]: 过滤统计和总过滤数
        """
        return {
            "filter_stats": dict(self._filter_stats),
            "total_filtered": (
                self._filter_stats["skipped_by_surface"]
                + self._filter_stats["skipped_by_context"]
                + self._filter_stats["skipped_by_capability"]
                + self._filter_stats["skipped_by_asr"]
            ),
        }
