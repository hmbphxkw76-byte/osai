"""
Target-Aware Converter Router
=============================

P0: 根据不同 Target 类型自动选择成功率最高的 Converter 链。

当前架构中 Converter 链选择仅由 OWASP ID / Scenario 驱动，
不感知 Target 类型（LLM Direct / Agent / Output Handling / Multimodal）。
本模块在 OWASP/Scenario 驱动之上增加 Target 维度：

  Target 类型 → 安全机制分析 → 最优 Converter 链序列

设计原则：
- 纯函数式路由：输入 target_type → 输出有序链名列表
- 与现有 owasp_strategy_map 叠加使用，Target 感知作为优先排序层
- 非 LLM 链优先（快速高成功率），LLM 链作为兜底
- 支持 converter_target 可用性检测（LLM 链需要 converter_target）

10 个 Target 分组（覆盖 PyRIT 全部 15+ Target 类型）：

  ┌───────────────────────┬──────────────────────────────────────┐
  │ Target Group          │ PyRIT Target Types                   │
  ├───────────────────────┼──────────────────────────────────────┤
  │ llm_direct            │ openai_chat, openai_responses,       │
  │                       │ litellm, azure_ml                    │
  ├───────────────────────┼──────────────────────────────────────┤
  │ llm_safety            │ prompt_shield                        │
  ├───────────────────────┼──────────────────────────────────────┤
  │ agent_web             │ playwright, playwright_copilot       │
  ├───────────────────────┼──────────────────────────────────────┤
  │ agent_copilot         │ websocket_copilot                    │
  ├───────────────────────┼──────────────────────────────────────┤
  │ agent_api             │ http_api                             │
  ├───────────────────────┼──────────────────────────────────────┤
  │ rag                   │ azure_blob (XPIA 载荷投递)            │
  ├───────────────────────┼──────────────────────────────────────┤
  │ output_handling       │ http_raw (Burp/原始 HTTP)             │
  ├───────────────────────┼──────────────────────────────────────┤
  │ multimodal_image      │ openai_image                         │
  ├───────────────────────┼──────────────────────────────────────┤
  │ multimodal_video      │ openai_video                         │
  ├───────────────────────┼──────────────────────────────────────┤
  │ multimodal_audio      │ openai_tts                           │
  └───────────────────────┴──────────────────────────────────────┘
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================
# Target Type → Target Group 映射
# ============================================================

TARGET_TYPE_GROUPS: Dict[str, str] = {
    # ── LLM Direct ──
    "openai_chat": "llm_direct",
    "openai_responses": "llm_direct",
    "litellm": "llm_direct",
    "azure_ml": "llm_direct",
    # ── LLM Safety ──
    "prompt_shield": "llm_safety",
    # ── Agent (Web) ──
    "playwright": "agent_web",
    "playwright_copilot": "agent_web",
    # ── Agent (Copilot) ──
    "websocket_copilot": "agent_copilot",
    # ── Agent (API) ──
    "http_api": "agent_api",
    # ── RAG ──
    "azure_blob": "rag",
    # ── Output Handling ──
    "http_raw": "output_handling",
    # ── Multimodal ──
    "openai_image": "multimodal_image",
    "openai_video": "multimodal_video",
    "openai_tts": "multimodal_audio",
    # ── Fallback ──
    "text": "llm_direct",
}


# ============================================================
# Target Group → Converter 链 Profile
# ============================================================

TARGET_CONVERTER_PROFILES: Dict[str, Dict[str, Any]] = {
    # ── LLM Direct ──────────────────────────────────────────────
    "llm_direct": {
        "high_asr_chains": [
            "multi_encoding_v2",
            "stealth_evasion",
            "encoding_bypass",
        ],
        "medium_asr_chains": [
            "policy_puppetry",
            "noise_case_chain",
            "unicode_attack",
        ],
        "llm_assisted_chains": [
            "persuasion_authority",
            "decomposition_chain",
            "llm_assisted",
        ],
        "bypass_mechanism": "content_filter",
        "description": "LLM 直连 — 内容过滤 + 关键词检测 + 拒绝分类器",
    },

    # ── LLM Safety ──────────────────────────────────────────────
    "llm_safety": {
        "high_asr_chains": [
            "stealth_evasion",
            "multi_encoding_v2",
            "encoding_bypass",
        ],
        "medium_asr_chains": [
            "noise_case_chain",
            "unicode_attack",
            "random_case",
        ],
        "llm_assisted_chains": [
            "decomposition_chain",
            "persuasion_authority",
        ],
        "bypass_mechanism": "prompt_shield_detection",
        "description": "LLM Safety — Prompt Shield 检测绕过",
    },

    # ── Agent (Web) ─────────────────────────────────────────────
    "agent_web": {
        "high_asr_chains": [
            "agent_injection_chain",
            "stealth_evasion",
        ],
        "medium_asr_chains": [
            "decomposition_policy_chain",
            "policy_puppetry_chain",
            "task_framing_chain",
        ],
        "llm_assisted_chains": [
            "persuasion_authority",
        ],
        "bypass_mechanism": "input_validation",
        "description": "Agent (Web UI) — 前端输入验证 + 后端双重检查",
    },

    # ── Agent (Copilot) ─────────────────────────────────────────
    "agent_copilot": {
        "high_asr_chains": [
            "agent_injection_chain",
            "unicode_attack",
        ],
        "medium_asr_chains": [
            "policy_puppetry_chain",
            "task_framing_chain",
            "decomposition_policy_chain",
        ],
        "llm_assisted_chains": [
            "persuasion_authority",
        ],
        "bypass_mechanism": "grounding_safety",
        "description": "Agent (Copilot) — 系统提示 + Grounding + 工具权限",
    },

    # ── Agent (API) ─────────────────────────────────────────────
    "agent_api": {
        "high_asr_chains": [
            "agent_injection_chain",
            "encoding_bypass",
        ],
        "medium_asr_chains": [
            "task_framing_chain",
            "decomposition_policy_chain",
        ],
        "llm_assisted_chains": [
            "persuasion_authority",
        ],
        "bypass_mechanism": "api_schema_validation",
        "description": "Agent (API) — API 层验证 + Schema 约束",
    },

    # ── RAG ─────────────────────────────────────────────────────
    "rag": {
        "high_asr_chains": [
            "xpia_stealth_chain",
            "pdf_injection",
        ],
        "medium_asr_chains": [
            "worddoc_injection",
            "text_jailbreak",
        ],
        "llm_assisted_chains": [],
        "bypass_mechanism": "no_content_check",
        "description": "RAG — 文档投毒 / XPIA 载荷投递",
    },

    # ── Output Handling ─────────────────────────────────────────
    "output_handling": {
        "high_asr_chains": [
            "format_injection",
            "text_jailbreak",
        ],
        "medium_asr_chains": [
            "pdf_injection",
            "xpia_stealth_chain",
        ],
        "llm_assisted_chains": [],
        "bypass_mechanism": "man_in_middle",
        "description": "Output Handling — 中间人位置 / 原始 HTTP",
    },

    # ── Multimodal (Image) ──────────────────────────────────────
    "multimodal_image": {
        "high_asr_chains": [
            "multimodal_image_attack",
        ],
        "medium_asr_chains": [
            "multimodal_steganography",
        ],
        "llm_assisted_chains": [],
        "bypass_mechanism": "image_content_policy",
        "description": "Multimodal (Image) — 图片内容策略 + 安全分类器",
    },

    # ── Multimodal (Video) ──────────────────────────────────────
    "multimodal_video": {
        "high_asr_chains": [
            "multimodal_image_attack",
        ],
        "medium_asr_chains": [],
        "llm_assisted_chains": [],
        "bypass_mechanism": "pre_generation_review",
        "description": "Multimodal (Video) — 生成前审核",
    },

    # ── Multimodal (Audio/TTS) ──────────────────────────────────
    "multimodal_audio": {
        "high_asr_chains": [
            "stealth_evasion",
            "encoding_bypass",
        ],
        "medium_asr_chains": [
            "unicode_attack",
        ],
        "llm_assisted_chains": [],
        "bypass_mechanism": "voice_content_review",
        "description": "Multimodal (Audio/TTS) — 语音内容审核",
    },
}


# ============================================================
# 默认 Profile（未识别 Target 类型时使用）
# ============================================================

_DEFAULT_PROFILE: Dict[str, Any] = {
    "high_asr_chains": ["stealth_evasion", "encoding_bypass"],
    "medium_asr_chains": ["policy_puppetry", "unicode_attack"],
    "llm_assisted_chains": ["llm_assisted"],
    "bypass_mechanism": "unknown",
    "description": "默认 — 通用混淆 + 编码绕过",
}


# ============================================================
# Router 核心逻辑
# ============================================================


def get_target_group(target_type: str) -> str:
    """
    获取 Target 类型对应的分组名

    Args:
        target_type: PyRIT Target 类型名（如 "openai_chat", "playwright"）

    Returns:
        Target 分组名（如 "llm_direct", "agent_web"）
    """
    return TARGET_TYPE_GROUPS.get(target_type, "llm_direct")


def get_target_converter_profile(target_type: str) -> Dict[str, Any]:
    """
    获取 Target 类型对应的 Converter 链 Profile

    Args:
        target_type: PyRIT Target 类型名

    Returns:
        Profile 字典，包含 high_asr_chains / medium_asr_chains /
        llm_assisted_chains / bypass_mechanism / description
    """
    group = get_target_group(target_type)
    profile = TARGET_CONVERTER_PROFILES.get(group)
    if profile is None:
        logger.warning(f"No converter profile for target group '{group}', using default")
        return _DEFAULT_PROFILE.copy()
    return profile


def select_converter_chains_for_target(
    target_type: str,
    converter_target_available: bool = True,
    max_chains: int = 8,
) -> List[str]:
    """
    根据 Target 类型选择最优 Converter 链序列

    返回有序链名列表，按预估 ASR 从高到低排列：
      1. high_asr_chains（非 LLM，快速高成功率）
      2. llm_assisted_chains（需 converter_target，语义变换）
      3. medium_asr_chains（兜底）

    Args:
        target_type: PyRIT Target 类型名
        converter_target_available: 是否有可用的 converter_target（LLM 辅助链需要）
        max_chains: 返回的最大链数量

    Returns:
        有序 Converter 链名列表
    """
    profile = get_target_converter_profile(target_type)

    chains: List[str] = []
    # 1. 非 LLM 高 ASR 链
    chains.extend(profile.get("high_asr_chains", []))
    # 2. LLM 辅助链（仅在 converter_target 可用时）
    if converter_target_available:
        chains.extend(profile.get("llm_assisted_chains", []))
    # 3. 中等 ASR 链
    chains.extend(profile.get("medium_asr_chains", []))

    # 去重（保持顺序）
    seen: set[str] = set()
    unique_chains: List[str] = []
    for c in chains:
        if c not in seen:
            seen.add(c)
            unique_chains.append(c)

    return unique_chains[:max_chains]


def get_chain_priority_for_target(
    chain_name: str,
    target_type: str,
) -> int:
    """
    获取特定 Converter 链在特定 Target 类型下的优先级

    优先级数字越小越优先（1 = 最高优先）。

    Args:
        chain_name: Converter 链名
        target_type: PyRIT Target 类型名

    Returns:
        优先级数字（1-based），不在 Profile 中返回 99
    """
    profile = get_target_converter_profile(target_type)

    high_asr = profile.get("high_asr_chains", [])
    llm_assisted = profile.get("llm_assisted_chains", [])
    medium_asr = profile.get("medium_asr_chains", [])

    if chain_name in high_asr:
        return high_asr.index(chain_name) + 1
    if chain_name in llm_assisted:
        return len(high_asr) + llm_assisted.index(chain_name) + 1
    if chain_name in medium_asr:
        return len(high_asr) + len(llm_assisted) + medium_asr.index(chain_name) + 1
    return 99


def get_target_group_summary() -> List[Dict[str, Any]]:
    """
    获取所有 Target 分组的摘要信息

    用于文档生成和执行前展示。

    Returns:
        分组信息列表，每项包含 group / targets / high_asr / medium_asr /
        llm_assisted / bypass_mechanism / description
    """
    # 反转 TARGET_TYPE_GROUPS: group → [target_types]
    group_to_types: Dict[str, List[str]] = {}
    for t_type, group in TARGET_TYPE_GROUPS.items():
        group_to_types.setdefault(group, []).append(t_type)

    summary: List[Dict[str, Any]] = []
    for group, profile in TARGET_CONVERTER_PROFILES.items():
        summary.append({
            "group": group,
            "targets": sorted(group_to_types.get(group, [])),
            "high_asr": profile.get("high_asr_chains", []),
            "medium_asr": profile.get("medium_asr_chains", []),
            "llm_assisted": profile.get("llm_assisted_chains", []),
            "bypass_mechanism": profile.get("bypass_mechanism", ""),
            "description": profile.get("description", ""),
        })
    return summary


class TargetAwareConverterRouter:
    """
    Target-Aware Converter 路由器

    根据不同 Target 类型选择成功率最高的 Converter 链。
    可作为 ScenarioOrchestrator / AdaptiveScenario 的顾问组件。

    Usage:
        router = TargetAwareConverterRouter()
        chains = router.select_chains("openai_chat", converter_target_available=True)
        # ["multi_encoding_v2", "stealth_evasion", "encoding_bypass", ...]
    """

    def select_chains(
        self,
        target_type: str,
        converter_target_available: bool = True,
        max_chains: int = 8,
    ) -> List[str]:
        """选择最优 Converter 链序列"""
        return select_converter_chains_for_target(
            target_type=target_type,
            converter_target_available=converter_target_available,
            max_chains=max_chains,
        )

    def get_priority(
        self,
        chain_name: str,
        target_type: str,
    ) -> int:
        """获取链在特定 Target 下的优先级"""
        return get_chain_priority_for_target(chain_name, target_type)

    def get_profile(self, target_type: str) -> Dict[str, Any]:
        """获取 Target 的 Converter Profile"""
        return get_target_converter_profile(target_type)

    def get_group(self, target_type: str) -> str:
        """获取 Target 分组"""
        return get_target_group(target_type)

    def display_profiles(self) -> None:
        """展示所有 Profile"""
        display_target_converter_profiles()

    def get_summary(self) -> List[Dict[str, Any]]:
        """获取所有分组摘要"""
        return get_target_group_summary()


def display_target_converter_profiles() -> None:
    """
    展示所有 Target 分组的 Converter 链 Profile

    在 pipeline 执行前调用，让用户了解针对不同 Target 类型
    将使用哪些 Converter 链。
    """
    summary = get_target_group_summary()

    print("\n" + "=" * 80)
    print("  Target-Aware Converter 链 Profile")
    print("=" * 80)

    for item in summary:
        print(f"\n  ── {item['group']} ──")
        print(f"  Targets: {', '.join(item['targets'])}")
        print(f"  Mechanism: {item['bypass_mechanism']}")
        print(f"  Description: {item['description']}")
        print(f"  High ASR:    {', '.join(item['high_asr']) if item['high_asr'] else '(none)'}")
        print(f"  LLM Assist:  {', '.join(item['llm_assisted']) if item['llm_assisted'] else '(none)'}")
        print(f"  Medium ASR:  {', '.join(item['medium_asr']) if item['medium_asr'] else '(none)'}")

    print("\n" + "=" * 80 + "\n")
