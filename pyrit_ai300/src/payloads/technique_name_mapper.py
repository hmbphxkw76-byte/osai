"""
Technique Name Mapper — 技术名标准化映射
==========================================

打通选择层（ASRRankBuilder / TieredSelectionWizard）与执行层
（FailureTypeRoutingSelector / ASR Prior Registry）的技术名差异。

YAML 种子文件中的 technique_group（如 "direct", "skeleton", "gradual_extraction"）
与 asr_prior_registry.py 中的 key（如 "prompt_sending", "skeleton_key", "pair"）
往往不一致。本模块提供统一映射，确保两个系统查询同一 ASR 数据源。

数据流:
  YAML metadata.technique_group
    → normalize_technique_name()  ← 本模块
      → asr_prior_registry.get_initial_q_value()
        → 模型感知 ASR 值

设计原则:
  - 纯映射表 + 查询函数，无状态无副作用
  - ASR 查询优先级: 学术先验 > 中性默认
  - Tier 阈值统一引用 asr_prior_registry（唯一定义点）
"""

import logging

from src.payloads.asr_prior_registry import (  # noqa: F401 — re-exports for backward compatibility
    TIER_S_THRESHOLD,
    TIER_A_THRESHOLD,
    TIER_B_THRESHOLD,
    TIER_C_THRESHOLD,
    tier_from_asr,
)

logger = logging.getLogger(__name__)


# ============================================================
# 技术名映射表: YAML technique_group → asr_prior_registry key
# ============================================================

TECHNIQUE_NAME_MAP: dict[str, str] = {
    # ── LLM01 直接攻击 ──
    "direct": "prompt_sending",
    "direct_extraction": "direct_injection",
    "authority_override": "skeleton_key",
    "translation_trick": "encoding_bypass",
    "skeleton": "skeleton_key",
    "skeleton_then_extract": "skeleton_key",
    "role_play": "role_play_movie_script",
    "unicode_confusable": "stealth_evasion",
    "verbatim_request": "prompt_sending",
    "markdown_injection": "format_injection",
    "sql_injection": "format_injection",

    # ── 多轮 ──
    "gradual_extraction": "pair",
    "iterative_jailbreak": "pair",
    "crescendo_jailbreak": "crescendo",
    "adaptive_jailbreak": "crescendo",
    "many_shot_jailbreak": "many_shot",

    # ── Agent ──
    "goal_hijack": "agent_injection_chain",
    "goal_hijacking": "agent_injection_chain",
    "indirect_injection": "direct_injection",
    "indirect_prompt_injection": "direct_injection",
    "prompt_smuggling": "stealth_evasion",
    "agent_break": "agent_injection_chain",
    "agent_communication": "agent_injection_chain",
    "agent_communication_expanded": "agent_injection_chain",
    "confused_deputy": "agent_injection_chain",

    # ── RAG ──
    "rag_poisoning": "agent_injection_chain",
    "rag_poison": "agent_injection_chain",
    "cross_namespace_rag_poison": "agent_injection_chain",
    "cross_tenant_leakage": "direct_injection",
    "vector_weakness": "agent_injection_chain",
    "vector_db_query_injection": "direct_injection",
    "rag_indirect_injection": "direct_injection",
    "rag_source_attribution": "direct_injection",

    # ── 编码 ──
    "cipher_chat": "encoding_bypass",
    "adversarial_suffix": "stealth_evasion",
    "autodan": "stealth_evasion",
    "glitch_token": "stealth_evasion",
    "special_token_injection": "stealth_evasion",
    "token_smuggling": "stealth_evasion",

    # ── 提取 ──
    "system_prompt_extraction": "direct_injection",
    "system_prompt_leakage": "direct_injection",
    "system_prompt_echo": "direct_injection",
    "configuration_extraction": "direct_injection",
    "sensitive_info": "direct_injection",
    "pii_anchor_extraction": "direct_injection",
    "training_data_extraction": "direct_injection",
    "memory_poisoning": "agent_injection_chain",
    "memory_extraction": "direct_injection",
    "memory_poison": "agent_injection_chain",
    "memory_attack": "agent_injection_chain",
    "agentic_memory_attack": "agent_injection_chain",

    # ── 安全 ──
    "hallucination_exploitation": "prompt_sending",
    "misinformation": "prompt_sending",
    "citation_elicitation": "prompt_sending",
    "resource_exhaustion": "prompt_sending",
    "context_padding": "prompt_sending",

    # ── 输出 ──
    "insecure_output_handling": "prompt_sending",
    "insecure_output": "prompt_sending",
    "structured_output": "prompt_sending",
    "structured_field_injection": "format_injection",
    "format_injection": "format_injection",

    # ── 供应链 ──
    "model_deserialization": "direct_injection",
    "pickle_deserialization": "direct_injection",
    "package_hallucination": "direct_injection",
    "dependency_confusion": "direct_injection",
    "supply_chain_pickle": "direct_injection",
    "supply_chain_probe": "direct_injection",
    "supply_chain": "direct_injection",

    # ── 多模态 ──
    "multimodal_injection": "agent_injection_chain",
    "multimodal_jailbreak_v2": "crescendo",

    # ── MCP ──
    "mcp_tool_poison": "agent_injection_chain",
    "mcp_tool_poisoning": "agent_injection_chain",
    "mcp_capability_confusion": "agent_injection_chain",
    "mcp_command_injection": "direct_injection",
    "mcp_session_fix": "agent_injection_chain",
    "mcp_token_leak": "direct_injection",

    # ── 其他已匹配 ──
    "wrapping_attack": "wrapping_attack",
    "bad_likert_judge": "bad_likert_judge",
    "best_of_n_jailbreak": "best_of_n_jailbreak",
    "cca_context_compliance": "context_compliance",
    "deep_inception": "role_play_movie_script",
    "few_shot_backdoor": "prompt_sending",
    "hidden_cot_injection": "agent_injection_chain",
    "identity_abuse": "skeleton_key",
    "identity_abuse_expanded": "skeleton_key",
    "parameter_pollution": "direct_injection",
    "prompt_to_rce": "direct_injection",
    "semantic_stealth_injection": "stealth_evasion",
    "tool_data_exfiltration": "direct_injection",
    "tool_hijacking": "agent_injection_chain",
    "tool_hijack": "agent_injection_chain",
    "tool_misuse": "agent_injection_chain",
    "agent_token_theft": "direct_injection",
    "agent_unauth_rce": "direct_injection",
    "cross_agent": "agent_injection_chain",
    "adversarial_embedding": "agent_injection_chain",
    "embedding_inversion": "direct_injection",
    "vector_db_rce": "direct_injection",
    "a2a_injection": "agent_injection_chain",
    "trust_exploit": "agent_injection_chain",
    "rogue_agent": "agent_injection_chain",
    "cascading_failure": "agent_injection_chain",
    "code_execution": "direct_injection",

    # ── CVE ──
    "cve_2025_32711_echoleak": "direct_injection",
    "cve_2025_1716_picklescan_pypi_rce": "direct_injection",
    "cve_2026_25874_lerobot_pickle_rce": "direct_injection",

    # ── Copilot ──
    "copilot_prompt_leak": "direct_injection",

    # ── frontier ──
    "frontier_2025_001_hcot": "prompt_sending",
    "frontier_2025_002_echoleak_prompt_leak": "direct_injection",
    "frontier_2025_003_mcp_tool_poison": "agent_injection_chain",
    "frontier_2025_004_tool_data_exfil": "direct_injection",

    # ── ASI 系列 ──
    "exam_native_attacks": "prompt_sending",
}


# ============================================================
# 统一 Tier 阈值 — 引用 asr_prior_registry（唯一定义点）
# ============================================================

# TIER_S_THRESHOLD / TIER_A_THRESHOLD / TIER_B_THRESHOLD / TIER_C_THRESHOLD
# tier_from_asr 均在文件顶部从 asr_prior_registry 导入


def normalize_technique_name(yaml_name: str) -> str:
    """
    将 YAML technique_group 名称标准化为 asr_prior_registry key。

    查询顺序:
    1. 精确匹配 TECHNIQUE_NAME_MAP
    2. 去除 _expanded / _v2 后缀后重试
    3. 原样返回（让 registry 的 fallback 机制处理）

    Args:
        yaml_name: YAML 文件中 metadata.technique_group 的值

    Returns:
        asr_prior_registry 中对应的 key
    """
    if not yaml_name:
        return ""

    # 1. 精确匹配
    if yaml_name in TECHNIQUE_NAME_MAP:
        return TECHNIQUE_NAME_MAP[yaml_name]

    # 2. 去除常见后缀
    for suffix in ["_expanded", "_v2", "_pruned"]:
        if yaml_name.endswith(suffix):
            base = yaml_name[: -len(suffix)]
            if base in TECHNIQUE_NAME_MAP:
                return TECHNIQUE_NAME_MAP[base]

    # 3. 原样返回
    return yaml_name


def get_normalized_asr(
    technique_name: str,
    model_name: str = "gpt-4o",
) -> float:
    """
    标准化技术名后查询学术 ASR 先验。

    ASR 查询优先级:
    1. 学术先验 ASR（JailbreakBench/HarmBench）
    2. 中性先验 0.3（未知技术）

    注意: 跨运行学习由 PyRIT 原生 CentralMemory 持久化

    Args:
        technique_name: YAML technique_group 或 registry key
        model_name: 目标模型名称

    Returns:
        ASR 值 (0.0-1.0)
    """
    try:
        from src.payloads.asr_prior_registry import get_initial_q_value

        # 先尝试标准化后的名称
        normalized = normalize_technique_name(technique_name)
        asr = get_initial_q_value(normalized, model_name)

        # 如果标准化后是中性先验(0.3)，且原始名称不同于标准化名称，
        # 再尝试原始名称（可能直接在 registry 中）
        if asr == 0.3 and normalized != technique_name:
            original_asr = get_initial_q_value(technique_name, model_name)
            if original_asr != 0.3:
                return original_asr

        return asr
    except Exception:
        return 0.3


def get_normalized_tier(
    technique_name: str,
    model_name: str = "gpt-4o",
) -> str:
    """
    标准化技术名后查询学术 Tier。

    使用 asr_prior_registry 统一 Tier 阈值:
    - S: ASR >= 70%
    - A: ASR 40-70%
    - B: ASR 15-40%
    - C: ASR 5-15%
    - D: ASR < 5%

    Args:
        technique_name: YAML technique_group 或 registry key
        model_name: 目标模型名称

    Returns:
        Tier 字符串 ("S" / "A" / "B" / "C" / "D")
    """
    asr = get_normalized_asr(technique_name, model_name)
    return tier_from_asr(asr)


def is_high_asr_technique(
    technique_name: str,
    model_name: str = "gpt-4o",
) -> bool:
    """
    判断技术是否为高 ASR（Tier S 或 A）。

    用于确定是否应该挂载 Converter 增强变体。

    Args:
        technique_name: 技术名称
        model_name: 目标模型名称

    Returns:
        True if Tier S or A (ASR >= 40%)
    """
    tier = get_normalized_tier(technique_name, model_name)
    return tier in ("S", "A")
