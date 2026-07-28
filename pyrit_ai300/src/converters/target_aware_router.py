"""
Target-Aware Converter Router
=============================

P0: 根据不同 Target 类型自动选择成功率最高的 Converter 链。

当前架构中 Converter 链选择仅由 OWASP ID / Scenario 驱动，
不感知 Target 类型（LLM Direct / Agent / Output Handling / Multimodal）。
本模块在 OWASP/Scenario 驱动之上增加 Target 维度：

  Target 类型 → 安全机制分析 → 最优 Converter 链序列

R3: 数据源统一 — Profile 定义从 YAML (target_aware_converter_profiles) 加载，
    消除 Python 硬编码与 YAML 的重复定义。YAML 为唯一数据源 (Single Source of Truth)。
R4: 动态链组合 — 基于 Target 能力（多模态支持）动态扩展链池
R6: 模态验证 — Converter 链输出模态与 Target 能力验证

设计原则：
- 纯函数式路由：输入 target_type → 输出有序链名列表
- R3: YAML 为唯一数据源，Python 硬编码仅作 fallback
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
# R3: Fallback 常量（仅当 YAML 加载失败时使用）
# ============================================================

_FALLBACK_TARGET_TYPE_GROUPS: Dict[str, str] = {
    "openai_chat": "llm_direct_strong",
    "openai_responses": "llm_direct_strong",
    "litellm": "llm_direct_weak",
    "azure_ml": "llm_direct_strong",
    "prompt_shield": "llm_safety",
    "playwright": "agent_web",
    "playwright_copilot": "agent_web",
    "websocket_copilot": "agent_copilot",
    "http_api": "agent_api",
    "azure_blob": "rag",
    "http_raw": "output_handling",
    "openai_image": "multimodal_image",
    "openai_video": "multimodal_video",
    "openai_tts": "multimodal_audio",
    "text": "llm_direct_strong",
}

_FALLBACK_TARGET_CONVERTER_PROFILES: Dict[str, Dict[str, Any]] = {
    "llm_direct_strong": {
        "high_asr_chains": [],
        "medium_asr_chains": ["stealth_evasion", "multi_encoding_v2", "agent_injection_chain"],
        "low_asr_chains": ["encoding_bypass", "unicode_attack", "random_case", "policy_puppetry"],
        "llm_assisted_chains": ["persuasion_authority", "decomposition_chain", "llm_assisted"],
        "bypass_mechanism": "content_filter + semantic_classifier",
        "description": "强过滤商业模型 — 内容过滤 + 语义安全分类器 + 拒绝分类器",
        "model_filter": "gpt-4o|gpt-4|claude-3|claude-4|gemini",
    },
    "llm_direct_weak": {
        "high_asr_chains": ["multi_encoding_v2", "stealth_evasion", "encoding_bypass"],
        "medium_asr_chains": ["persuasion_authority", "decomposition_chain", "agent_injection_chain"],
        "low_asr_chains": [],
        "llm_assisted_chains": ["persuasion_authority", "decomposition_chain", "llm_assisted"],
        "bypass_mechanism": "basic_keyword_filter",
        "description": "弱过滤/开源模型 — 基础关键词过滤, 编码攻击仍有效",
        "model_filter": "gpt-3.5|llama|vicuna|mistral|uncensored|phi",
    },
    # 向后兼容: llm_direct 默认映射到 strong
    "llm_direct": {
        "high_asr_chains": [],
        "medium_asr_chains": ["stealth_evasion", "multi_encoding_v2", "agent_injection_chain"],
        "low_asr_chains": ["encoding_bypass", "unicode_attack", "random_case", "policy_puppetry"],
        "llm_assisted_chains": ["persuasion_authority", "decomposition_chain", "llm_assisted"],
        "bypass_mechanism": "content_filter + semantic_classifier",
        "description": "LLM 直连 (默认=强过滤) — 内容过滤 + 语义安全分类器",
        "model_filter": "",
    },
    "llm_safety": {
        "high_asr_chains": ["stealth_evasion", "multi_encoding_v2"],
        "medium_asr_chains": ["noise_case_chain", "unicode_attack", "random_case"],
        "low_asr_chains": ["encoding_bypass"],
        "llm_assisted_chains": ["decomposition_chain", "persuasion_authority"],
        "bypass_mechanism": "prompt_shield_detection",
        "description": "LLM Safety — Prompt Shield 检测绕过",
        "model_filter": "",
    },
    "agent_web": {
        "high_asr_chains": ["agent_injection_chain", "stealth_evasion"],
        "medium_asr_chains": ["decomposition_policy_chain", "policy_puppetry_chain", "task_framing_chain"],
        "low_asr_chains": [],
        "llm_assisted_chains": ["persuasion_authority"],
        "bypass_mechanism": "input_validation",
        "description": "Agent (Web UI) — 前端输入验证 + 后端双重检查",
        "model_filter": "",
    },
    "agent_copilot": {
        "high_asr_chains": ["agent_injection_chain", "unicode_attack"],
        "medium_asr_chains": ["policy_puppetry_chain", "task_framing_chain", "decomposition_policy_chain"],
        "low_asr_chains": [],
        "llm_assisted_chains": ["persuasion_authority"],
        "bypass_mechanism": "grounding_safety",
        "description": "Agent (Copilot) — 系统提示 + Grounding + 工具权限",
        "model_filter": "",
    },
    "agent_api": {
        "high_asr_chains": ["agent_injection_chain", "encoding_bypass"],
        "medium_asr_chains": ["task_framing_chain", "decomposition_policy_chain"],
        "low_asr_chains": [],
        "llm_assisted_chains": ["persuasion_authority"],
        "bypass_mechanism": "api_schema_validation",
        "description": "Agent (API) — API 层验证 + Schema 约束",
        "model_filter": "",
    },
    "rag": {
        "high_asr_chains": ["xpia_stealth_chain", "pdf_injection"],
        "medium_asr_chains": ["worddoc_injection", "text_jailbreak"],
        "low_asr_chains": [],
        "llm_assisted_chains": [],
        "bypass_mechanism": "no_content_check",
        "description": "RAG — 文档投毒 / XPIA 载荷投递",
        "model_filter": "",
    },
    "output_handling": {
        "high_asr_chains": ["format_injection", "text_jailbreak"],
        "medium_asr_chains": ["pdf_injection", "xpia_stealth_chain"],
        "low_asr_chains": [],
        "llm_assisted_chains": [],
        "bypass_mechanism": "man_in_middle",
        "description": "Output Handling — 中间人位置 / 原始 HTTP",
        "model_filter": "",
    },
    "multimodal_image": {
        "high_asr_chains": ["multimodal_image_attack"],
        "medium_asr_chains": ["multimodal_steganography"],
        "low_asr_chains": [],
        "llm_assisted_chains": [],
        "bypass_mechanism": "image_content_policy",
        "description": "Multimodal (Image) — 图片内容策略 + 安全分类器",
        "model_filter": "",
    },
    "multimodal_video": {
        "high_asr_chains": ["multimodal_image_attack"],
        "medium_asr_chains": [],
        "low_asr_chains": [],
        "llm_assisted_chains": [],
        "bypass_mechanism": "pre_generation_review",
        "description": "Multimodal (Video) — 生成前审核",
        "model_filter": "",
    },
    "multimodal_audio": {
        "high_asr_chains": ["stealth_evasion", "encoding_bypass"],
        "medium_asr_chains": ["unicode_attack"],
        "low_asr_chains": [],
        "llm_assisted_chains": [],
        "bypass_mechanism": "voice_content_review",
        "description": "Multimodal (Audio/TTS) — 语音内容审核",
        "model_filter": "",
    },
}

_DEFAULT_PROFILE: Dict[str, Any] = {
    "high_asr_chains": ["persuasion_authority", "decomposition_chain"],
    "medium_asr_chains": ["stealth_evasion", "multi_encoding_v2"],
    "low_asr_chains": ["encoding_bypass", "unicode_attack"],
    "llm_assisted_chains": ["llm_assisted"],
    "bypass_mechanism": "unknown",
    "description": "默认 — 策略级变换优先 + 编码兜底",
    "model_filter": "",
}


# ============================================================
# R3: YAML 数据加载（单一数据源）
# ============================================================

_profiles_cache: Optional[Dict[str, Dict[str, Any]]] = None
_groups_cache: Optional[Dict[str, str]] = None


def _load_profiles_from_yaml() -> Dict[str, Dict[str, Any]]:
    """
    R3: 从 YAML 加载 Target Converter Profiles

    YAML target_aware_converter_profiles 段使用:
      high_asr / medium_asr / llm_assisted (YAML 键名)
    转换为内部格式:
      high_asr_chains / medium_asr_chains / llm_assisted_chains (Python 键名)

    Returns:
        Target 分组 → Profile 字典（内部格式）
    """
    global _profiles_cache
    if _profiles_cache is not None:
        return _profiles_cache

    try:
        from src.core.config_loader import get_config_loader
        config = get_config_loader()
        yaml_profiles = config.get_target_aware_converter_profiles()

        if not yaml_profiles:
            logger.debug("R3: No target_aware_converter_profiles in YAML, using fallback")
            _profiles_cache = dict(_FALLBACK_TARGET_CONVERTER_PROFILES)
            return _profiles_cache

        profiles: Dict[str, Dict[str, Any]] = {}
        for group, yaml_profile in yaml_profiles.items():
            profiles[group] = {
                "high_asr_chains": list(yaml_profile.get("high_asr", [])),
                "medium_asr_chains": list(yaml_profile.get("medium_asr", [])),
                "low_asr_chains": list(yaml_profile.get("low_asr", [])),
                "llm_assisted_chains": list(yaml_profile.get("llm_assisted", [])),
                "bypass_mechanism": yaml_profile.get("bypass_mechanism", "unknown"),
                "description": yaml_profile.get("description", ""),
                "target_types": list(yaml_profile.get("target_types", [])),
                "model_filter": yaml_profile.get("model_filter", ""),
            }

        _profiles_cache = profiles
        logger.info(f"R3: Loaded {len(profiles)} target converter profiles from YAML")
    except Exception as e:
        logger.debug(f"R3: Failed to load profiles from YAML, using fallback: {e}")
        _profiles_cache = dict(_FALLBACK_TARGET_CONVERTER_PROFILES)

    return _profiles_cache


def _load_groups_from_yaml() -> Dict[str, str]:
    """
    R3: 从 YAML 加载 Target Type → Group 映射

    从 YAML target_aware_converter_profiles 的 target_types 字段
    反向构建 target_type → group_name 映射。

    Returns:
        Target 类型 → 分组名 字典
    """
    global _groups_cache
    if _groups_cache is not None:
        return _groups_cache

    try:
        profiles = _load_profiles_from_yaml()
        groups: Dict[str, str] = {}

        for group_name, profile in profiles.items():
            for target_type in profile.get("target_types", []):
                groups[target_type] = group_name

        # 添加 fallback
        groups.setdefault("text", "llm_direct_strong")

        if not groups:
            _groups_cache = dict(_FALLBACK_TARGET_TYPE_GROUPS)
        else:
            _groups_cache = groups
            logger.info(f"R3: Loaded {len(groups)} target type → group mappings from YAML")
    except Exception as e:
        logger.debug(f"R3: Failed to load groups from YAML, using fallback: {e}")
        _groups_cache = dict(_FALLBACK_TARGET_TYPE_GROUPS)

    return _groups_cache


def _reload_from_yaml() -> None:
    """强制重新从 YAML 加载（用于测试）"""
    global _profiles_cache, _groups_cache
    _profiles_cache = None
    _groups_cache = None
    _load_profiles_from_yaml()
    _load_groups_from_yaml()


# ============================================================
# 向后兼容: 模块级常量（懒加载从 YAML）
# ============================================================

class _LazyDict(dict):
    """懒加载字典 — 首次访问时从 YAML 加载"""

    def __init__(self, loader_func):
        self._loader_func = loader_func
        self._loaded = False
        super().__init__()

    def _ensure_loaded(self):
        if not self._loaded:
            data = self._loader_func()
            super().update(data)
            self._loaded = True

    def __getitem__(self, key):
        self._ensure_loaded()
        return super().__getitem__(key)

    def __contains__(self, key):
        self._ensure_loaded()
        return super().__contains__(key)

    def get(self, key, default=None):
        self._ensure_loaded()
        return super().get(key, default)

    def keys(self):
        self._ensure_loaded()
        return super().keys()

    def values(self):
        self._ensure_loaded()
        return super().values()

    def items(self):
        self._ensure_loaded()
        return super().items()

    def __iter__(self):
        self._ensure_loaded()
        return super().__iter__()

    def __len__(self):
        self._ensure_loaded()
        return super().__len__()


# 模块级常量 — 懒加载从 YAML（向后兼容）
TARGET_TYPE_GROUPS: Dict[str, str] = _LazyDict(_load_groups_from_yaml)
TARGET_CONVERTER_PROFILES: Dict[str, Dict[str, Any]] = _LazyDict(_load_profiles_from_yaml)


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
    return TARGET_TYPE_GROUPS.get(target_type, "llm_direct_strong")


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
    # 4. 低 ASR 链（兜底, ASR引导策略 新增）
    chains.extend(profile.get("low_asr_chains", []))

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
    low_asr = profile.get("low_asr_chains", [])

    if chain_name in high_asr:
        return high_asr.index(chain_name) + 1
    if chain_name in llm_assisted:
        return len(high_asr) + llm_assisted.index(chain_name) + 1
    if chain_name in medium_asr:
        return len(high_asr) + len(llm_assisted) + medium_asr.index(chain_name) + 1
    if chain_name in low_asr:
        return len(high_asr) + len(llm_assisted) + len(medium_asr) + low_asr.index(chain_name) + 1
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
            "low_asr": profile.get("low_asr_chains", []),
            "llm_assisted": profile.get("llm_assisted_chains", []),
            "bypass_mechanism": profile.get("bypass_mechanism", ""),
            "description": profile.get("description", ""),
            "model_filter": profile.get("model_filter", ""),
        })
    return summary


# ============================================================
# R4+R6: 动态链组合 + 模态验证
# ============================================================


def select_dynamic_converter_chains(
    target_type: str,
    objective_target: Any = None,
    converter_target_available: bool = True,
    max_chains: int = 12,
) -> List[str]:
    """
    R4+R6: 动态选择 Converter 链 — Target 感知 + 模态验证

    在 select_converter_chains_for_target 基础上增加:
    1. R4: 基于 Target 能力动态扩展链池（如多模态 Target 追加图片链）
    2. R6: 模态验证 — 过滤输出模态与 Target 不兼容的链

    Args:
        target_type: PyRIT Target 类型名
        objective_target: 目标 PromptTarget 实例（用于 R6 模态验证）
        converter_target_available: 是否有可用的 converter_target
        max_chains: 返回的最大链数量

    Returns:
        经过模态验证的有序 Converter 链名列表
    """
    # Step 1: 获取 Target 感知推荐链
    chains = select_converter_chains_for_target(
        target_type=target_type,
        converter_target_available=converter_target_available,
        max_chains=max_chains,
    )

    # Step 2 (R6): 模态验证 — 过滤不兼容链
    if objective_target is not None:
        from src.scenarios.technique_factories import CONVERTER_VARIANT_CHAINS, _is_chain_modality_compatible

        filtered: List[str] = []
        for chain_name in chains:
            chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
            if chain_info is None:
                # 未知链，保留（可能是 YAML 中新增的链）
                filtered.append(chain_name)
                continue

            if _is_chain_modality_compatible(
                chain_name=chain_name,
                chain_info=chain_info,
                objective_target=objective_target,
                target_type=target_type,
            ):
                filtered.append(chain_name)
            else:
                logger.debug(
                    f"R6: Filtered out modality-incompatible chain '{chain_name}' "
                    f"for target_type='{target_type}'"
                )

        chains = filtered

    return chains[:max_chains]


class TargetAwareConverterRouter:
    """
    Target-Aware Converter 路由器

    根据不同 Target 类型选择成功率最高的 Converter 链。
    可作为 ScenarioOrchestrator / AdaptiveScenario 的顾问组件。

    R3: Profile 数据从 YAML 加载（单一数据源）
    R4+R6: 支持动态链组合 + 模态验证

    Usage:
        router = TargetAwareConverterRouter()
        chains = router.select_chains("openai_chat", converter_target_available=True)
        # ["multi_encoding_v2", "stealth_evasion", "encoding_bypass", ...]

        # R4+R6: 动态链选择（含模态验证）
        chains = router.select_dynamic_chains(
            "openai_chat",
            objective_target=target,
            converter_target_available=True,
        )
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

    def select_dynamic_chains(
        self,
        target_type: str,
        objective_target: Any = None,
        converter_target_available: bool = True,
        max_chains: int = 12,
    ) -> List[str]:
        """R4+R6: 动态链选择（含模态验证）"""
        return select_dynamic_converter_chains(
            target_type=target_type,
            objective_target=objective_target,
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
    print("  Target-Aware Converter 链 Profile (R3: YAML-driven)")
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
