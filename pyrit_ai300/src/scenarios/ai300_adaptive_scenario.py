"""
AI-300 Adaptive Scenario — 原生 AdaptiveScenario + FailureTypeRoutingSelector
============================================================================

P0+P2: 用原生 AdaptiveScenario 替代自建 AttackUpgradeStrategy

原生 AdaptiveTechniqueDispatcher 构建 SequentialAttack(FIRST_SUCCESS)：
  - 自动按 selector 排序尝试多个技术
  - 成功即停止（提前停止）
  - epsilon-greedy 跨 objective 学习

v3.0 L5 优化（原生 extra_request_converters 替代变体预注册）：
  - _build_techniques_dict() 中使用原生 AttackTechniqueFactory.create(extra_request_converters=...)
    为每个基础技术动态创建 Converter 变体 TechniqueBundle
  - 不再在 Registry 中预注册 110+ 个变体工厂，Registry 仅保留 ~34 个基础技术
  - 变体通过 extra_request_converters 追加 Converter（原生渐进式升级机制）
  - 原生 FIRST_SUCCESS 自动在首个成功变体处停止
  - _get_attack_technique_factories() 简化为仅 super()（消除双重调用）

L5 增强：ModalityRouter 集成 + Target-Aware 自动推断
  - _build_techniques_dict() 中调用 ModalityRouter 过滤不支持的技术
  - 自动从 objective_target 推断 target_type（无需手动传入）
  - 原生 TargetCapabilities 驱动的模态感知技术筛选

P1-A: SelectorScope 限定学习范围
  - 支持 all_runs()（默认，跨 run 学习）和 current_run()（仅当前 run）
  - 避免跨模型/跨场景的历史数据干扰

FailureTypeRoutingSelector 增加失败类型路由：
  - model_refusal → Converter 变体优先（编码/混淆绕过）
  - timeout → 基础单轮技术优先（减少执行时间）
  - objective_not_achieved → 强技术 + Converter 变体优先

v3.0 变更：
  - P0-B: extra_request_converters 替代变体预注册（原生渐进式升级）
  - P1-A: SelectorScope 限定学习范围
  - P1-B: 移除 per_attack_timeout（原生 max_retries + max_concurrency 足够）
  - P1-C: _get_attack_technique_factories() 简化为仅 super()
"""

import logging
import os
import re
from typing import Any

from pyrit.common import apply_defaults
from pyrit.models import Parameter
from pyrit.models.target.target_capabilities import CapabilityName
from pyrit.prompt_target.common.target_requirements import TargetRequirements
from pyrit.scenario import DatasetAttackConfiguration
from pyrit.scenario.core.scenario_technique import ScenarioTechnique
from pyrit.scenario.scenarios.adaptive import (
    AdaptiveScenario,
    TechniqueSelector,
)
from pyrit.scenario.scenarios.adaptive.selectors import SelectorScope

from src.scenarios.ai300_technique import AI300Technique
from src.scenarios.failure_type_selector import FailureTypeRoutingSelector

logger = logging.getLogger(__name__)


# ============================================================
# L5: 小模型检测 — 自动跳过 LLM 链避免 converter 失败
# ============================================================

# 已知的小模型模式（参数量过小无法可靠生成 JSON）
# 这些模型的 converter（PersuasionConverter/DecompositionConverter 等）
# 无法可靠生成 JSON 输出，导致 InvalidJsonException 使整个 atomic attack 失败
_SMALL_MODEL_PATTERNS: list[str] = [
    "0.5b", "0.6b", "0.8b", "1b", "1.0b", "1.3b", "1.5b", "1.7b", "1.8b", "2b", "2.0b",
    "tiny", "mini", "small", "nano",
    "qwen2:0.5", "qwen2:1", "qwen3:0", "qwen3:1",
    "gemma2:2", "phi3:mini", "phi3:3.8",
]


def _is_small_model(model_name: str) -> bool:
    """
    检测模型是否过小（无法可靠支持 LLM-based converter）

    LLM-based converter（如 PersuasionConverter/DecompositionConverter）需要
    模型能可靠生成 JSON 格式输出。小模型（<3B 参数）通常无法做到。

    检测方式：
    1. 模型名包含已知小模型模式（如 qwen3:1.7b）
    2. 参数量标识 <3B（如 0.6b/1.7b/2b）

    Args:
        model_name: 模型名称（如 "qwen3:1.7b", "gpt-4o"）

    Returns:
        True 如果模型被认为过小
    """
    if not model_name:
        return False

    name_lower = model_name.lower()

    # 检查已知小模型模式
    for pattern in _SMALL_MODEL_PATTERNS:
        if pattern in name_lower:
            return True

    # 检查参数量标识（如 "0.6b", "1.7b", "8b"）
    # ≤14B 的模型无法可靠生成 JSON（PersuasionConverter/DecompositionConverter 需要 JSON）
    import re as _re
    param_match = _re.search(r'(\d+\.?\d*)b\b', name_lower)
    if param_match:
        try:
            param_size = float(param_match.group(1))
            if param_size <= 14.0:
                return True
        except ValueError:
            pass

    return False


def _should_skip_llm_chains(converter_target: Any) -> bool:
    """
    判断是否应跳过 LLM-based converter 链

    跳过条件（任一满足即跳过）：
    1. 环境变量 CONVERTER_LLM_CHAINS_ENABLED=false 时总是跳过
    2. 自动检测：converter_target 的模型名为 'weak' tier（≤14B）
       使用 infer_model_tier_static() 统一分层标准
    """
    # 1. 环境变量显式控制
    env_val = os.getenv("CONVERTER_LLM_CHAINS_ENABLED", "auto").lower().strip()
    if env_val in ("false", "0", "no", "disabled", "off"):
        return True
    if env_val in ("true", "1", "yes", "enabled", "on"):
        return False

    # 2. auto 模式：检测 converter_target 的模型分层
    if converter_target is not None:
        # 类型安全地提取模型名（处理 RateLimitedTarget 等包装器）
        model_name = ""
        for attr in ("_model_name", "model_name", "_deployment_name"):
            val = getattr(converter_target, attr, "")
            if isinstance(val, str) and val:
                model_name = val
                break

        if model_name:
            # 使用统一的分层标准（与侦察阶段一致）
            from src.recon.recon_engine import infer_model_tier_static
            tier = infer_model_tier_static(model_name)
            if tier == "weak":
                logger.info(
                    f"Auto-detected weak converter model '{model_name}' (tier={tier}), "
                    f"skipping LLM-based converter chains to avoid InvalidJsonException"
                )
                return True

    return False


# ============================================================
# L5: Target 类型自动推断映射
# ============================================================

# PyRIT Target 类名 → target_type 映射
# 用于从 objective_target 实例自动推断 target_type，无需手动传入
_TARGET_CLASS_NAME_MAP: dict[str, str] = {
    "OpenAIChatTarget": "openai_chat",
    "OpenAIResponseTarget": "openai_responses",
    "LiteLLMChatTarget": "litellm",
    "AzureMLChatTarget": "azure_ml",
    "PromptShieldTarget": "prompt_shield",
    "PlaywrightTarget": "playwright",
    "PlaywrightCopilotTarget": "playwright_copilot",
    "CopilotTarget": "websocket_copilot",
    "WebSocketCopilotTarget": "websocket_copilot",
    "HTTPTarget": "http_api",
    "AzureBlobStorageTarget": "azure_blob",
    "OpenAIImageTarget": "openai_image",
    "OpenAIVideoTarget": "openai_video",
    "OpenAITTSTarget": "openai_tts",
}


class AI300EpsilonGreedySelector(FailureTypeRoutingSelector):
    """
    AI-300 Epsilon-Greedy 技术选择器（增强版）

    继承 FailureTypeRoutingSelector，在 EpsilonGreedyTechniqueSelector 基础上增加：
    1. 失败类型路由（替代自建 AttackUpgradeStrategy 的失败类型分析）
    2. 考试最优参数预设（epsilon=0.2, random_seed=42）
    3. Converter 变体感知排序（P1 增强）
    4. 编码攻击优先策略（考试快速高成功率）
    5. Target 类型感知优先级（P3 增强）
    6. OWASP 策略映射初始偏好（v2.0 — 消除双轨风险）
    7. SelectorScope 限定学习范围（P1-A — 跨 run vs 当前 run）
    8. ASR引导策略: 学术 ASR 先验排序 + strategy_mode 切换
    """

    def __init__(
        self,
        epsilon: float = 0.2,
        random_seed: int | None = 42,
        target_type: str | None = None,
        owasp_id: str | None = None,
        scope: SelectorScope | None = None,
        strategy_mode: str = "academic",
        model_name: str = "gpt-4o",
        model_tier: str = "unknown",
    ) -> None:
        super().__init__(
            epsilon=epsilon,
            random_seed=random_seed,
            target_type=target_type,
            owasp_id=owasp_id,
            scope=scope,
            strategy_mode=strategy_mode,
            model_name=model_name,
            model_tier=model_tier,
        )


class AI300AdaptiveScenario(AdaptiveScenario):
    """
    AI-300 自适应 Scenario — 原生 AdaptiveScenario + 失败类型路由 + Converter 变体

    用原生 AdaptiveScenario 替代自建 AttackUpgradeStrategy + ScenarioOrchestrator 升级重试。
    原生 AdaptiveTechniqueDispatcher 自动构建 SequentialAttack(FIRST_SUCCESS)：
      - 按 selector 排序尝试多个技术（含 Converter 变体）
      - 成功即停止（提前停止）
      - 成本 O(max_attempts x objectives) 而非 O(techniques x objectives)

    v3.0 增强：原生 extra_request_converters 渐进式 Converter 升级
      - _build_techniques_dict() 为每个基础技术动态创建 Converter 变体 bundles
      - 使用原生 AttackTechniqueFactory.create(extra_request_converters=...) 追加 Converter
      - Registry 仅保留基础技术（~34 个），不再预注册 110+ 变体工厂
      - 原生 FIRST_SUCCESS 自动在首个成功变体处停止

    FailureTypeRoutingSelector 在 epsilon-greedy 基础上增加失败类型路由：
      - model_refusal → Converter 变体优先
      - timeout → 基础单轮技术优先
      - objective_not_achieved → 强技术 + Converter 变体优先

    原生弹性恢复：
      - max_retries: Scenario 级别重试（原生弹性恢复）
      - max_concurrency: 原生 AttackExecutor 并发控制
      - 自动恢复（中断后可 resume）

    Usage:
        scenario = AI300AdaptiveScenario()
        scenario.set_params_from_args(args={
            "objective_target": target,
            "max_attempts_per_objective": 3,
        })
        await scenario.initialize_async()
        result = await scenario.run_async()
        # 原生 tqdm 进度条自动显示
        # 原生 max_retries 自动重试
        # 原生自动恢复（中断后可 resume）
    """

    VERSION: int = 1

    # L5: 能力需求 — 自适应 Scenario 需要多轮对话 + 系统提示词
    # 与 AI300Scenario 一致，初始化时由原生 Scenario.initialize_async() 验证
    TARGET_REQUIREMENTS: TargetRequirements = TargetRequirements(
        required=frozenset({CapabilityName.MULTI_TURN, CapabilityName.SYSTEM_PROMPT})
    )

    # ------------------------------------------------------------------
    # Abstract method implementations (required by AdaptiveScenario)
    # ------------------------------------------------------------------

    @classmethod
    def _atomic_attack_prefix(cls) -> str:
        """Return the prefix for per-objective atomic-attack names."""
        return "ai300_adaptive"

    @classmethod
    def get_technique_class(cls) -> type[ScenarioTechnique]:
        """Return the scenario's technique enum."""
        return AI300Technique

    @classmethod
    def default_dataset_config(cls) -> DatasetAttackConfiguration:
        """Return the default DatasetAttackConfiguration for AI-300 adaptive runs."""
        return DatasetAttackConfiguration(
            dataset_names=[
                "airt_hate",
                "airt_violence",
                "airt_harassment",
                "airt_misinformation",
                "airt_leakage",
            ],
            max_dataset_size=4,
        )

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    @apply_defaults
    def __init__(
        self,
        *,
        selector: TechniqueSelector | None = None,
        objective_scorer=None,
        converter_target: Any = None,
        target_type: str | None = None,
        owasp_id: str | None = None,
        scenario_result_id: str | None = None,
        scope: SelectorScope | None = None,
        strategy_mode: str = "academic",
        model_name: str = "gpt-4o",
        model_tier: str = "unknown",
    ) -> None:
        """
        初始化 AI-300 自适应 Scenario

        Args:
            selector: 技术选择器，None 时使用 AI300EpsilonGreedySelector（含失败类型路由）
            objective_scorer: 目标评分器
            converter_target: LLM 辅助 Converter 所需的目标 PromptTarget（通常为 judge_target）
            target_type: PyRIT Target 类型名（如 "openai_chat"），用于 Target 感知排序
            owasp_id: OWASP ID（如 "LLM01"），用于 v2.0 策略偏好初始排序
            scenario_result_id: 恢复 ID
            scope: SelectorScope 限定学习范围（默认 all_runs，跨 run 学习）
            strategy_mode: ASR引导策略 策略模式
                - "academic": 策略级优先, JailbreakBench 先验 (默认)
                - "exam": 编码优先, 快速验证
                - "balanced": 策略 + 编码交替
            model_name: 目标模型名称（影响 ASR 先验值，如 "gpt-4o"）
            model_tier: 模型过滤强度等级 ("strong"/"moderate"/"weak"/"unknown")
                影响初始技术偏好:
                - strong: 多轮迭代优先 (Tier S→A→B→encoding)
                - moderate: 策略+编码交替 (Tier S→A→encoding→B)
                - weak: 编码优先 (类似 exam 模式)
        """
        # P2: 保存 converter_target 用于构建 Converter 变体（在 super().__init__ 之前）
        self._converter_target = converter_target
        # L5: 保存 target_type 用于后续自动推断和过滤
        self._target_type = target_type
        # R2: objective_target 在 _build_techniques_dict 时存储
        self._objective_target: Any = None

        # P3: 如果没有传入 selector，创建带 target_type 和 owasp_id 的 AI300EpsilonGreedySelector
        if selector is None:
            selector = AI300EpsilonGreedySelector(
                target_type=target_type,
                owasp_id=owasp_id,
                scope=scope,
                strategy_mode=strategy_mode,
                model_name=model_name,
                model_tier=model_tier,
            )
        else:
            if target_type and hasattr(selector, "set_target_type"):
                selector.set_target_type(target_type)
            if owasp_id and hasattr(selector, "set_owasp_id"):
                selector.set_owasp_id(owasp_id)
            # ASR引导策略: 传播 strategy_mode 和 model_name 和 model_tier
            if hasattr(selector, "set_strategy_mode"):
                selector.set_strategy_mode(strategy_mode)
            if hasattr(selector, "set_model_tier"):
                selector.set_model_tier(model_tier)

        # 使用 FailureTypeRoutingSelector 替代自建 AttackUpgradeStrategy
        super().__init__(
            objective_scorer=objective_scorer,
            selector=selector,
            scenario_result_id=scenario_result_id,
        )

    @staticmethod
    def _infer_target_type(objective_target: Any) -> str | None:
        """
        L5: 从 objective_target 实例自动推断 target_type

        按优先级依次尝试：
        1. 目标实例的 _target_type 属性
        2. 目标类名在 _TARGET_CLASS_NAME_MAP 中的映射
        3. CamelCase → snake_case 转换后匹配已知 target_type

        Args:
            objective_target: PyRIT PromptTarget 实例

        Returns:
            target_type 字符串（如 "openai_chat"），无法推断时返回 None
        """
        if objective_target is None:
            return None

        # 1. 检查 _target_type 属性
        target_type = getattr(objective_target, "_target_type", None)
        if target_type:
            return target_type

        # 2. 类名直接映射
        class_name = type(objective_target).__name__
        if class_name in _TARGET_CLASS_NAME_MAP:
            return _TARGET_CLASS_NAME_MAP[class_name]

        # 3. CamelCase → snake_case 转换
        snake_name = re.sub(
            r"([A-Z]+)([A-Z][a-z])", r"\1_\2",
            re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", class_name)
        ).lower().replace("_target", "")
        # 检查是否匹配已知 target type
        from src.converters.target_aware_router import TARGET_TYPE_GROUPS
        if snake_name in TARGET_TYPE_GROUPS:
            return snake_name

        logger.debug(f"Could not infer target_type from class '{class_name}'")
        return None

    @classmethod
    def additional_parameters(cls) -> list[Parameter]:
        """
        声明自适应专用参数

        v3.0: 移除 per_attack_timeout（原生 max_retries + max_concurrency 足够）
        其余参数（max_retries, max_concurrency 等）由原生 Scenario 基类提供。

        Returns:
            - max_attempts_per_objective: 每个 objective 最大尝试次数（默认 3）
        """
        return [
            Parameter(
                name="max_attempts_per_objective",
                description="Max techniques tried per objective. Defaults to 3.",
                param_type=int,
                default=3,
            ),
        ]

    def _get_attack_technique_factories(self) -> dict[str, Any]:
        """
        P1-C v3.0: 简化为仅 super()（消除双重调用）

        原生方法从 catalog + registry 获取基础技术工厂。
        v2.0 在此追加 Converter 变体工厂，但 v3.0 不再需要：
        变体在 _build_techniques_dict() 中通过原生 extra_request_converters
        动态创建，无需预注册变体工厂到 Registry。

        Returns:
            技术名 → AttackTechniqueFactory 映射（仅基础技术）
        """
        return super()._get_attack_technique_factories()

    def _build_techniques_dict(
        self,
        *,
        objective_target: Any,
    ) -> dict[str, Any]:
        """
        v3.0: 覆盖原生方法，使用原生 extra_request_converters 创建 Converter 变体

        原生 _build_techniques_dict 只遍历 self._scenario_techniques（枚举值），
        但 Converter 变体名（如 "prompt_sending+stealth_evasion"）不在枚举中，
        导致变体工厂虽已注册但从未被选中。

        v3.0 方案（原生 extra_request_converters）：
        1. L5: 自动推断 target_type（如未手动传入）
        2. 调用 super() 获取基础技术的 TechniqueBundle dict
        3. L5: ModalityRouter 过滤 — 移除 Target 不支持的技术
        4. 从 super()._get_attack_technique_factories() 获取基础工厂
        5. 为已解析基础技术，使用 factory.create(extra_request_converters=...)
           动态创建 Converter 变体 TechniqueBundle
        6. 返回合并后的 dict（含基础 + 变体）

        原生 API 支持：
        AttackTechniqueFactory.create(extra_request_converters=...) 在已有 Converter
        基础上追加（additive），而非替换。这实现了渐进式 Converter 升级链：
          attempt 1: prompt_sending (无 Converter)
          attempt 2: prompt_sending + stealth_evasion (追加 Converter)
          attempt 3: prompt_sending + encoding_bypass (追加不同 Converter)

        这样原生 AdaptiveTechniqueDispatcher 的 SequentialAttack(FIRST_SUCCESS)
        就能按 selector 排序尝试 Converter 变体，成功即停止。
        """
        # L5: 自动推断 target_type（如未手动传入）
        if not self._target_type:
            inferred_type = self._infer_target_type(objective_target)
            if inferred_type:
                self._target_type = inferred_type
                # 同步到 selector
                selector = getattr(self, "_selector", None)
                if selector and hasattr(selector, "set_target_type"):
                    selector.set_target_type(inferred_type)
                logger.info(f"L5: Auto-inferred target_type='{inferred_type}' "
                            f"from {type(objective_target).__name__}")

        # R2: 存储 objective_target 供后续使用
        self._objective_target = objective_target

        # 1. 获取基础技术 bundles（原生枚举驱动）
        base_techniques = super()._build_techniques_dict(
            objective_target=objective_target,
        )

        # L5: ModalityRouter 过滤 — 移除 Target 不支持的技术
        base_techniques = self._filter_by_modality(
            base_techniques, objective_target
        )

        # 2. 获取基础工厂（P1-C: 仅 super()，不含变体）
        factories = self._get_attack_technique_factories()

        # 3. 找出已解析的基础技术名
        from src.scenarios.technique_factories import (
            CONVERTER_VARIANT_CHAINS,
            BASE_TECHNIQUES_FOR_VARIANTS,
            _is_chain_modality_compatible,
            _get_dynamic_chain_mapping,
        )
        from pyrit.models.identifiers import compute_inner_attack_eval_hash
        from pyrit.scenario.scenarios.adaptive import TechniqueBundle

        resolved_base_names = {b.name for b in base_techniques.values()}

        # 4. P0-B: 为已解析基础技术动态创建 Converter 变体 bundles
        #    使用原生 extra_request_converters 追加 Converter（渐进式升级）
        variant_count = 0
        skipped_llm = 0
        skipped_modality = 0
        skipped_runtime = 0
        skipped_no_factory = 0
        skipped_small_model = 0

        # L5: 小模型检测 — 自动跳过 LLM-based converter 链
        # 小模型无法可靠生成 JSON，导致 PersuasionConverter/DecompositionConverter
        # 抛出 InvalidJsonException，使整个 atomic attack 失败
        skip_llm_chains = _should_skip_llm_chains(self._converter_target)
        # 诊断信息（存储为实例属性，供 adaptive_runner 在 initialize_async 后结构化展示）
        _conv_type = type(self._converter_target).__name__ if self._converter_target else "None"
        _conv_model_diag = ""
        if self._converter_target is not None:
            for attr in ("_model_name", "model_name", "_deployment_name"):
                val = getattr(self._converter_target, attr, "")
                if isinstance(val, str) and val:
                    _conv_model_diag = val
                    break
        self._diag_converter_type = _conv_type
        self._diag_converter_model = _conv_model_diag
        self._diag_skip_llm_chains = skip_llm_chains
        logger.info(
            f"Converter target: type={_conv_type}, model={_conv_model_diag}, "
            f"skip_llm_chains={skip_llm_chains}"
        )
        if skip_llm_chains:
            logger.info(
                "LLM-based converter chains disabled (small model detected or "
                "CONVERTER_LLM_CHAINS_ENABLED=false). Only non-LLM chains will be used."
            )

        # R0: 获取 Target 感知动态链映射
        dynamic_mapping = _get_dynamic_chain_mapping(
            target_type=self._target_type,
            converter_target_available=(self._converter_target is not None),
        )
        chain_mapping = dynamic_mapping if dynamic_mapping else BASE_TECHNIQUES_FOR_VARIANTS

        from src.converters.converter_registry import load_preset_converter_chain

        for base_tech_name in resolved_base_names:
            # 只为支持变体的基础技术创建变体
            if base_tech_name not in chain_mapping:
                continue

            factory = factories.get(base_tech_name)
            if factory is None:
                skipped_no_factory += 1
                continue

            # 获取该基础技术的推荐 Converter 链
            chain_names = chain_mapping[base_tech_name]

            for chain_name in chain_names:
                chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
                if chain_info is None:
                    continue

                # 过滤 1: 需要运行时参数的链跳过
                if chain_info.get("requires_runtime_params", False):
                    skipped_runtime += 1
                    continue

                # 过滤 2: LLM 链需要 converter_target
                if chain_info["requires_llm"] and self._converter_target is None:
                    skipped_llm += 1
                    continue

                # 过滤 2b (L5): 小模型跳过 LLM 链
                # 小模型无法可靠生成 JSON，会导致 InvalidJsonException
                if chain_info["requires_llm"] and skip_llm_chains:
                    skipped_small_model += 1
                    continue

                # 过滤 3 (R2): 模态兼容性检测
                if objective_target is not None:
                    if not _is_chain_modality_compatible(
                        chain_name=chain_name,
                        chain_info=chain_info,
                        objective_target=objective_target,
                        target_type=self._target_type,
                    ):
                        skipped_modality += 1
                        continue

                # 加载 Converter 链配置
                try:
                    converter_config = load_preset_converter_chain(
                        chain_name=chain_name,
                        converter_target=self._converter_target,
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to load converter chain '{chain_name}' for "
                        f"variant '{base_tech_name}+{chain_name}': {e}"
                    )
                    continue

                if converter_config is None:
                    continue

                # P0-B: 提取 request_converters 用于原生 extra_request_converters
                extra_converters = converter_config.request_converters
                if not extra_converters:
                    continue

                variant_name = f"{base_tech_name}+{chain_name}"

                # 构建变体的 scoring config
                scoring_config = self._build_scoring_config_for_factory(factory=factory)
                if scoring_config is None:
                    continue

                # P0-B: 使用原生 extra_request_converters 创建变体
                try:
                    technique = factory.create(
                        objective_target=objective_target,
                        attack_scoring_config=scoring_config,
                        extra_request_converters=extra_converters,
                    )
                except (TypeError, ValueError) as exc:
                    logger.warning(
                        f"Skipping converter variant '{variant_name}': {exc}"
                    )
                    continue

                eval_hash = compute_inner_attack_eval_hash(attack=technique.attack)

                # 不覆盖已有的（幂等）
                if eval_hash in base_techniques:
                    continue

                adversarial_chat = factory.adversarial_chat
                if adversarial_chat is None and factory.uses_adversarial:
                    try:
                        from pyrit.executor.attack.core.attack_config import (
                            get_default_adversarial_target,
                        )
                        adversarial_chat = get_default_adversarial_target()
                    except Exception:
                        pass

                base_techniques[eval_hash] = TechniqueBundle(
                    attack=technique.attack,
                    name=variant_name,
                    seed_technique=technique.seed_technique,
                    adversarial_chat=adversarial_chat,
                )
                variant_count += 1

        # R0 fallback: 如果动态映射的所有链都被过滤，回退到静态映射
        if variant_count == 0 and dynamic_mapping is not None:
            logger.info(
                "R0: Dynamic mapping produced 0 variants after filtering, "
                "falling back to static mapping"
            )
            for base_tech_name in resolved_base_names:
                if base_tech_name not in BASE_TECHNIQUES_FOR_VARIANTS:
                    continue

                factory = factories.get(base_tech_name)
                if factory is None:
                    continue

                for chain_name in BASE_TECHNIQUES_FOR_VARIANTS[base_tech_name]:
                    chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
                    if chain_info is None:
                        continue

                    if chain_info.get("requires_runtime_params", False):
                        continue
                    if chain_info["requires_llm"] and self._converter_target is None:
                        continue

                    if objective_target is not None:
                        if not _is_chain_modality_compatible(
                            chain_name=chain_name,
                            chain_info=chain_info,
                            objective_target=objective_target,
                            target_type=self._target_type,
                        ):
                            continue

                    try:
                        converter_config = load_preset_converter_chain(
                            chain_name=chain_name,
                            converter_target=self._converter_target,
                        )
                    except Exception:
                        continue

                    if converter_config is None:
                        continue

                    extra_converters = converter_config.request_converters
                    if not extra_converters:
                        continue

                    variant_name = f"{base_tech_name}+{chain_name}"
                    scoring_config = self._build_scoring_config_for_factory(factory=factory)
                    if scoring_config is None:
                        continue

                    try:
                        technique = factory.create(
                            objective_target=objective_target,
                            attack_scoring_config=scoring_config,
                            extra_request_converters=extra_converters,
                        )
                    except (TypeError, ValueError):
                        continue

                    eval_hash = compute_inner_attack_eval_hash(attack=technique.attack)
                    if eval_hash in base_techniques:
                        continue

                    adversarial_chat = factory.adversarial_chat
                    if adversarial_chat is None and factory.uses_adversarial:
                        try:
                            from pyrit.executor.attack.core.attack_config import (
                                get_default_adversarial_target,
                            )
                            adversarial_chat = get_default_adversarial_target()
                        except Exception:
                            pass

                    base_techniques[eval_hash] = TechniqueBundle(
                        attack=technique.attack,
                        name=variant_name,
                        seed_technique=technique.seed_technique,
                        adversarial_chat=adversarial_chat,
                    )
                    variant_count += 1

        # 存储诊断统计供 adaptive_runner 结构化展示
        self._diag_total_techniques = len(base_techniques)
        self._diag_variant_count = variant_count
        self._diag_skipped_llm = skipped_llm
        self._diag_skipped_small_model = skipped_small_model
        self._diag_skipped_modality = skipped_modality
        self._diag_skipped_runtime = skipped_runtime
        self._diag_skipped_no_factory = skipped_no_factory

        logger.info(
            f"AI300AdaptiveScenario._build_techniques_dict: "
            f"{len(base_techniques)} total techniques "
            f"({variant_count} converter variants via extra_request_converters, "
            f"skipped: llm={skipped_llm}, small_model={skipped_small_model}, "
            f"modality={skipped_modality}, "
            f"runtime={skipped_runtime}, no_factory={skipped_no_factory})"
        )

        # 将 eval_hash → technique_name 映射传递给 selector
        # 原生 dispatcher 使用 eval_hash 作为 technique_identifiers，
        # 但 FailureTypeRoutingSelector 的排序逻辑基于技术名。
        hash_to_name = {h: b.name for h, b in base_techniques.items()}
        selector = getattr(self, "_selector", None)
        if selector is not None and hasattr(selector, "set_hash_name_mapping"):
            selector.set_hash_name_mapping(hash_to_name)

        return base_techniques

    def _filter_by_modality(
        self,
        techniques: dict[str, Any],
        objective_target: Any,
    ) -> dict[str, Any]:
        """
        L5: ModalityRouter 过滤 — 移除 Target 不支持的技术

        使用原生 TargetCapabilities 检查：
        - 多轮攻击技术 → 检查 supports_multi_turn
        - 不支持的技术被移除，避免无效执行

        Args:
            techniques: eval_hash → TechniqueBundle 映射
            objective_target: 目标 PromptTarget 实例

        Returns:
            过滤后的 techniques dict
        """
        try:
            from src.executor.attack.core.modality_router import ModalityRouter
            from pyrit.prompt_target.common.target_capabilities import CapabilityName

            caps = ModalityRouter.get_capabilities(objective_target)
            supports_multi_turn = caps.includes(capability=CapabilityName.MULTI_TURN)
        except Exception as e:
            logger.debug(f"ModalityRouter check skipped: {e}")
            return techniques

        if supports_multi_turn:
            # 支持多轮，无需过滤
            return techniques

        # 不支持多轮 — 过滤掉多轮技术
        from src.scenarios.failure_type_selector import _MULTI_TURN_TECHNIQUES
        from src.scenarios.technique_factories import get_base_technique_from_variant

        filtered: dict[str, Any] = {}
        skipped_count = 0
        for eval_hash, bundle in techniques.items():
            tech_name = bundle.name
            base_tech = get_base_technique_from_variant(tech_name)
            if base_tech in _MULTI_TURN_TECHNIQUES:
                skipped_count += 1
                logger.debug(
                    f"ModalityRouter: skipping '{tech_name}' "
                    f"(target doesn't support multi_turn)"
                )
            else:
                filtered[eval_hash] = bundle

        if skipped_count > 0:
            logger.info(
                f"L5 ModalityRouter: filtered out {skipped_count} multi-turn techniques "
                f"(target doesn't support multi_turn)"
            )

        return filtered

    # ------------------------------------------------------------------
    # Converter 变体展示
    # ------------------------------------------------------------------

    @staticmethod
    def get_converter_variants_summary() -> list[dict[str, Any]]:
        """
        获取所有可用 Converter 变体的摘要信息

        返回每个变体的基础技术、链名、描述、是否需要 LLM、优先级等信息。
        用于在执行前展示 executor 将使用的 Converter 类型/组合。

        Returns:
            变体信息列表，每项包含:
            - variant_name: 变体全名（如 "prompt_sending+stealth_evasion"）
            - base_technique: 基础技术名
            - converter_chain: Converter 链名
            - description: 描述
            - requires_llm: 是否需要 LLM
            - priority: 优先级（数字越小越优先）
        """
        from src.scenarios.technique_factories import (
            BASE_TECHNIQUES_FOR_VARIANTS,
            CONVERTER_VARIANT_CHAINS,
            AI300_TECHNIQUE_METADATA,
        )

        summary: list[dict[str, Any]] = []
        for base_tech, chain_names in BASE_TECHNIQUES_FOR_VARIANTS.items():
            meta = AI300_TECHNIQUE_METADATA.get(base_tech, {})
            for chain_name in chain_names:
                chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
                summary.append({
                    "variant_name": f"{base_tech}+{chain_name}",
                    "base_technique": base_tech,
                    "converter_chain": chain_name,
                    "description": f"{meta.get('description', '')} + {chain_info.get('description', '')}",
                    "requires_llm": chain_info.get("requires_llm", False),
                    "priority": chain_info.get("priority", 99),
                })
        return summary

    @staticmethod
    def display_converter_variants(
        *,
        verbose: bool = True,
        attack_plans: list[Any] | None = None,
    ) -> int:
        """
        展示所有可用的 Converter 变体类型/组合（分组卡片式）

        v5.0: 支持可选 attack_plans 参数，仅展示实际选中技术的 Converter 组合。
        当 attack_plans=None 时，保持全局展示行为（向后兼容）。

        在 pipeline 执行前调用，让用户了解 executor 将使用哪些 Converter 组合。
        原生 AdaptiveTechniqueDispatcher 会按 selector 排序尝试这些变体，
        FIRST_SUCCESS 策略在首个成功变体处自动停止。

        输出格式：按基础技术分组，每张卡片展示：
        - 技术名称与描述（人类可读）
        - 攻击模式（多轮/单轮）与学术 ASR
        - 该技术将尝试的 Converter 链列表（含描述、LLM 标记、优先级）

        Args:
            verbose: True 时打印格式化卡片，False 时仅返回数量
            attack_plans: 可选的攻击计划列表，仅展示其中包含的技术

        Returns:
            可用变体总数
        """
        summary = AI300AdaptiveScenario.get_converter_variants_summary()
        if not verbose:
            return len(summary)

        from src.scenarios.technique_factories import (
            BASE_TECHNIQUES_FOR_VARIANTS,
            CONVERTER_VARIANT_CHAINS,
            AI300_TECHNIQUE_METADATA,
        )

        # ── 技术模式中文名映射 ──
        _MODE_CN = {"multi_turn": "多轮迭代", "single_turn": "单轮直发"}

        # ── 技术 ASR 查询 (惰性导入, 避免循环依赖) ──
        try:
            from src.payloads.technique_name_mapper import get_normalized_asr
            from src.scenarios.asr_strategy_display import _get_tier
        except Exception:
            get_normalized_asr = None  # type: ignore
            _get_tier = None  # type: ignore

        # v5.0: 如果提供了 attack_plans，仅展示实际选中的技术
        if attack_plans is not None:
            selected_techs = set()
            for plan in attack_plans:
                tech = getattr(plan, "attack_technique", "")
                if tech:
                    selected_techs.add(tech)
            # 过滤 BASE_TECHNIQUES_FOR_VARIANTS 仅保留选中的技术
            tech_chain_map = {
                tech: chains for tech, chains in BASE_TECHNIQUES_FOR_VARIANTS.items()
                if tech in selected_techs
            }
        else:
            tech_chain_map = dict(BASE_TECHNIQUES_FOR_VARIANTS)

        # 过滤 summary 仅保留选中技术的变体
        if attack_plans is not None:
            summary = [v for v in summary if v["base_technique"] in selected_techs]

        total_non_llm = sum(1 for v in summary if not v["requires_llm"])
        total_llm = sum(1 for v in summary if v["requires_llm"])

        # ── 主标题: 双线装饰框 + ★ 强调 (无右边缘, 避免 CJK 宽度问题) ──
        W = 68
        print()
        print("  ╔" + "═" * W + "╗")
        print()
        title = "攻击技术 × Converter 组合矩阵"
        if attack_plans is not None:
            title += f" ({len(selected_techs)} 技术)"
        print(f"       ★  {title}  ★")
        print()
        print("    每个目标按优先级依次尝试 · 首次成功即停止 (FIRST_SUCCESS)")
        print()
        print("  ╚" + "═" * W + "╝")

        for base_tech, chain_names in tech_chain_map.items():
            meta = AI300_TECHNIQUE_METADATA.get(base_tech, {})
            tech_desc = meta.get("description", base_tech)
            tags = meta.get("tags", [])
            mode = "multi_turn" if "multi_turn" in tags else "single_turn"
            mode_cn = _MODE_CN.get(mode, mode)

            # ASR 信息
            asr_str = ""
            if get_normalized_asr and _get_tier:
                try:
                    asr = get_normalized_asr(base_tech)
                    tier = _get_tier(asr)
                    asr_str = f"  |  学术 ASR: {asr:.0%} (Tier {tier})"
                except Exception:
                    pass

            # 该技术可用的 Converter 链 (按优先级排序)
            chains_info = []
            for cn in chain_names:
                ci = CONVERTER_VARIANT_CHAINS.get(cn, {})
                chains_info.append({
                    "name": cn,
                    "desc": ci.get("description", ""),
                    "llm": ci.get("requires_llm", False),
                    "priority": ci.get("priority", 99),
                })
            chains_info.sort(key=lambda x: x["priority"])

            # ── 技术卡片: 双线边框 + ◆ 强调标题 ──
            print()
            print("  ┏" + "━" * W)
            print(f"  ┃  ◆ {base_tech} · {tech_desc}")
            print(f"  ┃    模式: {mode_cn}{asr_str}")
            print("  ┃")
            print("  ┃    将依次尝试以下 Converter 增强:")
            for ci in chains_info:
                llm_tag = "[LLM]  " if ci["llm"] else "[非LLM]"
                print(f"  ┃      P{ci['priority']}  {llm_tag}  {ci['name']}")
                if ci["desc"]:
                    print(f"  ┃            └─ {ci['desc']}")
            if mode == "multi_turn":
                print("  ┃")
                print(f"  ┃    执行流程: {base_tech} 逐轮升级 → 末轮注入 Converter → 首次成功即停止")
            else:
                print("  ┃")
                print(f"  ┃    执行流程: {base_tech} + Converter 变换 → 按优先级依次尝试 → 首次成功即停止")
            print("  ┗" + "━" * W)

        # ── 汇总: ■ 强调 ──
        print()
        print("  " + "═" * W)
        print(f"  ■ 汇总: {len(summary)} 个变体组合 "
              f"(非 LLM: {total_non_llm} 个 | LLM: {total_llm} 个)")
        print("  ■ 策略: 自适应选择 → 失败类型路由 → 首次成功停止")
        print("  ■ 机制: PyRIT 原生 extra_request_converters 渐进式追加")
        print("  " + "═" * W)
        print()
        return len(summary)
