"""
AI-300 Initializers — 对齐 PyRIT built-in initializers (L5 原生优先)
===================================================================

PyRIT 1.0.0 PyRIT Initializers 文档定义五大内置初始化器：
  1. TargetInitializer — 从环境变量注册 Target 到 TargetRegistry
  2. ScorerInitializer — 注册默认 Scorer 到 ScorerRegistry
  3. TechniqueInitializer — 注册攻击技术到 AttackTechniqueRegistry
  4. LoadDefaultDatasets — 加载数据集到 CentralMemory
  5. PreloadScenarioMetadata — 预热 ScenarioRegistry 元数据缓存

本模块提供 AI-300 专用 PyRITInitializer 子类，采用「原生优先 + AI-300 扩展」
策略：先委托原生初始化器执行标准注册，再追加 AI-300 考试专有配置。

设计原则（L5 原生优先）：
  - 每个 Initializer 先委托原生实现，再追加 AI-300 专有扩展
  - 原生初始化器处理标准 PyRIT 环境变量（OPENAI_CHAT_* / AZURE_OPENAI_*）
  - AI-300 扩展处理考试专有环境变量（TARGET_* / JUDGE_*）
  - 下游消费者通过 Registry 按名称或标签拉取实例
  - 不自动注入到手写攻击中

执行顺序（与 PyRIT 文档一致）：
  1. 环境变量加载 (.env / .env_local)
  2. 数据库配置
  3. Initializers 按传入顺序执行
"""

import logging
import os
from typing import Any

from pyrit.common.apply_defaults import set_default_value, set_global_variable
from pyrit.models import Parameter
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.setup.pyrit_initializer import PyRITInitializer

logger = logging.getLogger(__name__)


# ============================================================
# AI300TargetInitializer — 对齐 TargetInitializer
# ============================================================

class AI300TargetInitializer(PyRITInitializer):
    """
    AI-300 Target 初始化器（L5 原生优先 + AI-300 扩展）

    执行流程：
      Step 1: 委托原生 TargetInitializer — 从标准 PyRIT 环境变量
              （OPENAI_CHAT_* / AZURE_OPENAI_* 等 40+ 配置）注册 Target
              + auto-grouping（RoundRobinTarget）
      Step 2: AI-300 扩展 — 从 TARGET_* / JUDGE_* 环境变量注册考试专用 Target
              + set_default_value(temperature=0.7)

    原生优先策略确保：
      - 用户配置了标准 PyRIT 环境变量时获得完整原生体验
      - 仅配置 TARGET_*/JUDGE_* 时获得 AI-300 考试体验
      - 两者兼有时获得叠加体验

    Supported Parameters:
      - tags: 注册的 Target 标签列表（对齐原生 TargetInitializerTags）
      - auto_group: 是否自动创建 round-robin 分组
    """

    @property
    def supported_parameters(self) -> list[Parameter]:
        return [
            Parameter(
                name="tags",
                description="Target tags to register (e.g., ['default'], ['default', 'scorer'], or ['all'])",
                default=["default"],
            ),
            Parameter(
                name="auto_group",
                description="Auto-create round-robin groups from targets with matching behavioral eval params",
                default=True,
            ),
        ]

    @property
    def required_env_vars(self) -> list[str]:
        """AI-300 需要 TARGET_ENDPOINT（JUDGE_ENDPOINT 可回退到 TARGET_ENDPOINT）"""
        if not os.getenv("TARGET_ENDPOINT"):
            return ["TARGET_ENDPOINT"]
        return []

    async def initialize_async(self) -> None:
        """
        注册 Target 到 TargetRegistry

        Step 1: 委托原生 TargetInitializer（处理标准 PyRIT 环境变量）
        Step 2: AI-300 扩展（处理 TARGET_* / JUDGE_* 环境变量）
        """
        # Step 1: 委托原生 TargetInitializer
        from pyrit.setup.initializers.targets import TargetInitializer

        native_init = TargetInitializer()
        native_init.set_params_from_args(args={
            "tags": self.params.get("tags", ["default"]),
            "auto_group": self.params.get("auto_group", True),
        })
        try:
            await native_init.initialize_async()
            logger.info("AI300TargetInitializer: native TargetInitializer completed")
        except Exception as e:
            logger.warning(f"AI300TargetInitializer: native TargetInitializer failed (non-fatal): {e}")

        # Step 2: AI-300 扩展 — 注册考试专用 Target
        from pyrit.registry import TargetRegistry
        from src.targets import create_prompt_target, create_judge_target, TargetParams

        registry = TargetRegistry.get_registry_singleton()

        # 注册 objective target
        target_endpoint = os.getenv("TARGET_ENDPOINT")
        target_model = os.getenv("TARGET_MODEL", "")
        target_api_key = os.getenv("TARGET_API_KEY", "")

        if target_endpoint:
            try:
                target_params = TargetParams(
                    temperature=0.7,
                    discover_capabilities=False,
                )
                target, target_type = await create_prompt_target(
                    target_url=target_endpoint.rstrip("/v1") if target_endpoint.endswith("/v1") else target_endpoint,
                    api_key=target_api_key,
                    model_name=target_model,
                    params=target_params,
                )
                # 使用原生 API 注册
                registry.instances.register(target, name="objective_target")
                registry.instances.add_tags(name="objective_target", tags=["default", "objective"])
                logger.info(f"AI300TargetInitializer: registered 'objective_target' ({target_type})")
            except Exception as e:
                logger.warning(f"AI300TargetInitializer: failed to register objective_target: {e}")

        # 注册 judge target
        judge_endpoint = os.getenv("JUDGE_ENDPOINT", target_endpoint)
        judge_model = os.getenv("JUDGE_MODEL", "")
        judge_api_key = os.getenv("JUDGE_API_KEY", target_api_key)

        if judge_endpoint:
            try:
                judge_params = TargetParams(
                    temperature=0.0,
                    top_p=1.0,
                    force_json_output=True,
                    discover_capabilities=False,
                )
                judge, judge_type = await create_judge_target(
                    judge_url=judge_endpoint.rstrip("/v1") if judge_endpoint.endswith("/v1") else judge_endpoint,
                    api_key=judge_api_key,
                    model_name=judge_model,
                    params=judge_params,
                )
                registry.instances.register(judge, name="judge_target")
                registry.instances.add_tags(name="judge_target", tags=["default", "scorer"])
                logger.info(f"AI300TargetInitializer: registered 'judge_target' ({judge_type})")
            except Exception as e:
                logger.warning(f"AI300TargetInitializer: failed to register judge_target: {e}")

        # 设置默认 temperature（对齐原生 set_default_value 模式）
        set_default_value(
            class_type=OpenAIChatTarget,
            parameter_name="temperature",
            value=0.7,
        )


# ============================================================
# AI300ScorerInitializer — 对齐 ScorerInitializer
# ============================================================

class AI300ScorerInitializer(PyRITInitializer):
    """
    AI-300 Scorer 初始化器（L5 原生优先 + AI-300 扩展）

    执行流程：
      Step 1: 委托原生 ScorerInitializer — 注册 20+ 评分器变体
              （refusal/scale/ACS/likert/task_achieved/compound）
              + best-per-category 标签 + F1 选择
              仅在 TargetRegistry 非空时执行
      Step 2: AI-300 扩展 — 从 judge_target 注册考试专用评分器
              TrueFalseInverterScorer (拒绝检测) +
              SelfAskTrueFalseScorer (任务完成检测)

    注意：必须在 AI300TargetInitializer 之后运行（scorer 需要 chat target）。
    """

    @property
    def supported_parameters(self) -> list[Parameter]:
        return [
            Parameter(
                name="tags",
                description="Scorer tags to register",
                default=["default"],
            ),
        ]

    @property
    def required_env_vars(self) -> list[str]:
        """JUDGE_ENDPOINT 必须存在（或 TARGET_ENDPOINT 作为回退）"""
        if not os.getenv("JUDGE_ENDPOINT") and not os.getenv("TARGET_ENDPOINT"):
            return ["JUDGE_ENDPOINT"]
        return []

    async def initialize_async(self) -> None:
        """
        注册 Scorer 到 ScorerRegistry

        Step 1: 委托原生 ScorerInitializer（仅在 TargetRegistry 有标准 target 时执行）
        Step 2: AI-300 扩展（注册考试专用评分器）
        """
        from pyrit.registry import TargetRegistry, ScorerRegistry

        target_registry = TargetRegistry.get_registry_singleton()

        # Step 1: 委托原生 ScorerInitializer
        # 性能优化: 仅当 TargetRegistry 有标准 PyRIT target (OPENAI_CHAT_* 等) 时执行。
        # AI-300 考试场景使用 TARGET_*/JUDGE_* 环境变量，原生 ScorerInitializer
        # 会尝试注册 20+ 评分器，每个都因 "required target not found" 而失败,
        # 浪费 ~5-8s 异常处理时间。跳过原生委托, 直接走 AI-300 扩展路径。
        _has_standard_target = any(
            hasattr(entry, "tags") and "default" in (entry.tags or [])
            for entry in target_registry.instances
        )
        if _has_standard_target and len(target_registry.instances) > 0:
            from pyrit.setup.initializers.scorers import ScorerInitializer

            native_init = ScorerInitializer()
            native_init.set_params_from_args(args={
                "tags": self.params.get("tags", ["default"]),
            })
            try:
                await native_init.initialize_async()
                logger.info("AI300ScorerInitializer: native ScorerInitializer completed")
            except Exception as e:
                logger.warning(f"AI300ScorerInitializer: native ScorerInitializer failed (non-fatal): {e}")
        else:
            logger.info(
                "AI300ScorerInitializer: no standard PyRIT targets in TargetRegistry, "
                "skipping native ScorerInitializer (20+ scorer registration attempts avoided)."
            )

        # Step 2: AI-300 扩展 — 注册考试专用评分器
        from pyrit.score import (
            SelfAskRefusalScorer,
            SelfAskTrueFalseScorer,
            TrueFalseInverterScorer,
            TrueFalseQuestion,
            TrueFalseQuestionPaths,
        )

        scorer_registry = ScorerRegistry.get_registry_singleton()

        # 从 TargetRegistry 拉取 judge target
        judge_entry = target_registry.instances.get("judge_target")
        if judge_entry is None:
            logger.warning(
                "AI300ScorerInitializer: 'judge_target' not found in TargetRegistry. "
                "Skipping AI-300 specific scorer registration."
            )
            return

        judge_target = judge_entry.instance if hasattr(judge_entry, "instance") else judge_entry

        # 注册 TrueFalseInverterScorer (拒绝检测)
        # PyRIT 1.0.0: TrueFalseInverterScorer 接受 scorer 参数 (TrueFalseScorer 实例)，
        # 而非 chat_target/true_false_question_path。
        # 原生模式: TrueFalseInverterScorer(scorer=SelfAskRefusalScorer(chat_target=...))
        try:
            refusal_scorer = TrueFalseInverterScorer(
                scorer=SelfAskRefusalScorer(chat_target=judge_target),
            )
            scorer_registry.instances.register(
                refusal_scorer,
                name="refusal_scorer",
                tags=["default", "refusal", "objective"],
            )
            logger.info("AI300ScorerInitializer: registered 'refusal_scorer'")
        except Exception as e:
            logger.warning(f"AI300ScorerInitializer: failed to register refusal_scorer: {e}")

        # 注册 SelfAskTrueFalseScorer (任务完成检测)
        # PyRIT 1.0.0: SelfAskTrueFalseScorer.__init__ 不再接受 true_false_question_path 参数。
        # 使用 from_question() 工厂方法 + TrueFalseQuestion.from_yaml() 加载问题模板。
        try:
            task_scorer = SelfAskTrueFalseScorer.from_question(
                chat_target=judge_target,
                question=TrueFalseQuestion.from_yaml(TrueFalseQuestionPaths.TASK_ACHIEVED.value),
            )
            scorer_registry.instances.register(
                task_scorer,
                name="task_achieved_scorer",
                tags=["default", "task_achieved", "objective"],
            )
            logger.info("AI300ScorerInitializer: registered 'task_achieved_scorer'")
        except Exception as e:
            logger.warning(f"AI300ScorerInitializer: failed to register task_achieved_scorer: {e}")


# ============================================================
# AI300TechniqueInitializerWrapper — 对齐 TechniqueInitializer
# ============================================================

class AI300TechniqueInitializerWrapper(PyRITInitializer):
    """
    AI-300 Technique 初始化器（PyRITInitializer 包装器）

    对齐 PyRIT TechniqueInitializer，将 AI-300 的
    AI300TechniqueInitializer 包装为 PyRITInitializer 子类。

    注册 34 个 AttackTechniqueFactory 到 AttackTechniqueRegistry，
    支持 core/extra/encoding/all 分组控制。
    """

    @property
    def supported_parameters(self) -> list[Parameter]:
        return [
            Parameter(
                name="tags",
                description="Technique groups to register: ['core'], ['core', 'extra'], ['all'], ['encoding']",
                default=["core"],
            ),
            Parameter(
                name="target_type",
                description="PyRIT Target type for Target-aware dynamic chain selection (R0)",
                default=None,
            ),
            Parameter(
                name="objective_target",
                description="Objective PromptTarget instance for modality compatibility detection (R2)",
                default=None,
            ),
        ]

    async def initialize_async(self) -> None:
        """
        注册 AI-300 技术到 AttackTechniqueRegistry

        委托给 AI300TechniqueInitializer 执行实际注册。
        """
        from src.scenarios.technique_initializer import AI300TechniqueInitializer

        tags = self.params.get("tags", ["core"])
        target_type = self.params.get("target_type")
        objective_target = self.params.get("objective_target")

        # 委托给 AI300TechniqueInitializer
        inner = AI300TechniqueInitializer()
        init_args: dict[str, Any] = {"tags": tags}
        if target_type is not None:
            init_args["target_type"] = target_type
        if objective_target is not None:
            init_args["objective_target"] = objective_target
        inner.set_params_from_args(args=init_args)
        await inner.initialize_async()

        logger.info(
            f"AI300TechniqueInitializerWrapper: registered {inner.registered_count} techniques "
            f"(tags={tags}, target_type={target_type or 'None'})"
        )


# ============================================================
# AI300LoadDefaultDatasets — 对齐 LoadDefaultDatasets
# ============================================================

class AI300LoadDefaultDatasets(PyRITInitializer):
    """
    AI-300 默认数据集加载器

    对齐 PyRIT LoadDefaultDatasets，将 OWASP 数据集加载到 CentralMemory。

    AI-300 扩展：
      - 加载 OWASP LLM Top 10 + Agentic AI Top 10 数据集
      - 可选加载自定义数据集和远程数据集
      - 支持交互式选择层配置
    """

    @property
    def supported_parameters(self) -> list[Parameter]:
        return [
            Parameter(
                name="owasp",
                description="Load OWASP datasets (true/false)",
                default=True,
            ),
            Parameter(
                name="custom",
                description="Load custom datasets (true/false)",
                default=True,
            ),
            Parameter(
                name="remote",
                description="Load remote datasets (true/false)",
                default=False,
            ),
        ]

    async def initialize_async(self) -> None:
        """
        加载默认数据集到 CentralMemory

        委托给 DatasetManager 执行实际加载。
        """
        from src.payloads import DatasetManager

        owasp = self.params.get("owasp", ["true"])
        custom = self.params.get("custom", ["true"])
        remote = self.params.get("remote", ["false"])

        owasp_enabled = str(owasp[0] if isinstance(owasp, list) else owasp).lower() in ("true", "1", "yes")
        custom_enabled = str(custom[0] if isinstance(custom, list) else custom).lower() in ("true", "1", "yes")
        remote_enabled = str(remote[0] if isinstance(remote, list) else remote).lower() in ("true", "1", "yes")

        manager = DatasetManager()
        await manager.load_datasets(
            owasp=owasp_enabled,
            custom=custom_enabled,
            remote=remote_enabled,
        )

        total_seeds = len(manager.get_seeds())
        total_groups = len(manager.get_seed_groups())
        logger.info(
            f"AI300LoadDefaultDatasets: loaded {total_seeds} seeds, {total_groups} seed groups "
            f"(owasp={owasp_enabled}, custom={custom_enabled}, remote={remote_enabled})"
        )


# ============================================================
# AI300PreloadScenarioMetadata — 对齐 PreloadScenarioMetadata
# ============================================================

class AI300PreloadScenarioMetadata(PyRITInitializer):
    """
    AI-300 Scenario 元数据预热初始化器

    对齐 PyRIT PreloadScenarioMetadata，在启动时实例化所有已注册 Scenario
    一次，预热 ScenarioRegistry 元数据缓存。

    这样首次 --list-scenarios / GUI 调用是缓存命中，而非冷启动。
    每个 Scenario 的实例化失败在启动时暴露，而非运行时。
    """

    @property
    def required_env_vars(self) -> list[str]:
        return []

    async def initialize_async(self) -> None:
        """委托原生 PreloadScenarioMetadata 预热元数据缓存。"""
        from pyrit.setup.initializers.preload_scenario_metadata import PreloadScenarioMetadata

        native_init = PreloadScenarioMetadata()
        try:
            await native_init.initialize_async()
            logger.info("AI300PreloadScenarioMetadata: native PreloadScenarioMetadata completed")
        except Exception as e:
            logger.warning(f"AI300PreloadScenarioMetadata: native PreloadScenarioMetadata failed (non-fatal): {e}")


# ============================================================
# AI300DefaultValuesInitializer — 默认值初始化器
# ============================================================

class AI300DefaultValuesInitializer(PyRITInitializer):
    """
    AI-300 默认值初始化器

    对齐 PyRIT Default Values 文档，使用 set_default_value 设置
    AI-300 考试专用的默认值。

    设置的默认值：
      - OpenAIChatTarget.temperature = 0.7（目标模型有创意）
      - OpenAIChatTarget.top_p = 1.0（完整采样空间）

    显式提供的值总是覆盖默认值（即使 0, False, ""）。
    默认值仅在参数未提供或显式设为 None 时生效。
    """

    async def initialize_async(self) -> None:
        """设置 AI-300 默认值"""
        # 目标模型默认参数
        set_default_value(
            class_type=OpenAIChatTarget,
            parameter_name="temperature",
            value=0.7,
        )

        # 全局变量
        set_global_variable(
            name="AI300_EXAM_MODE",
            value=False,
        )
        set_global_variable(
            name="AI300_RETRY_ON_FAILURE",
            value=True,
        )

        logger.info("AI300DefaultValuesInitializer: set default values (temperature=0.7)")


# ============================================================
# 便捷工厂函数
# ============================================================

def get_default_initializers() -> list[PyRITInitializer]:
    """
    获取 AI-300 默认初始化器列表（L5 原生优先 + 性能优化）

    返回推荐的四阶段初始化器序列：
      1. AI300DefaultValuesInitializer     — 设置默认值（set_default_value）
      2. AI300TargetInitializer            — 委托原生 + 注册 AI-300 Target
      3. AI300ScorerInitializer            — 委托原生 + 注册 AI-300 Scorer
      4. AI300TechniqueInitializerWrapper  — 注册 AI-300 Technique

    性能优化（v8.1 — 消除启动 ~30s 延迟）:
      - 移除 AI300LoadDefaultDatasets: 与 Stage 4 DatasetManager.load_datasets() 重复加载
        相同 YAML 到 CentralMemory，浪费 ~10-15s I/O。Stage 4 已完整覆盖。
      - 移除 AI300PreloadScenarioMetadata: 总是因缺少 OPENAI_CHAT_MODEL 环境变量而失败，
        预热无效且浪费 ~5s。
      - AI300ScorerInitializer: 仅当 TargetRegistry 非空时委托原生 ScorerInitializer,
        避免 20+ 评分器逐个失败的异常处理开销。

    Returns:
        PyRITInitializer 子类实例列表（按执行顺序）
    """
    return [
        AI300DefaultValuesInitializer(),
        AI300TargetInitializer(),
        AI300ScorerInitializer(),
        AI300TechniqueInitializerWrapper(),
    ]
