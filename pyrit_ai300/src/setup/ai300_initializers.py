"""
AI-300 Initializers — 对齐 PyRIT built-in initializers
=======================================================

PyRIT 1.0.0 PyRIT Initializers 文档定义四大内置初始化器：
  1. TargetInitializer — 从环境变量注册 Target 到 TargetRegistry
  2. ScorerInitializer — 注册默认 Scorer 到 ScorerRegistry
  3. TechniqueInitializer — 注册攻击技术到 AttackTechniqueRegistry
  4. LoadDefaultDatasets — 加载数据集到 CentralMemory

本模块提供 AI-300 专用 PyRITInitializer 子类，封装上述功能
同时设置 AI-300 考试专用默认值。

设计原则（PyRIT 最佳实践）：
  - 每个 Initializer 是离散的、有序的启动配置单元
  - 执行一次，准备好共享状态
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
    AI-300 Target 初始化器

    对齐 PyRIT TargetInitializer，从环境变量注册 Target 到 TargetRegistry。

    AI-300 扩展：
      - 支持 TARGET_ENDPOINT / TARGET_MODEL / TARGET_API_KEY 环境变量
      - 支持 JUDGE_ENDPOINT / JUDGE_MODEL / JUDGE_API_KEY 环境变量
      - 自动注册为 "objective_target" 和 "judge_target" 名称
      - 设置 temperature 默认值（target=0.7, judge=0）

    Supported Parameters:
      - tags: 注册的 Target 标签列表
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
        """AI-300 只需要 TARGET_ENDPOINT 和 JUDGE_ENDPOINT"""
        vars_needed = []
        if not os.getenv("TARGET_ENDPOINT"):
            vars_needed.append("TARGET_ENDPOINT")
        if not os.getenv("JUDGE_ENDPOINT"):
            vars_needed.append("JUDGE_ENDPOINT")
        return vars_needed

    async def initialize_async(self) -> None:
        """
        注册 AI-300 Target 到 TargetRegistry

        从 .env 读取 TARGET_* 和 JUDGE_* 环境变量，
        创建 OpenAIChatTarget 实例并注册到 TargetRegistry。
        """
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
                registry.register_instance(
                    name="objective_target",
                    instance=target,
                    tags=["default", "objective"],
                )
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
                registry.register_instance(
                    name="judge_target",
                    instance=judge,
                    tags=["default", "scorer"],
                )
                logger.info(f"AI300TargetInitializer: registered 'judge_target' ({judge_type})")
            except Exception as e:
                logger.warning(f"AI300TargetInitializer: failed to register judge_target: {e}")

        # 设置默认 temperature
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
    AI-300 Scorer 初始化器

    对齐 PyRIT ScorerInitializer，注册默认评分器到 ScorerRegistry。

    AI-300 扩展：
      - 从 judge_target 注册 TrueFalseInverterScorer（拒绝检测）
      - 注册 SelfAskTrueFalseScorer（任务完成检测）
      - 标签体系对齐 ScorerInitializerTags

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
        """JUDGE_ENDPOINT 必须存在"""
        if not os.getenv("JUDGE_ENDPOINT"):
            return ["JUDGE_ENDPOINT"]
        return []

    async def initialize_async(self) -> None:
        """
        注册 AI-300 Scorer 到 ScorerRegistry

        从 TargetRegistry 拉取 judge_target，创建评分器实例并注册。
        """
        from pyrit.registry import TargetRegistry, ScorerRegistry
        from pyrit.prompt_normalizer import PromptNormalizer
        from pyrit.score import (
            SelfAskTrueFalseScorer,
            TrueFalseInverterScorer,
            TrueFalseQuestionPaths,
        )

        scorer_registry = ScorerRegistry.get_registry_singleton()
        target_registry = TargetRegistry.get_registry_singleton()

        # 从 TargetRegistry 拉取 judge target
        judge_entry = target_registry.instances.get("judge_target")
        if judge_entry is None:
            logger.warning(
                "AI300ScorerInitializer: 'judge_target' not found in TargetRegistry. "
                "Run AI300TargetInitializer first."
            )
            return

        judge_target = judge_entry.instance if hasattr(judge_entry, "instance") else judge_entry

        # 注册 TrueFalseInverterScorer (拒绝检测)
        try:
            refusal_scorer = TrueFalseInverterScorer(
                chat_target=judge_target,
                true_false_question_path=TrueFalseQuestionPaths.RESPECT_CONTEXT,
            )
            scorer_registry.register_instance(
                name="refusal_scorer",
                instance=refusal_scorer,
                tags=["default", "refusal", "objective"],
            )
            logger.info("AI300ScorerInitializer: registered 'refusal_scorer'")
        except Exception as e:
            logger.warning(f"AI300ScorerInitializer: failed to register refusal_scorer: {e}")

        # 注册 SelfAskTrueFalseScorer (任务完成检测)
        try:
            task_scorer = SelfAskTrueFalseScorer(
                chat_target=judge_target,
                true_false_question_path=TrueFalseQuestionPaths.TASK_ACHIEVED,
            )
            scorer_registry.register_instance(
                name="task_achieved_scorer",
                instance=task_scorer,
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
    获取 AI-300 默认初始化器列表

    返回推荐的四阶段初始化器序列：
      1. AI300DefaultValuesInitializer — 设置默认值
      2. AI300TargetInitializer — 注册 Target
      3. AI300ScorerInitializer — 注册 Scorer（依赖 Target）
      4. AI300TechniqueInitializerWrapper — 注册 Technique
      5. AI300LoadDefaultDatasets — 加载数据集

    Returns:
        PyRITInitializer 子类实例列表（按执行顺序）
    """
    return [
        AI300DefaultValuesInitializer(),
        AI300TargetInitializer(),
        AI300ScorerInitializer(),
        AI300TechniqueInitializerWrapper(),
        AI300LoadDefaultDatasets(),
    ]
