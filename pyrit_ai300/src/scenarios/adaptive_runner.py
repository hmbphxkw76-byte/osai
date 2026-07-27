"""
Adaptive Runner — P3+P4: 原生 AI300AdaptiveScenario 执行入口
============================================================

P3: 消除双轨 — pipeline.py 调用此模块替代 ScenarioOrchestrator.execute_batch()
P4: 原生优先 — 使用 DatasetAttackConfiguration(seed_groups=) 内联传入 attack_plans

核心设计（方案 A — PyRIT 原生优先）：
  PyRIT DatasetAttackConfiguration 原生支持 seed_groups= 参数，
  用于内联传入种子组（不触碰 Memory）。本模块将 pipeline 交互选择
  的 attack_plans 转换为 AttackSeedGroup 列表，通过 dataset_config
  参数传入 Scenario，完全对齐 PyRIT 原生数据流。

执行流程：
  1. attack_plans → AttackSeedGroup 列表（SeedGroupBuilder.build）
  2. DatasetAttackConfiguration(seed_groups=...) 内联配置
  3. 创建 AI300AdaptiveScenario（含 Converter 变体）
  4. 注册技术到 AttackTechniqueRegistry（含 Converter 变体）
  5. scenario.set_params_from_args(dataset_config=..., max_retries=..., max_concurrency=...)
  6. scenario.initialize_async() → 原生构建 AtomicAttack + SequentialAttack(FIRST_SUCCESS)
  7. scenario.run_async() → 原生执行（含 tqdm + max_retries + 自动恢复）
  8. ScenarioResult → BatchAttackResult（向后兼容）

保留自建：
  - per_attack_timeout 参数声明（PyRIT 无 per-attack 超时，保留为文档/未来扩展）
  - OWASP 映射（通过 memory_labels）
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.payloads.models import BatchAttackResult

logger = logging.getLogger(__name__)


@dataclass
class AdaptiveRunResult:
    """
    原生 AdaptiveScenario 执行结果

    封装原生 ScenarioResult + 向后兼容的 BatchAttackResult
    """

    native_result: Any = None  # 原生 ScenarioResult
    batch_result: BatchAttackResult = field(default_factory=BatchAttackResult)
    scenario_result_id: str = ""
    execution_time: float = 0.0
    converter_variants_used: int = 0
    total_techniques_tried: int = 0

    @property
    def succeeded(self) -> int:
        return self.batch_result.succeeded

    @property
    def failed(self) -> int:
        return self.batch_result.failed

    @property
    def success_rate(self) -> float:
        return self.batch_result.success_rate


async def run_adaptive_scenario_async(
    *,
    objective_target: Any,
    judge_target: Any,
    attack_plans: list[Any] | None = None,
    seed_groups: list[Any] | None = None,
    owasp_id: str = "",
    exam_id: str = "",
    max_attempts_per_objective: int = 3,
    per_attack_timeout: int = 300,
    max_retries: int = 0,
    max_concurrency: int = 4,
    verbose: bool = False,
    converter_target: Any = None,
    memory_labels: dict[str, str] | None = None,
    target_type: str | None = None,
) -> AdaptiveRunResult:
    """
    P3: 原生 AI300AdaptiveScenario 执行入口

    消除自建 AttackUpgradeStrategy 双轨，使用原生 AdaptiveScenario 执行：
    1. 注册技术（含 Converter 变体）到 AttackTechniqueRegistry
    2. 创建 AI300AdaptiveScenario
    3. scenario.initialize_async() + scenario.run_async()
    4. per_attack_timeout 包裹（自建保留）
    5. 结果转换为 BatchAttackResult（向后兼容）

    Args:
        objective_target: 目标 PromptTarget
        judge_target: 评审 LLM Target（同时用作 adversarial chat + converter_target）
        attack_plans: 攻击计划列表（向后兼容，用于提取 OWASP 映射）
        seed_groups: 种子组列表（原生路径，优先使用）
        owasp_id: OWASP 分类 ID
        exam_id: 考试 ID
        max_attempts_per_objective: 每个 objective 最大尝试次数
        per_attack_timeout: 单次攻击超时（自建保留）
        max_retries: Scenario 级别重试次数
        max_concurrency: 原生 AttackExecutor 并发数（默认 4）
        verbose: 是否详细输出
        converter_target: LLM 辅助 Converter 的 Target（默认为 judge_target）
        memory_labels: 额外 memory_labels
        target_type: PyRIT Target 类型名（如 "openai_chat"），用于 Target 感知排序

    Returns:
        AdaptiveRunResult 封装原生结果 + 向后兼容 BatchAttackResult
    """
    from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
    from src.scenarios.technique_factories import register_ai300_techniques
    from src.scenarios.scenario_result_bridge import (
        ScenarioResultBridge,
        build_memory_labels,
    )
    from src.scenarios.failure_type_selector import extract_failure_type_from_result
    from src.converters.target_aware_router import (
        get_target_group,
        select_converter_chains_for_target,
        get_target_converter_profile,
    )

    start_time = time.time()

    # converter_target 默认使用 judge_target
    if converter_target is None:
        converter_target = judge_target

    # ──────────────────────────────────────────────────────────
    # 方案 A 核心：attack_plans → AttackSeedGroup → DatasetAttackConfiguration(seed_groups=)
    # ──────────────────────────────────────────────────────────
    # PyRIT 原生 DatasetAttackConfiguration 支持三种互斥数据源：
    #   seeds= / seed_groups= / dataset_names=
    # seed_groups= 用于内联传入，完全不触碰 Memory，是官方设计的注入点。
    # ──────────────────────────────────────────────────────────
    from pyrit.scenario import DatasetAttackConfiguration
    from src.executor.attack.component.seed_group_builder import SeedGroupBuilder
    from src.scenarios.ai300_technique import AI300Technique

    attack_seed_groups: list[Any] = []
    pipeline_techniques: set[str] = set()

    if seed_groups:
        # 原生路径：直接使用传入的 seed_groups
        attack_seed_groups = list(seed_groups)
    elif attack_plans:
        # 兼容路径：从 attack_plans 转换为 AttackSeedGroup
        for plan in attack_plans:
            objective = plan.prompt_item.objective
            sg = SeedGroupBuilder.build(plan, objective, include_conversation=True)
            attack_seed_groups.append(sg)
            pipeline_techniques.add(plan.attack_technique)

    if not attack_seed_groups:
        logger.error("No attack seed groups to execute (both attack_plans and seed_groups are empty)")
        return AdaptiveRunResult(
            batch_result=BatchAttackResult(
                total_plans=len(attack_plans or []),
                executed=0,
                succeeded=0,
                failed=0,
                errored=1,
                results=[],
                errors=[{"error": "No attack seed groups provided"}],
            ),
            execution_time=time.time() - start_time,
        )

    # ──────────────────────────────────────────────────────────
    # PyRIT AtomicAttack 要求：同一技术下每个 seed group 的 objective 文本
    # 必须唯一（SHA256 去重）。多个 attack_plans 可能共享相同 objective 文本，
    # 需要在传入 DatasetAttackConfiguration 之前去重。
    # ──────────────────────────────────────────────────────────
    from pyrit.common.utils import to_sha256

    seen_objectives: set[str] = set()
    deduped_seed_groups: list[Any] = []
    duplicates_removed = 0

    for sg in attack_seed_groups:
        # 提取 objective 文本
        obj_value = None
        for seed in sg.seeds:
            if hasattr(seed, "value") and seed.__class__.__name__ == "SeedObjective":
                obj_value = seed.value
                break
        if obj_value is None:
            # 无法提取 objective，保留（让 PyRIT 自行处理）
            deduped_seed_groups.append(sg)
            continue

        obj_hash = to_sha256(obj_value)
        if obj_hash in seen_objectives:
            duplicates_removed += 1
            continue
        seen_objectives.add(obj_hash)
        deduped_seed_groups.append(sg)

    if duplicates_removed > 0:
        logger.info(
            f"AdaptiveRunner: removed {duplicates_removed} duplicate objective(s) "
            f"({len(attack_seed_groups)} → {len(deduped_seed_groups)} unique)"
        )

    attack_seed_groups = deduped_seed_groups

    # 创建内联 DatasetAttackConfiguration（不触碰 Memory）
    dataset_config = DatasetAttackConfiguration(seed_groups=attack_seed_groups)
    logger.info(
        f"AdaptiveRunner: {len(attack_seed_groups)} inline seed groups "
        f"(source: {'seed_groups' if seed_groups else 'attack_plans'})"
    )

    # 将 pipeline 选中的技术映射到 AI300Technique 枚举
    valid_technique_values = {t.value for t in AI300Technique}
    scenario_techniques: list[Any] = []
    for tech_name in pipeline_techniques:
        if tech_name in valid_technique_values:
            for member in AI300Technique:
                if member.value == tech_name:
                    scenario_techniques.append(member)
                    break
        else:
            logger.debug(f"Technique '{tech_name}' not in AI300Technique enum, skipping")

    if not scenario_techniques:
        # 无可映射技术时使用 DEFAULT（让 AI300Technique.default() 展开）
        scenario_techniques = None
        logger.info("No mappable pipeline techniques, using AI300Technique.DEFAULT")
    else:
        logger.info(f"Mapped {len(scenario_techniques)} pipeline techniques: {[t.value for t in scenario_techniques]}")

    # ──────────────────────────────────────────────────────────
    # 注册 judge_target 到 TargetRegistry — PyRIT 原生 target 解析
    # AdaptiveScenario 通过 get_default_adversarial_target() 和
    # get_default_scorer_target() 从 TargetRegistry.instances 查找:
    #   - "adversarial_chat" → 多轮技术的军师 Target
    #   - "objective_scorer_chat" → 评分器 Target
    # 如果未注册，PyRIT 会回退创建 OpenAIChatTarget，需要 OPENAI_CHAT_MODEL 环境变量。
    # ──────────────────────────────────────────────────────────
    try:
        from pyrit.registry import TargetRegistry
        registry = TargetRegistry.get_registry_singleton()
        registry.instances.register(judge_target, name="adversarial_chat")
        registry.instances.register(judge_target, name="objective_scorer_chat")
        logger.info("Registered judge_target as 'adversarial_chat' + 'objective_scorer_chat' in TargetRegistry")
    except Exception as e:
        logger.warning(f"Failed to register judge_target in TargetRegistry: {e}")

    # 创建 objective_scorer（从 judge_target 构建 SelfAskTrueFalseScorer）
    objective_scorer = None
    try:
        from pyrit.score import SelfAskTrueFalseScorer
        objective_scorer = SelfAskTrueFalseScorer(chat_target=judge_target)
        logger.debug("Created SelfAskTrueFalseScorer from judge_target")
    except Exception as e:
        logger.warning(f"Failed to create objective_scorer from judge_target: {e}")

    # 1. 注册技术（含 Converter 变体）到 AttackTechniqueRegistry
    try:
        register_ai300_techniques(
            tags=["all"],
            reset=False,
            converter_target=converter_target,
            include_variants=True,
            target_type=target_type,
            objective_target=objective_target,
        )
    except Exception as e:
        logger.warning(f"Technique registration failed (non-fatal): {e}")

    # 2. 构建 memory_labels（OWASP 映射）
    labels = build_memory_labels(owasp_id=owasp_id, exam_id=exam_id)
    if memory_labels:
        labels.update(memory_labels)

    # 3. 创建 AI300AdaptiveScenario（传入 objective_scorer + target_type + owasp_id）
    scenario = AI300AdaptiveScenario(
        converter_target=converter_target,
        objective_scorer=objective_scorer,
        target_type=target_type,
        owasp_id=owasp_id,
    )

    # ──────────────────────────────────────────────────────────
    # 原生参数传递：dataset_config + scenario_techniques + max_retries + max_concurrency
    # ──────────────────────────────────────────────────────────
    # 所有参数通过 set_params_from_args 传入，完全对齐 PyRIT 原生 Scenario 生命周期。
    # dataset_config: 内联 seed_groups（方案 A 核心）
    # scenario_techniques: pipeline 选中的技术（映射到 AI300Technique 枚举）
    # max_retries: Scenario 级别重试（原生弹性恢复）
    # max_concurrency: 原生 AttackExecutor 并发控制
    # ──────────────────────────────────────────────────────────
    scenario_params: dict[str, Any] = {
        "objective_target": objective_target,
        "max_attempts_per_objective": max_attempts_per_objective,
        "per_attack_timeout": per_attack_timeout,
        "memory_labels": labels,
        "dataset_config": dataset_config,
        "max_retries": max_retries,
        "max_concurrency": max_concurrency,
    }
    if scenario_techniques is not None:
        scenario_params["scenario_techniques"] = scenario_techniques

    scenario.set_params_from_args(args=scenario_params)

    if verbose:
        print(f"  [ADAPT] AI300AdaptiveScenario: max_attempts={max_attempts_per_objective}, "
              f"timeout={per_attack_timeout}s, retries={max_retries}")
        print(f"  [ADAPT] OWASP: {owasp_id}, Converter variants: enabled")

        # P3: 展示 Target 感知 Converter 路由信息
        if target_type:
            target_group = get_target_group(target_type)
            profile = get_target_converter_profile(target_type)
            recommended_chains = select_converter_chains_for_target(
                target_type,
                converter_target_available=(converter_target is not None),
            )
            print(f"\n  {'=' * 68}")
            print(f"  Target-Aware Converter 路由")
            print(f"  {'=' * 68}")
            print(f"  Target Type:  {target_type}")
            print(f"  Target Group: {target_group}")
            print(f"  Bypass:       {profile.get('bypass_mechanism', 'unknown')}")
            print(f"  Description:  {profile.get('description', '')}")
            print(f"  {'-' * 68}")
            print(f"  推荐 Converter 链序列 (按 ASR 优先级排序):")
            for i, chain in enumerate(recommended_chains, 1):
                is_llm = chain in profile.get("llm_assisted_chains", [])
                tag = " (LLM)" if is_llm else ""
                print(f"    {i}. {chain}{tag}")
            print(f"  {'=' * 68}\n")
        else:
            print(f"  [ADAPT] Target 类型未指定，使用全局 Converter 优先级")

        # 展示可用的 Converter 变体类型/组合
        AI300AdaptiveScenario.display_converter_variants(verbose=True)

    # 4. 初始化 Scenario
    try:
        await scenario.initialize_async()
    except Exception as e:
        logger.error(f"Scenario initialization failed: {e}")
        return AdaptiveRunResult(
            batch_result=BatchAttackResult(
                total_plans=len(attack_plans or []),
                executed=0,
                succeeded=0,
                failed=0,
                errored=1,
                results=[],
                errors=[{"error": f"Init failed: {e}"}],
            ),
            execution_time=time.time() - start_time,
        )

    # 5. 执行 Scenario（原生 run_async — 含 tqdm + max_retries + 自动恢复）
    #    不使用 asyncio.wait_for 包裹整个 scenario：
    #    - 原生 Scenario 已有 max_retries 弹性恢复机制
    #    - 原生 Scenario 有自动恢复（中断后可 resume）
    #    - per_attack_timeout 作为参数声明保留，未来可用于自定义 executor
    scenario_error = None
    try:
        native_result = await scenario.run_async()
    except Exception as e:
        logger.error(f"Scenario execution failed: {e}")
        scenario_error = str(e)
        # Scenario 失败时，部分结果已存入 PyRIT Memory 数据库
        # 尝试从 Memory 检索最新的 ScenarioResult（包含已完成的攻击结果）
        native_result = None
        try:
            from pyrit.memory import CentralMemory
            memory = CentralMemory.get_memory_instance()
            scenario_results = memory.get_scenario_results()
            if scenario_results:
                native_result = scenario_results[-1]
                logger.info(
                    f"Retrieved partial ScenarioResult from memory "
                    f"({len(scenario_results)} total results available)"
                )
        except Exception as e2:
            logger.warning(f"Failed to retrieve partial results from memory: {e2}")

    elapsed = time.time() - start_time

    # 6. 结果转换（向后兼容 BatchAttackResult）
    batch_result = _convert_native_to_batch_result(
        native_result,
        attack_plans=attack_plans,
        owasp_id=owasp_id,
    )
    if scenario_error:
        batch_result.errors.append({"error": f"Scenario failed: {scenario_error}"})

    # 统计 Converter 变体使用情况
    converter_variants = 0
    total_techniques = 0
    if native_result is not None:
        display_groups = native_result.get_display_groups() if hasattr(native_result, "get_display_groups") else {}
        for group_name, results in display_groups.items():
            for r in results:
                total_techniques += 1
                # Converter 检测：从 identifier.children['request_converters'] 提取
                identifier = None
                if hasattr(r, "get_attack_strategy_identifier"):
                    identifier = r.get_attack_strategy_identifier()
                if identifier is not None:
                    children = getattr(identifier, "children", None) or {}
                    if children.get("request_converters"):
                        converter_variants += 1

    if verbose:
        print(f"  [ADAPT] 完成: {batch_result.succeeded}/{batch_result.executed} 成功, "
              f"{converter_variants} converter variants used, {elapsed:.1f}s")
        # 统一展示：Per-Group Breakdown 含技术+Converter+OWASP
        from src.scenarios.scenario_output import display_enhanced_group_breakdown
        display_enhanced_group_breakdown(native_result, owasp_id=owasp_id)

    return AdaptiveRunResult(
        native_result=native_result,
        batch_result=batch_result,
        scenario_result_id=getattr(native_result, "id", ""),
        execution_time=elapsed,
        converter_variants_used=converter_variants,
        total_techniques_tried=total_techniques,
    )


def _convert_native_to_batch_result(
    native_result: Any,
    *,
    attack_plans: list[Any] | None = None,
    owasp_id: str = "",
) -> BatchAttackResult:
    """
    P4: 将原生 ScenarioResult 转换为 BatchAttackResult（向后兼容）

    Args:
        native_result: 原生 ScenarioResult
        attack_plans: 攻击计划列表（用于 total_plans 统计）
        owasp_id: OWASP 分类 ID

    Returns:
        BatchAttackResult 实例
    """
    if native_result is None:
        return BatchAttackResult(
            total_plans=len(attack_plans or []),
            executed=0,
            succeeded=0,
            failed=0,
            errored=0,
            results=[],
            errors=[],
        )

    # 从原生 ScenarioResult 提取攻击结果
    all_results: list[Any] = []
    if hasattr(native_result, "get_display_groups"):
        display_groups = native_result.get_display_groups()
        for group_name, results in display_groups.items():
            all_results.extend(results)
    elif hasattr(native_result, "attack_results"):
        all_results = list(native_result.attack_results)

    # 统计成功/失败
    succeeded = 0
    failed = 0
    errored = 0
    for r in all_results:
        if r is None:
            continue
        outcome = getattr(r, "outcome", None)
        if outcome is not None:
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
            if outcome_str == "SUCCESS":
                succeeded += 1
            elif outcome_str == "ERROR":
                errored += 1
            else:
                failed += 1
        else:
            failed += 1

    total_plans = len(attack_plans) if attack_plans else len(all_results)

    return BatchAttackResult(
        total_plans=total_plans,
        executed=len(all_results),
        succeeded=succeeded,
        failed=failed,
        errored=errored,
        results=all_results,
        errors=[],
    )
