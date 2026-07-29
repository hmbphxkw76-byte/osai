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
  4. 注册基础技术到 AttackTechniqueRegistry（v3.0: 不含变体）
  5. scenario.set_params_from_args(dataset_config=..., max_retries=..., max_concurrency=...)
  6. scenario.initialize_async() → 原生构建 AtomicAttack + SequentialAttack(FIRST_SUCCESS)
  7. scenario.run_async() → 原生执行（含 tqdm + max_retries + 自动恢复）
  8. P0-A: 失败类型分析 → 提取失败类型统计 + 更新 selector（供 resume 使用）
  9. ScenarioResult → BatchAttackResult（向后兼容）

v3.0 优化：
  - P0-A: 失败类型分析接入 — extract_failure_type_from_result 激活
  - P1-B: 移除 per_attack_timeout 传递（原生 max_retries + max_concurrency 足够）
  - 变体注册改为 include_variants=False（v3.0: 变体在 _build_techniques_dict 中动态创建）

保留自建：
  - OWASP 映射（通过 memory_labels）
"""

import logging
import time
from collections import Counter
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
    # P0-A: 失败类型统计
    failure_type_distribution: dict[str, int] = field(default_factory=dict)
    most_common_failure_type: str | None = None

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
    strategy_mode: str = "academic",
    model_name: str = "gpt-4o",
    model_tier: str = "unknown",
) -> AdaptiveRunResult:
    """
    P3: 原生 AI300AdaptiveScenario 执行入口

    消除自建 AttackUpgradeStrategy 双轨，使用原生 AdaptiveScenario 执行：
    1. 注册基础技术到 AttackTechniqueRegistry（v3.0: 不含变体）
    2. 创建 AI300AdaptiveScenario
    3. scenario.initialize_async() + scenario.run_async()
    4. P0-A: 失败类型分析 → 提取统计 + 更新 selector
    5. 结果转换为 BatchAttackResult（向后兼容）

    Args:
        objective_target: 目标 PromptTarget
        judge_target: 评审 LLM Target（仅用于 objective scoring）
        attack_plans: 攻击计划列表（向后兼容，用于提取 OWASP 映射）
        seed_groups: 种子组列表（原生路径，优先使用）
        owasp_id: OWASP 分类 ID
        exam_id: 考试 ID
        max_attempts_per_objective: 每个 objective 最大尝试次数
        per_attack_timeout: [v3.0 deprecated] 单次攻击超时（不再传递给 Scenario，
                           原生 max_retries + max_concurrency 足够）
        max_retries: Scenario 级别重试次数
        max_concurrency: 原生 AttackExecutor 并发数（默认 4）
        verbose: 是否详细输出
        converter_target: LLM 辅助 Converter 的 Target（默认为 judge_target，但推荐使用目标模型）
        memory_labels: 额外 memory_labels
        target_type: PyRIT Target 类型名（如 "openai_chat"），用于 Target 感知排序

    Returns:
        AdaptiveRunResult 封装原生结果 + 向后兼容 BatchAttackResult
    """
    from src.scenarios.ai300_adaptive_scenario import AI300AdaptiveScenario
    from src.scenarios.technique_factories import register_ai300_techniques
    from src.scenarios.scenario_result_bridge import (
        build_memory_labels,
    )
    from src.scenarios.failure_type_selector import extract_failure_type_from_result
    # v5.0: Target 路由展示已统一到 s6_execute.py，此处不再导入 target_aware_router
    # v3.0: PayloadStrategyMatcher 在 Adaptive 路径恢复使用
    from src.analysis.strategy_matcher import PayloadStrategyMatcher

    start_time = time.time()

    # converter_target 回退到 judge_target（向后兼容，但可能因安全对齐导致 Converter 500 错误）
    if converter_target is None:
        converter_target = judge_target
        logger.warning(
            "converter_target 未指定，回退到 judge_target。"
            "安全对齐模型可能拒绝生成攻击内容，导致 PersuasionConverter/DecompositionConverter 等 500 错误。"
            "建议在 pipeline 中传入 converter_target（默认使用目标模型）。"
        )

    # ──────────────────────────────────────────────────────────
    # 方案 A 核心：attack_plans → AttackSeedGroup → DatasetAttackConfiguration(seed_groups=)
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
    # 必须唯一（SHA256 去重）。
    # ──────────────────────────────────────────────────────────
    from pyrit.common.utils import to_sha256

    seen_objectives: set[str] = set()
    deduped_seed_groups: list[Any] = []
    duplicates_removed = 0

    for sg in attack_seed_groups:
        obj_value = None
        for seed in sg.seeds:
            if hasattr(seed, "value") and seed.__class__.__name__ == "SeedObjective":
                obj_value = seed.value
                break
        if obj_value is None:
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
        scenario_techniques = None
        logger.info("No mappable pipeline techniques, using AI300Technique.DEFAULT")
    else:
        logger.info(f"Mapped {len(scenario_techniques)} pipeline techniques: {[t.value for t in scenario_techniques]}")

    # ──────────────────────────────────────────────────────────
    # 注册 judge_target 到 TargetRegistry — PyRIT 原生 target 解析
    # ──────────────────────────────────────────────────────────
    try:
        from pyrit.registry import TargetRegistry
        registry = TargetRegistry.get_registry_singleton()
        registry.instances.register(judge_target, name="adversarial_chat")
        registry.instances.register(judge_target, name="objective_scorer_chat")
        logger.info("Registered judge_target as 'adversarial_chat' + 'objective_scorer_chat' in TargetRegistry")
    except Exception as e:
        logger.warning(f"Failed to register judge_target in TargetRegistry: {e}")

    # ──────────────────────────────────────────────────────────
    # v3.0: PayloadStrategyMatcher 在 Adaptive 路径恢复使用
    # 为每个 attack_plan 匹配 OWASP 策略，提取技术提示供 Scenario 使用
    # ──────────────────────────────────────────────────────────
    strategy_matcher = PayloadStrategyMatcher(target_type=target_type)
    matched_techniques: set[str] = set()
    if attack_plans:
        for plan in attack_plans:
            # 从 plan 中提取 OWASP ID 和技术提示
            plan_owasp = getattr(plan, "owasp_id", "") or owasp_id
            plan_tech_hint = ""
            prompt_item = getattr(plan, "prompt_item", None)
            if prompt_item:
                meta = getattr(prompt_item, "metadata", {}) or {}
                plan_tech_hint = meta.get("technique", meta.get("technique_group", ""))

            matched = strategy_matcher.match(
                owasp_id=plan_owasp,
                technique_hint=plan_tech_hint,
            )
            if matched.attack_technique:
                matched_techniques.add(matched.attack_technique)

        if matched_techniques:
            logger.info(
                f"PayloadStrategyMatcher: matched {len(matched_techniques)} techniques "
                f"from {len(attack_plans)} plans (target_type={target_type})"
            )

    # 创建 objective_scorer（从 judge_target 构建 SelfAskTrueFalseScorer）
    objective_scorer = None
    try:
        from pyrit.score import SelfAskTrueFalseScorer
        objective_scorer = SelfAskTrueFalseScorer(chat_target=judge_target)
        logger.debug("Created SelfAskTrueFalseScorer from judge_target")
    except Exception as e:
        logger.warning(f"Failed to create objective_scorer from judge_target: {e}")

    # 1. 注册基础技术到 AttackTechniqueRegistry
    #    v3.0: include_variants=False — 变体在 _build_techniques_dict 中通过
    #    原生 extra_request_converters 动态创建，不再预注册到 Registry
    try:
        register_ai300_techniques(
            tags=["all"],
            reset=False,
            converter_target=converter_target,
            include_variants=False,
            target_type=target_type,
            objective_target=objective_target,
        )
    except Exception as e:
        logger.warning(f"Technique registration failed (non-fatal): {e}")

    # 2. 构建 memory_labels（OWASP 映射）
    labels = build_memory_labels(owasp_id=owasp_id, exam_id=exam_id)
    if memory_labels:
        labels.update(memory_labels)

# 3. 创建 AI300AdaptiveScenario（传入 objective_scorer + target_type + owasp_id + strategy_mode + model_tier）
    scenario = AI300AdaptiveScenario(
        converter_target=converter_target,
        objective_scorer=objective_scorer,
        target_type=target_type,
        owasp_id=owasp_id,
        strategy_mode=strategy_mode,
        model_name=model_name,
        model_tier=model_tier,
    )

    # ──────────────────────────────────────────────────────────
    # 原生参数传递：dataset_config + scenario_techniques + max_retries + max_concurrency
    # v3.0: 移除 per_attack_timeout（原生 max_retries + max_concurrency 足够）
    # ──────────────────────────────────────────────────────────
    scenario_params: dict[str, Any] = {
        "objective_target": objective_target,
        "max_attempts_per_objective": max_attempts_per_objective,
        "memory_labels": labels,
        "dataset_config": dataset_config,
        "max_retries": max_retries,
        "max_concurrency": max_concurrency,
    }
    if scenario_techniques is not None:
        scenario_params["scenario_techniques"] = scenario_techniques

    scenario.set_params_from_args(args=scenario_params)

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

    # ── 执行前准备卡片（从 scenario 诊断属性读取） ──
    _display_pre_execution_card(scenario, len(attack_seed_groups))

    # 5. 执行 Scenario（原生 run_async — 含 tqdm + max_retries + 自动恢复）
    #
    # L5: ScenarioIdentifier 恢复验证
    #    scenario._scenario_result_id 在 initialize_async() 中由原生 Scenario 设置，
    #    是当前运行的唯一标识。失败时用此 ID 精确检索部分结果，
    #    不再使用 memory.get_scenario_results()[-1]（可能返回前一次运行的结果）。
    scenario_result_id = getattr(scenario, "_scenario_result_id", None)
    scenario_error = None
    try:
        native_result = await scenario.run_async()
    except Exception as e:
        logger.error(f"Scenario execution failed: {e}")
        scenario_error = str(e)
        native_result = None
        # L5: 使用 scenario_result_id 精确检索当前运行的部分结果
        # （不再使用 memory.get_scenario_results()[-1] 避免取到前一次运行的结果）
        try:
            from pyrit.memory import CentralMemory
            memory = CentralMemory.get_memory_instance()
            # 优先使用已捕获的 scenario_result_id 精确查询
            sid = scenario_result_id or getattr(scenario, "_scenario_result_id", None)
            if sid:
                scenario_results = memory.get_scenario_results(
                    scenario_result_ids=[sid]
                )
                if scenario_results:
                    native_result = scenario_results[0]
                    logger.info(
                        f"Retrieved partial ScenarioResult from memory "
                        f"(scenario_result_id={sid}, {len(scenario_results)} results found)"
                    )
            else:
                logger.warning("No scenario_result_id available, cannot retrieve partial results")
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

    # ──────────────────────────────────────────────────────────
    # P0-A: 失败类型分析 — 激活 extract_failure_type_from_result
    # ──────────────────────────────────────────────────────────
    # 从执行结果中提取失败类型，用于：
    # 1. 诊断分析 — 了解失败原因分布
    # 2. Selector 反馈 — 更新 _last_failure_type（供 resume 场景使用）
    # 3. 跨 run 学习 — 失败类型通过 memory 持久化，未来 run 可受益
    # ──────────────────────────────────────────────────────────
    converter_variants = 0
    total_techniques = 0
    failure_type_counter: Counter = Counter()
    most_common_failure_type: str | None = None

    if native_result is not None:
        display_groups = native_result.get_display_groups() if hasattr(native_result, "get_display_groups") else {}
        for group_name, results in display_groups.items():
            for r in results:
                if r is None:
                    continue
                total_techniques += 1

                # Converter 检测：从 identifier.children['request_converters'] 提取
                identifier = None
                if hasattr(r, "get_attack_strategy_identifier"):
                    identifier = r.get_attack_strategy_identifier()
                if identifier is not None:
                    children = getattr(identifier, "children", None) or {}
                    if children.get("request_converters"):
                        converter_variants += 1

                # P0-A: 失败类型提取
                outcome = getattr(r, "outcome", None)
                if outcome is not None:
                    outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                    if outcome_str != "SUCCESS":
                        # 提取失败类型
                        failure_type = extract_failure_type_from_result(r)
                        failure_type_counter[failure_type] += 1

                # P0-A: 也检查 SequentialAttackResult 的 child_attack_results
                # 每个 child 是一次技术尝试，提取更细粒度的失败类型
                child_results = getattr(r, "child_attack_results", None) or []
                for child in child_results:
                    if child is None:
                        continue
                    child_outcome = getattr(child, "outcome", None)
                    if child_outcome is not None:
                        child_outcome_str = str(child_outcome.value).upper() if hasattr(child_outcome, "value") else str(child_outcome).upper()
                        if child_outcome_str != "SUCCESS":
                            child_failure_type = extract_failure_type_from_result(child)
                            failure_type_counter[child_failure_type] += 1

    # 计算最常见的失败类型
    if failure_type_counter:
        most_common_failure_type = failure_type_counter.most_common(1)[0][0]
        logger.info(
            f"P0-A: Failure type analysis — "
            f"total failures: {sum(failure_type_counter.values())}, "
            f"distribution: {dict(failure_type_counter)}, "
            f"most common: {most_common_failure_type}"
        )

        # P0-A: 更新 selector 的失败类型（供 resume 场景使用）
        # 注意：原生 AdaptiveScenario 的所有技术选择在 initialize_async() 时已完成，
        # 所以这个更新不会影响当前 run 的技术排序。但对于 resume 场景
        # （中断后恢复），selector 会使用此失败类型进行初始排序。
        selector = getattr(scenario, "_selector", None)
        if selector and hasattr(selector, "update_failure_type"):
            selector.update_failure_type(most_common_failure_type)
            logger.debug(
                f"P0-A: Updated selector failure_type to '{most_common_failure_type}' "
                f"(for resume scenarios)"
            )

    # v5.0: 执行后展示已统一到 s6_execute.py 的执行结果概要 info_box
    # 此处不再重复输出 [ADAPT] 完成统计和失败类型分布

    return AdaptiveRunResult(
        native_result=native_result,
        batch_result=batch_result,
        scenario_result_id=getattr(native_result, "id", ""),
        execution_time=elapsed,
        converter_variants_used=converter_variants,
        total_techniques_tried=total_techniques,
        failure_type_distribution=dict(failure_type_counter),
        most_common_failure_type=most_common_failure_type,
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


# ============================================================
# L5 展示辅助函数
# ============================================================

_W = 68


def _display_pre_execution_card(scenario: Any, seed_group_count: int) -> None:
    """
    执行前准备卡片 — 从 scenario 诊断属性读取并结构化展示

    在 scenario.initialize_async() 完成后、run_async() 之前调用，
    替代之前 _build_techniques_dict 中的 [DIAG] 裸 print。

    展示内容：
    - Converter Target 类型和模型
    - LLM 链是否跳过
    - 技术注册统计（基础+变体+跳过原因）
    - 内联种子组数
    """
    try:
        conv_type = getattr(scenario, "_diag_converter_type", "N/A")
        conv_model = getattr(scenario, "_diag_converter_model", "N/A")
        skip_llm = getattr(scenario, "_diag_skip_llm_chains", False)
        total_tech = getattr(scenario, "_diag_total_techniques", 0)
        variant_cnt = getattr(scenario, "_diag_variant_count", 0)
        sk_llm = getattr(scenario, "_diag_skipped_llm", 0)
        sk_small = getattr(scenario, "_diag_skipped_small_model", 0)
        sk_modality = getattr(scenario, "_diag_skipped_modality", 0)
        sk_runtime = getattr(scenario, "_diag_skipped_runtime", 0)
        sk_no_factory = getattr(scenario, "_diag_skipped_no_factory", 0)

        base_count = total_tech - variant_cnt

        llm_status = "✓ 保留" if not skip_llm else "✗ 跳过 (弱模型/小参数)"
        skip_parts = []
        if sk_llm:
            skip_parts.append(f"llm={sk_llm}")
        if sk_small:
            skip_parts.append(f"小模型={sk_small}")
        if sk_modality:
            skip_parts.append(f"模态={sk_modality}")
        if sk_runtime:
            skip_parts.append(f"运行时={sk_runtime}")
        if sk_no_factory:
            skip_parts.append(f"无工厂={sk_no_factory}")
        skip_str = ", ".join(skip_parts) if skip_parts else "无"

        print()
        print(f"  ┌─ 执行前准备 {'─' * max(1, _W - 22)}┐")
        print(f"  │ Converter Target: {conv_type} ({conv_model})")
        print(f"  │ LLM 辅助链:     {llm_status}")
        print(f"  │ 技术注册:        {base_count} 基础 + {variant_cnt} Converter 变体 = {total_tech} 总计")
        print(f"  │ 跳过统计:        {skip_str}")
        print(f"  │ 内联种子组:      {seed_group_count} 个")
        print(f"  │ 初始化:          ✓ 完成 (DatasetAttackConfiguration 已就绪)")
        print(f"  └{'─' * _W}┘")
    except Exception:
        pass
