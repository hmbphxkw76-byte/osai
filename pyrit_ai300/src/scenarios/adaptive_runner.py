"""
Adaptive Runner — P3+P4: 原生 AI300AdaptiveScenario 执行入口 + per_attack_timeout 包裹
==================================================================================

P3: 消除双轨 — pipeline.py 调用此模块替代 ScenarioOrchestrator.execute_batch()
P4: per_attack_timeout 包裹 — PyRIT 无 per-attack 超时，通过 asyncio.wait_for 补充

执行流程：
  1. 创建 AI300AdaptiveScenario（含 Converter 变体）
  2. 注册技术到 AttackTechniqueRegistry（含 Converter 变体）
  3. scenario.initialize_async() → 原生构建 AtomicAttack + SequentialAttack(FIRST_SUCCESS)
  4. scenario.run_async() → 原生执行（含 tqdm + max_retries + 自动恢复）
  5. per_attack_timeout 包裹（自建保留）
  6. ScenarioResult → ScenarioResultBridge → BatchAttackResult（向后兼容）

保留自建：
  - per_attack_timeout（PyRIT 无 per-attack 超时）
  - OWASP 映射（通过 memory_labels）
"""

import asyncio
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

    # 创建 objective_scorer（从 judge_target 构建 SelfAskTrueFalseScorer）
    # PyRIT AdaptiveScenario 需要 objective_scorer，否则会尝试从 TargetRegistry
    # 获取默认 scorer，回退时创建 OpenAIChatTarget 需要 OPENAI_CHAT_MODEL 环境变量
    objective_scorer = None
    try:
        from pyrit.score import SelfAskTrueFalseScorer
        objective_scorer = SelfAskTrueFalseScorer(chat_target=judge_target)
        logger.debug("Created SelfAskTrueFalseScorer from judge_target")
    except Exception as e:
        logger.warning(f"Failed to create objective_scorer from judge_target: {e}")
        # Fallback: 注册 judge_target 为 'objective_scorer_chat' 到 TargetRegistry
        # 这样 PyRIT AdaptiveScenario._get_default_objective_scorer() 可以找到它
        try:
            from pyrit.registry import TargetRegistry
            registry = TargetRegistry.get_registry_singleton()
            registry.register_instance(
                name="objective_scorer_chat",
                instance=judge_target,
            )
            logger.info("Registered judge_target as 'objective_scorer_chat' in TargetRegistry")
        except Exception as e2:
            logger.warning(f"Failed to register judge_target as 'objective_scorer_chat': {e2}")

    # 1. 注册技术（含 Converter 变体）到 AttackTechniqueRegistry
    try:
        register_ai300_techniques(
            tags=["all"],
            reset=False,
            converter_target=converter_target,
            include_variants=True,
        )
    except Exception as e:
        logger.warning(f"Technique registration failed (non-fatal): {e}")

    # 2. 构建 memory_labels（OWASP 映射）
    labels = build_memory_labels(owasp_id=owasp_id, exam_id=exam_id)
    if memory_labels:
        labels.update(memory_labels)

    # 3. 创建 AI300AdaptiveScenario（传入 objective_scorer + target_type）
    scenario = AI300AdaptiveScenario(
        converter_target=converter_target,
        objective_scorer=objective_scorer,
        target_type=target_type,
    )

    # 设置参数
    scenario.set_params_from_args(args={
        "objective_target": objective_target,
        "max_attempts_per_objective": max_attempts_per_objective,
        "per_attack_timeout": per_attack_timeout,
    })

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

    # 5. 执行 Scenario（per_attack_timeout 包裹 — 自建保留）
    try:
        if per_attack_timeout > 0:
            native_result = await asyncio.wait_for(
                scenario.run_async(),
                timeout=per_attack_timeout,
            )
        else:
            native_result = await scenario.run_async()
    except asyncio.TimeoutError:
        logger.warning(f"Scenario timed out after {per_attack_timeout}s")
        native_result = getattr(scenario, "_scenario_result", None)
    except Exception as e:
        logger.error(f"Scenario execution failed: {e}")
        native_result = getattr(scenario, "_scenario_result", None)

    elapsed = time.time() - start_time

    # 6. 结果转换（向后兼容 BatchAttackResult）
    batch_result = _convert_native_to_batch_result(
        native_result,
        attack_plans=attack_plans,
        owasp_id=owasp_id,
    )

    # 统计 Converter 变体使用情况
    converter_variants = 0
    total_techniques = 0
    if native_result is not None:
        display_groups = native_result.get_display_groups() if hasattr(native_result, "get_display_groups") else {}
        for group_name, results in display_groups.items():
            for r in results:
                total_techniques += 1
                identifier = r.get_attack_strategy_identifier() if hasattr(r, "get_attack_strategy_identifier") else None
                if identifier and "+" in (identifier.unique_name or ""):
                    converter_variants += 1

    if verbose:
        print(f"  [ADAPT] 完成: {batch_result.succeeded}/{batch_result.executed} 成功, "
              f"{converter_variants} converter variants used, {elapsed:.1f}s")
        # 展示执行后实际使用的 Converter 变体及其结果
        AI300AdaptiveScenario.display_used_converters(native_result)
        # 增强展示：Per-Group Breakdown 含技术+Converter+OWASP
        _display_enhanced_group_breakdown(native_result, owasp_id=owasp_id)

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


def _display_enhanced_group_breakdown(
    native_result: Any,
    *,
    owasp_id: str = "",
) -> None:
    """
    增强 Per-Group Breakdown 展示（含攻击技术+Converter组合+OWASP 对齐）

    使用 PyRIT 原生 ScenarioResult.get_display_groups() 获取分组，
    然后从每个 AttackResult 中提取：
    - 攻击技术名（get_attack_strategy_identifier().unique_name）
    - Converter 变体（技术名中 "+" 后的部分）
    - OWASP ID（从 labels 提取，fallback 到传入的 owasp_id）

    Args:
        native_result: 原生 ScenarioResult
        owasp_id: 默认 OWASP ID（当 result 中无 labels 时使用）
    """
    if native_result is None:
        return

    if not hasattr(native_result, "get_display_groups"):
        return

    display_groups = native_result.get_display_groups()
    if not display_groups:
        return

    # 收集每组统计信息
    group_stats: list[dict[str, Any]] = []
    for group_name, results in display_groups.items():
        total = len(results)
        success = 0
        techniques: set[str] = set()
        converters: set[str] = set()
        owasp_ids: set[str] = set()

        for r in results:
            if r is None:
                continue
            # 成功统计
            outcome = getattr(r, "outcome", None)
            if outcome is not None:
                outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                if outcome_str == "SUCCESS":
                    success += 1

            # 技术名 + Converter 变体
            identifier = None
            if hasattr(r, "get_attack_strategy_identifier"):
                identifier = r.get_attack_strategy_identifier()
            if identifier is not None:
                name = getattr(identifier, "unique_name", "") or ""
                if "+" in name:
                    base_tech, converter_chain = name.split("+", 1)
                    techniques.add(base_tech)
                    converters.add(converter_chain)
                else:
                    techniques.add(name)

            # OWASP ID
            labels = getattr(r, "labels", None) or {}
            r_owasp = labels.get("owasp_id", "")
            if r_owasp:
                owasp_ids.add(r_owasp)

        failure = total - success
        rate = success / total if total > 0 else 0.0
        group_stats.append({
            "group_name": group_name,
            "total": total,
            "success": success,
            "failure": failure,
            "success_rate": rate,
            "techniques": sorted(techniques),
            "converters": sorted(converters),
            "owasp_id": ", ".join(sorted(owasp_ids)) if owasp_ids else owasp_id,
        })

    # 按成功率降序排列
    group_stats.sort(key=lambda s: s["success_rate"], reverse=True)

    # 输出增强版 Per-Group Breakdown
    print(f"\n  {'=' * 76}")
    print(f"  Enhanced Per-Group Breakdown (Techniques + Converters + OWASP)")
    print(f"  {'=' * 76}")

    for stat in group_stats:
        rate_pct = stat["success_rate"] * 100
        print(f"\n  Group: {stat['group_name']}")
        print(f"    Results: {stat['total']}, "
              f"Success: {stat['success']}, "
              f"Failure: {stat['failure']}, "
              f"Rate: {rate_pct:.0f}%")

        # 攻击技术
        if stat["techniques"]:
            print(f"    Techniques:  {', '.join(stat['techniques'])}")
        else:
            print(f"    Techniques:  (unknown)")

        # Converter 变体
        if stat["converters"]:
            print(f"    Converters:  {', '.join(stat['converters'])}")
        else:
            print(f"    Converters:  (none - base techniques only)")

        # OWASP 对齐
        if stat["owasp_id"]:
            print(f"    OWASP:       {stat['owasp_id']}")

    print(f"\n  {'=' * 76}\n")
