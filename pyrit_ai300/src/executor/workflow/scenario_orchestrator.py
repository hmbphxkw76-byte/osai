"""
Scenario Orchestrator
=====================

④ 攻击执行层 - Scenario 编排器

核心设计（PyRIT 原生优先 + 自建 Scenario 扩展）：
1. 委托 NativeAttackExecutor 执行单次攻击（使用原生 AttackExecutor）
2. 保留自建批量调度（asyncio.Semaphore + ProgressDashboard）
3. 保留自建升级重试（失败后自动升级到更强的攻击技术）
4. 保留自建双通道输出（终端 + Markdown 文件）
5. 集成 AttackResultAttribution 实现父级编排器关联
6. 支持原生 SequentialAttack 异构技术链 + completion_policy 可配置

架构分层（PyRIT 架构师视角）：
    NativeAttackExecutor: 单次执行（原生 AttackExecutor + AttackSeedGroup）
    ScenarioOrchestrator: 批量调度（并发 + 超时 + 升级重试 + 输出 + Attribution）

对齐 PyRIT 1.0.0 五层架构：
  ① 数据准备层 → DatasetManager.load_datasets()
  ② 数据管理层 → CentralMemory (add_seed_datasets_to_memory / get_seed_groups)
  ②.5 交互选择层 → SeedGroupSelector (build_catalog / filter / prompt_user)
  ③ 攻击准备层 → AttackPreparator (SeedGroup → AttackSeedGroup)
  ④ 攻击执行层 → ScenarioOrchestrator (本模块)
  ⑤ 评估与追踪层 → Scorer + PyRIT Memory 审计链
"""

import asyncio
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from pyrit.executor.attack import SequenceCompletionPolicy
from pyrit.executor.attack.core.attack_result_attribution import AttackResultAttribution

from src.payloads.models import (
    AttackMode,
    AttackPlan,
    BatchAttackResult,
    PromptItem,
)
from src.executor.attack.core.attack_builder import ATTACK_CLASS_MAP, ATTACK_METADATA, create_attack_instance
from src.executor.attack.core.native_executor import NativeAttackExecutor
from src.executor.attack.core.scenario_event_handler import ScenarioEventHandler
from src.executor.attack.core.constants import (
    MULTI_TURN_TECHNIQUES as _MULTI_TURN_TECHNIQUES,
    SINGLE_TURN_ATTACKS as _SINGLE_TURN_ATTACKS,
    TAP_FAMILY_ATTACKS as _TAP_FAMILY_ATTACKS,
)
from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


def _truncate(text: str, max_len: int = 60) -> str:
    """截断文本用于终端显示"""
    text = text.replace("\n", " ").replace("\r", " ").strip()
    return text[:max_len] + "..." if len(text) > max_len else text


class ScenarioOrchestrator:
    """
    Scenario 编排器 - 委托 NativeAttackExecutor 执行批量攻击

    自研部分（PyRIT 原生不支持）：
    - 批量并发调度 + 进度仪表盘（asyncio.Semaphore + ProgressDashboard）
    - 攻击升级重试（失败后自动升级到更强的攻击技术）
    - 双通道输出（终端 + Markdown 文件）
    - AttackResultAttribution 父级关联

    PyRIT 原生委托：
    - NativeAttackExecutor 使用原生 AttackExecutor 执行单次攻击
    - SequentialAttack 使用原生异构技术链
    """

    def __init__(self, output_manager: Any = None):
        """
        初始化 Scenario 编排器

        Args:
            output_manager: 可选的 OutputManager 实例（依赖注入）。
                如果传入 None（默认），将在首次批量执行时延迟初始化。
                传入实例便于单元测试中注入 Mock。
        """
        self.config_loader = get_config_loader()
        attack_techniques = self.config_loader.get_strategy_config().get("attack_techniques", {})
        self.adversarial_techniques = {
            tech for tech, config in attack_techniques.items()
            if config.get("requires_adversarial", False)
        }
        # 依赖注入：允许外部传入 OutputManager（测试友好）
        # 如果未传入，保持延迟初始化（向后兼容）
        self._output_manager = output_manager
        # 委托原生攻击执行器（并发数=1，由 ScenarioOrchestrator 控制并发）
        self._executor = NativeAttackExecutor(max_concurrency=1)
        # L5 对齐：ScenarioEventHandler 实现事件可观测性
        self._event_handler = ScenarioEventHandler(verbose=False)

    def _get_output_manager(self, exam_id: str = None, verbose: bool = False):
        """
        获取 OutputManager（延迟初始化，向后兼容）

        如果构造函数传入了 output_manager（依赖注入），直接返回。
        否则在首次调用时延迟初始化。
        """
        if self._output_manager is not None:
            return self._output_manager
        from src.reporting.output_manager import OutputManager
        eid = exam_id or f"batch_{int(time.time())}"
        self._output_manager = OutputManager(exam_id=eid, verbose=verbose)
        return self._output_manager

    # ------------------------------------------------------------------
    # 批量执行入口
    # ------------------------------------------------------------------

    async def execute_batch(
        self,
        attack_plans: List[AttackPlan],
        objective_target: Any,
        judge_target: Any,
        max_concurrency: int = 4,
        fail_fast: bool = False,
        per_attack_timeout: int = 300,
        verbose: bool = False,
        exam_id: str = None,
        completion_policy: SequenceCompletionPolicy = SequenceCompletionPolicy.FIRST_SUCCESS,
        timeout_overrides: Optional[Dict[str, int]] = None,
        max_retries: int = 0,
    ) -> BatchAttackResult:
        """
        批量执行攻击计划

        使用 asyncio.Semaphore 控制并发，委托 NativeAttackExecutor 执行单次攻击。
        SequentialAttack 模式使用原生异构技术链 + 可配置 completion_policy。

        对齐 PyRIT 1.0.0 Resiliency 文档的 scenario-level retry：
          max_retries=0 (默认): 快速失败，不重试
          max_retries=3: 弹性恢复，跳过已完成攻击从异常点恢复

        Args:
            attack_plans: 攻击计划列表
            objective_target: 目标 PromptTarget
            judge_target: 评审用 LLM Target
            max_concurrency: 最大并发数
            fail_fast: 是否快速失败
            per_attack_timeout: 默认单次攻击超时秒数（被 timeout_overrides 覆盖）
            verbose: 是否输出详细结果
            exam_id: 考试 ID（用于输出目录命名）
            completion_policy: SequentialAttack 完成策略
            timeout_overrides: 按攻击模式差异化超时配置，如 {"single_turn": 90, "multi_turn": 300}
            max_retries: Scenario 级别重试次数（0=快速失败，3=弹性恢复）
                对齐 PyRIT max_retries 参数，重试时跳过已完成的攻击。

        Returns:
            BatchAttackResult 包含执行统计和结果列表
        """
        total = len(attack_plans)
        result = BatchAttackResult(total_plans=total)
        semaphore = asyncio.Semaphore(max_concurrency)

        from src.reporting.output_manager import ProgressDashboard, SummaryTable
        output_manager = self._get_output_manager(exam_id, verbose=verbose)
        dashboard = ProgressDashboard(total)
        mode_stats: Dict[str, Dict[str, int]] = {}

        # 创建 Scenario 级别的 Attribution parent_id
        scenario_parent_id = str(uuid.uuid4())

        def _plan_brief(plan: AttackPlan) -> str:
            owasp = plan.owasp_id or "N/A"
            mode = plan.prompt_item.attack_mode.value
            tech = plan.attack_technique
            obj = _truncate(plan.prompt_item.objective)
            return f"{owasp} | {mode} | {tech} | \"{obj}\""

        def _plan_detail(plan: AttackPlan) -> str:
            owasp = plan.owasp_id or "N/A"
            mode = plan.prompt_item.attack_mode.value
            tech = plan.attack_technique
            attack_class_name = ATTACK_CLASS_MAP.get(tech, type(None)).__name__
            scorer = plan.scorer_type
            converter = plan.converter_chain_name or "none"
            converter_list = ""
            if plan.converter_chain_name:
                chain_cfg = self.config_loader.get_converter_chain_config(plan.converter_chain_name)
                if chain_cfg and chain_cfg.get("converters"):
                    converter_list = f" -> [{', '.join(chain_cfg['converters'])}]"
            obj = _truncate(plan.prompt_item.objective, max_len=80)
            lines = [
                f"  ┌─ Plan ──────────────────────────────────────────────",
                f"  │ OWASP:      {owasp}",
                f"  │ Attack:     {attack_class_name}  ({mode})",
                f"  │ Technique:  {tech}",
                f"  │ Scorer:     {scorer}",
                f"  │ Converter:  {converter}{converter_list}",
                f"  │ Objective:  \"{obj}\"",
                f"  └─────────────────────────────────────────────────────",
            ]
            return "\n".join(lines)

        def _update_mode_stats(plan: AttackPlan, succeeded: bool, failed: bool):
            mode = plan.prompt_item.attack_mode.value
            if mode not in mode_stats:
                mode_stats[mode] = {"total": 0, "success": 0, "fail": 0}
            mode_stats[mode]["total"] += 1
            if succeeded:
                mode_stats[mode]["success"] += 1
            if failed:
                mode_stats[mode]["fail"] += 1

        def _create_attribution(plan: AttackPlan) -> AttackResultAttribution:
            """为每个攻击计划创建 AttackResultAttribution"""
            from src.executor.attack.core.attack_builder import create_attack_result_attribution
            return create_attack_result_attribution(
                parent_id=scenario_parent_id,
                parent_collection=f"{plan.attack_technique}_{plan.plan_id}",
                parent_eval_hash=plan.owasp_id,
            )

        async def _run_one(plan: AttackPlan) -> None:
            async with semaphore:
                brief = _plan_brief(plan)
                print(_plan_detail(plan))
                effective_timeout = self._resolve_timeout(plan, per_attack_timeout, timeout_overrides)
                print(f"  [START]  {brief}")
                plan_start = time.time()

                try:
                    attack_result = await asyncio.wait_for(
                        self._execute_single_plan(
                            plan, objective_target, judge_target,
                            completion_policy=completion_policy,
                            attribution=_create_attribution(plan),
                        ),
                        timeout=effective_timeout,
                    )
                    elapsed = time.time() - plan_start
                    result.executed += 1
                    result.results.append(attack_result)
                    completed_count[0] += 1
                    dashboard.increment_completed()

                    outcome = getattr(attack_result, "outcome", None)
                    if outcome is not None:
                        outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                        if outcome_str == "SUCCESS":
                            result.succeeded += 1
                            dashboard.update(succeeded=1)
                            _update_mode_stats(plan, succeeded=True, failed=False)
                            print(f"  [OK]    [{completed_count[0]}/{total}]  {brief} -> SUCCESS ({elapsed:.1f}s)")
                            await output_manager.output_attack_result(
                                attack_result,
                                to_terminal=(verbose or os.getenv("VERBOSE_SUCCESS", "").lower() in ("1", "true", "yes")),
                                to_file=True,
                                include_auxiliary=True,
                                include_adversarial=True,
                            )
                        else:
                            result.failed += 1
                            dashboard.update(failed=1)
                            _update_mode_stats(plan, succeeded=False, failed=True)
                            print(f"  [FAIL]  [{completed_count[0]}/{total}]  {brief} -> {outcome_str} ({elapsed:.1f}s)")
                            await output_manager.output_attack_result(
                                attack_result, to_terminal=False, to_file=True,
                                include_auxiliary=True, include_adversarial=False,
                            )
                            # P1-1: 攻击失败 → 智能升级重试（多候选+递归）
                            await self._try_upgrade_plans(
                                plan, attack_result, objective_target, judge_target,
                                result, dashboard, output_manager, verbose,
                                per_attack_timeout, timeout_overrides, completed_count,
                                total, _plan_brief, _update_mode_stats, _create_attribution,
                                completion_policy,
                            )
                    else:
                        result.failed += 1
                        dashboard.update(failed=1)
                        _update_mode_stats(plan, succeeded=False, failed=True)
                        print(f"  [FAIL]  [{completed_count[0]}/{total}]  {brief} -> no outcome ({elapsed:.1f}s)")

                    if completed_count[0] % 10 == 0 or completed_count[0] == total:
                        dashboard.print_progress()

                except asyncio.TimeoutError:
                    elapsed = time.time() - plan_start
                    result.executed += 1
                    result.errored += 1
                    completed_count[0] += 1
                    dashboard.increment_completed()
                    dashboard.update(errored=1)
                    _update_mode_stats(plan, succeeded=False, failed=True)
                    result.errors.append({"plan_id": plan.plan_id, "error": f"Timeout after {effective_timeout}s"})
                    print(f"  [TOUT]  [{completed_count[0]}/{total}]  {brief} -> 超时 ({elapsed:.1f}s, limit={effective_timeout}s)")
                    if completed_count[0] % 10 == 0 or completed_count[0] == total:
                        dashboard.print_progress()
                except Exception as e:
                    elapsed = time.time() - plan_start
                    result.executed += 1
                    result.errored += 1
                    completed_count[0] += 1
                    dashboard.increment_completed()
                    dashboard.update(errored=1)
                    _update_mode_stats(plan, succeeded=False, failed=True)
                    error_msg = str(e)
                    result.errors.append({"plan_id": plan.plan_id, "error": error_msg})
                    logger.warning(f"Plan {plan.plan_id} failed (non-fatal): {e}")
                    print(f"  [ERR]   [{completed_count[0]}/{total}]  {brief} -> {_truncate(error_msg, 80)} ({elapsed:.1f}s)")
                    if completed_count[0] % 10 == 0 or completed_count[0] == total:
                        dashboard.print_progress()
                    if fail_fast:
                        raise

        completed_count = [0]
        # Scenario-level retry (对齐 PyRIT max_retries)
        # max_retries=0: 快速失败；max_retries>0: 弫性恢复，跳过已完成计划
        remaining_plans = list(attack_plans)
        attempt = 0
        total_attempts = 1 + max_retries

        while remaining_plans and attempt < total_attempts:
            attempt += 1
            if attempt > 1:
                logger.info(
                    f"Scenario retry attempt {attempt}/{total_attempts} "
                    f"({len(remaining_plans)} plans remaining)"
                )
                print(f"\n  [RETRY] Scenario attempt {attempt}/{total_attempts} "
                      f"({len(remaining_plans)} plans remaining)")
                # 重置信号量和仪表盘
                semaphore = asyncio.Semaphore(max_concurrency)
                dashboard = ProgressDashboard(len(remaining_plans))

            try:
                tasks = [_run_one(plan) for plan in remaining_plans]
                await asyncio.gather(*tasks, return_exceptions=not fail_fast)
                break  # 成功完成，退出重试循环
            except Exception as e:
                if attempt >= total_attempts:
                    logger.error(f"Scenario failed after {attempt} attempts: {e}")
                    raise
                # 筛选出未完成的计划用于重试
                completed_plan_ids = {r for r in result.results if r is not None}
                remaining_plans = [
                    p for p in remaining_plans
                    if p not in completed_plan_ids
                ]
                logger.warning(
                    f"Scenario failed on attempt {attempt} "
                    f"({e.__class__.__name__}: {e}). "
                    f"Retrying... ({total_attempts - attempt} retries remaining)"
                )

        dashboard.print_progress()
        if mode_stats:
            print(SummaryTable.render_mode_table(mode_stats))

        # L5 对齐：输出事件统计摘要
        event_summary = self._event_handler.get_summary()
        if event_summary["total_events"] > 0:
            print(f"  [Events] {event_summary['executions']} executions, "
                  f"{event_summary['successes']} successes, "
                  f"{event_summary['failures']} failures, "
                  f"{event_summary['total_errors']} errors")

        await output_manager.close()
        result.errors.append({"plan_id": "_meta", "error": f"output_log: {output_manager.log_path}"})
        result.errors.append({"plan_id": "_meta_scenario", "error": f"attempts: {attempt}/{total_attempts}"})
        return result

    # ------------------------------------------------------------------
    # 按技术分组批量执行（PyRIT 原生并行优化）
    # ------------------------------------------------------------------

    async def execute_batch_grouped(
        self,
        attack_plans: List[AttackPlan],
        objective_target: Any,
        judge_target: Any,
        max_concurrency: int = 4,
        fail_fast: bool = False,
        per_attack_timeout: int = 300,
        verbose: bool = False,
        exam_id: str = None,
        timeout_overrides: Optional[Dict[str, int]] = None,
    ) -> BatchAttackResult:
        """
        按技术分组批量执行攻击计划

        PyRIT 原生优化：将相同攻击技术的计划分组，使用同一个 Attack 实例
        批量执行（AttackExecutor 原生并行），减少 Attack 实例创建开销。

        分组策略：
        1. 按 attack_technique 分组
        2. 每组创建一个 Attack 实例 + 多个 AttackSeedGroup
        3. 调用 NativeAttackExecutor.execute_batch_same_technique() 原生并行执行
        4. SEQUENTIAL 模式的计划仍逐个执行（异构技术链）

        Args:
            attack_plans: 攻击计划列表
            objective_target: 目标 PromptTarget
            judge_target: 评审用 LLM Target
            max_concurrency: 最大并发数
            fail_fast: 是否快速失败
            per_attack_timeout: 默认单次攻击超时秒数（被 timeout_overrides 覆盖）
            verbose: 是否输出详细结果
            exam_id: 考试 ID
            timeout_overrides: 按攻击模式差异化超时配置

        Returns:
            BatchAttackResult 包含执行统计和结果列表
        """
        total = len(attack_plans)
        result = BatchAttackResult(total_plans=total)

        from src.reporting.output_manager import ProgressDashboard, SummaryTable
        output_manager = self._get_output_manager(exam_id, verbose=verbose)
        dashboard = ProgressDashboard(total)
        mode_stats: Dict[str, Dict[str, int]] = {}
        scenario_parent_id = str(uuid.uuid4())
        completed_count = [0]

        # 按技术分组（SEQUENTIAL 模式单独处理）
        from collections import defaultdict
        groups: Dict[str, List[AttackPlan]] = defaultdict(list)
        sequential_plans: List[AttackPlan] = []

        for plan in attack_plans:
            if plan.prompt_item.attack_mode == AttackMode.SEQUENTIAL:
                sequential_plans.append(plan)
            else:
                groups[plan.attack_technique].append(plan)

        def _plan_brief(plan: AttackPlan) -> str:
            owasp = plan.owasp_id or "N/A"
            mode = plan.prompt_item.attack_mode.value
            tech = plan.attack_technique
            obj = _truncate(plan.prompt_item.objective)
            return f"{owasp} | {mode} | {tech} | \"{obj}\""

        def _update_mode_stats(plan: AttackPlan, succeeded: bool, failed: bool):
            mode = plan.prompt_item.attack_mode.value
            if mode not in mode_stats:
                mode_stats[mode] = {"total": 0, "success": 0, "fail": 0}
            mode_stats[mode]["total"] += 1
            if succeeded:
                mode_stats[mode]["success"] += 1
            if failed:
                mode_stats[mode]["fail"] += 1

        async def _process_result(plan, attack_result, elapsed):
            """处理单个攻击结果"""
            result.executed += 1
            result.results.append(attack_result)
            completed_count[0] += 1
            dashboard.increment_completed()

            outcome = getattr(attack_result, "outcome", None)
            brief = _plan_brief(plan)
            if outcome is not None:
                outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                if outcome_str == "SUCCESS":
                    result.succeeded += 1
                    dashboard.update(succeeded=1)
                    _update_mode_stats(plan, succeeded=True, failed=False)
                    print(f"  [OK]    [{completed_count[0]}/{total}]  {brief} -> SUCCESS ({elapsed:.1f}s)")
                    await output_manager.output_attack_result(
                        attack_result,
                        to_terminal=(verbose or os.getenv("VERBOSE_SUCCESS", "").lower() in ("1", "true", "yes")),
                        to_file=True, include_auxiliary=True, include_adversarial=True,
                    )
                else:
                    result.failed += 1
                    dashboard.update(failed=1)
                    _update_mode_stats(plan, succeeded=False, failed=True)
                    print(f"  [FAIL]  [{completed_count[0]}/{total}]  {brief} -> {outcome_str} ({elapsed:.1f}s)")
                    await output_manager.output_attack_result(
                        attack_result, to_terminal=False, to_file=True,
                        include_auxiliary=True, include_adversarial=False,
                    )
            else:
                result.failed += 1
                dashboard.update(failed=1)
                _update_mode_stats(plan, succeeded=False, failed=True)
                print(f"  [FAIL]  [{completed_count[0]}/{total}]  {brief} -> no outcome ({elapsed:.1f}s)")

            if completed_count[0] % 10 == 0 or completed_count[0] == total:
                dashboard.print_progress()

        # 1. 按技术分组执行（原生并行）
        for technique, plans_in_group in groups.items():
            print(f"\n  === 技术分组: {technique} ({len(plans_in_group)} 个计划) ===")

            # 为该组创建共享的 Attack 实例
            from src.executor.attack.core.constants import (
                SINGLE_TURN_ATTACKS as _SINGLE_TURN_ATTACKS,
                TAP_FAMILY_ATTACKS as _TAP_FAMILY_ATTACKS,
                MAX_TURNS_ATTACKS as _MAX_TURNS_ATTACKS,
                TREE_DEPTH_ATTACKS as _TREE_DEPTH_ATTACKS,
            )
            from src.executor.attack.core.attack_builder import (
                create_attack_instance, create_attack_adversarial_config,
                create_attack_result_attribution,
            )
            from src.converters import load_preset_converter_chain
            from pyrit.models import AttackSeedGroup, SeedObjective, SeedPrompt

            first_plan = plans_in_group[0]
            scoring_config = self._executor._create_scoring_config(
                first_plan.scorer_type, judge_target, first_plan, technique
            )

            converter_config = None
            if first_plan.converter_chain_name:
                converter_config = load_preset_converter_chain(
                    first_plan.converter_chain_name, converter_target=judge_target
                )

            attack_kwargs: Dict[str, Any] = {}
            if converter_config:
                attack_kwargs["attack_converter_config"] = converter_config

            if technique not in _SINGLE_TURN_ATTACKS and technique in self.adversarial_techniques:
                attack_kwargs["attack_adversarial_config"] = create_attack_adversarial_config(
                    judge_target=judge_target,
                    metadata=first_plan.prompt_item.metadata or {},
                )

            if technique in _MAX_TURNS_ATTACKS:
                attack_kwargs["max_turns"] = first_plan.max_turns
            elif technique in _TREE_DEPTH_ATTACKS:
                attack_kwargs["tree_depth"] = first_plan.max_turns

            # TAP/PAIR 高级参数
            if technique in _TAP_FAMILY_ATTACKS:
                tap_metadata = first_plan.prompt_item.metadata or {}
                for param_key in ("tree_width", "branching_factor", "batch_size"):
                    param_value = tap_metadata.get(param_key)
                    if param_value is not None and isinstance(param_value, int) and param_value > 0:
                        attack_kwargs[param_key] = param_value

            attack = create_attack_instance(
                technique_name=technique,
                objective_target=objective_target,
                attack_scoring_config=scoring_config,
                event_handler=self._event_handler,
                **attack_kwargs,
            )

            # 构建该组所有计划的 AttackSeedGroup
            seed_groups = []
            plan_index_map = []  # 记录每个 seed_group 对应的 plan
            for plan in plans_in_group:
                sg = self._executor._build_attack_seed_group(
                    plan, plan.prompt_item.objective, include_conversation=True
                )
                seed_groups.append(sg)
                plan_index_map.append(plan)

            # 原生批量执行
            adversarial_chat = judge_target if (
                technique not in _SINGLE_TURN_ATTACKS and technique in self.adversarial_techniques
            ) else None

            objective_scorer = scoring_config.objective_scorer if scoring_config else None

            attribution = create_attack_result_attribution(
                parent_id=scenario_parent_id,
                parent_collection=f"{technique}_batch",
                parent_eval_hash=first_plan.owasp_id,
            )

            try:
                import time as _time
                batch_start = _time.time()
                group_timeout = self._resolve_timeout(first_plan, per_attack_timeout, timeout_overrides)
                executor_result = await asyncio.wait_for(
                    self._executor.execute_batch_same_technique(
                        attack=attack,
                        seed_groups=seed_groups,
                        adversarial_chat=adversarial_chat,
                        objective_scorer=objective_scorer,
                        memory_labels=first_plan.memory_labels,
                        attribution=attribution,
                        return_partial_on_failure=True,
                    ),
                    timeout=group_timeout * len(seed_groups),
                )
                batch_elapsed = _time.time() - batch_start

                # 处理结果
                for idx, attack_result in enumerate(executor_result.completed_results):
                    plan = plan_index_map[idx]
                    await _process_result(plan, attack_result, batch_elapsed / len(seed_groups))

                # 处理失败项
                for obj_str, exc in executor_result.incomplete_objectives:
                    plan = next((p for p in plans_in_group if p.prompt_item.objective == obj_str), None)
                    if plan:
                        result.executed += 1
                        result.errored += 1
                        completed_count[0] += 1
                        dashboard.increment_completed()
                        dashboard.update(errored=1)
                        _update_mode_stats(plan, succeeded=False, failed=True)
                        result.errors.append({"plan_id": plan.plan_id, "error": str(exc)})
                        print(f"  [ERR]   [{completed_count[0]}/{total}]  {_plan_brief(plan)} -> {_truncate(str(exc), 80)}")

            except asyncio.TimeoutError:
                print(f"  [TOUT]  技术组 {technique} 超时")
                for plan in plans_in_group:
                    result.executed += 1
                    result.errored += 1
                    completed_count[0] += 1
                    dashboard.increment_completed()
                    dashboard.update(errored=1)
                    _update_mode_stats(plan, succeeded=False, failed=True)
                    result.errors.append({"plan_id": plan.plan_id, "error": "Batch timeout"})
            except Exception as e:
                print(f"  [ERR]   技术组 {technique} 批量执行失败: {_truncate(str(e), 80)}")
                logger.warning(f"Batch execution for technique '{technique}' failed: {e}")
                # 回退到逐个执行
                for plan in plans_in_group:
                    try:
                        plan_start = _time.time()
                        plan_timeout = self._resolve_timeout(plan, per_attack_timeout, timeout_overrides)
                        attack_result = await asyncio.wait_for(
                            self._executor.execute_single_attack(
                                plan, objective_target, judge_target,
                                attribution=create_attack_result_attribution(
                                    parent_id=scenario_parent_id,
                                    parent_collection=f"{technique}_{plan.plan_id}",
                                    parent_eval_hash=plan.owasp_id,
                                ),
                            ),
                            timeout=plan_timeout,
                        )
                        elapsed = _time.time() - plan_start
                        await _process_result(plan, attack_result, elapsed)
                    except Exception as inner_e:
                        result.executed += 1
                        result.errored += 1
                        completed_count[0] += 1
                        dashboard.increment_completed()
                        dashboard.update(errored=1)
                        _update_mode_stats(plan, succeeded=False, failed=True)
                        result.errors.append({"plan_id": plan.plan_id, "error": str(inner_e)})
                        print(f"  [ERR]   [{completed_count[0]}/{total}]  {_plan_brief(plan)} -> {_truncate(str(inner_e), 80)}")

        # 2. SEQUENTIAL 模式逐个执行
        for plan in sequential_plans:
            try:
                import time as _time
                plan_start = _time.time()
                seq_timeout = self._resolve_timeout(plan, per_attack_timeout, timeout_overrides)
                attack_result = await asyncio.wait_for(
                    self._executor.execute_sequential_attack(
                        plan, objective_target, judge_target,
                        attribution=create_attack_result_attribution(
                            parent_id=scenario_parent_id,
                            parent_collection=f"sequential_{plan.plan_id}",
                            parent_eval_hash=plan.owasp_id,
                        ),
                    ),
                    timeout=seq_timeout,
                )
                elapsed = _time.time() - plan_start
                await _process_result(plan, attack_result, elapsed)
            except Exception as e:
                result.executed += 1
                result.errored += 1
                completed_count[0] += 1
                dashboard.increment_completed()
                dashboard.update(errored=1)
                _update_mode_stats(plan, succeeded=False, failed=True)
                result.errors.append({"plan_id": plan.plan_id, "error": str(e)})
                print(f"  [ERR]   [{completed_count[0]}/{total}]  {_plan_brief(plan)} -> {_truncate(str(e), 80)}")
                if fail_fast:
                    raise

        dashboard.print_progress()
        if mode_stats:
            print(SummaryTable.render_mode_table(mode_stats))
        await output_manager.close()
        result.errors.append({"plan_id": "_meta", "error": f"output_log: {output_manager.log_path}"})
        return result

    # ------------------------------------------------------------------
    # 超时解析 - 按攻击模式差异化
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_timeout(
        plan: AttackPlan,
        default_timeout: int,
        timeout_overrides: Optional[Dict[str, int]] = None,
    ) -> int:
        """
        根据攻击计划的模式解析有效超时时间

        优先级：timeout_overrides[mode] > default_timeout

        Args:
            plan: 攻击计划
            default_timeout: 默认超时秒数
            timeout_overrides: 按攻击模式差异化超时配置

        Returns:
            有效超时秒数
        """
        if not timeout_overrides:
            return default_timeout
        mode_str = plan.prompt_item.attack_mode.value
        return timeout_overrides.get(mode_str, default_timeout)

    # ------------------------------------------------------------------
    # 单计划执行 - 委托 NativeAttackExecutor
    # ------------------------------------------------------------------

    async def _execute_single_plan(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
        completion_policy: SequenceCompletionPolicy = SequenceCompletionPolicy.FIRST_SUCCESS,
        attribution: Optional[AttackResultAttribution] = None,
    ) -> Any:
        """
        根据 attack_mode 分派到不同的执行路径

        - SEQUENTIAL 模式：使用原生 SequentialAttack（异构技术链 + completion_policy）
        - MULTI_TURN 显式 turns：逐轮发送（委托 NativeAttackExecutor）
        - 其余模式：统一委托 NativeAttackExecutor.execute_single_attack()
        """
        mode = plan.prompt_item.attack_mode

        # SEQUENTIAL 模式：使用原生 SequentialAttack
        if mode == AttackMode.SEQUENTIAL:
            return await self._executor.execute_sequential_attack(
                plan, objective_target, judge_target,
                completion_policy=completion_policy,
                attribution=attribution,
            )

        # MULTI_TURN 模式且有显式 turns：逐轮发送
        if mode == AttackMode.MULTI_TURN and plan.prompt_item.multi_turn_steps:
            return await self._execute_multi_turn_explicit(
                plan, objective_target, judge_target, attribution=attribution
            )

        # 其余模式（SINGLE_TURN / MULTI_TURN 无显式 turns / CONVERTER_ENHANCED）
        # 统一委托 NativeAttackExecutor
        return await self._executor.execute_single_attack(
            plan, objective_target, judge_target,
            attribution=attribution,
        )

    async def _execute_multi_turn_explicit(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
        attribution: Optional[AttackResultAttribution] = None,
    ) -> Any:
        """
        多轮渐进攻击（显式 turns 模式）

        逐轮发送，每轮委托 NativeAttackExecutor.execute_single_attack()。
        对话上下文通过 PyRIT Memory 系统自动维护。
        """
        turns = plan.prompt_item.multi_turn_steps
        last_result = None

        for i, turn_objective in enumerate(turns):
            step_labels = {
                **plan.memory_labels,
                "multi_turn_step": str(i + 1),
                "total_turns": str(len(turns)),
            }
            last_result = await self._executor.execute_single_attack(
                plan, objective_target, judge_target,
                objective_override=turn_objective,
                memory_labels_override=step_labels,
                attribution=attribution,
            )
        return last_result

    # ------------------------------------------------------------------
    # 攻击升级策略（委托 upgrade_strategy.py 模块）
    # ------------------------------------------------------------------

    def _generate_upgrade_plans(
        self,
        original_plan: AttackPlan,
        failed_result: Any,
    ) -> List[AttackPlan]:
        """根据失败结果生成升级的攻击计划（委托 AttackUpgradeStrategy）"""
        if not hasattr(self, "_upgrade_strategy"):
            from src.executor.workflow.upgrade_strategy import AttackUpgradeStrategy
            self._upgrade_strategy = AttackUpgradeStrategy(self.config_loader)
        return self._upgrade_strategy.generate_upgrade_plans(original_plan, failed_result)

    def _create_upgraded_plan(
        self,
        original_plan: AttackPlan,
        new_technique: str,
        new_mode: AttackMode,
        converter_chain: Optional[str] = None,
        reason: str = "",
    ) -> AttackPlan:
        """创建升级的攻击计划（委托 AttackUpgradeStrategy）"""
        from src.executor.workflow.upgrade_strategy import AttackUpgradeStrategy
        return AttackUpgradeStrategy.create_upgraded_plan(
            original_plan, new_technique, new_mode,
            converter_chain=converter_chain, reason=reason,
        )

    # ------------------------------------------------------------------
    # P1-1: 智能升级重试（多候选+递归）
    # ------------------------------------------------------------------

    async def _try_upgrade_plans(
        self,
        original_plan: AttackPlan,
        failed_result: Any,
        objective_target: Any,
        judge_target: Any,
        result: Any,
        dashboard: Any,
        output_manager: Any,
        verbose: bool,
        per_attack_timeout: int,
        timeout_overrides: Optional[Dict[str, int]],
        completed_count: list,
        total: int,
        plan_brief_fn: Any,
        update_mode_stats_fn: Any,
        create_attribution_fn: Any,
        completion_policy: Any,
        _depth: int = 0,
        _tried: Optional[set] = None,
    ) -> bool:
        """
        P1-1: 智能升级重试 — 遍历多个候选方案，逐个尝试直到成功或耗尽

        支持递归升级：如果某个升级方案也失败，可以继续生成更深层的升级方案。
        受 MAX_UPGRADE_DEPTH 限制，防止无限递归。

        Args:
            original_plan: 原始失败的攻击计划
            failed_result: 失败的 AttackResult
            objective_target: 目标 PromptTarget
            judge_target: 评审 LLM Target
            result: BatchAttackResult 实例（用于统计）
            dashboard: ProgressDashboard 实例
            output_manager: OutputManager 实例
            verbose: 是否详细输出
            per_attack_timeout: 单次攻击超时
            timeout_overrides: 差异化超时配置
            completed_count: 完成计数器 [int]
            total: 总计划数
            plan_brief_fn: 计划摘要函数
            update_mode_stats_fn: 模式统计更新函数
            create_attribution_fn: Attribution 创建函数
            completion_policy: SequentialAttack 完成策略
            _depth: 当前升级深度（内部使用）
            _tried: 已尝试过的 (technique, mode) 组合集合（内部使用）

        Returns:
            True 如果某个升级方案成功，False 如果所有方案都失败
        """
        from src.executor.workflow.upgrade_strategy import MAX_UPGRADE_DEPTH

        if _depth >= MAX_UPGRADE_DEPTH:
            logger.debug(f"Upgrade depth limit reached ({_depth}), stopping recursive upgrade")
            return False

        tried = _tried or set()
        # 标记原始计划为已尝试
        tried.add((original_plan.attack_technique, original_plan.prompt_item.attack_mode.value))

        # 生成升级候选方案（传入已尝试组合和当前深度）
        if not hasattr(self, "_upgrade_strategy"):
            from src.executor.workflow.upgrade_strategy import AttackUpgradeStrategy
            self._upgrade_strategy = AttackUpgradeStrategy(self.config_loader)

        upgraded_plans = self._upgrade_strategy.generate_upgrade_plans(
            original_plan=original_plan,
            failed_result=failed_result,
            tried_combinations=tried,
            current_depth=_depth,
        )

        if not upgraded_plans:
            logger.info(f"No upgrade candidates available for {original_plan.plan_id} at depth {_depth}")
            return False

        for upgraded_plan in upgraded_plans:
            # 标记当前候选为已尝试
            combo = (upgraded_plan.attack_technique, upgraded_plan.prompt_item.attack_mode.value)
            tried.add(combo)

            result.upgrade_attempts += 1
            dashboard.update(upgrade_attempts=1)

            up_brief = plan_brief_fn(upgraded_plan)
            indent = "    " * _depth
            print(f"  [UPG]{indent}  {up_brief}  (升级自 {original_plan.attack_technique}, depth={_depth + 1})")

            up_effective_timeout = self._resolve_timeout(upgraded_plan, per_attack_timeout, timeout_overrides)
            up_start = time.time()

            try:
                upgraded_result = await asyncio.wait_for(
                    self._execute_single_plan(
                        upgraded_plan, objective_target, judge_target,
                        completion_policy=completion_policy,
                        attribution=create_attribution_fn(upgraded_plan),
                    ),
                    timeout=up_effective_timeout,
                )
                up_elapsed = time.time() - up_start
                result.executed += 1
                result.results.append(upgraded_result)
                upgraded_outcome = getattr(upgraded_result, "outcome", None)

                if upgraded_outcome is not None:
                    upgraded_outcome_str = (
                        str(upgraded_outcome.value).upper()
                        if hasattr(upgraded_outcome, "value")
                        else str(upgraded_outcome).upper()
                    )

                    if upgraded_outcome_str == "SUCCESS":
                        # 升级成功！
                        result.succeeded += 1
                        result.upgrade_success += 1
                        dashboard.update(succeeded=1, upgrade_success=1)
                        update_mode_stats_fn(upgraded_plan, succeeded=True, failed=False)
                        print(f"  [OK]{indent}   {up_brief} -> SUCCESS (升级, {up_elapsed:.1f}s)")
                        await output_manager.output_attack_result(
                            upgraded_result,
                            to_terminal=(verbose or os.getenv("VERBOSE_SUCCESS", "").lower() in ("1", "true", "yes")),
                            to_file=True, include_auxiliary=True, include_adversarial=True,
                        )
                        return True  # 成功，停止尝试其他候选

                    else:
                        # 升级也失败
                        result.failed += 1
                        dashboard.update(failed=1)
                        update_mode_stats_fn(upgraded_plan, succeeded=False, failed=True)
                        print(f"  [FAIL]{indent} {up_brief} -> {upgraded_outcome_str} (升级, {up_elapsed:.1f}s)")
                        await output_manager.output_attack_result(
                            upgraded_result, to_terminal=False, to_file=True,
                        )

                        # 递归升级：尝试升级这个失败的升级方案
                        recursive_success = await self._try_upgrade_plans(
                            upgraded_plan, upgraded_result, objective_target, judge_target,
                            result, dashboard, output_manager, verbose,
                            per_attack_timeout, timeout_overrides, completed_count,
                            total, plan_brief_fn, update_mode_stats_fn, create_attribution_fn,
                            completion_policy,
                            _depth=_depth + 1,
                            _tried=tried,
                        )
                        if recursive_success:
                            return True
                else:
                    result.failed += 1
                    dashboard.update(failed=1)
                    update_mode_stats_fn(upgraded_plan, succeeded=False, failed=True)
                    print(f"  [FAIL]{indent} {up_brief} -> no outcome (升级, {up_elapsed:.1f}s)")

            except asyncio.TimeoutError:
                elapsed = time.time() - up_start
                result.errored += 1
                dashboard.update(errored=1)
                result.errors.append({
                    "plan_id": upgraded_plan.plan_id,
                    "error": f"Upgrade timeout after {up_effective_timeout}s",
                })
                print(f"  [TOUT]{indent} {up_brief} -> 超时 ({elapsed:.1f}s, limit={up_effective_timeout}s)")
            except Exception as upgrade_error:
                result.errored += 1
                dashboard.update(errored=1)
                result.errors.append({
                    "plan_id": upgraded_plan.plan_id,
                    "error": f"Upgrade failed: {upgrade_error}",
                })
                print(f"  [ERR]{indent}  {up_brief} -> 升级失败: {_truncate(str(upgrade_error), 80)}")

        return False

    # ------------------------------------------------------------------
    # L5 对齐：事件可观测性 + AttackIdentifier 去重
    # ------------------------------------------------------------------

    def get_event_summary(self) -> Dict[str, Any]:
        """
        获取 ScenarioEventHandler 的事件统计摘要

        Returns:
            包含 total_events / total_errors / executions / successes / failures 的字典
        """
        return self._event_handler.get_summary()

    def get_event_errors(self) -> List[Any]:
        """获取所有错误事件记录"""
        return self._event_handler.get_errors()

    @staticmethod
    def deduplicate_plans_by_identifier(
        attack_plans: List[AttackPlan],
    ) -> tuple[List[AttackPlan], List[AttackPlan]]:
        """
        L5 对齐：利用 AttackIdentifier 体系进行攻击计划去重

        PyRIT 1.0.0 的 AttackStrategy.get_identifier() 返回 ComponentIdentifier，
        包含 attack class / target / scorer / converter 的内容哈希。
        相同 identifier 的攻击计划会产生相同的执行行为，可以安全跳过。

        去重策略：
        1. 按 (technique, objective, scorer_type, converter_chain_name) 分组
        2. 每组保留第一个计划（最高优先级）
        3. 返回 (unique_plans, duplicates)

        Args:
            attack_plans: 待去重的攻击计划列表

        Returns:
            (unique_plans, duplicates) 元组
        """
        seen_keys: set = set()
        unique: List[AttackPlan] = []
        duplicates: List[AttackPlan] = []

        for plan in attack_plans:
            # 构建去重键：技术 + 目标 + 评分器 + 转换器链
            dedup_key = (
                plan.attack_technique,
                plan.prompt_item.objective,
                plan.scorer_type,
                plan.converter_chain_name or "",
                plan.owasp_id or "",
            )
            if dedup_key in seen_keys:
                duplicates.append(plan)
                logger.debug(
                    f"Dedup: skipping duplicate plan {plan.plan_id} "
                    f"(technique={plan.attack_technique}, owasp={plan.owasp_id})"
                )
            else:
                seen_keys.add(dedup_key)
                unique.append(plan)

        if duplicates:
            logger.info(
                f"AttackIdentifier dedup: {len(attack_plans)} plans → "
                f"{len(unique)} unique, {len(duplicates)} duplicates removed"
            )

        return unique, duplicates


# ============================================================
# 工厂函数
# ============================================================


async def execute_batch_attacks(
    attack_plans: List[AttackPlan],
    objective_target: Any,
    judge_target: Any,
    max_concurrency: int = 4,
    fail_fast: bool = False,
    per_attack_timeout: int = 300,
    verbose: bool = False,
    exam_id: str = None,
    completion_policy: SequenceCompletionPolicy = SequenceCompletionPolicy.FIRST_SUCCESS,
    timeout_overrides: Optional[Dict[str, int]] = None,
    output_manager: Any = None,
    max_retries: int = 0,
) -> BatchAttackResult:
    """
    批量执行攻击计划（工厂函数）

    Args:
        attack_plans: 攻击计划列表
        objective_target: 目标 PromptTarget
        judge_target: 评审用 LLM Target
        max_concurrency: 最大并发数
        fail_fast: 是否快速失败
        per_attack_timeout: 默认单次攻击超时秒数（被 timeout_overrides 覆盖）
        verbose: 是否输出详细结果
        exam_id: 考试 ID
        completion_policy: SequentialAttack 完成策略
        timeout_overrides: 按攻击模式差异化超时配置，如 {"single_turn": 90, "multi_turn": 300}
        output_manager: 可选的 OutputManager 实例（依赖注入，测试友好）
        max_retries: Scenario 级别重试次数（0=快速失败，3=弫性恢复）
            对齐 PyRIT 1.0.0 Resiliency 文档的 max_retries 参数。
            重试时跳过已完成的攻击，从异常点恢复。

    Returns:
        BatchAttackResult
    """
    orchestrator = ScenarioOrchestrator(output_manager=output_manager)
    return await orchestrator.execute_batch(
        attack_plans, objective_target, judge_target,
        max_concurrency, fail_fast, per_attack_timeout,
        verbose=verbose, exam_id=exam_id,
        completion_policy=completion_policy,
        timeout_overrides=timeout_overrides,
        max_retries=max_retries,
    )
