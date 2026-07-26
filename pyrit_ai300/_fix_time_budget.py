#!/usr/bin/env python3
"""Add per-plan upgrade time budget to _try_upgrade_plans"""

filepath = "src/executor/workflow/scenario_orchestrator.py"
content = open(filepath, "r", encoding="utf-8").read()

# 1. Add _upgrade_time_budget parameter to _try_upgrade_plans signature
old_sig = """    async def _try_upgrade_plans(
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
    ) -> bool:"""

new_sig = """    async def _try_upgrade_plans(
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
        _cumulative_time: float = 0.0,
    ) -> bool:"""

if old_sig in content:
    content = content.replace(old_sig, new_sig, 1)
    print("OK: Added _cumulative_time parameter")
else:
    print("NOT FOUND: signature")

# 2. Add time budget check after depth check
old_depth_check = """        from src.executor.workflow.upgrade_strategy import MAX_UPGRADE_DEPTH

        if _depth >= MAX_UPGRADE_DEPTH:
            logger.debug(f"Upgrade depth limit reached ({_depth}), stopping recursive upgrade")
            return False"""

new_depth_check = """        from src.executor.workflow.upgrade_strategy import MAX_UPGRADE_DEPTH, MAX_UPGRADE_TOTAL_TIME

        if _depth >= MAX_UPGRADE_DEPTH:
            logger.debug(f"Upgrade depth limit reached ({_depth}), stopping recursive upgrade")
            return False

        # Per-plan total upgrade time budget check
        if _cumulative_time >= MAX_UPGRADE_TOTAL_TIME:
            logger.info(
                f"Upgrade time budget exhausted ({_cumulative_time:.0f}s >= {MAX_UPGRADE_TOTAL_TIME}s), "
                f"stopping upgrade for plan {original_plan.plan_id}"
            )
            print(f"  [STOP]  升级时间预算耗尽 ({_cumulative_time:.0f}s) → 放弃升级")
            return False"""

if old_depth_check in content:
    content = content.replace(old_depth_check, new_depth_check, 1)
    print("OK: Added time budget check")
else:
    print("NOT FOUND: depth check")

# 3. Track elapsed time and pass to recursive call
old_recursive = """                        # 递归升级：尝试升级这个失败的升级方案
                        recursive_success = await self._try_upgrade_plans(
                            upgraded_plan, upgraded_result, objective_target, judge_target,
                            result, dashboard, output_manager, verbose,
                            per_attack_timeout, timeout_overrides, completed_count,
                            total, plan_brief_fn, update_mode_stats_fn, create_attribution_fn,
                            completion_policy,
                            _depth=_depth + 1,
                            _tried=tried,
                        )"""

new_recursive = """                        # 递归升级：尝试升级这个失败的升级方案
                        recursive_success = await self._try_upgrade_plans(
                            upgraded_plan, upgraded_result, objective_target, judge_target,
                            result, dashboard, output_manager, verbose,
                            per_attack_timeout, timeout_overrides, completed_count,
                            total, plan_brief_fn, update_mode_stats_fn, create_attribution_fn,
                            completion_policy,
                            _depth=_depth + 1,
                            _tried=tried,
                            _cumulative_time=_cumulative_time + up_elapsed,
                        )"""

if old_recursive in content:
    content = content.replace(old_recursive, new_recursive, 1)
    print("OK: Added cumulative_time to recursive call")
else:
    print("NOT FOUND: recursive call")

open(filepath, "w", encoding="utf-8").write(content)
print("File saved")
