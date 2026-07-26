#!/usr/bin/env python3
"""Add downgrade attempt on timeout path in _run_one"""

filepath = "src/executor/workflow/scenario_orchestrator.py"
content = open(filepath, "r", encoding="utf-8").read()

# Find the timeout exception handler and add a downgrade attempt
old_timeout = """                except asyncio.TimeoutError:
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
                        dashboard.print_progress()"""

new_timeout = """                except asyncio.TimeoutError:
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
                    # Timeout → try single downgrade to simpler technique (depth=0, no recursion)
                    # Only for multi-turn attacks that timed out; skip if already single_turn
                    if plan.prompt_item.attack_mode.value != "single_turn" and not owasp_skip.get(plan.owasp_id or "UNKNOWN", False):
                        await self._try_upgrade_plans(
                            plan, None, objective_target, judge_target,
                            result, dashboard, output_manager, verbose,
                            per_attack_timeout, timeout_overrides, completed_count,
                            total, _plan_brief, _update_mode_stats, _create_attribution,
                            completion_policy,
                        )"""

if old_timeout in content:
    content = content.replace(old_timeout, new_timeout, 1)
    print("OK: Added downgrade attempt on timeout")
else:
    print("NOT FOUND: timeout handler")

open(filepath, "w", encoding="utf-8").write(content)
print("File saved")
