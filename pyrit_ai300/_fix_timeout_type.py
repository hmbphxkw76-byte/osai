#!/usr/bin/env python3
"""Fix timeout path to pass proper failure type"""

filepath = "src/executor/workflow/scenario_orchestrator.py"
content = open(filepath, "r", encoding="utf-8").read()

# Replace the None with a simple mock that has timeout info
old = """                    # Timeout → try single downgrade to simpler technique (depth=0, no recursion)
                    # Only for multi-turn attacks that timed out; skip if already single_turn
                    if plan.prompt_item.attack_mode.value != "single_turn" and not owasp_skip.get(plan.owasp_id or "UNKNOWN", False):
                        await self._try_upgrade_plans(
                            plan, None, objective_target, judge_target,
                            result, dashboard, output_manager, verbose,
                            per_attack_timeout, timeout_overrides, completed_count,
                            total, _plan_brief, _update_mode_stats, _create_attribution,
                            completion_policy,
                        )"""

new = """                    # Timeout → try single downgrade to simpler technique (depth=0, no recursion)
                    # Only for multi-turn attacks that timed out; skip if already single_turn
                    if plan.prompt_item.attack_mode.value != "single_turn" and not owasp_skip.get(plan.owasp_id or "UNKNOWN", False):
                        # Create a lightweight timeout indicator for failure type routing
                        _timeout_indicator = type("TimeoutResult", (), {
                            "error_message": f"Timeout after {effective_timeout}s",
                            "outcome_reason": "Timeout",
                            "outcome": None,
                        })()
                        await self._try_upgrade_plans(
                            plan, _timeout_indicator, objective_target, judge_target,
                            result, dashboard, output_manager, verbose,
                            per_attack_timeout, timeout_overrides, completed_count,
                            total, _plan_brief, _update_mode_stats, _create_attribution,
                            completion_policy,
                        )"""

if old in content:
    content = content.replace(old, new, 1)
    print("OK: Fixed timeout path to pass proper failure type")
else:
    print("NOT FOUND: timeout path")

open(filepath, "w", encoding="utf-8").write(content)
print("File saved")
