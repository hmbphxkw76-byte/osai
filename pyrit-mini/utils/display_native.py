"""display_native.py — PyRIT 

R2 PyRIT  Output :
    1. :  PyRIT  output_attack_async(result, format='pretty') + StdoutSink
    2. : converter(s) AttackResult  output  ()
    3. : per-objective per-attempt 

:
    -  PyRIT  output  (pyrit.output)
    -  False,  fallback 
    - /
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


async def print_native_attack_result(
    result: Any,
    *,
    include_auxiliary: bool = True,
    include_adversarial: bool = True,
    include_pruned: bool = True,
) -> bool:
    """ PyRIT  output_attack_async converter(s) AttackResult .

    R2 PyRIT :  pyrit.output ,
     prompt/response 
    """
    if result is None:
        logger.debug("No result to display (result is None)")
        return False

    try:
        from pyrit.output import OutputFormat, StdoutSink, output_attack_async

        await output_attack_async(
            result,
            format=OutputFormat.PRETTY,
            sink=StdoutSink(),
            include_auxiliary_metadata=include_auxiliary,
            include_adversarial_conversation=include_adversarial,
            include_pruned_conversations=include_pruned,
        )
        return True
    except Exception as e:
        logger.debug("Native attack output failed: %s — falling back to summary", e)
        return False


async def print_native_scenario_result(scenario_result: Any) -> bool:
    """ PyRIT  output_scenario_async  ScenarioResult ."""
    if scenario_result is None:
        logger.debug("No ScenarioResult to display (scenario_result is None)")
        return False

    try:
        from pyrit.output import OutputFormat, StdoutSink, output_scenario_async

        await output_scenario_async(
            scenario_result,
            format=OutputFormat.PRETTY,
            sink=StdoutSink(),
            sort_groups_by_success_rate=True,
        )
        return True
    except Exception as e:
        logger.debug("Native scenario output failed: %s — falling back to summary", e)
        return False


async def print_technique_trail(scenario_result: Any) -> None:
    """ per-objective per-attempt  (PyRIT : 'Inspecting which techniques were tried')."""
    if scenario_result is None:
        return

    try:
        from pyrit.models import AttackOutcome
    except ImportError:
        return

    display_groups = scenario_result.get_display_groups()
    if not display_groups:
        return

    from utils.display_primitives import _C_BOLD, _C_GREEN, _C_RED, _C_RESET

    for group_name, group_results in display_groups.items():
        if not group_results:
            continue

        print(f"\n{_C_BOLD}=== Group: {group_name} ==={_C_RESET}")

        objectives_order: list[str] = []
        objectives_map: dict[str, list[Any]] = {}
        for r in group_results:
            obj = getattr(r, "objective", "") or ""
            if obj not in objectives_map:
                objectives_map[obj] = []
                objectives_order.append(obj)
            objectives_map[obj].append(r)

        for objective in objectives_order:
            attempts = objectives_map[objective]
            final_outcome = getattr(attempts[-1], "outcome", None) if attempts else None
            is_success = final_outcome == AttackOutcome.SUCCESS if final_outcome else False

            outcome_str = (
                f"{_C_GREEN}success{_C_RESET}" if is_success
                else f"{_C_RED}failure{_C_RESET}"
            )
            obj_display = objective[:100] if len(objective) > 100 else objective
            print(f"  [{outcome_str}] '{obj_display}': ", end="")

            trail_parts: list[str] = []
            for attempt in attempts:
                tech_name = _get_technique_class_name(attempt)
                attempt_outcome = getattr(attempt, "outcome", None)
                attempt_ok = attempt_outcome == AttackOutcome.SUCCESS if attempt_outcome else False
                outcome_tag = "success" if attempt_ok else "failure"
                trail_parts.append(f"{tech_name}({outcome_tag})")

            if trail_parts:
                print(" → ".join(trail_parts))
            else:
                print("(no technique identifiers found)")


def _get_technique_class_name(result: Any) -> str:
    """imports AttackResult  ( technique trail )."""
    try:
        identifier = result.get_attack_strategy_identifier()
        if identifier is not None:
            class_name = getattr(identifier, "class_name", "")
            if class_name:
                return class_name
    except Exception:
        pass

    tech = getattr(result, "attack_technique", None) or getattr(result, "technique", None)
    if tech:
        if isinstance(tech, str):
            return tech
        return type(tech).__name__

    return ""
