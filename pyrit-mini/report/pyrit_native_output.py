"""PyRIT output Layer - PyRIT 1.0.1 output

# arXiv:2407.01232 - PyRIT, native output module (output_attack_async, output_scenario_async)
# arXiv:2402.12109 - Russinovich et al., CrescendoAttack (multi-turn progressive escalation)
# arXiv:2312.02191 - Mehrotra et al., TAPAttack (tree-of-attacks with pruning)
# arXiv:2310.08419 - Chao et al., PAIRAttack (iterative adversarial prompting)
# arXiv:2406.18112 - Hanna et al., SkeletonKeyAttack (prefix injection)
# arXiv:2402.05124 - Anthropic, ManyShotJailbreakAttack (many-shot jailbreaking)

 PyRIT  'pyrit.output' LayerEnsure
 PyRIT  OffSec AI-300

PyRIT  output :
    Sink () -> PrinterBase () -> Domain Printer ()

:
    - pretty (ANSI-colored): PyRIT
    - markdown: Jupyter/PyRIT  markdown

:
    - output_native_attack_results:  output_attack_async converter(s) AttackResult
    - output_native_scenario_result:  output_scenario_async  ScenarioResult
    - generate_native_output_files:  (attack_results.md + scenario_result.md)

OffSec AI-300 :
    - R2 PyRIT :  pyrit.output
    - R6 :  output +
    - :  PyRIT
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    pass

async def output_native_attack_results(
    attack_results: dict[str, list[Any]],
    output_dir: Path,
    *,
    include_auxiliary_scores: bool = True,
    include_adversarial_conversation: bool = True,
    include_pruned_conversations: bool = True,
) -> int:
    """ PyRIT output_attack_async converter(s) AttackResult

    :
        - output_dir/native_output/attack_<technique>_<index>.md (markdown )
        - output_dir/native_output/attack_<technique>_<index>.txt (pretty )

    PyRIT :
        -  MarkdownAttackResultMemoryPrinter (markdown )
        -  PrettyAttackResultMemoryPrinter (pretty )
        - : CentralMemory ( conversation_id )
        - : Header -> Summary -> Conversation History -> Metadata -> Footer

    Args:
        attack_results: {technique_name: [AttackResult, ...]}
        output_dir: Output directory
        include_auxiliary_scores:  (OffSec: True)
        include_adversarial_conversation:  (OffSec: True)
        include_pruned_conversations:

    Returns:
         AttackResult
    """
    from pyrit.output import FileSink, output_attack_async

    native_dir = output_dir / "native_output"
    native_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    fallback_count = 0
 # v57: native output fallback warnings,
    _fb_markdown_count = 0
    _fb_pretty_count = 0
    for technique_name, results in attack_results.items():
        safe_name = technique_name.replace("/", "_").replace("\\", "_")
        for i, result in enumerate(results):
         # - Markdown (PyRIT ) -
            md_path = native_dir / f"attack_{safe_name}_{i + 1}.md"
            try:
                await output_attack_async(
                    result,
                    format="markdown",
                    sink=FileSink(path=md_path),
                    include_auxiliary_scores=include_auxiliary_scores,
                    include_adversarial_conversation=include_adversarial_conversation,
                    include_pruned_conversations=include_pruned_conversations,
                )
                count += 1
            except Exception as e:
                logger.debug(
                    "Native markdown output failed for %s[%d]: %s - using fallback",
                    technique_name, i, e,
                )
 # Fallback: AttackResult
                fb_written = _write_fallback_attack_output(result, md_path, fmt="markdown")
                if fb_written:
                    fallback_count += 1
                    _fb_markdown_count += 1

 # - Pretty (ANSI-colored, PyRIT ) -
            txt_path = native_dir / f"attack_{safe_name}_{i + 1}.txt"
            try:
                await output_attack_async(
                    result,
                    format="pretty",
                    sink=FileSink(path=txt_path),
                    include_auxiliary_scores=include_auxiliary_scores,
                    include_adversarial_conversation=include_adversarial_conversation,
                    include_pruned_conversations=include_pruned_conversations,
                )
            except Exception as e:
                logger.debug(
                    "Native pretty output failed for %s[%d]: %s - using fallback",
                    technique_name, i, e,
                )
 # Fallback: pretty
                _write_fallback_attack_output(result, txt_path, fmt="pretty")
                _fb_pretty_count += 1

 # v57: - WARNING
    total_fb = _fb_markdown_count + _fb_pretty_count
    if total_fb > 0:
        logger.info(
            "Native output fallback: %d/%d results used fallback "
            "(MARKDOWN=%d, PRETTY=%d) - non-blocking, evidence saved",
            total_fb, count + fallback_count,
            _fb_markdown_count, _fb_pretty_count,
        )

    total = count + fallback_count
    if total:
        logger.info(
            "PyRIT native output: %d AttackResult saved to %s "
            "(%d native, %d fallback)",
            total, native_dir, count, fallback_count,
        )
    elif count == 0 and fallback_count == 0:
     # L5 v41: In dry-run mode, 0 AttackResult is expected (strike is
     # skipped). Downgrade to INFO to avoid false-alarm WARNING.
        logger.info(
            "PyRIT native output: 0 AttackResult saved "
            "(dry-run or no attack results - expected if --dry-run)"
        )
    return total

async def output_native_scenario_result(
    scenario_result: Any | None,
    output_dir: Path,
    *,
    sort_groups_by_success_rate: bool = True,
) -> bool:
    """ PyRIT output_scenario_async ScenarioResult

    :
        - output_dir/native_output/scenario_result.txt (pretty , ANSI-colored)
        - output_dir/native_output/scenario_result.md (markdown , Jupyter/)

    PyRIT :
        -  PrettyScenarioResultMemoryPrinter (pretty )
        -  MarkdownScenarioResultMemoryPrinter (markdown )
        - : Header -> Scenario Info -> Target Info -> Scorer Info
          -> Overall Statistics -> Per-Group Breakdown -> Footer

    Args:
        scenario_result: PyRIT ScenarioResult  ( None)
        output_dir: Output directory
        sort_groups_by_success_rate:

    Returns:
        True
    """
    if scenario_result is None:
        logger.debug("No ScenarioResult to output (scenario_result is None)")
        return False

    from pyrit.output import FileSink, output_scenario_async

    native_dir = output_dir / "native_output"
    native_dir.mkdir(parents=True, exist_ok=True)

 # - Pretty (ANSI-colored, PyRIT ) -
    txt_path = native_dir / "scenario_result.txt"
    try:
        await output_scenario_async(
            scenario_result,
            format="pretty",
            sink=FileSink(path=txt_path),
            sort_groups_by_success_rate=sort_groups_by_success_rate,
        )
        logger.info("PyRIT native scenario (pretty) output saved to %s", txt_path)
    except Exception as e:
        logger.warning("Native scenario pretty output failed: %s", e)

 # - Markdown (Jupyter/) -
    md_path = native_dir / "scenario_result.md"
    try:
        await output_scenario_async(
            scenario_result,
            format="markdown",
            sink=FileSink(path=md_path),
            sort_groups_by_success_rate=sort_groups_by_success_rate,
        )
        logger.info("PyRIT native scenario (markdown) output saved to %s", md_path)
    except Exception as e:
        logger.warning("Native scenario markdown output failed: %s", e)

    return True

async def generate_native_output_files(
    attack_results: dict[str, list[Any]],
    scenario_result: Any | None,
    output_dir: Path,
) -> Path:
    """all PyRIT

     PyRIT  output :
        1. native_output/attack_*.md - converter(s) AttackResult  markdown
        2. native_output/attack_*.txt - converter(s) AttackResult  pretty
        3. native_output/scenario_result.txt - ScenarioResult  pretty
        4. native_output/scenario_result.md - ScenarioResult  markdown
        5. native_output/README.md -

     (report.md/report.html ) :
        - native_output/ - PyRIT  ()
        - report.md / report.html - OffSec AI-300
        - evidence/ -  JSON
        - poc/ - PoC

    Args:
        attack_results: {technique_name: [AttackResult, ...]}
        scenario_result: ScenarioResult  ( None)
        output_dir: Output directory

    Returns:
        native_output
    """
    native_dir = output_dir / "native_output"
    native_dir.mkdir(parents=True, exist_ok=True)

 # 1. AttackResult
    attack_count = await output_native_attack_results(attack_results, output_dir)

 # 2. ScenarioResult
    scenario_ok = await output_native_scenario_result(scenario_result, output_dir)

 # 3. README
    readme_path = native_dir / "README.md"
    readme_path.write_text(
        _generate_readme(attack_count, scenario_ok),
        encoding="utf-8",
    )

    logger.info(
        "PyRIT native output complete: %d attack results, scenario=%s, dir=%s",
        attack_count, scenario_ok, native_dir,
    )
    return native_dir

def _write_fallback_attack_output(
    result: Any,
    path: Path,
    *,
    fmt: str = "markdown",
) -> bool:
    """ PyRIT output_attack_async fallback

    imports AttackResult
     PyRIT : Header -> Summary -> Conversation -> Footer

    : output_attack_async  CentralMemory.get_memory_instance()
     conversation  endpoint  setup_environment
    CentralMemory  AttackResult  conversation_id
     DB  output

    Args:
        result: PyRIT AttackResult
        path:
        fmt:  ("markdown"  "pretty")

    Returns:
        True
    """
    try:
     # AttackResult ( PyRIT 1.0.1 model )
        outcome = getattr(result, "outcome", None)
        outcome_str = str(outcome).upper() if outcome else "UNKNOWN"
        objective = getattr(result, "objective", "") or ""
        conversation_id = getattr(result, "conversation_id", "N/A")
        attack_id = getattr(result, "attack_result_id", getattr(result, "id", "N/A"))

 # scores - AttackResult last_score ( Score | None)
        score_lines: list[str] = []
        last_score = getattr(result, "last_score", None)
        if last_score:
            sv = getattr(last_score, "score_value", "")
            sr = getattr(last_score, "score_rationale", "")
            sc = getattr(last_score, "score_type", "")
            score_lines.append(f"  - Scorer: {type(last_score).__name__} | Type: {sc} | Value: {sv} | Rationale: {sr}")

 # conversation - last_response (MessagePiece)
        conv_pieces: list[str] = []
        try:
            last_response = getattr(result, "last_response", None)
            if last_response:
                role = getattr(last_response, "role", "assistant")
                val = getattr(
                    last_response,
                    "converted_value",
                    "") or getattr(
                    last_response,
                    "original_value",
                    "") or ""
                if val:
                    conv_pieces.append(f"  [{role}] {val[:500]}")
        except Exception:
            pass

 # Fallback: last_response , objective
        if not conv_pieces:
            if objective:
                conv_pieces.append(f"  [user] {objective[:500]}")

 #
        if fmt == "markdown":
            score_section = score_lines if score_lines else ["  (no scores available)"]
            conv_section = conv_pieces if conv_pieces else ["  (no conversation data available)"]
            lines = [
                f"# Attack Result: {outcome_str}",
                "",
                "## Basic Information",
                f"- Objective: {objective[:200]}",
                f"- Attack ID: {attack_id}",
                f"- Conversation ID: {conversation_id}",
                "",
                "## Outcome",
                f"- Status: **{outcome_str}**",
                "",
                "## Final Score",
                *score_section,
                "",
                "## Conversation History",
                *conv_section,
                "",
                "---",
                f"*Fallback output generated at: {__import__('datetime').datetime.utcnow().isoformat()} UTC*",
                "*This file uses fallback format because PyRIT native output_attack_async failed.*",
            ]
        else:  # pretty
            score_section = score_lines if score_lines else ["  (no scores available)"]
            conv_section = conv_pieces if conv_pieces else ["  (no conversation data available)"]
            lines = [
                f"{'=' * 60}",
                f"  ATTACK RESULT: {outcome_str}",
                f"{'=' * 60}",
                "",
                "--- Basic Information ---",
                f"  Objective: {objective[:200]}",
                f"  Attack ID: {attack_id}",
                f"  Conversation ID: {conversation_id}",
                "",
                "--- Outcome ---",
                f"  Status: {outcome_str}",
                "",
                "--- Final Score ---",
                *score_section,
                "",
                "--- Conversation History ---",
                *conv_section,
                "",
                f"{'=' * 60}",
                "  Fallback output - native output_attack_async failed",
                f"{'=' * 60}",
            ]

        path.write_text("\n".join(lines), encoding="utf-8")
        return True
    except Exception as e:
        logger.debug("Fallback output also failed for %s: %s", path, e)
        return False

def _generate_readme(attack_count: int, scenario_ok: bool) -> str:
    """ native_output README.md

     PyRIT 1.0.1  output :
        - PrettyAttackResultMemoryPrinter ( ANSI )
        - MarkdownAttackResultMemoryPrinter (Jupyter/ Markdown)
        - PrettyScenarioResultMemoryPrinter ()
    """
    lines = [
        "# PyRIT Native Output",
        "",
        "This directory contains output generated by the official PyRIT 'pyrit.output' module.",
        "All files follow the PyRIT 1.0.1 official output format standard.",
        "",
        "## Files",
        "",
        "| File | Format | PyRIT Printer | Description |",
        "|------|--------|---------------|-------------|",
        "| 'attack_*.md' | Markdown | 'MarkdownAttackResultMemoryPrinter' | Per-AttackResult output (Jupyter/MD) |",
        "| 'attack_*.txt' | Pretty (ANSI) | 'PrettyAttackResultMemoryPrinter' | Per-AttackResult output (terminal) |",
        "| 'scenario_result.txt' | Pretty (ANSI) | 'PrettyScenarioResultMemoryPrinter' | ScenarioResult summary (terminal) |",
        "| 'scenario_result.md' | Markdown | 'MarkdownScenarioResultMemoryPrinter' | ScenarioResult summary (Jupyter/MD) |",
        "",
        "## PyRIT Official AttackResult Output Structure",
        "",
        "Each attack result file follows the PyRIT 1.0.1 official format:",
        "",
        "1. **Header** - '[OK] ATTACK RESULT: SUCCESS' / '[FAIL] FAILURE' / '? UNDETERMINED'",
        "2. **Attack Summary** -",
        "   - [CLIPBOARD] Basic Information: Objective, Attack Type, Conversation ID",
        "   - [FAST] Execution Metrics: Turns Executed, Execution Time",
        "   - [TARGET] Outcome: Status, Reason",
        "   - Final Score: Scorer, Category, Type, Value, Rationale",
        "3. **Conversation History with Objective Target** -",
        "   - [DIAMOND] Turn N - USER (blue, wrapped text)",
        "   - [DIAMOND] ASSISTANT (yellow, wrapped text)",
        "   - [WRENCH] SYSTEM (magenta, if present)",
        "   - [FORBIDDEN] BLOCKED BY TARGET (if content filtered)",
        "4. **Adversarial Conversation (Red Team LLM)** -",
        "   Multi-turn attack reasoning (Crescendo/TAP/PAIR/RedTeaming)",
        "5. **Pruned Conversations** -",
        "   Branched conversation summaries ([TRASH] PRUNED #N)",
        "6. **Additional Metadata** - Attack-specific metadata",
        "7. **Footer** - 'Report generated at: YYYY-MM-DD HH:MM:SS UTC'",
        "",
        "## Single-Turn vs Multi-Turn Attack Output",
        "",
        "| Attack Type | Executor | Turns | Adversarial | Pruned |",
        "|------------|----------|-------|-------------|--------|",
        "| PromptSendingAttack | Single-turn | 1 | No | No |",
        "| MultiPromptSendingAttack | Single-turn | 1 | No | No |",
        "| ChunkedRequestAttack | Single-turn | 1 | No | No |",
        "| SkeletonKeyAttack | Single-turn | 1 | No | No |",
        "| ManyShotJailbreakAttack | Single-turn | 1 | No | No |",
        "| CrescendoAttack | Multi-turn | N | Yes | Yes |",
        "| TAPAttack | Multi-turn | N | Yes | Yes |",
        "| PAIRAttack | Multi-turn | N | Yes | Yes |",
        "| RedTeamingAttack | Multi-turn | N | Yes | Yes |",
        "",
        "## ScenarioResult Output Structure",
        "",
        "The 'scenario_result.txt' and 'scenario_result.md' files follow the PyRIT official format:",
        "",
        "1. **Header** - '[CHART] SCENARIO RESULTS: <scenario_name>'",
        "2. **Scenario Information** - Name, Version, PyRIT Version, Description",
        "3. **Target Information** - Target Type, Model, Endpoint",
        "4. **Scorer Information** - Scorer type, category, parameters",
        "5. **Overall Statistics** - Total Techniques, Attack Results, Success Rate, Objectives",
        "6. **Per-Group Breakdown** - Group name, result count, success rate",
        "7. **Footer** - Separator",
        "",
        "## Statistics",
        "",
        f"- Attack results output: **{attack_count}**",
        f"- Scenario result output: **{'Yes' if scenario_ok else 'No'}**",
        "",
        "## Reference",
        "",
        "- PyRIT Output Module: https://microsoft.github.io/PyRIT/1.0.1/code/output/output/",
        "- PyRIT Source: https://github.com/microsoft/PyRIT/blob/main/pyrit/output/",
        "- PyRIT Single-Turn Executors: https://microsoft.github.io/PyRIT/1.0.1/code/executor/single-turn/",
        "- PyRIT Multi-Turn Executors: https://microsoft.github.io/PyRIT/1.0.1/code/executor/multi-turn/",
        "",
    ]
    return "\n".join(lines)
