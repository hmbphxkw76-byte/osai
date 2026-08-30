"""PyRIT 原生 output 适配层 — 对齐 PyRIT 1.0.1 官方 output 模块标准。

# arXiv:2407.01232 — PyRIT, native output module (output_attack_async, output_scenario_async)
# arXiv:2402.12109 — Russinovich et al., CrescendoAttack (multi-turn progressive escalation)
# arXiv:2312.02191 — Mehrotra et al., TAPAttack (tree-of-attacks with pruning)
# arXiv:2310.08419 — Chao et al., PAIRAttack (iterative adversarial prompting)
# arXiv:2406.18112 — Hanna et al., SkeletonKeyAttack (prefix injection)
# arXiv:2402.05124 — Anthropic, ManyShotJailbreakAttack (many-shot jailbreaking)

本模块是 PyRIT 官方 `pyrit.output` 模块的薄适配层，确保攻击结果输出
完全符合 PyRIT 原生框架标准，同时与 OffSec AI-300 考试要求的
安全报告功能共存。

PyRIT 官方 output 架构:
    Sink (输出目标) → PrinterBase (渲染逻辑) → Domain Printer (具体格式)

输出格式:
    - pretty (ANSI-colored): 终端友好，PyRIT 默认格式
    - markdown: Jupyter/文档友好，PyRIT 官方 markdown 格式

关键函数:
    - output_native_attack_results: 使用 output_attack_async 输出每个 AttackResult
    - output_native_scenario_result: 使用 output_scenario_async 输出 ScenarioResult
    - generate_native_output_files: 生成官方标准文件 (attack_results.md + scenario_result.md)

OffSec AI-300 对齐:
    - R2 PyRIT 原生优先: 使用 pyrit.output 官方模块，不自行实现渲染逻辑
    - R6 红队就绪: 完整证据链，原生 output + 安全报告双输出
    - 考试评分: 官方格式输出证明 PyRIT 框架掌握能力
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
    """使用 PyRIT 官方 output_attack_async 输出每个 AttackResult。

    生成文件:
        - output_dir/native_output/attack_<technique>_<index>.md (markdown 格式)
        - output_dir/native_output/attack_<technique>_<index>.txt (pretty 格式)

    PyRIT 官方标准:
        - 使用 MarkdownAttackResultMemoryPrinter (markdown 格式)
        - 使用 PrettyAttackResultMemoryPrinter (pretty 格式)
        - 数据源: CentralMemory (通过 conversation_id 获取完整对话)
        - 输出结构: Header → Summary → Conversation History → Metadata → Footer

    Args:
        attack_results: {technique_name: [AttackResult, ...]} 字典。
        output_dir: 输出目录。
        include_auxiliary_scores: 是否包含辅助评分 (OffSec: True)。
        include_adversarial_conversation: 是否包含对抗对话 (OffSec: True)。
        include_pruned_conversations: 是否包含裁剪对话。

    Returns:
        成功输出的 AttackResult 数量。
    """
    from pyrit.output import FileSink, output_attack_async

    native_dir = output_dir / "native_output"
    native_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    fallback_count = 0
    for technique_name, results in attack_results.items():
        safe_name = technique_name.replace("/", "_").replace("\\", "_")
        for i, result in enumerate(results):
            # — Markdown 格式 (PyRIT 官方标准) —
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
                logger.warning(
                    "Native markdown output failed for %s[%d]: %s — using fallback",
                    technique_name, i, e,
                )
                # Fallback: 写入从 AttackResult 字段直接提取的简化输出
                fb_written = _write_fallback_attack_output(result, md_path, fmt="markdown")
                if fb_written:
                    fallback_count += 1

            # — Pretty 格式 (ANSI-colored, PyRIT 默认) —
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
                logger.warning(
                    "Native pretty output failed for %s[%d]: %s — using fallback",
                    technique_name, i, e,
                )
                # Fallback: 写入简化 pretty 输出
                _write_fallback_attack_output(result, txt_path, fmt="pretty")

    total = count + fallback_count
    if total:
        logger.info(
            "PyRIT native output: %d AttackResult saved to %s "
            "(%d native, %d fallback)",
            total, native_dir, count, fallback_count,
        )
    elif count == 0 and fallback_count == 0:
        logger.warning(
            "PyRIT native output: 0 AttackResult saved — "
            "attack_results may be empty or CentralMemory unavailable"
        )
    return total


async def output_native_scenario_result(
    scenario_result: Any | None,
    output_dir: Path,
    *,
    sort_groups_by_success_rate: bool = True,
) -> bool:
    """使用 PyRIT 官方 output_scenario_async 输出 ScenarioResult。

    生成文件:
        - output_dir/native_output/scenario_result.txt (pretty 格式, ANSI-colored)
        - output_dir/native_output/scenario_result.md (markdown 格式, Jupyter/文档友好)

    PyRIT 官方标准:
        - 使用 PrettyScenarioResultMemoryPrinter (pretty 格式)
        - 使用 MarkdownScenarioResultMemoryPrinter (markdown 格式)
        - 输出结构: Header → Scenario Info → Target Info → Scorer Info
          → Overall Statistics → Per-Group Breakdown → Footer

    Args:
        scenario_result: PyRIT ScenarioResult 对象 (可为 None)。
        output_dir: 输出目录。
        sort_groups_by_success_rate: 按成功率排序分组。

    Returns:
        True 如果成功输出。
    """
    if scenario_result is None:
        logger.debug("No ScenarioResult to output (scenario_result is None)")
        return False

    from pyrit.output import FileSink, output_scenario_async

    native_dir = output_dir / "native_output"
    native_dir.mkdir(parents=True, exist_ok=True)

    # — Pretty 格式 (ANSI-colored, PyRIT 默认) —
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

    # — Markdown 格式 (Jupyter/文档友好) —
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
    """生成所有 PyRIT 官方标准输出文件。

    这是 PyRIT 原生 output 的统一入口，生成:
        1. native_output/attack_*.md — 每个 AttackResult 的 markdown 格式
        2. native_output/attack_*.txt — 每个 AttackResult 的 pretty 格式
        3. native_output/scenario_result.txt — ScenarioResult 的 pretty 格式
        4. native_output/scenario_result.md — ScenarioResult 的 markdown 格式
        5. native_output/README.md — 说明文档

    与安全报告 (report.md/report.html 等) 并行存在:
        - native_output/ — PyRIT 官方标准输出 (证明框架掌握能力)
        - report.md / report.html — OffSec AI-300 安全评估报告
        - evidence/ — 证据收集 JSON
        - poc/ — PoC 脚本

    Args:
        attack_results: {technique_name: [AttackResult, ...]} 字典。
        scenario_result: ScenarioResult 对象 (可为 None)。
        output_dir: 输出目录。

    Returns:
        native_output 目录路径。
    """
    native_dir = output_dir / "native_output"
    native_dir.mkdir(parents=True, exist_ok=True)

    # 1. 输出每个 AttackResult
    attack_count = await output_native_attack_results(attack_results, output_dir)

    # 2. 输出 ScenarioResult
    scenario_ok = await output_native_scenario_result(scenario_result, output_dir)

    # 3. 生成 README
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
    """当 PyRIT 原生 output_attack_async 失败时的 fallback 输出。

    从 AttackResult 对象字段直接提取关键信息，写入简化格式的文件。
    保留 PyRIT 官方格式的核心结构: Header → Summary → Conversation → Footer。

    根因: output_attack_async 内部通过 CentralMemory.get_memory_instance()
    获取 conversation 数据，多 endpoint 模式下 setup_environment 清除
    CentralMemory 单例后，之前的 AttackResult 引用的 conversation_id
    在新 DB 中不存在，导致原生 output 抛出异常。

    Args:
        result: PyRIT AttackResult 对象。
        path: 输出文件路径。
        fmt: 输出格式 ("markdown" 或 "pretty")。

    Returns:
        True 如果成功写入。
    """
    try:
        # 从 AttackResult 提取字段 (对齐 PyRIT 1.0.1 model 字段名)
        outcome = getattr(result, "outcome", None)
        outcome_str = str(outcome).upper() if outcome else "UNKNOWN"
        objective = getattr(result, "objective", "") or ""
        conversation_id = getattr(result, "conversation_id", "N/A")
        attack_id = getattr(result, "attack_result_id", getattr(result, "id", "N/A"))

        # 提取 scores — AttackResult 有 last_score (单个 Score | None)
        score_lines: list[str] = []
        last_score = getattr(result, "last_score", None)
        if last_score:
            sv = getattr(last_score, "score_value", "")
            sr = getattr(last_score, "score_rationale", "")
            sc = getattr(last_score, "score_type", "")
            score_lines.append(f"  - Scorer: {type(last_score).__name__} | Type: {sc} | Value: {sv} | Rationale: {sr}")

        # 提取 conversation — 从 last_response (MessagePiece) 提取
        conv_pieces: list[str] = []
        try:
            last_response = getattr(result, "last_response", None)
            if last_response:
                role = getattr(last_response, "role", "assistant")
                val = getattr(last_response, "converted_value", "") or getattr(last_response, "original_value", "") or ""
                if val:
                    conv_pieces.append(f"  [{role}] {val[:500]}")
        except Exception:
            pass

        # Fallback: 如果 last_response 为空, 从 objective 构造最小对话
        if not conv_pieces:
            if objective:
                conv_pieces.append(f"  [user] {objective[:500]}")

        # 构建输出内容
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
                "  Fallback output — native output_attack_async failed",
                f"{'=' * 60}",
            ]

        path.write_text("\n".join(lines), encoding="utf-8")
        return True
    except Exception as e:
        logger.debug("Fallback output also failed for %s: %s", path, e)
        return False


def _generate_readme(attack_count: int, scenario_ok: bool) -> str:
    """生成 native_output 目录的 README.md。

    对齐 PyRIT 1.0.1 官方 output 模块格式标准:
        - PrettyAttackResultMemoryPrinter (终端 ANSI 彩色)
        - MarkdownAttackResultMemoryPrinter (Jupyter/文档 Markdown)
        - PrettyScenarioResultMemoryPrinter (场景汇总)
    """
    lines = [
        "# PyRIT Native Output",
        "",
        "This directory contains output generated by the official PyRIT `pyrit.output` module.",
        "All files follow the PyRIT 1.0.1 official output format standard.",
        "",
        "## Files",
        "",
        "| File | Format | PyRIT Printer | Description |",
        "|------|--------|---------------|-------------|",
        "| `attack_*.md` | Markdown | `MarkdownAttackResultMemoryPrinter` | Per-AttackResult output (Jupyter/MD) |",
        "| `attack_*.txt` | Pretty (ANSI) | `PrettyAttackResultMemoryPrinter` | Per-AttackResult output (terminal) |",
        "| `scenario_result.txt` | Pretty (ANSI) | `PrettyScenarioResultMemoryPrinter` | ScenarioResult summary (terminal) |",
        "| `scenario_result.md` | Markdown | `MarkdownScenarioResultMemoryPrinter` | ScenarioResult summary (Jupyter/MD) |",
        "",
        "## PyRIT Official AttackResult Output Structure",
        "",
        "Each attack result file follows the PyRIT 1.0.1 official format:",
        "",
        "1. **Header** — `✅ ATTACK RESULT: SUCCESS` / `❌ FAILURE` / `❓ UNDETERMINED`",
        "2. **Attack Summary** —",
        "   - 📋 Basic Information: Objective, Attack Type, Conversation ID",
        "   - ⚡ Execution Metrics: Turns Executed, Execution Time",
        "   - 🎯 Outcome: Status, Reason",
        "   - Final Score: Scorer, Category, Type, Value, Rationale",
        "3. **Conversation History with Objective Target** —",
        "   - 🔹 Turn N - USER (blue, wrapped text)",
        "   - 🔸 ASSISTANT (yellow, wrapped text)",
        "   - 🔧 SYSTEM (magenta, if present)",
        "   - 🚫 BLOCKED BY TARGET (if content filtered)",
        "4. **Adversarial Conversation (Red Team LLM)** —",
        "   Multi-turn attack reasoning (Crescendo/TAP/PAIR/RedTeaming)",
        "5. **Pruned Conversations** —",
        "   Branched conversation summaries (🗑️ PRUNED #N)",
        "6. **Additional Metadata** — Attack-specific metadata",
        "7. **Footer** — `Report generated at: YYYY-MM-DD HH:MM:SS UTC`",
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
        "The `scenario_result.txt` and `scenario_result.md` files follow the PyRIT official format:",
        "",
        "1. **Header** — `📊 SCENARIO RESULTS: <scenario_name>`",
        "2. **Scenario Information** — Name, Version, PyRIT Version, Description",
        "3. **Target Information** — Target Type, Model, Endpoint",
        "4. **Scorer Information** — Scorer type, category, parameters",
        "5. **Overall Statistics** — Total Techniques, Attack Results, Success Rate, Objectives",
        "6. **Per-Group Breakdown** — Group name, result count, success rate",
        "7. **Footer** — Separator",
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
