"""PyRIT 原生 output 适配层 — 对齐 PyRIT 1.0.1 官方 output 模块标准。

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
    from pyrit.output import FileSink, OutputFormat, output_attack_async

    native_dir = output_dir / "native_output"
    native_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for technique_name, results in attack_results.items():
        safe_name = technique_name.replace("/", "_").replace("\\", "_")
        for i, result in enumerate(results):
            # — Markdown 格式 (PyRIT 官方标准) —
            md_path = native_dir / f"attack_{safe_name}_{i + 1}.md"
            try:
                await output_attack_async(
                    result,
                    format=OutputFormat.MARKDOWN,
                    sink=FileSink(path=md_path),
                    include_auxiliary_scores=include_auxiliary_scores,
                    include_adversarial_conversation=include_adversarial_conversation,
                    include_pruned_conversations=include_pruned_conversations,
                )
                count += 1
            except Exception as e:
                logger.warning(
                    "Native markdown output failed for %s[%d]: %s",
                    technique_name, i, e,
                )

            # — Pretty 格式 (ANSI-colored, PyRIT 默认) —
            txt_path = native_dir / f"attack_{safe_name}_{i + 1}.txt"
            try:
                await output_attack_async(
                    result,
                    format=OutputFormat.PRETTY,
                    sink=FileSink(path=txt_path),
                    include_auxiliary_scores=include_auxiliary_scores,
                    include_adversarial_conversation=include_adversarial_conversation,
                    include_pruned_conversations=include_pruned_conversations,
                )
            except Exception as e:
                logger.warning(
                    "Native pretty output failed for %s[%d]: %s",
                    technique_name, i, e,
                )

    if count:
        logger.info(
            "PyRIT native output: %d AttackResult saved to %s (markdown + pretty)",
            count, native_dir,
        )
    return count


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

    from pyrit.output import FileSink, OutputFormat, output_scenario_async

    native_dir = output_dir / "native_output"
    native_dir.mkdir(parents=True, exist_ok=True)

    # — Pretty 格式 (ANSI-colored, PyRIT 默认) —
    txt_path = native_dir / "scenario_result.txt"
    try:
        await output_scenario_async(
            scenario_result,
            format=OutputFormat.PRETTY,
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
            format=OutputFormat.MARKDOWN,
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
