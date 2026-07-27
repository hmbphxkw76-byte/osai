"""
Scenario Output — 原生 output_scenario_async + StdoutSink/FileSink 双通道
========================================================================

P1: 用原生 output_scenario_async + StdoutSink/FileSink 替代自建双通道输出

直接使用 PyRIT 原生 output_scenario_async，支持：
  - StdoutSink: 终端 pretty 格式输出（PrettyScenarioResultMemoryPrinter）
  - FileSink: 文件输出（Markdown 格式）
  - sort_groups_by_success_rate: 按成功率排序 Per-Group Breakdown

移除自建 _format_scenario_output，完全依赖原生 PrettyScenarioResultMemoryPrinter。
"""

import logging
from pathlib import Path
from typing import Any

from pyrit.output import (
    FileSink,
    StdoutSink,
    output_scenario_async as _native_output_scenario_async,
)

from src.scenarios.scenario_result_bridge import ScenarioResultBridge

logger = logging.getLogger(__name__)


async def output_scenario_async(
    result: Any,
    *,
    sort_groups_by_success_rate: bool = False,
    to_terminal: bool = True,
    to_file: bool = False,
    file_path: str | Path | None = None,
    output_manager: Any = None,
) -> str:
    """
    原生双通道输出 Scenario 结果

    使用 PyRIT 原生 output_scenario_async + StdoutSink/FileSink。
    移除自建格式化逻辑，完全依赖原生 PrettyScenarioResultMemoryPrinter。

    Args:
        result: Scenario 结果（ScenarioResult / ScenarioResultBridge / BatchAttackResult）
        sort_groups_by_success_rate: 是否按成功率排序 Per-Group Breakdown
        to_terminal: 是否输出到终端
        to_file: 是否输出到文件
        file_path: 文件路径（to_file=True 时必填）
        output_manager: 可选的 OutputManager（向后兼容，未使用原生 FileSink 时）

    Returns:
        输出路径字符串（用于日志记录）
    """
    # 尝试获取原生 ScenarioResult
    native_result = _try_get_native_scenario_result(result)

    if native_result is not None:
        # 原生 ScenarioResult — 直接使用原生 output_scenario_async
        if to_terminal:
            await _native_output_scenario_async(
                native_result,
                sink=StdoutSink(),
                sort_groups_by_success_rate=sort_groups_by_success_rate,
            )

        if to_file:
            path = Path(file_path) if file_path else Path("output/reports/scenario_result.md")
            path.parent.mkdir(parents=True, exist_ok=True)
            await _native_output_scenario_async(
                native_result,
                sink=FileSink(path=path),
                sort_groups_by_success_rate=sort_groups_by_success_rate,
            )
            return str(path)

        return "terminal"

    # 回退：使用 ScenarioResultBridge 的自建格式化（向后兼容）
    logger.info("Using ScenarioResultBridge fallback (native ScenarioResult not available)")
    bridge = _ensure_bridge(result)
    stats = bridge.get_per_group_stats()

    if sort_groups_by_success_rate:
        stats.sort(key=lambda s: s["success_rate"], reverse=True)

    lines = _format_bridge_output(bridge, stats)
    output_text = "\n".join(lines)

    if to_terminal:
        print(output_text)

    if to_file:
        path = Path(file_path) if file_path else Path("output/reports/scenario_result.md")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output_text, encoding="utf-8")
        return str(path)

    return "terminal"


def output_scenario_summary(result: Any) -> dict[str, Any]:
    """
    输出 Scenario 摘要统计

    Args:
        result: Scenario 结果

    Returns:
        摘要字典
    """
    bridge = _ensure_bridge(result)
    return bridge.get_summary()


def sort_results_by_success_rate(
    results: list[Any],
    *,
    ascending: bool = False,
) -> list[Any]:
    """
    按成功率排序结果列表

    Args:
        results: 结果列表
        ascending: 是否升序排列

    Returns:
        排序后的结果列表
    """
    def _success_rate(r: Any) -> float:
        if isinstance(r, dict) and "success_rate" in r:
            return r["success_rate"]
        return 0.0

    return sorted(results, key=_success_rate, reverse=not ascending)


def get_per_group_breakdown(result: Any) -> list[dict[str, Any]]:
    """
    获取 Per-Group Breakdown 分组统计

    Args:
        result: Scenario 结果

    Returns:
        每组统计列表
    """
    bridge = _ensure_bridge(result)
    return bridge.get_per_group_stats()


# ============================================================
# 内部辅助函数
# ============================================================

def _try_get_native_scenario_result(result: Any) -> Any:
    """尝试获取原生 ScenarioResult，如果不可用返回 None"""
    # 如果已经是原生 ScenarioResult
    try:
        from pyrit.scenario import ScenarioResult
        if isinstance(result, ScenarioResult):
            return result
    except Exception:
        pass

    # 如果有 .result 属性指向原生 ScenarioResult
    native = getattr(result, "_native_result", None) or getattr(result, "scenario_result", None)
    if native is not None:
        return native

    return None


def _ensure_bridge(result: Any) -> ScenarioResultBridge:
    """确保结果是 ScenarioResultBridge 类型"""
    if isinstance(result, ScenarioResultBridge):
        return result
    from src.payloads.models import BatchAttackResult
    if isinstance(result, BatchAttackResult):
        return ScenarioResultBridge(result)
    # 尝试包装
    if hasattr(result, "results") or hasattr(result, "attack_results"):
        class _Adapter:
            def __init__(self, r):
                self._r = r
            @property
            def results(self):
                return getattr(self._r, "attack_results", getattr(self._r, "results", []))
            @property
            def total_plans(self):
                return len(self.results)
            @property
            def executed(self):
                return len(self.results)
            @property
            def succeeded(self):
                return sum(
                    1 for r in self.results
                    if r is not None and hasattr(r, "outcome") and
                    str(getattr(r.outcome, "value", r.outcome)).upper() == "SUCCESS"
                )
            @property
            def failed(self):
                return self.executed - self.succeeded
            @property
            def errored(self):
                return 0
            @property
            def success_rate(self):
                return self.succeeded / self.executed if self.executed > 0 else 0.0
            @property
            def upgrade_attempts(self):
                return 0
            @property
            def upgrade_success(self):
                return 0
            @property
            def errors(self):
                return []
        return ScenarioResultBridge(_Adapter(result))
    raise TypeError(f"Unsupported result type: {type(result).__name__}")


def _format_bridge_output(
    bridge: ScenarioResultBridge,
    stats: list[dict[str, Any]],
) -> list[str]:
    """格式化 ScenarioResultBridge 输出（增强版：含技术+Converter+OWASP）"""
    summary = bridge.get_summary()
    lines = [
        "=" * 80,
        "  SCENARIO RESULTS: " + summary["scenario_name"],
        "=" * 80,
        "",
        "Scenario Information",
        "-" * 80,
        f"  Scenario Name: {summary['scenario_name']}",
        f"  Scenario Version: {summary['scenario_version']}",
        "",
        "Overall Statistics",
        "-" * 80,
        f"  Total Attacks: {summary['total_attacks']}",
        f"  Successful: {summary['successful_attacks']}",
        f"  Failed: {summary['failed_attacks']}",
        f"  Errored: {summary['errored_attacks']}",
        f"  Success Rate: {summary['success_rate'] * 100:.1f}%",
    ]

    if summary.get("upgrade_attempts", 0) > 0:
        lines.append(
            f"  Upgrade Attempts: {summary['upgrade_attempts']} "
            f"(success: {summary['upgrade_success']})"
        )

    if summary.get("errors_count", 0) > 0:
        lines.append(f"  Errors: {summary['errors_count']}")

    lines.extend([
        "",
        "Per-Group Breakdown",
        "-" * 80,
    ])

    for stat in stats:
        rate_pct = stat["success_rate"] * 100
        lines.append(f"  Group: {stat['group_name']}")
        lines.append(
            f"    Results: {stat['total']}, "
            f"Success: {stat['success']}, "
            f"Failure: {stat['failure']}, "
            f"Rate: {rate_pct:.0f}%"
        )
        # 增强列：攻击技术
        techniques = stat.get("techniques", [])
        if techniques:
            lines.append(f"    Techniques: {', '.join(techniques)}")
        # 增强列：Converter 变体
        converters = stat.get("converter_variants", [])
        if converters:
            lines.append(f"    Converters: {', '.join(converters)}")
        else:
            lines.append(f"    Converters: (none)")
        # 增强列：OWASP 对齐
        owasp = stat.get("owasp_id", "")
        if owasp:
            lines.append(f"    OWASP: {owasp}")

    lines.extend(["", "=" * 80])
    return lines
