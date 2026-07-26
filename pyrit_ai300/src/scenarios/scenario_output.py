"""
Scenario Output — 对齐 pyrit.output.output_scenario_async
=========================================================

P4: 结果标准化与弹性恢复 — output_scenario_async + Per-Group Breakdown

提供 Scenario 结果的格式化输出和统计功能：
  - output_scenario_async: 格式化输出 Scenario 结果
  - output_scenario_summary: 输出摘要统计
  - sort_results_by_success_rate: 按成功率排序
  - get_per_group_breakdown: 获取 Per-Group 分组统计

桥接 PyRIT 原生 output_scenario_async 和当前项目的 OutputManager。
"""

import logging
from typing import Any

from src.scenarios.scenario_result_bridge import ScenarioResultBridge

logger = logging.getLogger(__name__)


# ============================================================
# 输出函数
# ============================================================

async def output_scenario_async(
    result: Any,
    *,
    sort_groups_by_success_rate: bool = False,
    to_terminal: bool = True,
    to_file: bool = False,
    output_manager: Any = None,
) -> str:
    """
    格式化输出 Scenario 结果

    对齐 PyRIT 1.0.0 output_scenario_async，支持：
    - Per-Group Breakdown 分组统计
    - sort_groups_by_success_rate 按成功率排序
    - 终端 + 文件双通道输出

    Args:
        result: Scenario 结果（ScenarioResult / ScenarioResultBridge / BatchAttackResult）
        sort_groups_by_success_rate: 是否按成功率排序
        to_terminal: 是否输出到终端
        to_file: 是否输出到文件
        output_manager: 可选的 OutputManager 实例

    Returns:
        格式化的文本输出
    """
    bridge = _ensure_bridge(result)
    stats = bridge.get_per_group_stats()

    if sort_groups_by_success_rate:
        stats.sort(key=lambda s: s["success_rate"], reverse=True)

    lines = _format_scenario_output(bridge, stats)

    output_text = "\n".join(lines)

    if to_terminal:
        print(output_text)

    if to_file and output_manager:
        try:
            output_manager.write_scenario_output(output_text)
        except Exception as e:
            logger.warning(f"Failed to write scenario output to file: {e}")

    return output_text


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
        if hasattr(r, "success_rate"):
            return r["success_rate"]
        if isinstance(r, dict) and "success_rate" in r:
            return r["success_rate"]
        return 0.0

    return sorted(results, key=_success_rate, reverse=not ascending)


def get_per_group_breakdown(result: Any) -> list[dict[str, Any]]:
    """
    获取 Per-Group Breakdown 分组统计

    对齐 PyRIT ScenarioResult.get_display_groups() 的统计输出。

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


def _format_scenario_output(
    bridge: ScenarioResultBridge,
    stats: list[dict[str, Any]],
) -> list[str]:
    """格式化 Scenario 结果输出"""
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
        lines.append(
            f"  Group: {stat['group_name']}"
        )
        lines.append(
            f"    Results: {stat['total']}, "
            f"Success: {stat['success']}, "
            f"Failure: {stat['failure']}, "
            f"Rate: {rate_pct:.0f}%"
        )

    lines.extend([
        "",
        "=" * 80,
    ])

    return lines
