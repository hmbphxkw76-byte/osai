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


# OWASP ID → 名称映射
_OWASP_NAMES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Info Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data & Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector & Embedding Weakness",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    "ASI01": "Goal Hijacking",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity Abuse",
    "ASI04": "Supply Chain (Agentic)",
    "ASI05": "Code Execution",
    "ASI06": "Data Exfiltration",
    "ASI07": "Overreliance",
    "ASI08": "Authorization Bypass",
    "ASI09": "Memory Poisoning",
    "ASI10": "Trust Boundary Violation",
}


def _clean_technique_name(raw_name: str) -> tuple[str, str]:
    """
    清理技术名，去掉 hash 后缀，分离 Converter 变体

    PyRIT 原生 unique_name 格式: "ClassName::hash" 或 "ClassName::hash+converter_chain"

    Returns:
        (base_technique, converter_chain) — converter_chain 为空表示基础技术
    """
    if not raw_name:
        return ("", "")
    # 去掉 hash 后缀: "PromptSendingAttack::49fe4c34" → "PromptSendingAttack"
    base = raw_name.split("::")[0] if "::" in raw_name else raw_name
    # 分离 Converter 变体: "PromptSendingAttack+stealth_evasion" → ("PromptSendingAttack", "stealth_evasion")
    if "+" in base:
        parts = base.split("+", 1)
        return (parts[0], parts[1])
    return (base, "")


def _extract_converters_from_identifier(identifier: Any) -> list[str]:
    """
    从 ComponentIdentifier 提取 Converter 类名列表（PyRIT 原生 API）

    当 attack 配置了 attack_converter_config 时，identifier.children 中
    会包含 'request_converters' 键，其值为 ConverterIdentifier 列表。
    每个 ConverterIdentifier.class_name 即为 Converter 的类名。

    Args:
        identifier: AttackResult 的 ComponentIdentifier

    Returns:
        Converter 类名列表（如 ["Base64Converter", "ROT13Converter"]）
    """
    converters: list[str] = []
    children = getattr(identifier, "children", None) or {}

    # 检查 request_converters
    req_converters = children.get("request_converters")
    if req_converters:
        if isinstance(req_converters, list):
            for conv_id in req_converters:
                cn = getattr(conv_id, "class_name", "")
                if cn:
                    converters.append(cn)
        else:
            cn = getattr(req_converters, "class_name", "")
            if cn:
                converters.append(cn)

    # 检查 response_converters
    resp_converters = children.get("response_converters")
    if resp_converters:
        if isinstance(resp_converters, list):
            for conv_id in resp_converters:
                cn = getattr(conv_id, "class_name", "")
                if cn:
                    converters.append(cn)

    return converters


# 数据集名 → OWASP ID 映射（AIRT 数据集无显式 OWASP 标签时的回退映射）
_DATASET_OWASP_MAP: dict[str, str] = {
    "airt_leakage": "LLM02",
    "airt_misinformation": "LLM09",
    "airt_violence": "LLM09",
    "airt_hate": "LLM09",
    "airt_harassment": "LLM09",
    "llm01": "LLM01",
    "llm02": "LLM02",
    "llm03": "LLM03",
    "llm04": "LLM04",
    "llm05": "LLM05",
    "llm06": "LLM06",
    "llm07": "LLM07",
    "llm08": "LLM08",
    "llm09": "LLM09",
    "llm10": "LLM10",
    "asi01": "ASI01",
    "asi02": "ASI02",
    "asi03": "ASI03",
    "asi04": "ASI04",
    "asi05": "ASI05",
    "asi06": "ASI06",
    "asi07": "ASI07",
    "asi08": "ASI08",
    "asi09": "ASI09",
    "asi10": "ASI10",
}


def display_enhanced_group_breakdown(
    native_result: Any,
    *,
    owasp_id: str = "",
    sort_by_success_rate: bool = True,
) -> None:
    """
    统一 Per-Group Breakdown 展示（含攻击技术+Converter组合+OWASP 对齐）

    合并原生 Per-Group Breakdown 和增强列为一次输出，避免重复：
    - Group / Results / Success / Failure / Rate（原生信息）
    - Techniques: 该组使用的攻击技术列表（去掉 hash 后缀）
    - Converters: 该组使用的 Converter 列表（从 identifier.children 提取）
    - OWASP: 该组关联的 OWASP ID + 名称

    使用 PyRIT 原生 API 提取信息：
    - ScenarioResult.get_display_groups() 获取分组
    - AttackResult.get_attack_strategy_identifier() 获取技术名 + converter children
    - AttackResult.labels["owasp_id"] 获取 OWASP ID（回退到数据集名映射）

    Args:
        native_result: 原生 ScenarioResult
        owasp_id: 默认 OWASP ID（当 result 中无 labels 时使用）
        sort_by_success_rate: 是否按成功率降序排列
    """
    if native_result is None:
        return

    if not hasattr(native_result, "get_display_groups"):
        return

    display_groups = native_result.get_display_groups()
    if not display_groups:
        return

    # 收集每组统计信息
    group_stats: list[dict[str, Any]] = []
    for group_name, results in display_groups.items():
        total = len(results)
        success = 0
        techniques: set[str] = set()
        converters: set[str] = set()
        owasp_ids: set[str] = set()

        for r in results:
            if r is None:
                continue
            # 成功统计
            outcome = getattr(r, "outcome", None)
            outcome_str = ""
            if outcome is not None:
                outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                if outcome_str == "SUCCESS":
                    success += 1

            # 技术名 + Converter 检测（原生 API）
            identifier = None
            if hasattr(r, "get_attack_strategy_identifier"):
                identifier = r.get_attack_strategy_identifier()
            if identifier is not None:
                name = getattr(identifier, "unique_name", "") or ""
                base_tech, _ = _clean_technique_name(name)
                if base_tech:
                    techniques.add(base_tech)

                # 从 identifier.children 提取 Converter 类名
                conv_names = _extract_converters_from_identifier(identifier)
                for cn in conv_names:
                    converters.add(cn)

            # OWASP ID（原生 labels API）
            labels = getattr(r, "labels", None) or {}
            r_owasp = labels.get("owasp_id", "")
            if r_owasp:
                owasp_ids.add(r_owasp)

        # OWASP 回退：从数据集名推断
        if not owasp_ids:
            for ds_name_part in group_name.split("::"):
                ds_name = ds_name_part.replace("ai300_adaptive_", "")
                mapped = _DATASET_OWASP_MAP.get(ds_name)
                if mapped:
                    owasp_ids.add(mapped)
                    break

        failure = total - success
        rate = success / total if total > 0 else 0.0
        # OWASP ID + 名称
        owasp_id_str = ", ".join(sorted(owasp_ids)) if owasp_ids else owasp_id
        owasp_names = []
        for oid in owasp_id_str.split(", "):
            oid = oid.strip()
            if oid:
                name = _OWASP_NAMES.get(oid, "")
                owasp_names.append(f"{oid}: {name}" if name else oid)
        owasp_display = " | ".join(owasp_names) if owasp_names else ""

        group_stats.append({
            "group_name": group_name,
            "total": total,
            "success": success,
            "failure": failure,
            "success_rate": rate,
            "techniques": sorted(techniques),
            "converters": sorted(converters),
            "owasp_id": owasp_id_str,
            "owasp_display": owasp_display,
        })

    # 按成功率降序排列
    if sort_by_success_rate:
        group_stats.sort(key=lambda s: s["success_rate"], reverse=True)

    # 输出 Per-Group Breakdown（合并原生+增强）
    print(f"\n  {'=' * 76}")
    print(f"  Per-Group Breakdown (Techniques + Converters + OWASP)")
    print(f"  {'=' * 76}")

    for stat in group_stats:
        rate_pct = stat["success_rate"] * 100
        print(f"\n  Group: {stat['group_name']}")
        print(f"    Results: {stat['total']}, "
              f"Success: {stat['success']}, "
              f"Failure: {stat['failure']}, "
              f"Rate: {rate_pct:.0f}%")

        # 攻击技术（去掉 hash 后缀）
        if stat["techniques"]:
            print(f"    Techniques:  {', '.join(stat['techniques'])}")
        else:
            print(f"    Techniques:  (unknown)")

        # Converter 变体
        if stat["converters"]:
            print(f"    Converters:  {', '.join(stat['converters'])}")
        else:
            print(f"    Converters:  (none - base techniques only)")

        # OWASP 对齐（ID + 名称）
        if stat["owasp_display"]:
            print(f"    OWASP:       {stat['owasp_display']}")

    print(f"\n  {'=' * 76}")


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
