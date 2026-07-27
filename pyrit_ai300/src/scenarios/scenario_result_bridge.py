"""
Scenario Result Bridge — BatchAttackResult ↔ ScenarioResult 桥接 + OWASP 集成
==============================================================================

P4: 结果标准化与弹性恢复 + OWASP 映射优化

桥接当前项目的 BatchAttackResult 和 PyRIT 原生 ScenarioResult：
  - batch_result_to_scenario_result: 将 BatchAttackResult 转换为 ScenarioResultBridge
  - ScenarioResultBridge: 双向桥接器，提供统一接口

OWASP 映射优化：
  - 通过原生 memory_labels 标记 OWASP ID
  - 从 memory 中提取 OWASP 映射
  - 保留自建 owasp_mapping.yaml 配置

弹性恢复优化：
  - 原生 scenario_result_id 支持自动恢复
  - 原生 max_retries 自动重试
  - Bridge 保存 scenario_result_id 用于 resume
"""

import logging
import uuid
from typing import Any

from src.payloads.models import BatchAttackResult

logger = logging.getLogger(__name__)


class ScenarioResultBridge:
    """
    BatchAttackResult ↔ ScenarioResult 双向桥接器

    提供统一接口，使当前项目的 BatchAttackResult 可以被
    PyRIT 原生 output_scenario_async 等函数使用。

    优化：
    - 保存 _native_result 引用，使 output_scenario_async 可直接使用原生 ScenarioResult
    - 保存 _scenario_result_id，支持原生 resume
    - OWASP 映射通过 memory_labels 集成
    """

    def __init__(
        self,
        batch_result: BatchAttackResult,
        *,
        native_result: Any = None,
        scenario_result_id: str | None = None,
        memory_labels: dict[str, str] | None = None,
    ) -> None:
        """
        初始化桥接器

        Args:
            batch_result: 当前项目的 BatchAttackResult
            native_result: 可选的原生 ScenarioResult（如果通过原生 Scenario 运行）
            scenario_result_id: 可选的 ScenarioResult ID（用于 resume）
            memory_labels: 可选的 memory_labels（含 OWASP ID 等）
        """
        self._batch_result = batch_result
        self._native_result = native_result
        self._id = scenario_result_id or str(uuid.uuid4())
        self._memory_labels = memory_labels or {}

    @property
    def id(self) -> str:
        """ScenarioResult ID（用于 resume）"""
        return self._id

    @property
    def scenario_name(self) -> str:
        """Scenario 名称"""
        return "AI300Scenario"

    @property
    def scenario_version(self) -> int:
        """Scenario 版本"""
        return 1

    @property
    def attack_results(self) -> list:
        """扁平化攻击结果列表"""
        return [r for r in self._batch_result.results if r is not None]

    @property
    def total_attacks(self) -> int:
        """总攻击数"""
        return self._batch_result.executed

    @property
    def successful_attacks(self) -> int:
        """成功攻击数"""
        return self._batch_result.succeeded

    @property
    def failed_attacks(self) -> int:
        """失败攻击数"""
        return self._batch_result.failed

    @property
    def native_result(self) -> Any:
        """原生 ScenarioResult（如果可用）"""
        return self._native_result

    @property
    def memory_labels(self) -> dict[str, str]:
        """memory_labels（含 OWASP ID 等）"""
        return self._memory_labels

    def objective_achieved_rate(self) -> float:
        """目标达成率（成功率）"""
        if self._batch_result.executed == 0:
            return 0.0
        return self._batch_result.success_rate

    def get_display_groups(self) -> dict[str, list]:
        """
        按 display_group 分组结果

        如果有原生 ScenarioResult，委托给原生 get_display_groups()。
        否则按 attack_technique 分组。
        """
        if self._native_result is not None:
            return self._native_result.get_display_groups()

        groups: dict[str, list] = {}
        for result in self.attack_results:
            technique = "unknown"
            if hasattr(result, "get_attack_strategy_identifier"):
                identifier = result.get_attack_strategy_identifier()
                if identifier:
                    technique = identifier.class_name
            elif hasattr(result, "attack_strategy_type"):
                technique = str(result.attack_strategy_type)

            groups.setdefault(technique, []).append(result)
        return groups

    def get_per_group_stats(self) -> list[dict[str, Any]]:
        """
        获取每组的统计信息（增强版：含攻击技术+Converter组合+OWASP 对齐）

        如果有原生 ScenarioResult，使用原生 Per-Group Breakdown 并增强：
        - techniques: 该组使用的攻击技术列表
        - converter_variants: 该组使用的 Converter 变体列表
        - owasp_id: 该组关联的 OWASP ID（从 labels 提取）
        """
        if self._native_result is not None:
            display_groups = self._native_result.get_display_groups()
            stats = []
            for group_name, results in display_groups.items():
                total = len(results)
                success = sum(
                    1 for r in results
                    if hasattr(r, "outcome") and
                    str(getattr(r.outcome, "value", r.outcome)).upper() == "SUCCESS"
                )
                # 提取攻击技术 + Converter 变体信息
                techniques_used: list[str] = []
                converters_used: list[str] = []
                owasp_ids: set[str] = set()
                for r in results:
                    if r is None:
                        continue
                    # 提取技术名
                    tech_name = _extract_technique_name(r)
                    if tech_name and tech_name not in techniques_used:
                        techniques_used.append(tech_name)
                    # 提取 Converter 变体
                    conv = _extract_converter_from_result(r)
                    if conv and conv not in converters_used:
                        converters_used.append(conv)
                    # 提取 OWASP ID
                    owasp = _extract_owasp_from_result(r)
                    if owasp:
                        owasp_ids.add(owasp)
                stats.append({
                    "group_name": group_name,
                    "total": total,
                    "success": success,
                    "failure": total - success,
                    "success_rate": success / total if total > 0 else 0.0,
                    "techniques": techniques_used,
                    "converter_variants": converters_used,
                    "owasp_id": ", ".join(sorted(owasp_ids)) if owasp_ids else "",
                })
            return stats

        groups = self.get_display_groups()
        stats = []
        for group_name, results in groups.items():
            total = len(results)
            success = sum(
                1 for r in results
                if hasattr(r, "outcome") and
                str(getattr(r.outcome, "value", r.outcome)).upper() == "SUCCESS"
            )
            failure = total - success
            rate = success / total if total > 0 else 0.0
            # 提取攻击技术 + Converter 变体信息
            techniques_used: list[str] = []
            converters_used: list[str] = []
            owasp_ids: set[str] = set()
            for r in results:
                if r is None:
                    continue
                tech_name = _extract_technique_name(r)
                if tech_name and tech_name not in techniques_used:
                    techniques_used.append(tech_name)
                conv = _extract_converter_from_result(r)
                if conv and conv not in converters_used:
                    converters_used.append(conv)
                owasp = _extract_owasp_from_result(r)
                if owasp:
                    owasp_ids.add(owasp)
            stats.append({
                "group_name": group_name,
                "total": total,
                "success": success,
                "failure": failure,
                "success_rate": rate,
                "techniques": techniques_used,
                "converter_variants": converters_used,
                "owasp_id": ", ".join(sorted(owasp_ids)) if owasp_ids else "",
            })
        return stats

    def get_upgrade_stats(self) -> dict[str, int]:
        """获取升级重试统计"""
        return {
            "upgrade_attempts": self._batch_result.upgrade_attempts,
            "upgrade_success": self._batch_result.upgrade_success,
        }

    def get_errors(self) -> list[dict[str, str]]:
        """获取错误列表"""
        return self._batch_result.errors

    def get_owasp_mapping(self) -> dict[str, str]:
        """
        获取 OWASP 映射

        从 memory_labels 中提取 OWASP ID 映射。
        保留自建 OWASP 映射功能，通过原生 memory_labels 集成。

        Returns:
            OWASP ID -> 攻击结果数 的映射
        """
        owasp_mapping: dict[str, str] = {}
        owasp_id = self._memory_labels.get("owasp_id", "")
        if owasp_id:
            owasp_mapping[owasp_id] = f"{self.successful_attacks}/{self.total_attacks}"
        return owasp_mapping

    def get_summary(self) -> dict[str, Any]:
        """获取完整摘要"""
        return {
            "scenario_name": self.scenario_name,
            "scenario_version": self.scenario_version,
            "scenario_result_id": self._id,
            "total_attacks": self.total_attacks,
            "successful_attacks": self.successful_attacks,
            "failed_attacks": self.failed_attacks,
            "errored_attacks": self._batch_result.errored,
            "success_rate": self.objective_achieved_rate(),
            "upgrade_attempts": self._batch_result.upgrade_attempts,
            "upgrade_success": self._batch_result.upgrade_success,
            "errors_count": len(self._batch_result.errors),
            "has_native_result": self._native_result is not None,
            "memory_labels": dict(self._memory_labels),
        }


# ============================================================
# 结果提取辅助函数（PyRIT 原生 API 优先）
# ============================================================


def _extract_technique_name(result: Any) -> str:
    """
    从 AttackResult 提取攻击技术名称（PyRIT 原生 API）

    使用原生 get_attack_strategy_identifier().unique_name 获取技术名。
    如果技术名含 "+"（Converter 变体），只返回基础技术部分。
    """
    identifier = None
    if hasattr(result, "get_attack_strategy_identifier"):
        identifier = result.get_attack_strategy_identifier()
    if identifier is not None:
        name = getattr(identifier, "unique_name", "") or ""
        # Converter 变体格式: "prompt_sending+stealth_evasion"
        if "+" in name:
            return name.split("+")[0]
        return name
    return ""


def _extract_converter_from_result(result: Any) -> str:
    """
    从 AttackResult 提取 Converter 信息（PyRIT 原生 API）

    从 identifier.children['request_converters'] 检测 Converter。
    当 attack 配置了 attack_converter_config 时，identifier.children 中
    会包含 'request_converters' 键，其值为 ConverterIdentifier 列表。

    Returns:
        Converter 类名列表（逗号分隔），无 Converter 时返回空字符串
    """
    identifier = None
    if hasattr(result, "get_attack_strategy_identifier"):
        identifier = result.get_attack_strategy_identifier()
    if identifier is None:
        return ""

    children = getattr(identifier, "children", None) or {}
    req_converters = children.get("request_converters")
    if not req_converters:
        return ""

    names: list[str] = []
    if isinstance(req_converters, list):
        for conv_id in req_converters:
            cn = getattr(conv_id, "class_name", "")
            if cn:
                names.append(cn)
    else:
        cn = getattr(req_converters, "class_name", "")
        if cn:
            names.append(cn)
    return ", ".join(names)


def _extract_owasp_from_result(result: Any) -> str:
    """
    从 AttackResult 提取 OWASP ID（PyRIT 原生 labels API）

    PyRIT 原生 AttackResult.labels 是 dict[str, str]，
    我们通过 memory_labels 注入了 owasp_id。
    """
    labels = getattr(result, "labels", None) or {}
    owasp_id = labels.get("owasp_id", "")
    if owasp_id:
        return owasp_id
    # Fallback: 检查 metadata
    metadata = getattr(result, "metadata", None) or {}
    return str(metadata.get("owasp_id", ""))


# ============================================================
# 便捷函数
# ============================================================

def batch_result_to_scenario_result(
    batch_result: BatchAttackResult,
    *,
    native_result: Any = None,
    scenario_result_id: str | None = None,
    memory_labels: dict[str, str] | None = None,
) -> ScenarioResultBridge:
    """
    将 BatchAttackResult 转换为 ScenarioResultBridge

    Args:
        batch_result: 当前项目的 BatchAttackResult
        native_result: 可选的原生 ScenarioResult
        scenario_result_id: 可选的 ScenarioResult ID（用于 resume）
        memory_labels: 可选的 memory_labels（含 OWASP ID 等）

    Returns:
        ScenarioResultBridge 实例，提供原生 ScenarioResult 兼容接口
    """
    return ScenarioResultBridge(
        batch_result,
        native_result=native_result,
        scenario_result_id=scenario_result_id,
        memory_labels=memory_labels,
    )


def build_memory_labels(
    owasp_id: str = "",
    exam_id: str = "",
    **extra: str,
) -> dict[str, str]:
    """
    构建 memory_labels（含 OWASP ID 等）

    通过原生 memory_labels 将 OWASP 映射集成到 Scenario 运行中。
    原生 Scenario 支持 memory_labels 参数，自动标记所有攻击结果。

    Args:
        owasp_id: OWASP 分类 ID（如 "LLM01"）
        exam_id: 考试 ID
        **extra: 额外标签

    Returns:
        memory_labels 字典
    """
    labels: dict[str, str] = {}
    if owasp_id:
        labels["owasp_id"] = owasp_id
    if exam_id:
        labels["exam_id"] = exam_id
    labels.update(extra)
    return labels
