"""
Scenario Result Bridge — BatchAttackResult <-> ScenarioResult 桥接
====================================================================

P4: 结果标准化与弹性恢复 — ScenarioResult 适配层

桥接当前项目的 BatchAttackResult 和 PyRIT 原生 ScenarioResult：
  - batch_result_to_scenario_result: 将 BatchAttackResult 转换为 ScenarioResult
  - ScenarioResultBridge: 双向桥接器，提供统一接口

保留自建优势：
  - BatchAttackResult 的升级重试统计
  - AttackResultAttribution 父级关联
  - OWASP 映射
  - 错误详情

桥接到原生 API：
  - ScenarioResult 的 get_display_groups()
  - ScenarioResult 的 objective_achieved_rate()
  - ScenarioResult 的 attack_results 列表
"""

import logging
import uuid
from typing import Any

from src.payloads.models import BatchAttackResult

logger = logging.getLogger(__name__)


class ScenarioResultBridge:
    """
    BatchAttackResult <-> ScenarioResult 双向桥接器

    提供统一接口，使当前项目的 BatchAttackResult 可以被
    PyRIT 原生 output_scenario_async 等函数使用。

    核心方法：
      - to_display_groups(): 返回按 display_group 分组的结果
      - get_success_rate(): 返回整体成功率
      - get_per_group_stats(): 返回每组统计
      - get_attack_results(): 返回扁平化结果列表
    """

    def __init__(self, batch_result: BatchAttackResult) -> None:
        """
        初始化桥接器

        Args:
            batch_result: 当前项目的 BatchAttackResult
        """
        self._batch_result = batch_result
        self._id = str(uuid.uuid4())

    @property
    def id(self) -> str:
        """ScenarioResult ID"""
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

    def objective_achieved_rate(self) -> float:
        """目标达成率（成功率）"""
        if self._batch_result.executed == 0:
            return 0.0
        return self._batch_result.success_rate

    def get_display_groups(self) -> dict[str, list]:
        """
        按 display_group 分组结果

        模拟 PyRIT ScenarioResult.get_display_groups() 的行为。
        由于 BatchAttackResult 不原生支持 display_group，
        按 attack_technique 分组。
        """
        groups: dict[str, list] = {}
        for result in self.attack_results:
            technique = "unknown"
            if hasattr(result, "get_attack_strategy_identifier"):
                identifier = result.get_attack_strategy_identifier()
                if identifier:
                    technique = identifier.class_name
            elif hasattr(result, "attack_strategy_type"):
                technique = str(result.attack_strategy_type)

            group_name = technique
            groups.setdefault(group_name, []).append(result)
        return groups

    def get_per_group_stats(self) -> list[dict[str, Any]]:
        """
        获取每组的统计信息

        Returns:
            每组统计列表，每项包含：
            - group_name: 组名
            - total: 总数
            - success: 成功数
            - failure: 失败数
            - success_rate: 成功率
        """
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
            stats.append({
                "group_name": group_name,
                "total": total,
                "success": success,
                "failure": failure,
                "success_rate": rate,
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

    def get_summary(self) -> dict[str, Any]:
        """获取完整摘要"""
        return {
            "scenario_name": self.scenario_name,
            "scenario_version": self.scenario_version,
            "total_attacks": self.total_attacks,
            "successful_attacks": self.successful_attacks,
            "failed_attacks": self.failed_attacks,
            "errored_attacks": self._batch_result.errored,
            "success_rate": self.objective_achieved_rate(),
            "upgrade_attempts": self._batch_result.upgrade_attempts,
            "upgrade_success": self._batch_result.upgrade_success,
            "errors_count": len(self._batch_result.errors),
        }


# ============================================================
# 便捷函数
# ============================================================

def batch_result_to_scenario_result(
    batch_result: BatchAttackResult,
) -> ScenarioResultBridge:
    """
    将 BatchAttackResult 转换为 ScenarioResultBridge

    Args:
        batch_result: 当前项目的 BatchAttackResult

    Returns:
        ScenarioResultBridge 实例，提供原生 ScenarioResult 兼容接口
    """
    return ScenarioResultBridge(batch_result)
