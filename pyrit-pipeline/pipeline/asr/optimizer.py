# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ASR 驱动的攻击优化器。.

基于历史 AttackResult 数据，为当前运行提供:
  - 按 harm category 的历史 ASR 排序 (指导数据集优先级)
  - 按技术的成功率排序 (指导技术选择)
  - 目标模型感知的载荷筛选
  - **同次运行内 ASR 动态反馈** (Stage 3 → Stage 2 闭环)

设计原则:
  - ASR 数据驱动: 所有决策基于 memory 中的实测数据
  - 冷启动友好: 无历史数据时退化为均匀采样 (Laplace 平滑)
  - PyRIT 原生兼容: 不替换原生组件, 仅在 pipeline 层提供排序信号
  - **不依赖私有 API**: 使用原生 ``AttackStats`` 公共 dataclass,
    自行构建统计结果, 不调用 ``_compute_stats`` 私有函数

参考:
  - arXiv:2402.16860 (HarmBench) — 标准化红队评估框架
  - arXiv:2310.04451 (PAIR) — 自适应攻击策略选择
  - arXiv:2406.16241 (TAP) — 基于搜索的技术选择优化

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 15:00 — 替换 _compute_stats 私有 API 为本地 compute_stats, 消除上游依赖风险
>   2026-8-1 15:05 — 添加 memory 查询异常保护, 数据库异常不再直接传播
>   2026-8-1 15:10 — 添加 query_current_run_asr_by_technique 实现同次运行内 ASR 反馈
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from pyrit.analytics.result_analysis import AttackStats
from pyrit.memory import CentralMemory
from pyrit.models import AttackOutcome

if TYPE_CHECKING:
    from pyrit.memory.memory_interface import MemoryInterface

logger = logging.getLogger(__name__)

# P1: 经验 ASR 持久化路径
_EMPIRICAL_ASR_PATH = Path("outputs/empirical_asr.json")


# ──────────────────────────────────────────────────────────────────
#  公共工具: 替代原生私有 API _compute_stats
# ──────────────────────────────────────────────────────────────────


def compute_stats(
    *,
    successes: int,
    failures: int,
    undetermined: int,
    errors: int,
) -> AttackStats:
    """构建 ``AttackStats`` 统计对象 (替代原生私有 ``_compute_stats``)。.

    使用原生公共 dataclass ``AttackStats``, 不依赖 ``pyrit.analytics.result_analysis._compute_stats``
    私有函数。逻辑等价但只依赖公共 API, 上游变更不会破坏本模块。

    Args:
        successes: 成功数。
        failures: 失败数。
        undetermined: 未确定数。
        errors: 错误数。

    Returns:
        AttackStats 实例。
    """
    total_decided: int = successes + failures
    success_rate: float | None = successes / total_decided if total_decided > 0 else None
    return AttackStats(
        success_rate=success_rate,
        total_decided=total_decided,
        successes=successes,
        failures=failures,
        undetermined=undetermined,
        errors=errors,
    )


# ──────────────────────────────────────────────────────────────────
#  历史 ASR 查询 (跨运行学习)
# ──────────────────────────────────────────────────────────────────


def query_historical_asr_by_category(
    *,
    memory: MemoryInterface | None = None,
    scenario_result_id: str | None = None,
) -> dict[str, AttackStats]:
    """查询历史 ASR, 按 harm category 分组统计。.

    基于 memory 中的全部 (或指定运行的) AttackResult, 按 targeted_harm_categories
    聚合成功/失败计数。用于指导数据集优先级排序: 历史 ASR 高的 harm category
    优先攻击 (攻击为王原则)。

    Args:
        memory: Memory 实例, 默认从 CentralMemory 获取。
        scenario_result_id: 限定查询范围到指定运行, None 则查询全部历史。

    Returns:
        dict[str, AttackStats]: harm_category -> AttackStats 映射。
        无历史数据的 category 不包含在结果中。
        数据库异常时返回空字典 (优雅降级)。
    """
    if memory is None:
        memory = CentralMemory.get_memory_instance()

    try:
        results = memory.get_attack_results(scenario_result_id=scenario_result_id)
    except Exception as e:
        logger.warning(f"查询历史 ASR (by category) 失败, 返回空结果: {e}")
        return {}

    # 按 harm category 聚合
    category_counts: dict[str, tuple[int, int, int, int]] = defaultdict(lambda: (0, 0, 0, 0))
    for result in results:
        # AttackResult 携带 targeted_harm_categories (从 AtomicAttack 继承)
        categories = getattr(result, "targeted_harm_categories", None) or []
        if not categories:
            # 回退: 从 objective 的 seed metadata 获取 (如果有)
            categories = ["unknown"]

        s, f, u, e = (0, 0, 0, 0)
        if result.outcome == AttackOutcome.SUCCESS:
            s = 1
        elif result.outcome == AttackOutcome.FAILURE:
            f = 1
        elif result.outcome == AttackOutcome.ERROR:
            e = 1
        else:
            u = 1

        for cat in categories:
            ps, pf, pu, pe = category_counts[cat]
            category_counts[cat] = (ps + s, pf + f, pu + u, pe + e)

    return {
        cat: compute_stats(successes=s, failures=f, undetermined=u, errors=e)
        for cat, (s, f, u, e) in category_counts.items()
    }


def sort_datasets_by_asr(
    dataset_names: list[str],
    *,
    asr_by_category: dict[str, AttackStats] | None = None,
) -> list[str]:
    """按历史 ASR 排序数据集名称。.

    将每个数据集映射到其主要的 harm category, 然后按该 category 的历史 ASR
    降序排列。无历史数据的数据集排在末尾 (Laplace 平滑后默认 0.5)。

    数据集 → harm category 映射 (基于数据集元数据):
      - harmbench → cybercrime, illegal, chemical_biological, harassment
      - jbb_behaviors → disinformation, economic_harm, harassment, malware, physical_harm, privacy, sexual
      - strong_reject → disinformation, hate, illegal_goods, non_violent_crimes, sexual, violence

    Args:
        dataset_names: 待排序的数据集名称列表。
        asr_by_category: 历史 ASR 统计, None 则查询 memory。

    Returns:
        排序后的数据集名称列表 (ASR 高的在前)。
    """
    if asr_by_category is None:
        asr_by_category = query_historical_asr_by_category()

    # 数据集 → 主要 harm categories 映射
    _DATASET_CATEGORIES: dict[str, list[str]] = {
        "harmbench": ["cybercrime", "illegal", "chemical_biological", "harassment", "harmful"],
        "jbb_behaviors": [
            "disinformation",
            "economic harm",
            "harassment/discrimination",
            "malware/hacking",
            "physical harm",
            "privacy",
            "sexual/adult content",
        ],
        "strong_reject": [
            "disinformation and deception",
            "hate, harassment and discrimination",
            "illegal goods and services",
            "non-violent crimes",
            "sexual content",
            "violence",
        ],
        "adv_bench": ["cybercrime", "illegal", "chemical_biological", "harassment"],
    }

    def _dataset_asr_score(name: str) -> float:
        """计算数据集的 ASR 分数 (取其主要 category 的平均 ASR)。."""
        categories = _DATASET_CATEGORIES.get(name, [])
        if not categories:
            return 0.5  # 未知数据集: 中等优先级

        scores: list[float] = []
        for cat in categories:
            stats = asr_by_category.get(cat)
            if stats and stats.total_decided > 0:
                # Laplace 平滑: (successes + 1) / (total + 2)
                smoothed = (stats.successes + 1) / (stats.total_decided + 2)
                scores.append(smoothed)
        if not scores:
            return 0.5  # 无历史数据: 中等优先级 (Laplace 平滑)
        return sum(scores) / len(scores)

    return sorted(dataset_names, key=_dataset_asr_score, reverse=True)


def query_historical_asr_by_technique(
    *,
    memory: MemoryInterface | None = None,
    scenario_result_id: str | None = None,
) -> dict[str, AttackStats]:
    """查询历史 ASR, 按攻击技术分组统计。.

    基于 memory 中的全部 (或指定运行的) AttackResult, 按 attack strategy class name
    聚合成功/失败计数。用于:
      - 展示技术 ASR 排行榜 (透明化)
      - 指导 epsilon 调参 (高 ASR 技术多 → 降低探索)
      - 验证 selector 的技术选择是否合理

    Args:
        memory: Memory 实例, 默认从 CentralMemory 获取。
        scenario_result_id: 限定查询范围。

    Returns:
        dict[str, AttackStats]: technique_name -> AttackStats 映射。
        数据库异常时返回空字典 (优雅降级)。
    """
    if memory is None:
        memory = CentralMemory.get_memory_instance()

    try:
        results = memory.get_attack_results(scenario_result_id=scenario_result_id)
    except Exception as e:
        logger.warning(f"查询历史 ASR (by technique) 失败, 返回空结果: {e}")
        return {}

    technique_counts: dict[str, tuple[int, int, int, int]] = defaultdict(lambda: (0, 0, 0, 0))
    for result in results:
        strategy_id = result.get_attack_strategy_identifier()
        technique_name = strategy_id.class_name if strategy_id else "unknown"

        s, f, u, e = technique_counts[technique_name]
        if result.outcome == AttackOutcome.SUCCESS:
            technique_counts[technique_name] = (s + 1, f, u, e)
        elif result.outcome == AttackOutcome.FAILURE:
            technique_counts[technique_name] = (s, f + 1, u, e)
        elif result.outcome == AttackOutcome.ERROR:
            technique_counts[technique_name] = (s, f, u, e + 1)
        else:
            technique_counts[technique_name] = (s, f, u + 1, e)

    return {
        tech: compute_stats(successes=s, failures=f, undetermined=u, errors=e)
        for tech, (s, f, u, e) in technique_counts.items()
    }


# ──────────────────────────────────────────────────────────────────
#  同次运行内 ASR 反馈 (Stage 3 → Stage 2 闭环)
# ──────────────────────────────────────────────────────────────────


def query_current_run_asr_by_technique(
    scenario_result_id: str,
    *,
    memory: MemoryInterface | None = None,
) -> dict[str, AttackStats]:
    """查询当前运行中已完成的 AttackResult ASR (按技术分组)。.

    在 Stage 3 ``initialize_async()`` 完成后、Stage 4 ``run_async()`` 执行前调用,
    实现同次运行内 ASR 反馈闭环:

    1. Stage 2 构建场景 (基于历史 ASR 排序数据集和技术)
    2. Stage 3 初始化场景, 构建 AtomicAttack
    3. **[本函数]** 查询当前运行中已完成的 ASR (resume 场景有已完成结果)
    4. 将反馈写入 ``ctx.metadata`` 供后续阶段使用
    5. Stage 4 执行时, ``EpsilonGreedyTechniqueSelector`` 已可读取更新后的 ASR

    在冷启动 (首次运行) 时, 当前运行无已完成结果, 返回空字典,
    不影响后续流程 (退化为历史 ASR 驱动)。

    Args:
        scenario_result_id: 当前运行的 ScenarioResult ID。
        memory: Memory 实例, 默认从 CentralMemory 获取。

    Returns:
        dict[str, AttackStats]: 当前运行中已完成的技术 ASR 统计。
        数据库异常或无数据时返回空字典。
    """
    if not scenario_result_id:
        return {}

    if memory is None:
        memory = CentralMemory.get_memory_instance()

    try:
        results = memory.get_attack_results(scenario_result_id=scenario_result_id)
    except Exception as e:
        logger.warning(f"查询当前运行 ASR 失败, 跳过动态反馈: {e}")
        return {}

    if not results:
        logger.debug("当前运行无已完成 AttackResult, 跳过动态反馈 (冷启动)")
        return {}

    technique_counts: dict[str, tuple[int, int, int, int]] = defaultdict(lambda: (0, 0, 0, 0))
    for result in results:
        strategy_id = result.get_attack_strategy_identifier()
        technique_name = strategy_id.class_name if strategy_id else "unknown"

        s, f, u, e = technique_counts[technique_name]
        if result.outcome == AttackOutcome.SUCCESS:
            technique_counts[technique_name] = (s + 1, f, u, e)
        elif result.outcome == AttackOutcome.FAILURE:
            technique_counts[technique_name] = (s, f + 1, u, e)
        elif result.outcome == AttackOutcome.ERROR:
            technique_counts[technique_name] = (s, f, u, e + 1)
        else:
            technique_counts[technique_name] = (s, f, u + 1, e)

    asr_map = {
        tech: compute_stats(successes=s, failures=f, undetermined=u, errors=e)
        for tech, (s, f, u, e) in technique_counts.items()
    }

    if asr_map:
        logger.info(f"同次运行 ASR 反馈: {len(asr_map)} 个技术有已完成结果")
        for tech, stats in sorted(asr_map.items(), key=lambda x: x[1].success_rate or 0, reverse=True):
            if stats.total_decided > 0:
                sr = stats.success_rate or 0
                logger.info(f"  当前运行 {tech}: {sr * 100:.1f}% ({stats.successes}/{stats.total_decided})")

    return asr_map


# ──────────────────────────────────────────────────────────────────
#  ASR 摘要展示 (透明化)
# ──────────────────────────────────────────────────────────────────


def get_technique_asr_summary(
    *,
    memory: MemoryInterface | None = None,
) -> str:
    """生成技术 ASR 排行榜摘要 (用于 Stage 2 日志展示)。.

    Args:
        memory: Memory 实例。

    Returns:
        格式化的技术 ASR 排行榜字符串。
    """
    asr_by_tech = query_historical_asr_by_technique(memory=memory)

    if not asr_by_tech:
        return "  (无历史技术 ASR 数据 — 首次运行)"

    lines: list[str] = ["  历史 ASR (按技术):"]
    for tech, stats in sorted(asr_by_tech.items(), key=lambda x: x[1].success_rate or 0, reverse=True):
        if stats.total_decided > 0:
            sr = stats.success_rate or 0
            bar = "█" * int(sr * 20)
            lines.append(f"    {tech:<40} {sr * 100:>5.1f}% ({stats.successes}/{stats.total_decided}) {bar}")

    return "\n".join(lines)


def get_asr_summary(
    *,
    asr_by_category: dict[str, AttackStats] | None = None,
    memory: MemoryInterface | None = None,
) -> str:
    """生成 ASR 摘要文本 (用于 Stage 2 日志展示)。.

    Args:
        asr_by_category: 预查询的 ASR 统计, None 则查询 memory。
        memory: Memory 实例。

    Returns:
        格式化的 ASR 摘要字符串。
    """
    if asr_by_category is None:
        asr_by_category = query_historical_asr_by_category(memory=memory)

    if not asr_by_category:
        return "  (无历史 ASR 数据 — 首次运行, 使用均匀采样)"

    lines: list[str] = ["  历史 ASR (按 harm category):"]
    for cat, stats in sorted(asr_by_category.items(), key=lambda x: x[1].success_rate or 0, reverse=True):
        if stats.total_decided > 0:
            sr = stats.success_rate or 0
            bar = "█" * int(sr * 20)
            lines.append(f"    {cat:<40} {sr * 100:>5.1f}% ({stats.successes}/{stats.total_decided}) {bar}")

    return "\n".join(lines)


def get_current_run_asr_summary(
    asr_by_tech: dict[str, AttackStats],
) -> str:
    """生成当前运行 ASR 反馈摘要 (用于 Stage 3 日志展示)。.

    Args:
        asr_by_tech: 当前运行的技术 ASR 统计。

    Returns:
        格式化的当前运行 ASR 摘要字符串。
    """
    if not asr_by_tech:
        return "  (当前运行无已完成结果 — 冷启动)"

    lines: list[str] = ["  同次运行 ASR 反馈 (动态调参依据):"]
    for tech, stats in sorted(asr_by_tech.items(), key=lambda x: x[1].success_rate or 0, reverse=True):
        if stats.total_decided > 0:
            sr = stats.success_rate or 0
            bar = "█" * int(sr * 20)
            lines.append(f"    {tech:<40} {sr * 100:>5.1f}% ({stats.successes}/{stats.total_decided}) {bar}")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────
#  P1: 经验 ASR 自动刷新 (运行后历史数据覆盖学术先验)
# ──────────────────────────────────────────────────────────────────


def save_empirical_asr(
    asr_per_technique: dict[str, float],
    *,
    path: Path | None = None,
) -> None:
    """保存运行时经验 ASR 到 JSON 文件, 供下次运行覆盖学术先验。.

    P1: 每次运行后调用, 将实际 ASR 数据持久化。
    下次运行时 ``load_empirical_asr()`` 加载并覆盖学术先验,
    实现 "经验 ASR > 学术先验" 的自动刷新。

    Args:
        asr_per_technique: {技术名: ASR百分比} 字典 (0-100)。
        path: 保存路径, 默认 ``output/empirical_asr.json``。
    """
    if path is None:
        path = _EMPIRICAL_ASR_PATH

    path.parent.mkdir(parents=True, exist_ok=True)

    # 转换为 0-1 范围并添加元数据
    data = {
        "techniques": {tech: asr / 100.0 for tech, asr in asr_per_technique.items()},
        "_meta": {
            "total_techniques": len(asr_per_technique),
            "description": "Empirical ASR data collected from runtime. Overrides academic priors.",
        },
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(f"Empirical ASR saved to {path} ({len(asr_per_technique)} techniques)")


def load_empirical_asr(
    path: Path | None = None,
) -> dict[str, float]:
    """加载经验 ASR 数据 (0-1 范围)。.

    P1: 在 Stage 2 构建 warm-start ASR 时调用,
    将经验数据与学术先验合并 (经验优先)。

    Args:
        path: 加载路径, 默认 ``outputs/empirical_asr.json``。

    Returns:
        {技术名: ASR(0-1)} 字典, 文件不存在时返回空字典。
    """
    if path is None:
        path = _EMPIRICAL_ASR_PATH

    if not path.exists():
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        techniques = data.get("techniques", {})
        logger.info(f"Empirical ASR loaded from {path} ({len(techniques)} techniques)")
        return techniques
    except Exception as e:
        logger.warning(f"Failed to load empirical ASR from {path}: {e}")
        return {}


def merge_empirical_with_priors(
    academic_asr: dict[str, float],
    empirical_asr: dict[str, float] | None = None,
) -> dict[str, float]:
    """合并学术先验 ASR 与经验 ASR (经验优先)。.

    P1: 经验 ASR 覆盖学术先验, 未覆盖的技术保留学术先验值。
    这实现了 "运行后历史数据覆盖学术先验" 的自动刷新机制。

    Args:
        academic_asr: 学术先验 ASR 字典 (技术→ASR 0-1)。
        empirical_asr: 经验 ASR 字典, None 则自动加载。

    Returns:
        合并后的 ASR 字典 (经验优先)。
    """
    if empirical_asr is None:
        empirical_asr = load_empirical_asr()

    if not empirical_asr:
        return dict(academic_asr)

    merged = dict(academic_asr)
    overridden = 0
    for tech, asr in empirical_asr.items():
        if tech in merged:
            overridden += 1
        merged[tech] = asr

    if overridden > 0:
        logger.info(f"ASR refresh: {overridden} techniques overridden by empirical data out of {len(merged)} total")

    return merged
