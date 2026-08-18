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

import hashlib
import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pyrit.analytics.result_analysis import AttackStats
from pyrit.memory import CentralMemory
from pyrit.models import AttackOutcome

if TYPE_CHECKING:
    from pyrit.memory.memory_interface import MemoryInterface

logger = logging.getLogger(__name__)

# P1: 经验 ASR 持久化路径 (G-05: 按模型分文件存储)
_EMPIRICAL_ASR_DIR = Path("outputs/empirical_asr")
_EMPIRICAL_ASR_PATH = Path("outputs/empirical_asr.json")  # 向后兼容回退


def _get_model_safe_name(model_name: str) -> str:
    """将模型名转换为文件系统安全的名称。."""
    return model_name.replace("/", "_").replace("\\", "_").replace(":", "_")


def _get_empirical_asr_path(model_name: str | None = None) -> Path:
    """获取经验 ASR 文件路径 (G-05: 按模型分文件).

    Args:
        model_name: 模型名。如果提供, 返回 ``outputs/empirical_asr/{model}.json``;
            如果为 None, 返回旧的全局路径 ``outputs/empirical_asr.json``。
    """
    if model_name and model_name != "unknown":
        safe_name = _get_model_safe_name(model_name)
        return _EMPIRICAL_ASR_DIR / f"{safe_name}.json"
    return _EMPIRICAL_ASR_PATH


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
    dataset_level_asr: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """按历史 ASR 排序数据集名称。.

    优先使用 **数据集级经验 ASR** (跨运行持久化的 per-dataset ASR),
    如果不存在则回退到 harm category 级 ASR (当前运行查询 CentralMemory)。

    数据集级 ASR (优先):
      - 从 ``outputs/empirical_asr/dataset_level_{model}.json`` 加载
      - 直接按 per-dataset ASR 降序排列, 精度更高

    harm category 级 ASR (回退):
      - 将每个数据集映射到其主要的 harm category, 然后按该 category 的历史 ASR
        降序排列。无历史数据的数据集排在末尾 (Laplace 平滑后默认 0.5)。

    数据集 → harm category 映射 (基于数据集元数据):
      - harmbench → cybercrime, illegal, chemical_biological, harassment
      - jbb_behaviors → disinformation, economic_harm, harassment, malware, physical_harm, privacy, sexual
      - strong_reject → disinformation, hate, illegal_goods, non_violent_crimes, sexual, violence

    Args:
        dataset_names: 待排序的数据集名称列表。
        asr_by_category: 历史 ASR 统计 (category 级), None 则查询 memory。
        dataset_level_asr: 数据集级经验 ASR (跨运行持久化),
            优先于 asr_by_category。None 则回退到 category 级。

    Returns:
        排序后的数据集名称列表 (ASR 高的在前)。
    """
    # 优先使用数据集级经验 ASR (跨运行持久化, 精度更高)
    if dataset_level_asr:
        def _dataset_asr_score_direct(name: str) -> float:
            info = dataset_level_asr.get(name)
            if info:
                return info.get("asr", 0.5)
            return 0.5  # 未知数据集: 中等优先级
        return sorted(dataset_names, key=_dataset_asr_score_direct, reverse=True)

    # 回退: harm category 级 ASR (当前运行查询)
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


def _query_asr_by_technique(
    results: list[Any],
) -> dict[str, AttackStats]:
    """从已获取的 AttackResult 列表按技术聚合 ASR (私有 helper)。.

    被 ``query_historical_asr_by_technique`` 和
    ``query_current_run_asr_by_technique`` 共享, 消除重复的
    outcome 聚合逻辑 (DRY)。

    Args:
        results: 已从 memory 获取的 AttackResult 列表。

    Returns:
        dict[str, AttackStats]: technique_name -> AttackStats 映射。
    """
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

    return _query_asr_by_technique(results)


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

    asr_map = _query_asr_by_technique(results)

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
    model_name: str | None = None,
    path: Path | None = None,
    sample_counts: dict[str, int] | None = None,
) -> None:
    """保存运行时经验 ASR 到 JSON 文件, 供下次运行覆盖学术先验。.

    G-05: 当 ``model_name`` 提供时, 按模型分文件存储到
    ``outputs/empirical_asr/{model}.json``, 实现模型隔离。
    无 ``model_name`` 时回退到全局路径 (向后兼容)。

    Args:
        asr_per_technique: {技术名: ASR百分比} 字典 (0-100)。
        model_name: 目标模型名 (G-05 按模型隔离)。
        path: 保存路径, 默认按模型名自动推导。
        sample_counts: {技术名: 样本数} 字典, v60+ 置信度标注用。
    """
    if path is None:
        path = _get_empirical_asr_path(model_name)

    path.parent.mkdir(parents=True, exist_ok=True)

    # O1 修复: 过滤非攻击技术名 (数据集名不应保存为技术 ASR)
    # v60+: 保留 alt_path_ 前缀键 (替代路径ASR, 非注册技术名但需持久化)
    from pipeline.analysis.technique_name_mapper import is_known_technique

    filtered_asr = {
        tech: asr
        for tech, asr in asr_per_technique.items()
        if is_known_technique(tech) or tech.startswith("alt_path_")
    }
    skipped_count = len(asr_per_technique) - len(filtered_asr)
    if skipped_count > 0:
        logger.debug(f"save_empirical_asr: skipped {skipped_count} non-technique keys")

    # v60+: 新增 sample_counts 到 _meta, 供 warm-start 置信度计算
    meta: dict[str, Any] = {
        "total_techniques": len(filtered_asr),
        "model_name": model_name or "unknown",
        "description": "Empirical ASR data collected from runtime. Overrides academic priors.",
    }
    if sample_counts:
        # 仅保留有 ASR 数据的技术样本数
        meta["sample_counts"] = {
            tech: count for tech, count in sample_counts.items() if tech in filtered_asr
        }

    data = {
        "techniques": {tech: asr / 100.0 for tech, asr in filtered_asr.items()},
        "_meta": meta,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(f"Empirical ASR saved to {path} ({len(asr_per_technique)} techniques, model={model_name or 'global'})")



def load_empirical_asr(
    model_name: str | None = None,
    *,
    path: Path | None = None,
) -> dict[str, float]:
    """加载经验 ASR 数据 (0-1 范围)。.

    G-05: 当 ``model_name`` 提供时, 优先加载按模型分文件的路径
    ``outputs/empirical_asr/{model}.json``; 如果不存在则回退到全局路径。

    Args:
        model_name: 目标模型名 (G-05 按模型隔离)。
        path: 加载路径, 默认按模型名自动推导。

    Returns:
        {技术名: ASR(0-1)} 字典, 文件不存在时返回空字典。
    """
    if path is None:
        path = _get_empirical_asr_path(model_name)
        # G-05: 如果按模型的路径不存在, 尝试回退到全局路径 (向后兼容)
        if not path.exists() and model_name and model_name != "unknown":
            global_path = _EMPIRICAL_ASR_PATH
            if global_path.exists():
                path = global_path

    if not path.exists():
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        techniques = data.get("techniques", {})
        logger.info(f"Empirical ASR loaded from {path} ({len(techniques)} techniques)")
        return techniques
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load empirical ASR from {path}: {e}")
        return {}


def load_empirical_asr_with_counts(
    model_name: str | None = None,
    *,
    path: Path | None = None,
) -> tuple[dict[str, float], dict[str, int]]:
    """加载经验 ASR 数据 + 样本数 (v60+ 置信度标注用).

    Args:
        model_name: 目标模型名 (G-05 按模型隔离)。
        path: 加载路径, 默认按模型名自动推导。

    Returns:
        (techniques, sample_counts) 元组:
        - techniques: {技术名: ASR(0-1)} 字典
        - sample_counts: {技术名: 样本数} 字典, 无样本数时为空字典
    """
    if path is None:
        path = _get_empirical_asr_path(model_name)
        if not path.exists() and model_name and model_name != "unknown":
            global_path = _EMPIRICAL_ASR_PATH
            if global_path.exists():
                path = global_path

    if not path.exists():
        return {}, {}

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        techniques = data.get("techniques", {})
        meta = data.get("_meta", {})
        sample_counts = meta.get("sample_counts", {})
        logger.info(
            f"Empirical ASR+counts loaded from {path} "
            f"({len(techniques)} techniques, {len(sample_counts)} with counts)"
        )
        return techniques, sample_counts
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load empirical ASR+counts from {path}: {e}")
        return {}, {}


# ──────────────────────────────────────────────────────────────────
#  P1: 种子级 ASR (per-seed prompt, not per-technique)
# ──────────────────────────────────────────────────────────────────

_SEED_LEVEL_DIR = Path("outputs/empirical_asr")


def _get_seed_level_asr_path(model_name: str | None = None) -> Path:
    """获取种子级 ASR 文件路径."""
    if model_name and model_name != "unknown":
        safe = _get_model_safe_name(model_name)
        return _SEED_LEVEL_DIR / f"seed_level_{safe}.json"
    return _SEED_LEVEL_DIR / "seed_level_global.json"


def save_seed_level_asr(
    seed_asr: dict[str, dict[str, Any]],
    *,
    model_name: str | None = None,
) -> None:
    """保存种子级实测 ASR 数据."""
    path = _get_seed_level_asr_path(model_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "model": model_name or "unknown",
        "timestamp": datetime.now().isoformat(),
        "seeds": seed_asr,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(f"Seed-level ASR saved to {path} ({len(seed_asr)} seeds, model={model_name or 'global'})")


def load_seed_level_asr(model_name: str | None = None) -> dict[str, dict[str, Any]]:
    """加载种子级实测 ASR 数据."""
    path = _get_seed_level_asr_path(model_name)
    if not path.exists() and model_name and model_name != "unknown":
        path = _SEED_LEVEL_DIR / "seed_level_global.json"
    if not path.exists():
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("seeds", {})
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load seed-level ASR from {path}: {e}")
        return {}


def _extract_seed_text(result: Any, memory: Any) -> str:
    """从 AttackResult 提取种子文本 (多路径回退, R-022 PyRIT 原生优先).

    回退顺序:
      1. result.objective — PyRIT 1.0.1 原生字段 (所有数据集 seed_type=objective)
      2. result.metadata — 元数据中的 seed_prompt / original_prompt
      3. memory.get_messages(conversation_id) — 从对话历史提取第一条 user 消息

    Args:
        result: AttackResult 实例.
        memory: MemoryInterface 实例 (用于查询对话历史).

    Returns:
        种子文本, 空字符串表示未提取到.
    """
    # 路径 1: PyRIT 原生 objective 字段 (所有数据集 seed_type=objective)
    try:
        objective = getattr(result, "objective", None)
        if objective and isinstance(objective, str) and len(objective) > 5:
            return objective
    except Exception:
        pass

    # 路径 2: metadata 中的 seed_prompt / original_prompt
    try:
        metadata = getattr(result, "metadata", None) or {}
        if isinstance(metadata, dict):
            for key in ("seed_prompt", "original_prompt", "prompt", "payload"):
                val = metadata.get(key)
                if val and isinstance(val, str) and len(val) > 5:
                    return val
    except Exception:
        pass

    # 路径 3: 从 CentralMemory 查询对话历史 (最后手段)
    try:
        conversation_id = getattr(result, "conversation_id", None)
        if conversation_id and memory:
            messages = memory.get_messages(conversation_id=conversation_id)
            if messages:
                for msg in messages:
                    role = getattr(msg, "role", "") or ""
                    if role == "user":
                        content = (
                            getattr(msg, "original_value", None)
                            or getattr(msg, "converted_value", None)
                            or getattr(msg, "content", None)
                            or ""
                        )
                        if content and isinstance(content, str) and len(content) > 5:
                            return content
    except Exception:
        pass

    return ""


def collect_seed_level_asr_from_memory(
    model_name: str | None = None,
) -> dict[str, dict[str, Any]]:
    """从 PyRIT CentralMemory 收集种子级 ASR 数据.

    遍历所有 AttackResult, 按 seed_text (种子 prompt) 分组, 计算每个种子的 ASR.
    使用多路径提取 (R-022 PyRIT 原生优先): objective → metadata → conversation.

    Args:
        model_name: 目标模型名 (用于按模型隔离保存).

    Returns:
        {seed_hash: {asr, successes, total, seed_preview}} 字典.
    """
    try:
        memory = CentralMemory.get_memory_instance()
        results = memory.get_attack_results()
    except Exception as e:
        logger.warning(f"Failed to query AttackResults for seed-level ASR: {e}")
        return {}

    logger.info(
        f"collect_seed_level_asr_from_memory: queried {len(results)} AttackResults "
        f"from CentralMemory (model={model_name})"
    )

    seed_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"s": 0, "f": 0, "u": 0, "e": 0, "preview": ""})
    empty_objective_count = 0

    for result in results:
        seed_text = _extract_seed_text(result, memory)

        if not seed_text:
            empty_objective_count += 1
            continue

        seed_hash = hashlib.md5(seed_text[:200].encode("utf-8")).hexdigest()
        seed_stats[seed_hash]["preview"] = seed_text[:100]

        outcome = result.outcome
        if outcome == AttackOutcome.SUCCESS:
            seed_stats[seed_hash]["s"] += 1
        elif outcome == AttackOutcome.FAILURE:
            seed_stats[seed_hash]["f"] += 1
        elif outcome == AttackOutcome.ERROR:
            seed_stats[seed_hash]["e"] += 1
        else:
            seed_stats[seed_hash]["u"] += 1

    result_asr: dict[str, dict[str, Any]] = {}
    for seed_hash, stats in seed_stats.items():
        total = stats["s"] + stats["f"] + stats["u"] + stats["e"]
        if total == 0:
            continue
        successes = stats["s"]
        # P4: Wilson 下界保守估计 (小样本不过拟合)
        raw_asr = successes / total
        wilson_asr = _wilson_lower_bound(successes, total) if total < 30 else raw_asr
        result_asr[seed_hash] = {
            "asr": round(wilson_asr, 3),
            "raw_asr": round(raw_asr, 3),
            "successes": successes,
            "total": total,
            "seed_preview": stats["preview"],
        }

    if result_asr:
        save_seed_level_asr(result_asr, model_name=model_name)
        logger.info(
            f"collect_seed_level_asr_from_memory: saved {len(result_asr)} seeds "
            f"(from {len(results)} results, {empty_objective_count} empty, model={model_name})"
        )
    else:
        # 降级为 debug — 冷启动时无历史 ASR 是正常情况, 不污染攻击者视角
        logger.debug(
            "collect_seed_level_asr_from_memory: result_asr is empty "
            f"(results={len(results)}, empty_objective={empty_objective_count}, "
            f"model={model_name}) — no seed_level file written"
        )

    return result_asr



def _wilson_lower_bound(successes: int, total: int, z: float = 1.96) -> float:
    """计算 Wilson 区间下界 — 小样本时保守估计 ASR。.

    G-14: 使用 Wilson 区间下界对小样本经验数据
    做保守估计, 避免少量样本导致的过拟合。

    Args:
        successes: 成功次数。
        total: 总次数。
        z: Z 值 (1.96 = 95% 置信区间)。

    Returns:
        Wilson 区间下界 (0-1)。
    """
    if total == 0:
        return 0.0
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / denominator
    return max(0.0, center - margin)


def merge_empirical_with_priors(
    academic_asr: dict[str, float],
    empirical_asr: dict[str, float] | None = None,
    *,
    model_name: str | None = None,
) -> dict[str, float]:
    """合并学术先验 ASR 与经验 ASR (G-14: 加权融合)。.

    G-14: 使用经验数据覆盖学术先验, 同时为未来扩展预留加权融合接口。
    经验数据来源于实际运行统计, 可信度高于学术先验。
    无经验数据的技术保留学术先验值。

    Args:
        academic_asr: 学术先验 ASR 字典 (技术→ASR 0-1)。
        empirical_asr: 经验 ASR 字典, None 则自动加载。
        model_name: 目标模型名 (G-05 按模型加载)。

    Returns:
        合并后的 ASR 字典。
    """
    if empirical_asr is None:
        empirical_asr = load_empirical_asr(model_name)

    if not empirical_asr:
        return dict(academic_asr)

    # O1 修复: 过滤非攻击技术名 (数据集名如 harmbench 不应进入 ASR 字典)
    from pipeline.analysis.technique_name_mapper import is_known_technique

    merged = dict(academic_asr)
    overridden = 0
    skipped = 0
    for tech, emp_asr in empirical_asr.items():
        if not is_known_technique(tech):
            skipped += 1
            continue
        if tech in merged:
            overridden += 1
        merged[tech] = emp_asr

    if overridden > 0:
        logger.info(f"ASR refresh: {overridden} techniques overridden by empirical data out of {len(merged)} total")
    if skipped > 0:
        logger.debug(f"ASR refresh: skipped {skipped} non-technique keys (dataset names)")

    return merged


# ──────────────────────────────────────────────────────────────────
#  数据集级 ASR (per-dataset, 跨运行持久化)
# ──────────────────────────────────────────────────────────────────

_DATASET_LEVEL_DIR = Path("outputs/empirical_asr")


def _get_dataset_level_asr_path(model_name: str | None = None) -> Path:
    """获取数据集级 ASR 文件路径."""
    if model_name and model_name != "unknown":
        safe = _get_model_safe_name(model_name)
        return _DATASET_LEVEL_DIR / f"dataset_level_{safe}.json"
    return _DATASET_LEVEL_DIR / "dataset_level_global.json"


def collect_dataset_level_asr_from_memory(
    model_name: str | None = None,
    dataset_names: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """从 PyRIT CentralMemory 收集数据集级 ASR 数据.

    遍历所有 AttackResult, 通过匹配种子文本 (objective) 确定每个结果
    所属的数据集, 然后按数据集聚合 ASR.

    R-022: 消费原生 CentralMemory.get_attack_results() + AttackResult.outcome
    + CentralMemory.get_seed_prompts() (原生 API).

    Args:
        model_name: 目标模型名 (用于按模型隔离保存).
        dataset_names: 数据集名称列表 (用于构建 seed→dataset 映射).
            None 时从 CentralMemory 查询所有已注册数据集.

    Returns:
        {dataset_name: {asr, raw_asr, successes, total}} 字典.
    """
    try:
        memory = CentralMemory.get_memory_instance()
        results = memory.get_attack_results()
    except Exception as e:
        logger.warning(f"Failed to query AttackResults for dataset-level ASR: {e}")
        return {}

    logger.info(
        f"collect_dataset_level_asr_from_memory: queried {len(results)} AttackResults "
        f"from CentralMemory (model={model_name})"
    )

    # 构建 seed_text → dataset_name 映射 (R-022: 原生 get_seed_prompts API)
    seed_to_dataset: dict[str, str] = {}
    if dataset_names is None:
        # 从 metadata 获取已加载的数据集名称
        try:
            all_prompts = memory.get_seed_prompts()
            dataset_names = list(
                {getattr(p, "dataset_name", "") for p in all_prompts if getattr(p, "dataset_name", "")}
            )
        except Exception:
            dataset_names = []
    for ds_name in dataset_names or []:
        try:
            prompts = memory.get_seed_prompts(dataset_name=ds_name)
            if not prompts:
                continue
            for p in prompts:
                value = getattr(p, "value", None) or getattr(p, "original_value", None) or ""
                if value and isinstance(value, str) and len(value) > 5:
                    # 用前 200 字符做匹配键 (同 seed-level ASR 的 hash 方式)
                    seed_to_dataset[value[:200]] = ds_name
        except Exception:
            continue

    logger.info(
        f"collect_dataset_level_asr_from_memory: built {len(seed_to_dataset)} "
        f"seed→dataset mappings for {len(dataset_names or [])} datasets"
    )

    # 按数据集聚合 outcome
    ds_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"s": 0, "f": 0, "u": 0, "e": 0})
    unmatched_count = 0

    for result in results:
        seed_text = _extract_seed_text(result, memory)
        if not seed_text:
            unmatched_count += 1
            continue

        match_key = seed_text[:200]
        ds_name = seed_to_dataset.get(match_key)
        if not ds_name:
            unmatched_count += 1
            continue

        outcome = result.outcome
        if outcome == AttackOutcome.SUCCESS:
            ds_stats[ds_name]["s"] += 1
        elif outcome == AttackOutcome.FAILURE:
            ds_stats[ds_name]["f"] += 1
        elif outcome == AttackOutcome.ERROR:
            ds_stats[ds_name]["e"] += 1
        else:
            ds_stats[ds_name]["u"] += 1

    result_asr: dict[str, dict[str, Any]] = {}
    for ds_name, stats in ds_stats.items():
        total = stats["s"] + stats["f"] + stats["u"] + stats["e"]
        if total == 0:
            continue
        successes = stats["s"]
        raw_asr = successes / total
        wilson_asr = _wilson_lower_bound(successes, total) if total < 30 else raw_asr
        result_asr[ds_name] = {
            "asr": round(wilson_asr, 3),
            "raw_asr": round(raw_asr, 3),
            "successes": successes,
            "total": total,
        }

    if result_asr:
        save_dataset_level_asr(result_asr, model_name=model_name)
        logger.info(
            f"collect_dataset_level_asr_from_memory: saved {len(result_asr)} datasets "
            f"(from {len(results)} results, {unmatched_count} unmatched, model={model_name})"
        )
    else:
        # 降级为 debug — 冷启动时无历史 ASR 是正常情况, 不污染攻击者视角
        logger.debug(
            "collect_dataset_level_asr_from_memory: result_asr is empty "
            f"(results={len(results)}, unmatched={unmatched_count}, "
            f"model={model_name}) — no dataset_level file written"
        )

    return result_asr


def save_dataset_level_asr(
    dataset_asr: dict[str, dict[str, Any]],
    *,
    model_name: str | None = None,
) -> None:
    """保存数据集级实测 ASR 数据.

    R-022: 与 save_seed_level_asr / save_empirical_asr 同构模式,
    JSON 持久化, 按模型分文件存储.

    Args:
        dataset_asr: {dataset_name: {asr, raw_asr, successes, total}} 字典.
        model_name: 目标模型名 (G-05 按模型隔离).
    """
    path = _get_dataset_level_asr_path(model_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "model": model_name or "unknown",
        "timestamp": datetime.now().isoformat(),
        "datasets": dataset_asr,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(f"Dataset-level ASR saved to {path} ({len(dataset_asr)} datasets, model={model_name or 'global'})")


def load_dataset_level_asr(
    model_name: str | None = None,
) -> dict[str, dict[str, Any]]:
    """加载数据集级实测 ASR 数据 (跨运行持久化).

    R-022: 与 load_seed_level_asr / load_empirical_asr 同构模式,
    优先加载按模型分文件路径, 不存在时回退到全局路径.

    Args:
        model_name: 目标模型名 (G-05 按模型加载).

    Returns:
        {dataset_name: {asr, raw_asr, successes, total}} 字典, 文件不存在时返回空字典.
    """
    path = _get_dataset_level_asr_path(model_name)
    if not path.exists() and model_name and model_name != "unknown":
        path = _DATASET_LEVEL_DIR / "dataset_level_global.json"
    if not path.exists():
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("datasets", {})
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load dataset-level ASR from {path}: {e}")
        return {}


# ──────────────────────────────────────────────────────────────────
#  MTOS: 多轮目标适宜性评分 (Multi-Turn Objective Suitability Score)
# ──────────────────────────────────────────────────────────────────
# 学术依据:
#   - Crescendo (arXiv:2402.12109): 渐进升级擅长突破单轮防御,
#     最优目标 = 单轮 ASR 低但目标可实现
#   - TAP (arXiv:2312.02191): 树搜索需"部分路径可成功"空间,
#     最优目标 = 中等难度 (单轮 ASR 10-30%)
#   - HarmBench (arXiv:2402.04249): 类别平衡采样确保覆盖
#   - DART (arXiv:2407.06485): per-seed × per-model ASR 指导选择
# ──────────────────────────────────────────────────────────────────

# MTOS 权重默认值 (可被 YAML 覆盖)
_MTOS_DEFAULT_WEIGHTS: dict[str, float] = {
    "asr_suitability": 0.35,
    "difficulty": 0.25,
    "severity": 0.20,
    "category_diversity": 0.20,
}

# 难度评分映射 (hard=高适宜, Crescendo 价值最大化)
_DIFFICULTY_SCORES: dict[str, float] = {
    "hard": 1.0,
    "medium": 0.7,
    "easy": 0.3,
}

# 严重性评分映射 (critical=高影响)
_SEVERITY_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.2,
}


def _compute_asr_suitability(
    asr: float,
    total: int,
    *,
    asr_window: tuple[float, float] = (0.0, 0.15),
) -> float:
    """计算 ASR 适宜性分数 (钟形曲线, 峰值在窗口中心).

    核心原则: 多轮攻击的种子选择应反向于单轮 —
    高单轮 ASR 种子已被单轮攻破, Crescendo 多轮渐进的价值被浪费.

    Args:
        asr: 历史单轮 ASR (Wilson 下界).
        total: 该种子的历史尝试次数.
        asr_window: (lower, upper) 偏好窗口, 默认 (0.0, 0.15) 适合 Crescendo.

    Returns:
        适宜性分数 [0.0, 1.0].
    """
    lower, upper = asr_window
    center = (lower + upper) / 2.0

    # 0% ASR 特殊处理: 区分小样本 (不确定) 和大样本 (确认难)
    if asr == 0.0:
        if total < 3:
            return 0.6  # 小样本不确定性高, Crescendo 可能突破
        return 0.3  # 多次尝试均失败, 可能确实无法突破
    elif asr < lower:
        # 低于窗口下限 (非 0%) — 偏难但非完全失败
        return 0.5
    elif asr <= upper:
        # 在偏好窗口内 — 最优
        # 越接近窗口中心越高
        distance_from_center = abs(asr - center) / max(center - lower, 0.001)
        return 1.0 - 0.2 * distance_from_center  # 0.8 ~ 1.0
    elif asr <= 0.50:
        # 中等 ASR — 单轮已可部分突破, 多轮仍有价值但递减
        return 0.4
    else:
        # 高 ASR — 单轮已可攻破, 多轮攻击浪费资源
        return 0.1


def compute_mtos_score(
    seed_hash: str,
    seed_asr_data: dict[str, Any] | None,
    seed_metadata: dict[str, Any] | None,
    *,
    used_owasp_ids: set[str] | None = None,
    weights: dict[str, float] | None = None,
    asr_window: tuple[float, float] = (0.0, 0.15),
) -> float:
    """计算单个种子的 MTOS (多轮目标适宜性) 分数.

    MTOS = w_asr × ASR_suitability + w_diff × Difficulty + w_sev × Severity + w_cat × Category_diversity

    Args:
        seed_hash: 种子哈希 (用于查 seed_asr_data).
        seed_asr_data: {seed_hash: {asr, total, seed_preview}} 历史数据.
        seed_metadata: 种子元数据 {difficulty, severity, owasp_id, ...}.
        used_owasp_ids: 已选种子的 OWASP ID 集合 (用于类别多样性).
        weights: 权重覆盖 (None=使用默认权重).
        asr_window: ASR 偏好窗口.

    Returns:
        MTOS 分数 [0.0, 1.0+], 越高越适宜.
    """
    w = weights or _MTOS_DEFAULT_WEIGHTS
    used = used_owasp_ids or set()

    # 维度 1: ASR 适宜性
    asr_val = 0.0
    total_val = 0
    if seed_asr_data and seed_hash in seed_asr_data:
        info = seed_asr_data[seed_hash]
        if isinstance(info, dict):
            asr_val = float(info.get("asr", 0.0))
            total_val = int(info.get("total", 0))
    asr_score = _compute_asr_suitability(asr_val, total_val, asr_window=asr_window)

    # 维度 2: Difficulty
    diff_str = ""
    if seed_metadata and isinstance(seed_metadata, dict):
        diff_str = str(seed_metadata.get("difficulty", "")).lower()
    diff_score = _DIFFICULTY_SCORES.get(diff_str, 0.5)  # 未知=中等

    # 维度 3: Severity
    sev_str = ""
    if seed_metadata and isinstance(seed_metadata, dict):
        sev_str = str(seed_metadata.get("severity", "")).lower()
    sev_score = _SEVERITY_SCORES.get(sev_str, 0.5)

    # 维度 4: Category diversity
    owasp_id = ""
    if seed_metadata and isinstance(seed_metadata, dict):
        owasp_id = str(seed_metadata.get("owasp_id", ""))
    cat_score = 1.0 if (owasp_id and owasp_id not in used) else 0.0

    # 加权求和
    mtos = (
        w.get("asr_suitability", 0.35) * asr_score
        + w.get("difficulty", 0.25) * diff_score
        + w.get("severity", 0.20) * sev_score
        + w.get("category_diversity", 0.20) * cat_score
    )

    return round(mtos, 4)


def select_multiturn_objectives(
    *,
    seed_level_asr: dict[str, dict[str, Any]] | None = None,
    datasets: list[str] | None = None,
    weights: dict[str, float] | None = None,
    crescendo_asr_window: tuple[float, float] = (0.0, 0.15),
    tap_asr_window: tuple[float, float] = (0.10, 0.30),
    cold_start_min_seeds: int = 5,
) -> tuple[str | None, str | None, dict[str, Any]]:
    """为 Crescendo/TAP 选择最优多轮攻击目标.

    统一入口: 热启动 (有足够历史 ASR) 走 MTOS 评分,
    冷启动 (无/少历史数据) 走元数据驱动选择.

    学术依据:
      - Crescendo (arXiv:2402.12109): 渐进升级突破单轮防御
      - TAP (arXiv:2312.02191): 树搜索需中等难度空间
      - HarmBench (arXiv:2402.04249): 类别平衡采样
      - DART (arXiv:2407.06485): per-seed × per-model ASR 指导选择

    Args:
        seed_level_asr: 历史种子级 ASR 数据 (来自 load_seed_level_asr).
        datasets: 数据集名称列表 (用于冷启动遍历 CentralMemory).
        weights: MTOS 权重覆盖.
        crescendo_asr_window: Crescendo 偏好的 ASR 窗口.
        tap_asr_window: TAP 偏好的 ASR 窗口.
        cold_start_min_seeds: 低于此数走冷启动策略.

    Returns:
        (crescendo_obj, tap_obj, meta):
          - crescendo_obj: Crescendo 目标文本 (或 None)
          - tap_obj: TAP 目标文本 (或 None)
          - meta: 选择元信息 {strategy, crescendo_seed_hash, tap_seed_hash, ...}
    """
    asr_data = seed_level_asr or {}
    is_cold_start = len(asr_data) < cold_start_min_seeds

    meta: dict[str, Any] = {
        "strategy": "cold_start" if is_cold_start else "warm_start",
        "crescendo_seed_hash": "",
        "tap_seed_hash": "",
        "crescendo_asr": None,
        "tap_asr": None,
        "crescendo_owasp_id": "",
        "tap_owasp_id": "",
        "crescendo_extra": [],  # P4: 额外 Crescendo 目标 (不同 OWASP 类别)
    }

    if not is_cold_start:
        # ── 热启动: MTOS 评分 ──
        # 从 CentralMemory 获取种子元数据 (与 ASR 数据关联)
        seed_meta_map = _build_seed_metadata_map(asr_data)

        # Crescendo 选种
        crescendo_obj, cres_hash, cres_owasp = _select_by_mtos(
            asr_data,
            seed_meta_map,
            used_owasp_ids=set(),
            weights=weights,
            asr_window=crescendo_asr_window,
        )
        if crescendo_obj:
            meta["crescendo_seed_hash"] = cres_hash
            meta["crescendo_owasp_id"] = cres_owasp
            cres_info = asr_data.get(cres_hash, {})
            if isinstance(cres_info, dict):
                meta["crescendo_asr"] = cres_info.get("asr")

        # P4: Crescendo 额外目标 (第2个, 不同 OWASP 类别)
        used_owasp_cres = {cres_owasp} if cres_owasp else set()
        cres_extra_obj, cres_extra_hash, cres_extra_owasp = _select_by_mtos(
            asr_data,
            seed_meta_map,
            used_owasp_ids=used_owasp_cres,
            weights=weights,
            asr_window=crescendo_asr_window,
            exclude_hash=cres_hash,
        )
        if cres_extra_obj:
            meta["crescendo_extra"].append({
                "objective": cres_extra_obj,
                "owasp_id": cres_extra_owasp,
                "seed_hash": cres_extra_hash,
            })

        # TAP 选种 (不同 OWASP 类别)
        used_owasp = used_owasp_cres | ({cres_extra_owasp} if cres_extra_owasp else set())
        tap_obj, tap_hash, tap_owasp = _select_by_mtos(
            asr_data,
            seed_meta_map,
            used_owasp_ids=used_owasp,
            weights=weights,
            asr_window=tap_asr_window,
            exclude_hash=cres_hash,
        )
        if tap_obj:
            meta["tap_seed_hash"] = tap_hash
            meta["tap_owasp_id"] = tap_owasp
            tap_info = asr_data.get(tap_hash, {})
            if isinstance(tap_info, dict):
                meta["tap_asr"] = tap_info.get("asr")

    else:
        # ── 冷启动: 元数据驱动选种 ──
        crescendo_obj, tap_obj, cold_meta = _select_cold_start(
            datasets=datasets,
            crescendo_asr_window=crescendo_asr_window,
            tap_asr_window=tap_asr_window,
        )
        meta.update(cold_meta)

    return crescendo_obj, tap_obj, meta


def _build_seed_metadata_map(
    asr_data: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """从 CentralMemory 构建种子哈希 → 元数据映射.

    通过匹配 seed_preview 文本的前 200 字符来关联 ASR 数据和种子元数据.
    """
    meta_map: dict[str, dict[str, Any]] = {}

    try:
        memory = CentralMemory.get_memory_instance()
        all_prompts = memory.get_seed_prompts()
    except Exception as e:
        logger.debug(f"Failed to get seed prompts for metadata map: {e}")
        return meta_map

    # 构建 preview → metadata 查找表
    preview_to_meta: dict[str, dict[str, Any]] = {}
    for p in all_prompts:
        value = (
            getattr(p, "value", None)
            or getattr(p, "original_value", None)
            or ""
        )
        if value and len(value) > 5:
            preview = value[:100]
            metadata = getattr(p, "metadata", None)
            if isinstance(metadata, dict):
                preview_to_meta[preview] = metadata

    # 关联 ASR 数据 → 元数据
    for seed_hash, info in asr_data.items():
        if not isinstance(info, dict):
            continue
        preview = info.get("seed_preview", "")
        if preview and preview in preview_to_meta:
            meta_map[seed_hash] = preview_to_meta[preview]
        else:
            # 尝试模糊匹配 (前 50 字符)
            short_preview = preview[:50]
            for p, m in preview_to_meta.items():
                if p.startswith(short_preview):
                    meta_map[seed_hash] = m
                    break

    return meta_map


def _select_by_mtos(
    asr_data: dict[str, dict[str, Any]],
    seed_meta_map: dict[str, dict[str, Any]],
    *,
    used_owasp_ids: set[str],
    weights: dict[str, float] | None = None,
    asr_window: tuple[float, float] = (0.0, 0.15),
    exclude_hash: str | None = None,
) -> tuple[str | None, str, str]:
    """按 MTOS 分数选种, 返回 (objective_text, seed_hash, owasp_id)."""
    scored: list[tuple[float, str, dict[str, Any]]] = []

    for seed_hash, info in asr_data.items():
        if seed_hash == exclude_hash:
            continue
        if not isinstance(info, dict):
            continue

        metadata = seed_meta_map.get(seed_hash, {})
        score = compute_mtos_score(
            seed_hash=seed_hash,
            seed_asr_data=asr_data,
            seed_metadata=metadata,
            used_owasp_ids=used_owasp_ids,
            weights=weights,
            asr_window=asr_window,
        )
        scored.append((score, seed_hash, info))

    if not scored:
        return None, "", ""

    # 按 MTOS 降序, 取 Top-1
    scored.sort(key=lambda x: x[0], reverse=True)
    best_score, best_hash, best_info = scored[0]

    # 提取 objective 文本
    obj_text = best_info.get("seed_preview", "")[:200]
    if not obj_text or len(obj_text) < 10:
        return None, "", ""

    # 提取 owasp_id
    metadata = seed_meta_map.get(best_hash, {})
    owasp_id = str(metadata.get("owasp_id", "")) if isinstance(metadata, dict) else ""

    return obj_text, best_hash, owasp_id


def _select_cold_start(
    *,
    datasets: list[str] | None = None,
    crescendo_asr_window: tuple[float, float] = (0.0, 0.15),
    tap_asr_window: tuple[float, float] = (0.10, 0.30),
) -> tuple[str | None, str | None, dict[str, Any]]:
    """冷启动选种: 无历史 ASR 时基于种子元数据选种.

    策略:
      1. 从 CentralMemory 遍历所有已加载种子
      2. 过滤: difficulty ∈ {medium, hard} AND severity ∈ {critical, high}
      3. 评分: Difficulty(0.4) + Severity(0.35) + Category_diversity(0.25)
      4. Crescendo ← Top-1 (偏好 hard); TAP ← Top-2 (不同 OWASP, 偏好 medium)
    """
    meta: dict[str, Any] = {
        "strategy": "cold_start",
        "crescendo_seed_hash": "",
        "tap_seed_hash": "",
        "crescendo_asr": None,
        "tap_asr": None,
        "crescendo_owasp_id": "",
        "tap_owasp_id": "",
    }

    try:
        memory = CentralMemory.get_memory_instance()
    except Exception as e:
        logger.debug(f"Cold start: failed to get CentralMemory: {e}")
        return None, None, meta

    # 收集所有种子 + 元数据
    candidates: list[dict[str, Any]] = []
    ds_names = datasets or []
    if not ds_names:
        try:
            all_prompts = memory.get_seed_prompts()
            ds_names = list(
                {getattr(p, "dataset_name", "") for p in all_prompts if getattr(p, "dataset_name", "")}
            )
        except Exception:
            pass

    for ds_name in ds_names:
        try:
            prompts = memory.get_seed_prompts(dataset_name=ds_name)
            if not prompts:
                continue
            for p in prompts:
                value = (
                    getattr(p, "value", None)
                    or getattr(p, "original_value", None)
                    or ""
                )
                if not value or len(value) < 10:
                    continue
                metadata = getattr(p, "metadata", None)
                if not isinstance(metadata, dict):
                    metadata = {}
                difficulty = str(metadata.get("difficulty", "")).lower()
                severity = str(metadata.get("severity", "")).lower()
                # 过滤: 仅选 medium/hard + critical/high
                if difficulty not in ("medium", "hard"):
                    continue
                if severity not in ("critical", "high"):
                    continue
                candidates.append({
                    "value": value[:200],
                    "metadata": metadata,
                    "difficulty": difficulty,
                    "severity": severity,
                    "owasp_id": str(metadata.get("owasp_id", "")),
                    "dataset_name": ds_name,
                })
        except Exception:
            continue

    if not candidates:
        # 最终 fallback: 取首个数据集首个种子 (与旧逻辑兼容)
        return _cold_start_fallback(datasets, meta)

    # 评分: Difficulty(0.4) + Severity(0.35) + Category_diversity(0.25)
    used_owasp: set[str] = set()

    def _cold_score(c: dict[str, Any], *, prefer_difficulty: str = "hard") -> float:
        diff_score = 1.0 if c["difficulty"] == prefer_difficulty else 0.7
        sev_score = 1.0 if c["severity"] == "critical" else 0.7
        cat_score = 1.0 if (c["owasp_id"] and c["owasp_id"] not in used_owasp) else 0.0
        return 0.4 * diff_score + 0.35 * sev_score + 0.25 * cat_score

    # Crescendo: 偏好 hard
    candidates.sort(key=lambda c: _cold_score(c, prefer_difficulty="hard"), reverse=True)
    cres_candidate = candidates[0]
    cres_obj = cres_candidate["value"]
    cres_owasp = cres_candidate["owasp_id"]
    used_owasp.add(cres_owasp)
    meta["crescendo_owasp_id"] = cres_owasp

    # TAP: 偏好 medium, 不同 OWASP 类别
    tap_candidates = [c for c in candidates[1:] if c["owasp_id"] not in used_owasp]
    if not tap_candidates:
        tap_candidates = candidates[1:] if len(candidates) > 1 else []

    tap_obj = None
    tap_owasp = ""
    if tap_candidates:
        tap_candidates.sort(key=lambda c: _cold_score(c, prefer_difficulty="medium"), reverse=True)
        tap_candidate = tap_candidates[0]
        tap_obj = tap_candidate["value"]
        tap_owasp = tap_candidate["owasp_id"]
        meta["tap_owasp_id"] = tap_owasp

    return cres_obj, tap_obj, meta


def _cold_start_fallback(
    datasets: list[str] | None,
    meta: dict[str, Any],
) -> tuple[str | None, str | None, dict[str, Any]]:
    """最终冷启动 fallback: 从 CentralMemory 取首个种子 (兼容旧逻辑)."""
    try:
        memory = CentralMemory.get_memory_instance()
        for ds_name in (datasets or [])[:3]:
            prompts = memory.get_seed_prompts(dataset_name=ds_name)
            if prompts:
                p = prompts[0]
                obj = (
                    getattr(p, "value", None)
                    or getattr(p, "original_value", None)
                    or ""
                )[:200]
                if obj and len(obj) > 10:
                    metadata = getattr(p, "metadata", None)
                    if isinstance(metadata, dict):
                        meta["crescendo_owasp_id"] = str(metadata.get("owasp_id", ""))
                    # TAP: 取第 2 个种子
                    tap_obj = None
                    if len(prompts) >= 2:
                        p2 = prompts[1]
                        tap_obj = (
                            getattr(p2, "value", None)
                            or getattr(p2, "original_value", None)
                            or ""
                        )[:200]
                        if not tap_obj or len(tap_obj) <= 10 or tap_obj == obj:
                            tap_obj = None
                    return obj, tap_obj, meta
    except Exception as e:
        logger.debug(f"Cold start fallback failed: {e}")

    return None, None, meta
