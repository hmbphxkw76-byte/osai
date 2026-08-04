# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""多模型 ASR 对比矩阵 — 跨模型攻击成功率分析 (R-022: PyRIT 原生优先)。

本模块是 PyRIT 原生 ASR 数据的**分析层增强** (R-022):
  - 不修改原生 Scorer 或 Scenario 生命周期
  - 消费原生 ``outputs/empirical_asr/{model}.json`` 数据文件
  - 生成跨模型 per-technique ASR 对比矩阵
  - 识别模型特异性弱点 (高方差技术)

**对比矩阵能力**:
  1. 扫描 ``outputs/empirical_asr/`` 目录中所有模型 ASR 文件
  2. 构建 技术 × 模型 矩阵 (每个单元格 = ASR 0-1)
  3. 计算每个技术的跨模型统计 (均值/标准差/极差)
  4. 识别高方差技术 (模型特异性弱点)
  5. 识别低方差高 ASR 技术 (普遍弱点)
  6. 生成模型排名 (整体 ASR + 技术覆盖)

学术依据:
  - Universal and Transferable Attacks on Aligned Language Models:
    Zou et al. (arXiv:2307.15043) — 跨模型攻击迁移性
  - Model-Specific Vulnerabilities in LLMs: Andriushchenko et al. (arXiv:2404.13221)

> **日期**: 2026-8-5
"""

from __future__ import annotations

import json
import logging
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 经验 ASR 目录 (与 optimizer.py 保持一致)
_EMPIRICAL_ASR_DIR = Path("outputs/empirical_asr")


@dataclass
class ModelASRProfile:
    """单模型 ASR 档案。

    Attributes:
        model_name: 模型名称。
        technique_asr: 技术→ASR 映射。
        overall_asr: 整体 ASR (所有技术均值)。
        technique_count: 技术数量。
    """

    model_name: str = ""
    technique_asr: dict[str, float] = field(default_factory=dict)

    @property
    def overall_asr(self) -> float:
        """整体 ASR (所有技术均值)。"""
        if not self.technique_asr:
            return 0.0
        return statistics.mean(self.technique_asr.values())

    @property
    def technique_count(self) -> int:
        """技术数量。"""
        return len(self.technique_asr)


@dataclass
class TechniqueComparison:
    """单技术跨模型对比。

    Attributes:
        technique: 技术名称。
        model_asr: 模型→ASR 映射。
        mean_asr: 跨模型均值 ASR。
        stdev_asr: 跨模型标准差。
        max_asr: 最高 ASR。
        min_asr: 最低 ASR。
        range_asr: 极差 (max-min)。
        is_model_specific: 是否为模型特异性弱点 (高方差)。
        is_universal_weakness: 是否为普遍弱点 (低方差+高 ASR)。
    """

    technique: str = ""
    model_asr: dict[str, float] = field(default_factory=dict)

    @property
    def mean_asr(self) -> float:
        """跨模型均值 ASR。"""
        if not self.model_asr:
            return 0.0
        return statistics.mean(self.model_asr.values())

    @property
    def stdev_asr(self) -> float:
        """跨模型标准差。"""
        if len(self.model_asr) < 2:
            return 0.0
        return statistics.stdev(self.model_asr.values())

    @property
    def max_asr(self) -> float:
        """最高 ASR。"""
        return max(self.model_asr.values()) if self.model_asr else 0.0

    @property
    def min_asr(self) -> float:
        """最低 ASR。"""
        return min(self.model_asr.values()) if self.model_asr else 0.0

    @property
    def range_asr(self) -> float:
        """极差 (max-min)。"""
        return self.max_asr - self.min_asr

    @property
    def is_model_specific(self) -> bool:
        """是否为模型特异性弱点 (极差 > 0.3)。"""
        return self.range_asr > 0.3

    @property
    def is_universal_weakness(self) -> bool:
        """是否为普遍弱点 (均值 > 0.5 且极差 < 0.2)。"""
        return self.mean_asr > 0.5 and self.range_asr < 0.2


@dataclass
class TrendAnalysis:
    """单技术 ASR 趋势分析 (时间维度)。

    Attributes:
        technique: 技术名称。
        model_trends: 模型→(时间戳, ASR) 列表 映射。
        overall_trend: 整体趋势 (improving/stagnating/worsening)。
        trend_description: 趋势描述。
    """

    technique: str = ""
    model_trends: dict[str, list[tuple[str, float]]] = field(default_factory=dict)

    @property
    def overall_trend(self) -> str:
        """整体趋势判断。"""
        all_latest: list[float] = []
        all_earliest: list[float] = []

        for _model, snapshots in self.model_trends.items():
            if len(snapshots) >= 2:
                all_earliest.append(snapshots[0][1])
                all_latest.append(snapshots[-1][1])

        if not all_latest:
            return "insufficient_data"

        avg_earliest = statistics.mean(all_earliest) if all_earliest else 0.0
        avg_latest = statistics.mean(all_latest)

        delta = avg_latest - avg_earliest
        if delta > 0.05:
            return "worsening"  # ASR 上升 = 防御恶化
        elif delta < -0.05:
            return "improving"  # ASR 下降 = 防御改善
        else:
            return "stagnating"

    @property
    def trend_description(self) -> str:
        """趋势描述文本。"""
        trend = self.overall_trend
        _descriptions = {
            "worsening": "ASR 上升趋势 — 防御可能恶化 (新攻击技术有效或模型更新引入漏洞)",
            "improving": "ASR 下降趋势 — 防御可能改善 (安全补丁或模型对齐增强)",
            "stagnating": "ASR 保持稳定 — 防御水平无显著变化",
        }
        return _descriptions.get(trend, "数据不足, 无法判断趋势")


class MultiModelASRMatrix:
    """多模型 ASR 对比矩阵 — 跨模型攻击成功率分析。

    本类是 PyRIT 原生 ASR 数据的**分析层增强** (R-022)。

    用法::

        matrix = MultiModelASRMatrix()
        matrix.load_all_models()
        comparison = matrix.compare_technique("jailbreak")
        ranking = matrix.rank_models()
        report = matrix.generate_report()
    """

    # 模型特异性阈值
    MODEL_SPECIFIC_RANGE_THRESHOLD = 0.3
    UNIVERSAL_WEAKNESS_MEAN_THRESHOLD = 0.5
    UNIVERSAL_WEAKNESS_RANGE_THRESHOLD = 0.2

    def __init__(self, asr_dir: Path | None = None) -> None:
        """初始化多模型 ASR 对比矩阵。

        Args:
            asr_dir: 经验 ASR 目录, 默认 ``outputs/empirical_asr/``。
        """
        self._asr_dir = asr_dir or _EMPIRICAL_ASR_DIR
        self._models: dict[str, ModelASRProfile] = {}
        self._all_techniques: set[str] = set()

    @property
    def model_count(self) -> int:
        """已加载模型数。"""
        return len(self._models)

    @property
    def technique_count(self) -> int:
        """技术总数。"""
        return len(self._all_techniques)

    @property
    def model_names(self) -> list[str]:
        """已加载模型名列表。"""
        return list(self._models.keys())

    def load_model(self, model_name: str) -> bool:
        """加载单个模型的 ASR 数据。

        Args:
            model_name: 模型名称。

        Returns:
            是否成功加载。
        """
        safe_name = model_name.replace("/", "_").replace("\\", "_").replace(":", "_")
        path = self._asr_dir / f"{safe_name}.json"

        if not path.exists():
            logger.warning(f"ASR file not found for model {model_name}: {path}")
            return False

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            techniques = data.get("techniques", {})
            if not techniques:
                logger.warning(f"No techniques in ASR file for model {model_name}")
                return False

            profile = ModelASRProfile(
                model_name=model_name,
                technique_asr=techniques,
            )
            self._models[model_name] = profile
            self._all_techniques.update(techniques.keys())
            logger.info(
                f"Loaded ASR for model {model_name}: {len(techniques)} techniques, "
                f"overall ASR={profile.overall_asr:.2%}"
            )
            return True
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load ASR for model {model_name}: {e}")
            return False

    def load_all_models(self) -> int:
        """扫描 ASR 目录并加载所有模型的 ASR 数据。

        Returns:
            成功加载的模型数。
        """
        if not self._asr_dir.exists():
            logger.warning(f"ASR directory not found: {self._asr_dir}")
            return 0

        count = 0
        for json_file in self._asr_dir.glob("*.json"):
            # 跳过非模型文件 (如 benchmark_result.json, seed_level_*.json)
            name = json_file.stem
            if name in ("benchmark_result", "asr_priors") or name.startswith("seed_level_"):
                continue
            if self.load_model(name):
                count += 1

        logger.info(f"Loaded {count} models from {self._asr_dir}")
        return count

    def get_matrix(self) -> dict[str, dict[str, float]]:
        """获取完整对比矩阵。

        Returns:
            {技术: {模型: ASR}} 矩阵。
        """
        matrix: dict[str, dict[str, float]] = {}
        for tech in sorted(self._all_techniques):
            matrix[tech] = {}
            for model_name, profile in self._models.items():
                matrix[tech][model_name] = profile.technique_asr.get(tech, 0.0)
        return matrix

    def compare_technique(self, technique: str) -> TechniqueComparison | None:
        """对比指定技术的跨模型 ASR。

        Args:
            technique: 技术名称。

        Returns:
            TechniqueComparison 对比结果, 若无数据返回 None。
        """
        if technique not in self._all_techniques:
            return None

        model_asr: dict[str, float] = {}
        for model_name, profile in self._models.items():
            asr = profile.technique_asr.get(technique)
            if asr is not None:
                model_asr[model_name] = asr

        return TechniqueComparison(technique=technique, model_asr=model_asr)

    def compare_all_techniques(self) -> list[TechniqueComparison]:
        """对比所有技术的跨模型 ASR。

        Returns:
            TechniqueComparison 列表 (按均值 ASR 降序)。
        """
        comparisons: list[TechniqueComparison] = []
        for tech in sorted(self._all_techniques):
            comp = self.compare_technique(tech)
            if comp:
                comparisons.append(comp)

        comparisons.sort(key=lambda c: c.mean_asr, reverse=True)
        return comparisons

    def rank_models(self) -> list[tuple[str, float, int]]:
        """按整体 ASR 排名模型。

        Returns:
            (模型名, 整体 ASR, 技术数) 列表 (按 ASR 降序)。
        """
        ranking = [
            (name, profile.overall_asr, profile.technique_count)
            for name, profile in self._models.items()
        ]
        ranking.sort(key=lambda x: x[1], reverse=True)
        return ranking

    def get_model_specific_techniques(self) -> list[TechniqueComparison]:
        """获取模型特异性弱点 (高方差技术)。

        Returns:
            TechniqueComparison 列表 (按极差降序)。
        """
        all_comps = self.compare_all_techniques()
        specific = [
            c for c in all_comps
            if c.range_asr > self.MODEL_SPECIFIC_RANGE_THRESHOLD
        ]
        specific.sort(key=lambda c: c.range_asr, reverse=True)
        return specific

    def get_universal_weaknesses(self) -> list[TechniqueComparison]:
        """获取普遍弱点 (低方差+高 ASR)。

        Returns:
            TechniqueComparison 列表 (按均值 ASR 降序)。
        """
        all_comps = self.compare_all_techniques()
        universal = [
            c for c in all_comps
            if c.mean_asr > self.UNIVERSAL_WEAKNESS_MEAN_THRESHOLD
            and c.range_asr < self.UNIVERSAL_WEAKNESS_RANGE_THRESHOLD
        ]
        universal.sort(key=lambda c: c.mean_asr, reverse=True)
        return universal

    def load_model_history(self, model_name: str) -> list[tuple[str, dict[str, float]]]:
        """加载模型的历史 ASR 快照 (时间维度)。

        扫描 ``outputs/empirical_asr/history/`` 目录中该模型的时间戳快照文件。

        Args:
            model_name: 模型名称。

        Returns:
            (时间戳, 技术→ASR 映射) 列表, 按时间戳升序。
        """
        safe_name = model_name.replace("/", "_").replace("\\", "_").replace(":", "_")
        history_dir = self._asr_dir / "history"

        if not history_dir.exists():
            return []

        snapshots: list[tuple[str, dict[str, float]]] = []
        for hist_file in history_dir.glob(f"{safe_name}_*.json"):
            # 文件名格式: {model}_{YYYYMMDD_HHMMSS}.json
            timestamp = hist_file.stem.replace(f"{safe_name}_", "")
            try:
                with open(hist_file, encoding="utf-8") as f:
                    data = json.load(f)
                techniques = data.get("techniques", {})
                if techniques:
                    snapshots.append((timestamp, techniques))
            except (json.JSONDecodeError, OSError):
                continue

        snapshots.sort(key=lambda x: x[0])
        return snapshots

    def save_asr_snapshot(self, model_name: str, techniques: dict[str, float]) -> None:
        """保存当前 ASR 快照到历史目录 (时间维度追踪)。

        这是**数据层增强** (R-022): 仅保存数据文件, 不修改原生组件。

        Args:
            model_name: 模型名称。
            techniques: 技术→ASR 映射。
        """
        from datetime import datetime

        safe_name = model_name.replace("/", "_").replace("\\", "_").replace(":", "_")
        history_dir = self._asr_dir / "history"
        history_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_path = history_dir / f"{safe_name}_{timestamp}.json"

        try:
            with open(snapshot_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "model": model_name,
                        "timestamp": timestamp,
                        "techniques": techniques,
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                )
            logger.info(f"Saved ASR snapshot for {model_name}: {snapshot_path}")
        except OSError as e:
            logger.warning(f"Failed to save ASR snapshot: {e}")

    def get_trend_analysis(self, technique: str) -> TrendAnalysis:
        """获取指定技术的 ASR 趋势分析 (时间维度)。

        Args:
            technique: 技术名称。

        Returns:
            TrendAnalysis 趋势分析结果。
        """
        trend = TrendAnalysis(technique=technique)

        for model_name in self._models:
            history = self.load_model_history(model_name)
            if not history:
                # 无历史数据, 使用当前数据作为唯一点
                current_asr = self._models[model_name].technique_asr.get(technique)
                if current_asr is not None:
                    trend.model_trends[model_name] = [("current", current_asr)]
            else:
                snapshots: list[tuple[str, float]] = []
                for timestamp, techniques in history:
                    asr = techniques.get(technique)
                    if asr is not None:
                        snapshots.append((timestamp, asr))
                # 添加当前数据
                current_asr = self._models[model_name].technique_asr.get(technique)
                if current_asr is not None:
                    snapshots.append(("current", current_asr))

                if snapshots:
                    trend.model_trends[model_name] = snapshots

        return trend

    def get_all_trends(self) -> list[TrendAnalysis]:
        """获取所有技术的 ASR 趋势分析。

        Returns:
            TrendAnalysis 列表 (按趋势变化幅度降序)。
        """
        trends: list[TrendAnalysis] = []
        for tech in sorted(self._all_techniques):
            trend = self.get_trend_analysis(tech)
            if trend.model_trends:
                trends.append(trend)

        # 按趋势严重程度排序: worsening > improving > stagnating > insufficient
        priority = {"worsening": 0, "improving": 1, "stagnating": 2, "insufficient_data": 3}
        trends.sort(key=lambda t: priority.get(t.overall_trend, 4))
        return trends

    def generate_report(self) -> dict[str, Any]:
        """生成完整对比报告 (存入 ctx.metadata)。

        Returns:
            报告字典。
        """
        matrix = self.get_matrix()
        comparisons = self.compare_all_techniques()
        ranking = self.rank_models()
        model_specific = self.get_model_specific_techniques()
        universal = self.get_universal_weaknesses()

        return {
            "model_count": self.model_count,
            "technique_count": self.technique_count,
            "model_names": self.model_names,
            "model_ranking": [
                {"model": name, "overall_asr": round(asr, 4), "technique_count": count}
                for name, asr, count in ranking
            ],
            "matrix": {
                tech: {model: round(asr, 4) for model, asr in models.items()}
                for tech, models in matrix.items()
            },
            "technique_stats": [
                {
                    "technique": c.technique,
                    "mean_asr": round(c.mean_asr, 4),
                    "stdev_asr": round(c.stdev_asr, 4),
                    "max_asr": round(c.max_asr, 4),
                    "min_asr": round(c.min_asr, 4),
                    "range_asr": round(c.range_asr, 4),
                    "is_model_specific": c.is_model_specific,
                    "is_universal_weakness": c.is_universal_weakness,
                }
                for c in comparisons
            ],
            "model_specific_weaknesses": [
                {
                    "technique": c.technique,
                    "range": round(c.range_asr, 4),
                    "best_model": max(c.model_asr, key=c.model_asr.get),
                    "best_asr": round(c.max_asr, 4),
                    "worst_model": min(c.model_asr, key=c.model_asr.get),
                    "worst_asr": round(c.min_asr, 4),
                }
                for c in model_specific
            ],
            "universal_weaknesses": [
                {
                    "technique": c.technique,
                    "mean_asr": round(c.mean_asr, 4),
                    "range": round(c.range_asr, 4),
                }
                for c in universal
            ],
            "trend_analysis": [
                {
                    "technique": t.technique,
                    "overall_trend": t.overall_trend,
                    "description": t.trend_description,
                    "model_count": len(t.model_trends),
                    "models_with_history": [
                        m for m, snaps in t.model_trends.items() if len(snaps) >= 2
                    ],
                }
                for t in self.get_all_trends()
                if t.overall_trend != "insufficient_data"
            ],
        }

    def print_summary(self) -> None:
        """打印对比矩阵摘要到终端。"""
        if self.model_count == 0:
            print("  [多模型对比] 无可用 ASR 数据")
            return

        print(f"\n  ┌─ 多模型 ASR 对比矩阵 ({self.model_count} 模型 × {self.technique_count} 技术) ─┐")

        # 模型排名
        ranking = self.rank_models()
        print("  │ 模型排名:")
        for i, (name, asr, count) in enumerate(ranking, 1):
            print(f"  │   {i}. {name[:30]:<30} ASR={asr:.1%} ({count} 技术)")

        # 模型特异性弱点
        specific = self.get_model_specific_techniques()
        if specific:
            print("  │ 模型特异性弱点 (高方差):")
            for c in specific[:5]:
                best = max(c.model_asr, key=c.model_asr.get)
                worst = min(c.model_asr, key=c.model_asr.get)
                print(
                    f"  │   {c.technique[:25]:<25} 极差={c.range_asr:.1%} "
                    f"({best[:15]}={c.max_asr:.0%} vs {worst[:15]}={c.min_asr:.0%})"
                )

        # 普遍弱点
        universal = self.get_universal_weaknesses()
        if universal:
            print("  │ 普遍弱点 (高 ASR + 低方差):")
            for c in universal[:5]:
                print(f"  │   {c.technique[:25]:<25} 均值={c.mean_asr:.1%} 极差={c.range_asr:.1%}")

        # 时间维度趋势
        trends = [t for t in self.get_all_trends() if t.overall_trend != "insufficient_data"]
        if trends:
            print("  │ ASR 趋势 (时间维度):")
            for t in trends[:5]:
                symbol = {"worsening": "↑", "improving": "↓", "stagnating": "→"}.get(t.overall_trend, "?")
                models_with_hist = len([m for m, snaps in t.model_trends.items() if len(snaps) >= 2])
                print(f"  │   {symbol} {t.technique[:23]:<23} {t.overall_trend:<12} ({models_with_hist} 模型有历史)")

        print("  └───────────────────────────────────────────────────────────┘")
