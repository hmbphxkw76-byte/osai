# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""三层渐进式选择向导 — 按 ASR Tier 分层推荐攻击技术。.

红队评估面临"技术太多、时间有限"的困境。本模块实现三层渐进式选择:

  Layer 1 (快速评估): Tier S/A 技术 (ASR >= 40%) — 少量高命中率攻击
  Layer 2 (标准评估): + Tier B 技术 (ASR >= 15%) — 覆盖中等有效性攻击
  Layer 3 (深度评估): + Tier C/D 技术 (ASR < 15%) — 全面覆盖所有攻击

每层推荐的技术数量、数据集大小、并发度不同:
  Layer 1: 3-5 个技术, 每数据集 5 个种子, 并发 5
  Layer 2: 8-12 个技术, 每数据集 10 个种子, 并发 5
  Layer 3: 全部技术, 每数据集 20 个种子, 并发 3

学术依据:
  - JailbreakBench (arXiv:2402.01135): Tier 分层标准
  - HarmBench (arXiv:2402.04249): ASR 加权采样防止执行爆炸
  - Russellinovich et al. (arXiv:2402.12109): 高 ASR 技术优先

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from pipeline.asr.prior_registry import get_initial_q_value, tier_from_asr

logger = logging.getLogger(__name__)


# ============================================================
# 层级配置
# ============================================================


@dataclass
class TierLayerConfig:
    """单个层级的配置。."""

    layer: int
    name: str
    description: str
    min_tier: str  # 最低包含的 Tier
    max_techniques: int
    max_dataset_size: int
    max_concurrency: int
    max_attempts: int
    include_baseline: bool

    @property
    def tier_filter(self) -> set[str]:
        """获取该层包含的所有 Tier。."""
        all_tiers = ["S", "A", "B", "C", "D", "UNKNOWN"]
        idx = all_tiers.index(self.min_tier)
        return set(all_tiers[: idx + 1])


# 三层默认配置
LAYER_CONFIGS: dict[int, TierLayerConfig] = {
    1: TierLayerConfig(
        layer=1,
        name="快速评估",
        description="Tier S/A 高 ASR 技术, 少量种子, 快速获取结果信号",
        min_tier="A",
        max_techniques=5,
        max_dataset_size=5,
        max_concurrency=5,
        max_attempts=2,
        include_baseline=True,
    ),
    2: TierLayerConfig(
        layer=2,
        name="标准评估",
        description="+ Tier B 中等 ASR 技术, 覆盖更多攻击向量",
        min_tier="B",
        max_techniques=12,
        max_dataset_size=10,
        max_concurrency=5,
        max_attempts=3,
        include_baseline=True,
    ),
    3: TierLayerConfig(
        layer=3,
        name="深度评估",
        description="+ Tier C/D 低 ASR 技术, 全面覆盖所有攻击向量",
        min_tier="D",
        max_techniques=99,
        max_dataset_size=20,
        max_concurrency=3,
        max_attempts=5,
        include_baseline=True,
    ),
}


# ============================================================
# 推荐结果
# ============================================================


@dataclass
class LayerRecommendation:
    """单个层级的推荐结果。."""

    layer: int
    config: TierLayerConfig
    recommended_techniques: list[str] = field(default_factory=list)
    technique_tiers: dict[str, str] = field(default_factory=dict)
    estimated_time_minutes: float = 0.0
    estimated_cost: str = "low"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "layer": self.layer,
            "name": self.config.name,
            "description": self.config.description,
            "recommended_techniques": self.recommended_techniques,
            "technique_tiers": self.technique_tiers,
            "max_techniques": self.config.max_techniques,
            "max_dataset_size": self.config.max_dataset_size,
            "max_concurrency": self.config.max_concurrency,
            "max_attempts": self.config.max_attempts,
            "include_baseline": self.config.include_baseline,
            "estimated_time_minutes": round(self.estimated_time_minutes, 1),
            "estimated_cost": self.estimated_cost,
        }


@dataclass
class TieredRecommendation:
    """三层渐进式推荐结果。."""

    model_name: str = ""
    model_tier: str = ""
    owasp_id: str = ""
    layers: list[LayerRecommendation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "model_name": self.model_name,
            "model_tier": self.model_tier,
            "owasp_id": self.owasp_id,
            "layers": [layer.to_dict() for layer in self.layers],
        }


# ============================================================
# TieredSelectionWizard
# ============================================================


class TieredSelectionWizard:
    """三层渐进式选择向导。.

    使用方式:
        wizard = TieredSelectionWizard(
            model_name="gpt-4o",
            model_tier="strong",
        )
        recommendation = wizard.recommend(
            available_techniques=["crescendo", "tap", "many_shot", ...],
            owasp_id="LLM01",
        )
        print(wizard.format_recommendation(recommendation))
    """

    # 单次攻击预估时间 (分钟)
    _TIME_PER_ATTACK = {
        "S": 0.5,  # 高 ASR 技术通常单轮
        "A": 1.0,  # 中等多轮
        "B": 1.5,  # 多轮或 LLM 辅助
        "C": 2.0,  # 低效多轮
        "D": 2.5,  # 极低效
        "UNKNOWN": 1.5,
    }

    def __init__(
        self,
        model_name: str = "gpt-4o",
        model_tier: str = "unknown",
    ) -> None:
        """Initialize TieredSelectionWizard."""
        self._model_name = model_name
        self._model_tier = model_tier

    def recommend(
        self,
        available_techniques: Sequence[str],
        owasp_id: str = "",
        datasets: Sequence[str] | None = None,
    ) -> TieredRecommendation:
        """生成三层渐进式推荐。.

        Args:
            available_techniques: 可用技术列表
            owasp_id: OWASP 分类 ID
            datasets: 数据集列表 (用于估算时间)

        Returns:
            TieredRecommendation: 三层推荐结果
        """
        # 计算每个技术的 ASR 和 Tier
        tech_asr_tier: dict[str, tuple[float, str]] = {}
        for tech in available_techniques:
            asr = get_initial_q_value(
                tech,
                model_name=self._model_name,
                model_tier=self._model_tier,
                owasp_id=owasp_id,
            )
            tier = tier_from_asr(asr)
            tech_asr_tier[tech] = (asr, tier)

        # 按 ASR 降序排列
        sorted_techs = sorted(
            tech_asr_tier.keys(),
            key=lambda t: tech_asr_tier[t][0],
            reverse=True,
        )

        recommendation = TieredRecommendation(
            model_name=self._model_name,
            model_tier=self._model_tier,
            owasp_id=owasp_id,
        )

        num_datasets = len(datasets) if datasets else 3

        for layer_num in [1, 2, 3]:
            config = LAYER_CONFIGS[layer_num]
            tier_filter = config.tier_filter

            # 筛选该层级的技术
            layer_techs = [t for t in sorted_techs if tech_asr_tier[t][1] in tier_filter]

            # 限制数量
            layer_techs = layer_techs[: config.max_techniques]

            # 添加 baseline
            if config.include_baseline and "prompt_sending" not in layer_techs:
                layer_techs.append("prompt_sending")

            # 估算时间
            est_time = self._estimate_time(
                layer_techs,
                tech_asr_tier,
                config.max_dataset_size,
                num_datasets,
            )

            # 估算成本
            cost = self._estimate_cost(layer_techs, tech_asr_tier)

            layer_rec = LayerRecommendation(
                layer=layer_num,
                config=config,
                recommended_techniques=layer_techs,
                technique_tiers={t: tech_asr_tier[t][1] for t in layer_techs},
                estimated_time_minutes=est_time,
                estimated_cost=cost,
            )
            recommendation.layers.append(layer_rec)

        logger.info(
            f"TieredSelectionWizard: {len(available_techniques)} techniques → "
            f"L1={len(recommendation.layers[0].recommended_techniques)}, "
            f"L2={len(recommendation.layers[1].recommended_techniques)}, "
            f"L3={len(recommendation.layers[2].recommended_techniques)}"
        )

        return recommendation

    def format_recommendation(self, rec: TieredRecommendation) -> str:
        """生成推荐报告文本。."""
        lines: list[str] = ["--- 三层渐进式选择向导 ---"]
        lines.append(f"  目标模型: {rec.model_name} (tier={rec.model_tier})")
        if rec.owasp_id:
            lines.append(f"  OWASP 分类: {rec.owasp_id}")

        for layer in rec.layers:
            lines.append(f"\n  Layer {layer.layer}: {layer.config.name}")
            lines.append(f"    {layer.config.description}")
            lines.append(f"    预估时间: {layer.estimated_time_minutes:.0f} 分钟")
            lines.append(f"    预估成本: {layer.estimated_cost}")
            lines.append(f"    最大技术数: {layer.config.max_techniques}")
            lines.append(f"    每数据集种子数: {layer.config.max_dataset_size}")
            lines.append(f"    并发数: {layer.config.max_concurrency}")
            lines.append(f"    每目标最大尝试: {layer.config.max_attempts}")
            lines.append(f"    推荐技术 ({len(layer.recommended_techniques)}):")
            for tech in layer.recommended_techniques:
                tier = layer.technique_tiers.get(tech, "?")
                lines.append(f"      [{tier}] {tech}")

        lines.append("\n  建议:")
        lines.append("    首次评估: 从 Layer 1 开始, 快速获取 ASR 基线")
        lines.append("    深度评估: 执行 Layer 2/3, 覆盖更多攻击向量")
        lines.append("    修复验证: 修复后重新执行 Layer 1 确认 ASR 下降")

        return "\n".join(lines)

    def get_layer_config(self, layer: int) -> TierLayerConfig:
        """获取指定层级的配置。."""
        return LAYER_CONFIGS.get(layer, LAYER_CONFIGS[2])

    def _estimate_time(
        self,
        techniques: list[str],
        tech_asr_tier: dict[str, tuple[float, str]],
        max_dataset_size: int,
        num_datasets: int,
    ) -> float:
        """估算执行时间 (分钟)。."""
        total_time = 0.0
        total_seeds = max_dataset_size * num_datasets

        for tech in techniques:
            tier = tech_asr_tier.get(tech, (0.0, "UNKNOWN"))[1]
            time_per = self._TIME_PER_ATTACK.get(tier, 1.5)
            total_time += total_seeds * time_per

        # 并发加速 (粗略估算)
        return total_time / 5.0  # 假设平均 5 并发

    def _estimate_cost(
        self,
        techniques: list[str],
        tech_asr_tier: dict[str, tuple[float, str]],
    ) -> str:
        """估算执行成本。."""
        llm_techs = sum(1 for t in techniques if tech_asr_tier.get(t, (0.0, "UNKNOWN"))[1] in ("S", "A"))
        total = len(techniques)
        if total == 0:
            return "minimal"
        ratio = llm_techs / total
        if ratio > 0.6:
            return "high"
        if ratio > 0.3:
            return "medium"
        return "low"
