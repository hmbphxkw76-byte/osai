# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Pipeline 状态容器。.

``PipelineContext`` 是贯穿六个阶段的唯一状态载体。
每个阶段读取上一阶段的产出、写入自己的产出，阶段间不直接耦合。

设计原则:
  - 阶段间通信仅通过 Context 字段，不通过返回值或全局变量
  - 每个字段标注所属阶段 (Stage N 产出)，便于追踪数据流
  - 新增阶段只需新增字段，不影响已有阶段

数据 5 层架构 (L1→L5) 贯穿 Stage 1→3:
  L1: Seed Source       — Stage 1 (远程数据集/本地.prompt/GCG/Fuzzer 生成)
  L2: Seed Organization  — Stage 1→2 (AttackSeedGroup 构造)
  L3: Dataset Config     — Stage 2 (CompoundDatasetAttackConfiguration)
  L4: Memory Persistence — Stage 1→6 (CentralMemory SQLite)
  L5: Analytics & Select — Stage 2→4 (EpsilonGreedy + ASR 驱动选择)

Executor 5 层架构 (L1→L5) 贯穿 Stage 2→4:
  L1: Attack Parameters   — Stage 2 (set_params_from_args)
  L2: Attack Strategy     — Stage 2 (AttackStrategy + Converter 变体)
  L3: Attack Config       — Stage 2 (AttackConverterConfig + AttackScoringConfig)
  L4: Compound Attack     — Stage 3 (SequentialAttack FIRST_SUCCESS/EXHAUSTIVE)
  L5: Scenario           — Stage 2→4 (TextAdaptive / AIRT / Garak / Benchmark / Foundry)

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 22:00 — P2-5: 修复 docstring "五个阶段" → "六个阶段" (架构对齐 v7.0)
>   2026-8-1 20:00 — v6.0: 集成 ASRRankBuilder/GroupFallbackExecutor/target_aware_router 字段
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyrit.models import ScenarioResult
    from pyrit.scenario.core.scenario import Scenario
    from pyrit.score import Scorer

    from pipeline.reporting.output_manager import OutputManager


@dataclass
class PipelineContext:
    """贯穿流水线五个阶段的状态容器。.

    每个阶段读取所需字段、写入自己的产出字段。
    字段按产出阶段标注，未初始化时为 None。

    Attributes:
        args: 命令行参数 (Config 阶段产出).
        config: ConfigurationLoader 实例 (Stage 1 产出).

        Stage 1 产出 — 数据 L1 (Seed Source) + L4 (Memory):
        scenario_name: 场景类型名称 (text_adaptive / airt_* / garak_* 等).
        gcg_seeds_count: GCG 生成的种子组数 (0 = 未启用).
        fuzzer_seeds_count: Fuzzer 变异的种子组数 (0 = 未启用).
        is_multimodal: 目标是否支持多模态输入.
        multimodal_converters: 推荐的多模态 Converter 预设列表.
        rate_limited: 是否已包装 RateLimitedTarget.
        http_target_configured: 是否已配置 HTTP Target.

        Stage 2 产出 — Executor L1 (Parameters) + L2 (Strategy) + L3 (Config) + L5 (Scenario):
        scenario: Scenario 场景实例 (TextAdaptive / AIRT / Garak 等).
        objective_scorer: 评分器实例.
        selector: FailureTypeRoutingSelector 实例 (供 Stage 4 运行时反馈).
        sorted_datasets: ASR 排序后的数据集列表.
        warm_start_asr: warm-start ASR 先验字典.
        max_attempts_per_objective: 每 objective 最大技术尝试数.
        converter_routing_count: Converter 路由分配总数.

        Stage 4 产出 — 执行结果:
        result: ScenarioResult 执行结果.
        asr_per_technique: 按技术分组的 ASR 统计.
        overall_asr: 总体 ASR 百分比.

        Stage 5 产出 — 报告:
        output_dir: 报告输出目录.

        metadata: 自由扩展字段，供未来阶段使用.
    """

    # Config 阶段产出
    args: Any = None

    # Stage 1 产出 — 数据 L1 (Seed Source) + L4 (Memory)
    config: Any = None
    scenario_name: str = "text_adaptive"
    gcg_seeds_count: int = 0
    fuzzer_seeds_count: int = 0
    is_multimodal: bool = False
    multimodal_converters: list[str] = field(default_factory=list)
    rate_limited: bool = False
    http_target_configured: bool = False

    # Stage 2 产出 — Executor L1-L3 + L5 (Scenario) + 数据 L3 (Dataset Config) + L5 (Analytics)
    scenario: Scenario | None = None
    objective_scorer: Scorer | None = None
    selector: Any = None  # FailureTypeRoutingSelector 实例 (供 Stage 4 运行时反馈)
    sorted_datasets: list[str] = field(default_factory=list)
    warm_start_asr: dict[str, float] = field(default_factory=dict)
    max_attempts_per_objective: int = 3
    converter_routing_count: int = 0
    target_type: str | None = None  # Stage 2 探测的目标类型
    ranked_groups: list = field(default_factory=list)  # ASRRankBuilder 排序结果
    fallback_plan: Any = None  # GroupFallbackExecutor 降级计划
    tier_layer: int = 0  # TieredSelectionWizard 层级 (0=未指定)
    plan_pid_map: dict[str, str] = field(default_factory=dict)  # P编号映射: dataset→"P1-P5"
    technique_converter_map: dict[str, list] = field(default_factory=dict)  # 技术→Converter链映射 (Stage 2→4 传递)

    # Stage 4 产出
    result: ScenarioResult | None = None
    asr_per_technique: dict[str, float] = field(default_factory=dict)
    overall_asr: int = 0

    # Stage 5 产出
    output_dir: Path | None = None

    # 贯穿全流水线
    output_manager: OutputManager | None = None

    # L5 对齐: 评估时间追踪 (main.py 设置 start_time, stage_output 设置 end_time)
    start_time: datetime | None = None
    end_time: datetime | None = None

    # 自由扩展
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── 便捷方法: 阶段间衔接摘要 ──

    def stage1_summary(self) -> str:
        """Stage 1 → Stage 2 衔接摘要 (数据 L1/L4 层)。."""
        lines = [
            "  → Stage 2 输入:",
            f"    数据 L1 (Seed Source): {self._seed_source_summary()}",
            f"    数据 L4 (Memory): {self.config.memory_db_type if self.config else 'N/A'}",
        ]
        if self.gcg_seeds_count > 0:
            lines.append(f"    GCG 种子: {self.gcg_seeds_count} 组")
        if self.fuzzer_seeds_count > 0:
            lines.append(f"    Fuzzer 种子: {self.fuzzer_seeds_count} 组")
        if self.is_multimodal:
            lines.append(f"    多模态: {len(self.multimodal_converters)} 个 Converter 预设")
        if self.rate_limited:
            lines.append("    限速包装: 已启用")
        if self.http_target_configured:
            lines.append("    HTTP Target: 已配置")
        return "\n".join(lines)

    def stage2_summary(self) -> str:
        """Stage 2 → Stage 3 衔接摘要 (Executor L1-L3 + L5 层)。."""
        lines = [
            "  → Stage 3 输入:",
            f"    Executor L1 (Parameters): {self.max_attempts_per_objective} max_attempts, "
            f"{self.args.max_concurrency if self.args else 5} concurrency",
            f"    Executor L2 (Strategy): {self.scenario_name}",
            f"    Executor L3 (Config): converter_routing={self.converter_routing_count}",
            f"    Executor L5 (Scenario): {type(self.scenario).__name__ if self.scenario else 'N/A'}",
            f"    数据 L3 (Dataset Config): {len(self.sorted_datasets)} 个数据集",
            f"    数据 L5 (Analytics): warm_start={len(self.warm_start_asr)} 个技术先验",
            f"    数据 L5 (Analytics): ranked_groups={len(self.ranked_groups)}, "
            f"fallback_plan={'yes' if self.fallback_plan else 'no'}",
        ]
        return "\n".join(lines)

    def _seed_source_summary(self) -> str:
        """数据 L1 (Seed Source) 摘要。."""
        sources = []
        if self.args and self.args.datasets:
            sources.append(f"{len(self.args.datasets)} 远程")
        if self.args and self.args.local_datasets:
            sources.append(f"{len(self.args.local_datasets)} 本地")
        if self.gcg_seeds_count > 0:
            sources.append(f"{self.gcg_seeds_count} GCG")
        if self.fuzzer_seeds_count > 0:
            sources.append(f"{self.fuzzer_seeds_count} Fuzzer")
        return " + ".join(sources) if sources else "(无)"
