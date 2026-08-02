# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""PyRIT 原生端到端流水线 — 六阶段拆分 (ASR 驱动, Attack-King 策略)。.

每个阶段是独立模块，通过 ``PipelineContext`` 传递状态。
修改某个阶段不影响其他阶段。

六阶段流程:
  1. stage_init          — 原生初始化 + GCG/Fuzzer 种子生成 + 多模态检测
  2. stage_scenario      — ASR 驱动场景配置 (数据集排序 + 评分器 + Converter 路由)
  3. stage_initialize    — 场景初始化 (构建 AtomicAttack + ASR 智能调度)
  4. stage_execute       — 场景执行 (AttackExecutor 并发 + 失败类型反馈)
  5. stage_post_analysis — 执行后分析 (ASR 实测vs先验 + 经验写回)
  6. stage_output        — 结果输出 (证据收集 + HTML/PDF 报告)

Usage:
    from pipeline import PipelineContext
    from pipeline.config import parse_args
    from pipeline.stages.stage_init import run as stage_init
    from pipeline.stages.stage_scenario import run as stage_scenario
    from pipeline.stages.stage_initialize import run as stage_initialize
    from pipeline.stages.stage_execute import run as stage_execute
    from pipeline.stages.stage_post_analysis import run as stage_post_analysis
    from pipeline.stages.stage_output import run as stage_output

    ctx = PipelineContext(args=parse_args())
    await stage_init(ctx)
    await stage_scenario(ctx)
    await stage_initialize(ctx)
    await stage_execute(ctx)
    await stage_post_analysis(ctx)
    await stage_output(ctx)

架构文档: docs/asr_driven_e2e_architecture.md (v7.0)
开发规范: docs/development_guidelines.md (v2.0)
"""

from pipeline.context import PipelineContext

__all__ = ["PipelineContext"]
