# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""流水线六阶段子包。.

每个阶段是独立模块，通过 ``PipelineContext`` 传递状态。
修改某个阶段不影响其他阶段。

七阶段流程:
  1. stage_init          — 原生初始化 + GCG/Fuzzer 种子生成 + 多模态检测
  2. stage_target_classify — 目标侦察 + 认证桥接 (PTES Recon → Auth Bridge)
  3. stage_scenario     — 场景配置 (多场景 + ASR 驱动数据集 + 评分器)
  4. stage_initialize  — 场景初始化 (构建 AtomicAttack)
  5. stage_execute      — 场景执行 (AttackExecutor 并发 + 断点续跑)
  6. stage_post_analysis — 执行后离线分析
  7. stage_output       — 结果输出 (三级输出 + HTML/PDF 报告)

Usage:
    from pipeline.stages import stage_init, stage_scenario, stage_initialize
    from pipeline.stages import stage_execute, stage_post_analysis, stage_output

    await stage_init.run(ctx)
    await stage_scenario.run(ctx)
    await stage_initialize.run(ctx)
    await stage_execute.run(ctx)
    await stage_post_analysis.run(ctx)
    await stage_output.run(ctx)
"""

from pipeline.stages.stage_execute import run as stage_execute_run
from pipeline.stages.stage_init import run as stage_init_run
from pipeline.stages.stage_initialize import run as stage_initialize_run
from pipeline.stages.stage_output import run as stage_output_run
from pipeline.stages.stage_post_analysis import run as stage_post_analysis_run
from pipeline.stages.stage_scenario import run as stage_scenario_run

__all__ = [
    "stage_init_run",
    "stage_scenario_run",
    "stage_initialize_run",
    "stage_execute_run",
    "stage_post_analysis_run",
    "stage_output_run",
]
