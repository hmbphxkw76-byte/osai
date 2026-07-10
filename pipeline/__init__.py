"""
RedTeam_AI Pipeline — 模块化管道编排引擎

子模块:
  models    — 数据模型 & 常量 (PipelineStage, PipelineState, ...)
  guidance  — 阶段专家指导 (Expert Guidance)
  engine    — 全流程管道编排器 (RedTeamPipeline)
  cli       — CLI 入口 (main)

向后兼容: 所有公开符号可通过 `from pipeline import ...` 访问。
"""
from pipeline.models import (
    GARAK_PROBES_INFO,
    STAGE_LABELS,
    STAGE_ORDER,
    PipelineStage,
    PipelineState,
    console,
)
from pipeline.guidance import print_expert_guidance
from pipeline.engine import RedTeamPipeline
from pipeline.cli import main

__all__ = [
    "PipelineStage",
    "PipelineState",
    "STAGE_ORDER",
    "STAGE_LABELS",
    "GARAK_PROBES_INFO",
    "print_expert_guidance",
    "RedTeamPipeline",
    "main",
    "console",
]
