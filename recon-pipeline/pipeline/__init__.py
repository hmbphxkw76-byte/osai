# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""recon-pipeline: 解耦的端到端侦察流水线。

阶段化目录 (pipeline/):
  stages/classify_stage.py - 目标分类 (LLM WebApp vs 模型平台, 认证/跨域/二次验证)
  stages/auth_stage.py     - 认证决策 (自动选策略)
  stages/recon_stage.py    - 端到端侦察编排 (agent/mcp/rag/embedding/llm...)
  stages/export_stage.py   - 标准报告导出 (json/pyrit/garak, 供下游消费)

引擎:
  runner.PipelineRunner - 串联阶段, 仅通过 PipelineContext 交换数据
  registry              - 阶段注册表 (解耦 runner 与具体阶段)
  models                - 阶段间解耦数据契约
  context_loader        - 从 .env + config/ 加载参数
"""

from __future__ import annotations

from pipeline.models import (
    AuthDecision,
    PipelineContext,
    PlatformVendor,
    StageResult,
    TargetClassification,
    TargetCategory,
)
from pipeline.registry import all_stages, get_stage, list_stages, register
from pipeline.runner import DEFAULT_STAGE_ORDER, PipelineResult, PipelineRunner
from pipeline.context_loader import load_context

__all__ = [
    "PipelineContext",
    "TargetClassification",
    "TargetCategory",
    "PlatformVendor",
    "AuthDecision",
    "StageResult",
    "PipelineRunner",
    "PipelineResult",
    "DEFAULT_STAGE_ORDER",
    "register",
    "get_stage",
    "list_stages",
    "all_stages",
    "load_context",
]
