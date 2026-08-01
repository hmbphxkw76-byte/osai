# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""流水线展示工具 — 头部信息 + 尾部汇总。

从 main.py 提取，保持编排层纯净。
"""

from __future__ import annotations

import os

from pipeline.context import PipelineContext


def print_pipeline_header(ctx: PipelineContext) -> None:
    """打印流水线头部信息 (目标模型 + 场景 + 日志路径)。"""
    output_mgr = ctx.output_manager
    print("=" * 70)
    print("  PyRIT 端到端全自动 AI 红队框架")
    print("=" * 70)
    model_name = getattr(ctx.args, "model", None) or os.getenv("OPENAI_CHAT_MODEL", "N/A")
    scorer_model = os.getenv(
        "OBJECTIVE_SCORER_CHAT_MODEL",
        os.getenv("AZURE_CONTENT_SAFETY_API_ENDPOINT", "N/A"),
    )
    print(f"  目标模型: {model_name}")
    print(f"  评分器模型: {scorer_model}")
    print(f"  场景: {getattr(ctx.args, 'scenario', 'text_adaptive')}")
    if getattr(ctx.args, "exhaustive", False):
        print("  模式: EXHAUSTIVE (全技术评估)")
    if output_mgr:
        print(f"  日志文件: {output_mgr.log_path}")
        print(f"  噪音日志: {output_mgr.noise_log_path}")
    print()


def print_pipeline_footer(ctx: PipelineContext) -> None:
    """打印流水线尾部汇总。"""
    print("\n" + "=" * 70)
    print("  Pipeline 完成 [6/6]")
    print("=" * 70)
    if ctx.result:
        total = sum(len(v) for v in ctx.result.attack_results.values())
        success = sum(
            1
            for v in ctx.result.attack_results.values()
            for ar in v
            if ar.outcome and ar.outcome.name == "SUCCESS"
        )
        print(f"  执行结果: {success}/{total} 成功")
    if ctx.overall_asr is not None:
        print(f"  总体 ASR: {ctx.overall_asr}%")
    if ctx.output_manager:
        print(f"  日志: {ctx.output_manager.log_path}")
        print(f"  噪音日志: {ctx.output_manager.noise_log_path}")
