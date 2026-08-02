# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""流水线展示工具 — 头部信息 + 尾部汇总。.

从 main.py 提取，保持编排层纯净。
"""

from __future__ import annotations

import os

from pipeline.context import PipelineContext


def print_pipeline_header(ctx: PipelineContext) -> None:
    """打印流水线头部信息 (目标模型 + 场景 + 日志路径)。.

    B2 修复: 对齐参考日志格式, 增加 URL/端点/开始时间/Verbose 字段。
    """
    output_mgr = ctx.output_manager
    print()
    print("=" * 70)
    print("  PyRIT 端到端全自动 AI 红队框架")
    print("=" * 70)

    # B2: 目标 URL 和端点
    target_url = os.getenv("TARGET_BASE_URL", os.getenv("OPENAI_CHAT_ENDPOINT", "N/A"))
    target_endpoint = os.getenv("TARGET_ENDPOINT", target_url)
    model_name = getattr(ctx.args, "model", None) or os.getenv("OPENAI_CHAT_MODEL", "N/A")
    scorer_endpoint = os.getenv("OBJECTIVE_SCORER_CHAT_ENDPOINT", os.getenv("AZURE_CONTENT_SAFETY_API_ENDPOINT", "N/A"))
    scorer_model = os.getenv(
        "OBJECTIVE_SCORER_CHAT_MODEL",
        os.getenv("AZURE_CONTENT_SAFETY_API_ENDPOINT", "N/A"),
    )

    print(f"  目标 URL: {target_url}")
    print(f"  目标端点: {target_endpoint}")
    print(f"  目标模型: {model_name}")
    if scorer_endpoint != "N/A":
        print(f"  评分器端点: {scorer_endpoint}")
    print(f"  评分器模型: {scorer_model}")
    print(f"  开始时间: {ctx.start_time.isoformat() if ctx.start_time else 'N/A'}")
    if output_mgr:
        print(f"  日志文件: {output_mgr.log_path}")
        print(f"  噪音日志: {output_mgr.noise_log_path}")
    verbose = getattr(ctx.args, "verbose", False)
    print(f"  Verbose: {'开启 (成功攻击详情输出)' if verbose else '关闭'}")
    print(f"  场景: {getattr(ctx.args, 'scenario', 'text_adaptive')}")
    if getattr(ctx.args, "exhaustive", False):
        print("  模式: EXHAUSTIVE (全技术评估)")
    print()


def print_pipeline_footer(ctx: PipelineContext) -> None:
    """Print pipeline footer summary.

    B2 修复: 对齐参考日志格式, 增加总用时/报告路径/证据路径字段。
    """
    print("\n" + "=" * 70)
    print("  Pipeline 完成")
    print("=" * 70)

    # B2: 总用时
    if ctx.start_time and ctx.end_time:
        duration = ctx.end_time - ctx.start_time
        print(f"  总用时: {duration}")
    elif ctx.start_time:
        from datetime import datetime as _dt
        duration = _dt.now() - ctx.start_time
        print(f"  总用时: {duration}")

    if ctx.result:
        total = sum(len(v) for v in ctx.result.attack_results.values())
        success = sum(
            1
            for v in ctx.result.attack_results.values()
            for ar in v
            if ar.outcome and ar.outcome.name == "SUCCESS"
        )
        print(f"  执行结果: {success}/{total} 成功")

    # F2 修复: 数据源和攻击计划 (对齐参考日志格式)
    if ctx.sorted_datasets:
        print(f"  数据源: {len(ctx.sorted_datasets)} 批次")
    if ctx.scenario and hasattr(ctx.scenario, "atomic_attack_count"):
        print(f"  攻击计划: {ctx.scenario.atomic_attack_count} 个")

    if ctx.overall_asr is not None:
        print(f"  总体 ASR: {ctx.overall_asr}%")

    # B2: 报告和证据路径
    l5_report = ctx.metadata.get("l5_report", {})
    if l5_report:
        if l5_report.get("report_path"):
            print(f"  报告: {l5_report['report_path']}")
        if l5_report.get("evidence_archive"):
            print(f"  证据: {l5_report['evidence_archive']}")
    elif ctx.output_manager:
        report_p = ctx.output_manager.report_path("md")
        evidence_p = ctx.output_manager.evidence_zip_path
        if report_p.exists():
            print(f"  报告: {report_p}")
        if evidence_p.exists():
            print(f"  证据: {evidence_p}")

    if ctx.output_manager:
        print(f"  日志: {ctx.output_manager.log_path}")
        print(f"  噪音日志: {ctx.output_manager.noise_log_path}")
