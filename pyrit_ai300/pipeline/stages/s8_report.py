"""
Stage 8/8: 报告 + 总结
=====================

OWASP 映射 + 证据导出 + 汇总。
"""

from datetime import datetime

from pipeline.context import PipelineContext
from pipeline.display import banner, info_box, stage_header


async def run(ctx: PipelineContext) -> None:
    """执行报告生成阶段"""
    stage_header(8, "报告 + 总结", "OWASP 映射 + 证据导出 + 汇总")

    ctx.end_time = datetime.now()

    from src.reporting import generate_report
    ctx.report_result = await generate_report(
        scenario_result=ctx.batch_result.results,
        exam_id=ctx.exam_id,
        start_time=ctx.start_time,
        end_time=ctx.end_time,
    )

    report_lines = [
        f"报告路径: {ctx.report_result.report_path}",
        f"证据包:   {ctx.report_result.evidence_archive}",
        f"发现漏洞: {len(ctx.report_result.owasp_findings)} 个",
        f"攻击总数: {ctx.report_result.summary.total_attacks}",
        f"成功攻击: {ctx.report_result.summary.successful_attacks}",
        f"成功率:   {ctx.report_result.summary.success_rate * 100:.1f}%",
    ]
    if getattr(ctx.report_result, "report_html_path", None):
        report_lines.append(f"HTML 报告: {ctx.report_result.report_html_path}")
    if getattr(ctx.report_result, "report_pdf_path", None):
        report_lines.append(f"PDF 报告: {ctx.report_result.report_pdf_path}")
    info_box("报告生成", report_lines)

    # 总结
    banner("Pipeline 完成")
    print(f"总用时: {ctx.end_time - ctx.start_time}")
    print(f"数据源: {len(ctx.prompt_batches)} 批次, {ctx.total_prompts} 提示词")
    print(f"攻击计划: {ctx.batch_result.total_plans} 个")
    print(f"执行结果: {ctx.batch_result.succeeded}/{ctx.batch_result.executed} 成功")
    print(f"报告: {ctx.report_result.report_path}")
    print(f"证据: {ctx.report_result.evidence_archive}")
    print(f"日志: {ctx.log_path}")
