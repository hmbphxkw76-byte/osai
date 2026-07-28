"""
PyRIT Pipeline — 8 阶段编排器
=============================

将旧版 1000+ 行的单函数 pipeline.py 拆分为独立的阶段模块。
每个阶段是 pipeline/stages/ 下的一个文件，接收 PipelineContext 并修改其字段。

架构:
  Pre   s0_init          初始化 PyRIT (静默)
  1/8   s1_recon          Recon 侦察层
  2/8   s2_analysis       Analysis 分析层
  3/8   s3_targets        Target 接入层
  4/8   s4_datasets       Datasets 数据载荷端
  5/8   s5_matching       Target/Converter 自适应匹配
  6/8   s6_execute        Executor 执行层
  7/8   s7_post_analysis  执行后分析
  8/8   s8_report         报告 + 总结

向后兼容: run_attack_pipeline() 保持原有签名，供 cli.py 调用。
"""

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from pipeline.context import PipelineContext
from pipeline.display import banner

# Fix Windows terminal Unicode encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


async def run_attack_pipeline(target_url: str, owasp_ids: list[str] | None = None):
    """
    执行完整的 8 阶段攻击流程。

    Args:
        target_url: 目标 URL
        owasp_ids: 指定 OWASP 分类列表，None 表示加载全部

    Returns:
        ReportResult 或 None（如果提前终止）
    """
    ctx = _init_context(target_url, owasp_ids)
    _print_header(ctx)

    # 安装噪音过滤器
    from src.core.pipeline_display import get_display, reset_display
    display = get_display(stage_total=8)
    display.install_noise_filter(ctx.log_path)

    try:
        # Pre-stage: 初始化
        from pipeline.stages import s0_init
        await s0_init.run(ctx)

        # Stage 1: Recon
        from pipeline.stages import s1_recon
        if not await s1_recon.run(ctx):
            return None

        # Stage 2: Analysis
        from pipeline.stages import s2_analysis
        await s2_analysis.run(ctx)

        # Stage 3: Targets
        from pipeline.stages import s3_targets
        await s3_targets.run(ctx)

        # Stage 4: Datasets
        from pipeline.stages import s4_datasets
        if not await s4_datasets.run(ctx):
            return None

        # Stage 5: Matching
        from pipeline.stages import s5_matching
        await s5_matching.run(ctx)

        # Stage 6: Execute
        from pipeline.stages import s6_execute
        if not await s6_execute.run(ctx):
            return None

        # Stage 7: Post-analysis
        from pipeline.stages import s7_post_analysis
        await s7_post_analysis.run(ctx)

        # Stage 8: Report
        from pipeline.stages import s8_report
        await s8_report.run(ctx)

        return ctx.report_result

    finally:
        # 卸载噪音过滤器
        try:
            reset_display()
        except Exception:
            pass


def _init_context(target_url: str, owasp_ids: list[str] | None) -> PipelineContext:
    """初始化 PipelineContext"""
    from src.core.config_loader import get_config_loader
    from src.core.logging_utils import setup_logging

    config_loader = get_config_loader()
    start_time = datetime.now()
    exam_id = f"exam_{start_time.strftime('%Y%m%d_%H%M%S')}"
    log_path = setup_logging(config_loader, start_time)

    target_endpoint = os.getenv("TARGET_ENDPOINT", f"{target_url.rstrip('/')}/v1")
    target_model = os.getenv("TARGET_MODEL", "qwen3:0.6b")
    target_api_key = os.getenv("TARGET_API_KEY", "ollama")
    judge_endpoint = os.getenv("JUDGE_ENDPOINT", target_endpoint)
    judge_model = os.getenv("JUDGE_MODEL", "qwen3:1.7b")
    judge_api_key = os.getenv("JUDGE_API_KEY", "ollama")

    return PipelineContext(
        config_loader=config_loader,
        start_time=start_time,
        exam_id=exam_id,
        log_path=log_path,
        verbose=config_loader.get_verbose_success(),
        owasp_ids=owasp_ids,
        target_url=target_url,
        target_endpoint=target_endpoint,
        target_model=target_model,
        target_api_key=target_api_key,
        judge_endpoint=judge_endpoint,
        judge_model=judge_model,
        judge_api_key=judge_api_key,
    )


def _print_header(ctx: PipelineContext) -> None:
    """打印 pipeline 头部信息"""
    banner("PyRIT 端到端全自动 AI 红队框架")
    print(f"\n目标 URL: {ctx.target_url}")
    print(f"目标端点: {ctx.target_endpoint}")
    print(f"目标模型: {ctx.target_model}")
    print(f"评分器端点: {ctx.judge_endpoint}")
    print(f"评分器模型: {ctx.judge_model}")
    print(f"开始时间: {ctx.start_time.isoformat()}")
    print(f"日志文件: {ctx.log_path}")
    print(f"Verbose: {'开启 (成功攻击详情输出)' if ctx.verbose else '关闭'}")


# ============================================================
# CLI 入口 (向后兼容 pipeline.py main())
# ============================================================


def main():
    """
    CLI 主入口

    Usage:
      python -m pipeline                              # 使用 .env 中的目标
      python -m pipeline http://192.168.0.22:11434    # 指定目标 URL
      python -m pipeline http://192.168.0.22:11434 LLM01,LLM06
    """
    project_root = Path(__file__).parent.parent
    env_path = project_root / ".env"
    load_dotenv(env_path)
    print(f"加载环境变量: {env_path}")

    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_endpoint = os.getenv("TARGET_ENDPOINT", "http://localhost:11434/v1")
        target_url = target_endpoint[:-3] if target_endpoint.endswith("/v1") else target_endpoint

    owasp_ids = None
    if len(sys.argv) > 2:
        owasp_ids = [x.strip().upper() for x in sys.argv[2].split(",") if x.strip()]
        print(f"CLI 指定 OWASP IDs: {owasp_ids}")

    asyncio.run(run_attack_pipeline(target_url, owasp_ids=owasp_ids))


if __name__ == "__main__":
    main()
