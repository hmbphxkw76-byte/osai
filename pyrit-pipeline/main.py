"""PyRIT 原生端到端 AI Red Team 流水线 — 纯编排入口。

仅串联 pipeline/ 下六个阶段，自身不含任何业务逻辑。
修改某个阶段时，只需编辑 pipeline/stages/stage_*.py，不影响本文件。

六阶段流程 (含 R-008 临时文件清理):
  1. stage_init          — 原生初始化 + GCG/Fuzzer 种子生成 + 多模态检测
  2. stage_scenario      — ASR 驱动场景配置 (数据集排序 + 评分器 + Converter 路由)
  3. stage_initialize    — 场景初始化 (构建 AtomicAttack + ASR 智能调度)
  4. stage_execute       — 场景执行 (AttackExecutor 并发 + 失败类型反馈)
  5. stage_post_analysis — 执行后分析 (ASR 实测vs先验 + 经验写回)
  6. stage_output        — 结果输出 (证据收集 + HTML/PDF 报告)

架构文档: docs/asr_driven_e2e_architecture.md (v7.0)
开发规范: docs/development_guidelines.md (v2.0)

Usage:
  python main.py --datasets harmbench jbb_behaviors strong_reject --load-owasp-local
  python main.py --load-owasp-local --tier-layer 1
  python main.py --resume <scenario_result_id>
"""

import asyncio
import sys
from pathlib import Path

from pipeline import PipelineContext
from pipeline.config import parse_args, setup_environment
from pipeline.reporting.output_manager import OutputManager
from pipeline.stages.stage_execute import run as stage_execute
from pipeline.stages.stage_init import run as stage_init
from pipeline.stages.stage_initialize import run as stage_initialize
from pipeline.stages.stage_output import run as stage_output
from pipeline.stages.stage_post_analysis import run as stage_post_analysis
from pipeline.stages.stage_scenario import run as stage_scenario
from pipeline.utils.cleaner import clean_temp_files
from pipeline.utils.display import print_pipeline_footer, print_pipeline_header
from pipeline.utils.noise_redirector import redirect_noise_to_file


async def main_async() -> None:
    """串联六个阶段, 全流水线双日志包裹。"""
    setup_environment()
    ctx = PipelineContext(args=parse_args())
    ctx.output_manager = OutputManager(
        base_dir=getattr(ctx.args, "output_dir", None) or "outputs",
    )
    ctx.metadata["noise_log_path"] = str(ctx.output_manager.noise_log_path)
    ctx.metadata["signal_log_path"] = str(ctx.output_manager.log_path)

    print_pipeline_header(ctx)
    clean_temp_files("pre")

    # 全流水线双日志包裹: 信号行写入终端 + signal log, 噪音行写入 noise log
    # 内层 (stage_init/scenario) 的 redirect_noise_to_file 不传 signal_log_path,
    # 信号行透传到本层 NoiseFilter 统一写入信号日志, 避免重复
    with redirect_noise_to_file(
        Path(ctx.metadata["noise_log_path"]),
        Path(ctx.metadata["signal_log_path"]),
    ):
        await stage_init(ctx)

        # XPIA 工作流 (可选, 提前返回)
        if getattr(ctx.args, "xpia", False):
            print("\n" + "=" * 70)
            print("[XPIA] Cross-Domain Prompt Injection Attack 工作流")
            print("=" * 70)
            from pipeline.workflows.xpia import run_xpia
            await run_xpia(ctx)
            return

        await stage_scenario(ctx)
        await stage_initialize(ctx)
        await stage_execute(ctx)
        await stage_post_analysis(ctx)
        await stage_output(ctx)

    # P3: 持久化动态发现的内容过滤器标记 (供下次运行加载)
    _persist_discovered_content_filter_markers()

    clean_temp_files("post")
    print_pipeline_footer(ctx)


def _persist_discovered_content_filter_markers() -> None:
    """P3: 持久化运行时动态发现的内容过滤器标记。

    在 Stage 1 初始化时,content_filter_ext 的 heuristic 自动发现机制
    可能识别出未知 API 供应商的安全审查错误码。本函数在流水线结束后
   将这些标记写入 data/config/content_filter_discovered.json,
    供下次运行直接加载,避免重复 heuristic 检测。

    同时,P4: 由于内容过滤响应被正确识别为 blocked (非异常),
    场景级 max_retries 不会对确定性 blocked 响应触发重试,
    从根本上消除了重试浪费。
    """
    try:
        from pipeline.utils.content_filter_ext import persist_discovered_markers

        persist_discovered_markers()
    except Exception:
        pass  # 非关键路径,静默失败


if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(0)
