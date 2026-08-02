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

# R-012: 始终使用 UTF-8 编码 — 在所有 import 之前强制设置,
# 确保 stdout/stderr 在 Windows GBK 终端下也能正确输出 Unicode 字符
import os as _os
import logging
import sys

_logger = logging.getLogger(__name__)

_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import asyncio
import signal
from datetime import datetime
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
from pipeline.stages.stage_web_auth import run as stage_web_auth
from pipeline.utils.cleaner import clean_temp_files
from pipeline.utils.display import print_pipeline_footer, print_pipeline_header
from pipeline.utils.noise_redirector import redirect_noise_to_file

# P3-2: 全局优雅退出标志
_shutdown_requested = False


def _signal_handler(signum, frame):
    """P3-2: 信号处理器 — SIGINT/SIGTERM 时优雅退出。."""
    global _shutdown_requested
    _shutdown_requested = True
    sig_name = signal.Signals(signum).name
    print(f"\n[{sig_name}] 收到退出信号, 等待当前阶段完成后退出...")
    print("  (再次按 Ctrl+C 立即退出)")
    # 第二次信号直接退出
    signal.signal(signal.SIGINT, lambda *_: sys.exit(1))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))


async def main_async() -> None:
    """串联六个阶段, 全流水线双日志包裹。."""
    # P3-2: 注册信号处理器
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    setup_environment()
    ctx = PipelineContext(args=parse_args())
    ctx.output_manager = OutputManager(
        base_dir=getattr(ctx.args, "output_dir", None) or "outputs",
    )
    ctx.metadata["noise_log_path"] = str(ctx.output_manager.noise_log_path)
    ctx.metadata["signal_log_path"] = str(ctx.output_manager.log_path)

    ctx.start_time = datetime.now()
    clean_temp_files("pre")

    try:
        # B1 修复: 将 header 和 footer 移入 redirect 上下文, 确保完整日志写入 signal log
        with redirect_noise_to_file(
                Path(ctx.metadata["noise_log_path"]),
                Path(ctx.metadata["signal_log_path"]),
            ):
            print_pipeline_header(ctx)
            await stage_init(ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 1 后退出")
                return

            # Stage 1.5: Web 目标自动认证桥接 (仅当 --web-target-url 时激活)
            web_bridged = await stage_web_auth(ctx)
            if web_bridged and _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 1.5 (Web Auth) 后退出")
                return

            # XPIA 工作流 (可选, 提前返回)
            if getattr(ctx.args, "xpia", False):
                print("\n" + "=" * 70)
                print("[XPIA] Cross-Domain Prompt Injection Attack 工作流")
                print("=" * 70)
                from pipeline.workflows.xpia import run_xpia
                await run_xpia(ctx)
                return

            # 多模态注入场景 (可选, 提前返回)
            if getattr(ctx.args, "multimodal", False):
                print("\n" + "=" * 70)
                print("[Multimodal] 多模态注入场景")
                print("=" * 70)
                from pipeline.scenarios.multimodal_injection import run_multimodal_injection
                await run_multimodal_injection(ctx)
                return

            # 模型提取场景 (可选, 提前返回)
            if getattr(ctx.args, "scenario", "") == "model_extraction":
                print("\n" + "=" * 70)
                print("[Model Extraction] 模型提取场景")
                print("=" * 70)
                from pipeline.scenarios.model_extraction import run_model_extraction
                await run_model_extraction(ctx)
                return

            # 侦察驱动场景选择 (当 recon_result 存在时)
            recon_result = ctx.metadata.get("recon_result")
            if recon_result and not getattr(ctx.args, "scenario", None):
                from pipeline.integrations.web_redteam_bridge import recommend_scenarios_from_recon
                scenarios = recommend_scenarios_from_recon(recon_result)
                if scenarios:
                    print("\n  [Recon] 侦察结果推荐场景:")
                    for s in scenarios:
                        print(f"    [P{s['priority']}] {s['scenario']} ({s['owasp_id']}) — {s['rationale'][:80]}")

                    # 自动选择最高优先级场景
                    top_scenario = scenarios[0]
                    if top_scenario["scenario"] == "xpia":
                        print(f"\n  [Recon] 自动选择 XPIA 工作流")
                        from pipeline.workflows.xpia import run_xpia
                        await run_xpia(ctx)
                        return
                    elif top_scenario["scenario"] == "multimodal":
                        print(f"\n  [Recon] 自动选择多模态注入场景")
                        from pipeline.scenarios.multimodal_injection import run_multimodal_injection
                        await run_multimodal_injection(ctx)
                        return
                    elif top_scenario["scenario"] == "model_extraction":
                        print(f"\n  [Recon] 自动选择模型提取场景")
                        from pipeline.scenarios.model_extraction import run_model_extraction
                        await run_model_extraction(ctx)
                        return
                    # text_adaptive 继续走标准流水线

            await stage_scenario(ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 2 后退出")
                return

            await stage_initialize(ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 3 后退出")
                return

            await stage_execute(ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 4 后退出 (结果已保存)")
                # Stage 4 结果已持久化到 CentralMemory, 可安全退出
                return

            await stage_post_analysis(ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 5 后退出")
                return

            await stage_output(ctx)

            print_pipeline_footer(ctx)
    finally:
        # 清理 Web 目标的浏览器会话 (如有)
        _cleanup_web_session(ctx)

    # P3: 持久化动态发现的内容过滤器标记 (供下次运行加载)
    _persist_discovered_content_filter_markers()

    clean_temp_files("post")


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
    except (OSError, RuntimeError):
        pass  # 非关键路径,静默失败


def _cleanup_web_session(ctx: PipelineContext) -> None:
    """清理 Web 目标的浏览器会话 (如有)。

    在 finally 块中调用, 确保 Web 目标的 Playwright 浏览器
    在流水线结束 (正常或异常) 后正确关闭。
    """
    session = ctx.metadata.get("web_browser_session")
    if session is not None:
        try:
            import asyncio

            # 如果有事件循环运行, 异步关闭; 否则同步关闭
            try:
                loop = asyncio.get_running_loop()
                if loop:
                    loop.create_task(session.close())
                else:
                    raise RuntimeError("no loop")
            except (RuntimeError, OSError):
                session.close()
            _logger.debug("Web browser session cleaned up")
        except (OSError, RuntimeError):
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(0)
    except SystemExit:
        raise
