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
  python main.py
  python main.py --dataset-scope owasp_llm
  python main.py --max-dataset-size 5 --max-attempts 3
  python main.py --resume <scenario_result_id>
"""

# R-012: 始终使用 UTF-8 编码 — 在所有 import 之前强制设置,
# 确保 stdout/stderr 在 Windows GBK 终端下也能正确输出 Unicode 字符
import logging
import os as _os
import sys
import warnings

# 抑制第三方库 (如 confusables) 的 SyntaxWarning (invalid escape sequence)
# 这些警告来自 .venv 中的第三方包源码, 非本项目代码, 属于噪音直接抑制
warnings.filterwarnings("ignore", category=SyntaxWarning)

_logger = logging.getLogger(__name__)

_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
# write_through=True 确保每次 write 后立即 flush 到底层缓冲
# line_buffering=True 确保遇到 \n 时立即 flush
# 这两个参数防止 reconfigure 后缓冲模式变为 block-buffered 导致终端无输出
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", write_through=True, line_buffering=True)
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", write_through=True, line_buffering=True)

import asyncio
import contextlib
import os
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
from pipeline.stages.stage_target_classify import run as stage_target_classify
from pipeline.utils.cleaner import clean_temp_files
from pipeline.utils.contract_validator import ContractValidator
from pipeline.utils.display import print_pipeline_footer, print_pipeline_header
from pipeline.utils.noise_redirector import redirect_noise_to_file

# P3-2: 全局优雅退出标志
_shutdown_requested = False


def _cancel_all_async_tasks() -> int:
    """取消当前事件循环中所有 asyncio 任务, 立即停止 API 调用。.

    Returns:
        被取消的任务数
    """
    cancelled = 0
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return 0

    # 收集所有 pending 任务 (排除当前正在执行的)
    tasks = [t for t in asyncio.all_tasks(loop) if not t.done()]
    for task in tasks:
        task.cancel()
        cancelled += 1

    return cancelled


def _signal_handler(signum: int, frame: object) -> None:
    """P3-2: 信号处理器 — SIGINT/SIGTERM 时优雅退出 + 立即取消 API 调用。.

    第一次中断:
      1. 设置 _shutdown_requested 标志 (阶段间检查)
      2. 立即取消所有 asyncio 任务 (停止 API 调用, 避免后台消耗 token)
    第二次中断:
      硬退出 os._exit(1) — 不执行任何清理, 立即终止进程
    """
    global _shutdown_requested

    # 第二次信号: 硬退出, 立即终止进程 (避免后台继续消耗 token)
    if _shutdown_requested:
        print("\n[FORCE EXIT] 立即终止进程...")
        with contextlib.suppress(Exception):
            clean_temp_files("post")
        os._exit(1)

    # 第一次信号: 优雅退出
    _shutdown_requested = True
    sig_name = signal.Signals(signum).name
    print(f"\n[{sig_name}] 收到退出信号, 正在停止 API 调用...")

    # 立即取消所有 asyncio 任务 (停止正在进行的 API 调用)
    cancelled = _cancel_all_async_tasks()
    if cancelled > 0:
        print(f"  已取消 {cancelled} 个后台任务 (API 调用已停止)")
    print("  (再次按 Ctrl+C 立即硬退出)")


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

            # Stage 0.5: 统一目标类型判别 + 认证桥接 (仅当 --target-url 时激活)
            target_url = getattr(ctx.args, "target_url", None)
            if target_url:
                target_bridged = await stage_target_classify(ctx)
                if target_bridged and _shutdown_requested:
                    print("\n[SHUTDOWN] 在 Stage 0.5 (目标桥接) 后退出")
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
                from pipeline.integrations.web_redteam import recommend_scenarios_from_recon
                from pipeline.utils.decision_trace import DecisionTrace

                scenarios = recommend_scenarios_from_recon(recon_result)
                if scenarios:
                    # A5: Recon 驱动决策追溯
                    trace = DecisionTrace.get_instance()
                    trace.record(
                        stage="main",
                        layer="recon_driven_selection",
                        decision="recon_scenarios_recommended",
                        reason=f"Recon result drove {len(scenarios)} scenario recommendations",
                        top_scenario=scenarios[0]["scenario"] if scenarios else "none",
                        total_recommendations=len(scenarios),
                    )
                    print("\n  [Recon] 侦察结果推荐场景:")
                    for s in scenarios:
                        print(f"    [P{s['priority']}] {s['scenario']} ({s['owasp_id']}) — {s['rationale'][:80]}")

                    # 自动选择最高优先级场景
                    top_scenario = scenarios[0]
                    if top_scenario["scenario"] == "xpia":
                        print("\n  [Recon] 自动选择 XPIA 工作流")
                        from pipeline.workflows.xpia import run_xpia
                        await run_xpia(ctx)
                        return
                    elif top_scenario["scenario"] == "multimodal":
                        print("\n  [Recon] 自动选择多模态注入场景")
                        from pipeline.scenarios.multimodal_injection import run_multimodal_injection
                        await run_multimodal_injection(ctx)
                        return
                    elif top_scenario["scenario"] == "model_extraction":
                        print("\n  [Recon] 自动选择模型提取场景")
                        from pipeline.scenarios.model_extraction import run_model_extraction
                        await run_model_extraction(ctx)
                        return
                    # text_adaptive 继续走标准流水线

            await stage_scenario(ctx)
            _validate_contract(1, 2, ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 2 后退出")
                return

            await stage_initialize(ctx)
            _validate_contract(2, 3, ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 3 后退出")
                return

            await stage_execute(ctx)
            _validate_contract(3, 4, ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 4 后退出 (结果已保存)")
                # Stage 4 结果已持久化到 CentralMemory, 可安全退出
                return

            await stage_post_analysis(ctx)
            _validate_contract(4, 5, ctx)
            if _shutdown_requested:
                print("\n[SHUTDOWN] 在 Stage 5 后退出")
                return

            await stage_output(ctx)
            _validate_contract(5, 6, ctx)

            # D1+D6: 输出决策追溯和事件总线摘要
            _print_trace_and_event_summary()

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
   将这些标记写入 data/setting/content_filter_discovered.json,
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


_validator = ContractValidator()


def _validate_contract(stage_from: int, stage_to: int, ctx: PipelineContext) -> None:
    """D5: 阶段间数据流契约验证。."""
    result = _validator.validate(stage_from, stage_to, ctx)
    if not result.passed:
        print(f"  ⚠ [D5] 契约验证失败: {result}")
    elif result.warnings:
        print(f"  [D5] 契约验证通过 (有警告): {result.warnings}")
    else:
        print(f"  [D5] 契约验证通过: {result.stage_from} → {result.stage_to}")


def _print_trace_and_event_summary() -> None:
    """D1+D6: 输出决策追溯和事件总线摘要。."""
    try:
        from pipeline.utils.decision_trace import DecisionTrace
        from pipeline.utils.event_bus import EventBus

        # D1: 决策追溯摘要
        trace = DecisionTrace.get_instance()
        if trace.record_count > 0:
            print("\n  ┌─ D1: 决策追溯摘要 ───────────────────────────────────────┐")
            print(f"  │ 共 {trace.record_count} 条决策记录")
            stages = {}
            for r in trace.get_records():
                stages.setdefault(r.stage, []).append(r)
            for stage, records in sorted(stages.items()):
                print(f"  │   {stage}: {len(records)} 条")
            print("  └───────────────────────────────────────────────────────────────┘")

        # D6: 事件总线摘要
        bus = EventBus.get_instance()
        if bus.event_count > 0:
            print(f"\n  [D6] 事件总线: 共发布 {bus.event_count} 个事件")
            if bus.jsonl_path:
                print(f"       JSONL: {bus.jsonl_path}")
    except Exception as e:
        _logger.debug(f"Trace/event summary failed: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n用户中断")
        # 确保临时文件清理 (R-008)
        with contextlib.suppress(Exception):
            clean_temp_files("post")
        os._exit(0)
    except SystemExit:
        # 确保临时文件清理 (R-008)
        with contextlib.suppress(Exception):
            clean_temp_files("post")
        raise
    except Exception as e:
        print(f"\n流水线异常: {e}")
        with contextlib.suppress(Exception):
            clean_temp_files("post")
        os._exit(1)
