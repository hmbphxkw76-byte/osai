#!/usr/bin/env python3
"""main.py — PyRIT 攻击链路入口 (纯编排层)。

攻击链路 (6 阶段, arXiv:2407.01232 — PyRIT 原生框架):
    ① recon     → Burp 拦截: 读取 HTTP 请求 + 侦察: 解析, 探测能力指纹, 构建 HTTPTarget
    ② arm       → 种子选取: 从 YAML 种子文件加载, 按历史 ASR 排序 + Converter: 构建 L5 最优链
    ③ strike    → 攻击发送: PyRIT 原生 PromptSendingAttack 多路径执行 (FIRST_SUCCESS)
    ④ escalate  → 多轮升级: Crescendo→TAP→PAIR→GCG→native (ASR<90% 触发, 含中间退出)
    ⑤ assess    → 评分判定: T0→J1→J2→J3 级联评分, ASR 统计, Wilson CI, 双 Judge 交叉验证
                     (or_aggregation OR 聚合追踪, scorer_metrics T0 评分器指标)
    ⑥ report    → 报告生成: 证据收集 + MD/HTML/JSON/PoC/SARIF

    不指定 --stage 时按顺序执行全部 6 个阶段 (strike+escalate 合为一步), 向后兼容。
    指定 --stage <name> 时执行到该阶段完成后停止, 便于分阶段开发和调试。

模块化架构:
    core/       — 流水线编排 (orchestrator), 上下文 (context), 配置 (config), 日志 (logging_config), 清理 (cleanup)
    recon/      — Burp 拦截, HTTP 解析, 目标指纹, 能力探测
    arm/        — 种子选取, Converter 链, 技术选择
    strike/     — 攻击执行, 多路径, 升级链
    assess/     — 评分器, ASR 统计, 双 Judge
    report/     — 证据收集, 报告生成 (MD/HTML/JSON/PoC/SARIF)
    targets/    — RateLimitedTarget, 内容过滤
    utils/      — 终端输出, 缓存清理

使用方式:
    # 全火力模式 (AI-300 考试首选 — 最高 ASR 配置)
    python main.py --offensive

    # 分阶段执行 (--stage 控制, 6 个阶段可独立调试):
    python main.py --burp request --stage recon
    python main.py --burp deepseek --stage arm
    python main.py --burp qwen --stage strike
    python main.py --stage escalate
    python main.py --stage assess
    python main.py --stage report

    # 自定义参数
    python main.py --burp request \
        --seeds elite_jailbreaks --converters l5_optimal \
        --techniques auto --max-seeds 25
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

# UTF-8 强制 (Windows GBK 终端兼容)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 项目根目录加入 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


async def run(argv: list[str] | None = None) -> None:
    """主流程入口 — 初始化环境 + 启动攻击链路编排器。

    编排逻辑委托给 core/orchestrator.py → run_attack_pipeline()。
    此处仅负责:
        1. 日志配置 (终端 WARNING+, 文件全量 INFO)
        2. 信号处理 (SIGINT/SIGTERM 优雅退出)
        3. 参数解析 + 环境初始化 (PyRIT DB)
        4. 流水线上下文构建 (PipelineContext)
        5. 生产级 try/finally 保障资源清理
    """
    # ── 导入核心模块 ──
    from core.cleanup import cleanup_resources, has_residual_resources
    from core.config import (
        ensure_output_dir,
        get_output_dir,
        parse_args,
        setup_environment,
    )
    from core.context import PipelineContext, apply_relaxed_adversarial_schema
    from core.logging_config import (
        configure_root_logging,
        flush_and_close_handlers,
        install_signal_handlers,
        setup_logging,
    )
    from core.orchestrator import run_attack_pipeline
    # R11: 导入 Scenario 路由器以启用目标感知攻击链
    from core.scenario_router import get_router, apply_scenario_overrides
    from utils.display import print_banner, print_phase, print_status

    # ── 日志基础配置 ──
    configure_root_logging()

    # ── 打印横幅 ──
    print_banner()

    # ── 解析参数 + 输出目录 ──
    args = parse_args(argv)
    output_dir = get_output_dir(args)
    ensure_output_dir(output_dir)

    # ── 配置文件日志 + 终端控制 ──
    setup_logging(output_dir, getattr(args, "verbose", False))

    # rate_limit 环境变量
    rate_limit = getattr(args, "rate_limit", None)
    if rate_limit:
        os.environ["RATE_LIMIT"] = str(rate_limit)

    # ── 构建流水线上下文 ──
    ctx = PipelineContext(args=args, output_dir=output_dir)
    ctx.scenario_result_id = getattr(args, "resume", None)
    ctx.memory_labels = getattr(args, "memory_labels_parsed", {}) or {}

    # ── 安装信号处理器 ──
    install_signal_handlers(ctx)

    # ── INIT: 初始化 PyRIT 环境 ──
    print_phase("INIT", "初始化 PyRIT 环境...")
    apply_relaxed_adversarial_schema()
    await setup_environment(output_dir)
    print_status("INIT", "DONE", f"Output: {output_dir}", ok=True)

    # ── 执行攻击链路编排 (try/finally 保障资源清理) ──
    _logger = logging.getLogger(__name__)

    # R10: dry-run 零 token 流水线完整性验证
    # main.py 层面: 早期返回,跳过 run_attack_pipeline()
    # orchestrator.py 层面: 防御性第二道防线,即使 main.py 逻辑失效也能跳过攻击
    _is_dry_run = getattr(args, "dry_run", False)
    if _is_dry_run:
        # [DRY-RUN] 跳过攻击: execute_attacks 和 execute_text_adaptive 不会被调用
        # [DRY-RUN] 跳过升级: check_and_escalate 不会被调用
        _logger.info("[DRY-RUN] 零 token 验证模式 — 跳过真实 API 调用")
        _logger.info("[DRY-RUN] [DRY-RUN] 跳过攻击执行 (execute_attacks)")
        _logger.info("[DRY-RUN] [DRY-RUN] 跳过升级链 (check_and_escalate)")
        print_status("DRY-RUN", "DONE", "零 token 验证通过 — 跳过全部攻击/升级", ok=True)
        return

    # R11: Scenario 路由器集成 — 将路由器传递给编排器,启用目标感知攻击链
    router = get_router()

    try:
        await run_attack_pipeline(ctx, router=router)
    except KeyboardInterrupt:
        _logger.info("收到中断信号, 执行资源清理...")
        try:
            await cleanup_resources(ctx)
        except Exception as e:
            # R-H2 合规: 不静默吞错, 记录非致命异常
            _logger.debug("中断清理时资源释放失败 (non-fatal): %s", e)
        raise
    finally:
        # 最终保障: 如果仍有残留资源, 尝试清理
        try:
            if has_residual_resources(ctx):
                await cleanup_resources(ctx)
        except Exception:
            pass
        # 确保所有 FileHandler flush + close
        flush_and_close_handlers()


# ═══════════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[!] 用户中断, 退出")
        sys.exit(130)
