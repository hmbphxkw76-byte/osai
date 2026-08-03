#!/usr/bin/env python3
# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

r"""Web Red Team Framework — 薄入口.

仅串联 pipeline/ 下各独立阶段, 自身不含任何业务逻辑。
对齐 main.py 的设计模式。

双模式流水线:

  Browser 模式 (--target-profile / --target-url):
    0. pipeline.stage_init    — PyRIT 原生初始化
    1. pipeline.stage_auth    — 浏览器认证 (人工辅助 + 自动检测)
    2. pipeline.stage_recon   — 侦察数据加载 (可选, 从外部 JSON 加载)
    3. pipeline.stage_target  — 目标创建 (PlaywrightTarget)
    4. pipeline.stage_attack  — 攻击执行
    5. pipeline.stage_output  — 结果输出

  API 模式 (--api-url):
    0. pipeline.stage_init    — PyRIT 原生初始化
    1. pipeline.stage_auth    — API 配置加载 (跳过浏览器认证)
    2. pipeline.stage_recon   — 侦察数据加载 (可选, 从外部 JSON 加载)
    3. pipeline.stage_target  — 目标创建 (HTTPTarget + RateLimitedTarget)
    4. pipeline.stage_attack  — 攻击执行
    5. pipeline.stage_output  — 结果输出

Usage:
  # Browser 模式
  python -m web_redteam.run --target-profile <yaml> --attack-type <type> --objective <text>
  python -m web_redteam.run --target-url <url>

  # API 模式
  python -m web_redteam.run --api-url <url> --api-headers '<json>' --api-body '<json>' \\
    --max-rpm 60 --max-concurrency 5 --attack-type prompt_sending --objective <text>
"""

import asyncio
import json
import logging
import re
import signal
import sys
from datetime import datetime
from pathlib import Path

from web_redteam.config import parse_args
from web_redteam.pipeline.context import WebRedTeamContext
from web_redteam.pipeline.stage_attack import run as stage_attack
from web_redteam.pipeline.stage_auth import run as stage_auth
from web_redteam.pipeline.stage_init import run as stage_init
from web_redteam.pipeline.stage_output import run as stage_output
from web_redteam.pipeline.stage_recon import run as stage_recon
from web_redteam.pipeline.stage_target import run as stage_target

# Windows 事件循环策略 (对齐 doc/code/targets/10_2_playwright_target_copilot.py)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

logger = logging.getLogger(__name__)

# G16: 全局超时 (秒) — 涵盖认证+侦察+攻击+输出
_GLOBAL_TIMEOUT_SECONDS = 900

# G10: 优雅关闭 — 中断事件
_shutdown_event: asyncio.Event | None = None

# R3: 检查点文件路径
_CHECKPOINT_FILE = Path("outputs/web_redteam_checkpoint.json")

# R3: 流水线阶段定义 (有序)
_PIPELINE_STAGES = [
    "stage_init",
    "stage_auth",
    "stage_recon",
    "stage_target",
    "stage_attack",
    "stage_output",
]


# ============================================================
# G9: 凭据日志脱敏过滤器
# ============================================================


class CredentialRedactionFilter(logging.Filter):
    """G9: 日志中自动脱敏 Bearer token / API key.

    匹配以下模式并替换为 ***:
      - Bearer sk-xxx... → Bearer ***
      - api_key=sk-xxx... → api_key=***
      - Authorization: Bearer xxx → Authorization: Bearer ***
    """

    # 匹配 Bearer <token> (不含引号和空格的连续字符)
    _BEARER_PATTERN = re.compile(r"(Bearer\s+)[^\s,;\"']+", re.IGNORECASE)
    # 匹配 api_key=xxx 或 api-key: xxx
    _APIKEY_PATTERN = re.compile(r"((?:api[_-]key)[=:]\s*)[^\s,;\"']+", re.IGNORECASE)
    # 匹配 sk- 开头的 OpenAI key
    _SK_PATTERN = re.compile(r"(sk-)[A-Za-z0-9]{10,}", re.IGNORECASE)

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D102
        """脱敏日志记录中的凭据信息.."""
        msg = str(record.msg)
        msg = self._BEARER_PATTERN.sub(r"\1***", msg)
        msg = self._APIKEY_PATTERN.sub(r"\1***", msg)
        msg = self._SK_PATTERN.sub(r"\1***", msg)
        record.msg = msg
        return True


def _setup_logging() -> None:
    """配置日志 — 注册 G9 凭据脱敏过滤器.."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    handler.addFilter(CredentialRedactionFilter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


# ============================================================
# G10: 优雅关闭
# ============================================================


def _signal_handler(sig: int, frame: object) -> None:
    """G10: 信号处理器 — 设置中断事件.

    第一次中断: 设置事件, 等待当前阶段完成
    第二次中断: 立即退出
    """
    global _shutdown_event
    if _shutdown_event is not None and not _shutdown_event.is_set():
        logger.info("G10: 收到中断信号, 正在保存部分结果...")
        _shutdown_event.set()
    else:
        logger.warning("G10: 强制退出")
        sys.exit(1)


async def _save_partial_results(ctx: WebRedTeamContext) -> None:
    """G10+R3: 保存部分结果 (中断时调用).

    同时保存 R3 检查点文件, 用于 --resume 恢复.
    """
    if ctx.result is None and ctx.target is None and ctx.api_config is None:
        return

    partial_dir = Path(
        f"outputs/web_redteam_partial_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    partial_dir.mkdir(parents=True, exist_ok=True)

    # 保存已有结果
    if ctx.result is not None:
        try:
            (partial_dir / "partial_result.txt").write_text(
                str(ctx.result), encoding="utf-8"
            )
            logger.info(f"G10: 部分结果已保存: {partial_dir / 'partial_result.txt'}")
        except Exception as e:
            logger.warning(f"G10: failed to save partial result: {e}")

    # 保存上下文状态摘要 + R3 检查点
    summary = {
        "api_mode": ctx.api_mode,
        "target_url": ctx.api_config.url if ctx.api_config else None,
        "attack_type": getattr(ctx.args, "attack_type", None),
        "has_result": ctx.result is not None,
        "has_target": ctx.target is not None,
        "has_api_config": ctx.api_config is not None,
        "interrupted_at": datetime.now().isoformat(),
    }

    (partial_dir / "interrupt_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logger.info(f"G10: 中断摘要已保存: {partial_dir / 'interrupt_summary.json'}")

    # R3: 保存检查点 (供 --resume 使用)
    _save_checkpoint(ctx, partial_dir / "checkpoint.json")


def _save_checkpoint(ctx: WebRedTeamContext, path: Path | None = None) -> None:
    """R3: 保存流水线检查点.

    记录已完成的阶段, 供 --resume 恢复时跳过.

    Args:
        ctx: WebRedTeamContext.
        path: 检查点文件路径 (默认: _CHECKPOINT_FILE).
    """
    checkpoint_path = path or _CHECKPOINT_FILE
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

    checkpoint = {
        "timestamp": datetime.now().isoformat(),
        "api_mode": ctx.api_mode,
        "completed_stages": list(ctx.metadata.get("completed_stages", set())),
        "has_api_config": ctx.api_config is not None,
        "has_target": ctx.target is not None,
        "has_result": ctx.result is not None,
    }

    if ctx.api_config:
        checkpoint["api_config"] = ctx.api_config.to_display_dict()

    checkpoint_path.write_text(
        json.dumps(checkpoint, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    logger.debug(f"R3: checkpoint saved to {checkpoint_path}")


def _load_checkpoint(path: str) -> dict | None:
    """R3: 加载检查点文件.

    Args:
        path: 检查点 JSON 文件路径.

    Returns:
        检查点字典, 失败返回 None.
    """
    checkpoint_path = Path(path)
    if not checkpoint_path.exists():
        logger.error(f"R3: checkpoint file not found: {path}")
        return None

    try:
        data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        logger.info(
            f"R3: checkpoint loaded (completed_stages={data.get('completed_stages', [])})"
        )
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"R3: failed to load checkpoint: {e}")
        return None


# ============================================================
# 主流水线
# ============================================================


async def main_async() -> None:
    """串联六个阶段 (双模式 + G10: 优雅关闭 + R3: 中断恢复)."""
    global _shutdown_event
    _shutdown_event = asyncio.Event()

    args = parse_args()

    # 判定模式: 有 --api-url 则为 API 模式
    api_mode = args.api_url is not None

    ctx = WebRedTeamContext(args=args, api_mode=api_mode)

    # R3: 加载检查点 (如果提供了 --resume)
    completed_stages: set[str] = set()
    resume_path = getattr(args, "resume", None)
    if resume_path:
        checkpoint = _load_checkpoint(resume_path)
        if checkpoint:
            completed_stages = set(checkpoint.get("completed_stages", []))
            ctx.metadata["completed_stages"] = completed_stages
            logger.info(
                f"R3: resuming from checkpoint, "
                f"{len(completed_stages)} stages already completed"
            )

    logger.info("=" * 70)
    if api_mode:
        logger.info("[模式] API POST 攻击 (HTTPTarget + RateLimitedTarget)")
    else:
        logger.info("[模式] Browser UI 攻击 (PlaywrightTarget)")
    logger.info("=" * 70)

    # G10: 注册信号处理器
    signal.signal(signal.SIGINT, _signal_handler)
    if sys.platform != "win32":
        signal.signal(signal.SIGTERM, _signal_handler)

    try:
        # G16: 全局超时保护
        await asyncio.wait_for(
            _run_pipeline(ctx),
            timeout=_GLOBAL_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.error(f"全局超时 ({_GLOBAL_TIMEOUT_SECONDS}s), 流水线被终止")
    except asyncio.CancelledError:
        # G10: 中断导致的 CancelledError
        logger.info("流水线被中断, 正在保存部分结果...")
        await _save_partial_results(ctx)
    finally:
        # G10: 如果中断事件已设置, 保存部分结果
        if _shutdown_event is not None and _shutdown_event.is_set():
            await _save_partial_results(ctx)

        # 清理浏览器会话 (仅 Browser 模式)
        if ctx.browser_session:
            await ctx.browser_session.close()

        # 清理信号量 (API 模式)
        if ctx.api_mode:
            try:
                from pipeline.targets.rate_limited_target import cleanup_semaphores

                cleanup_semaphores()
            except ImportError:
                pass


async def _run_pipeline(ctx: WebRedTeamContext) -> None:
    """实际流水线执行 (G16: 被全局超时包裹 + R3: 检查点恢复)."""
    completed_stages: set[str] = ctx.metadata.get("completed_stages", set())

    def _is_done(stage: str) -> bool:
        """R3: 检查阶段是否已完成 (从检查点恢复时跳过)."""
        if stage in completed_stages:
            logger.info(f"R3: skipping completed stage: {stage}")
            return True
        return False

    def _mark_done(stage: str) -> None:
        """R3: 标记阶段完成并保存检查点."""
        completed_stages.add(stage)
        ctx.metadata["completed_stages"] = completed_stages
        _save_checkpoint(ctx)

    # Stage 0: PyRIT 初始化
    if not _is_done("stage_init"):
        await stage_init(ctx)
        _mark_done("stage_init")

    # G10: 检查中断
    if _shutdown_event is not None and _shutdown_event.is_set():
        raise asyncio.CancelledError("shutdown requested")

    # Stage 1: 认证
    if not _is_done("stage_auth"):
        await stage_auth(ctx)
        _mark_done("stage_auth")

    if _shutdown_event is not None and _shutdown_event.is_set():
        raise asyncio.CancelledError("shutdown requested")

    # Stage 2: 侦察数据加载
    should_recon = (
        getattr(ctx.args, "recon", False)
        or getattr(ctx.args, "recon_data", None) is not None
    )
    if should_recon and not _is_done("stage_recon"):
        await stage_recon(ctx)
        _mark_done("stage_recon")

    if _shutdown_event is not None and _shutdown_event.is_set():
        raise asyncio.CancelledError("shutdown requested")

    # Stage 3: 目标创建
    if not _is_done("stage_target"):
        await stage_target(ctx)
        _mark_done("stage_target")

    if _shutdown_event is not None and _shutdown_event.is_set():
        raise asyncio.CancelledError("shutdown requested")

    # Stage 4: 攻击执行
    if not _is_done("stage_attack"):
        await stage_attack(ctx)
        _mark_done("stage_attack")

    if _shutdown_event is not None and _shutdown_event.is_set():
        raise asyncio.CancelledError("shutdown requested")

    # Stage 5: 结果输出
    if not _is_done("stage_output"):
        await stage_output(ctx)
        _mark_done("stage_output")

    # R3: 流水线完成, 清理检查点
    _CHECKPOINT_FILE.unlink(missing_ok=True)
    logger.info("R3: pipeline completed, checkpoint cleaned up")


if __name__ == "__main__":
    _setup_logging()
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        # G10: 已由信号处理器处理, 这里仅防止 traceback
        logger.info("用户中断")
        sys.exit(0)
