"""资源清理模块 — 从 main.py 提取的 Target 生命周期管理。

生产级资源清理 — 确保所有 Target 资源在流水线结束时正确释放。
防止 httpx.AsyncClient 连接泄漏、DB 引擎未释放、浏览器进程残留。
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def cleanup_resources(
    ctx: "PipelineContext",
    *,
    exclude_shared: bool = False,
) -> None:
    """生产级资源清理 — 确保所有 Target 资源在流水线结束时正确释放。

    断点修复: 之前 main.py 在各阶段退出点 (包括正常结束) 时
    没有调用 RateLimitedTarget.cleanup() 和 Playwright 资源清理,
    导致 httpx.AsyncClient 连接泄漏、DB 引擎未释放、浏览器进程残留。

    清理顺序 (LIFO — 后创建的先清理):
        1. extra_objective_targets (port_expander 发现的额外目标)
        2. multi_turn_target (多轮攻击目标, 可能与 objective_target 相同)
        3. objective_target (主攻击目标, RateLimitedTarget.cleanup)
        4. Playwright 浏览器实例 (_browser, _playwright_instance)
        5. adversarial_target / scoring_target (辅助目标, 通常无状态)

    多 endpoint 模式 (exclude_shared=True):
        仅清理 objective 相关的 targets (1-4 + Playwright),
        跳过 adversarial/scoring/converter (5), 因为这些是攻击者自己的 LLM,
        在多 endpoint 循环中跨 endpoint 复用, 由循环结束后统一清理。
        清理后将 objective 引用置为 None, 确保下个 endpoint 重建 target。

    学术依据:
        - Heroux et al. (arXiv:2403.04206) §3.2 — 资源生命周期管理
        - PyRIT (arXiv:2407.01232) — dispose_db_engine() 资源释放
        - Greshake et al. (arXiv:2302.12173) — 逐个深度攻击需独立资源
    """
    cleaned: set[int] = set()  # 避免重复清理同一对象 (objective_target == multi_turn_target)

    async def _cleanup_target(target: Any, label: str) -> None:
        """清理单个 Target 的资源 (幂等, 非阻塞)。"""
        if target is None:
            return
        target_id = id(target)
        if target_id in cleaned:
            return
        cleaned.add(target_id)
        try:
            if hasattr(target, "cleanup") and callable(target.cleanup):
                result = target.cleanup()
                if asyncio.iscoroutine(result):
                    await result
                logger.debug("Cleaned up %s: %s", label, type(target).__name__)
        except Exception as e:
            logger.debug("Cleanup %s failed (non-fatal): %s", label, e)

    # 1. 清理 extra_objective_targets (port_expander 发现的额外目标)
    for port, extra_target in getattr(ctx, "extra_objective_targets", {}).items():
        await _cleanup_target(extra_target, f"extra_objective_target[port={port}]")
    ctx.extra_objective_targets = {}  # 清除引用

    # 2. 清理 multi_turn_target (可能与 objective_target 相同, cleaned 集去重)
    await _cleanup_target(getattr(ctx, "multi_turn_target", None), "multi_turn_target")
    ctx.multi_turn_target = None  # 清除引用

    # 3. 清理 objective_target (主攻击目标)
    await _cleanup_target(getattr(ctx, "objective_target", None), "objective_target")
    ctx.objective_target = None  # 清除引用

    # 4. 清理 Playwright 浏览器实例 (browser 模式)
    # 数据流: target_router._create_playwright_target → ctx._browser_context/_browser/_playwright_instance
    #         → cleanup_resources → browser.close() + playwright.stop()
    # 幂等: 清理后清除引用, 防止 finally 块重复清理
    _browser_context = getattr(ctx, "_browser_context", None)
    _browser = getattr(ctx, "_browser", None)
    _playwright_instance = getattr(ctx, "_playwright_instance", None)
    try:
        if _browser_context is not None:
            await _browser_context.close()
            ctx._browser_context = None  # 幂等: 清除引用
            logger.debug("Closed Playwright browser context")
    except Exception as e:
        logger.debug("Playwright browser context close failed (non-fatal): %s", e)
    try:
        if _browser is not None:
            await _browser.close()
            ctx._browser = None  # 幂等: 清除引用
            logger.debug("Closed Playwright browser")
    except Exception as e:
        logger.debug("Playwright browser close failed (non-fatal): %s", e)
    try:
        if _playwright_instance is not None:
            await _playwright_instance.stop()
            ctx._playwright_instance = None  # 幂等: 清除引用
            logger.debug("Stopped Playwright instance")
    except Exception as e:
        logger.debug("Playwright instance stop failed (non-fatal): %s", e)

    # 5. adversarial_target / scoring_target 通常是 OpenAIChatTarget (无 httpx client 需关闭)
    #    但如果被 RateLimitedTarget 包装过, cleanup 已在上面执行
    #    此处仅清理未被包装的裸 Target (如 _create_adversarial_target 直接创建的)
    # 多 endpoint 模式 (exclude_shared=True): 跳过共享 targets, 由循环结束后统一清理
    if not exclude_shared:
        # 5a. extra_adversarial_targets (多模型并行攻击的额外攻击者 LLM)
        for i, extra_adv in enumerate(getattr(ctx, "extra_adversarial_targets", [])):
            await _cleanup_target(extra_adv, f"extra_adversarial_target[{i}]")
        ctx.extra_adversarial_targets = []  # 清除引用
        await _cleanup_target(getattr(ctx, "adversarial_target", None), "adversarial_target")
        ctx.adversarial_target = None  # 清除引用
        await _cleanup_target(getattr(ctx, "scoring_target", None), "scoring_target")
        ctx.scoring_target = None  # 清除引用
        await _cleanup_target(getattr(ctx, "converter_target", None), "converter_target")
        ctx.converter_target = None  # 清除引用

    logger.info(
        "Resource cleanup complete (cleaned %d targets, shared_excluded=%s)",
        len(cleaned),
        exclude_shared,
    )


def has_residual_resources(ctx: "PipelineContext") -> bool:
    """检查 ctx 中是否还有残留的 Target 引用。"""
    return (
        getattr(ctx, "objective_target", None) is not None
        or getattr(ctx, "adversarial_target", None) is not None
        or getattr(ctx, "scoring_target", None) is not None
        or getattr(ctx, "converter_target", None) is not None
        or getattr(ctx, "_browser", None) is not None
        or getattr(ctx, "_playwright_instance", None) is not None
    )
