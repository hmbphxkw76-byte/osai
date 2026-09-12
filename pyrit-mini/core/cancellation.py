# -*- coding: utf-8 -*-
"""core/cancellation.py — 协作式取消令牌（plan Wave 4.6）。

背景（plan 附录 A / Wave 4.6 缺陷）：
    `core/logging_config.py` 的 SIGINT 处理器在**二次**收到中断信号时直接
    `os._exit(130)`。`os._exit` 是进程级立即终止，**不抛异常、不展开栈**，
    因此所有 `finally` 清理（资源释放、checkpoint 落盘、memory 关闭、报告收尾）
    全部被跳过——用户按下两次 Ctrl+C 后，运行产物处于半写状态且无任何留痕。

本模块提供进程内唯一的 `CancellationToken`：
    - 首次中断：置位令牌并抛 `KeyboardInterrupt`，让 asyncio / 流水线正常展开栈，
      每个阶段的 `finally` 都能执行；耗时循环可轮询 `is_cancelled` 主动收敛。
    - 二次及以上：抛 `SystemExit(130)`。`SystemExit` 同为异常，仍会执行
      `finally`，但会终止后续阶段调度——既保留强制退出能力，又不再强杀。

Constitution:
    - C9（诚实汇报）：取消次数与原因可查询，禁止无声丢失。
    - C3（单一事实源）：取消状态只有本模块一个持有者，禁止各处自定义 flag。

Academic basis:
    - PyRIT (arXiv:2407.01232) — 长时运行攻击编排需要可中断且可恢复的执行模型。
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

# 约定退出码：与 shell 中 SIGINT 终止（128+2）保持一致
INTERRUPT_EXIT_CODE = 130


class CancelledError(RuntimeError):
    """由 `raise_if_cancelled()` 抛出，表示流水线已被请求取消。"""


class CancellationToken:
    """线程安全的协作式取消令牌。

    典型用法：
        token = get_cancellation_token()
        for item in worklist:
            token.raise_if_cancelled()      # 或 if token.is_cancelled: break
            ...
    """

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._count = 0
        self._reason: str | None = None

    # -- 查询 ------------------------------------------------------------
    @property
    def is_cancelled(self) -> bool:
        """是否已被请求取消。"""
        return self._event.is_set()

    @property
    def count(self) -> int:
        """累计收到的取消请求次数（首次 = 1）。"""
        with self._lock:
            return self._count

    @property
    def reason(self) -> str | None:
        """首次取消的原因（人类可读），未取消时为 None。"""
        with self._lock:
            return self._reason

    def __bool__(self) -> bool:
        """`if token:` 等价于「已取消」，便于在条件判断中直接使用。"""
        return self.is_cancelled

    def snapshot(self) -> dict[str, Any]:
        """导出可序列化快照，供 orchestration_log / 报告留痕（C9）。"""
        return {"cancelled": self.is_cancelled, "count": self.count, "reason": self.reason}

    # -- 变更 ------------------------------------------------------------
    def cancel(self, reason: str | None = None) -> int:
        """请求取消，返回本次是第几次取消请求（首次返回 1）。

        Args:
            reason: 取消原因，仅首次记录（后续请求保留首因，便于定位根因）。

        Returns:
            累计取消次数。
        """
        with self._lock:
            self._count += 1
            current = self._count
            if self._reason is None:
                self._reason = reason
        self._event.set()
        logger.warning("收到取消请求（第 %d 次）：%s", current, reason or "未说明原因")
        return current

    def raise_if_cancelled(self) -> None:
        """若已取消则抛 `CancelledError`，供循环主动让出。"""
        if self.is_cancelled:
            raise CancelledError(f"执行已取消：{self.reason or '未说明原因'}")

    def reset(self) -> None:
        """重置令牌（仅供测试与 `--resume` 新开一轮时使用）。"""
        with self._lock:
            self._count = 0
            self._reason = None
        self._event.clear()


# ── 进程内唯一实例（C3：取消状态只有一个持有者） ─────────────────────────────

_token = CancellationToken()


def get_cancellation_token() -> CancellationToken:
    """取得进程内唯一的取消令牌。"""
    return _token


def reset_cancellation_token() -> CancellationToken:
    """重置并返回一个干净的取消令牌（测试 / 新一轮运行使用）。"""
    _token.reset()
    return _token


def request_cancel(reason: str | None = None) -> int:
    """请求取消当前运行，返回累计取消次数。"""
    return _token.cancel(reason)
