"""core/target_factory — 跨层 Target 工厂接缝（REQ-149/151；CP-009 S4/S6）。

recon 与 strike 的本层域类（MCPTarget/RAGTarget/A2ATarget）经此工厂互访，
双方都不静态 import 对方域（依赖矩阵 `recon→strike` / `strike→recon` 均为 ✗）：

- 注册由 strike 侧在导入期完成（`strike→core` ✓），见 `strike/targets/__init__.py`；
- recon 侧只查表（`recon→core` ✓），见 `recon/adapters/__init__.py` 的
  `_build_mcp_rag_a2a`；

本模块零攻击逻辑，仅持注册表（NEG-4 合规：仅标准库 + typing）。
"""

from __future__ import annotations

from typing import Any, Callable

# kind（"mcp"/"rag"/"a2a"）→ 构造器（接收 inner=BaseAdapter，返回 Target 实例）
_TARGET_FACTORIES: dict[str, Callable[..., Any]] = {}


def register_target(kind: str, factory: Callable[..., Any]) -> None:
    """strike 侧在导入期登记某 kind 的 Target 构造器（strike→core ✓）。"""
    _TARGET_FACTORIES[kind] = factory


def build_target(kind: str, *, inner: Any, **kwargs: Any) -> Any:
    """按 kind 取出已登记构造器并构建 Target 实例（recon 侧调用，recon→core ✓）。

    Raises:
        KeyError: 该 kind 未登记——通常意味着 `strike.targets` 包尚未导入。
    """
    factory = _TARGET_FACTORIES.get(kind)
    if factory is None:
        raise KeyError(f"未登记的 target kind: {kind}（strike.targets 包未导入？）")
    return factory(inner=inner, **kwargs)
