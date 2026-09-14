"""core/adapter_registry — 跨层 Adapter 注册表接缝（REQ-149 IC-2；CP-009 S6）。

recon 的适配器类（BaseAdapter/HTTPAdapter/JSONRPCAdapter/AdapterResponse）与中央构造器
`build_adapter` 经此注册表供 strike 侧取用，双方都不静态 import 对方域
（依赖矩阵 `strike→recon` 为 ✗）：

- 登记由 recon 侧在导入期完成（recon→core ✓），见 `recon/adapters/__init__.py`；
- strike 侧只查表（strike→core ✓），见 `strike/targets/{a2a,mcp,rag}.py` 与 `strike/playbook.py`。

本模块零攻击逻辑，仅持注册表（NEG-4 合规：仅标准库 + typing）。
"""

from __future__ import annotations

from typing import Any, Callable

# 符号名 → 注册对象（适配器类 / 构造器）
_ADAPTERS: dict[str, Any] = {}


def register_adapter(name: str, obj: Any) -> None:
    """recon 侧在导入期登记某适配器符号（recon→core ✓）。"""
    _ADAPTERS[name] = obj


def get_adapter(name: str) -> Any:
    """按名取出已登记适配器符号（strike 侧调用，strike→core ✓）。

    Raises:
        KeyError: 该符号未登记——通常意味着 `recon.adapters` 包尚未导入。
    """
    obj = _ADAPTERS.get(name)
    if obj is None:
        raise KeyError(f"未登记的 adapter 符号: {name}（recon.adapters 包未导入？）")
    return obj


def get_build_adapter() -> Callable[..., Any]:
    """取用中央适配器构造器 `build_adapter`（REQ-149 IC-2 唯一入口）。"""
    return get_adapter("build_adapter")
