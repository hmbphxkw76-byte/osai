"""core.adapter_registry 接缝单元测试（CP-012 S6 收口）。

验证跨层符号注册表（recon→core ✓ / strike→core ✓）的核心契约：
- `register_adapter` / `get_adapter` 取用往返；
- 未登记符号抛 `KeyError`；
- `get_build_adapter` 取回中央构造器；
- S6 三个跨层符号（AgentCard / get_tls_verify / get_stealth_manager）经 recon.adapters
  导入期登记后可用，使 strike 侧无需静态 import recon 域（strike→recon ✗）。
"""

from __future__ import annotations

import pytest

import recon.adapters  # noqa: F401  # 触发跨层符号登记（recon→core ✓）
from core.adapter_registry import get_adapter, get_build_adapter, register_adapter


def test_register_and_get_roundtrip() -> None:
    register_adapter("__test_dummy__", 42)
    assert get_adapter("__test_dummy__") == 42


def test_get_unknown_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        get_adapter("__test_missing__")


def test_get_build_adapter_returns_callable() -> None:
    # build_adapter 由 recon.adapters 在导入期登记（recon→core ✓）
    assert callable(get_build_adapter())


def test_s6_symbols_registered_via_recon_adapters() -> None:
    assert callable(get_adapter("AgentCard"))
    assert callable(get_adapter("get_tls_verify"))
    assert callable(get_adapter("get_stealth_manager"))
