"""core.target_factory 接缝单元测试（CP-012 S4 收口）。

验证跨层 Target 工厂（recon→core ✓ / strike→core ✓）的核心契约：
- `register_target` / `build_target` 取用往返；
- 未登记 kind 抛 `KeyError`；
- S4 三个跨层符号（get_shared_bridge / SessionConfig / SessionStateManager）经
  core.adapter_registry 接缝（由 strike 侧导入期登记）供 recon 取用，recon 无需
  静态 import strike 域（recon→strike ✗）。
"""

from __future__ import annotations

import pytest

from core.target_factory import build_target, register_target


def _dummy_factory(*, inner: object, **kwargs: object) -> dict:
    return {"inner": inner, "extra": kwargs}


def test_register_and_build_roundtrip() -> None:
    register_target("__test_dummy__", _dummy_factory)
    obj = build_target("__test_dummy__", inner="adapter", extra=1)
    assert obj == {"inner": "adapter", "extra": {"extra": 1}}


def test_build_unknown_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        build_target("__test_missing__", inner=None)


def test_s4_symbols_registered_via_strike() -> None:
    import recon.adapters  # noqa: F401  # 触发 recon 侧接缝
    import strike.mcp.orchestrator  # noqa: F401  # 触发 strike 侧登记
    import strike.session  # noqa: F401  # 触发 strike 侧登记
    from core.adapter_registry import get_adapter

    assert callable(get_adapter("get_shared_bridge"))
    assert callable(get_adapter("SessionConfig"))
    assert callable(get_adapter("SessionStateManager"))
