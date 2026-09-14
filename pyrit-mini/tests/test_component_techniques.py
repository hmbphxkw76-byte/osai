# -*- coding: utf-8 -*-
"""core.component_techniques 测试（R-DELIVERY-2 补齐：component_techniques 缺配套测试）。

本模块仅做 technique↔component 索引查表，依赖 core.registry 与 tools._purity_baselines。
测试用 monkeypatch 注入确定性数据，不依赖真实注册表状态。
"""
from __future__ import annotations

import pytest

from core import component_techniques as ct


class _FakeSpec:
    def __init__(self, sid: str) -> None:
        self.id = sid


class _FakeRegistry:
    def spec(self, key: str) -> _FakeSpec:
        return _FakeSpec(key)


@pytest.fixture(autouse=True)
def _reset_tech_cache() -> None:
    """模块级 technique→component 缓存跨测试需清零，否则 monkeypatch _baselines 不生效。"""
    ct._technique_to_component = None
    yield
    ct._technique_to_component = None


@pytest.fixture
def fake_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """令 required_techniques_for 走 FakeRegistry（key → id 恒等）。"""
    monkeypatch.setattr("core.registry.get_registry", lambda: _FakeRegistry())


def test_component_id_for_technique_unknown_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ct, "_baselines", lambda: {})
    assert ct.component_id_for_technique("__no_such_technique__") is None


def test_component_id_for_technique_known(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ct,
        "_baselines",
        lambda: {
            "mcp": {"required_techniques": ["tool_poisoning", "schema_poisoning"]},
            "web": {"required_techniques": ["prompt_injection"]},
        },
    )
    assert ct.component_id_for_technique("tool_poisoning") == "mcp"
    assert ct.component_id_for_technique("schema_poisoning") == "mcp"
    assert ct.component_id_for_technique("prompt_injection") == "web"
    # 未知 technique 仍返回 None
    assert ct.component_id_for_technique("does_not_exist") is None


def test_required_techniques_for(
    fake_registry: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ct,
        "_baselines",
        lambda: {"web": {"required_techniques": ["prompt_injection", "xss"]}},
    )
    assert ct.required_techniques_for("web") == ["prompt_injection", "xss"]
    # techniques_for_component 为语义别名，行为一致
    assert ct.techniques_for_component("web") == ["prompt_injection", "xss"]


def test_required_techniques_for_missing(
    fake_registry: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ct, "_baselines", lambda: {})
    assert ct.required_techniques_for("nope") == []
    assert ct.techniques_for_component("nope") == []


def test_baselines_unavailable_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    """tools._purity_baselines 不可用时 _baselines 退化为 {}，零回归。"""
    import builtins

    real_import = builtins.__import__

    def _blocked(name: str, *args, **kwargs):
        if name == "tools._purity_baselines" or name.startswith("tools._purity_baselines."):
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked)
    assert ct._baselines() == {}
