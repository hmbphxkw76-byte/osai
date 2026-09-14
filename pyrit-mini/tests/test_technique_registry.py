"""Tests for core.technique_registry — plug-in extension registry."""

from __future__ import annotations

from core.technique_registry import (
    CONVERTER_REGISTRY,
    SCORER_REGISTRY,
    STRATEGY_REGISTRY,
    get_scorer,
    get_strategy_class,
    register_converter,
    register_scorer,
    register_strategy,
    resolve_converters,
)


def test_register_and_resolve_converter() -> None:
    calls: list[object] = []

    @register_converter("MyConv")
    def builder(converter_target: object) -> list[str]:
        calls.append(converter_target)
        return ["c1", "c2"]

    assert CONVERTER_REGISTRY["MyConv"] is builder
    out = resolve_converters(["MyConv"], converter_target="T")
    assert out == ["c1", "c2"]
    assert calls == ["T"]


def test_resolve_unknown_skipped() -> None:
    # Unknown names are skipped (IA-6), never crash.
    assert resolve_converters(["DoesNotExist"]) == []


def test_register_scorer() -> None:
    @register_scorer("my_component")
    def checker(text: str) -> tuple[bool, float, str]:
        return (True, 1.0, "success")

    assert get_scorer("my_component") is checker
    assert SCORER_REGISTRY["my_component"] is checker


def test_register_strategy() -> None:
    class FakeAttack:
        pass

    register_strategy("fake_strat", FakeAttack)
    assert get_strategy_class("fake_strat") is FakeAttack
    assert STRATEGY_REGISTRY["fake_strat"] is FakeAttack
