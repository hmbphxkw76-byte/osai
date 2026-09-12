# -*- coding: utf-8 -*-
"""tests/test_authorization_scope.py — plan Wave 2.9（R-S1 安全边界）回归测试。

此前 `strike/common/decision_safety.py` 只能 `getattr(ctx, "authorized_targets", None)`，
而 `PipelineContext` 上**并无该字段** → 恒 None → 授权边界检查整段被跳过 →
越界攻击静默放行。本测试锁定「字段存在 + 范围匹配唯一实现 + 启动期拒绝」三件事。

Constitution: R-S1（授权目标集合必须被遵守）、C3（单一事实源）、C7（配置数据流不断）、
C9（诚实汇报，禁止静默）。
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.context import (
    collect_target_hosts,
    enforce_authorized_scope,
    is_host_authorized,
    normalize_authorized_targets,
    validate_authorized_scope,
)

# ── 归一（C3：解析只准一份） ────────────────────────────────────────────────


def test_normalize_none_returns_empty():
    assert normalize_authorized_targets(None) == []


def test_normalize_comma_string():
    assert normalize_authorized_targets("A.com, b.com , c.com") == ["a.com", "b.com", "c.com"]


def test_normalize_list_strips_and_lowercases():
    assert normalize_authorized_targets(["  Example.COM ", "a.com", ""]) == ["example.com", "a.com"]


def test_normalize_dedupes_preserving_order():
    assert normalize_authorized_targets("b.com,a.com,b.com") == ["b.com", "a.com"]


def test_normalize_strips_trailing_dot():
    assert normalize_authorized_targets("example.com.") == ["example.com"]


def test_normalize_rejects_unknown_type_loudly():
    """未知类型必须留痕并按「未声明」处理，不得抛异常中断启动。"""
    assert normalize_authorized_targets(12345) == []


# ── 范围匹配 ────────────────────────────────────────────────────────────────


def test_host_authorized_exact_match():
    assert is_host_authorized("api.example.com", ["api.example.com"])


def test_host_authorized_subdomain_of_bare_domain():
    assert is_host_authorized("api.example.com", ["example.com"])


def test_host_authorized_wildcard_form():
    assert is_host_authorized("api.example.com", ["*.example.com"])


def test_host_not_authorized_similar_suffix():
    """`notexample.com` 不得因后缀相似被误判为 `example.com` 的子域。"""
    assert not is_host_authorized("notexample.com", ["example.com"])


def test_host_not_authorized_empty_whitelist():
    """白名单为空表示「未声明」，不做正向授权判定。"""
    assert not is_host_authorized("anything.com", [])


def test_host_not_authorized_empty_host():
    assert not is_host_authorized("", ["example.com"])


# ── 启动期划分 ──────────────────────────────────────────────────────────────


def test_validate_scope_splits_allowed_and_denied():
    allowed, denied = validate_authorized_scope(
        ["a.example.com", "evil.com", "b.example.com"],
        ["example.com"],
    )
    assert allowed == ["a.example.com", "b.example.com"]
    assert denied == ["evil.com"]


def test_validate_scope_undeclared_allows_all_but_caller_must_warn():
    allowed, denied = validate_authorized_scope(["a.com", "b.com"], [])
    assert allowed == ["a.com", "b.com"]
    assert denied == []


# ── 目标 host 采集 ──────────────────────────────────────────────────────────


def test_collect_target_hosts_from_api_endpoint():
    args = SimpleNamespace(
        _burp_list=[],
        target_api_endpoint="https://api.Example.com:8443/v1/chat",
        browser_url=None,
    )
    assert collect_target_hosts(args) == ["api.example.com"]


def test_collect_target_hosts_from_browser_url_without_scheme():
    args = SimpleNamespace(_burp_list=[], target_api_endpoint=None, browser_url="target.local/agent")
    assert collect_target_hosts(args) == ["target.local"]


def test_collect_target_hosts_from_burp_file():
    args = SimpleNamespace(_burp_list=["config/burp/mocka.txt"], target_api_endpoint=None, browser_url=None)
    hosts = collect_target_hosts(args)
    assert hosts, "burp 文件应解析出至少一个 host"


def test_collect_target_hosts_survives_unparsable_burp():
    """解析失败必须留痕并跳过，不得让启动期授权校验整体崩掉（C9）。"""
    args = SimpleNamespace(
        _burp_list=["definitely/not/here.txt"],
        target_api_endpoint=None,
        browser_url=None,
    )
    assert collect_target_hosts(args) == []


# ── decision_safety 真实生效 ────────────────────────────────────────────────


def test_decision_safety_blocks_out_of_scope_target():
    from strike.common.decision_safety import check_decision_safety_boundary

    ctx = SimpleNamespace(authorized_targets=["example.com"])
    ok, reason = check_decision_safety_boundary(ctx, {"target": "evil.com", "strategy": "crescendo"})
    assert ok is False
    assert "authorized" in reason.lower()


def test_decision_safety_allows_in_scope_target():
    from strike.common.decision_safety import check_decision_safety_boundary

    ctx = SimpleNamespace(authorized_targets=["example.com"])
    ok, _ = check_decision_safety_boundary(ctx, {"target": "api.example.com", "strategy": "crescendo"})
    assert ok is True


def test_decision_safety_still_skips_when_undeclared():
    """未声明范围时保持既有放行语义（避免过度阻断），但由 main.py 负责 WARNING 留痕。"""
    from strike.common.decision_safety import check_decision_safety_boundary

    ctx = SimpleNamespace(authorized_targets=[])
    ok, _ = check_decision_safety_boundary(ctx, {"target": "anything.com", "strategy": "crescendo"})
    assert ok is True


# ── C7：defaults.yaml → args ────────────────────────────────────────────────


def test_defaults_yaml_declares_authorized_targets_key():
    from core._config_parsers import _load_defaults

    defaults = _load_defaults()
    assert "authorized_targets" in defaults, "defaults.yaml 缺少 authorized_targets（C7 断链）"


def test_pipeline_context_has_first_class_field():
    """一等字段存在是 decision_safety 能生效的前提（回归此前的恒 None 缺陷）。"""
    from dataclasses import fields

    from core.context import PipelineContext

    assert "authorized_targets" in {f.name for f in fields(PipelineContext)}


# ── 启动期强制拒绝（main.py 实际调用的函数） ────────────────────────────────


def _ctx_stub() -> SimpleNamespace:
    return SimpleNamespace(authorized_targets=[])


def test_enforce_rejects_out_of_scope_target_at_startup():
    """越界目标必须 SystemExit，绝不静默放行（R-S1 / C9）。"""
    ctx = _ctx_stub()
    args = SimpleNamespace(authorized_targets="example.com")
    with patch("core.context.collect_target_hosts", return_value=["evil.com"]):
        with pytest.raises(SystemExit) as exc:
            enforce_authorized_scope(args, ctx)
    assert "evil.com" in str(exc.value)
    assert "AUTHORIZATION" in str(exc.value)


def test_enforce_allows_in_scope_target_and_writes_first_class_field():
    ctx = _ctx_stub()
    args = SimpleNamespace(authorized_targets="example.com")
    with patch("core.context.collect_target_hosts", return_value=["api.example.com"]):
        allowed = enforce_authorized_scope(args, ctx)

    assert allowed == ["api.example.com"]
    # 一等字段被写入 → decision_safety 的边界检查从此真正生效
    assert ctx.authorized_targets == ["example.com"]


def test_enforce_warns_loudly_when_scope_undeclared(caplog):
    """未声明范围时不得静默：必须 WARNING 留痕。"""
    ctx = _ctx_stub()
    args = SimpleNamespace(authorized_targets=None)
    with patch("core.context.collect_target_hosts", return_value=["anything.com"]):
        with caplog.at_level("WARNING", logger="core.context"):
            allowed = enforce_authorized_scope(args, ctx)

    assert allowed == ["anything.com"]
    assert ctx.authorized_targets == []
    assert any("未声明授权范围" in r.getMessage() for r in caplog.records)


def test_enforce_wildcard_scope_matches_subdomain():
    ctx = _ctx_stub()
    args = SimpleNamespace(authorized_targets="*.example.com")
    with patch("core.context.collect_target_hosts", return_value=["deep.sub.example.com"]):
        assert enforce_authorized_scope(args, ctx) == ["deep.sub.example.com"]
