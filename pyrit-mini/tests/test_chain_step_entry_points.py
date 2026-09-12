# -*- coding: utf-8 -*-
"""tests/test_chain_step_entry_points.py — plan Wave 5 / 执行日志 §14 项 2。

验证 3 个此前「纯类模块、执行器无入口」的链步骤现已补齐 run_* 薄封装，
且 strike/common/chain_executor 能发现并调用它们：
    - strike.rag.data_poisoning   -> run_data_poisoning
    - strike.a2a.card_spoofer     -> run_card_spoofer
    - strike.evasion.audit        -> run_audit_evasion

Constitution: C9（诚实汇报：无活体目标时仅产出种子，不静默跳过）。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from strike.a2a import card_spoofer as a2a_mod
from strike.common.chain_executor import _pick_entry, resolve_module
from strike.evasion import audit as audit_mod
from strike.rag import data_poisoning as rag_mod


def _fake_ctx(**overrides) -> SimpleNamespace:
    """构造最小化 PipelineContext 替身（仅含 run_* 读取的字段）。"""
    args = SimpleNamespace(
        exfil_url="https://attacker.example/collect",
        trigger_domain="attacker.example",
        poison_table="customers",
        poison_kb_entry="sales_process",
        a2a_target_agent="sales-agent.internal",
        a2a_orchestrator_url="",  # 默认不发起真实劫持
    )
    for key, val in overrides.items():
        setattr(args, key, val)
    return SimpleNamespace(args=args, adversarial_target=None)


def test_entry_functions_exist():
    for mod, name in (
        (rag_mod, "run_data_poisoning"),
        (a2a_mod, "run_card_spoofer"),
        (audit_mod, "run_audit_evasion"),
    ):
        assert callable(getattr(mod, name, None)), f"{mod.__name__} 缺少 {name}"


def test_chain_executor_discovers_entries():
    # 模拟组件规划器产出的 action = strike_modules 首模块基名
    assert _pick_entry(rag_mod, "data_poisoning") is rag_mod.run_data_poisoning
    assert _pick_entry(a2a_mod, "card_spoofer") is a2a_mod.run_card_spoofer
    assert _pick_entry(audit_mod, "audit") is audit_mod.run_audit_evasion


def test_resolve_module_routes_to_modules():
    # 注册表已声明这些模块（config/components/*.yaml -> strike_modules）
    assert resolve_module("rag_pipeline", "data_poisoning") == "strike.rag.data_poisoning"
    assert resolve_module("a2a_agent_integrity", "card_spoofer") == "strike.a2a.card_spoofer"
    assert resolve_module("audit_evasion", "audit") == "strike.evasion.audit"


def test_run_data_poisoning_generates_seeds():
    out = asyncio.run(rag_mod.run_data_poisoning(_fake_ctx()))
    assert isinstance(out, dict)
    assert out["count"] > 0
    assert len(out["seeds"]) == out["count"]
    assert all("value" in s and "metadata" in s for s in out["seeds"])


def test_run_card_spoofer_generates_seeds_no_live_hijack():
    out = asyncio.run(a2a_mod.run_card_spoofer(_fake_ctx()))
    assert out["count"] > 0
    assert out["spoof_result"] is None  # 无 orchestrator_url 时不发起真实劫持（C9 诚实）
    assert len(out["seeds"]) == out["count"]


def test_run_audit_evasion_generates_payloads_no_target():
    out = asyncio.run(audit_mod.run_audit_evasion(_fake_ctx()))
    assert out["count"] > 0
    assert out["execution_report"] is None  # 无 adversarial_target 不发起实跑
    assert len(out["seeds"]) == out["count"]
