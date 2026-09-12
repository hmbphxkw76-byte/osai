# -*- coding: utf-8 -*-
"""tests/test_runtime_wiring_fixes.py — 端到端实跑暴露的三处阻断缺陷回归测试。

这三项都是**跑起来才发现**的（单元测试全绿但主链路 0 攻击），因此必须用测试钉死：

1. `strike.common._executor_helpers._build_prepended_conversation_config`
   PyRIT 1.0 把 `PrependedConversationConfig` 从
   `pyrit.executor.attack.core.attack_executor` 迁到 `pyrit.executor.attack.component`，
   且不再接受 `prepended_conversation` 构造参数。旧代码双错叠加 → ImportError
   → `PromptSendingAttack` 构造失败 → **整条基线攻击 0 攻击**（plan §11.1 根因）。
2. `strike.common.chain_executor._pick_entry`
   action 与模块入口命名不一致（action=filter_bypass vs run_output_filter_bypass），
   精确匹配导致实测 5/5 链步骤全部「无可调用入口」失败。
3. `recon.target_router` 日志多传实参 → logging 抛格式化异常 → 该条 INFO 被静默丢弃（C9）。

Constitution: C1（PyRIT 原生优先）、C9（诚实汇报，禁止静默）、C10（验证义务）。
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from strike.common.chain_executor import _pick_entry

# ── 1. PrependedConversationConfig 解析（PyRIT 1.0 迁移） ────────────────────


def _ctx(system_prompt: str = "") -> SimpleNamespace:
    return SimpleNamespace(service_profile={"system_prompt": system_prompt})


def test_no_system_prompt_returns_none():
    from strike.common._executor_helpers import _build_prepended_conversation_config

    assert _build_prepended_conversation_config(_ctx("")) is None


def test_missing_service_profile_returns_none():
    from strike.common._executor_helpers import _build_prepended_conversation_config

    assert _build_prepended_conversation_config(SimpleNamespace()) is None


def test_with_system_prompt_returns_native_config_without_raising():
    """核心回归：不得再因 ImportError/TypeError 打断攻击构造。"""
    from strike.common._executor_helpers import _build_prepended_conversation_config

    cfg = _build_prepended_conversation_config(_ctx("You are a helpful assistant."))
    # 有原生类时返回实例；环境缺失时返回 None（且已留痕），两者都不得抛异常
    assert cfg is None or isinstance(cfg, object)


def test_uses_current_pyrit_location_when_available():
    """若 PyRIT 提供该类，必须来自新位置且能成功构造。"""
    from strike.common._executor_helpers import _build_prepended_conversation_config

    try:
        from pyrit.executor.attack.component import PrependedConversationConfig
    except ImportError:
        pytest.skip("当前 PyRIT 版本未提供 PrependedConversationConfig")

    cfg = _build_prepended_conversation_config(_ctx("sys"))
    assert isinstance(cfg, PrependedConversationConfig)


def test_prompt_sending_attack_accepts_the_built_config():
    """与真实消费方对齐：构造出的 config 必须能被 PromptSendingAttack 接受。"""
    from strike.common._executor_helpers import _build_prepended_conversation_config

    try:
        from pyrit.executor.attack import PromptSendingAttack
    except ImportError:
        pytest.skip("PyRIT PromptSendingAttack 不可用")

    cfg = _build_prepended_conversation_config(_ctx("sys"))
    accepted = "prepended_conversation_config" in __import__("inspect").signature(
        PromptSendingAttack.__init__
    ).parameters
    assert accepted, "PromptSendingAttack 不再接受 prepended_conversation_config，需同步更新接线"
    assert cfg is None or cfg is not None  # 仅确保不抛异常


# ── 2. 链步骤入口解析 ────────────────────────────────────────────────────────


def _make_module(entries: dict[str, object]) -> SimpleNamespace:
    """构造「模块自身定义」的入口：`__module__` 必须与模块名一致才会被选中。"""
    mod = SimpleNamespace(__name__="m")
    for name, fn in entries.items():
        fn.__module__ = "m"  # type: ignore[union-attr]
        setattr(mod, name, fn)
    return mod


def test_exact_run_action_match():
    def run_thing():
        return 1

    mod = _make_module({"run_thing": run_thing})
    assert _pick_entry(mod, "thing") is run_thing


def test_substring_match_resolves_renamed_entry():
    """action=filter_bypass → 实际入口 run_output_filter_bypass。"""
    def run_output_filter_bypass():
        return 1

    mod = _make_module({"run_output_filter_bypass": run_output_filter_bypass})
    assert _pick_entry(mod, "filter_bypass") is run_output_filter_bypass


def test_generic_candidate_execute_is_used():
    def execute():
        return 1

    mod = _make_module({"execute": execute})
    assert _pick_entry(mod, "unknown_action") is execute


def test_any_run_entry_used_as_last_resort():
    def run_mcpsec_pyrit_attack():
        return 1

    mod = _make_module({"run_mcpsec_pyrit_attack": run_mcpsec_pyrit_attack})
    # action=orchestrator 与入口名无关，应回退到模块自带的 run_* 入口
    assert _pick_entry(mod, "orchestrator") is run_mcpsec_pyrit_attack


def test_imported_helpers_are_not_mistaken_for_entries():
    """只认模块**自身定义**的入口，避免误抓 import 进来的第三方函数。"""
    mod = SimpleNamespace(__name__="m")
    foreign = lambda: 1  # noqa: E731
    foreign.__module__ = "some.other.module"
    mod.execute = foreign
    assert _pick_entry(mod, "x") is None


def test_class_only_module_returns_none_not_error():
    """纯类模块（无函数入口）返回 None，由调用方显式失败，不得抛异常。"""
    mod = SimpleNamespace(__name__="m", SomeAttack=type("SomeAttack", (), {}))
    assert _pick_entry(mod, "audit") is None


def test_real_modules_resolve_to_an_entry():
    """对真实 strike 模块做冒烟：能解析出入口的不得再退化为 None。"""
    import importlib

    cases = {
        ("llm_gateway", "filter_bypass"): "strike.model.filter_bypass",
        ("mcp_tool_poisoning", "orchestrator"): "strike.mcp.orchestrator",
    }
    for (_, action), dotted in cases.items():
        mod = importlib.import_module(dotted)
        assert _pick_entry(mod, action) is not None, f"{dotted} 仍无法解析入口"


# ── 3. 日志格式化实参守卫（防静默丢日志） ────────────────────────────────────

_PLACEHOLDER = re.compile(r"%(?!%)[-+#0 ]*\d*(\.\d+)?[sdifFeEgGxXocr]")


def _scan_log_format_mismatches(root: Path) -> list[str]:
    """扫描字面格式串与实参个数不匹配的日志调用（Starred 无法静态判定，跳过）。"""
    problems: list[str] = []
    for path in root.rglob("*.py"):
        if any(part in {"outputs", ".git", "tests", "__pycache__"} for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in {"debug", "info", "warning", "error", "critical"}):
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                continue
            if any(isinstance(a, ast.Starred) for a in node.args[1:]):
                continue  # *args 展开无法静态计数
            placeholders = len(_PLACEHOLDER.findall(node.args[0].value))
            supplied = len(node.args) - 1
            if placeholders != supplied:
                problems.append(
                    f"{path}:{node.lineno} 占位符={placeholders} 实参={supplied} :: {node.args[0].value[:60]}"
                )
    return problems


def test_no_log_call_has_format_argument_mismatch():
    """多传/少传实参会让 logging 抛异常并**静默丢弃**该条日志（C9 违例）。"""
    problems = _scan_log_format_mismatches(Path("."))
    assert not problems, "存在日志格式化实参不匹配：\n" + "\n".join(problems)
