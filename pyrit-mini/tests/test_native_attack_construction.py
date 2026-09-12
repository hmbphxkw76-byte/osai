# -*- coding: utf-8 -*-
"""tests/test_native_attack_construction.py — 原生多轮攻击构造契约回归。

**为什么需要本文件（2026-09-12 P0 缺陷）**
    PyRIT 1.0.1 的 `CrescendoAttack` / `TAPAttack` / `PAIRAttack` / `RedTeamingAttack`
    构造函数把 `attack_adversarial_config` 设为**必填**（无默认值），且
        - TAP/PAIR 的树参数为 `tree_width` / `tree_depth`（**不是** `width` / `depth`）
        - PAIRAttack **不存在** `max_iterations`
    本仓库此前所有调用点都按 0.x API 传参，构造必然抛异常，异常又被外层
    `try/except` 静默吞掉 —— L2/L3/L4 升级链与渐进式多轮**从未真正执行**。

    本测试把"参数名 + 必填项"做成**对真实 PyRIT 签名的断言**，
    任何一处再次漂移都会红灯，而不是静默退化（R-DRIFT-1 + C9）。

Constitution: C1（PyRIT 原生优先）、I5（三角色分离）、C9（诚实汇报）、R-DRIFT-1。
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from strike.strategies import crescendo_params, pair_params, red_teaming_params, tap_params
from strike.strategies.adversarial import (
    accepted_kwargs,
    build_adversarial_config,
    build_native_attack_kwargs,
)

# 需要对抗侧 LLM 的原生多轮攻击类
_ADVERSARIAL_ATTACKS = (
    ("pyrit.executor.attack.multi_turn", "CrescendoAttack", crescendo_params),
    ("pyrit.executor.attack.multi_turn", "TAPAttack", tap_params),
    ("pyrit.executor.attack.multi_turn", "PAIRAttack", pair_params),
    ("pyrit.executor.attack", "RedTeamingAttack", red_teaming_params),
)


def _import_cls(module_path: str, cls_name: str):
    import importlib

    return getattr(importlib.import_module(module_path), cls_name)


def _make_multi_turn_target():
    """构造一个声明了多轮 + 系统提示能力的哑目标（PyRIT 1.0.1 会校验能力）。

    多轮攻击类会做 `TargetRequirements` 校验：目标必须**原生**支持
    `supports_multi_turn` / `supports_system_prompt`，否则直接 raise。
    生产目标（`HTTPTarget`）具备这些能力；测试中用 `TextTarget` + 自定义
    `TargetConfiguration` 复刻同样的能力声明。
    """
    from pyrit.prompt_target import TextTarget
    from pyrit.prompt_target.common.target_capabilities import TargetCapabilities
    from pyrit.prompt_target.common.target_configuration import TargetConfiguration

    capabilities = TargetCapabilities(
        supports_multi_turn=True,
        supports_multi_message_pieces=True,
        supports_editable_history=True,
        supports_system_prompt=True,
    )
    return TextTarget(custom_configuration=TargetConfiguration(capabilities=capabilities))


# ── 1. 参数名必须与 PyRIT 构造形参逐字一致（C1）──────────────────────────────


@pytest.mark.parametrize("module_path,cls_name,params_fn", _ADVERSARIAL_ATTACKS)
def test_params_are_accepted_by_pyrit_constructor(module_path, cls_name, params_fn):
    """算法参数字典里不允许出现 PyRIT 不接受的键（静默失败的主要来源）。"""
    cls = _import_cls(module_path, cls_name)
    accepted = set(inspect.signature(cls.__init__).parameters)
    unknown = set(params_fn()) - accepted
    assert not unknown, f"{cls_name} 不接受 {sorted(unknown)}（R-DRIFT-1 漂移）"


@pytest.mark.parametrize("module_path,cls_name,params_fn", _ADVERSARIAL_ATTACKS)
def test_adversarial_config_is_required_and_supplied(module_path, cls_name, params_fn):
    """必填的 `attack_adversarial_config` 必须由适配器注入。"""
    cls = _import_cls(module_path, cls_name)
    signature = inspect.signature(cls.__init__)
    assert "attack_adversarial_config" in signature.parameters, (
        f"{cls_name} 的签名已变化，本断言需同步（PyRIT 升级）"
    )

    ctx = SimpleNamespace(adversarial_target=SimpleNamespace())
    kwargs = build_native_attack_kwargs(ctx, cls, params_fn())
    assert kwargs is not None, f"{cls_name} 构造参数组装失败（I5 三角色分离）"
    assert "attack_adversarial_config" in kwargs


# ── 2. 缺失对抗侧目标必须显式失败，不得静默 ──────────────────────────────────


@pytest.mark.parametrize("module_path,cls_name,params_fn", _ADVERSARIAL_ATTACKS)
def test_missing_adversarial_target_returns_none(module_path, cls_name, params_fn):
    """无 adversarial_target → 返回 None（调用方据此留痕），不得假装成功。"""
    cls = _import_cls(module_path, cls_name)
    ctx = SimpleNamespace(adversarial_target=None)
    assert build_native_attack_kwargs(ctx, cls, params_fn()) is None


def test_build_adversarial_config_uses_ctx_adversarial_target():
    """I5：对抗侧目标只准取自 ctx.adversarial_target。"""
    sentinel = SimpleNamespace(name="adversarial")
    config = build_adversarial_config(SimpleNamespace(adversarial_target=sentinel))
    assert config is not None and config.target is sentinel


def test_build_adversarial_config_missing_target_logs_warning(caplog):
    """C9：能力缺失必须 WARNING 留痕，禁止静默。"""
    with caplog.at_level("WARNING", logger="strike.strategies.adversarial"):
        assert build_adversarial_config(SimpleNamespace(adversarial_target=None)) is None
    assert any("adversarial_target" in r.getMessage() for r in caplog.records)


# ── 3. 真实构造：用哑目标实例化，确保不再抛异常 ──────────────────────────────


@pytest.fixture
def pyrit_memory():
    """PyRIT 1.0.1 的 `PromptTarget.__init__` 要求已初始化的 CentralMemory。

    CentralMemory 是进程级 singleton，故用 fixture 挂一个内存库并在结束后还原
    （与 `tests/common/test_adapters.py` 同款做法）。
    """
    from pyrit.memory import CentralMemory, SQLiteMemory

    previous = getattr(CentralMemory, "_memory_instance", None)
    CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:"))
    try:
        yield CentralMemory.get_memory_instance()
    finally:
        CentralMemory._memory_instance = previous


@pytest.mark.parametrize("module_path,cls_name,params_fn", _ADVERSARIAL_ATTACKS)
def test_native_attack_can_be_constructed_with_dummy_targets(
    pyrit_memory, module_path, cls_name, params_fn
):
    """端到端构造：objective_target + adversarial_target 均为哑对象时也**不得抛异常**。

    这是本次缺陷的核心回归点——此前构造必抛 TypeError。
    """
    cls = _import_cls(module_path, cls_name)
    ctx = SimpleNamespace(
        adversarial_target=_make_multi_turn_target(),
        objective_target=_make_multi_turn_target(),
    )
    kwargs = build_native_attack_kwargs(ctx, cls, params_fn())
    assert kwargs is not None

    attack = cls(objective_target=_make_multi_turn_target(), **kwargs)  # 不抛异常即通过
    assert attack is not None


# ── 4. 参数过滤器的防御语义 ──────────────────────────────────────────────────


def test_accepted_kwargs_drops_unknown_and_logs(caplog):
    """未知参数被剔除且留痕（漂移必须被人看见）。"""
    cls = _import_cls("pyrit.executor.attack.multi_turn", "TAPAttack")
    with caplog.at_level("WARNING", logger="strike.strategies.adversarial"):
        kept = accepted_kwargs(cls, {"tree_width": 3, "not_a_param": 1})
    assert kept == {"tree_width": 3}
    assert any("not_a_param" in r.getMessage() for r in caplog.records)


def test_skeleton_key_attack_needs_no_adversarial_config():
    """SkeletonKeyAttack 无对抗侧要求 —— 只会被注入 0-token 评分配置（I2）。"""
    from pyrit.executor.attack import SkeletonKeyAttack

    kwargs = build_native_attack_kwargs(SimpleNamespace(), SkeletonKeyAttack, {})
    assert "attack_adversarial_config" not in kwargs
    # I2：攻击执行路径一律带 0-token 评分器，不得为 LLM 评分器
    assert "attack_scoring_config" in kwargs
