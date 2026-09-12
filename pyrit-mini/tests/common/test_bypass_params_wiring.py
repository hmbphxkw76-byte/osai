"""BL-034 接真回归：bypass 三类攻击参数经 SSOT 传入 PyRIT 原生攻击类。

缺陷背景（C7/C9）：`many_shot_example_count` / `chunked_request_chunk_size` /
`chunked_request_total_length` / `red_teaming_max_turns` 四键此前仅被
`_apply_defaults` 拷进 `args`，**无任何消费者**；而 `utils/display.py` 侧的标签表
声称展示这些参数 —— 造成"终端展示数值 ≠ 攻击实际取值"的不实呈现。
现统一经 `strike.strategies.params` 读取并传入 PyRIT 原生攻击类。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strike.strategies.params import (
    algo_params,
    chunked_request_params,
    many_shot_params,
    red_teaming_params,
)


@pytest.fixture
def pyrit_memory():
    """PyRIT 1.0.1 的 `AttackAdversarialConfig` / `AttackScoringConfig` 构造需要已初始化的 CentralMemory。

    CentralMemory 是进程级 singleton，用内存库挂上、测试后还原（与
    `tests/test_native_attack_construction.py` 同款做法）。
    """
    from pyrit.memory import CentralMemory, SQLiteMemory

    previous = getattr(CentralMemory, "_memory_instance", None)
    CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:"))
    try:
        yield CentralMemory.get_memory_instance()
    finally:
        CentralMemory._memory_instance = previous


def _make_target():
    """构造声明了多轮 + 系统提示能力的哑目标（PyRIT 1.0.1 会校验能力）。"""
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


@pytest.fixture
def _ctx(pyrit_memory) -> SimpleNamespace:
    # I5 三角色分离：需要对抗侧 LLM 的原生攻击（RedTeaming/Crescendo/TAP/PAIR）
    # 必须能从 ctx 取到 adversarial_target，否则适配器会显式降级（不得静默）。
    # 该目标必须是真实 PromptTarget 子类（AttackAdversarialConfig 会做 pydantic 校验），
    # 故用声明了能力的 TextTarget 而非 MagicMock。
    return SimpleNamespace(
        objective_target=_make_target(),
        adversarial_target=_make_target(),
        args=SimpleNamespace(),
    )


class TestSpecsRegistration:
    def test_new_algorithms_registered(self) -> None:
        for name in ("many_shot", "chunked_request", "red_teaming"):
            assert algo_params(name) != {}, f"{name} 未登记进 _SPECS"

    def test_values_come_from_defaults_yaml(self) -> None:
        assert many_shot_params()["example_count"] == 100
        assert chunked_request_params()["chunk_size"] == 50
        assert chunked_request_params()["total_length"] == 200
        assert red_teaming_params()["max_turns"] == 3

    def test_args_override_yaml(self) -> None:
        args = SimpleNamespace(many_shot_example_count=7, red_teaming_max_turns=9)
        assert many_shot_params(args)["example_count"] == 7
        assert red_teaming_params(args)["max_turns"] == 9


class TestExecutorWiring:
    """断言参数**真的**到达 PyRIT 攻击类构造（不是只存在于 args）。"""

    def test_many_shot_passes_example_count(self, _ctx: SimpleNamespace) -> None:
        from strike.model.filter_bypass import execute_many_shot_attack

        with patch("pyrit.executor.attack.ManyShotJailbreakAttack") as cls:
            cls.return_value.execute_async = AsyncMock(return_value="r")
            asyncio.run(execute_many_shot_attack(_ctx, "objective"))
        assert cls.call_args.kwargs["example_count"] == 100
        assert cls.call_args.kwargs["objective_target"] is _ctx.objective_target

    def test_chunked_passes_chunk_size_and_total_length(self, _ctx: SimpleNamespace) -> None:
        from strike.model.filter_bypass import execute_chunked_request_attack

        with patch("pyrit.executor.attack.ChunkedRequestAttack") as cls:
            cls.return_value.execute_async = AsyncMock(return_value="r")
            asyncio.run(execute_chunked_request_attack(_ctx, "objective"))
        assert cls.call_args.kwargs["chunk_size"] == 50
        assert cls.call_args.kwargs["total_length"] == 200

    def test_red_teaming_passes_max_turns(self, _ctx: SimpleNamespace) -> None:
        import inspect

        from pyrit.executor.attack import RedTeamingAttack

        from strike.model.filter_bypass import execute_red_teaming_attack

        # 捕获真实构造参数：包装 __init__ 但要**保留真实签名**，否则适配器
        # `accepted_kwargs` 读不到 max_turns（R-DRIFT-1 会把合法参数当漂移剔掉）。
        captured: dict[str, Any] = {}
        real_init = RedTeamingAttack.__init__
        real_sig = inspect.signature(real_init)

        def _spy_init(self: Any, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)
            real_init(self, *args, **kwargs)

        _spy_init.__signature__ = real_sig  # 关键：让 inspect.signature 返回真实签名

        with patch.object(RedTeamingAttack, "execute_async", new=AsyncMock(return_value="r")):
            with patch.object(RedTeamingAttack, "__init__", _spy_init):
                asyncio.run(execute_red_teaming_attack(_ctx, "objective"))
        assert captured["max_turns"] == 3
        assert "attack_adversarial_config" in captured
        assert "attack_scoring_config" in captured

    def test_ctx_args_override_reaches_attack(self, _ctx: SimpleNamespace) -> None:
        from strike.model.filter_bypass import execute_many_shot_attack

        _ctx.args = SimpleNamespace(many_shot_example_count=11)
        with patch("pyrit.executor.attack.ManyShotJailbreakAttack") as cls:
            cls.return_value.execute_async = AsyncMock(return_value="r")
            asyncio.run(execute_many_shot_attack(_ctx, "objective"))
        assert cls.call_args.kwargs["example_count"] == 11

    def test_ctx_without_args_falls_back_to_yaml(self) -> None:
        from strike.model.filter_bypass import execute_many_shot_attack

        ctx = SimpleNamespace(objective_target=MagicMock())  # 无 args 属性
        with patch("pyrit.executor.attack.ManyShotJailbreakAttack") as cls:
            cls.return_value.execute_async = AsyncMock(return_value="r")
            asyncio.run(execute_many_shot_attack(ctx, "objective"))
        assert cls.call_args.kwargs["example_count"] == 100


class TestDeadKeysRemoved:
    """BL-034：功能不存在的死键必须已从 defaults.yaml 摘除（R-H1）。"""

    @pytest.mark.parametrize(
        "key",
        [
            "bon_persuasion_count",
            "cair_max_iterations",
            "cair_success_threshold",
            "cair_enable_llm_mutation",
            "tap_branching_factor",
            "dos_attack_enabled",
            "dos_max_payload_size",
            "dos_max_concurrent",
            "auto_l4_optimization_enabled",
            "auto_l4_confidence_threshold",
            "auto_l4_max_seeds",
            "auto_l4_agent_surfaces",
        ],
    )
    def test_key_absent(self, key: str) -> None:
        from core._config_parsers import _load_defaults

        assert key not in _load_defaults(), f"{key} 仍在 defaults.yaml（BL-034 未闭环）"

    def test_attack_params_survive(self) -> None:
        """摘除死键不得影响仍被消费的 L5 参数（NEG-6 精神）。"""
        from core._config_parsers import _load_defaults

        defaults = _load_defaults()
        for key in (
            "best_of_n_retries",
            "tap_tree_width",
            "tap_tree_depth",
            "pair_tree_width",
            "pair_tree_depth",
            "crescendo_max_backtracks",
            "crescendo_max_turns",
            "many_shot_example_count",
            "chunked_request_chunk_size",
            "chunked_request_total_length",
            "red_teaming_max_turns",
            "target_asr",
            "max_attempts",
            "max_seeds",
        ):
            assert key in defaults, f"误删 L5 参数 {key}"

    def test_no_dangling_label_references(self) -> None:
        """标签表不得引用已不存在的参数键（避免二次断链）。"""
        from core._config_parsers import _load_defaults

        defaults = _load_defaults()
        labels = defaults.get("technique_param_labels") or {}
        dangling = [k for k in labels if k not in defaults]
        assert not dangling, f"technique_param_labels 引用不存在的键: {dangling}"
