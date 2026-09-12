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
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strike.strategies.params import (
    algo_params,
    chunked_request_params,
    many_shot_params,
    red_teaming_params,
)


@pytest.fixture
def _ctx() -> SimpleNamespace:
    return SimpleNamespace(objective_target=MagicMock(), args=SimpleNamespace())


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
        from strike.model.filter_bypass import execute_red_teaming_attack

        with patch("pyrit.executor.attack.RedTeamingAttack") as cls:
            cls.return_value.execute_async = AsyncMock(return_value="r")
            asyncio.run(execute_red_teaming_attack(_ctx, "objective"))
        assert cls.call_args.kwargs["max_turns"] == 3

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
            "pair_max_iterations",
            "crescendo_max_backtracks",
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
