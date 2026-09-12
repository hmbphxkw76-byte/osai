# -*- coding: utf-8 -*-
"""tests/test_algorithm_params.py — plan Wave 4.3 / 4.4 回归测试。

4.3：TAP / PAIR / Crescendo 的算法参数此前分散在 4 / 2 / 3 处硬编码且互不一致
     （TAP depth=3/2/3、width=3/3/5；PAIR max_iterations=5/10），
     而 `config/defaults.yaml` 里声明的 `tap_tree_width` 等键**无人消费**（C7 断链）。
     现统一由 `strike/strategies/params.py` 从 YAML 读取。

4.4：`_is_success` 曾有两套实现——SSOT 用 `score_val > 0`，`progressive_strike`
     用 `bool(score_val)`，负分值得出相反结论（R-H3 违例）。现统一为单一事实源。

Constitution: C3（单一事实源）、C7（配置数据流不可断）、R-H3（成功口径唯一）、
IA-6（未知输入不崩溃）。
"""

from __future__ import annotations

from types import SimpleNamespace

from strike.strategies import algo_params, crescendo_params, pair_params, tap_params

# ── 4.3：参数外置到 YAML ────────────────────────────────────────────────────


def test_crescendo_params_read_from_yaml():
    params = crescendo_params()
    assert "max_backtracks" in params
    assert isinstance(params["max_backtracks"], int)


def test_tap_params_read_from_yaml():
    params = tap_params()
    # P0（2026-09-12）：PyRIT TAPAttack 形参为 tree_width/tree_depth（非 width/depth）。
    assert {"tree_width", "tree_depth", "branching_factor"} <= set(params)
    assert isinstance(params["tree_width"], int) and isinstance(params["tree_depth"], int)
    assert isinstance(params["branching_factor"], int)


def test_pair_params_read_from_yaml():
    # P0：PAIRAttack 无 max_iterations 形参；其迭代深度即 tree_depth。
    params = pair_params()
    assert {"tree_width", "tree_depth"} <= set(params)
    assert isinstance(params["tree_width"], int) and isinstance(params["tree_depth"], int)


def test_yaml_declares_all_algorithm_keys():
    """defaults.yaml 必须声明全部算法参数，否则 SSOT 形同虚设（C7 断链）。"""
    from core._config_parsers import _load_defaults

    defaults = _load_defaults()
    for key in (
        "crescendo_max_backtracks",
        "crescendo_max_turns",
        "tap_tree_width",
        "tap_tree_depth",
        # BL-038 接真（CP-003）：`tap_branching` → TAPAttack(branching_factor=...)
        "tap_branching",
        "pair_tree_width",
        "pair_tree_depth",
    ):
        assert key in defaults, f"defaults.yaml 缺少算法参数 {key}"


def test_args_override_yaml_c7_priority():
    """CLI/配置文件优先级高于 defaults.yaml（C7 单向数据流）。"""
    args = SimpleNamespace(tap_tree_width=9, tap_tree_depth=8, tap_branching=4)
    assert tap_params(args) == {"tree_width": 9, "tree_depth": 8, "branching_factor": 4}


def test_unknown_algorithm_returns_empty_and_does_not_crash(caplog):
    """IA-6：未知算法返回空字典 + 留痕，不抛异常。"""
    with caplog.at_level("WARNING", logger="strike.strategies.params"):
        assert algo_params("not-an-algorithm") == {}
    assert any("未知算法名" in r.getMessage() for r in caplog.records)


def test_params_are_kwargs_compatible_with_pyrit_constructors():
    """参数键名必须与 PyRIT 原生攻击类构造参数一致（C1：不得自研命名）。

    改为**对真实 PyRIT 签名断言**（不再手工抄写键集合）：任何自研命名或 PyRIT
    升级导致的 API 失效都会在此暴露（R-DRIFT-1 的功能侧补强）。
    """
    import inspect

    from pyrit.executor.attack.multi_turn import CrescendoAttack, PAIRAttack, TAPAttack

    cases = (
        (crescendo_params(), CrescendoAttack),
        (tap_params(), TAPAttack),
        (pair_params(), PAIRAttack),
    )
    for params, cls in cases:
        accepted = set(inspect.signature(cls.__init__).parameters)
        unknown = set(params) - accepted
        assert not unknown, f"{cls.__name__} 不接受参数 {sorted(unknown)}（C1：不得自研命名）"


def test_pair_params_default_matches_converged_value():
    """PAIR 的迭代深度 SSOT 收敛：tree_depth 取 pair_tree_depth（消除 5/10 双口径）。"""
    assert pair_params()["tree_depth"] == 4


# ── 4.4：`_is_success` 单一事实源 ───────────────────────────────────────────


def test_progressive_strike_delegates_to_ssot():
    """progressive_strike 不得再有自己的成功判据实现。"""
    from strike.common import progressive_strike
    from utils.attack_utils import is_attack_successful

    negative = SimpleNamespace(outcome=None, score_value=-1, scores=None)
    assert progressive_strike._is_success(negative) is is_attack_successful(negative)


def test_negative_score_is_not_success_under_ssot():
    """SSOT 口径为 `score_val > 0`：负分值判定为失败（旧双轨会判成功）。"""
    from utils.attack_utils import is_attack_successful

    assert is_attack_successful(SimpleNamespace(outcome=None, score_value=-1, scores=None)) is False
    assert is_attack_successful(SimpleNamespace(outcome=None, score_value=1, scores=None)) is True


def test_outcome_takes_precedence_over_score():
    from utils.attack_utils import is_attack_successful

    assert is_attack_successful(SimpleNamespace(outcome="failure", score_value=1, scores=None)) is False
    assert is_attack_successful(SimpleNamespace(outcome="success", score_value=0, scores=None)) is True


def test_scores_dict_form_is_supported_by_ssot():
    """历史模块用 dict[str, Score]，SSOT 必须覆盖该形态（否则各模块又各写一份）。"""
    from utils.attack_utils import is_attack_successful

    assert is_attack_successful(SimpleNamespace(outcome=None, score_value=None, scores={"j": SimpleNamespace(score_value="true")})) is True
    assert is_attack_successful(SimpleNamespace(outcome=None, score_value=None, scores={"j": SimpleNamespace(score_value="false")})) is False


def test_scores_list_form_is_supported_by_ssot():
    from utils.attack_utils import is_attack_successful

    assert is_attack_successful(SimpleNamespace(outcome=None, score_value=None, scores=[SimpleNamespace(score_value="success")])) is True


def test_no_result_is_not_success():
    from utils.attack_utils import is_attack_successful

    assert is_attack_successful(SimpleNamespace(outcome=None, score_value=None, scores=None)) is False


def test_executor_attack_paths_delegates_to_ssot():
    from strike.common._executor_attack_paths import _is_success
    from utils.attack_utils import is_attack_successful

    sample = SimpleNamespace(outcome="success", score_value=None, scores=None)
    assert _is_success(sample) is is_attack_successful(sample)
