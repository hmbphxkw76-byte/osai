"""Companion test for ``core.is_success`` (CP-009 S7).

SSOT ``is_attack_successful`` 现驻 core；本文件验证其口径与向后兼容别名。
"""

from core.is_success import (
    _is_result_success,
    _is_success,
    is_attack_successful,
)


class _FakeResult:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_outcome_success():
    assert is_attack_successful(_FakeResult(outcome="SUCCESS")) is True


def test_outcome_failure():
    assert is_attack_successful(_FakeResult(outcome="FAILURE")) is False


def test_score_value_true():
    assert is_attack_successful(_FakeResult(score_value="true")) is True
    assert is_attack_successful(_FakeResult(score_value=1)) is True


def test_score_value_false():
    assert is_attack_successful(_FakeResult(score_value=0)) is False


def test_scores_list():
    class _Score:
        score_value = 1

    assert is_attack_successful(_FakeResult(scores=[_Score()])) is True


def test_aliases_identity():
    assert _is_success is is_attack_successful
    assert _is_result_success is is_attack_successful
