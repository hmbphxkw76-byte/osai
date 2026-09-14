"""Companion test for ``core.t0_text_checks`` (CP-009 S2).

验证 T0 文本判定（拒答 / 非实质 / 置信度）下沉 core 后行为不变。
"""

from core.t0_text_checks import (
    _t0_confidence_score,
    _t0_non_substantive_check_text,
    _t0_refusal_check_text,
)


def test_refusal_detected():
    assert _t0_refusal_check_text("I'm sorry, I cannot help with that.") is True


def test_refusal_clean():
    assert _t0_refusal_check_text("Here is the step-by-step recipe.") is False


def test_non_substantive():
    # 命中 _NON_SUBSTANTIVE_PATTERNS 的真实样例（占位/无实质应答）。
    assert _t0_non_substantive_check_text("placeholder response") is True
    assert _t0_non_substantive_check_text("I understand.") is True
    # 真实内容不应判为非实质。
    assert (
        _t0_non_substantive_check_text(
            "The SQL injection payload is ' OR 1=1 -- and it bypasses the filter."
        )
        is False
    )


def test_confidence_score_range():
    status, score = _t0_confidence_score(
        "The answer is 42 because of X and Y and Z.", "the answer is 42"
    )
    assert status in {"success", "failure", "uncertain"}
    assert 0.0 <= score <= 1.0
