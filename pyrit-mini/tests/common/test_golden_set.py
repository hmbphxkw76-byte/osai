"""REQ-156 / NFR-16：golden set 量化门禁（FPR / FNR / Cohen's κ）。

只对**确定性（0-token）判定器**做量化断言，保证 CI 可复现；LLM Judge 相关
指标不在此文件（不确定性 → 不入量化门禁）。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml
from pyrit.models import MessagePiece

from assess.impact.exfil import OOBReceiptLog, generate_canary
from assess.impact.verdict import decide_verdict
from assess.semantic_scorers import RetrievalPoisoningScorer, ToolExecutionScorer
from assess.success_levels import classify_success_level

_GOLDEN = Path(__file__).resolve().parent.parent / "golden" / "golden_set.yaml"


def _golden() -> dict:
    return yaml.safe_load(_GOLDEN.read_text(encoding="utf-8"))


def _score(scorer, text: str) -> bool:
    piece = MessagePiece(role="assistant", original_value=text, converted_value=text)
    scores = asyncio.run(scorer._score_piece_async(piece))
    return scores[0].score_value == "true"


def _rates(tp: int, fp: int, fn: int) -> tuple[float, float]:
    fpr = fp / (fp + tp) if (fp + tp) else 0.0  # 在"实际为真"集合上
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return round(fpr, 4), round(fnr, 4)


def _cohens_kappa(y_true: list[bool], y_pred: list[bool]) -> float:
    n = len(y_true)
    if n == 0:
        return 0.0
    po = sum(1 for a, b in zip(y_true, y_pred) if a == b) / n
    p1_t = sum(1 for a in y_true if a) / n
    p1_p = sum(1 for b in y_pred if b) / n
    pe = p1_t * p1_p + (1 - p1_t) * (1 - p1_p)
    if pe == 1.0:
        return 0.0
    return round((po - pe) / (1 - pe), 4)


def _evaluate(scorer, cases: list[dict]) -> tuple[list[bool], list[bool]]:
    y_true, y_pred = [], []
    for case in cases:
        y_true.append(bool(case["expected"]))
        y_pred.append(_score(scorer, str(case["text"])))
    return y_true, y_pred


class TestGoldenSetStructure:
    def test_file_exists_and_has_thresholds(self) -> None:
        data = _golden()
        assert data["schema_version"] == "1.0"
        for key in ("max_false_positive_rate", "max_false_negative_rate", "min_cohens_kappa"):
            assert key in data["thresholds"]

    def test_all_case_groups_present(self) -> None:
        data = _golden()
        for group in ("tool_execution_cases", "retrieval_poisoning_cases", "success_level_cases", "verdict_cases"):
            assert data.get(group), f"golden set 缺少 {group}"


class TestToolExecutionScorerGolden:
    def test_fpr_fnr_kappa_within_thresholds(self) -> None:
        data = _golden()
        y_true, y_pred = _evaluate(ToolExecutionScorer(), data["tool_execution_cases"])
        tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
        fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
        fpr, fnr = _rates(tp, fp, fn)
        kappa = _cohens_kappa(y_true, y_pred)
        thresholds = data["thresholds"]
        assert fpr <= thresholds["max_false_positive_rate"], f"FPR={fpr}"
        assert fnr <= thresholds["max_false_negative_rate"], f"FNR={fnr}"
        assert kappa >= thresholds["min_cohens_kappa"], f"kappa={kappa}"


class TestRetrievalPoisoningScorerGolden:
    def test_fpr_fnr_kappa_within_thresholds(self) -> None:
        data = _golden()
        y_true, y_pred = _evaluate(RetrievalPoisoningScorer(), data["retrieval_poisoning_cases"])
        tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
        fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
        fpr, fnr = _rates(tp, fp, fn)
        kappa = _cohens_kappa(y_true, y_pred)
        thresholds = data["thresholds"]
        assert fpr <= thresholds["max_false_positive_rate"], f"FPR={fpr}"
        assert fnr <= thresholds["max_false_negative_rate"], f"FNR={fnr}"
        assert kappa >= thresholds["min_cohens_kappa"], f"kappa={kappa}"


class TestSuccessLevelGolden:
    def test_all_levels_match(self) -> None:
        data = _golden()
        mismatches = []
        for case in data["success_level_cases"]:
            level = classify_success_level(
                outcome=case["outcome"],
                component_type=case.get("component_type", ""),
                impact_verdict=case.get("impact_verdict") or None,
                text=case.get("text", ""),
            )
            if level != case["expected_level"]:
                mismatches.append((case["text"][:40], case["expected_level"], level))
        assert not mismatches, f"L1–L4 分层不符: {mismatches}"


class TestVerdictGolden:
    def test_all_verdicts_match(self) -> None:
        data = _golden()
        mismatches = []
        for case in data["verdict_cases"]:
            log = OOBReceiptLog()
            if case.get("canary_receipt"):
                canary = generate_canary()
                log.record(canary=canary)
                canaries = [canary]
            else:
                canaries = []
            outcome = decide_verdict(
                response_text=case["response_text"],
                canaries=canaries,
                receipt_log=log,
                side_effect_confirmed=bool(case.get("side_effect_confirmed")),
            )
            if outcome["verdict"] != case["expected"]:
                mismatches.append((case["response_text"][:40], case["expected"], outcome["verdict"]))
        assert not mismatches, f"四态判定不符: {mismatches}"


@pytest.mark.parametrize("group", ["tool_execution_cases", "retrieval_poisoning_cases"])
def test_cases_have_balanced_labels(group: str) -> None:
    """黄金集必须同时含正负样本，否则 FPR/FNR 无意义。"""
    cases = _golden()[group]
    labels = {bool(c["expected"]) for c in cases}
    assert labels == {True, False}, f"{group} 缺少正/负样本"
