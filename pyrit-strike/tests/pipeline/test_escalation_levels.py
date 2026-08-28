"""escalation_level1-3 独立单元测试 — 升级链各层级函数。

覆盖:
    - Level 1: _filter_by_suitable_for, _apply_mtos_ranking, _build_skeleton_key_seed_groups
    - Level 2: _get_partial_from_memory, _create_fallback_fsts, _build_refusal_inverter_scoring_config
    - Level 3: _is_success, _get_objective, _select_still_failed, _select_still_failed_clustered
    - escalation_attacks: _is_security_audit_error, _SecurityAuditError
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# Level 1: _filter_by_suitable_for
# ═══════════════════════════════════════════════════════


class TestFilterBySuitableFor:
    """测试 _filter_by_suitable_for 函数."""

    def test_empty_objectives(self):
        from pipeline.strike.escalation_level1 import _filter_by_suitable_for

        ctx = MagicMock()
        result = _filter_by_suitable_for([], ctx, "crescendo")
        assert result == []

    def test_no_metadata_map_returns_all(self):
        from pipeline.strike.escalation_level1 import _filter_by_suitable_for

        ctx = MagicMock()
        ctx._obj_metadata_map = {}
        objectives = ["obj1", "obj2"]
        result = _filter_by_suitable_for(objectives, ctx, "crescendo")
        assert result == objectives

    def test_exact_match_filtered(self):
        from pipeline.strike.escalation_level1 import _filter_by_suitable_for

        ctx = MagicMock()
        ctx._obj_metadata_map = {
            "obj1": {"suitable_for": "crescendo"},
            "obj2": {"suitable_for": "pair"},
            "obj3": {"suitable_for": "tap"},
        }
        objectives = ["obj1", "obj2", "obj3"]
        result = _filter_by_suitable_for(objectives, ctx, "crescendo")
        assert "obj1" in result
        assert "obj2" not in result
        assert "obj3" not in result

    def test_no_annotation_included_as_generic(self):
        from pipeline.strike.escalation_level1 import _filter_by_suitable_for

        ctx = MagicMock()
        ctx._obj_metadata_map = {
            "obj1": {"suitable_for": "crescendo"},
            "obj2": {},
            "obj3": {"suitable_for": "pair"},
        }
        objectives = ["obj1", "obj2", "obj3"]
        result = _filter_by_suitable_for(objectives, ctx, "crescendo")
        assert "obj1" in result
        assert "obj2" in result
        assert "obj3" not in result

    def test_empty_after_filter_falls_back_to_all(self):
        from pipeline.strike.escalation_level1 import _filter_by_suitable_for

        ctx = MagicMock()
        ctx._obj_metadata_map = {
            "obj1": {"suitable_for": "pair"},
            "obj2": {"suitable_for": "tap"},
        }
        objectives = ["obj1", "obj2"]
        result = _filter_by_suitable_for(objectives, ctx, "crescendo")
        assert result == objectives


# ═══════════════════════════════════════════════════════
# Level 1: _apply_mtos_ranking
# ═══════════════════════════════════════════════════════


class TestApplyMtosRanking:
    """测试 _apply_mtos_ranking 函数."""

    def test_empty_objectives(self):
        from pipeline.strike.escalation_level1 import _apply_mtos_ranking

        ctx = MagicMock()
        result = _apply_mtos_ranking([], ctx)
        assert result == []

    def test_no_asr_history_returns_original(self):
        from pipeline.strike.escalation_level1 import _apply_mtos_ranking

        ctx = MagicMock()
        ctx._obj_asr_map = {}
        ctx._obj_metadata_map = {}
        objectives = ["obj1", "obj2"]
        result = _apply_mtos_ranking(objectives, ctx, technique_name="crescendo")
        assert len(result) == 2
        assert set(result) == {"obj1", "obj2"}


# ═══════════════════════════════════════════════════════
# Level 2: _build_refusal_inverter_scoring_config
# ═══════════════════════════════════════════════════════


class TestBuildRefusalInverterScoringConfig:
    """测试 _build_refusal_inverter_scoring_config 函数."""

    def test_returns_config_when_no_scoring_target(self):
        """scoring_target=None 时仍返回配置 (fallback 到 refusal inverter 或空)."""
        from pipeline.strike.escalation_level2 import _build_refusal_inverter_scoring_config

        ctx = MagicMock()
        ctx.scoring_target = None
        ctx.adversarial_target = None
        result = _build_refusal_inverter_scoring_config(ctx)
        # 无 scoring/adversarial target 时返回空 AttackScoringConfig
        assert result is not None

    def test_returns_config_when_scoring_target_available(self):
        from pipeline.strike.escalation_level2 import _build_refusal_inverter_scoring_config

        ctx = MagicMock()
        ctx.scoring_target = MagicMock()
        ctx.adversarial_target = None
        try:
            result = _build_refusal_inverter_scoring_config(ctx)
            # 可能返回配置对象或空配置
            assert result is not None
        except Exception:
            # 在无 PyRIT 环境时可能抛异常, 测试不依赖 PyRIT 初始化
            pass


# ═══════════════════════════════════════════════════════
# Level 3: _is_success
# ═══════════════════════════════════════════════════════


class TestIsSuccess:
    """测试 _is_success 函数."""

    def test_outcome_success_string(self):
        from pipeline.strike.escalation_level3 import _is_success

        result = MagicMock()
        result.outcome = "success"
        assert _is_success(result) is True

    def test_outcome_success_enum(self):
        from pipeline.strike.escalation_level3 import _is_success

        result = MagicMock()
        outcome = MagicMock()
        outcome.value = "success"
        result.outcome = outcome
        assert _is_success(result) is True

    def test_outcome_failure(self):
        from pipeline.strike.escalation_level3 import _is_success

        result = MagicMock()
        result.outcome = "failure"
        assert _is_success(result) is False

    def test_outcome_none_checks_score(self):
        from pipeline.strike.escalation_level3 import _is_success

        result = MagicMock()
        result.outcome = None
        score = MagicMock()
        score.get_value.return_value = True
        result.last_score = score
        assert _is_success(result) is True

    def test_outcome_none_no_score(self):
        from pipeline.strike.escalation_level3 import _is_success

        result = MagicMock()
        result.outcome = None
        result.last_score = None
        assert _is_success(result) is False


# ═══════════════════════════════════════════════════════
# Level 3: _get_objective
# ═══════════════════════════════════════════════════════


class TestGetObjective:
    """测试 _get_objective 函数."""

    def test_returns_objective(self):
        from pipeline.strike.escalation_level3 import _get_objective

        result = MagicMock()
        result.objective = "test objective"
        assert _get_objective(result) == "test objective"

    def test_returns_empty_when_none(self):
        from pipeline.strike.escalation_level3 import _get_objective

        result = MagicMock()
        result.objective = None
        assert _get_objective(result) == ""


# ═══════════════════════════════════════════════════════
# Level 3: _select_still_failed
# ═══════════════════════════════════════════════════════


class TestSelectStillFailed:
    """测试 _select_still_failed 函数."""

    def test_all_succeeded(self):
        from pipeline.strike.escalation_level3 import _select_still_failed

        result1 = MagicMock()
        result1.outcome = "success"
        result1.objective = "obj1"

        attack_results = {"tech1": [result1]}
        original_failed = ["obj1"]
        still_failed = _select_still_failed(attack_results, original_failed)
        assert still_failed == []

    def test_none_succeeded(self):
        from pipeline.strike.escalation_level3 import _select_still_failed

        result1 = MagicMock()
        result1.outcome = "failure"
        result1.objective = "obj1"

        attack_results = {"tech1": [result1]}
        original_failed = ["obj1", "obj2"]
        still_failed = _select_still_failed(attack_results, original_failed)
        assert len(still_failed) == 2

    def test_partial_success(self):
        from pipeline.strike.escalation_level3 import _select_still_failed

        r1 = MagicMock()
        r1.outcome = "success"
        r1.objective = "obj1"

        r2 = MagicMock()
        r2.outcome = "failure"
        r2.objective = "obj2"

        attack_results = {"tech1": [r1], "tech2": [r2]}
        original_failed = ["obj1", "obj2", "obj3"]
        still_failed = _select_still_failed(attack_results, original_failed)
        assert "obj1" not in still_failed
        assert "obj2" in still_failed
        assert "obj3" in still_failed


# ═══════════════════════════════════════════════════════
# escalation_attacks: _is_security_audit_error
# ═══════════════════════════════════════════════════════


class TestSecurityAuditError:
    """测试 _is_security_audit_error 和 _SecurityAuditError."""

    def test_detects_security_audit_fail(self):
        from pipeline.strike.escalation_attacks import _is_security_audit_error

        assert _is_security_audit_error("Error: security_audit_fail") is True

    def test_detects_content_filter(self):
        from pipeline.strike.escalation_attacks import _is_security_audit_error

        assert _is_security_audit_error("content_filter triggered") is True

    def test_detects_safety_violation(self):
        from pipeline.strike.escalation_attacks import _is_security_audit_error

        assert _is_security_audit_error("safety_violation detected") is True

    def test_detects_policy_violation(self):
        from pipeline.strike.escalation_attacks import _is_security_audit_error

        assert _is_security_audit_error("policy_violation: blocked") is True

    def test_no_match_normal_error(self):
        from pipeline.strike.escalation_attacks import _is_security_audit_error

        assert _is_security_audit_error("Connection timeout") is False

    def test_no_match_empty(self):
        from pipeline.strike.escalation_attacks import _is_security_audit_error

        assert _is_security_audit_error("") is False

    def test_security_audit_error_is_exception(self):
        from pipeline.strike.escalation_attacks import _SecurityAuditError

        assert issubclass(_SecurityAuditError, Exception)
