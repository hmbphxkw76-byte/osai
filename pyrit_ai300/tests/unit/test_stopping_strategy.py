"""
Tests for the three-layer stopping strategy.

L1: completion_policy=FIRST_SUCCESS (PyRIT native, not tested here)
L2: owasp_success_threshold — OWASP-aware success ratio threshold
    - Within same OWASP: skip remaining plans when threshold reached
    - Between OWASPs: all OWASPs must have success to stop descending
L3: stop_on_first_success — global first success stop (most aggressive)

Test coverage:
  1. BatchAttackResult model fields (owasp_success_map, owasp_total_map, skipped_by_stop)
  2. ConfigLoader getters (get_owasp_success_threshold, get_stop_on_first_success)
  3. AdaptiveRunner signature accepts L2/L3 params
  4. GroupFallbackExecutor OWASP-aware tier stopping logic
  5. GroupFallbackExecutor backward compatibility (threshold=0.0)
  6. GroupFallbackExecutor stop_on_first_success
  7. Threshold calculation tests
"""

import inspect
import math
from unittest.mock import MagicMock, patch

import pytest

from src.payloads.models import AttackPlan, AttackMode, BatchAttackResult, PromptItem


# ============================================================
# Helpers
# ============================================================


def _make_tg_info(technique_group="skeleton_key", tier=None, owasp_id="LLM01"):
    """Create a mock TechniqueGroupInfo with required fields."""
    from src.payloads.asr_rank_builder import ASRTier, TechniqueGroupInfo

    return TechniqueGroupInfo(
        technique_group=technique_group,
        owasp_id=owasp_id,
        seed_count=1,
        max_asr=0.9,
        avg_asr=0.9,
        has_asr_data=True,
        tier=tier or ASRTier.S,
        heuristic_score=90.0,
        attack_modes=["single_turn"],
        difficulties=["medium"],
        severities=["high"],
        evasion_levels=["none"],
        dataset_name="test_dataset",
    )


def _make_attack_plan(plan_id="p1", owasp_id="LLM01", technique_group="skeleton_key"):
    """Create a mock AttackPlan."""
    return AttackPlan(
        plan_id=plan_id,
        prompt_item=PromptItem(
            id=f"item_{plan_id}",
            objective="test objective",
            attack_mode=AttackMode.SINGLE_TURN,
            owasp_id=owasp_id,
            metadata={"technique_group": technique_group},
        ),
        attack_technique="prompt_sending",
        owasp_id=owasp_id,
    )


def _make_batch_result(
    succeeded=0,
    executed=0,
    owasp_success_map=None,
    owasp_total_map=None,
    skipped_by_stop=0,
):
    """Create a mock BatchAttackResult with stopping strategy fields."""
    return BatchAttackResult(
        total_plans=executed,
        executed=executed,
        succeeded=succeeded,
        failed=executed - succeeded,
        owasp_success_map=owasp_success_map or {},
        owasp_total_map=owasp_total_map or {},
        skipped_by_stop=skipped_by_stop,
    )


def _make_adaptive_result(batch_result):
    """Create a mock AdaptiveRunResult wrapping a BatchAttackResult."""
    mock = MagicMock()
    mock.batch_result = batch_result
    return mock


# ============================================================
# 1. BatchAttackResult Model Fields
# ============================================================


class TestBatchAttackResultStoppingFields:
    """Test that BatchAttackResult has the new stopping strategy fields."""

    def test_owasp_success_map_default(self):
        """owasp_success_map defaults to empty dict."""
        result = BatchAttackResult()
        assert result.owasp_success_map == {}

    def test_owasp_total_map_default(self):
        """owasp_total_map defaults to empty dict."""
        result = BatchAttackResult()
        assert result.owasp_total_map == {}

    def test_skipped_by_stop_default(self):
        """skipped_by_stop defaults to 0."""
        result = BatchAttackResult()
        assert result.skipped_by_stop == 0

    def test_owasp_success_map_set(self):
        """owasp_success_map can be set."""
        result = BatchAttackResult(owasp_success_map={"LLM01": 3, "LLM02": 0})
        assert result.owasp_success_map["LLM01"] == 3
        assert result.owasp_success_map["LLM02"] == 0

    def test_succeeded_owasp_ids_property(self):
        """succeeded_owasp_ids returns set of OWASP IDs with >0 success."""
        result = BatchAttackResult(
            owasp_success_map={"LLM01": 3, "LLM02": 0, "ASI01": 1}
        )
        assert result.succeeded_owasp_ids == {"LLM01", "ASI01"}

    def test_succeeded_owasp_ids_empty(self):
        """succeeded_owasp_ids returns empty set when no successes."""
        result = BatchAttackResult(
            owasp_success_map={"LLM01": 0, "LLM02": 0}
        )
        assert result.succeeded_owasp_ids == set()

    def test_succeeded_owasp_ids_no_map(self):
        """succeeded_owasp_ids returns empty set when map is empty."""
        result = BatchAttackResult()
        assert result.succeeded_owasp_ids == set()


# ============================================================
# 2. ConfigLoader Getters
# ============================================================


class TestConfigLoaderStoppingStrategy:
    """Test ConfigLoader getters for stopping strategy."""

    def test_get_owasp_success_threshold_default(self):
        """get_owasp_success_threshold returns default 0.0 from pipeline.yaml."""
        import os
        from src.core.config_loader import ConfigLoader

        old_val = os.environ.pop("OWASP_SUCCESS_THRESHOLD", None)
        try:
            loader = ConfigLoader()
            val = loader.get_owasp_success_threshold()
            # P0-1: default is now 0.0 (maximize success rate)
            assert val == 0.0
        finally:
            if old_val is not None:
                os.environ["OWASP_SUCCESS_THRESHOLD"] = old_val

    def test_get_owasp_success_threshold_env_override(self):
        """get_owasp_success_threshold respects env override."""
        import os
        from src.core.config_loader import ConfigLoader

        old_val = os.environ.get("OWASP_SUCCESS_THRESHOLD")
        os.environ["OWASP_SUCCESS_THRESHOLD"] = "0.5"
        try:
            loader = ConfigLoader()
            val = loader.get_owasp_success_threshold()
            assert val == 0.5
        finally:
            if old_val is None:
                os.environ.pop("OWASP_SUCCESS_THRESHOLD", None)
            else:
                os.environ["OWASP_SUCCESS_THRESHOLD"] = old_val

    def test_get_stop_on_first_success_default(self):
        """get_stop_on_first_success returns default False."""
        import os
        from src.core.config_loader import ConfigLoader

        old_val = os.environ.pop("STOP_ON_FIRST_SUCCESS", None)
        try:
            loader = ConfigLoader()
            val = loader.get_stop_on_first_success()
            assert val is False
        finally:
            if old_val is not None:
                os.environ["STOP_ON_FIRST_SUCCESS"] = old_val

    def test_get_stop_on_first_success_env_override(self):
        """get_stop_on_first_success respects env override."""
        import os
        from src.core.config_loader import ConfigLoader

        old_val = os.environ.get("STOP_ON_FIRST_SUCCESS")
        os.environ["STOP_ON_FIRST_SUCCESS"] = "true"
        try:
            loader = ConfigLoader()
            val = loader.get_stop_on_first_success()
            assert val is True
        finally:
            if old_val is None:
                os.environ.pop("STOP_ON_FIRST_SUCCESS", None)
            else:
                os.environ["STOP_ON_FIRST_SUCCESS"] = old_val


# ============================================================
# 3. AdaptiveRunner Signature Tests
# ============================================================


class TestAdaptiveRunnerSignature:
    """Test that run_adaptive_scenario_async accepts L2/L3 params."""

    def test_has_owasp_success_threshold(self):
        """run_adaptive_scenario_async has owasp_success_threshold parameter."""
        from src.scenarios.adaptive_runner import run_adaptive_scenario_async

        sig = inspect.signature(run_adaptive_scenario_async)
        assert "owasp_success_threshold" in sig.parameters
        assert sig.parameters["owasp_success_threshold"].default == 0.0

    def test_has_stop_on_first_success(self):
        """run_adaptive_scenario_async has stop_on_first_success parameter."""
        from src.scenarios.adaptive_runner import run_adaptive_scenario_async

        sig = inspect.signature(run_adaptive_scenario_async)
        assert "stop_on_first_success" in sig.parameters
        assert sig.parameters["stop_on_first_success"].default is False


# ============================================================
# 4. GroupFallbackExecutor OWASP-Aware Stopping
# ============================================================


class TestGroupFallbackExecutorOWASPAware:
    """Test GroupFallbackExecutor OWASP-aware tier stopping logic."""

    def test_execute_with_fallback_has_threshold_param(self):
        """execute_with_fallback accepts owasp_success_threshold."""
        from src.payloads.group_fallback_executor import GroupFallbackExecutor

        sig = inspect.signature(GroupFallbackExecutor.execute_with_fallback)
        assert "owasp_success_threshold" in sig.parameters
        assert sig.parameters["owasp_success_threshold"].default == 0.0

    def test_execute_with_fallback_has_stop_param(self):
        """execute_with_fallback accepts stop_on_first_success."""
        from src.payloads.group_fallback_executor import GroupFallbackExecutor

        sig = inspect.signature(GroupFallbackExecutor.execute_with_fallback)
        assert "stop_on_first_success" in sig.parameters
        assert sig.parameters["stop_on_first_success"].default is False

    @pytest.mark.asyncio
    async def test_owasp_aware_stops_when_all_owasps_succeed(self):
        """L2: stops descending when all OWASP categories have success."""
        from src.payloads.group_fallback_executor import GroupFallbackExecutor
        from src.payloads.asr_rank_builder import ASRTier

        executor = GroupFallbackExecutor()

        plans = [
            _make_attack_plan("p1", "LLM01", "skeleton_key"),
            _make_attack_plan("p2", "LLM02", "skeleton_key"),
        ]

        tier_s_result = _make_batch_result(
            succeeded=2,
            executed=2,
            owasp_success_map={"LLM01": 1, "LLM02": 1},
            owasp_total_map={"LLM01": 1, "LLM02": 1},
        )

        fallback_chain = [[_make_tg_info("skeleton_key", ASRTier.S)]]

        with patch(
            "src.payloads.group_fallback_executor.run_adaptive_scenario_async",
            return_value=_make_adaptive_result(tier_s_result),
        ):
            result = await executor.execute_with_fallback(
                attack_plans=plans,
                fallback_chain=fallback_chain,
                strategy=__import__(
                    "src.payloads.tiered_selection_wizard", fromlist=["FallbackStrategy"]
                ).FallbackStrategy.SEQUENTIAL_ASR_DESC,
                objective_target=MagicMock(),
                judge_target=MagicMock(),
                owasp_success_threshold=0.8,
            )

        assert result.stopped_at_tier == "S"
        assert len(result.tiers_executed) == 1

    @pytest.mark.asyncio
    async def test_owasp_aware_continues_when_owasp_missing(self):
        """L2: continues descending when some OWASP has no success."""
        from src.payloads.group_fallback_executor import GroupFallbackExecutor
        from src.payloads.asr_rank_builder import ASRTier

        executor = GroupFallbackExecutor()

        plans = [
            _make_attack_plan("p1", "LLM01", "skeleton_key"),
            _make_attack_plan("p2", "LLM02", "crescendo"),
        ]

        tier_s_result = _make_batch_result(
            succeeded=1,
            executed=1,
            owasp_success_map={"LLM01": 1, "LLM02": 0},
            owasp_total_map={"LLM01": 1, "LLM02": 1},
        )

        tier_a_result = _make_batch_result(
            succeeded=1,
            executed=1,
            owasp_success_map={"LLM02": 1},
            owasp_total_map={"LLM02": 1},
        )

        fallback_chain = [
            [_make_tg_info("skeleton_key", ASRTier.S)],
            [_make_tg_info("crescendo", ASRTier.A)],
        ]

        with patch(
            "src.payloads.group_fallback_executor.run_adaptive_scenario_async",
            side_effect=[
                _make_adaptive_result(tier_s_result),
                _make_adaptive_result(tier_a_result),
            ],
        ):
            result = await executor.execute_with_fallback(
                attack_plans=plans,
                fallback_chain=fallback_chain,
                strategy=__import__(
                    "src.payloads.tiered_selection_wizard", fromlist=["FallbackStrategy"]
                ).FallbackStrategy.SEQUENTIAL_ASR_DESC,
                objective_target=MagicMock(),
                judge_target=MagicMock(),
                owasp_success_threshold=0.8,
            )

        assert len(result.tiers_executed) == 2
        assert result.stopped_at_tier == "A"

    @pytest.mark.asyncio
    async def test_backward_compatible_no_threshold(self):
        """Without owasp_success_threshold (0.0), uses old first-success-stop behavior."""
        from src.payloads.group_fallback_executor import GroupFallbackExecutor
        from src.payloads.asr_rank_builder import ASRTier

        executor = GroupFallbackExecutor()

        plans = [_make_attack_plan("p1", "LLM01", "skeleton_key")]

        tier_s_result = _make_batch_result(succeeded=1, executed=1)

        fallback_chain = [
            [_make_tg_info("skeleton_key", ASRTier.S)],
            [_make_tg_info("crescendo", ASRTier.A)],
        ]

        with patch(
            "src.payloads.group_fallback_executor.run_adaptive_scenario_async",
            return_value=_make_adaptive_result(tier_s_result),
        ):
            result = await executor.execute_with_fallback(
                attack_plans=plans,
                fallback_chain=fallback_chain,
                strategy=__import__(
                    "src.payloads.tiered_selection_wizard", fromlist=["FallbackStrategy"]
                ).FallbackStrategy.SEQUENTIAL_ASR_DESC,
                objective_target=MagicMock(),
                judge_target=MagicMock(),
                owasp_success_threshold=0.0,
            )

        assert result.stopped_at_tier == "S"
        assert len(result.tiers_executed) == 1

    @pytest.mark.asyncio
    async def test_stop_on_first_success(self):
        """L3: stop_on_first_success stops on any success."""
        from src.payloads.group_fallback_executor import GroupFallbackExecutor
        from src.payloads.asr_rank_builder import ASRTier

        executor = GroupFallbackExecutor()

        plans = [
            _make_attack_plan("p1", "LLM01", "skeleton_key"),
            _make_attack_plan("p2", "LLM02", "skeleton_key"),
        ]

        tier_s_result = _make_batch_result(
            succeeded=1,
            executed=2,
            owasp_success_map={"LLM01": 1},
        )

        fallback_chain = [
            [_make_tg_info("skeleton_key", ASRTier.S)],
            [_make_tg_info("crescendo", ASRTier.A)],
        ]

        with patch(
            "src.payloads.group_fallback_executor.run_adaptive_scenario_async",
            return_value=_make_adaptive_result(tier_s_result),
        ):
            result = await executor.execute_with_fallback(
                attack_plans=plans,
                fallback_chain=fallback_chain,
                strategy=__import__(
                    "src.payloads.tiered_selection_wizard", fromlist=["FallbackStrategy"]
                ).FallbackStrategy.SEQUENTIAL_ASR_DESC,
                objective_target=MagicMock(),
                judge_target=MagicMock(),
                stop_on_first_success=True,
            )

        assert result.stopped_at_tier == "S"
        assert len(result.tiers_executed) == 1

    @pytest.mark.asyncio
    async def test_owasp_aware_skips_succeeded_owasp_in_next_tier(self):
        """L2: next tier filters out plans for already-succeeded OWASPs."""
        from src.payloads.group_fallback_executor import GroupFallbackExecutor
        from src.payloads.asr_rank_builder import ASRTier

        executor = GroupFallbackExecutor()

        plans = [
            _make_attack_plan("p1", "LLM01", "skeleton_key"),
            _make_attack_plan("p2", "LLM02", "crescendo"),
        ]

        tier_s_result = _make_batch_result(
            succeeded=1,
            executed=1,
            owasp_success_map={"LLM01": 1},
            owasp_total_map={"LLM01": 1},
        )

        tier_a_result = _make_batch_result(
            succeeded=1,
            executed=1,
            owasp_success_map={"LLM02": 1},
            owasp_total_map={"LLM02": 1},
        )

        fallback_chain = [
            [_make_tg_info("skeleton_key", ASRTier.S)],
            [_make_tg_info("crescendo", ASRTier.A)],
        ]

        call_args_list = []

        async def mock_execute(*args, **kwargs):
            call_args_list.append(kwargs)
            if len(call_args_list) == 1:
                return _make_adaptive_result(tier_s_result)
            return _make_adaptive_result(tier_a_result)

        with patch(
            "src.payloads.group_fallback_executor.run_adaptive_scenario_async",
            side_effect=mock_execute,
        ):
            await executor.execute_with_fallback(
                attack_plans=plans,
                fallback_chain=fallback_chain,
                strategy=__import__(
                    "src.payloads.tiered_selection_wizard", fromlist=["FallbackStrategy"]
                ).FallbackStrategy.SEQUENTIAL_ASR_DESC,
                objective_target=MagicMock(),
                judge_target=MagicMock(),
                owasp_success_threshold=0.8,
            )

        assert len(call_args_list) == 2
        tier_a_plans = call_args_list[1]["attack_plans"]
        assert all(p.owasp_id != "LLM01" for p in tier_a_plans)
        assert any(p.owasp_id == "LLM02" for p in tier_a_plans)


# ============================================================
# 5. Threshold Calculation Tests
# ============================================================


class TestThresholdCalculation:
    """Test the threshold calculation logic."""

    def test_threshold_80_percent_of_6(self):
        """80% of 6 = 4.8, ceil = 5 required successes."""
        total = 6
        threshold = 0.8
        required = math.ceil(total * threshold)
        assert required == 5

    def test_threshold_80_percent_of_5(self):
        """80% of 5 = 4.0, ceil = 4 required successes."""
        total = 5
        threshold = 0.8
        required = math.ceil(total * threshold)
        assert required == 4

    def test_threshold_80_percent_of_1(self):
        """80% of 1 = 0.8, ceil = 1 required success."""
        total = 1
        threshold = 0.8
        required = math.ceil(total * threshold)
        assert required == 1

    def test_threshold_80_percent_of_10(self):
        """80% of 10 = 8.0, ceil = 8 required successes."""
        total = 10
        threshold = 0.8
        required = math.ceil(total * threshold)
        assert required == 8

    def test_threshold_50_percent_of_6(self):
        """50% of 6 = 3.0, ceil = 3 required successes."""
        total = 6
        threshold = 0.5
        required = math.ceil(total * threshold)
        assert required == 3

    def test_threshold_100_percent_of_6(self):
        """100% of 6 = 6.0, ceil = 6 required successes."""
        total = 6
        threshold = 1.0
        required = math.ceil(total * threshold)
        assert required == 6
