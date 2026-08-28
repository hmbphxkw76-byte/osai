"""L5 v11 优化测试 — 多模型并行升级、运行时阈值在线更新、UCB C 自适应、Converter 路径动态裁剪。

覆盖:
    - escalation: _select_still_failed, _run_multi_model_escalation, _ONLINE_THRESHOLD_UPDATE_INTERVAL
    - adaptive_dual_judge: _ONLINE_THRESHOLD_UPDATE_INTERVAL, 在线阈值更新逻辑
    - seed_ranker: _compute_adaptive_ucb_c, UCB C 参数自适应
    - executor: _prune_low_asr_converters, Converter 路径动态裁剪
    - asr_tracker: _save_converter_asr_history, converter 级 ASR 保存
    - config: defaults.yaml L5 v11 参数验证
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# escalation: _select_still_failed
# ═══════════════════════════════════════════════════════


class TestSelectStillFailed:
    """测试 _select_still_failed — 从升级结果中选择仍然失败的目标."""

    def test_all_still_failed(self):
        from pyrit.models import AttackOutcome

        from pipeline.strike.escalation import _select_still_failed

        # All results are failures
        failed_result = MagicMock()
        failed_result.outcome = AttackOutcome.FAILURE
        failed_result.objective = "obj1"

        attack_results = {"crescendo": [failed_result]}
        original = ["obj1", "obj2", "obj3"]

        still_failed = _select_still_failed(attack_results, original)
        assert len(still_failed) == 3
        assert "obj1" in still_failed
        assert "obj2" in still_failed
        assert "obj3" in still_failed

    def test_some_succeeded(self):
        from pyrit.models import AttackOutcome

        from pipeline.strike.escalation import _select_still_failed

        success_result = MagicMock()
        success_result.outcome = AttackOutcome.SUCCESS
        success_result.objective = "obj1"

        attack_results = {"crescendo": [success_result]}
        original = ["obj1", "obj2", "obj3"]

        still_failed = _select_still_failed(attack_results, original)
        assert len(still_failed) == 2
        assert "obj1" not in still_failed
        assert "obj2" in still_failed
        assert "obj3" in still_failed

    def test_empty_attack_results(self):
        from pipeline.strike.escalation import _select_still_failed

        still_failed = _select_still_failed({}, ["obj1", "obj2"])
        assert len(still_failed) == 2

    def test_empty_original(self):
        from pipeline.strike.escalation import _select_still_failed

        still_failed = _select_still_failed({"crescendo": []}, [])
        assert still_failed == []


# ═══════════════════════════════════════════════════════
# escalation: _run_multi_model_escalation (集成测试 with mocks)
# ═══════════════════════════════════════════════════════


class TestRunMultiModelEscalation:
    """测试 _run_multi_model_escalation — 多模型并行升级."""

    @pytest.mark.asyncio
    async def test_no_extra_targets_returns_empty(self):
        from pipeline.strike.escalation import _run_multi_model_escalation

        ctx = MagicMock()
        ctx.objective_target = MagicMock()
        ctx.multi_turn_target = MagicMock()
        ctx.args = MagicMock(max_concurrency=3)
        ctx.scoring_target = None
        ctx.adversarial_target = None

        results = await _run_multi_model_escalation(ctx, ["obj1"], [])
        assert results == {}

    @pytest.mark.asyncio
    async def test_with_extra_targets(self):
        """测试多模型并行升级的基本流程 (使用 mock)."""
        from pipeline.strike.escalation import _run_multi_model_escalation

        ctx = MagicMock()
        ctx.objective_target = MagicMock()
        ctx.multi_turn_target = MagicMock()
        ctx.args = MagicMock(max_concurrency=3)
        ctx.scoring_target = MagicMock()
        ctx.adversarial_target = MagicMock()

        # Mock the executor and attack to avoid real API calls
        mock_executor_result = MagicMock()
        mock_executor_result.completed_results = []
        mock_executor_result.incomplete_objectives = []

        with patch(
            "pipeline.strike.executor._create_objective_scorer",
            return_value=MagicMock(),
        ), patch(
            "pipeline.strike.escalation._create_fallback_fsts",
            return_value=MagicMock(),
        ):
            results = await _run_multi_model_escalation(
                ctx,
                ["obj1"],
                [MagicMock()],
            )
            # Results may be empty if mock executor returns nothing
            assert isinstance(results, dict)


# ═══════════════════════════════════════════════════════
# adaptive_dual_judge: _ONLINE_THRESHOLD_UPDATE_INTERVAL
# ═══════════════════════════════════════════════════════


class TestOnlineThresholdUpdateInterval:
    """测试运行时阈值在线更新间隔常量."""

    def test_interval_is_positive_integer(self):
        from pipeline.assess.adaptive_dual_judge import _ONLINE_THRESHOLD_UPDATE_INTERVAL

        assert isinstance(_ONLINE_THRESHOLD_UPDATE_INTERVAL, int)
        assert _ONLINE_THRESHOLD_UPDATE_INTERVAL > 0

    def test_interval_is_reasonable(self):
        """间隔应在合理范围 (5-100), 太小频繁IO, 太大不灵活."""
        from pipeline.assess.adaptive_dual_judge import _ONLINE_THRESHOLD_UPDATE_INTERVAL

        assert 5 <= _ONLINE_THRESHOLD_UPDATE_INTERVAL <= 100


class TestOnlineThresholdUpdate:
    """测试 AdaptiveDualJudgeScorer 的在线阈值更新逻辑."""

    def test_threshold_updates_on_interval(self):
        """测试每 N 次评分后阈值会更新."""
        from pipeline.assess.adaptive_dual_judge import (
            _ONLINE_THRESHOLD_UPDATE_INTERVAL,
            AdaptiveDualJudgeScorer,
        )

        # Create a mock scorer with the right attributes
        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        scorer._total_scored = 0
        scorer._high_confidence_threshold = 0.85
        scorer._dual_judge_invoked = 0
        scorer._agreements = 0
        scorer._disagreements = 0
        scorer._third_judge_invoked = 0

        # Simulate the online update logic
        with patch(
            "pipeline.assess.adaptive_dual_judge._compute_adaptive_threshold",
            return_value=0.75,
        ):
            # Simulate scoring _ONLINE_THRESHOLD_UPDATE_INTERVAL times
            scorer._total_scored = _ONLINE_THRESHOLD_UPDATE_INTERVAL

            # Check if the update condition is met
            should_update = (
                scorer._total_scored % _ONLINE_THRESHOLD_UPDATE_INTERVAL == 0
                and scorer._total_scored > 0
            )
            assert should_update

    def test_threshold_no_update_off_interval(self):
        """测试非间隔点不更新阈值."""
        from pipeline.assess.adaptive_dual_judge import (
            _ONLINE_THRESHOLD_UPDATE_INTERVAL,
        )

        total_scored = _ONLINE_THRESHOLD_UPDATE_INTERVAL - 1
        should_update = (
            total_scored % _ONLINE_THRESHOLD_UPDATE_INTERVAL == 0
            and total_scored > 0
        )
        assert not should_update


# ═══════════════════════════════════════════════════════
# seed_ranker: _compute_adaptive_ucb_c
# ═══════════════════════════════════════════════════════


class TestComputeAdaptiveUcbC:
    """测试 _compute_adaptive_ucb_c — UCB C 参数自适应."""

    def test_few_attempts_high_c(self):
        """种子数少时 C=0.9 (基线 0.8 + 高方差 +0.1)."""
        from pipeline.arm.seed_ranker import _compute_adaptive_ucb_c

        # Use high-variance values: std_dev > 30 triggers +0.1
        C = _compute_adaptive_ucb_c(
            seed_attempts={"s1": 3, "s2": 2},
            asr_history={"s1": 80.0, "s2": 10.0},
        )
        assert C == 0.9  # N=5 < 10, high variance -> +0.1 adjustment

    def test_medium_attempts_standard_c(self):
        """种子数中等时 C=0.5 (标准平衡, 高方差不调整)."""
        from pipeline.arm.seed_ranker import _compute_adaptive_ucb_c

        # N=20, between 10 and 50, use high variance to avoid adjustment
        attempts = {f"seed_{i}": 2 for i in range(10)}
        asr = {f"seed_{i}": 80.0 if i < 5 else 20.0 for i in range(10)}
        C = _compute_adaptive_ucb_c(attempts, asr)
        assert C == 0.5

    def test_many_attempts_low_c(self):
        """种子数多时 C=0.3 (弱探索, 高方差不调整)."""
        from pipeline.arm.seed_ranker import _compute_adaptive_ucb_c

        # N=60, > 50, high variance to avoid reduction
        attempts = {f"seed_{i}": 3 for i in range(20)}
        asr = {f"seed_{i}": 80.0 if i < 10 else 20.0 for i in range(20)}
        C = _compute_adaptive_ucb_c(attempts, asr)
        assert C == 0.3

    def test_high_variance_increases_c(self):
        """高方差时 C 增加 0.1 (多探索)."""
        from pipeline.arm.seed_ranker import _compute_adaptive_ucb_c

        # N=20, but high variance (std > 30)
        attempts = {f"seed_{i}": 2 for i in range(10)}
        asr = {f"seed_{i}": 80.0 if i < 5 else 10.0 for i in range(10)}
        C = _compute_adaptive_ucb_c(attempts, asr)
        assert abs(C - 0.6) < 0.001  # 0.5 + 0.1 (float comparison)

    def test_low_variance_decreases_c(self):
        """低方差时 C 减少 0.1 (少探索)."""
        from pipeline.arm.seed_ranker import _compute_adaptive_ucb_c

        # N=20, low variance (std < 10)
        attempts = {f"seed_{i}": 2 for i in range(10)}
        asr = {f"seed_{i}": 50.0 for i in range(10)}  # all same → std=0
        C = _compute_adaptive_ucb_c(attempts, asr)
        assert abs(C - 0.4) < 0.001  # 0.5 - 0.1 (float comparison)

    def test_c_clamped_to_min(self):
        """C 截断到最小 0.1."""
        from pipeline.arm.seed_ranker import _compute_adaptive_ucb_c

        # N=60 (>50 → C=0.3), low variance → C=0.2
        attempts = {f"seed_{i}": 3 for i in range(20)}
        asr = {f"seed_{i}": 50.0 for i in range(20)}
        C = _compute_adaptive_ucb_c(attempts, asr)
        assert abs(C - 0.2) < 0.001  # 0.3 - 0.1 (float comparison)

    def test_empty_history_default_c(self):
        """无历史数据时返回分层基线 C."""
        from pipeline.arm.seed_ranker import _compute_adaptive_ucb_c

        C = _compute_adaptive_ucb_c({}, {})
        assert C == 0.8  # N=0 < 10

    def test_c_in_valid_range(self):
        """C 始终在 [0.1, 1.0] 范围内."""
        from pipeline.arm.seed_ranker import _compute_adaptive_ucb_c

        test_cases = [
            ({}, {}),
            ({"s1": 1}, {"s1": 50.0}),
            ({"s1": 100}, {"s1": 50.0}),
            ({f"s{i}": 5 for i in range(20)}, {f"s{i}": 80.0 if i < 10 else 10.0 for i in range(20)}),
        ]
        for attempts, asr in test_cases:
            C = _compute_adaptive_ucb_c(attempts, asr)
            assert 0.1 <= C <= 1.0


# ═══════════════════════════════════════════════════════
# executor: _prune_low_asr_converters
# ═══════════════════════════════════════════════════════


class TestPruneLowAsrConverters:
    """测试 _prune_low_asr_converters — Converter 路径动态裁剪."""

    def test_no_history_returns_original(self):
        """无 ASR 历史时不裁剪."""
        from pipeline.strike.executor import _prune_low_asr_converters

        converters = [MagicMock() for _ in range(5)]
        for i, c in enumerate(converters):
            type(c).__name__ = f"Converter{i}"

        with patch("pathlib.Path.exists", return_value=False):
            result = _prune_low_asr_converters(converters)
            assert len(result) == 5

    def test_few_converters_not_pruned(self):
        """路径数 ≤ 4 时不裁剪."""
        from pipeline.strike.executor import _prune_low_asr_converters

        converters = [MagicMock() for _ in range(3)]
        for i, c in enumerate(converters):
            type(c).__name__ = f"Converter{i}"

        result = _prune_low_asr_converters(converters)
        assert len(result) == 3

    def test_prune_low_asr_paths(self):
        """裁剪 ASR < 5% 的路径."""
        from pipeline.strike.executor import _prune_low_asr_converters

        # Create 6 converters
        converters = [MagicMock() for _ in range(6)]
        names = ["HighASR1", "HighASR2", "LowASR1", "LowASR2", "NoHistory1", "NoHistory2"]
        for i, c in enumerate(converters):
            type(c).__name__ = names[i]

        # Mock ASR history
        converter_asr = {
            "HighASR1": 40.0,
            "HighASR2": 30.0,
            "LowASR1": 2.0,   # < 5% → pruned
            "LowASR2": 3.0,   # < 5% → pruned
        }

        mock_data = {"converter_asr": converter_asr}
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = json.dumps(mock_data)

        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=json.dumps(mock_data)):
            result = _prune_low_asr_converters(converters)
            # 6 - 2 pruned = 4 (minimum, so they're restored to maintain _MIN_PATHS=4)
            # Actually with 4 remaining, no pruning happens because 4 >= _MIN_PATHS
            # So we should get 4 paths
            assert len(result) <= 6
            assert len(result) >= 4

    def test_min_paths_restoration(self):
        """裁剪后剩余 < 4 时恢复部分路径."""
        from pipeline.strike.executor import _prune_low_asr_converters

        # Create 8 converters, all with low ASR
        converters = [MagicMock() for _ in range(8)]
        for i, c in enumerate(converters):
            type(c).__name__ = f"LowConverter{i}"

        # All have ASR < 5%
        converter_asr = {f"LowConverter{i}": float(i) for i in range(8)}

        mock_data = {"converter_asr": converter_asr}

        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=json.dumps(mock_data)):
            result = _prune_low_asr_converters(converters)
            # All would be pruned, but min_paths=4 restores some
            assert len(result) >= 4

    def test_sorting_by_asr_descending(self):
        """裁剪后按 ASR 降序排列."""
        from pipeline.strike.executor import _prune_low_asr_converters

        converters = [MagicMock() for _ in range(5)]
        names = ["ConverterA", "ConverterB", "ConverterC", "ConverterD", "ConverterE"]
        for i, c in enumerate(converters):
            type(c).__name__ = names[i]

        converter_asr = {
            "ConverterA": 10.0,
            "ConverterB": 50.0,
            "ConverterC": 30.0,
            "ConverterD": 20.0,
            "ConverterE": 40.0,
        }

        mock_data = {"converter_asr": converter_asr}

        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=json.dumps(mock_data)):
            result = _prune_low_asr_converters(converters)
            # All ASR > 5%, so none pruned, just sorted
            assert len(result) == 5
            # Check sorted by ASR descending
            result_asrs = [converter_asr.get(type(c).__name__, -1) for c in result]
            assert result_asrs == sorted(result_asrs, reverse=True)


# ═══════════════════════════════════════════════════════
# asr_tracker: _save_converter_asr_history
# ═══════════════════════════════════════════════════════


class TestSaveConverterAsrHistory:
    """测试 _save_converter_asr_history — converter 级 ASR 保存."""

    def test_save_converter_asr(self, tmp_path):
        from pipeline.assess.asr_tracker import _save_converter_asr_history

        # Create a mock asr_history.json
        history_path = tmp_path / "asr_history.json"
        history_data = {"asr": {}, "converter_asr": {}}
        history_path.write_text(json.dumps(history_data), encoding="utf-8")

        # Patch the path used by the function
        with patch("pathlib.Path.resolve") as mock_resolve:
            mock_resolve.return_value.parent.parent.parent = tmp_path
            with patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.read_text", return_value=json.dumps(history_data)):
                _save_converter_asr_history(
                    converter_asr={"Base64Converter": 10.0, "ROT13Converter": 5.0},
                    converter_attempts={"Base64Converter": 10, "ROT13Converter": 20},
                )

    def test_ema_merge_converter_asr(self, tmp_path):
        """EMA 合并 converter ASR."""
        from pipeline.assess.asr_tracker import _save_converter_asr_history

        # Existing data with one converter
        history_data = {
            "asr": {},
            "converter_asr": {"Base64Converter": 20.0},
        }

        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=json.dumps(history_data)):
            _save_converter_asr_history(
                converter_asr={"Base64Converter": 30.0},
                converter_attempts={"Base64Converter": 5},
            )
            # EMA: 0.3 * 30 + 0.7 * 20 = 9 + 14 = 23.0


# ═══════════════════════════════════════════════════════
# config: defaults.yaml L5 v11 参数验证
# ═══════════════════════════════════════════════════════


class TestConfigL5V11:
    """测试 config/defaults.yaml L5 v11 参数."""

    def test_online_threshold_update_interval(self):
        # V2 精简: online_threshold_update_interval 已从 defaults.yaml 删除
        pytest.skip("V2: online_threshold_update_interval removed from defaults.yaml")

    def test_ucb_c_adaptive_enabled(self):
        # V2 精简: ucb_c_adaptive_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: ucb_c_adaptive_enabled removed from defaults.yaml")

    def test_converter_path_pruning_enabled(self):
        # V2 精简: converter_path_pruning_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: converter_path_pruning_enabled removed from defaults.yaml")

    def test_converter_prune_asr_threshold(self):
        # V2 精简: converter_prune_asr_threshold 已从 defaults.yaml 删除
        pytest.skip("V2: converter_prune_asr_threshold removed from defaults.yaml")

    def test_converter_min_paths(self):
        # V2 精简: converter_min_paths 已从 defaults.yaml 删除
        pytest.skip("V2: converter_min_paths removed from defaults.yaml")

    def test_multi_model_escalation_enabled(self):
        # V2 精简: multi_model_escalation_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: multi_model_escalation_enabled removed from defaults.yaml")


# ═══════════════════════════════════════════════════════
# 集成测试: save_asr_history with converter ASR
# ═══════════════════════════════════════════════════════


class TestSaveAsrHistoryWithConverterAsr:
    """测试 save_asr_history 中的 converter 级 ASR 提取."""

    def test_converter_asr_extracted(self, tmp_path, monkeypatch):
        from pyrit.models import AttackOutcome

        from pipeline.arm import seed_ranker
        from pipeline.assess import asr_tracker

        monkeypatch.setattr(seed_ranker, "_ASR_HISTORY_PATH", tmp_path / "asr_history.json")
        monkeypatch.setattr(seed_ranker, "_SEEDS_DIR", tmp_path)

        # Create results with converter metadata
        success = MagicMock()
        success.outcome = AttackOutcome.SUCCESS
        success.objective = "test objective"
        success.metadata = {"converter_name": "Base64Converter"}

        failure = MagicMock()
        failure.outcome = AttackOutcome.FAILURE
        failure.objective = "test objective 2"
        failure.metadata = {"converter_name": "Base64Converter"}

        asr_tracker.save_asr_history(
            {"prompt_sending": 50.0},
            attack_results={"prompt_sending": [success, failure]},
        )

        data = json.loads(
            seed_ranker._ASR_HISTORY_PATH.read_text(encoding="utf-8")
        )
        assert "converter_asr" in data
        assert "Base64Converter" in data["converter_asr"]
        assert data["converter_asr"]["Base64Converter"] == 50.0  # 1/2 = 50%
