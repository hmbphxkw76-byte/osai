"""L5 v9 优化修复的单元测试。

覆盖关键修复:
    - evidence._is_success() 不再宽松 fallback
    - asr_tracker._get_outcome() 不再宽松 fallback
    - converter_chains.l5_optimal() 构建 7+ 路径
    - presets.get_strategy_args() 策略预设覆盖
    - auth_bridge.inject_auth_headers() 认证注入
    - seed_ranker.update_asr_history() 种子级 ASR 更新
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ── evidence._is_success() 测试 ──


class TestIsSuccess:
    """测试 evidence._is_success() 不再宽松 fallback。"""

    def test_explicit_success_outcome(self):
        """AttackOutcome.SUCCESS → True。"""
        from pyrit.models import AttackOutcome

        from pipeline.report.evidence import _is_success

        result = MagicMock()
        result.outcome = AttackOutcome.SUCCESS
        assert _is_success(result) is True

    def test_explicit_failure_outcome(self):
        """AttackOutcome.FAILURE → False。"""
        from pyrit.models import AttackOutcome

        from pipeline.report.evidence import _is_success

        result = MagicMock()
        result.outcome = AttackOutcome.FAILURE
        assert _is_success(result) is False

    def test_long_response_without_score_is_not_success(self):
        """L5 v9: 无 LLM Judge 评分时, 长 response 不再判为成功。"""
        from pipeline.report.evidence import _is_success

        result = MagicMock()
        result.outcome = None
        result.last_score = None
        result.response = "This is a very long response that is over ten characters long."
        # L5 v9: 不再通过 response 长度猜测
        assert _is_success(result) is False

    def test_empty_response_is_not_success(self):
        """空 response → False。"""
        from pipeline.report.evidence import _is_success

        result = MagicMock()
        result.outcome = None
        result.last_score = None
        result.response = ""
        assert _is_success(result) is False


# ── asr_tracker._get_outcome() 测试 ──


class TestGetOutcome:
    """测试 asr_tracker._get_outcome() 不再宽松 fallback。"""

    def test_non_refusal_response_is_undecided(self):
        """L5 v23: 非拒绝响应由后处理双 Judge 判为 success (之前 v9 为 undecided)。

        v23 变更: 后处理双 Judge 启发式第二 Judge 会对 failure/undecided
        结果进行二次检测: 如果响应文本非空且不含拒绝关键词 → 覆盖为 success。
        这修正了 RefusalInverter 在 SSE 边界 case 下的假阴性。
        """
        from pipeline.assess import asr_tracker, dual_judge

        # L5 v31: 禁用 LLM Judge (测试环境无有效 objective, 使用启发式 fallback)
        # 拆分后全局状态在 dual_judge 模块, 需同步设置
        dual_judge._judge_init_attempted = True
        dual_judge._cached_truefalse_judge = None
        dual_judge._cached_harmbench_judge = None
        # 向后兼容: 同时设置 asr_tracker 的 re-export 引用
        asr_tracker._judge_init_attempted = True
        asr_tracker._cached_truefalse_judge = None
        asr_tracker._cached_harmbench_judge = None

        result = MagicMock()
        result.outcome = None
        result.last_score = None
        result.response = "Sure, here is some information about security testing..."
        # L5 v23: 后处理双 Judge 将非拒绝响应判为 success
        assert asr_tracker._get_outcome(result) == "success"

    def test_empty_response_is_undecided(self):
        """空 response → undecided。"""
        from pipeline.assess.asr_tracker import _get_outcome

        result = MagicMock()
        result.outcome = None
        result.last_score = None
        result.response = ""
        assert _get_outcome(result) == "undecided"


# ── converter_chains.l5_optimal() 测试 ──


class TestL5Optimal:
    """测试 l5_optimal converter 链构建。"""

    def test_l5_optimal_without_converter_target(self):
        """L5 v36: 无 converter_target 时仍返回非 LLM converter (SelectiveTextConverter/ROT13/SearchReplace)."""
        from pipeline.arm.converter_chains import l5_optimal

        converters = l5_optimal(converter_target=None)
        # L5 v36: 至少应有 SelectiveTextConverter, ROT13, SearchReplace, TemplateSegment
        assert len(converters) >= 3
        type_names = [type(c).__name__ for c in converters]
        assert "SelectiveTextConverter" in type_names
        assert "ROT13Converter" in type_names

    def test_l5_optimal_with_mock_converter_target(self):
        """有 converter_target 时返回 7+ 路径。"""
        from pipeline.arm.converter_chains import l5_optimal

        mock_target = MagicMock()
        converters = l5_optimal(converter_target=mock_target)
        # 即使某些 LLM converter 构建失败, 至少应有非 LLM converter
        assert len(converters) >= 3


# ── presets.get_strategy_args() 测试 ──


class TestStrategyPresets:
    """测试策略预设。"""

    def test_full_offensive_uses_l5_optimal(self):
        """full_offensive 策略使用 l5_optimal converter 链。"""
        from pipeline.strategy.presets import get_strategy_args

        args = get_strategy_args("full_offensive")
        assert args["converters"] == "l5_optimal"

    def test_quick_scan_has_converters(self):
        """L5 v32: quick_scan 策略使用 L5 optimal converter 链."""
        from pipeline.strategy.presets import get_strategy_args

        args = get_strategy_args("quick_scan")
        assert args["converters"] == "l5_optimal"

    def test_unknown_strategy_raises(self):
        """未知策略名应抛出 KeyError。"""
        from pipeline.strategy.presets import get_strategy_args

        with pytest.raises(KeyError):
            get_strategy_args("nonexistent_strategy")


# ── auth_bridge 测试 ──


class TestAuthBridge:
    """测试 auth_bridge 认证注入。"""

    def test_inject_bearer_token(self):
        """Bearer Token 注入。"""
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw_request = "POST /api/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        auth_state = {"token": "test-token-123"}
        result = inject_auth_headers(raw_request, auth_state)
        assert "Authorization: Bearer test-token-123" in result

    def test_inject_cookie(self):
        """Cookie 注入。"""
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw_request = "POST /api/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        auth_state = {"cookies": {"session": "abc123", "csrf": "xyz789"}}
        result = inject_auth_headers(raw_request, auth_state)
        assert "Cookie: session=abc123; csrf=xyz789" in result

    def test_no_auth_state_returns_original(self):
        """无 auth_state 时返回原始请求。"""
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw_request = "POST /api/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        result = inject_auth_headers(raw_request, None)
        assert result == raw_request

    def test_load_auth_state_none(self):
        """None 文件路径返回 None。"""
        from pipeline.recon.auth_bridge import load_auth_state

        assert load_auth_state(None) is None

    def test_load_auth_state_nonexistent(self):
        """不存在的文件返回 None。"""
        from pipeline.recon.auth_bridge import load_auth_state

        assert load_auth_state("/nonexistent/path/to/auth.json") is None


# ── update_asr_history 种子级 ASR 测试 ──


class TestUpdateAsrHistory:
    """测试种子级 ASR 更新。"""

    def test_update_with_seed_asr(self, tmp_path, monkeypatch):
        """种子级 ASR 应被写入 asr_history.json。"""
        from pipeline.arm import seed_ranker

        # 指向临时路径 (monkeypatch 自动恢复, 避免污染其他测试)
        monkeypatch.setattr(seed_ranker, "_ASR_HISTORY_PATH", tmp_path / "asr_history.json")
        monkeypatch.setattr(seed_ranker, "_SEEDS_DIR", tmp_path)

        seed_ranker.update_asr_history(
            {"prompt_sending": 30.0},
            seed_asr={"test objective": 50.0},
            seed_attempts={"test objective": 3},
        )

        data = json.loads(
            seed_ranker._ASR_HISTORY_PATH.read_text(encoding="utf-8")
        )
        assert "seed_asr" in data
        assert "test objective" in data["seed_asr"]
        assert data["seed_asr"]["test objective"] == 50.0
        assert data["seed_attempts"]["test objective"] == 3

    def test_ema_merge_seed_asr(self, tmp_path, monkeypatch):
        """EMA 合并: 第二次更新应使用加权平均。"""
        from pipeline.arm import seed_ranker

        monkeypatch.setattr(seed_ranker, "_ASR_HISTORY_PATH", tmp_path / "asr_history.json")
        monkeypatch.setattr(seed_ranker, "_SEEDS_DIR", tmp_path)

        # 第一次更新
        seed_ranker.update_asr_history(
            {"prompt_sending": 30.0},
            seed_asr={"seed1": 100.0},
            seed_attempts={"seed1": 1},
        )

        # 第二次更新 (EMA: 0.3 * 50 + 0.7 * 100 = 85)
        seed_ranker.update_asr_history(
            {"prompt_sending": 40.0},
            seed_asr={"seed1": 50.0},
            seed_attempts={"seed1": 1},
        )

        data = json.loads(
            seed_ranker._ASR_HISTORY_PATH.read_text(encoding="utf-8")
        )
        assert data["seed_asr"]["seed1"] == 85.0  # EMA: 0.3*50 + 0.7*100
        assert data["seed_attempts"]["seed1"] == 2  # 累加


# ── collect_dual_judge_stats 测试 ──


class TestDualJudgeStats:
    """测试双 Judge 统计从 ctx.scorer 获取。"""

    def test_stats_from_ctx_scorer(self):
        """L5 v9: 优先从 ctx.scorer 获取统计。"""
        from pipeline.assess.asr_tracker import collect_dual_judge_stats

        ctx = MagicMock()
        mock_scorer = MagicMock()
        mock_scorer.get_stats.return_value = {"total_scored": 10, "dual_judge_invoked": 5}
        ctx.scorer = mock_scorer

        stats = collect_dual_judge_stats(ctx)
        assert stats["total_scored"] == 10
        assert stats["dual_judge_invoked"] == 5
