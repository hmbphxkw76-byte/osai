"""分阶段执行引擎测试 — 覆盖全部 10 项 L5 差距修复

测试矩阵:
    Gap #1:  test_adaptive_generations_ci_driven          — CI 宽度驱动 gen 自适应
    Gap #2:  test_phase0_high_parallel / test_phase4_low   — 并发自适应
    Gap #3:  test_buff_high_refusal / medium / low         — Buff 策略自适应
    Gap #4:  test_vlm_probes_promoted_to_phase1            — 多模态探针提权
    Gap #5:  test_token_budget_exceeded / within_budget    — token 预算控制
    Gap #6:  test_configurable_asr_thresholds              — 阈值可配置
    Gap #7:  test_smoke_probes_zh / en / unknown           — 语言适配
    Gap #8:  test_phase_trend_data                         — 趋势数据构建
    Gap #9:  test_atkgen_enabled_in_phase4                 — atkgen 集成
    Gap #10: test_interactive_checkpoint                   — 人工确认断点
    综合:    test_full_phased_flow                         — 完整流程
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.phased_execution import (
    DEFAULT_PHASES,
    PhaseConfig,
    PhaseResult,
    PhasedConfig,
    adapt_phases_by_modality,
    adapt_smoke_probes_by_language,
    build_phase_execute_cfg,
    build_phase_trend_data,
    check_token_budget,
    compute_adaptive_generations,
    evaluate_phase_result,
    interactive_checkpoint,
    load_phased_config,
    save_phase_decision_log,
    select_buff_by_defense_behavior,
    select_probes_for_phase,
)


# ---------------------------------------------------------------------------
# Gap #1: Phase 4 自适应 generations
# ---------------------------------------------------------------------------

class TestAdaptiveGenerations:
    """Gap #1: 根据 CI 宽度动态计算 Phase 4 generations"""

    def test_adaptive_generations_ci_driven(self):
        """CI 宽度大时应增加 generations"""
        results = [
            PhaseResult(
                phase_id=1, name="test", probe_count=5, probes_succeeded=5,
                probes_failed=0, worst_asr=40.0, hit_count=2,
                ci_width=60.0,  # CI 宽度 60% → 需要更多 generations
                asr_by_probe={"probe.a": 40.0, "probe.b": 20.0},
            ),
        ]
        gen = compute_adaptive_generations(
            ["probe.a", "probe.b"], results, base_generations=10,
        )
        assert gen > 10, f"CI 宽度 60% 应增加 generations > 10, got {gen}"
        assert gen <= 100, f"generations 不应超 100, got {gen}"

    def test_adaptive_generations_ci_narrow(self):
        """CI 宽度小时保持 base generations"""
        results = [
            PhaseResult(
                phase_id=1, name="test", probe_count=5, probes_succeeded=5,
                probes_failed=0, worst_asr=40.0, hit_count=2,
                ci_width=15.0,  # CI 宽度 15% < 20% → 不需要增加
                asr_by_probe={"probe.a": 40.0},
            ),
        ]
        gen = compute_adaptive_generations(
            ["probe.a"], results, base_generations=10,
        )
        assert gen == 10, f"CI 宽度 15% 应保持 base=10, got {gen}"

    def test_adaptive_generations_no_ci_data(self):
        """无 CI 数据时用默认值"""
        results = [
            PhaseResult(
                phase_id=1, name="test", probe_count=5, probes_succeeded=5,
                probes_failed=0, worst_asr=40.0, hit_count=2,
                ci_width=0.0,  # 无 CI 数据
            ),
        ]
        gen = compute_adaptive_generations(
            ["probe.a"], results, base_generations=10,
        )
        assert gen == 10


# ---------------------------------------------------------------------------
# Gap #2: 阶段间并发自适应
# ---------------------------------------------------------------------------

class TestParallelAdaptive:
    """Gap #2: Phase 0 高并发 / Phase 4 低并发"""

    def test_phase0_high_parallel(self):
        """Phase 0 应使用高并发"""
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 0)
        assert phase.parallel_requests == 4, "Phase 0 应 parallel_requests=4"

        cfg = build_phase_execute_cfg(phase, {"parallel_requests": 1}, PhasedConfig())
        assert cfg["parallel_requests"] == 4, "Phase 0 应覆盖并发为 4"
        assert cfg["rate_limit"]["max_rpm"] >= 120, "Phase 0 应放宽 max_rpm"

    def test_phase4_low_parallel(self):
        """Phase 4 应使用低并发"""
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 4)
        assert phase.parallel_requests == 1, "Phase 4 应 parallel_requests=1"

        cfg = build_phase_execute_cfg(
            phase,
            {"parallel_requests": 4, "rate_limit": {"max_rpm": 60}},
            PhasedConfig(),
        )
        assert cfg["parallel_requests"] == 1, "Phase 4 应覆盖并发为 1"
        assert cfg["rate_limit"]["max_rpm"] <= 30, "Phase 4 应收紧 max_rpm"


# ---------------------------------------------------------------------------
# Gap #3: Phase 2 Buff 策略自适应
# ---------------------------------------------------------------------------

class TestBuffStrategyAdaptive:
    """Gap #3: 根据 refusal_rate 动态选择 Buff"""

    def test_buff_high_refusal(self):
        """高拒绝率 → 翻译+小写 Buff"""
        cfg = PhasedConfig()
        buff = select_buff_by_defense_behavior(60.0, cfg)
        assert "translation" in buff.lower(), f"高拒绝率应用翻译 Buff, got {buff}"

    def test_buff_medium_refusal(self):
        """中等拒绝率 → Base64 Buff"""
        cfg = PhasedConfig()
        buff = select_buff_by_defense_behavior(30.0, cfg)
        assert "base64" in buff.lower(), f"中等拒绝率应用 Base64 Buff, got {buff}"

    def test_buff_low_refusal(self):
        """低拒绝率 → 无 Buff"""
        cfg = PhasedConfig()
        buff = select_buff_by_defense_behavior(10.0, cfg)
        assert buff == "", f"低拒绝率应无 Buff, got {buff}"


# ---------------------------------------------------------------------------
# Gap #4: 多模态探针在 Phase 1 优先级提升
# ---------------------------------------------------------------------------

class TestVLMProbePromotion:
    """Gap #4: VLM 探针从 tier2 提升到 Phase 1"""

    def test_vlm_probes_promoted_to_phase1(self):
        """image 模态目标应在 Phase 1 追加 VLM 探针"""
        phases = adapt_phases_by_modality(DEFAULT_PHASES, ["text", "image"])
        phase1 = next(p for p in phases if p.phase_id == 1)
        assert phase1.fixed_probes is not None, "Phase 1 应有 fixed_probes（VLM 提权）"
        # 应包含 VisualJailbreak
        vlm_names = [p for p in phase1.fixed_probes if "visual" in p.lower()]
        assert len(vlm_names) > 0, "Phase 1 fixed_probes 应含 VLM 探针"

    def test_text_only_no_promotion(self):
        """text-only 目标不应追加 VLM 探针"""
        phases = adapt_phases_by_modality(DEFAULT_PHASES, ["text"])
        phase1 = next(p for p in phases if p.phase_id == 1)
        assert phase1.fixed_probes is None, "text-only 目标 Phase 1 不应有 fixed_probes"

    def test_phase1_select_includes_vlm(self):
        """Phase 1 探针选择应包含 VLM 提权探针"""
        phases = adapt_phases_by_modality(DEFAULT_PHASES, ["text", "image"])
        phase1 = next(p for p in phases if p.phase_id == 1)
        all_probes = [
            {"name": "probes.dan.DanInTheWild", "tier": 1},
            {"name": "probes.visualgame.VisualJailbreak", "tier": 2},
        ]
        selected = select_probes_for_phase(phase1, all_probes)
        names = [p["name"] for p in selected]
        assert "probes.visualgame.VisualJailbreak" in names, \
            "VLM 探针应被选入 Phase 1"


# ---------------------------------------------------------------------------
# Gap #5: token 预算控制
# ---------------------------------------------------------------------------

class TestTokenBudget:
    """Gap #5: 阶段间 token 预算控制"""

    def test_token_budget_exceeded(self):
        """超预算时应返回 True"""
        cfg = PhasedConfig(max_tokens_budget=100000)
        over, reason = check_token_budget(120000, cfg)
        assert over is True
        assert "100000" in reason

    def test_token_budget_within(self):
        """未超预算时应返回 False"""
        cfg = PhasedConfig(max_tokens_budget=100000)
        over, _ = check_token_budget(50000, cfg)
        assert over is False

    def test_token_budget_unlimited(self):
        """0 = 不限制"""
        cfg = PhasedConfig(max_tokens_budget=0)
        over, _ = check_token_budget(999999999, cfg)
        assert over is False


# ---------------------------------------------------------------------------
# Gap #6: 决策门 ASR 阈值可配置化
# ---------------------------------------------------------------------------

class TestConfigurableThresholds:
    """Gap #6: 决策门 ASR 阈值可配置"""

    def test_configurable_asr_thresholds(self):
        """自定义阈值应影响决策门"""
        cfg = PhasedConfig(critical_asr_threshold=30.0)
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 1)
        result = PhaseResult(
            phase_id=1, name="test", probe_count=5, probes_succeeded=5,
            probes_failed=0, worst_asr=35.0, hit_count=2,
        )
        decision, reason = evaluate_phase_result(phase, result, 2, cfg)
        assert decision == "continue"
        assert "CRITICAL" in reason, f"ASR=35% > 30% 阈值应标记 CRITICAL, got: {reason}"

    def test_default_threshold(self):
        """默认阈值 50%"""
        cfg = PhasedConfig()
        assert cfg.critical_asr_threshold == 50.0

    def test_skip_phase3_configurable(self):
        """skip_phase3_if_no_hits=true 时跳过"""
        cfg = PhasedConfig(skip_phase3_if_no_hits=True)
        phase2 = next(p for p in DEFAULT_PHASES if p.phase_id == 2)
        result = PhaseResult(
            phase_id=2, name="test", probe_count=5, probes_succeeded=5,
            probes_failed=0, worst_asr=0.0, hit_count=0,
        )
        decision, _ = evaluate_phase_result(phase2, result, 0, cfg)
        assert decision == "skip", "skip_phase3_if_no_hits=true 应跳过"

    def test_load_from_yaml(self):
        """从 yaml dict 加载配置"""
        yaml_cfg = {
            "critical_asr_threshold": 25.0,
            "max_tokens_budget": 500000,
            "interactive": True,
            "phase4_enable_atkgen": True,
        }
        cfg = load_phased_config(yaml_cfg)
        assert cfg.critical_asr_threshold == 25.0
        assert cfg.max_tokens_budget == 500000
        assert cfg.interactive is True
        assert cfg.phase4_enable_atkgen is True


# ---------------------------------------------------------------------------
# Gap #7: Phase 0 探针语言适配
# ---------------------------------------------------------------------------

class TestSmokeProbeLanguage:
    """Gap #7: Phase 0 探针语言适配"""

    def test_smoke_probes_zh(self):
        """中文目标应使用中文冒烟探针"""
        phases = adapt_smoke_probes_by_language(DEFAULT_PHASES, "zh")
        phase0 = next(p for p in phases if p.phase_id == 0)
        assert "zh" in phase0.desc, "Phase 0 desc 应标注语言=zh"
        # 应包含中文翻译注入探针
        assert any("translation" in p.lower() for p in phase0.fixed_probes), \
            "中文目标应含中文翻译注入探针"

    def test_smoke_probes_en(self):
        """英文目标应使用英文冒烟探针"""
        phases = adapt_smoke_probes_by_language(DEFAULT_PHASES, "en")
        phase0 = next(p for p in phases if p.phase_id == 0)
        assert "en" in phase0.desc
        assert "probes.dan.DanInTheWild" in phase0.fixed_probes

    def test_smoke_probes_unknown(self):
        """未知语言应默认英文"""
        phases = adapt_smoke_probes_by_language(DEFAULT_PHASES, "unknown")
        phase0 = next(p for p in phases if p.phase_id == 0)
        assert "probes.dan.DanInTheWild" in phase0.fixed_probes


# ---------------------------------------------------------------------------
# Gap #8: 阶段趋势数据
# ---------------------------------------------------------------------------

class TestPhaseTrendData:
    """Gap #8: 阶段趋势数据构建"""

    def test_phase_trend_data(self):
        """应正确构建阶段趋势数据"""
        results = [
            PhaseResult(
                phase_id=0, name="冒烟", probe_count=3, probes_succeeded=3,
                probes_failed=0, worst_asr=0.0, hit_count=0,
                tokens_consumed=100, elapsed_seconds=5.0, decision="continue",
            ),
            PhaseResult(
                phase_id=1, name="高危", probe_count=20, probes_succeeded=18,
                probes_failed=2, worst_asr=30.0, hit_count=5,
                tokens_consumed=5000, elapsed_seconds=120.0, decision="continue",
            ),
            PhaseResult(
                phase_id=2, name="扩展", probe_count=30, probes_succeeded=28,
                probes_failed=2, worst_asr=15.0, hit_count=3,
                tokens_consumed=8000, elapsed_seconds=180.0, decision="continue",
            ),
        ]
        trend = build_phase_trend_data(results)

        assert trend["phase_count"] == 3
        assert trend["phases_executed"] == 3
        assert len(trend["trend_points"]) == 3
        assert trend["trend_points"][0]["phase_id"] == 0
        assert trend["trend_points"][1]["cumulative_hits"] == 5
        assert trend["trend_points"][2]["cumulative_hits"] == 8
        # ASR 从 0 → 30 → 15, first < last → decreasing? No: 0→30 is increasing
        assert trend["asr_trend_direction"] == "increasing"
        assert trend["cumulative_tokens"] == 13100

    def test_phase_trend_insufficient(self):
        """仅 1 个阶段时应返回 insufficient"""
        results = [
            PhaseResult(
                phase_id=0, name="冒烟", probe_count=3, probes_succeeded=3,
                probes_failed=0, worst_asr=0.0, hit_count=0, decision="continue",
            ),
        ]
        trend = build_phase_trend_data(results)
        assert trend["asr_trend_direction"] == "insufficient"


# ---------------------------------------------------------------------------
# Gap #9: Phase 4 atkgen 动态变异集成
# ---------------------------------------------------------------------------

class TestAtkgenIntegration:
    """Gap #9: Phase 4 atkgen 动态变异集成"""

    def test_atkgen_enabled_in_phase4(self):
        """phase4_enable_atkgen=true 时 cfg 应含 atkgen 标记"""
        cfg = PhasedConfig(phase4_enable_atkgen=True)
        phase4 = next(p for p in DEFAULT_PHASES if p.phase_id == 4)
        execute_cfg = build_phase_execute_cfg(
            phase4, {}, cfg, {"enabled": True, "num_mutations": 3},
        )
        assert execute_cfg.get("_phased_atkgen_enabled") is True
        assert execute_cfg.get("_atkgen_cfg") is not None

    def test_atkgen_disabled_by_default(self):
        """默认不启用 atkgen"""
        cfg = PhasedConfig()
        phase4 = next(p for p in DEFAULT_PHASES if p.phase_id == 4)
        execute_cfg = build_phase_execute_cfg(phase4, {}, cfg)
        assert not execute_cfg.get("_phased_atkgen_enabled")


# ---------------------------------------------------------------------------
# Gap #10: 阶段间人工确认断点
# ---------------------------------------------------------------------------

class TestInteractiveCheckpoint:
    """Gap #10: 阶段间人工确认断点"""

    def test_interactive_disabled(self):
        """interactive=False 时应直接 continue"""
        cfg = PhasedConfig(interactive=False)
        phase = DEFAULT_PHASES[0]
        result = PhaseResult(
            phase_id=0, name="冒烟", probe_count=3, probes_succeeded=3,
            probes_failed=0, worst_asr=0.0, hit_count=0,
        )
        next_phase = DEFAULT_PHASES[1]
        decision = interactive_checkpoint(phase, result, next_phase, cfg)
        assert decision == "continue"

    def test_interactive_continue(self):
        """interactive=True, 输入 c → continue"""
        cfg = PhasedConfig(interactive=True)
        phase = DEFAULT_PHASES[0]
        result = PhaseResult(
            phase_id=0, name="冒烟", probe_count=3, probes_succeeded=3,
            probes_failed=0, worst_asr=0.0, hit_count=0,
        )
        next_phase = DEFAULT_PHASES[1]
        with patch("builtins.input", return_value="c"):
            decision = interactive_checkpoint(phase, result, next_phase, cfg)
        assert decision == "continue"

    def test_interactive_stop(self):
        """interactive=True, 输入 q → stop"""
        cfg = PhasedConfig(interactive=True)
        phase = DEFAULT_PHASES[0]
        result = PhaseResult(
            phase_id=0, name="冒烟", probe_count=3, probes_succeeded=3,
            probes_failed=0, worst_asr=0.0, hit_count=0,
        )
        next_phase = DEFAULT_PHASES[1]
        with patch("builtins.input", return_value="q"):
            decision = interactive_checkpoint(phase, result, next_phase, cfg)
        assert decision == "stop"

    def test_interactive_skip(self):
        """interactive=True, 输入 s → skip"""
        cfg = PhasedConfig(interactive=True)
        phase = DEFAULT_PHASES[0]
        result = PhaseResult(
            phase_id=0, name="冒烟", probe_count=3, probes_succeeded=3,
            probes_failed=0, worst_asr=0.0, hit_count=0,
        )
        next_phase = DEFAULT_PHASES[1]
        with patch("builtins.input", return_value="s"):
            decision = interactive_checkpoint(phase, result, next_phase, cfg)
        assert decision == "skip"

    def test_interactive_no_next_phase(self):
        """无下一阶段时应 continue"""
        cfg = PhasedConfig(interactive=True)
        phase = DEFAULT_PHASES[-1]
        result = PhaseResult(
            phase_id=4, name="深度", probe_count=3, probes_succeeded=3,
            probes_failed=0, worst_asr=50.0, hit_count=2,
        )
        decision = interactive_checkpoint(phase, result, None, cfg)
        assert decision == "continue"


# ---------------------------------------------------------------------------
# 决策门综合测试
# ---------------------------------------------------------------------------

class TestDecisionGate:
    """决策门评估综合测试"""

    def test_phase0_all_fail_stop(self):
        """Phase 0 全失败 → 终止"""
        cfg = PhasedConfig()
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 0)
        result = PhaseResult(
            phase_id=0, name="冒烟", probe_count=3, probes_succeeded=0,
            probes_failed=3, worst_asr=0.0, hit_count=0,
        )
        decision, reason = evaluate_phase_result(phase, result, 0, cfg)
        assert decision == "stop"
        assert "失败" in reason

    def test_phase0_partial_success_continue(self):
        """Phase 0 部分成功 → 继续"""
        cfg = PhasedConfig()
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 0)
        result = PhaseResult(
            phase_id=0, name="冒烟", probe_count=3, probes_succeeded=2,
            probes_failed=1, worst_asr=10.0, hit_count=1,
        )
        decision, _ = evaluate_phase_result(phase, result, 1, cfg)
        assert decision == "continue"

    def test_phase1_critical(self):
        """Phase 1 ASR > critical → CRITICAL"""
        cfg = PhasedConfig(critical_asr_threshold=50.0)
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 1)
        result = PhaseResult(
            phase_id=1, name="高危", probe_count=20, probes_succeeded=20,
            probes_failed=0, worst_asr=60.0, hit_count=5,
        )
        decision, reason = evaluate_phase_result(phase, result, 5, cfg)
        assert decision == "continue"
        assert "CRITICAL" in reason

    def test_phase2_no_hits_skip_phase3(self):
        """Phase 2 无命中 + skip_phase3_if_no_hits → 跳过"""
        cfg = PhasedConfig(skip_phase3_if_no_hits=True)
        phase2 = next(p for p in DEFAULT_PHASES if p.phase_id == 2)
        result = PhaseResult(
            phase_id=2, name="扩展", probe_count=30, probes_succeeded=30,
            probes_failed=0, worst_asr=0.0, hit_count=0,
        )
        decision, _ = evaluate_phase_result(phase2, result, 0, cfg)
        assert decision == "skip"


# ---------------------------------------------------------------------------
# 决策日志保存测试
# ---------------------------------------------------------------------------

class TestDecisionLog:
    """决策日志保存测试"""

    def test_save_decision_log(self, tmp_path):
        """决策日志应正确保存为 JSON"""
        results = [
            PhaseResult(
                phase_id=0, name="冒烟", probe_count=3, probes_succeeded=3,
                probes_failed=0, worst_asr=0.0, hit_count=0,
                elapsed_seconds=5.0, decision="continue",
                decision_reason="冒烟验证通过",
                refusal_rate=10.0, ci_width=20.0, tokens_consumed=100,
            ),
        ]
        log_path = save_phase_decision_log(
            results, "test_run_001", str(tmp_path),
        )
        assert Path(log_path).exists()
        with open(log_path, encoding="utf-8") as f:
            data = json.load(f)
        assert data["run_id"] == "test_run_001"
        assert data["total_phases"] == 1
        assert data["phases"][0]["phase_id"] == 0
        assert data["phases"][0]["refusal_rate"] == 10.0
        assert data["phases"][0]["tokens_consumed"] == 100
        assert data["summary"]["total_hits"] == 0


# ---------------------------------------------------------------------------
# 探针选择测试
# ---------------------------------------------------------------------------

class TestProbeSelection:
    """探针选择测试"""

    def test_select_phase0_fixed(self):
        """Phase 0 应选固定探针子集"""
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 0)
        all_probes = [
            {"name": "probes.dan.DanInTheWild", "tier": 1},
            {"name": "probes.latentinjection.LatentJailbreak", "tier": 1},
            {"name": "probes.dan.Ablation_Dan_11_0", "tier": 1},
            {"name": "probes.other.OtherProbe", "tier": 2},
        ]
        selected = select_probes_for_phase(phase, all_probes)
        names = [p["name"] for p in selected]
        assert "probes.dan.DanInTheWild" in names
        assert "probes.other.OtherProbe" not in names

    def test_select_phase1_by_tier(self):
        """Phase 1 应按 tier=1 过滤"""
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 1)
        all_probes = [
            {"name": "probe.tier1a", "tier": 1},
            {"name": "probe.tier1b", "tier": 1},
            {"name": "probe.tier2a", "tier": 2},
            {"name": "probe.tier3a", "tier": 3},
        ]
        selected = select_probes_for_phase(phase, all_probes)
        assert len(selected) == 2
        for p in selected:
            assert p["tier"] == 1

    def test_select_phase4_hit_probes(self):
        """Phase 4 应仅选命中探针"""
        phase = next(p for p in DEFAULT_PHASES if p.phase_id == 4)
        all_probes = [
            {"name": "probe.hit1", "tier": 1},
            {"name": "probe.hit2", "tier": 2},
            {"name": "probe.miss1", "tier": 1},
        ]
        selected = select_probes_for_phase(
            phase, all_probes, hit_probes=["probe.hit1", "probe.hit2"],
        )
        names = [p["name"] for p in selected]
        assert "probe.hit1" in names
        assert "probe.hit2" in names
        assert "probe.miss1" not in names


# ---------------------------------------------------------------------------
# PhaseConfig / PhasedConfig 数据类测试
# ---------------------------------------------------------------------------

class TestDataclasses:
    """数据类完整性测试"""

    def test_phase_config_fields(self):
        """PhaseConfig 应含全部 gap 字段"""
        p = PhaseConfig(
            phase_id=0, name="test", desc="test",
            tiers=None, buff_spec="", generations=1, soft_prompt_cap=3,
        )
        assert hasattr(p, "max_tokens_budget")
        assert hasattr(p, "parallel_requests")
        assert hasattr(p, "adaptive_generations")

    def test_phase_result_fields(self):
        """PhaseResult 应含全部 gap 字段"""
        r = PhaseResult(
            phase_id=0, name="test", probe_count=1,
            probes_succeeded=1, probes_failed=0, worst_asr=0.0, hit_count=0,
        )
        assert hasattr(r, "refusal_rate")
        assert hasattr(r, "ci_width")
        assert hasattr(r, "tokens_consumed")
        assert hasattr(r, "asr_by_probe")
        assert r.refusal_rate == 0.0
        assert r.ci_width == 0.0
        assert r.tokens_consumed == 0
        assert r.asr_by_probe == {}

    def test_phased_config_defaults(self):
        """PhasedConfig 默认值"""
        cfg = PhasedConfig()
        assert cfg.critical_asr_threshold == 50.0
        assert cfg.continue_asr_threshold == 0.0
        assert cfg.max_tokens_budget == 0
        assert cfg.phase0_parallel_requests == 4
        assert cfg.phase4_parallel_requests == 1
        assert cfg.interactive is False
        assert cfg.phase4_enable_atkgen is False

    def test_load_phased_config_none(self):
        """load_phased_config(None) 应返回默认配置"""
        cfg = load_phased_config(None)
        assert cfg.critical_asr_threshold == 50.0
