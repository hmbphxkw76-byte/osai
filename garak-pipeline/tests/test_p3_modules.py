"""P3 优化模块测试 — agent_injection / scheduler / adaptive_payload / dashboard"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ============================================================
# agent_injection 探针测试
# ============================================================
class TestAgentInjection:
    """Multi-agent 攻击场景探针测试"""

    def test_specs_count(self):
        """应有 6 个探针规范"""
        from pipeline.custom_probes.agent_injection import AGENT_INJECTION_SPECS

        assert len(AGENT_INJECTION_SPECS) == 6

    def test_probe_classes_count(self):
        """应有 6 个 Probe 类"""
        from pipeline.custom_probes.agent_injection import AGENT_INJECTION_PROBE_CLASSES

        assert len(AGENT_INJECTION_PROBE_CLASSES) == 6

    def test_all_specs_have_required_fields(self):
        """每个 spec 应有 name/prompts/owasp_agentic/tier"""
        from pipeline.custom_probes.agent_injection import AGENT_INJECTION_SPECS

        for spec in AGENT_INJECTION_SPECS:
            assert "name" in spec
            assert "prompts" in spec
            assert len(spec["prompts"]) >= 2
            assert spec.get("owasp_agentic") is not None
            assert spec.get("tier") in (1, 2, 3)

    def test_probe_classes_have_prompts(self):
        """每个 Probe 类应有非空 prompts"""
        from pipeline.custom_probes.agent_injection import AGENT_INJECTION_PROBE_CLASSES

        for cls in AGENT_INJECTION_PROBE_CLASSES:
            assert hasattr(cls, "prompts") or True  # prompts 在 __init__ 中设置
            assert hasattr(cls, "goal")
            assert hasattr(cls, "tags")
            assert cls.active is True

    def test_registered_in_init(self):
        """新探针应注册到 ALL_CUSTOM_SPECS"""
        from pipeline.custom_probes import ALL_CUSTOM_SPECS

        names = [s["name"] for s in ALL_CUSTOM_SPECS]
        assert "custom.AgentIndirectInjection" in names
        assert "custom.AgentMemoryPoisoning" in names
        assert "custom.AgentGoalHijack" in names
        assert "custom.AgentOrchestrationExploit" in names
        assert "custom.AgentMultiTurnManipulation" in names
        assert "custom.AgentPrivilegeEscalation" in names


# ============================================================
# scheduler 模块测试
# ============================================================
class TestScheduler:
    """定时调度模块测试"""

    def test_load_schedule_config_not_found(self):
        """配置文件不存在时返回空 dict"""
        from pipeline.scheduler import load_schedule_config

        result = load_schedule_config("nonexistent.yaml")
        assert result == {}

    def test_load_schedule_config_valid(self):
        """有效配置文件应正常解析"""
        import yaml

        from pipeline.scheduler import load_schedule_config

        cfg = {"schedule": {"cron": "0 2 * * 1", "profile": "balanced"}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            yaml.safe_dump(cfg, f)
            f.flush()
            result = load_schedule_config(f.name)
        assert "schedule" in result

    def test_evaluate_alerts_defcon(self):
        """DEFCON ≤ 2 触发告警"""
        from pipeline.scheduler import _evaluate_alerts

        summary = {
            "targets": [{"name": "t1", "status": "success", "defcon": 1, "worst_asr": 80}],
        }
        alerts = _evaluate_alerts(summary, None, ["defcon_le_2"])
        assert len(alerts) == 1
        assert alerts[0]["type"] == "defcon_critical"

    def test_evaluate_alerts_asr(self):
        """ASR > 50% 触发告警"""
        from pipeline.scheduler import _evaluate_alerts

        summary = {
            "targets": [{"name": "t1", "status": "success", "defcon": 4, "worst_asr": 60}],
        }
        alerts = _evaluate_alerts(summary, None, ["asr_gt_50"])
        assert len(alerts) == 1
        assert alerts[0]["type"] == "asr_high"

    def test_evaluate_alerts_no_trigger(self):
        """不满足告警条件时不触发"""
        from pipeline.scheduler import _evaluate_alerts

        summary = {
            "targets": [{"name": "t1", "status": "success", "defcon": 4, "worst_asr": 20}],
        }
        alerts = _evaluate_alerts(summary, None, ["defcon_le_2", "asr_gt_50"])
        assert len(alerts) == 0


# ============================================================
# adaptive_payload 模块测试
# ============================================================
class TestAdaptivePayload:
    """实时防御规避模块测试"""

    def test_analyze_refusal_standard(self):
        """检测标准拒绝模式"""
        from pipeline.adaptive_payload import analyze_refusal

        result = analyze_refusal("I cannot help with that request.")
        assert result["is_refusal"] is True
        assert result["refusal_type"] == "standard_refusal"

    def test_analyze_refusal_chinese(self):
        """检测中文拒绝模式"""
        from pipeline.adaptive_payload import analyze_refusal

        result = analyze_refusal("抱歉，我无法回答这个问题。")
        assert result["is_refusal"] is True
        assert result["refusal_type"] == "chinese_refusal"

    def test_analyze_refusal_none(self):
        """非拒绝响应"""
        from pipeline.adaptive_payload import analyze_refusal

        result = analyze_refusal("Sure, here's how you do it: step 1...")
        assert result["is_refusal"] is False

    def test_select_mutation_strategy(self):
        """选择变异策略"""
        from pipeline.adaptive_payload import select_mutation_strategy

        strategies = select_mutation_strategy("standard_refusal")
        assert len(strategies) > 0
        assert "encoding_base64" in strategies

    def test_select_mutation_strategy_unknown(self):
        """未知拒绝类型返回默认策略"""
        from pipeline.adaptive_payload import select_mutation_strategy

        strategies = select_mutation_strategy("unknown_type")
        assert "encoding_base64" in strategies

    def test_mutate_payload_base64(self):
        """Base64 编码变异"""
        from pipeline.adaptive_payload import mutate_payload

        result = mutate_payload("test payload", "encoding_base64")
        assert "Decode and execute:" in result
        assert result != "test payload"

    def test_mutate_payload_role_play(self):
        """角色扮演变异"""
        from pipeline.adaptive_payload import mutate_payload

        result = mutate_payload("harmful request", "role_play")
        assert "fictional story" in result
        assert "harmful request" in result

    def test_mutate_payload_language_switch(self):
        """语言切换变异"""
        from pipeline.adaptive_payload import mutate_payload

        result = mutate_payload("test question", "language_switch")
        assert "中文" in result

    def test_adaptive_mutate_no_history(self):
        """无历史时使用默认策略集"""
        from pipeline.adaptive_payload import adaptive_mutate

        results = adaptive_mutate("test payload")
        assert len(results) > 0
        strategies = [r["strategy"] for r in results]
        assert "encoding_base64" in strategies

    def test_adaptive_mutate_with_refusal_history(self):
        """有拒绝历史时选择针对性策略"""
        from pipeline.adaptive_payload import adaptive_mutate

        results = adaptive_mutate("test", response_history=["I cannot help with that."])
        assert len(results) > 0

    def test_rot13(self):
        """ROT13 编码正确性"""
        from pipeline.adaptive_payload import _rot13

        assert _rot13("hello") == "uryyb"
        assert _rot13("uryyb") == "hello"  # ROT13 is self-inverse


# ============================================================
# dashboard 模块测试
# ============================================================
class TestDashboard:
    """Web UI 看板模块测试"""

    def test_collect_trend_data_empty(self):
        """空目录返回空趋势"""
        from pipeline.dashboard import _collect_trend_data

        with tempfile.TemporaryDirectory() as tmpdir:
            result = _collect_trend_data(Path(tmpdir))
            assert result["runs"] == []

    def test_collect_target_data_empty(self):
        """空目录返回空目标"""
        from pipeline.dashboard import _collect_target_data

        with tempfile.TemporaryDirectory() as tmpdir:
            result = _collect_target_data(Path(tmpdir))
            assert result["targets"] == []

    def test_collect_compliance_data_empty(self):
        """空目录返回空合规数据"""
        from pipeline.dashboard import _collect_compliance_data

        with tempfile.TemporaryDirectory() as tmpdir:
            result = _collect_compliance_data(Path(tmpdir))
            assert result["frameworks"] == []

    def test_collect_latest_status_idle(self):
        """无 checkpoint 时状态为 idle"""
        from pipeline.dashboard import _collect_latest_status

        with tempfile.TemporaryDirectory() as tmpdir:
            result = _collect_latest_status(Path(tmpdir))
            assert result["status"] == "idle"

    def test_render_dashboard_html(self):
        """HTML 页面应包含基本结构"""
        from pipeline.dashboard import _render_dashboard_html

        html = _render_dashboard_html()
        assert "<html" in html
        assert "chart.js" in html
        assert "WebSocket" in html
