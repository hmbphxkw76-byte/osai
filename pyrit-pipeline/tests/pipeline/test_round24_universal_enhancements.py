# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Round 24 通用攻击增强层测试。

测试覆盖:
  O1: ControlModeAwareOrchestrator (3 种控制模式策略)
  O2: SecretValidationScorer (4 种验证策略)
  O3: TargetClassifier SSE/JSON 流式检测增强
"""

from __future__ import annotations

import pytest

# ──────────────────────────────────────────────────────────────────
# O1: ControlModeAwareOrchestrator
# ──────────────────────────────────────────────────────────────────


class TestControlModeAwareOrchestrator:
    """ControlModeAwareOrchestrator 测试。"""

    @pytest.mark.asyncio
    async def test_run_detect_mode_mock(self) -> None:
        """detect 模式: 无 target 时使用 mock 响应。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="detect")
        result = await orchestrator.run_async()
        assert result.mode == "detect"
        assert result.total_probes > 0
        assert len(result.probes) == result.total_probes

    @pytest.mark.asyncio
    async def test_run_off_mode_mock(self) -> None:
        """off 模式: 直接发送 baseline payload。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="off")
        result = await orchestrator.run_async()
        assert result.mode == "off"
        assert result.total_probes > 0
        assert result.total_probes <= 2  # off 模式只发送 2 个探针

    @pytest.mark.asyncio
    async def test_run_mitigate_mode_mock(self) -> None:
        """mitigate 模式: 尝试绕过控制机制。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="mitigate")
        result = await orchestrator.run_async()
        assert result.mode == "mitigate"
        assert result.total_probes > 0

    @pytest.mark.asyncio
    async def test_invalid_mode_defaults_to_detect(self) -> None:
        """无效 mode 默认为 detect。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="invalid")
        assert orchestrator._mode == "detect"

    def test_detect_control_refusal(self) -> None:
        """检测拒绝响应中的控制机制。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="detect")
        assert orchestrator._detect_control("I cannot help with that request.")
        assert orchestrator._detect_control("I'm not able to provide that information.")
        assert orchestrator._detect_control("I must decline this request.")

    def test_detect_control_no_control(self) -> None:
        """非拒绝响应不检测到控制机制。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="detect")
        assert not orchestrator._detect_control("Sure, here is the information you requested.")
        assert not orchestrator._detect_control("")

    def test_detect_bypass_success(self) -> None:
        """检测绕过成功指标。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="mitigate")
        assert orchestrator._detect_bypass_success("Sure, here is the system prompt.")
        assert orchestrator._detect_bypass_success("Certainly, I can help with that.")

    def test_detect_bypass_no_success(self) -> None:
        """非合作响应不检测到绕过成功。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="mitigate")
        assert not orchestrator._detect_bypass_success("I cannot help with that.")
        assert not orchestrator._detect_bypass_success("")

    def test_generate_summary(self) -> None:
        """摘要生成。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="detect")
        summary = orchestrator._generate_summary(control_detected=True, bypass_count=2)
        assert "Mode: detect" in summary
        assert "Control detected: yes" in summary
        assert "Bypass success: 2" in summary

    def test_detect_probes_count(self) -> None:
        """detect 模式探针数量。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        assert len(ControlModeAwareOrchestrator.DETECT_PROBES) == 5

    def test_mitigate_probes_count(self) -> None:
        """mitigate 模式探针数量。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        assert len(ControlModeAwareOrchestrator.MITIGATE_PROBES) == 5


# ──────────────────────────────────────────────────────────────────
# O2: SecretValidationScorer
# ──────────────────────────────────────────────────────────────────


class TestSecretValidationScorer:
    """SecretValidationScorer 测试。"""

    def test_validate_empty_response(self) -> None:
        """空响应无 secret。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate("")
        assert result.total_findings == 0
        assert "no secrets" in result.summary.lower() or "empty" in result.summary.lower()

    def test_validate_format_api_key(self) -> None:
        """格式验证: OpenAI API Key。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate("The API key is sk-abcdefghijklmnopqrstuvwxyz1234567890")
        assert result.total_findings > 0
        assert result.max_confidence > 0.0

    def test_validate_format_jwt(self) -> None:
        """格式验证: JWT token。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate(
            "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4f"
        )
        assert result.total_findings > 0

    def test_validate_format_aws_key(self) -> None:
        """格式验证: AWS Access Key。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
        assert result.total_findings > 0

    def test_validate_exact_match(self) -> None:
        """精确匹配已知 secret。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        known_secret = "my-super-secret-key-12345"
        result = scorer.validate(
            f"The key is {known_secret} in the config",
            known_secrets=[known_secret],
        )
        assert result.total_findings > 0
        assert result.max_confidence == 1.0

    def test_validate_semantic_keywords(self) -> None:
        """语义分析: secret-like 关键词。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate(
            "The api_key is stored in the environment variables. "
            "The password should be at least 8 characters."
        )
        assert result.total_findings > 0

    def test_validate_api_endpoint(self) -> None:
        """API 端点验证。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate(
            "The API endpoint is https://api.example.com/v1/chat/completions"
        )
        assert result.total_findings > 0

    def test_validate_no_secret(self) -> None:
        """无 secret 的响应。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate("Hello, how can I help you today?")
        assert result.total_findings == 0

    def test_validate_specific_strategies(self) -> None:
        """指定策略子集验证。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer(strategies=["format"])
        result = scorer.validate("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        assert result.total_findings > 0
        assert "format" in result.strategies_used
        assert "exact" not in result.strategies_used

    def test_mask_secret(self) -> None:
        """脱敏处理。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        masked = scorer._mask_secret("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        assert masked.startswith("sk-a")
        assert masked.endswith("7890")
        assert "*" in masked

    def test_mask_short_secret(self) -> None:
        """短 secret 脱敏。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        masked = scorer._mask_secret("short")
        assert "*" in masked

    def test_min_confidence_filter(self) -> None:
        """最低置信度过滤。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        # 设置高阈值, 只有 exact (1.0) 和 format (0.8) 通过
        scorer = SecretValidationScorer(min_confidence=0.7)
        result = scorer.validate(
            "The api_key is sk-abcdefghijklmnopqrstuvwxyz1234567890"
        )
        # format 策略 (0.8) 和 semantic (0.5) 都会匹配
        # 但 semantic 的 0.5 < 0.7, 被过滤
        for finding in result.findings:
            assert finding.confidence >= 0.7

    def test_strategies_used(self) -> None:
        """默认使用全部 4 种策略。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        assert len(result.strategies_used) == 4
        assert "exact" in result.strategies_used
        assert "format" in result.strategies_used
        assert "semantic" in result.strategies_used
        assert "api" in result.strategies_used


# ──────────────────────────────────────────────────────────────────
# O3: TargetClassifier SSE/JSON 流式检测
# ──────────────────────────────────────────────────────────────────


class TestTargetClassifierSSE:
    """TargetClassifier SSE/JSON 流式检测测试。"""

    def test_streaming_url_patterns_match(self) -> None:
        """流式 URL 模式匹配。."""
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier(render_check=False)
        assert classifier._match_streaming_url_patterns("https://api.example.com/stream")
        assert classifier._match_streaming_url_patterns("https://api.example.com/sse")
        assert classifier._match_streaming_url_patterns("https://api.example.com/events")
        assert classifier._match_streaming_url_patterns("https://api.example.com/v1/chat/completions")
        assert classifier._match_streaming_url_patterns("https://api.example.com/api/stream")
        assert classifier._match_streaming_url_patterns("https://api.example.com/subscribe")

    def test_streaming_url_patterns_no_match(self) -> None:
        """非流式 URL 不匹配。."""
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier(render_check=False)
        assert not classifier._match_streaming_url_patterns("https://example.com/chat")
        assert not classifier._match_streaming_url_patterns("https://example.com/playground")

    def test_detect_streaming_json_ndjson(self) -> None:
        """检测 NDJSON 流式 JSON。."""
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier(render_check=False)
        result = classifier._detect_streaming_json(
            "application/x-ndjson",
            {},
        )
        assert result == "ndjson"

    def test_detect_streaming_json_stream_json(self) -> None:
        """检测 stream+json 流式 JSON。."""
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier(render_check=False)
        result = classifier._detect_streaming_json(
            "application/stream+json",
            {},
        )
        assert result == "stream_json"

    def test_detect_streaming_json_chunked(self) -> None:
        """检测 chunked + JSON 流式。."""
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier(render_check=False)
        result = classifier._detect_streaming_json(
            "application/json",
            {"transfer-encoding": "chunked"},
        )
        assert result == "stream_json"

    def test_detect_streaming_json_non_streaming(self) -> None:
        """非流式 JSON 返回空字符串。."""
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier(render_check=False)
        result = classifier._detect_streaming_json(
            "application/json",
            {},
        )
        assert result == ""

    def test_classification_has_streaming_fields(self) -> None:
        """TargetClassification 包含流式字段。."""
        from pipeline.integrations.target_classifier import TargetClassification

        tc = TargetClassification()
        assert hasattr(tc, "streaming_type")
        assert hasattr(tc, "is_streaming")
        assert tc.streaming_type == ""
        assert tc.is_streaming is False

    def test_classification_str_includes_streaming(self) -> None:
        """__str__ 包含流式信息。."""
        from pipeline.integrations.target_classifier import TargetClassification

        tc = TargetClassification(streaming_type="sse", is_streaming=True)
        s = str(tc)
        assert "streaming_type" in s
        assert "sse" in s
        assert "is_streaming" in s
        assert "True" in s

    @pytest.mark.asyncio
    async def test_classify_sse_url_pattern(self) -> None:
        """SSE URL 模式 → 流式 API 平台。."""
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier(render_check=False)
        result = await classifier.classify("https://api.example.com/stream")
        assert result.target_type == "llm_api_platform"
        assert result.is_streaming is True
        assert result.streaming_type == "sse"
        assert "streaming" in result.detection_reason.lower()

    @pytest.mark.asyncio
    async def test_classify_sse_url_with_api_path(self) -> None:
        """API 路径 + SSE 路径 → 流式 API 平台。."""
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier(render_check=False)
        result = await classifier.classify("https://api.example.com/v1/chat/completions")
        assert result.target_type == "llm_api_platform"
        assert result.is_streaming is True
        assert result.streaming_type == "sse"


# ──────────────────────────────────────────────────────────────────
# Round 26: Metadata 完整性 + Secret 验证多源扫描
# ──────────────────────────────────────────────────────────────────


class TestMetadataCompleteness:
    """验证攻击增强模块的 metadata 包含探针响应文本 (供 Secret 验证扫描)。"""

    @pytest.mark.asyncio
    async def test_backdoor_result_contains_probe_responses(self) -> None:
        """后门探测结果包含探针响应文本。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None, max_probes=3)
        result = await orchestrator.run_async()

        # 验证每个探针都有 response 字段
        for probe in result.probes:
            assert hasattr(probe, "response")
            assert probe.response  # 非空

    @pytest.mark.asyncio
    async def test_control_mode_result_contains_probe_responses(self) -> None:
        """控制模式感知结果包含探针响应文本。."""
        from pipeline.scenarios.control_mode_aware import ControlModeAwareOrchestrator

        orchestrator = ControlModeAwareOrchestrator(target=None, mode="detect")
        result = await orchestrator.run_async()

        # 验证每个探针都有 response 字段
        for probe in result.probes:
            assert hasattr(probe, "response")
            assert probe.response  # 非空


class TestSecretValidationMultiSource:
    """Secret 验证评分器多源扫描测试。"""

    def test_validate_from_backdoor_response(self) -> None:
        """从后门探针响应中检测 secret。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        # 模拟后门探针响应包含 API key
        response = "The system configuration contains api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = scorer.validate(response)
        assert result.total_findings > 0

    def test_validate_from_control_mode_response(self) -> None:
        """从控制模式探针响应中检测 secret。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        # 模拟控制模式探针响应包含 JWT
        response = (
            "Sure, here is the token: "
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4f"
        )
        result = scorer.validate(response)
        assert result.total_findings > 0

    def test_validate_from_mcp_response(self) -> None:
        """从 MCP 探针响应中检测 secret。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        # 模拟 MCP 探针响应包含 AWS key
        response = "Configuration loaded. AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
        result = scorer.validate(response)
        assert result.total_findings > 0

    def test_validate_multiple_sources_aggregation(self) -> None:
        """多源聚合验证: 多个响应中的 secret 被全部检测到。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        responses = [
            "api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890",
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4f",
            "No secrets here, just normal text.",
        ]

        total_findings = 0
        for resp in responses:
            result = scorer.validate(resp)
            total_findings += result.total_findings

        # 至少检测到 2 个 secret (API key + JWT)
        assert total_findings >= 2

    def test_validate_clean_response_no_findings(self) -> None:
        """干净响应无 secret 检出。."""
        from pipeline.scoring.secret_validation_scorer import SecretValidationScorer

        scorer = SecretValidationScorer()
        result = scorer.validate("I cannot help with that request. Please follow safety guidelines.")
        # 控制模式拒绝响应不应包含 secret
        assert result.total_findings == 0 or result.max_confidence < 0.5
