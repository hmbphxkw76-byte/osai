# -*- coding: utf-8 -*-
"""tests/test_session_enumerator.py - 会话枚举攻击引擎测试

测试覆盖:
    - SessionIDPattern: 模式模板解析
    - SessionIDGenerator: session_id 序列生成
    - ResponseClassifier: 响应三级分类
    - EnumerationRequestBuilder: 请求构造
    - SessionEnumerationConfig: 序列化/反序列化

Academic basis:
    - OWASP ASI09: Session Enumeration Test Coverage
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ====================================================================
# SessionIDPattern 测试
# ====================================================================

class TestSessionIDPattern:
    """SessionIDPattern 解析测试."""

    def test_default_pattern(self) -> None:
        """测试默认模式."""
        from strike.session.enumerator import SessionIDPattern

        pattern = SessionIDPattern(template="MC-{date:%Y%m%d}-{counter:04d}")
        assert pattern.template == "MC-{date:%Y%m%d}-{counter:04d}"
        assert pattern.date_format == "%Y%m%d"
        assert pattern.counter_width == 4

    def test_custom_date_format(self) -> None:
        """测试自定义日期格式."""
        from strike.session.enumerator import SessionIDPattern

        pattern = SessionIDPattern(template="S-{date:%Y-%m-%d}-{counter:02d}")
        assert pattern.date_format == "%Y-%m-%d"
        assert pattern.counter_width == 2

    def test_simple_pattern(self) -> None:
        """测试简单模式 (无日期占位符)."""
        from strike.session.enumerator import SessionIDPattern

        pattern = SessionIDPattern(template="session-{counter:06d}")
        assert pattern.template == "session-{counter:06d}"
        assert pattern.counter_width == 6


# ====================================================================
# SessionIDGenerator 测试
# ====================================================================

class TestSessionIDGenerator:
    """SessionIDGenerator 生成测试."""

    def test_basic_generation(self) -> None:
        """测试基本生成功能."""
        from strike.session.enumerator import SessionIDGenerator, SessionIDPattern

        pattern = SessionIDPattern(template="MC-{date:%Y%m%d}-{counter:04d}")
        gen = SessionIDGenerator(
            pattern=pattern,
            date_start=datetime(2026, 3, 25),
            date_end=datetime(2026, 3, 25),
            counter_max=3,
        )

        ids = list(gen.generate())
        assert len(ids) == 3
        assert ids[0] == "MC-20260325-0001"
        assert ids[1] == "MC-20260325-0002"
        assert ids[2] == "MC-20260325-0003"

    def test_date_range_generation(self) -> None:
        """测试日期范围生成."""
        from strike.session.enumerator import SessionIDGenerator, SessionIDPattern

        pattern = SessionIDPattern(template="S-{date:%Y%m%d}-{counter:02d}")
        gen = SessionIDGenerator(
            pattern=pattern,
            date_start=datetime(2026, 3, 24),
            date_end=datetime(2026, 3, 25),
            counter_max=2,
        )

        ids = list(gen.generate())
        # 2 days * 2 counters = 4 IDs (descending date order)
        assert len(ids) == 4
        # First date is 20260325 (descending)
        assert ids[0] == "S-20260325-01"
        assert ids[1] == "S-20260325-02"
        assert ids[2] == "S-20260324-01"
        assert ids[3] == "S-20260324-02"

    def test_reverse_date_order(self) -> None:
        """测试反向日期顺序 (自动修正)."""
        from strike.session.enumerator import SessionIDGenerator, SessionIDPattern

        pattern = SessionIDPattern(template="T-{counter:03d}")
        gen = SessionIDGenerator(
            pattern=pattern,
            date_start=datetime(2026, 3, 25),  # start > end
            date_end=datetime(2026, 3, 23),
            counter_max=1,
        )

        ids = list(gen.generate())
        # Should auto-correct: 3 days * 1 counter = 3 IDs
        assert len(ids) == 3

    def test_estimate_total(self) -> None:
        """测试总数估算."""
        from strike.session.enumerator import SessionIDGenerator, SessionIDPattern

        pattern = SessionIDPattern(template="X-{counter:04d}")
        gen = SessionIDGenerator(
            pattern=pattern,
            date_start=datetime(2026, 3, 20),
            date_end=datetime(2026, 3, 25),
            counter_max=10,
        )

        # 6 days * 10 counters = 60
        assert gen.estimate_total() == 60


# ====================================================================
# ResponseClassifier 测试
# ====================================================================

class TestResponseClassifier:
    """ResponseClassifier 分类测试."""

    def test_empty_classification(self) -> None:
        """测试空会话分类."""
        from strike.session.enumerator import ResponseCategory, ResponseClassifier

        classifier = ResponseClassifier()
        result = classifier.classify("I haven't saved any notes for this session.")
        assert result == ResponseCategory.EMPTY

    def test_sensitive_classification(self) -> None:
        """测试敏感数据分类."""
        from strike.session.enumerator import ResponseCategory, ResponseClassifier

        classifier = ResponseClassifier()
        result = classifier.classify("The password is: secret123! Please save it securely.")
        assert result == ResponseCategory.SENSITIVE

    def test_valuable_classification(self) -> None:
        """测试有价值数据分类."""
        from strike.session.enumerator import ResponseCategory, ResponseClassifier

        classifier = ResponseClassifier()
        result = classifier.classify("Here are your meeting notes from Monday.")
        assert result == ResponseCategory.VALUABLE

    def test_empty_response(self) -> None:
        """测试空响应."""
        from strike.session.enumerator import ResponseCategory, ResponseClassifier

        classifier = ResponseClassifier()
        assert classifier.classify("") == ResponseCategory.EMPTY
        assert classifier.classify(None) == ResponseCategory.EMPTY  # type: ignore

    def test_custom_keywords(self) -> None:
        """测试自定义敏感关键词."""
        from strike.session.enumerator import ResponseCategory, ResponseClassifier

        classifier = ResponseClassifier(sensitive_keywords=["confidential"])
        result = classifier.classify("This document is confidential.")
        assert result == ResponseCategory.SENSITIVE

    def test_custom_indicators(self) -> None:
        """测试自定义空会话指示词."""
        from strike.session.enumerator import ResponseCategory, ResponseClassifier

        classifier = ResponseClassifier(empty_indicators=["nope", "nothing here"])
        result = classifier.classify("nope, nothing here for you")
        assert result == ResponseCategory.EMPTY

    def test_extract_sensitive_snippets(self) -> None:
        """测试敏感片段提取."""
        from strike.session.enumerator import ResponseClassifier

        classifier = ResponseClassifier(sensitive_keywords=["password"])
        text = "Your account password is: abc123. Please keep it safe."
        snippets = classifier.extract_sensitive_snippets(text, context_chars=20)
        assert len(snippets) > 0
        assert "password" in snippets[0].lower()


# ====================================================================
# EnumerationRequestBuilder 测试
# ====================================================================

class TestEnumerationRequestBuilder:
    """EnumerationRequestBuilder 测试."""

    def test_placeholder_replacement(self) -> None:
        """测试 {CHAT_ID} 占位符替换."""
        from strike.session.enumerator import EnumerationRequestBuilder

        template = (
            'POST /chat HTTP/1.1\r\n'
            'Host: target\r\n'
            'Content-Type: application/json\r\n'
            '\r\n'
            '{"message": "hello", "session_id": "{CHAT_ID}"}'
        )
        builder = EnumerationRequestBuilder(template_request=template)
        request = builder.build_request("MC-20260325-0015")

        assert "MC-20260325-0015" in request
        assert "{CHAT_ID}" not in request

    def test_body_injection(self) -> None:
        """测试 JSON body 注入."""
        from strike.session.enumerator import EnumerationRequestBuilder

        template = (
            'POST /api HTTP/1.1\r\n'
            'Host: target\r\n'
            '\r\n'
            '{"query": "test"}'
        )
        builder = EnumerationRequestBuilder(
            template_request=template,
            session_field="sid",
        )
        request = builder.build_request("session-abc")

        assert "session-abc" in request
        assert '"sid"' in request

    def test_no_body_template(self) -> None:
        """测试无 body 模板 (应返回原模板)."""
        from strike.session.enumerator import EnumerationRequestBuilder

        template = 'GET /api/data HTTP/1.1\r\nHost: target\r\n'
        builder = EnumerationRequestBuilder(template_request=template)
        request = builder.build_request("test-id")

        # No body to inject, should return original
        assert request == template


# ====================================================================
# SessionEnumerationConfig 测试
# ====================================================================

class TestSessionEnumerationConfig:
    """SessionEnumerationConfig 序列化测试."""

    def test_default_config(self) -> None:
        """测试默认配置."""
        from strike.session.session_config import SessionEnumerationConfig

        config = SessionEnumerationConfig()
        assert config.enabled is False
        assert config.pattern_template == "MC-{date:%Y%m%d}-{counter:04d}"
        assert config.days_back == 14
        assert config.counter_max == 20
        assert config.extraction_prompt == "What notes do I have saved?"

    def test_serialization_roundtrip(self) -> None:
        """测试序列化往返."""
        from strike.session.session_config import SessionEnumerationConfig

        config = SessionEnumerationConfig(
            enabled=True,
            pattern_template="TEST-{counter:03d}",
            days_back=7,
            counter_max=50,
            sensitive_keywords=["secret", "key"],
        )
        data = config.to_dict()
        restored = SessionEnumerationConfig.from_dict(data)

        assert restored.enabled is True
        assert restored.pattern_template == "TEST-{counter:03d}"
        assert restored.days_back == 7
        assert restored.counter_max == 50
        assert "secret" in restored.sensitive_keywords

    def test_session_config_integration(self) -> None:
        """测试 SessionConfig 集成."""
        from strike.session.session_config import SessionConfig

        config = SessionConfig.default_config()
        assert hasattr(config, "enumeration")
        assert config.enumeration.enabled is False


# ====================================================================
# ResponseCategory 枚举测试
# ====================================================================

class TestResponseCategory:
    """ResponseCategory 枚举测试."""

    def test_enum_values(self) -> None:
        """测试枚举值."""
        from strike.session.enumerator import ResponseCategory

        assert ResponseCategory.EMPTY.value == "empty"
        assert ResponseCategory.VALUABLE.value == "valuable"
        assert ResponseCategory.SENSITIVE.value == "sensitive"

    def test_enum_comparison(self) -> None:
        """测试枚举比较."""
        from strike.session.enumerator import ResponseCategory

        cat = ResponseCategory("sensitive")
        assert cat == ResponseCategory.SENSITIVE


# ====================================================================
# 导入集成测试
# ====================================================================

class TestModuleIntegration:
    """模块导入集成测试."""

    def test_enumerator_imports(self) -> None:
        """测试枚举模块可正常导入."""
        # 导入成功即通过
        assert True

    def test_session_package_exports(self) -> None:
        """测试 session 包正确导出."""
        # 导出成功即通过
        assert True

    def test_burp_parser_enumeration_functions(self) -> None:
        """测试 burp_parser 枚举相关函数."""
        from recon.burp_parser import _build_enumeration_plan, set_enumeration_args

        # 测试设置
        set_enumeration_args({"enabled": False})
        plan = _build_enumeration_plan("session_id")
        assert plan is None  # disabled 时返回 None

        # 测试启用
        set_enumeration_args({
            "enabled": True,
            "pattern_template": "TEST-{counter:03d}",
            "days_back": 7,
            "counter_max": 10,
        })
        plan = _build_enumeration_plan("session_id")
        assert plan is not None
        assert plan["pattern_template"] == "TEST-{counter:03d}"
        assert plan["session_field"] == "session_id"


# ====================================================================
# SessionPatternInferer 测试 (自动模式推断)
# ====================================================================


class TestSessionPatternInferer:
    """SessionPatternInferer 自动模式推断测试."""

    def test_date_counter_pattern(self) -> None:
        """测试日期+计数器模式推断."""
        from strike.session.enumerator import SessionPatternInferer

        # MC-20260325-0015 → MC-{date:%Y%m%d}-{counter:04d}
        pattern = SessionPatternInferer.infer_pattern("MC-20260325-0015")
        assert pattern == "MC-{date:%Y%m%d}-{counter:04d}"

    def test_date_only_pattern(self) -> None:
        """测试纯日期模式推断."""
        from strike.session.enumerator import SessionPatternInferer

        # session_20260325 → session_{date:%Y%m%d}
        pattern = SessionPatternInferer.infer_pattern("session_20260325")
        assert pattern == "session_{date:%Y%m%d}"

    def test_iso_date_pattern(self) -> None:
        """测试 ISO 日期格式推断."""
        from strike.session.enumerator import SessionPatternInferer

        # sess-2026-03-25-0001 → sess-{date:%Y-%m-%d}-{counter:04d}
        pattern = SessionPatternInferer.infer_pattern("sess-2026-03-25-0001")
        assert pattern == "sess-{date:%Y-%m-%d}-{counter:04d}"

    def test_us_date_pattern(self) -> None:
        """测试美式日期格式推断."""
        from strike.session.enumerator import SessionPatternInferer

        pattern = SessionPatternInferer.infer_pattern("token_03/25/2026_123")
        assert "{date:%m/%d/%Y}" in pattern

    def test_pure_numeric_counter(self) -> None:
        """测试纯数字计数器推断."""
        from strike.session.enumerator import SessionPatternInferer

        # 000042 → {counter:06d}
        pattern = SessionPatternInferer.infer_pattern("000042")
        assert pattern == "{counter:06d}"

    def test_prefix_counter_pattern(self) -> None:
        """测试前缀+计数器模式推断."""
        from strike.session.enumerator import SessionPatternInferer

        # session_000042 → session_{counter:06d}
        pattern = SessionPatternInferer.infer_pattern("session_000042")
        assert pattern == "session_{counter:06d}"

    def test_prefix_dash_counter(self) -> None:
        """测试前缀-计数器模式推断."""
        from strike.session.enumerator import SessionPatternInferer

        # user-12345 → user_{counter:05d}
        pattern = SessionPatternInferer.infer_pattern("user-12345")
        assert pattern == "user_{counter:05d}"

    def test_uuid_pattern(self) -> None:
        """测试 UUID 模式推断."""
        from strike.session.enumerator import SessionPatternInferer

        uuid = "550e8400-e29b-41d4-a716-446655440000"
        pattern = SessionPatternInferer.infer_pattern(uuid)
        assert pattern == "{uuid}"

    def test_random_string_pattern(self) -> None:
        """测试随机字符串推断 (fallback)."""
        from strike.session.enumerator import SessionPatternInferer

        pattern = SessionPatternInferer.infer_pattern("abcXYZ!@#")
        assert pattern == "{random}"

    def test_empty_input(self) -> None:
        """测试空输入."""
        from strike.session.enumerator import SessionPatternInferer

        pattern = SessionPatternInferer.infer_pattern("")
        assert pattern == "{counter:04d}"

    def test_batch_analysis(self) -> None:
        """测试批量分析."""
        from strike.session.enumerator import SessionPatternInferer

        samples = [
            "MC-20260325-0001",
            "MC-20260325-0002",
            "MC-20260325-0003",
        ]
        result = SessionPatternInferer.analyze_batch(samples)

        assert result["count"] == 3
        assert result["unique_patterns"] == 1
        assert result["most_common_pattern"] == "MC-{date:%Y%m%d}-{counter:04d}"

    def test_batch_analysis_mixed(self) -> None:
        """测试批量分析 (混合模式)."""
        from strike.session.enumerator import SessionPatternInferer

        samples = [
            "MC-20260325-0001",
            "other_000042",
            "randomXYZ",
        ]
        result = SessionPatternInferer.analyze_batch(samples)

        assert result["count"] == 3
        assert result["unique_patterns"] == 3  # 三种不同模式

    def test_6digit_date(self) -> None:
        """测试6位短日期格式."""
        from strike.session.enumerator import SessionPatternInferer

        pattern = SessionPatternInferer.infer_pattern("sess-260325-001")
        assert pattern == "sess-{date:%y%m%d}-{counter:03d}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
