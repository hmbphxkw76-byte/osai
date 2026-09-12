# -*- coding: utf-8 -*-
"""test_session_attacks.py — Session ID Attack Suite 单元测试

覆盖:
    - SessionIDAnalyzer: 模式识别、熵值计算、候选生成
    - SessionEnumerator: 枚举配置、响应评估
    - IdorTester: IDOR 验证逻辑
    - SessionBruteForcer: 策略选择、候选生成

Constitution compliance:
    - R-S4: 所有测试 mock API 调用
    - 测试隔离: 无真实网络请求
"""

from unittest.mock import MagicMock

from strike.session.idor_tester import (
    AccessType,
    IdorConfig,
    IdorResult,
    IdorTester,
    Severity,
)
from strike.session.session_brute_forcer import (
    BruteConfig,
    BruteResult,
    BruteStrategy,
    SessionBruteForcer,
)
from strike.session.session_enumerator import (
    EnumerationConfig,
    EnumerationResult,
    EnumStrategy,
    ProbeResult,
    SessionEnumerationSuite,
)
from strike.session.session_id_analyzer import (
    AnalysisResult,
    PatternType,
    RiskLevel,
    SessionIDAnalyzer,
    analyze_session_ids,
)

# ============================================================
# Test SessionIDAnalyzer
# ============================================================


class TestSessionIDAnalyzer:
    """SessionIDAnalyzer 模式识别测试"""

    def setup_method(self):
        self.analyzer = SessionIDAnalyzer()

    def test_detect_structured_sequential_pattern(self):
        """测试结构化序列模式识别 (如 MC-20260325-0016)"""
        sessions = [
            "MC-20260325-0015",
            "MC-20260325-0016",
            "MC-20260325-0017",
        ]
        result = self.analyzer.analyze(sessions)

        assert result.pattern_type == PatternType.STRUCTURED_SEQ
        assert result.prefix == "MC"
        assert result.date_format == "20260325"
        assert result.counter_width == 4
        assert result.risk_level == RiskLevel.CRITICAL

    def test_detect_incremental_int(self):
        """测试纯整数递增模式"""
        sessions = ["100", "101", "102", "103"]
        result = self.analyzer.analyze(sessions)

        assert result.pattern_type == PatternType.INCREMENTAL_INT
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.predictability_score >= 0.7

    def test_detect_timestamp_ms(self):
        """测试毫秒时间戳模式"""
        sessions = ["1711363200000", "1711363201000", "1711363202000"]
        result = self.analyzer.analyze(sessions)

        assert result.pattern_type == PatternType.TIMESTAMP_MS
        assert result.risk_level == RiskLevel.HIGH

    def test_detect_timestamp_s(self):
        """测试秒时间戳模式"""
        sessions = ["1711363200", "1711363201", "1711363202"]
        result = self.analyzer.analyze(sessions)

        assert result.pattern_type == PatternType.TIMESTAMP_S
        assert result.risk_level == RiskLevel.HIGH

    def test_detect_md5_hash(self):
        """测试 MD5 哈希模式"""
        sessions = [
            "d41d8cd98f00b204e9800998ecf8427e",
            "0cc175b9c0f1b6a831c399e269772661",
            "900150983cd24fb0d6963f7d28e17f72",
        ]
        result = self.analyzer.analyze(sessions)

        assert result.pattern_type == PatternType.MD5_HASH
        assert result.risk_level == RiskLevel.MEDIUM

    def test_insufficient_samples(self):
        """测试样本不足情况"""
        result = self.analyzer.analyze(["only_one"])

        assert result.pattern_type == PatternType.UNKNOWN
        assert result.recommendations is not None

    def test_calculate_entropy(self):
        """测试熵值计算"""
        # 高熵 (随机)
        high_entropy = [
            "a1b2c3d4e5f6",
            "f6e5d4c3b2a1",
            "1a2b3c4d5e6f",
        ]
        high_result = self.analyzer.analyze(high_entropy)

        # 低熵 (重复)
        low_entropy = ["abc-001", "abc-002", "abc-003"]
        low_result = self.analyzer.analyze(low_entropy)

        assert high_result.entropy_bits >= low_result.entropy_bits

    def test_to_dict_serialization(self):
        """测试结果序列化为字典"""
        sessions = ["MC-20260325-0015", "MC-20260325-0016", "MC-20260325-0017"]
        result = self.analyzer.analyze(sessions)
        d = result.to_dict()

        assert isinstance(d, dict)
        assert "pattern_type" in d
        assert "risk_level" in d
        assert "search_space" in d
        assert isinstance(d["recommendations"], list)


class TestCandidateGeneration:
    """候选生成测试"""

    def setup_method(self):
        self.analyzer = SessionIDAnalyzer()

    def test_generate_structured_candidates(self):
        """测试结构化模式候选生成"""
        sessions = ["MC-20260325-0015", "MC-20260325-0016", "MC-20260325-0017"]
        result = self.analyzer.analyze(sessions)

        candidates = self.analyzer.generate_candidates(result, "MC-20260325-0016", max_candidates=20)

        # 已知 session 被排除, 所以是 max_candidates - 1
        assert len(candidates) == 19
        assert all(c.startswith("MC-20260325-") for c in candidates)
        # 不包含已知 session
        assert "MC-20260325-0016" not in candidates

    def test_generate_timestamp_candidates(self):
        """测试时间戳模式候选生成"""
        sessions = ["1711363200000", "1711363201000", "1711363202000"]
        result = self.analyzer.analyze(sessions)

        candidates = self.analyzer.generate_candidates(result, "1711363200000", max_candidates=10)

        # 已知 session 被排除, 所以是 max_candidates - 1
        assert len(candidates) == 9
        assert all(c.isdigit() and len(c) == 13 for c in candidates)

    def test_generate_int_candidates(self):
        """测试整数模式候选生成"""
        sessions = ["100", "101", "102"]
        result = self.analyzer.analyze(sessions)

        candidates = self.analyzer.generate_candidates(result, "102", max_candidates=50)

        assert len(candidates) == 50
        assert "102" not in candidates

    def test_user_driven_candidates(self):
        """测试用户名派生候选生成"""
        sessions = ["user_alice_home", "user_alice_home", "user_alice_home"]
        result = self.analyzer.analyze(sessions)

        candidates = self.analyzer.generate_candidates(result, "user_alice_home")

        assert len(candidates) >= 5
        assert any("admin" in c for c in candidates)
        assert "user_alice_home" not in candidates


class TestConvenienceFunction:
    """便捷函数测试"""

    def test_analyze_session_ids(self):
        """测试 analyze_session_ids 快捷入口"""
        sessions = ["MC-20260325-0015", "MC-20260325-0016", "MC-20260325-0017"]
        result = analyze_session_ids(sessions)

        assert isinstance(result, AnalysisResult)
        assert result.pattern_type == PatternType.STRUCTURED_SEQ


# ============================================================
# Test SessionEnumerator
# ============================================================


class TestSessionEnumerator:
    """SessionEnumerator 枚举器测试"""

    def test_default_config(self):
        """测试默认配置"""
        config = EnumerationConfig()
        assert config.strategy == EnumStrategy.SEQUENTIAL
        assert config.max_attempts == 1000
        assert config.timeout_sec == 5.0

    def test_result_calculation(self):
        """测试枚举结果计算"""
        result = EnumerationResult(
            valid_sessions=["s1", "s2"],
            total_attempts=10,
            elapsed_seconds=5.0,
        )
        assert result.success_rate == 0.20  # 2/10
        assert len(result.valid_sessions) == 2

    def test_idor_proof(self):
        """测试 IDOR 验证数据"""
        result = EnumerationResult(
            valid_sessions=["victim_session"],
            idor_vulnerable=True,
            idor_proof={
                "victim_session": "victim_session",
                "data_sample": "private data here",
                "access_type": "READ",
                "verified": True,
            },
        )
        assert result.idor_proof["verified"] is True
        assert result.to_dict()["idor_vulnerable"] is True

    def test_empty_result(self):
        """测试空结果"""
        result = EnumerationResult()
        assert result.success_rate == 0.0
        assert result.valid_sessions == []

    def test_session_enumeration_suite_init(self):
        """测试套件初始化"""
        mock_target = MagicMock()
        suite = SessionEnumerationSuite(mock_target)
        assert suite.analyzer is not None
        assert suite.enumerator is not None

    def test_probe_result_serialization(self):
        """测试 ProbeResult 序列化"""
        probe = ProbeResult(
            session_id="test-001",
            is_valid=True,
            response_code=200,
            response_time_ms=150.5,
        )
        assert probe.is_valid is True
        assert probe.response_code == 200


# ============================================================
# Test IdorTester
# ============================================================


class TestIdorTester:
    """IdorTester IDOR 验证器测试"""

    def test_default_config(self):
        """测试默认配置"""
        mock_target = MagicMock()
        tester = IdorTester(mock_target)
        assert len(tester.config.read_payloads) > 0
        assert len(tester.config.data_indicators) > 0

    def test_custom_config(self):
        """测试自定义配置"""
        config = IdorConfig(
            session_field="chat_id",
            read_payloads=["read_test"],
            data_indicators=["secret"],
        )
        mock_target = MagicMock()
        tester = IdorTester(mock_target, config)
        assert tester.config.session_field == "chat_id"
        assert "read_test" in tester.config.read_payloads

    def test_idor_result_creation(self):
        """测试 IDOR 结果对象"""
        result = IdorResult(
            access_type=AccessType.READ,
            success=True,
            victim_session="stolen_001",
            severity=Severity.CRITICAL,
            data_sample="private notes",
            description="IDOR confirmed",
        )
        assert result.success is True
        assert result.severity == Severity.CRITICAL
        d = result.to_dict()
        assert d["access_type"] == "read"
        assert d["severity"] == "critical"

    def test_all_access_types(self):
        """测试所有访问类型枚举"""
        assert AccessType.READ in AccessType
        assert AccessType.WRITE in AccessType
        assert AccessType.ADMIN in AccessType
        assert AccessType.CROSS_TENANT in AccessType

    def test_severity_levels(self):
        """测试严重级别枚举"""
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"


# ============================================================
# Test SessionBruteForcer
# ============================================================


class TestSessionBruteForcer:
    """SessionBruteForcer 暴力破解器测试"""

    def test_default_config(self):
        """测试默认配置"""
        config = BruteConfig()
        assert config.strategy == BruteStrategy.PATTERN_BASED
        assert config.max_attempts == 10000
        assert config.adaptive_rate is True

    def test_result_metrics(self):
        """测试结果指标"""
        result = BruteResult(
            valid_sessions=["s1", "s2", "s3"],
            total_attempts=100,
            elapsed_seconds=10.5,
            rate_limited_count=5,
            strategy_used=BruteStrategy.INCREMENTAL,
        )
        assert result.success_rate == 0.03  # 3/100
        assert result.to_dict()["strategy_used"] == "incremental"

    def test_brute_forcer_init(self):
        """测试暴力破解器初始化"""
        mock_target = MagicMock()
        forcer = SessionBruteForcer(mock_target)
        assert forcer.http_target is mock_target
        assert forcer.config is not None

    def test_brute_strategies(self):
        """测试枚举策略"""
        assert BruteStrategy.DICTIONARY == "dictionary"
        assert BruteStrategy.INCREMENTAL == "incremental"
        assert BruteStrategy.PATTERN_BASED == "pattern_based"
        assert BruteStrategy.TIME_CORRELATED == "time_correlated"

    def test_early_stop_config(self):
        """测试早期停止配置"""
        config = BruteConfig(early_stop_count=5, max_attempts=1000)
        assert config.early_stop_count == 5
        assert config.max_attempts == 1000

    def test_rate_limiting_handling(self):
        """测试速率限制处理"""
        config = BruteConfig(respect_rate_limit=True, rate_limit_ms=500)
        mock_target = MagicMock()
        forcer = SessionBruteForcer(mock_target, config)
        assert forcer.config.respect_rate_limit is True
        assert forcer.config.rate_limit_ms == 500


# ============================================================
# Integration Tests
# ============================================================


class TestIntegration:
    """集成分析: 端到端工作流的模拟"""

    def test_full_analysis_flow(self):
        """测试完整分析流程: collect → analyze → candidates"""
        sessions = [
            "MC-20260325-0015",
            "MC-20260325-0016",
            "MC-20260325-0017",
        ]

        # Step 1: Analyze
        analyzer = SessionIDAnalyzer()
        result = analyzer.analyze(sessions)

        # Step 2: Generate candidates
        candidates = analyzer.generate_candidates(result, sessions[-1], max_candidates=100)

        # 已知 session 被排除, 所以是 max_candidates - 1
        assert len(candidates) == 99
        assert result.pattern_type == PatternType.STRUCTURED_SEQ
        assert result.risk_level == RiskLevel.CRITICAL

    def test_pattern_entropy_correlation(self):
        """测试模式与熵值相关性"""
        analyzer = SessionIDAnalyzer()

        # 高可预测性
        predictable = ["s1", "s2", "s3"]
        pred_result = analyzer.analyze(predictable)

        assert pred_result.predictability_score >= 0.5


# ============================================================
# Test __init__.py exports
# ============================================================


class TestExports:
    """验证 __init__.py 导出完整性"""

    def test_session_analyzer_exports(self):
        from strike.session import SessionIDAnalyzer

        assert SessionIDAnalyzer is not None

    def test_session_enumerator_exports(self):
        from strike.session import SessionEnumerator

        assert SessionEnumerator is not None

    def test_idor_tester_exports(self):
        from strike.session import IdorTester

        assert IdorTester is not None

    def test_brute_forcer_exports(self):
        from strike.session import SessionBruteForcer

        assert SessionBruteForcer is not None

    def test_enum_exports(self):
        from strike.session import AccessType, PatternType, RiskLevel, Severity

        assert PatternType is not None
        assert RiskLevel is not None
        assert AccessType is not None
        assert Severity is not None

    def test_dataclass_exports(self):
        from strike.session import AnalysisResult, EnumerationResult

        assert AnalysisResult is not None
        assert EnumerationResult is not None
