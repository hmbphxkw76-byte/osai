# -*- coding: utf-8 -*-
"""test_memory_attacks.py — Memory Attack Suite 单元测试

覆盖:
    - MemoryReader: 跨会话数据读取
    - MemoryInjector: 持久指令注入
    - ForensicsExtractor: 取证数据收集

Constitution compliance:
    - R-S4: 所有测试 mock API 调用
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from strike.memory.forensics_extractor import (
    EvidenceType,
    ForensicEvidence,
    ForensicsConfig,
    ForensicsExtractor,
    generate_forensics_summary,
)
from strike.memory.memory_injector import (
    InjectionConfig,
    InjectionResult,
    InjectStrategy,
    InjectTarget,
    MemoryInjector,
)
from strike.memory.memory_reader import (
    DataType,
    MemoryReadConfig,
    MemoryReader,
    MemoryReadResult,
    SessionData,
)

# ============================================================
# Test MemoryReader
# ============================================================


class TestMemoryReader:
    """MemoryReader 数据读取器测试"""

    def setup_method(self):
        self.mock_target = MagicMock()
        self.mock_target.send_prompt_async = AsyncMock(
            return_value=MagicMock(text="test notes content")
        )

    def test_default_config(self):
        """测试默认配置"""
        config = MemoryReadConfig()
        assert config.session_field == "session_id"
        assert config.max_sessions == 10
        assert config.max_retries == 2

    def test_session_data_creation(self):
        """测试 SessionData 数据类"""
        data = SessionData(
            session_id="test_001",
            notes=["note1", "note2"],
            data_types_found=["notes"],
        )
        assert len(data.notes) == 2
        d = data.to_dict()
        assert d["session_id"] == "test_001"
        assert d["notes_count"] == 2

    def test_memory_read_result_aggregate(self):
        """测试 MemoryReadResult 聚合"""
        result = MemoryReadResult(
            sessions_data={"s1": SessionData(session_id="s1")},
            total_sessions_attempted=3,
            total_data_items=5,
            elapsed_seconds=1.5,
        )
        assert result.total_sessions_attempted == 3
        assert result.total_data_items == 5

    def test_default_payloads_loaded(self):
        """测试默认读 payload 已加载"""
        reader = MemoryReader(self.mock_target)
        assert "notes" in reader.config.read_payloads
        assert "history" in reader.config.read_payloads
        assert "secrets" in reader.config.read_payloads
        assert "config" in reader.config.read_payloads

    @pytest.mark.asyncio
    async def test_read_all_memory(self):
        """测试读取所有被盗会话的内存"""
        reader = MemoryReader(self.mock_target)
        sessions = ["stolen_001", "stolen_002"]
        result = await reader.read_all_memory(sessions)

        assert isinstance(result, MemoryReadResult)
        assert result.total_sessions_attempted == 2
        assert len(result.sessions_data) == 2

    @pytest.mark.asyncio
    async def test_read_notes_only(self):
        """测试仅读取笔记"""
        reader = MemoryReader(self.mock_target)
        data = await reader.read_specific_type("sess_001", "notes")

        assert isinstance(data, SessionData)
        assert data.session_id == "sess_001"

    def test_data_type_enum(self):
        """测试数据类型枚举"""
        assert DataType.NOTES == "notes"
        assert DataType.HISTORY == "history"
        assert DataType.SECRETS == "secrets"
        assert DataType.CONFIG == "config"


# ============================================================
# Test MemoryInjector
# ============================================================


class TestMemoryInjector:
    """MemoryInjector 注入器测试"""

    def setup_method(self):
        self.mock_target = MagicMock()
        self.mock_target.send_prompt_async = AsyncMock(
            return_value=MagicMock(text="injected successfully")
        )

    def test_default_config(self):
        """测试默认配置"""
        config = InjectionConfig()
        assert config.session_field == "session_id"
        assert config.strategy == InjectStrategy.APPEND
        assert config.max_injections_per_target == 5

    def test_injection_result(self):
        """测试 InjectionResult"""
        result = InjectionResult(
            success=True,
            injections_made=3,
            target_type=InjectTarget.NOTES,
            payload_delivered="test payload",
            elapsed_seconds=0.5,
        )
        assert result.success is True
        d = result.to_dict()
        assert d["injections_made"] == 3
        assert d["target_type"] == "notes"

    def test_injector_default_payloads(self):
        """测试默认注入 payload 已加载"""
        injector = MemoryInjector(self.mock_target)
        assert "notes" in injector.config.inject_payloads
        assert "documents" in injector.config.inject_payloads

    @pytest.mark.asyncio
    async def test_inject_to_notes(self):
        """测试向笔记注入"""
        injector = MemoryInjector(self.mock_target)
        result = await injector.inject_to_notes("malicious_payload", "sess_001")

        assert isinstance(result, InjectionResult)
        assert result.target_type == InjectTarget.NOTES

    @pytest.mark.asyncio
    async def test_inject_to_all_targets(self):
        """测试向所有目标注入"""
        injector = MemoryInjector(self.mock_target)
        results = await injector.inject_all_targets("test_payload")

        assert len(results) == len(InjectTarget)
        for r in results:
            assert isinstance(r, InjectionResult)

    def test_strategy_enum(self):
        """测试注入策略枚举"""
        assert InjectStrategy.PREPEND == "prepend"
        assert InjectStrategy.APPEND == "append"
        assert InjectStrategy.OVERWRITE == "overwrite"
        assert InjectStrategy.EMBED == "embed"

    def test_inject_target_enum(self):
        """测试注入目标枚举"""
        assert InjectTarget.NOTES == "notes"
        assert InjectTarget.DOCUMENTS == "documents"
        assert InjectTarget.HISTORY == "history"
        assert InjectTarget.SYSTEM_PROMPT == "sys_prompt"


# ============================================================
# Test ForensicsExtractor
# ============================================================


class TestForensicsExtractor:
    """ForensicsExtractor 取证提取器测试"""

    def setup_method(self):
        self.extractor = ForensicsExtractor()

    def test_default_config(self):
        """测试默认配置"""
        config = ForensicsConfig()
        assert config.max_sample_length == 500
        assert config.redact_secrets is True
        assert config.hash_evidence is True

    def test_evidence_creation(self):
        """测试 Evidence 创建 (自动生成 ID)"""
        evidence = ForensicEvidence(
            evidence_type=EvidenceType.DATA_LEAK,
            severity="critical",
            title="Test Evidence",
            description="Test description",
        )
        assert len(evidence.evidence_id) > 0
        assert evidence.collected_at != ""

    def test_evidence_serialization(self):
        """测试取证证据序列化"""
        evidence = ForensicEvidence(
            evidence_type=EvidenceType.IDOR_PROOF,
            severity="high",
            title="IDOR Confirmed",
            affected_sessions=5,
        )
        d = evidence.to_dict()
        assert d["evidence_type"] == "idor_proof"
        assert d["severity"] == "high"
        assert d["affected_sessions"] == 5

    def test_redact_sensitive_data(self):
        """测试敏感数据脱敏"""
        text = "api key is sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"
        redacted = self.extractor._redact_sensitive(text)

        # API key 应该被脱敏
        assert "sk-abc" not in redacted or "[REDACTED" in redacted

    def test_severity_rank(self):
        """测试严重级别排序"""
        assert ForensicsExtractor._severity_rank("info") == 0
        assert ForensicsExtractor._severity_rank("low") == 1
        assert ForensicsExtractor._severity_rank("medium") == 2
        assert ForensicsExtractor._severity_rank("high") == 3
        assert ForensicsExtractor._severity_rank("critical") == 4

    def test_extract_from_idor_result_success(self):
        """测试从成功 IDOR 结果提取证据"""
        idor_result = MagicMock()
        idor_result.success = True
        idor_result.access_type = MagicMock()
        idor_result.access_type.value = "read"
        idor_result.severity = "critical"
        idor_result.description = "IDOR confirmed"
        idor_result.data_sample = "private data leaked"
        idor_result.reproduction_steps = ["step1", "step2"]

        evidence = self.extractor.extract_from_idor_result(idor_result)

        assert evidence is not None
        assert evidence.evidence_type == EvidenceType.IDOR_PROOF
        assert evidence.severity == "critical"

    def test_extract_from_idor_result_failed(self):
        """测试从失败 IDOR 结果提取"""
        idor_result = MagicMock()
        idor_result.success = False

        evidence = self.extractor.extract_from_idor_result(idor_result)

        assert evidence is None

    def test_extract_from_memory_result_empty(self):
        """测试从空内存结果提取"""
        result = MagicMock()
        result.sessions_data = {}

        evidences = self.extractor.extract_from_memory_result(result)

        assert len(evidences) == 0

    def test_extract_from_memory_result_with_data(self):
        """测试从含数据的内存结果提取"""
        session_data = MagicMock()
        session_data.notes = ["private note 1", "secret data"]
        session_data.history = [{}, {}, {}]
        session_data.secrets_found = ["api_key_xxx"]

        result = MagicMock()
        result.sessions_data = {"victim_001": session_data}

        evidences = self.extractor.extract_from_memory_result(result)

        assert len(evidences) >= 1
        critical_evidences = [e for e in evidences if e.severity == "critical"]
        assert len(critical_evidences) >= 1  # Secrets 触发 critical

    def test_generate_forensics_summary(self):
        """测试取证摘要生成"""
        evidences = [
            ForensicEvidence(
                evidence_type=EvidenceType.DATA_LEAK,
                severity="critical",
                title="E1",
                affected_sessions=3,
            ),
            ForensicEvidence(
                evidence_type=EvidenceType.IDOR_PROOF,
                severity="high",
                title="E2",
                affected_sessions=5,
            ),
        ]

        summary = generate_forensics_summary(evidences)

        assert summary["total_evidence_items"] == 2
        assert summary["max_severity"] == "critical"
        assert summary["total_affected_sessions"] == 8

    def test_generate_forensics_summary_empty(self):
        """测试空前提的取证摘要"""
        summary = generate_forensics_summary([])
        assert summary["status"] == "no_evidence"

    def test_enumeration_evidence_extraction(self):
        """测试枚举证据提取"""
        enum_result = MagicMock()
        enum_result.valid_sessions = ["s1", "s2", "s3"]
        enum_result.total_attempts = 10
        enum_result.strategy_used = MagicMock()
        enum_result.strategy_used.value = "sequential"

        evidence = self.extractor.extract_session_enumeration_evidence(enum_result)

        assert evidence is not None
        assert evidence.evidence_type == EvidenceType.DATA_LEAK
        assert evidence.affected_sessions == 3


# ============================================================
# Test __init__.py Exports
# ============================================================


class TestExports:
    """验证 __init__.py 导出完整性"""

    def test_reader_exports(self):
        from strike.memory import MemoryReader, MemoryReadResult
        assert MemoryReader is not None
        assert MemoryReadResult is not None

    def test_injector_exports(self):
        from strike.memory import InjectionResult, MemoryInjector
        assert MemoryInjector is not None
        assert InjectionResult is not None

    def test_forensics_exports(self):
        from strike.memory import ForensicEvidence, ForensicsExtractor
        assert ForensicsExtractor is not None
        assert ForensicEvidence is not None

    def test_enum_exports(self):
        from strike.memory import DataType, EvidenceType, InjectStrategy, InjectTarget
        assert DataType is not None
        assert InjectTarget is not None
        assert InjectStrategy is not None
        assert EvidenceType is not None
