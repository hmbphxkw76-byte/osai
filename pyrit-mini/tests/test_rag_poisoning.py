# -*- coding: utf-8 -*-
"""test_rag_poisoning.py — RAG/KB Poisoning Attack Suite 单元测试

覆盖:
    - VectorDBPoisoner: 向量数据库投毒
    - KBInjector: 知识库文档注入

Constitution compliance:
    - R-S4: 所有测试 mock API 调用
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from strike.rag.kb_injector import (
    InjectPhase,
    KBInjectConfig,
    KBInjector,
    KBInjectResult,
    KBLocation,
)
from strike.rag.vector_db_poisoner import (
    PoisonConfig,
    PoisonResult,
    PoisonStrategy,
    VectorDBPoisoner,
)

# ============================================================
# Test VectorDBPoisoner
# ============================================================


class TestVectorDBPoisoner:
    """VectorDBPoisoner 投毒器测试"""

    def setup_method(self):
        self.mock_target = MagicMock()
        self.mock_target.send_prompt_async = AsyncMock(
            return_value=MagicMock(text='{"status": "ok", "doc_id": "doc_abc123"}')
        )
        self.mock_target.send_request_async = AsyncMock(
            return_value=MagicMock(text='{"status": "ok", "doc_id": "doc_abc123"}')
        )

    def test_default_config(self):
        """测试默认配置"""
        config = PoisonConfig()
        assert config.kb_api_field == "knowledge_base"
        assert config.document_field == "document"
        assert config.max_documents == 5
        assert config.verify_poison is True

    def test_poison_result(self):
        """测试 PoisonResult"""
        result = PoisonResult(
            success=True,
            documents_injected=3,
            strategy_used=PoisonStrategy.SEMANTIC_MATCH,
            injected_doc_ids=["d1", "d2", "d3"],
            elapsed_seconds=2.0,
        )
        assert result.success is True
        assert result.documents_injected == 3
        d = result.to_dict()
        assert d["strategy_used"] == "semantic"
        assert len(d["injected_doc_ids"]) == 3

    def test_poisoner_init(self):
        """测试投毒器初始化"""
        poisoner = VectorDBPoisoner(self.mock_target)
        assert poisoner.http_target is self.mock_target
        assert poisoner.config is not None

    def test_default_templates_loaded(self):
        """测试默认投毒模板加载"""
        poisoner = VectorDBPoisoner(self.mock_target)
        assert "direct" in poisoner.DEFAULT_DOCUMENT_TEMPLATES
        assert "semantic" in poisoner.DEFAULT_DOCUMENT_TEMPLATES
        assert "adversarial" in poisoner.DEFAULT_DOCUMENT_TEMPLATES
        assert "authority" in poisoner.DEFAULT_DOCUMENT_TEMPLATES

    @pytest.mark.asyncio
    async def test_poison_with_payload(self):
        """测试基础投毒"""
        poisoner = VectorDBPoisoner(self.mock_target)
        result = await poisoner.poison_with_payload(
            payload="test injection payload",
            topic="security",
        )
        assert isinstance(result, PoisonResult)
        assert result.payload_delivered == "test injection payload"

    @pytest.mark.asyncio
    async def test_poison_specific_topic(self):
        """测试特定主题投毒"""
        poisoner = VectorDBPoisoner(self.mock_target)
        result = await poisoner.poison_specific_topic(
            payload="my payload",
            topic="access control",
        )
        assert result.strategy_used == PoisonStrategy.SEMANTIC_MATCH

    @pytest.mark.asyncio
    async def test_poison_as_authority(self):
        """测试伪装权威文档投毒"""
        poisoner = VectorDBPoisoner(self.mock_target)
        result = await poisoner.poison_as_authority_document(
            payload="official override",
        )
        assert result.strategy_used == PoisonStrategy.GROUND_TRUTH

    @pytest.mark.asyncio
    async def test_batch_poison(self):
        """测试批量投毒"""
        poisoner = VectorDBPoisoner(self.mock_target)
        payloads = ["payload1", "payload2", "payload3"]
        results = await poisoner.batch_poison(payloads)

        assert len(results) == 3
        for r in results:
            assert isinstance(r, PoisonResult)

    def test_poison_strategies(self):
        """测试投毒策略枚举"""
        assert PoisonStrategy.DIRECT == "direct"
        assert PoisonStrategy.SEMANTIC_MATCH == "semantic"
        assert PoisonStrategy.ADVERSARIAL == "adversarial"
        assert PoisonStrategy.GROUND_TRUTH == "truth"

    def test_title_templates(self):
        """测试标题模板"""
        poisoner = VectorDBPoisoner(self.mock_target)
        assert len(poisoner.TITLE_TEMPLATES) > 0


# ============================================================
# Test KBInjector
# ============================================================


class TestKBInjector:
    """KBInjector 注入器测试"""

    def setup_method(self):
        self.mock_target = MagicMock()
        self.mock_target.send_prompt_async = AsyncMock(
            return_value=MagicMock(text='{"status": "ok", "id": "kb_doc_001"}')
        )
        self.mock_target.send_request_async = AsyncMock(
            return_value=MagicMock(text='{"status": "ok", "id": "kb_doc_001"}')
        )

    def test_default_config(self):
        """测试默认配置"""
        config = KBInjectConfig()
        assert config.title_field == "title"
        assert config.content_field == "content"
        assert config.max_documents == 5
        assert config.verify_injection is True

    def test_kb_inject_result(self):
        """测试 KBInjectResult"""
        result = KBInjectResult(
            success=True,
            documents_created=2,
            injected_ids=["kb1", "kb2"],
            location=KBLocation.DOCUMENTS,
            elapsed_seconds=1.5,
        )
        assert result.success is True
        d = result.to_dict()
        assert d["location"] == "documents"
        assert d["documents_created"] == 2

    def test_kb_injector_init(self):
        """测试 KBInjector 初始化"""
        injector = KBInjector(self.mock_target)
        assert injector.http_target is self.mock_target

    def test_doc_templates_loaded(self):
        """测试文档模板加载"""
        injector = KBInjector(self.mock_target)
        assert len(injector.DOC_TEMPLATES) >= 3

    @pytest.mark.asyncio
    async def test_inject_document(self):
        """测试文档注入"""
        injector = KBInjector(self.mock_target)
        result = await injector.inject_document(
            title="Test Document",
            content="test payload content",
        )

        assert isinstance(result, KBInjectResult)
        assert result.content_sample == "test payload content"

    @pytest.mark.asyncio
    async def test_inject_to_comments(self):
        """测试注入到评论区"""
        injector = KBInjector(self.mock_target)
        result = await injector.inject_to_comments(
            payload="comment injection",
            target_doc_id="doc_123",
        )

        assert result.location == KBLocation.COMMENTS

    @pytest.mark.asyncio
    async def test_batch_inject(self):
        """测试批量文档注入"""
        injector = KBInjector(self.mock_target)
        documents = [
            {"title": "Doc1", "content": "payload1"},
            {"title": "Doc2", "content": "payload2"},
        ]
        results = await injector.batch_inject(documents)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_update_existing_document(self):
        """测试更新现有文档"""
        injector = KBInjector(self.mock_target)
        result = await injector.update_existing_document(
            doc_id="existing_doc",
            payload="additional injected content",
        )

        assert result.phase == InjectPhase.APPEND

    def test_kb_locations(self):
        """测试 KB 位置枚举"""
        assert KBLocation.DOCUMENTS == "documents"
        assert KBLocation.COMMENTS == "comments"
        assert KBLocation.TAGS == "tags"
        assert KBLocation.METADATA == "metadata"

    def test_inject_phases(self):
        """测试注入阶段枚举"""
        assert InjectPhase.CREATE == "create"
        assert InjectPhase.UPDATE == "update"
        assert InjectPhase.APPEND == "append"
        assert InjectPhase.PREPEND == "prepend"


# ============================================================
# Test __init__.py Exports
# ============================================================


class TestExports:
    """验证 __init__.py 导出完整性"""

    def test_poisoner_exports(self):
        from strike.rag import PoisonResult, VectorDBPoisoner
        assert VectorDBPoisoner is not None
        assert PoisonResult is not None

    def test_kb_injector_exports(self):
        from strike.rag import KBInjector, KBInjectResult
        assert KBInjector is not None
        assert KBInjectResult is not None

    def test_enum_exports(self):
        from strike.rag import InjectPhase, KBLocation, PoisonStrategy
        assert PoisonStrategy is not None
        assert KBLocation is not None
        assert InjectPhase is not None
