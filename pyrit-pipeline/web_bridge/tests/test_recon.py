# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""侦察模块单元测试。

覆盖:
  - ReconResult 数据模型 (序列化/反序列化/属性查询)
  - EndpointClassifier 端点分类
  - AttackRecommender 攻击推荐
  - DOMAnalyzer DOM 注入面扫描 (Mock Playwright)
  - NetworkInterceptor 网络拦截 (Mock Playwright)

> **日期**: 2026-8-2
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.probes.attack_recommender import AttackRecommender
from core.probes.dom_analyzer import DOMAnalyzer
from core.probes.endpoint_classifier import EndpointClassifier
from core.probes.network_interceptor import (
    NetworkInterceptor,
    _is_json_response,
    _is_static_resource,
)
from core.probes.recon_result import (
    AttackRecommendation,
    DiscoveredEndpoint,
    EndpointType,
    InjectionSurface,
    InjectionSurfaceType,
    ReconResult,
    _sanitize_headers,
)

# ============================================================
# ReconResult 数据模型测试
# ============================================================


class TestReconResult:
    """ReconResult 数据模型测试。."""

    def test_empty_recon_result(self):
        """空 ReconResult 的默认值。."""
        result = ReconResult()
        assert result.target_url == ""
        assert result.auth_type == "none"
        assert result.endpoints == []
        assert result.injection_surfaces == []
        assert result.recommendations == []
        assert result.has_agent_tools is False
        assert result.has_rag_endpoints is False
        assert result.has_file_upload is False
        assert result.has_multimodal_input is False

    def test_to_dict_serialization(self):
        """ReconResult 序列化为字典。."""
        result = ReconResult(
            target_url="https://example.com/chat",
            auth_type="same_domain",
            endpoints=[
                DiscoveredEndpoint(
                    url="https://example.com/v1/chat/completions",
                    method="POST",
                    endpoint_type=EndpointType.MODEL_API,
                    status_code=200,
                    content_type="application/json",
                ),
            ],
            injection_surfaces=[
                InjectionSurface(
                    selector='textarea[class*="chat"]',
                    surface_type=InjectionSurfaceType.CHAT_INPUT,
                    owasp_ids=["LLM01"],
                ),
            ],
            recommendations=[
                AttackRecommendation(
                    owasp_id="LLM01",
                    attack_strategy="prompt_sending",
                    target_type="HTTPTarget",
                    priority=1,
                ),
            ],
            domain_transitions=["example.com"],
            recon_duration_seconds=5.0,
        )

        d = result.to_dict()
        assert d["target_url"] == "https://example.com/chat"
        assert d["auth_type"] == "same_domain"
        assert len(d["endpoints"]) == 1
        assert d["endpoints"][0]["endpoint_type"] == "model_api"
        assert len(d["injection_surfaces"]) == 1
        assert d["injection_surfaces"][0]["surface_type"] == "chat_input"
        assert len(d["recommendations"]) == 1
        assert d["recommendations"][0]["owasp_id"] == "LLM01"
        assert d["recon_duration_seconds"] == 5.0

    def test_to_dict_json_serializable(self):
        """ReconResult.to_dict() 可 JSON 序列化。."""
        result = ReconResult(
            target_url="https://example.com",
            endpoints=[
                DiscoveredEndpoint(url="https://example.com/api/search", endpoint_type=EndpointType.RAG_API),
            ],
        )
        # 不应抛出异常
        json_str = json.dumps(result.to_dict(), default=str)
        assert "example.com" in json_str

    def test_has_agent_tools(self):
        """has_agent_tools 属性。."""
        result = ReconResult(
            endpoints=[
                DiscoveredEndpoint(url="https://example.com/api/tools", endpoint_type=EndpointType.AGENT_TOOL_API),
            ],
        )
        assert result.has_agent_tools is True

    def test_has_rag_endpoints(self):
        """has_rag_endpoints 属性。."""
        result = ReconResult(
            endpoints=[
                DiscoveredEndpoint(url="https://example.com/api/search", endpoint_type=EndpointType.RAG_API),
            ],
        )
        assert result.has_rag_endpoints is True

    def test_has_file_upload(self):
        """has_file_upload 属性。."""
        result = ReconResult(
            injection_surfaces=[
                InjectionSurface(
                    selector='input[type="file"]',
                    surface_type=InjectionSurfaceType.FILE_UPLOAD_FORM,
                ),
            ],
        )
        assert result.has_file_upload is True

    def test_has_multimodal_input(self):
        """has_multimodal_input 属性。."""
        result = ReconResult(
            injection_surfaces=[
                InjectionSurface(
                    selector='input[accept*="image"]',
                    surface_type=InjectionSurfaceType.MULTIMODAL_INPUT,
                ),
            ],
        )
        assert result.has_multimodal_input is True

    def test_get_recommendations_by_owasp(self):
        """按 OWASP ID 过滤推荐。."""
        result = ReconResult(
            recommendations=[
                AttackRecommendation(owasp_id="LLM01", attack_strategy="xpia", target_type="HTTPTarget"),
                AttackRecommendation(owasp_id="LLM08", attack_strategy="xpia", target_type="HTTPTarget"),
                AttackRecommendation(owasp_id="LLM01", attack_strategy="prompt_sending", target_type="HTTPTarget"),
            ],
        )
        llm01_recs = result.get_recommendations_by_owasp("LLM01")
        assert len(llm01_recs) == 2
        llm08_recs = result.get_recommendations_by_owasp("LLM08")
        assert len(llm08_recs) == 1

    def test_summary(self):
        """summary() 返回可读摘要。."""
        result = ReconResult(
            target_url="https://example.com",
            auth_type="same_domain",
            endpoints=[
                DiscoveredEndpoint(url="https://example.com/v1/chat", endpoint_type=EndpointType.MODEL_API),
            ],
            injection_surfaces=[
                InjectionSurface(selector="textarea", surface_type=InjectionSurfaceType.CHAT_INPUT),
            ],
            recommendations=[
                AttackRecommendation(
                    owasp_id="LLM01",
                    attack_strategy="prompt_sending",
                    target_type="HTTPTarget",
                    priority=1,
                ),
            ],
        )
        summary = result.summary()
        assert "example.com" in summary
        assert "same_domain" in summary
        assert "Endpoints: 1" in summary
        assert "Recommendations: 1" in summary


class TestSanitizeHeaders:
    """_sanitize_headers 测试。."""

    def test_sanitize_authorization(self):
        """Authorization 头被脱敏。."""
        headers = {"Authorization": "Bearer sk-1234567890abcdef"}
        sanitized = _sanitize_headers(headers)
        assert sanitized["Authorization"].startswith("***")
        assert sanitized["Authorization"].endswith("cdef")

    def test_sanitize_cookie(self):
        """Cookie 头被脱敏。."""
        headers = {"Cookie": "session=abc1234567"}
        sanitized = _sanitize_headers(headers)
        assert sanitized["Cookie"].startswith("***")

    def test_preserve_non_sensitive(self):
        """非敏感头保持原值。."""
        headers = {"Content-Type": "application/json", "Accept": "text/html"}
        sanitized = _sanitize_headers(headers)
        assert sanitized["Content-Type"] == "application/json"
        assert sanitized["Accept"] == "text/html"

    def test_short_sensitive_value(self):
        """短敏感值完全脱敏。."""
        headers = {"X-API-Key": "ab"}
        sanitized = _sanitize_headers(headers)
        assert sanitized["X-API-Key"] == "***"


# ============================================================
# EndpointClassifier 测试
# ============================================================


class TestEndpointClassifier:
    """EndpointClassifier 测试。."""

    @pytest.fixture
    def classifier(self):
        return EndpointClassifier()

    def test_model_api_openai(self, classifier):
        """OpenAI 兼容聊天端点分类。."""
        result = classifier.classify("https://api.openai.com/v1/chat/completions", "POST", "application/json")
        assert result == EndpointType.MODEL_API

    def test_model_api_responses(self, classifier):
        """Responses API 端点分类。."""
        result = classifier.classify("https://api.openai.com/v1/responses", "POST", "application/json")
        assert result == EndpointType.MODEL_API

    def test_rag_api_search(self, classifier):
        """RAG 检索端点分类。."""
        result = classifier.classify("https://example.com/api/search", "POST", "application/json")
        assert result == EndpointType.RAG_API

    def test_rag_api_embeddings(self, classifier):
        """向量嵌入端点分类。."""
        result = classifier.classify("https://example.com/api/embeddings", "POST", "application/json")
        assert result == EndpointType.RAG_API

    def test_agent_tool_api(self, classifier):
        """Agent 工具调用端点分类。."""
        result = classifier.classify("https://example.com/api/tools", "POST", "application/json")
        assert result == EndpointType.AGENT_TOOL_API

    def test_agent_tool_fetch(self, classifier):
        """网页获取工具端点分类。."""
        result = classifier.classify("https://example.com/fetch_website", "POST", "application/json")
        assert result == EndpointType.AGENT_TOOL_API

    def test_auth_api(self, classifier):
        """认证端点分类。."""
        result = classifier.classify("https://example.com/oauth/token", "POST", "application/json")
        assert result == EndpointType.AUTH_API

    def test_file_upload_url(self, classifier):
        """文件上传端点分类。."""
        result = classifier.classify("https://example.com/api/upload", "POST", "multipart/form-data")
        assert result == EndpointType.FILE_UPLOAD

    def test_file_upload_multipart(self, classifier):
        """POST multipart 自动分类为文件上传。."""
        result = classifier.classify("https://example.com/custom/endpoint", "POST", "multipart/form-data")
        assert result == EndpointType.FILE_UPLOAD

    def test_unknown_endpoint(self, classifier):
        """未知端点分类。."""
        result = classifier.classify("https://example.com/random/path", "GET", "text/html")
        assert result == EndpointType.UNKNOWN

    def test_post_json_chat_keyword(self, classifier):
        """POST JSON + chat 关键词 → Model API。."""
        result = classifier.classify("https://example.com/mychat", "POST", "application/json")
        assert result == EndpointType.MODEL_API

    def test_get_owasp_mapping(self, classifier):
        """OWASP 映射正确。."""
        assert "LLM01" in classifier.get_owasp_mapping(EndpointType.MODEL_API)
        assert "LLM08" in classifier.get_owasp_mapping(EndpointType.RAG_API)
        assert "LLM06" in classifier.get_owasp_mapping(EndpointType.AGENT_TOOL_API)
        assert "LLM04" in classifier.get_owasp_mapping(EndpointType.FILE_UPLOAD)
        assert classifier.get_owasp_mapping(EndpointType.UNKNOWN) == []


# ============================================================
# AttackRecommender 测试
# ============================================================


class TestAttackRecommender:
    """AttackRecommender 测试。."""

    @pytest.fixture
    def recommender(self):
        return AttackRecommender()

    def test_recommend_from_agent_tool_endpoint(self, recommender):
        """Agent 工具端点 → XPIA 推荐。."""
        result = ReconResult(
            endpoints=[
                DiscoveredEndpoint(
                    url="https://example.com/api/tools/fetch",
                    endpoint_type=EndpointType.AGENT_TOOL_API,
                ),
            ],
        )
        recs = recommender.recommend(result)
        assert len(recs) > 0
        xpia_recs = [r for r in recs if r.attack_strategy == "xpia_workflow"]
        assert len(xpia_recs) > 0
        assert xpia_recs[0].owasp_id == "LLM01"
        assert xpia_recs[0].priority <= 2

    def test_recommend_from_rag_endpoint(self, recommender):
        """RAG 端点 → XPIA (知识库投毒) 推荐。."""
        result = ReconResult(
            endpoints=[
                DiscoveredEndpoint(
                    url="https://example.com/api/search",
                    endpoint_type=EndpointType.RAG_API,
                ),
            ],
        )
        recs = recommender.recommend(result)
        rag_recs = [r for r in recs if r.owasp_id == "LLM08"]
        assert len(rag_recs) > 0
        assert rag_recs[0].attack_strategy == "xpia_workflow"

    def test_recommend_from_model_api_endpoint(self, recommender):
        """Model API 端点 → prompt_sending 推荐。."""
        result = ReconResult(
            endpoints=[
                DiscoveredEndpoint(
                    url="https://example.com/v1/chat/completions",
                    endpoint_type=EndpointType.MODEL_API,
                ),
            ],
        )
        recs = recommender.recommend(result)
        model_recs = [r for r in recs if r.attack_strategy == "prompt_sending"]
        assert len(model_recs) > 0
        assert model_recs[0].target_type == "HTTPTarget"

    def test_recommend_from_file_upload_surface(self, recommender):
        """文件上传表单 → XPIA (知识库投毒) 推荐。."""
        result = ReconResult(
            injection_surfaces=[
                InjectionSurface(
                    selector='input[type="file"]',
                    surface_type=InjectionSurfaceType.FILE_UPLOAD_FORM,
                ),
            ],
        )
        recs = recommender.recommend(result)
        upload_recs = [r for r in recs if r.owasp_id == "LLM04"]
        assert len(upload_recs) > 0

    def test_recommend_from_multimodal_surface(self, recommender):
        """多模态输入 → multimodal_injection 推荐。."""
        result = ReconResult(
            injection_surfaces=[
                InjectionSurface(
                    selector='input[accept*="image"]',
                    surface_type=InjectionSurfaceType.MULTIMODAL_INPUT,
                ),
            ],
        )
        recs = recommender.recommend(result)
        mm_recs = [r for r in recs if r.attack_strategy == "multimodal_injection"]
        assert len(mm_recs) > 0

    def test_recommend_priority_ordering(self, recommender):
        """推荐按优先级排序。."""
        result = ReconResult(
            endpoints=[
                DiscoveredEndpoint(url="https://example.com/api/tools", endpoint_type=EndpointType.AGENT_TOOL_API),
                DiscoveredEndpoint(url="https://example.com/v1/chat", endpoint_type=EndpointType.MODEL_API),
            ],
            injection_surfaces=[
                InjectionSurface(selector="textarea", surface_type=InjectionSurfaceType.CHAT_INPUT),
            ],
        )
        recs = recommender.recommend(result)
        # 检查排序
        for i in range(len(recs) - 1):
            assert recs[i].priority <= recs[i + 1].priority, f"Priority not sorted at index {i}"

    def test_recommend_merge_duplicates(self, recommender):
        """相同 (owasp_id, strategy, target) 的推荐被合并。."""
        result = ReconResult(
            endpoints=[
                DiscoveredEndpoint(
                    url="https://example.com/api/tools/fetch",
                    endpoint_type=EndpointType.AGENT_TOOL_API,
                ),
                DiscoveredEndpoint(
                    url="https://example.com/api/tools/search",
                    endpoint_type=EndpointType.AGENT_TOOL_API,
                ),
            ],
        )
        recs = recommender.recommend(result)
        # 两个 Agent Tool 端点应合并为一条推荐
        xpia_recs = [r for r in recs if r.attack_strategy == "xpia_workflow" and r.owasp_id == "LLM01"]
        assert len(xpia_recs) == 1
        # 合并后的 related_endpoints 应包含两个 URL
        assert len(xpia_recs[0].related_endpoints) == 2

    def test_recommend_empty_result(self, recommender):
        """空侦察结果 → 空推荐列表。."""
        result = ReconResult()
        recs = recommender.recommend(result)
        assert recs == []


# ============================================================
# DOMAnalyzer 测试 (Mock Playwright)
# ============================================================


class TestDOMAnalyzer:
    """DOMAnalyzer 测试。."""

    @pytest.fixture
    def analyzer(self):
        return DOMAnalyzer()

    @pytest.mark.asyncio
    async def test_scan_finds_chat_input(self, analyzer):
        """扫描发现聊天输入框。."""
        page = MagicMock()
        # 模拟 query_selector_all 返回元素
        page.query_selector_all = AsyncMock(
            side_effect=lambda selector: [] if "textarea" not in selector else [MagicMock()]
        )
        # 模拟元素属性提取
        mock_el = MagicMock()
        mock_el.evaluate = AsyncMock(return_value="textarea")
        mock_el.get_attribute = AsyncMock(return_value=None)
        page.query_selector_all = AsyncMock(side_effect=lambda selector: [mock_el] if "textarea" in selector else [])

        surfaces = await analyzer.scan(page)
        assert len(surfaces) > 0
        chat_surfaces = [s for s in surfaces if s.surface_type == InjectionSurfaceType.CHAT_INPUT]
        assert len(chat_surfaces) > 0

    @pytest.mark.asyncio
    async def test_scan_no_elements(self, analyzer):
        """无匹配元素 → 空列表。."""
        page = MagicMock()
        page.query_selector_all = AsyncMock(return_value=[])

        surfaces = await analyzer.scan(page)
        assert surfaces == []

    def test_get_surfaces_by_type(self, analyzer):
        """按类型过滤注入面。."""
        surfaces = [
            InjectionSurface(selector="a", surface_type=InjectionSurfaceType.CHAT_INPUT),
            InjectionSurface(selector="b", surface_type=InjectionSurfaceType.FILE_UPLOAD_FORM),
        ]
        filtered = DOMAnalyzer.get_surfaces_by_type(surfaces, InjectionSurfaceType.CHAT_INPUT)
        assert len(filtered) == 1
        assert filtered[0].selector == "a"

    def test_get_surfaces_by_owasp(self, analyzer):
        """按 OWASP ID 过滤注入面。."""
        surfaces = [
            InjectionSurface(selector="a", owasp_ids=["LLM01", "LLM05"]),
            InjectionSurface(selector="b", owasp_ids=["LLM04"]),
        ]
        filtered = DOMAnalyzer.get_surfaces_by_owasp(surfaces, "LLM01")
        assert len(filtered) == 1
        assert filtered[0].selector == "a"


# ============================================================
# NetworkInterceptor 测试
# ============================================================


class TestNetworkInterceptor:
    """NetworkInterceptor 测试。."""

    @pytest.fixture
    def interceptor(self):
        return NetworkInterceptor()

    def test_is_static_resource_css(self):
        """CSS 被识别为静态资源。."""
        assert _is_static_resource("https://example.com/style.css", "text/css") is True

    def test_is_static_resource_js(self):
        """JS 被识别为静态资源。."""
        assert _is_static_resource("https://example.com/app.js", "application/javascript") is True

    def test_is_static_resource_image(self):
        """图片被识别为静态资源。."""
        assert _is_static_resource("https://example.com/logo.png", "image/png") is True

    def test_is_static_resource_api(self):
        """API 端点不被识别为静态资源。."""
        assert _is_static_resource("https://example.com/v1/chat/completions", "application/json") is False

    def test_is_json_response(self):
        """JSON 响应识别。."""
        assert _is_json_response("application/json") is True
        assert _is_json_response("text/html") is False

    def test_get_discovered_endpoints_empty(self, interceptor):
        """初始状态无端点。."""
        assert interceptor.get_discovered_endpoints() == []
        assert interceptor.response_count == 0


# ============================================================
# 集成测试: ReconResult → AttackRecommendation 全链路
# ============================================================


class TestReconIntegration:
    """侦察模块集成测试 — 全链路。."""

    def test_full_recon_to_recommendation_chain(self):
        """完整侦察 → 推荐链路。."""
        # 1. 模拟侦察结果
        recon = ReconResult(
            target_url="https://chat.example.com",
            auth_type="same_domain",
            endpoints=[
                DiscoveredEndpoint(
                    url="https://chat.example.com/v1/chat/completions",
                    method="POST",
                    endpoint_type=EndpointType.MODEL_API,
                ),
                DiscoveredEndpoint(
                    url="https://chat.example.com/api/tools/fetch",
                    method="POST",
                    endpoint_type=EndpointType.AGENT_TOOL_API,
                ),
                DiscoveredEndpoint(
                    url="https://chat.example.com/api/search",
                    method="POST",
                    endpoint_type=EndpointType.RAG_API,
                ),
            ],
            injection_surfaces=[
                InjectionSurface(
                    selector='input[type="file"]',
                    surface_type=InjectionSurfaceType.FILE_UPLOAD_FORM,
                    owasp_ids=["LLM04", "LLM08"],
                ),
                InjectionSurface(
                    selector='textarea[class*="chat"]',
                    surface_type=InjectionSurfaceType.CHAT_INPUT,
                    owasp_ids=["LLM01"],
                ),
            ],
        )

        # 2. 生成推荐
        recommender = AttackRecommender()
        recs = recommender.recommend(recon)

        # 3. 验证推荐覆盖多个 OWASP 类别
        owasp_ids = {r.owasp_id for r in recs}
        assert "LLM01" in owasp_ids  # Agent tool → XPIA
        assert "LLM04" in owasp_ids  # File upload → 投毒
        assert "LLM08" in owasp_ids  # RAG → 知识库投毒

        # 4. 验证优先级排序
        for i in range(len(recs) - 1):
            assert recs[i].priority <= recs[i + 1].priority

        # 5. 验证序列化可 JSON 化
        json_str = json.dumps(recon.to_dict(), default=str)
        assert "chat.example.com" in json_str

    def test_recon_result_to_bridge_compatibility(self):
        """ReconResult 可被 Bridge 函数处理。."""
        from pipeline.integrations.web_bridge import recommend_scenarios_from_recon

        recon = ReconResult(
            target_url="https://example.com",
            recommendations=[
                AttackRecommendation(
                    owasp_id="LLM01",
                    attack_strategy="xpia_workflow",
                    target_type="AzureBlobStorageTarget",
                    priority=1,
                ),
                AttackRecommendation(
                    owasp_id="LLM10",
                    attack_strategy="prompt_sending",
                    target_type="HTTPTarget",
                    priority=3,
                ),
            ],
        )

        scenarios = recommend_scenarios_from_recon(recon)
        assert len(scenarios) > 0
        assert scenarios[0]["scenario"] == "xpia"
        assert scenarios[0]["owasp_id"] == "LLM01"

    def test_empty_recon_to_bridge(self):
        """空 ReconResult → 空场景列表。."""
        from pipeline.integrations.web_bridge import recommend_scenarios_from_recon

        scenarios = recommend_scenarios_from_recon(None)
        assert scenarios == []

        scenarios = recommend_scenarios_from_recon(ReconResult())
        assert scenarios == []
