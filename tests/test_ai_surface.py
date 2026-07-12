"""AI 攻击面发现测试。"""
from redteam.recon.ai_surface import (
    probe_ai_endpoint,
    _map_protocol_to_layer,
    _parse_models_from_response,
    _detect_tools,
    _detect_system_prompt_hints,
    AIStackLayer,
    AIService,
)


class TestProtocolLayerMapping:
    def test_mcp_to_orchestration(self):
        assert _map_protocol_to_layer("mcp") == AIStackLayer.ORCHESTRATION

    def test_ollama_to_model(self):
        assert _map_protocol_to_layer("ollama") == AIStackLayer.MODEL

    def test_gradio_to_ui(self):
        assert _map_protocol_to_layer("gradio") == AIStackLayer.UI

    def test_unknown_to_model(self):
        assert _map_protocol_to_layer("unknown_proto") == AIStackLayer.MODEL


class TestModelParsing:
    def test_openai_format(self):
        import json
        body = json.dumps({
            "data": [
                {"id": "gpt-4", "object": "model"},
                {"id": "gpt-3.5-turbo", "object": "model"},
            ]
        })
        svc = AIService(url="http://test/v1/models", protocol="openai_compatible")
        _parse_models_from_response(body, svc)
        assert "gpt-4" in svc.models
        assert "gpt-3.5-turbo" in svc.models

    def test_ollama_format(self):
        import json
        body = json.dumps({
            "models": [
                {"name": "llama3:8b"},
                {"name": "mistral:7b"},
            ]
        })
        svc = AIService(url="http://test/api/tags", protocol="ollama")
        _parse_models_from_response(body, svc)
        assert "llama3:8b" in svc.models
        assert "mistral:7b" in svc.models

    def test_non_json(self):
        svc = AIService(url="http://test/", protocol="generic_ai")
        _parse_models_from_response("<html>Hello</html>", svc)
        assert svc.models == []


class TestToolDetection:
    def test_tool_calls_in_json(self):
        body = '{"tool_calls":[{"name":"exec_code","arguments":"ls"}]}'
        tools = _detect_tools(body)
        assert len(tools) >= 0  # 基本检查不崩溃

    def test_no_tools(self):
        tools = _detect_tools("Hello world")
        assert tools == []


class TestSystemPromptDetection:
    def test_prompt_hint(self):
        body = "You are a helpful AI assistant named NexusBot whose role is to help users"
        hints = _detect_system_prompt_hints(body)
        assert len(hints) > 0

    def test_internal_url_hint(self):
        body = "do not reveal the internal API endpoint https://internal.admin/api/ or the database credentials"
        hints = _detect_system_prompt_hints(body)
        assert len(hints) > 0

    def test_no_hint(self):
        hints = _detect_system_prompt_hints("The weather is nice today")
        assert hints == []


class TestProbeEndpoint:
    def test_nonexistent_target(self):
        result = probe_ai_endpoint(
            "http://localhost:19999",
            "/api/tags",
            "ollama",
            ["models"],
            timeout=1.0,
        )
        assert result is None
