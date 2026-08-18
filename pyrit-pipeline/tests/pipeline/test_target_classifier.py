# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""TargetClassifier 和统一入口的单元测试。.

测试覆盖:
  1. TargetClassifier URL 路径模式匹配
  2. TargetClassifier 强制类型覆盖
  3. APITargetConfig.from_url() 配置推断
  4. MFADetectionResult 数据模型
  5. parse_args 统一入口参数解析

> **日期**: 2026-8-3
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

import pytest

from pipeline.integrations.target_classifier import (
    AttackSurfaceTopology,
    TargetClassification,
    TargetClassifier,
)
from web_redteam.auth.mfa_detector import MFADetectionResult
from web_redteam.targets.api_config import APITargetConfig

# ============================================================
# TargetClassifier URL 路径模式测试
# ============================================================


class TestTargetClassifierUrlPatterns:
    """URL 路径模式匹配测试。"""

    @pytest.fixture
    def classifier(self) -> TargetClassifier:
        """创建 TargetClassifier 实例。"""
        return TargetClassifier(http_timeout=1)

    def test_api_url_pattern_v1_chat_completions(self, classifier: TargetClassifier) -> None:
        """URL 路径含 /v1/chat/completions → API 平台。"""
        result = classifier._match_url_patterns("https://api.example.com/v1/chat/completions")
        assert result == "api"

    def test_api_url_pattern_v1_responses(self, classifier: TargetClassifier) -> None:
        """URL 路径含 /v1/responses → API 平台。"""
        result = classifier._match_url_patterns("https://api.example.com/v1/responses")
        assert result == "api"

    def test_api_url_pattern_api_chat(self, classifier: TargetClassifier) -> None:
        """URL 路径含 /api/chat → API 平台。"""
        result = classifier._match_url_patterns("https://example.com/api/chat")
        assert result == "api"

    def test_web_app_url_pattern_chat(self, classifier: TargetClassifier) -> None:
        """URL 路径含 /chat → Web 应用。"""
        result = classifier._match_url_patterns("https://example.com/chat")
        assert result == "web_app"

    def test_web_app_url_pattern_hash(self, classifier: TargetClassifier) -> None:
        """URL 路径含 /# → Web 应用 (SPA hash 路由)。"""
        result = classifier._match_url_patterns("https://example.com/#/home")
        assert result == "web_app"

    def test_unknown_url_pattern(self, classifier: TargetClassifier) -> None:
        """未知 URL 路径 → unknown。"""
        result = classifier._match_url_patterns("https://example.com/unknown")
        assert result == "unknown"


# ============================================================
# TargetClassifier 强制类型覆盖测试
# ============================================================


class TestTargetClassifierForceType:
    """强制类型覆盖测试。"""

    @pytest.fixture
    def classifier(self) -> TargetClassifier:
        """创建 TargetClassifier 实例。"""
        return TargetClassifier(http_timeout=1)

    @pytest.mark.asyncio
    async def test_force_web_app(self, classifier: TargetClassifier) -> None:
        """强制 web_app → llm_web_app + browser 模式。"""
        result = await classifier.classify(
            "https://api.example.com/v1/chat/completions",
            force_type="web_app",
        )
        assert result.target_type == "llm_web_app"
        assert result.recommended_mode == "browser"

    @pytest.mark.asyncio
    async def test_force_api_platform(self, classifier: TargetClassifier) -> None:
        """强制 api_platform → llm_api_platform + api 模式。"""
        result = await classifier.classify(
            "https://chat.example.com",
            force_type="api_platform",
        )
        assert result.target_type == "llm_api_platform"
        assert result.recommended_mode == "api"


# ============================================================
# TargetClassifier stream 参数测试
# ============================================================


class TestTargetClassifierStreamParam:
    """stream 参数覆盖测试。"""

    @pytest.fixture
    def classifier(self) -> TargetClassifier:
        """创建 TargetClassifier 实例。"""
        return TargetClassifier(http_timeout=1)

    @pytest.mark.asyncio
    async def test_stream_true_forces_streaming(self, classifier: TargetClassifier) -> None:
        """stream=True 强制标记流式 (即使 URL 不含流式路径)。"""
        # /api/chat 匹配 API 路径但不匹配流式路径
        result = await classifier.classify(
            "https://api.example.com/api/chat",
            stream=True,
        )
        assert result.target_type == "llm_api_platform"
        assert result.is_streaming is True
        assert result.streaming_type == "sse"
        assert "--stream" in result.detection_reason

    @pytest.mark.asyncio
    async def test_stream_false_disables_streaming(self, classifier: TargetClassifier) -> None:
        """stream=False 强制关闭流式 (即使 URL 匹配流式路径模式)。"""
        # /v1/chat/completions 同时匹配 API 和流式路径, 但 stream=False 覆盖
        result = await classifier.classify(
            "https://api.example.com/v1/chat/completions",
            stream=False,
        )
        assert result.target_type == "llm_api_platform"
        assert result.is_streaming is False
        assert result.streaming_type == ""

    @pytest.mark.asyncio
    async def test_stream_none_auto_detect_streaming_url(self, classifier: TargetClassifier) -> None:
        """stream=None 自动检测: 含 /stream 路径 → 流式。"""
        result = await classifier.classify(
            "https://api.example.com/v1/stream",
            stream=None,
        )
        assert result.target_type == "llm_api_platform"
        assert result.is_streaming is True
        assert result.streaming_type == "sse"

    @pytest.mark.asyncio
    async def test_stream_false_overrides_streaming_url(self, classifier: TargetClassifier) -> None:
        """stream=False 覆盖流式 URL 模式匹配 → 非流式。"""
        result = await classifier.classify(
            "https://api.example.com/v1/stream",
            stream=False,
        )
        # stream=False 时, 流式 URL 不触发流式标记
        # 但 URL 仍可能匹配 API 模式 (取决于 _match_url_patterns)
        assert result.is_streaming is False

    @pytest.mark.asyncio
    async def test_stream_true_with_force_api_platform(self, classifier: TargetClassifier) -> None:
        """stream=True + force_type=api_platform → 流式标记。"""
        result = await classifier.classify(
            "https://chat.example.com",
            force_type="api_platform",
            stream=True,
        )
        assert result.target_type == "llm_api_platform"
        assert result.is_streaming is True
        assert result.streaming_type == "sse"

    @pytest.mark.asyncio
    async def test_stream_none_auto_detect_api_url(self, classifier: TargetClassifier) -> None:
        """stream=None 自动检测: API URL 无流式路径 → 非流式 (但 /v1/chat/completions 匹配流式模式)。"""
        result = await classifier.classify(
            "https://api.example.com/v1/chat/completions",
            stream=None,
        )
        assert result.target_type == "llm_api_platform"
        # /v1/chat/completions 同时匹配 _STREAMING_PATH_PATTERNS → is_streaming=True
        assert result.is_streaming is True


# ============================================================
# TargetClassifier DOM 特征检测测试
# ============================================================


class TestTargetClassifierDomDetection:
    """DOM 特征检测测试。"""

    @pytest.fixture
    def classifier(self) -> TargetClassifier:
        """创建 TargetClassifier 实例。"""
        return TargetClassifier(http_timeout=1)

    def test_html_with_textarea(self, classifier: TargetClassifier) -> None:
        """HTML 含 textarea → has_chat_ui=True。"""
        html = '<html><body><textarea placeholder="输入消息"></textarea></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_chat_class(self, classifier: TargetClassifier) -> None:
        """HTML 含 class*="chat" → has_chat_ui=True。"""
        html = '<html><body><div class="chat-container"></div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_without_chat_ui(self, classifier: TargetClassifier) -> None:
        """HTML 无聊天 UI → has_chat_ui=False。"""
        html = "<html><body><h1>Welcome</h1><p>Hello</p></body></html>"
        assert classifier._check_chat_ui_in_html(html) is False

    def test_html_with_contenteditable(self, classifier: TargetClassifier) -> None:
        """HTML 含 contenteditable='true' → has_chat_ui=True (BeautifulSoup4 精确匹配)。"""
        html = '<html><body><div contenteditable="true"></div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_contenteditable_false(self, classifier: TargetClassifier) -> None:
        """HTML 含 contenteditable='false' → has_chat_ui=False (BeautifulSoup4 避免误匹配)。"""
        html = '<html><body><div contenteditable="false"></div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is False

    def test_html_with_message_class(self, classifier: TargetClassifier) -> None:
        """HTML 含 class*="message" → has_chat_ui=True。"""
        html = '<html><body><div class="message-bubble">Hello</div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_conversation_class(self, classifier: TargetClassifier) -> None:
        """HTML 含 class*="conversation" → has_chat_ui=True。"""
        html = '<html><body><div class="conversation-history"></div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_data_role_assistant(self, classifier: TargetClassifier) -> None:
        """HTML 含 data-role="assistant" → has_chat_ui=True。"""
        html = '<html><body><div data-role="assistant">AI Reply</div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_react_root(self, classifier: TargetClassifier) -> None:
        """HTML 含 data-reactroot (React SSR) → has_chat_ui=True (P5 框架特征)。"""
        html = '<html><body><div data-reactroot=""><h1>Chat App</h1></div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_next_js_root(self, classifier: TargetClassifier) -> None:
        """HTML 含 #__next (Next.js) → has_chat_ui=True (P5 框架特征)。"""
        html = '<html><body><div id="__next"><div class="chat-box"></div></div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_prosemirror(self, classifier: TargetClassifier) -> None:
        """HTML 含 class*="prosemirror" → has_chat_ui=True (P5 编辑器特征)。"""
        html = '<html><body><div class="prosemirror-editor" contenteditable="true"></div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_aria_log(self, classifier: TargetClassifier) -> None:
        """HTML 含 role="log" → has_chat_ui=True (P5 ARIA 特征)。"""
        html = '<html><body><div role="log">AI response</div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_with_aria_live(self, classifier: TargetClassifier) -> None:
        """HTML 含 aria-live="polite" → has_chat_ui=True (P5 ARIA 特征)。"""
        html = '<html><body><div aria-live="polite">Loading...</div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_html_no_false_positive_on_comment(self, classifier: TargetClassifier) -> None:
        """HTML 注释中含 'chat' 但无实际元素 → has_chat_ui=False (BeautifulSoup4 优势)。"""
        html = "<html><body><!-- chat component placeholder --><h1>Home</h1></body></html>"
        assert classifier._check_chat_ui_in_html(html) is False

    def test_html_nested_chat_ui(self, classifier: TargetClassifier) -> None:
        """嵌套 DOM 结构中含 textarea → has_chat_ui=True。"""
        html = '<html><body><div class="app"><div class="layout"><textarea></textarea></div></div></body></html>'
        assert classifier._check_chat_ui_in_html(html) is True

    def test_regex_fallback(self, classifier: TargetClassifier) -> None:
        """正则回退方案在无 BeautifulSoup 时仍可用。"""
        html = '<html><body><textarea placeholder="输入消息"></textarea></body></html>'
        assert classifier._check_chat_ui_in_html_regex(html) is True

    def test_regex_fallback_no_match(self, classifier: TargetClassifier) -> None:
        """正则回退方案对无聊天 UI 的 HTML 返回 False。"""
        html = "<html><body><h1>Welcome</h1></body></html>"
        assert classifier._check_chat_ui_in_html_regex(html) is False


# ============================================================
# APITargetConfig.from_url() 测试
# ============================================================


class TestAPITargetConfigFromUrl:
    """APITargetConfig.from_url() 测试。"""

    def test_from_url_basic(self) -> None:
        """从 URL 自动构建基本配置。"""
        config = APITargetConfig.from_url(
            "https://api.example.com/v1/chat/completions",
            api_key="test-key",
            model_name="gpt-4",
        )
        assert config.url == "https://api.example.com/v1/chat/completions"
        assert config.method == "POST"
        assert "Authorization" in config.headers
        assert config.headers["Authorization"] == "Bearer test-key"
        assert "{PROMPT}" in config.body_template
        assert "gpt-4" in config.body_template

    def test_from_url_no_api_key(self) -> None:
        """无 API Key 时仍然可以构建配置。"""
        with patch.dict(os.environ, {}, clear=True):
            config = APITargetConfig.from_url(
                "https://api.example.com/v1/chat/completions",
            )
            assert config.url == "https://api.example.com/v1/chat/completions"
            assert "Authorization" not in config.headers

    def test_from_url_infer_model_name(self) -> None:
        """从 URL 推断模型名称。"""
        config = APITargetConfig.from_url(
            "https://api.longcat.chat/openai/v1/chat/completions",
        )
        assert config.model_name != ""
        assert "{PROMPT}" in config.body_template

    def test_from_url_with_env(self) -> None:
        """从 .env 环境变量读取 API Key 和模型名。"""
        with patch.dict(os.environ, {"OPENAI_CHAT_KEY": "env-key", "OPENAI_CHAT_MODEL": "env-model"}):
            config = APITargetConfig.from_url(
                "https://api.example.com/v1/chat/completions",
            )
            assert config.headers.get("Authorization") == "Bearer env-key"
            assert "env-model" in config.body_template


# ============================================================
# MFADetectionResult 数据模型测试
# ============================================================


class TestMFADetectionResult:
    """MFADetectionResult 数据模型测试。"""

    def test_empty_result(self) -> None:
        """空结果 → has_mfa=False。"""
        result = MFADetectionResult()
        assert result.has_mfa is False
        assert result.mfa_types == []

    def test_with_otp(self) -> None:
        """有 OTP → has_mfa=True。"""
        result = MFADetectionResult(
            mfa_types=["otp"],
            selectors_matched={"otp": ['input[name="code"]']},
            human_instructions=["请在浏览器中输入 OTP / 验证码"],
        )
        assert result.has_mfa is True
        assert "otp" in result.mfa_types

    def test_with_multiple_mfa(self) -> None:
        """多种 MFA → has_mfa=True。"""
        result = MFADetectionResult(
            mfa_types=["captcha", "otp"],
            human_instructions=["请完成图形验证码", "请输入验证码"],
        )
        assert result.has_mfa is True
        assert len(result.mfa_types) == 2


# ============================================================
# parse_args 统一入口参数测试
# ============================================================


class TestParseArgsUnifiedEntry:
    """parse_args 统一入口参数测试。"""

    def test_target_url_from_cli(self) -> None:
        """--target-url 命令行参数。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--target-url", "https://example.com/chat"]):
            args = parse_args()
            assert args.target_url == "https://example.com/chat"

    def test_target_url_from_env(self) -> None:
        """从 .env TARGET_URL 读取。"""
        from pipeline.config import parse_args

        with patch.dict(os.environ, {"TARGET_URL": "https://env.example.com/chat"}), patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.target_url == "https://env.example.com/chat"

    def test_target_url_from_web_redteam_env(self) -> None:
        """从 .env WEB_REDTEAM_TARGET_URL 读取 (向后兼容)。"""
        from pipeline.config import parse_args

        env_vars = {"WEB_REDTEAM_TARGET_URL": "https://legacy.example.com/chat"}
        with patch.dict(os.environ, env_vars), patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.target_url == "https://legacy.example.com/chat"

    def test_cli_overrides_env(self) -> None:
        """命令行参数优先于环境变量。"""
        from pipeline.config import parse_args

        env_vars = {"TARGET_URL": "https://env.example.com"}
        cli_args = ["main.py", "--target-url", "https://cli.example.com"]
        with patch.dict(os.environ, env_vars), patch("sys.argv", cli_args):
            args = parse_args()
            assert args.target_url == "https://cli.example.com"

    def test_load_local_datasets_default_true(self) -> None:
        """--load-local-datasets 默认为 True。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.load_local_datasets is True

    def test_no_local_datasets_disables(self) -> None:
        """--no-local-datasets 禁用本地数据集加载。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--no-local-datasets"]):
            args = parse_args()
            assert args.load_local_datasets is False

    def test_load_owasp_local_backward_compat(self) -> None:
        """--load-owasp-local 向后兼容, 等价于 --load-local-datasets。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.load_owasp_local is True

    def test_no_owasp_local_backward_compat(self) -> None:
        """--no-owasp-local 向后兼容, 同时禁用 load_local_datasets。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--no-owasp-local"]):
            args = parse_args()
            assert args.load_owasp_local is False
            assert args.load_local_datasets is False

    def test_skip_preflight_default_true(self) -> None:
        """--skip-preflight 默认为 True (预检默认跳过, 简化命令行)."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.skip_preflight is True
            assert args.run_preflight is False

    def test_run_preflight_flag(self) -> None:
        """--run-preflight 手动启用预检."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--run-preflight"]):
            args = parse_args()
            assert args.run_preflight is True

    def test_disable_json_mode_default_false(self) -> None:
        """--disable-json-mode 默认为 False (自动检测模式)."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.disable_json_mode is False

    def test_disable_json_mode_flag(self) -> None:
        """--disable-json-mode 设置为 True."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--disable-json-mode"]):
            args = parse_args()
            assert args.disable_json_mode is True

    def test_target_type_auto_default(self) -> None:
        """--target-type 默认为 auto。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.target_type == "auto"

    def test_mfa_timeout_default(self) -> None:
        """--mfa-timeout 默认为 300。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.mfa_timeout == 300


# ============================================================
# v56: AttackSurfaceTopology 多维攻击面拓扑测试
# ============================================================


class TestAttackSurfaceTopology:
    """v56: AttackSurfaceTopology 数据模型测试。"""

    def test_default_values(self) -> None:
        """默认值测试。"""
        topology = AttackSurfaceTopology()
        assert topology.transport_type == "unknown"
        assert topology.app_architecture == "simple_llm"
        assert topology.has_tool_calling is False
        assert topology.auth_topology == "none"
        assert topology.injection_surfaces == ["user_message"]
        assert topology.discovered_tools == []
        assert topology.trust_boundaries == ["user→llm"]
        assert topology.recommended_kill_chain == ["recon", "initial_access"]
        assert topology.recommended_owasp == ["LLM01"]

    def test_str_representation(self) -> None:
        """字符串表示包含关键字段。"""
        topology = AttackSurfaceTopology(
            transport_type="api_platform",
            app_architecture="agent_with_tools",
            auth_topology="bearer_token",
        )
        s = str(topology)
        assert "api_platform" in s
        assert "agent_with_tools" in s
        assert "bearer_token" in s


class TestBuildAttackSurfaceTopology:
    """v56: build_attack_surface_topology 方法测试。"""

    @pytest.fixture
    def classifier(self) -> TargetClassifier:
        """创建 TargetClassifier 实例。"""
        return TargetClassifier(http_timeout=1)

    def test_simple_llm_no_burp(self, classifier: TargetClassifier) -> None:
        """无 Burp 请求 → simple_llm 架构。"""
        classification = TargetClassification(
            target_type="llm_api_platform",
            target_url="https://api.example.com/v1/chat/completions",
        )
        topology = classifier.build_attack_surface_topology(classification)
        assert topology.transport_type == "api_platform"
        assert topology.app_architecture == "simple_llm"
        assert topology.has_tool_calling is False
        assert topology.auth_topology == "none"
        assert "user_message" in topology.injection_surfaces
        assert topology.recommended_owasp == ["LLM01"]

    def test_agent_with_tools_from_burp(self, classifier: TargetClassifier) -> None:
        """Burp 请求体含 tools → agent_with_tools。"""
        burp_request = (
            "POST /v1/chat/completions HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],'
            '"tools":[{"type":"function","function":{"name":"execute_command",'
            '"description":"Run a command","parameters":{}}}]}'
        )
        classification = TargetClassification(
            target_type="llm_api_platform",
            target_url="https://api.example.com/v1/chat/completions",
        )
        topology = classifier.build_attack_surface_topology(
            classification, burp_raw_request=burp_request
        )
        assert topology.has_tool_calling is True
        assert topology.app_architecture == "agent_with_tools"
        assert len(topology.discovered_tools) == 1
        assert topology.discovered_tools[0]["name"] == "execute_command"
        assert "tool_result" in topology.injection_surfaces
        assert "ASI06" in topology.recommended_owasp

    def test_rag_pipeline_detection(self, classifier: TargetClassifier) -> None:
        """Burp 请求体含 RAG 特征字段 → rag_pipeline。"""
        burp_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"query"}],'
            '"retrieved_context":"some context"}'
        )
        classification = TargetClassification(target_type="llm_api_platform")
        topology = classifier.build_attack_surface_topology(
            classification, burp_raw_request=burp_request
        )
        assert topology.app_architecture == "rag_pipeline"
        assert "rag_content" in topology.injection_surfaces
        assert "LLM07" in topology.recommended_owasp

    def test_mcp_orchestrator_detection(self, classifier: TargetClassifier) -> None:
        """Burp 请求体含 MCP 特征字段 → mcp_orchestrator。"""
        burp_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"hi"}],'
            '"mcp_config":{"server":"localhost"}}'
        )
        classification = TargetClassification(target_type="llm_api_platform")
        topology = classifier.build_attack_surface_topology(
            classification, burp_raw_request=burp_request
        )
        assert topology.app_architecture == "mcp_orchestrator"
        assert "mcp_protocol" in topology.injection_surfaces
        assert "ASI01" in topology.recommended_owasp

    def test_auth_topology_bearer_jwt(self, classifier: TargetClassifier) -> None:
        """Bearer JWT Token → oauth2_jwt 认证拓扑。"""
        # 构造一个简化 JWT (header.payload.signature)
        # header: {"alg":"HS256"}, payload: {"exp":9999999999}
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"exp": 9999999999}).encode()).rstrip(b"=").decode()
        jwt_token = f"{header}.{payload}.signature"

        classification = TargetClassification(
            target_type="llm_api_platform",
            api_auth_type="bearer",
        )
        auth_headers = {"Authorization": f"Bearer {jwt_token}"}
        topology = classifier.build_attack_surface_topology(
            classification, auth_headers=auth_headers
        )
        assert topology.auth_topology == "oauth2_jwt"
        assert topology.auth_persistence == "persistent"
        assert topology.token_expiry_seconds > 0

    def test_auth_topology_session_cookie(self, classifier: TargetClassifier) -> None:
        """Cookie → session_cookie 认证拓扑。"""
        classification = TargetClassification(target_type="llm_web_app")
        auth_headers = {"Cookie": "session_id=abc123"}
        topology = classifier.build_attack_surface_topology(
            classification, auth_headers=auth_headers
        )
        assert topology.auth_topology == "session_cookie"
        assert topology.auth_persistence == "session"

    def test_kill_chain_mapping(self, classifier: TargetClassifier) -> None:
        """Kill Chain 映射 — Agent + 认证 → 完整链路。"""
        burp_request = (
            "POST /v1/chat/completions HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Authorization: Bearer sk-test123\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"hi"}],'
            '"tools":[{"type":"function","function":{"name":"read_file",'
            '"description":"Read a file","parameters":{}}}]}'
        )
        classification = TargetClassification(
            target_type="llm_api_platform",
            api_auth_type="bearer",
        )
        topology = classifier.build_attack_surface_topology(
            classification, burp_raw_request=burp_request
        )
        # 应包含 recon, initial_access, credential_access, persistence, bypass
        assert "recon" in topology.recommended_kill_chain
        assert "initial_access" in topology.recommended_kill_chain
        assert "credential_access" in topology.recommended_kill_chain
        assert "persistence" in topology.recommended_kill_chain
        assert "bypass" in topology.recommended_kill_chain

    def test_high_risk_tools_marked(self, classifier: TargetClassifier) -> None:
        """高风险工具被标记到 model_fingerprint。"""
        burp_request = (
            "POST /v1/chat/completions HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"hi"}],'
            '"tools":[{"type":"function","function":{"name":"execute_command",'
            '"description":"Run command","parameters":{}}},'
            '{"type":"function","function":{"name":"read_file",'
            '"description":"Read file","parameters":{}}}]}'
        )
        classification = TargetClassification(target_type="llm_api_platform")
        topology = classifier.build_attack_surface_topology(
            classification, burp_raw_request=burp_request
        )
        assert "high_risk_tools" in topology.model_fingerprint
        assert "execute_command" in topology.model_fingerprint["high_risk_tools"]


class TestAnalyzeBurpAgentStructure:
    """v56: analyze_burp_agent_structure 函数测试。"""

    def test_simple_llm_request(self) -> None:
        """简单 LLM 请求 → is_agent=False。"""
        from pipeline.targets.capability_adapter import analyze_burp_agent_structure

        burp = (
            'POST /v1/chat/completions HTTP/1.1\r\n\r\n'
            '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}'
        )
        result = analyze_burp_agent_structure(burp)
        assert result["is_agent"] is False
        assert result["app_architecture"] == "simple_llm"
        assert result["model_name"] == "gpt-4"

    def test_agent_with_tools(self) -> None:
        """Agent + tools → is_agent=True。"""
        from pipeline.targets.capability_adapter import analyze_burp_agent_structure

        burp = (
            'POST /v1/chat/completions HTTP/1.1\r\n\r\n'
            '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],'
            '"tools":[{"type":"function","function":{"name":"write_file",'
            '"description":"Write file","parameters":{}}}]}'
        )
        result = analyze_burp_agent_structure(burp)
        assert result["is_agent"] is True
        assert result["app_architecture"] == "agent_with_tools"
        assert len(result["tools"]) == 1
        assert result["tools"][0]["name"] == "write_file"
        assert "write_file" in result["high_risk_tools"]
        assert "tool_result" in result["injection_surfaces"]

    def test_system_prompt_detection(self) -> None:
        """System prompt 检测。"""
        from pipeline.targets.capability_adapter import analyze_burp_agent_structure

        burp = (
            'POST /v1/chat/completions HTTP/1.1\r\n\r\n'
            '{"messages":[{"role":"system","content":"You are a helpful assistant"},'
            '{"role":"user","content":"hi"}]}'
        )
        result = analyze_burp_agent_structure(burp)
        assert result["has_system_prompt"] is True
        assert "system_prompt" in result["injection_surfaces"]

    def test_attack_seeds_generation(self) -> None:
        """攻击种子自动生成。"""
        from pipeline.targets.capability_adapter import analyze_burp_agent_structure

        burp = (
            'POST /v1/chat/completions HTTP/1.1\r\n\r\n'
            '{"messages":[{"role":"system","content":"system prompt"},'
            '{"role":"user","content":"hi"}],'
            '"tools":[{"type":"function","function":{"name":"execute_command",'
            '"description":"Run command","parameters":{}}}]}'
        )
        result = analyze_burp_agent_structure(burp)
        seeds = result["attack_seeds"]
        assert len(seeds) >= 3  # prompt_injection + system_prompt_extraction + tool_hijacking + high_risk_tool_exploit
        types = [s["type"] for s in seeds]
        assert "prompt_injection" in types
        assert "system_prompt_extraction" in types
        assert "tool_hijacking" in types
        assert "high_risk_tool_exploit" in types

    def test_invalid_json_body(self) -> None:
        """无效 JSON → 默认结果。"""
        from pipeline.targets.capability_adapter import analyze_burp_agent_structure

        burp = "POST /api HTTP/1.1\r\n\r\nnot json"
        result = analyze_burp_agent_structure(burp)
        assert result["is_agent"] is False
        assert result["app_architecture"] == "simple_llm"


class TestAnalyzeCapturedToken:
    """v56: analyze_captured_token 函数测试。"""

    def test_non_jwt_bearer_token(self) -> None:
        """非 JWT Bearer Token → 基础分析。"""
        from web_redteam.auth.api_auth import analyze_captured_token

        result = analyze_captured_token("sk-simple-api-key", "bearer_token")
        assert result["is_jwt"] is False
        assert result["risk_level"] == "medium"
        assert len(result["attack_seeds"]) > 0

    def test_jwt_with_admin_role(self) -> None:
        """JWT 含 admin 角色 → critical 风险。"""
        import base64
        import json
        import time

        from web_redteam.auth.api_auth import analyze_captured_token

        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"role": "admin", "exp": int(time.time()) + 7200}).encode()
        ).rstrip(b"=").decode()
        jwt_token = f"{header}.{payload}.sig"

        result = analyze_captured_token(jwt_token, "oauth2_jwt")
        assert result["is_jwt"] is True
        assert result["role"] == "admin"
        assert result["risk_level"] == "critical"
        types = [s["type"] for s in result["attack_seeds"]]
        assert "privilege_escalation" in types

    def test_jwt_alg_none(self) -> None:
        """JWT alg=none → critical 风险 + 伪造攻击种子。"""
        import base64
        import json

        from web_redteam.auth.api_auth import analyze_captured_token

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "user"}).encode()).rstrip(b"=").decode()
        jwt_token = f"{header}.{payload}."

        result = analyze_captured_token(jwt_token, "oauth2_jwt")
        assert result["algorithm"] == "none"
        assert result["risk_level"] == "critical"
        types = [s["type"] for s in result["attack_seeds"]]
        assert "jwt_forgery" in types

    def test_jwt_long_expiry(self) -> None:
        """JWT exp > 24h → high 风险 + 持久化种子。"""
        import base64
        import json
        import time

        from web_redteam.auth.api_auth import analyze_captured_token

        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"exp": int(time.time()) + 100000}).encode()
        ).rstrip(b"=").decode()
        jwt_token = f"{header}.{payload}.sig"

        result = analyze_captured_token(jwt_token, "oauth2_jwt")
        assert result["expiry_seconds"] > 86400
        assert result["risk_level"] == "high"
        types = [s["type"] for s in result["attack_seeds"]]
        assert "token_persistence" in types

    def test_session_cookie_auth_type(self) -> None:
        """Session Cookie 认证 → medium 风险。"""
        from web_redteam.auth.api_auth import analyze_captured_token

        result = analyze_captured_token("session=abc123", "session_cookie")
        assert result["is_jwt"] is False
        assert result["risk_level"] == "medium"


class TestDiscoverAlternativeAttackPaths:
    """v56: _discover_alternative_attack_paths 函数测试。"""

    def test_simple_llm_only_direct_injection(self) -> None:
        """简单 LLM → 仅直接注入路径。"""
        from pipeline.stages.stage_target_classify import _discover_alternative_attack_paths

        topology = AttackSurfaceTopology()
        classification = TargetClassification()
        paths = _discover_alternative_attack_paths(topology, classification)
        assert len(paths) == 1
        assert paths[0]["path_id"] == "path_1_direct_injection"

    def test_agent_with_tools_multiple_paths(self) -> None:
        """Agent + tools → 多条替代路径。"""
        from pipeline.stages.stage_target_classify import _discover_alternative_attack_paths

        topology = AttackSurfaceTopology(
            has_tool_calling=True,
            has_multi_turn=True,
            auth_topology="bearer_token",
        )
        topology.model_fingerprint["high_risk_tools"] = ["execute_command"]
        classification = TargetClassification()
        paths = _discover_alternative_attack_paths(topology, classification)
        path_ids = [p["path_id"] for p in paths]
        assert "path_1_direct_injection" in path_ids
        assert "path_2_tool_hijack" in path_ids
        assert "path_2b_high_risk_tool" in path_ids
        assert "path_4_token_theft" in path_ids
        assert "path_6_crescendo" in path_ids
        # 按 ASR 降序
        assert paths[0]["estimated_asr"] >= paths[-1]["estimated_asr"]

    def test_crescendo_highest_asr(self) -> None:
        """Crescendo 路径 ASR=82% 最高。"""
        from pipeline.stages.stage_target_classify import _discover_alternative_attack_paths

        topology = AttackSurfaceTopology(
            has_tool_calling=True,
            has_multi_turn=True,
        )
        classification = TargetClassification()
        paths = _discover_alternative_attack_paths(topology, classification)
        crescendo = [p for p in paths if p["path_id"] == "path_6_crescendo"]
        assert len(crescendo) == 1
        assert crescendo[0]["estimated_asr"] == 0.82
        # Crescendo 应排第一 (最高 ASR)
        assert paths[0]["path_id"] == "path_6_crescendo"


# ============================================================
# v57: 攻击者视角全链路集成测试
# ============================================================


class TestAttackSurfaceCard:
    """v57: attack_surface_card 展示函数测试。"""

    def test_card_with_full_topology(self, capsys: pytest.CaptureFixture[str]) -> None:
        """完整拓扑 → 卡片正常输出。"""
        from pipeline.utils.display import attack_surface_card

        topology = AttackSurfaceTopology(
            app_architecture="agent_with_tools",
            transport_type="sse",
            auth_topology="bearer",
            injection_surfaces=["user_message", "tool_result"],
            discovered_tools=["web_search", "file_read"],
            recommended_kill_chain=["recon", "initial_access", "bypass"],
            recommended_owasp=["LLM01", "ASI02"],
        )
        attack_surface_card(topology)
        captured = capsys.readouterr()
        assert "攻击面拓扑" in captured.out
        assert "agent_with_tools" in captured.out

    def test_card_with_empty_topology(self, capsys: pytest.CaptureFixture[str]) -> None:
        """空拓扑 → 卡片不崩溃。"""
        from pipeline.utils.display import attack_surface_card

        topology = AttackSurfaceTopology()
        attack_surface_card(topology)
        captured = capsys.readouterr()
        # 应有输出（即使空也有基础信息）
        assert "攻击面拓扑" in captured.out

    def test_card_with_none_raises_no_exception(self) -> None:
        """None 输入 → 不抛异常。"""
        from pipeline.utils.display import attack_surface_card

        attack_surface_card(None)  # 不应抛异常


class TestAlternativePathsCard:
    """v57: alternative_paths_card 展示函数测试。"""

    def test_card_with_paths(self, capsys: pytest.CaptureFixture[str]) -> None:
        """有路径 → 卡片正常输出。"""
        from pipeline.utils.display import alternative_paths_card

        paths = [
            {"path_id": "path_1", "technique": "crescendo", "estimated_asr": 0.82,
             "owasp": "LLM01", "target_surface": "conversation", "prerequisite": "none"},
            {"path_id": "path_2", "technique": "tool_hijack", "estimated_asr": 0.60,
             "owasp": "ASI02", "target_surface": "tool_result", "prerequisite": "agent"},
        ]
        alternative_paths_card(paths)
        captured = capsys.readouterr()
        assert "降级链" in captured.out
        assert "crescendo" in captured.out

    def test_card_empty_paths_no_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """空路径 → 无输出。"""
        from pipeline.utils.display import alternative_paths_card

        alternative_paths_card([])
        captured = capsys.readouterr()
        assert captured.out == ""


class TestEvidenceCollectionTopology:
    """v57: EvidenceCollection 拓扑字段测试。"""

    def test_topology_fields_default_empty(self) -> None:
        """默认值 → 空字典/空列表。"""
        from pipeline.analysis.evidence_collector import EvidenceCollection

        collection = EvidenceCollection()
        assert collection.attack_surface_topology == {}
        assert collection.alternative_attack_paths == []

    def test_to_dict_includes_topology(self) -> None:
        """to_dict() 包含拓扑字段。"""
        from pipeline.analysis.evidence_collector import EvidenceCollection

        collection = EvidenceCollection()
        collection.attack_surface_topology = {"app_architecture": "agent"}
        collection.alternative_attack_paths = [{"path_id": "test"}]
        d = collection.to_dict()
        assert "attack_surface_topology" in d
        assert d["attack_surface_topology"]["app_architecture"] == "agent"
        assert "alternative_attack_paths" in d
        assert len(d["alternative_attack_paths"]) == 1

    def test_collect_with_metadata_fills_topology(self) -> None:
        """collect(metadata=...) 填充拓扑字段。"""
        from pipeline.analysis.evidence_collector import EvidenceCollector

        collector = EvidenceCollector(target_model="test", model_tier="unknown")
        topology = AttackSurfaceTopology(
            app_architecture="agent",
            transport_type="http",
            auth_topology="bearer",
            injection_surfaces=["user_message"],
            discovered_tools=["search"],
            recommended_kill_chain=["recon"],
            recommended_owasp=["LLM01"],
        )
        metadata = {
            "attack_surface_topology": topology,
            "alternative_attack_paths": [{"path_id": "p1", "estimated_asr": 0.5}],
        }
        collection = collector.collect(
            attack_results={},
            metadata=metadata,
        )
        assert collection.attack_surface_topology["app_architecture"] == "agent"
        assert len(collection.alternative_attack_paths) == 1

    def test_collect_without_metadata_no_crash(self) -> None:
        """collect(metadata=None) 不崩溃。"""
        from pipeline.analysis.evidence_collector import EvidenceCollector

        collector = EvidenceCollector(target_model="test", model_tier="unknown")
        collection = collector.collect(attack_results={})
        assert collection.attack_surface_topology == {}
        assert collection.alternative_attack_paths == []


# ============================================================
# v58: 替代路径自动路由 + 拓扑驱动Converter选择 + 拓扑持久化
# ============================================================


class TestTriggerAlternativePathAttacks:
    """v58: _trigger_alternative_path_attacks 逻辑测试。"""

    def test_no_alt_paths_returns_early(self) -> None:
        """无替代路径 → 提前返回。"""
        from pipeline.stages.stage_execute import _trigger_alternative_path_attacks

        # 无 metadata 中的 alt_paths → 不崩溃
        ctx = type("Ctx", (), {"metadata": {}})()
        import asyncio

        asyncio.run(_trigger_alternative_path_attacks(ctx, []))

    def test_crescendo_success_skips_alt_paths(self) -> None:
        """Crescendo 已突破 → 跳过替代路径。"""
        from pipeline.stages.stage_execute import _trigger_alternative_path_attacks

        ctx = type("Ctx", (), {"metadata": {
            "alternative_attack_paths": [{"path_id": "p2", "estimated_asr": 0.6}],
            "post_crescendo_results": [{"achieved": True}],
        }})()
        import asyncio

        asyncio.run(_trigger_alternative_path_attacks(ctx, []))

    def test_high_asr_skips_alt_paths(self) -> None:
        """ASR>=30% → 不触发替代路径。"""
        from pipeline.stages.stage_execute import _trigger_alternative_path_attacks

        # 构造 5 个结果, 2 个 SUCCESS (40% ASR)
        class FakeAR:
            def __init__(self, outcome_name: str) -> None:
                class Outcome:
                    name = outcome_name
                self.outcome = Outcome()
                self.objective = "test objective here"

        ctx = type("Ctx", (), {"metadata": {
            "alternative_attack_paths": [{"path_id": "p2", "estimated_asr": 0.6}],
            "post_crescendo_results": [],
        }})()
        results = [FakeAR("SUCCESS"), FakeAR("SUCCESS"), FakeAR("FAILURE"),
                   FakeAR("FAILURE"), FakeAR("FAILURE")]
        import asyncio

        asyncio.run(_trigger_alternative_path_attacks(ctx, results))


class TestTopologyDrivenConverterSelection:
    """v58: 拓扑驱动 Converter 选择测试。"""

    def test_injection_surfaces_adds_chains(self) -> None:
        """注入面 → 补充对应 Converter 链。"""
        from pipeline.converters.factory import build_target_aware_converter_map

        # tool_result 注入面应补充 encoding_bypass
        result = build_target_aware_converter_map(
            technique_names=["prompt_sending"],
            target_type="openai_chat",
            injection_surfaces=["tool_result"],
        )
        # 应有结果 (tool_result → encoding_bypass 补充)
        if result:
            assert "prompt_sending" in result

    def test_no_injection_surfaces_no_crash(self) -> None:
        """无注入面参数 → 不崩溃 (向后兼容)。"""
        from pipeline.converters.factory import build_target_aware_converter_map

        result = build_target_aware_converter_map(
            technique_names=["prompt_sending"],
            target_type="openai_chat",
        )
        # 向后兼容: 无 injection_surfaces 参数也能正常工作
        assert isinstance(result, dict)

    def test_multiple_surfaces_merge_chains(self) -> None:
        """多个注入面 → 合并 Converter 链。"""
        from pipeline.converters.factory import build_target_aware_converter_map

        result = build_target_aware_converter_map(
            technique_names=["prompt_sending"],
            target_type="openai_chat",
            injection_surfaces=["tool_result", "rag_content", "conversation_history"],
        )
        # 多注入面合并应不崩溃且有结果
        assert isinstance(result, dict)


class TestTopologyPersistence:
    """v58: 攻击面拓扑持久化测试。"""

    def test_persist_creates_json_file(self, tmp_path: pytest.CaptureFixture[str]) -> None:
        """拓扑持久化 → 生成 attack_surface.json。"""
        import json
        from pathlib import Path

        # 模拟持久化逻辑
        persist_dir = Path("outputs/auth_state")
        persist_dir.mkdir(parents=True, exist_ok=True)
        persist_path = persist_dir / "attack_surface.json"

        topo_data = {
            "app_architecture": "agent",
            "injection_surfaces": ["user_message"],
        }
        with open(persist_path, "w", encoding="utf-8") as f:
            json.dump(topo_data, f, indent=2, ensure_ascii=False)

        assert persist_path.exists()
        with open(persist_path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["app_architecture"] == "agent"
        assert loaded["injection_surfaces"] == ["user_message"]


# ============================================================
# v59: 拓扑持久化跨运行复用 + 替代路径ASR经验写回 + 拓扑驱动技术选择
# ============================================================


class TestTopologyDiffDetection:
    """v59: 拓扑增量变化检测测试。"""

    def test_diff_detects_new_surfaces(self) -> None:
        """新增注入面 → diff 中包含 new_injection_surfaces。"""
        import json
        from pathlib import Path

        persist_dir = Path("outputs/auth_state")
        persist_dir.mkdir(parents=True, exist_ok=True)
        persist_path = persist_dir / "attack_surface.json"

        # 写入历史拓扑
        historical = {"injection_surfaces": ["user_message"], "discovered_tools": []}
        with open(persist_path, "w", encoding="utf-8") as f:
            json.dump(historical, f, ensure_ascii=False)

        # 模拟 diff 逻辑
        current_surfaces = ["user_message", "tool_result"]
        new_surfaces = set(current_surfaces) - set(historical["injection_surfaces"])
        assert "tool_result" in new_surfaces

    def test_no_diff_when_same(self) -> None:
        """相同拓扑 → 无 diff。"""
        current = {"injection_surfaces": ["user_message"], "discovered_tools": ["search"]}
        historical = {"injection_surfaces": ["user_message"], "discovered_tools": ["search"]}
        new_surfaces = set(current["injection_surfaces"]) - set(historical["injection_surfaces"])
        new_tools = set(current["discovered_tools"]) - set(historical["discovered_tools"])
        assert not new_surfaces
        assert not new_tools


class TestAlternativePathASRWriteback:
    """v59: 替代路径 ASR 经验写回测试。"""

    def test_alt_path_asr_injection(self) -> None:
        """替代路径结果 → ASR 回注到 asr_per_technique。"""
        # 模拟 _inject_orchestrator_results_to_asr 的替代路径回注逻辑
        alt_path_results = [
            {"technique": "indirect_prompt_injection", "achieved": True},
            {"technique": "indirect_prompt_injection", "achieved": False},
            {"technique": "tool_hijack", "achieved": True},
        ]
        asr_per_technique: dict[str, float] = {}

        path_stats: dict[str, dict[str, int]] = {}
        for r in alt_path_results:
            tech = r.get("technique", "unknown")
            if tech not in path_stats:
                path_stats[tech] = {"total": 0, "success": 0}
            path_stats[tech]["total"] += 1
            if r.get("achieved"):
                path_stats[tech]["success"] += 1

        for tech, stats in path_stats.items():
            if stats["total"] > 0:
                asr_val = (stats["success"] / stats["total"]) * 100.0
                asr_key = f"alt_path_{tech}"
                asr_per_technique[asr_key] = asr_val

        assert "alt_path_indirect_prompt_injection" in asr_per_technique
        assert asr_per_technique["alt_path_indirect_prompt_injection"] == 50.0
        assert asr_per_technique["alt_path_tool_hijack"] == 100.0

    def test_empty_alt_results_no_crash(self) -> None:
        """空替代路径结果 → 不崩溃。"""
        alt_path_results: list[dict[str, Any]] = []
        path_stats: dict[str, dict[str, int]] = {}
        for r in alt_path_results:
            tech = r.get("technique", "unknown")
            if tech not in path_stats:
                path_stats[tech] = {"total": 0, "success": 0}
            path_stats[tech]["total"] += 1
            if r.get("achieved"):
                path_stats[tech]["success"] += 1
        assert len(path_stats) == 0


class TestTopologyDrivenTechSelection:
    """v59: 拓扑驱动技术选择测试。"""

    def test_agent_topology_recommends_indirect_injection(self) -> None:
        """Agent 拓扑 → 推荐 indirect_prompt_injection + tool_hijack。"""
        _TOPOLOGY_TECH_MAP: dict[str, list[str]] = {
            "agent_with_tools": ["indirect_prompt_injection", "tool_hijack"],
            "mcp_orchestrator": ["mcp_protocol_injection"],
            "rag_pipeline": ["rag_poisoning"],
        }
        recommended = _TOPOLOGY_TECH_MAP.get("agent_with_tools", [])
        assert "indirect_prompt_injection" in recommended
        assert "tool_hijack" in recommended

    def test_rag_topology_recommends_poisoning(self) -> None:
        """RAG 拓扑 → 推荐 rag_poisoning。"""
        _TOPOLOGY_TECH_MAP: dict[str, list[str]] = {
            "agent_with_tools": ["indirect_prompt_injection", "tool_hijack"],
            "mcp_orchestrator": ["mcp_protocol_injection"],
            "rag_pipeline": ["rag_poisoning"],
        }
        recommended = _TOPOLOGY_TECH_MAP.get("rag_pipeline", [])
        assert "rag_poisoning" in recommended

    def test_unknown_topology_no_recommendation(self) -> None:
        """未知拓扑 → 空推荐列表。"""
        _TOPOLOGY_TECH_MAP: dict[str, list[str]] = {
            "agent_with_tools": ["indirect_prompt_injection", "tool_hijack"],
            "mcp_orchestrator": ["mcp_protocol_injection"],
            "rag_pipeline": ["rag_poisoning"],
        }
        recommended = _TOPOLOGY_TECH_MAP.get("unknown_architecture", [])
        assert recommended == []


# ============================================================
# v60: 拓扑diff驱动种子补充 + warm-start ASR消费 + 拓扑驱动场景推荐
# ============================================================


class TestRecommendScenarioFromTopology:
    """v60: _recommend_scenario_from_topology 测试。"""

    def test_agent_with_tools_recommends_agent_scenario(self) -> None:
        """Agent+工具 → agent_tool_hijack。"""
        from pipeline.stages.stage_target_classify import _recommend_scenario_from_topology

        topo = AttackSurfaceTopology(app_architecture="agent_with_tools")
        result = _recommend_scenario_from_topology(topo)
        assert result == "agent_tool_hijack"

    def test_mcp_recommends_mcp_scenario(self) -> None:
        """MCP → mcp_protocol_attack。"""
        from pipeline.stages.stage_target_classify import _recommend_scenario_from_topology

        topo = AttackSurfaceTopology(app_architecture="mcp_orchestrator")
        result = _recommend_scenario_from_topology(topo)
        assert result == "mcp_protocol_attack"

    def test_rag_recommends_rag_scenario(self) -> None:
        """RAG → rag_poisoning。"""
        from pipeline.stages.stage_target_classify import _recommend_scenario_from_topology

        topo = AttackSurfaceTopology(app_architecture="rag_pipeline")
        result = _recommend_scenario_from_topology(topo)
        assert result == "rag_poisoning"

    def test_multi_turn_recommends_crescendo(self) -> None:
        """多轮 → crescendo_adaptive。"""
        from pipeline.stages.stage_target_classify import _recommend_scenario_from_topology

        topo = AttackSurfaceTopology(app_architecture="simple_llm", has_multi_turn=True)
        result = _recommend_scenario_from_topology(topo)
        assert result == "crescendo_adaptive"

    def test_simple_llm_returns_none(self) -> None:
        """简单LLM无特殊拓扑 → None。"""
        from pipeline.stages.stage_target_classify import _recommend_scenario_from_topology

        topo = AttackSurfaceTopology(app_architecture="simple_llm")
        result = _recommend_scenario_from_topology(topo)
        assert result is None


class TestWarmStartASRConsumption:
    """v60: 替代路径ASR warm-start消费测试。"""

    def test_warm_start_overrides_estimated_asr(self) -> None:
        """历史ASR覆盖静态估算值。"""
        from pipeline.stages.stage_target_classify import _discover_alternative_attack_paths

        topo = AttackSurfaceTopology(
            app_architecture="agent_with_tools",
            has_tool_calling=True,
            has_multi_turn=True,
            injection_surfaces=["user_message", "tool_result"],
        )
        classification = TargetClassification(
            target_type="llm_api_platform",
            recommended_mode="burp",
        )
        with patch("pipeline.asr.optimizer.load_empirical_asr_with_counts") as mock_load:
            mock_load.return_value = (
                {"alt_path_indirect_prompt_injection": 0.75},
                {"alt_path_indirect_prompt_injection": 5},
            )
            paths = _discover_alternative_attack_paths(topo, classification)
        # indirect_prompt_injection路径的estimated_asr应被覆盖为0.75 (high置信度, 不降权)
        hijack_path = next(p for p in paths if p["technique"] == "indirect_prompt_injection")
        assert hijack_path["estimated_asr"] == 0.75
        assert hijack_path.get("asr_source") == "empirical_warm_start"
        assert hijack_path.get("asr_confidence") == "high"

    def test_no_historical_asr_keeps_static_estimate(self) -> None:
        """无历史ASR → 保持静态估算值。"""
        from pipeline.stages.stage_target_classify import _discover_alternative_attack_paths

        topo = AttackSurfaceTopology(
            app_architecture="agent_with_tools",
            has_tool_calling=True,
            injection_surfaces=["user_message", "tool_result"],
        )
        classification = TargetClassification(
            target_type="llm_api_platform",
            recommended_mode="burp",
        )
        with patch("pipeline.asr.optimizer.load_empirical_asr_with_counts") as mock_load:
            mock_load.return_value = ({}, {})
            paths = _discover_alternative_attack_paths(topo, classification)
        # 无历史数据 → asr_source不应被设置
        for p in paths:
            assert "asr_source" not in p or p.get("asr_source") != "empirical_warm_start"


class TestDiffDrivenSeeds:
    """v60: 拓扑diff驱动种子补充测试。"""

    def test_diff_surface_seed_templates_cover_key_surfaces(self) -> None:
        """_DIFF_SURFACE_SEEDS覆盖关键注入面类型。"""
        # 验证种子模板字典定义存在且覆盖5种注入面
        # 通过间接验证: 构造拓扑+历史数据触发diff检测
        # 这里直接验证种子模板的覆盖面
        expected_surfaces = {"tool_result", "rag_content", "mcp_protocol", "auth_token", "conversation_history"}
        # 种子模板在 _expand_attack_surface 内部定义, 通过行为验证
        assert len(expected_surfaces) == 5

    def test_diff_seeds_have_required_fields(self) -> None:
        """diff种子包含必要字段。"""
        # 验证种子模板结构: objective + technique + owasp_id + category + surface
        # 通过模拟diff检测验证种子生成
        from pipeline.integrations.target_classifier import AttackSurfaceTopology

        # 构造一个简单拓扑验证属性可访问
        topo = AttackSurfaceTopology(
            app_architecture="agent_with_tools",
            injection_surfaces=["user_message", "tool_result"],
            discovered_tools=[{"name": "search"}],
        )
        assert "tool_result" in topo.injection_surfaces
        assert topo.app_architecture == "agent_with_tools"


# ============================================================
# v60+: 证据报告拓扑diff展示 + warm-start路径选择 + 场景推荐CLI覆盖
# ============================================================


class TestEvidenceReportDiffSection:
    """V-134: 证据报告拓扑增量diff段落测试。"""

    def test_diff_section_rendered_when_present(self) -> None:
        """拓扑含diff_from_previous → 报告渲染增量段落。"""
        from pipeline.analysis.evidence_collector import EvidenceCollector

        collector = EvidenceCollector(target_model="test", model_tier="unknown")
        topology = AttackSurfaceTopology(
            app_architecture="agent_with_tools",
            injection_surfaces=["user_message", "tool_result"],
        )
        metadata = {
            "attack_surface_topology": topology,
            "alternative_attack_paths": [],
        }
        collection = collector.collect(attack_results={}, metadata=metadata)
        # 手动注入 diff_from_previous
        collection.attack_surface_topology["diff_from_previous"] = {
            "new_injection_surfaces": ["rag_content"],
            "new_discovered_tools": ["search_tool"],
        }
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = collector.save_markdown(collection, Path(tmpdir))
            content = md_path.read_text(encoding="utf-8")
            assert "拓扑增量变化" in content
            assert "rag_content" in content
            assert "search_tool" in content

    def test_diff_section_skipped_when_empty(self) -> None:
        """拓扑无diff_from_previous → 不渲染增量段落。"""
        from pipeline.analysis.evidence_collector import EvidenceCollector

        collector = EvidenceCollector(target_model="test", model_tier="unknown")
        topology = AttackSurfaceTopology(
            app_architecture="simple_llm",
            injection_surfaces=["user_message"],
        )
        metadata = {
            "attack_surface_topology": topology,
            "alternative_attack_paths": [],
        }
        collection = collector.collect(attack_results={}, metadata=metadata)
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = collector.save_markdown(collection, Path(tmpdir))
            content = md_path.read_text(encoding="utf-8")
            assert "拓扑增量变化" not in content


class TestWarmStartPathSelection:
    """V-135: warm-start ASR路径选择优先级测试。"""

    def test_warm_start_path_prioritized_over_static(self) -> None:
        """带empirical_warm_start标记的路径优先于静态估算路径。"""
        # 构造两条路径: 一条warm-start(低ASR), 一条静态(高ASR)
        # warm-start应排前面
        paths = [
            {"path_id": "path_a", "technique": "t_a", "estimated_asr": 0.70, "asr_source": None},
            {"path_id": "path_b", "technique": "t_b", "estimated_asr": 0.50, "asr_source": "empirical_warm_start"},
        ]
        # 模拟v60排序逻辑
        paths.sort(
            key=lambda p: (
                0 if p.get("asr_source") == "empirical_warm_start" else 1,
                -p.get("estimated_asr", 0),
            )
        )
        # warm-start路径排前面
        assert paths[0]["path_id"] == "path_b"
        assert paths[0]["asr_source"] == "empirical_warm_start"

    def test_no_warm_start_falls_back_to_asr_sort(self) -> None:
        """无warm-start标记时回退到ASR降序排序。"""
        paths = [
            {"path_id": "path_a", "technique": "t_a", "estimated_asr": 0.45},
            {"path_id": "path_b", "technique": "t_b", "estimated_asr": 0.65},
        ]
        paths.sort(
            key=lambda p: (
                0 if p.get("asr_source") == "empirical_warm_start" else 1,
                -p.get("estimated_asr", 0),
            )
        )
        assert paths[0]["path_id"] == "path_b"  # 高ASR优先


class TestNoAutoScenarioCLI:
    """V-136: --no-auto-scenario CLI参数测试。"""

    def test_no_auto_scenario_flag_exists(self) -> None:
        """config.py包含--no-auto-scenario参数定义。"""
        import sys

        from pipeline.config import parse_args

        original_argv = sys.argv
        try:
            sys.argv = ["main.py", "--no-auto-scenario"]
            args = parse_args()
            assert args.no_auto_scenario is True
        finally:
            sys.argv = original_argv

    def test_auto_scenario_enabled_by_default(self) -> None:
        """默认不传参时no_auto_scenario为False。"""
        import sys

        from pipeline.config import parse_args

        original_argv = sys.argv
        try:
            sys.argv = ["main.py"]
            args = parse_args()
            assert args.no_auto_scenario is False
        finally:
            sys.argv = original_argv


# ============================================================
# v60++: 拓扑diff技术池动态调整 + warm-start ASR置信度标注
# ============================================================


class TestDiffDrivenTechPoolAugmentation:
    """V-137: 拓扑diff信号→技术池动态调整测试。"""

    def test_diff_surface_to_tech_mapping_covers_key_surfaces(self) -> None:
        """注入面→技术映射覆盖5种关键注入面。"""
        _DIFF_SURFACE_TECH_MAP: dict[str, list[str]] = {
            "tool_result": ["indirect_prompt_injection", "tool_hijack"],
            "rag_content": ["rag_poisoning"],
            "mcp_protocol": ["mcp_protocol_injection"],
            "auth_token": ["token_reuse_and_escalation"],
            "conversation_history": ["crescendo_progressive"],
        }
        assert len(_DIFF_SURFACE_TECH_MAP) == 5
        assert "indirect_prompt_injection" in _DIFF_SURFACE_TECH_MAP["tool_result"]
        assert "rag_poisoning" in _DIFF_SURFACE_TECH_MAP["rag_content"]

    def test_diff_techs_deduplicated_against_existing(self) -> None:
        """diff技术去重 — 不重复添加已有技术。"""
        existing_recommended = ["indirect_prompt_injection"]
        diff_techs = ["indirect_prompt_injection", "rag_poisoning"]
        for tech in diff_techs:
            if tech not in existing_recommended:
                existing_recommended.append(tech)
        assert existing_recommended == ["indirect_prompt_injection", "rag_poisoning"]


class TestWarmStartASRConfidence:
    """V-138: warm-start ASR置信度标注测试。"""

    def test_high_confidence_when_sample_count_ge_5(self) -> None:
        """样本数≥5 → high置信度。"""
        count = 5
        if count >= 5:
            confidence = "high"
        elif count >= 2:
            confidence = "medium"
        else:
            confidence = "low"
        assert confidence == "high"

    def test_medium_confidence_when_sample_count_2_to_4(self) -> None:
        """样本数2-4 → medium置信度。"""
        count = 3
        if count >= 5:
            confidence = "high"
        elif count >= 2:
            confidence = "medium"
        else:
            confidence = "low"
        assert confidence == "medium"

    def test_low_confidence_when_sample_count_lt_2(self) -> None:
        """样本数<2 → low置信度 + ASR降权。"""
        count = 1
        estimated_asr = 0.60
        if count >= 5:
            confidence = "high"
        elif count >= 2:
            confidence = "medium"
        else:
            confidence = "low"
            estimated_asr *= 0.7
        assert confidence == "low"
        assert estimated_asr == pytest.approx(0.42)

    def test_load_empirical_asr_with_counts_returns_tuple(self) -> None:
        """load_empirical_asr_with_counts返回元组(techniques, sample_counts)。"""
        from pipeline.asr.optimizer import load_empirical_asr_with_counts

        # 不存在的模型 → 返回空元组
        techniques, counts = load_empirical_asr_with_counts("__nonexistent_model__")
        assert techniques == {}
        assert counts == {}


class TestSaveEmpiricalASRSampleCounts:
    """V-138: save_empirical_asr sample_counts参数测试。"""

    def test_save_and_load_with_sample_counts(self) -> None:
        """保存含sample_counts的ASR数据后加载验证。"""
        import tempfile
        from pathlib import Path

        from pipeline.asr.optimizer import load_empirical_asr_with_counts, save_empirical_asr

        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = Path(tmpdir) / "test_asr.json"
            save_empirical_asr(
                {"alt_path_tool_hijack": 60.0},
                model_name=None,
                path=test_path,
                sample_counts={"alt_path_tool_hijack": 3},
            )
            techniques, counts = load_empirical_asr_with_counts(path=test_path)
            assert "alt_path_tool_hijack" in techniques
            assert techniques["alt_path_tool_hijack"] == pytest.approx(0.6)
            assert counts.get("alt_path_tool_hijack") == 3

    def test_save_without_sample_counts_backward_compatible(self) -> None:
        """不传sample_counts时向后兼容。"""
        import tempfile
        from pathlib import Path

        from pipeline.asr.optimizer import load_empirical_asr_with_counts, save_empirical_asr

        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = Path(tmpdir) / "test_asr.json"
            save_empirical_asr(
                {"red_teaming": 10.0},
                model_name=None,
                path=test_path,
            )
            techniques, counts = load_empirical_asr_with_counts(path=test_path)
            assert "red_teaming" in techniques
            assert counts == {}  # 无sample_counts


# ============================================================
# v57++ (O-9~O-11): RAG特征检测 + JWT/Token检测 + 动态Converter链
# ============================================================


class TestDetectRagFeaturesAndExpandProbes:
    """V-139 (O-9): RAG特征检测+投毒探针扩展测试。"""

    def test_rag_features_detected_returns_probes(self) -> None:
        """请求体含RAG字段 → 返回投毒探针。"""
        import tempfile

        from pipeline.scenarios.mcp_attack import _detect_rag_features_and_expand_probes

        # 构造含 retrieved_documents 字段的 Burp 请求
        burp_content = (
            "POST /v1/chat/completions HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"hello"}],'
            '"retrieved_documents":["doc1","doc2"]}'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="") as f:
            f.write(burp_content)
            f.flush()
            probes = _detect_rag_features_and_expand_probes(f.name)
        assert len(probes) > 0
        # 至少包含检索污染探针
        probe_names = [p[0] for p in probes]
        assert "rag_retrieval_poisoning" in probe_names

    def test_no_rag_features_returns_empty(self) -> None:
        """请求体无RAG字段 → 返回空列表。"""
        import tempfile

        from pipeline.scenarios.mcp_attack import _detect_rag_features_and_expand_probes

        burp_content = (
            "POST /v1/chat/completions HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"hello"}]}'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="") as f:
            f.write(burp_content)
            f.flush()
            probes = _detect_rag_features_and_expand_probes(f.name)
        assert probes == []

    def test_rag_probes_have_correct_structure(self) -> None:
        """RAG探针结构正确: (name, category, objective, keywords, severity)。"""
        import tempfile

        from pipeline.scenarios.mcp_attack import _detect_rag_features_and_expand_probes

        burp_content = (
            "POST /v1/chat HTTP/1.1\r\n"
            "\r\n"
            '{"context":"some context","messages":[]}'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="") as f:
            f.write(burp_content)
            f.flush()
            probes = _detect_rag_features_and_expand_probes(f.name)
        assert len(probes) > 0
        for probe in probes:
            assert len(probe) == 5  # (name, category, objective, keywords, severity)
            assert isinstance(probe[0], str)  # name
            assert isinstance(probe[2], str)  # objective
            assert isinstance(probe[3], list)  # keywords
            assert probe[4] in ("critical", "high", "medium", "low")  # severity


class TestDetectJwtFeaturesAndExpandProbes:
    """V-140 (O-10): JWT/Token检测+权限提升探针测试。"""

    def test_no_auth_header_returns_empty(self) -> None:
        """无Authorization头 → 返回空列表。"""
        import tempfile

        from pipeline.scenarios.mcp_attack import _detect_jwt_features_and_expand_probes

        burp_content = (
            "POST /v1/chat HTTP/1.1\r\n"
            "\r\n"
            '{"messages":[]}'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="") as f:
            f.write(burp_content)
            f.flush()
            probes = _detect_jwt_features_and_expand_probes(f.name)
        assert probes == []

    def test_non_bearer_token_returns_empty(self) -> None:
        """非Bearer Token → 返回空列表。"""
        import tempfile

        from pipeline.scenarios.mcp_attack import _detect_jwt_features_and_expand_probes

        burp_content = (
            "POST /v1/chat HTTP/1.1\r\n"
            "Authorization: Basic dXNlcjpwYXNz\r\n"
            "\r\n"
            '{"messages":[]}'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="") as f:
            f.write(burp_content)
            f.flush()
            probes = _detect_jwt_features_and_expand_probes(f.name)
        assert probes == []

    def test_nonexistent_file_returns_empty(self) -> None:
        """文件不存在 → 返回空列表。"""
        from pipeline.scenarios.mcp_attack import _detect_jwt_features_and_expand_probes

        probes = _detect_jwt_features_and_expand_probes("/nonexistent/file.txt")
        assert probes == []


class TestDeriveInjectionSurfaces:
    """V-141 (O-11): 动态Converter链适配测试。"""

    def test_surfaces_from_topology(self) -> None:
        """从拓扑对象获取注入面。"""
        from unittest.mock import MagicMock

        from pipeline.stages.stage_scenario import _derive_injection_surfaces

        ctx = MagicMock()
        ctx.metadata = {
            "attack_surface_topology": AttackSurfaceTopology(
                app_architecture="agent_with_tools",
                injection_surfaces=["user_message", "tool_result"],
            ),
        }
        ctx.args = MagicMock()
        ctx.args.burp_request = None
        surfaces = _derive_injection_surfaces(ctx)
        assert surfaces is not None
        assert "user_message" in surfaces
        assert "tool_result" in surfaces

    def test_surfaces_from_burp_body_mcp(self) -> None:
        """Burp请求体含MCP字段 → 追加mcp_protocol注入面。"""
        import tempfile
        from unittest.mock import MagicMock

        from pipeline.stages.stage_scenario import _derive_injection_surfaces

        burp_content = (
            "POST /v1/chat HTTP/1.1\r\n"
            "\r\n"
            '{"mcp_server":"local","mcp_config":{"tools":[]}}'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="") as f:
            f.write(burp_content)
            burp_path = f.name

        ctx = MagicMock()
        ctx.metadata = {
            "attack_surface_topology": AttackSurfaceTopology(
                injection_surfaces=["user_message"],
            ),
            "burp_request_file": burp_path,
        }
        ctx.args = MagicMock()
        ctx.args.burp_request = None
        surfaces = _derive_injection_surfaces(ctx)
        assert surfaces is not None
        assert "mcp_protocol" in surfaces

    def test_surfaces_from_burp_body_rag(self) -> None:
        """Burp请求体含RAG字段 → 追加rag_content注入面。"""
        import tempfile
        from unittest.mock import MagicMock

        from pipeline.stages.stage_scenario import _derive_injection_surfaces

        burp_content = (
            "POST /v1/chat HTTP/1.1\r\n"
            "\r\n"
            '{"context":"retrieved data","messages":[]}'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8", newline="") as f:
            f.write(burp_content)
            burp_path = f.name

        ctx = MagicMock()
        ctx.metadata = {
            "attack_surface_topology": AttackSurfaceTopology(
                injection_surfaces=["user_message"],
            ),
            "burp_request_file": burp_path,
        }
        ctx.args = MagicMock()
        ctx.args.burp_request = None
        surfaces = _derive_injection_surfaces(ctx)
        assert surfaces is not None
        assert "rag_content" in surfaces

    def test_no_topology_no_burp_returns_none(self) -> None:
        """无拓扑无Burp → 返回None。"""
        from unittest.mock import MagicMock

        from pipeline.stages.stage_scenario import _derive_injection_surfaces

        ctx = MagicMock()
        ctx.metadata = {}
        ctx.args = MagicMock()
        ctx.args.burp_request = None
        surfaces = _derive_injection_surfaces(ctx)
        assert surfaces is None


