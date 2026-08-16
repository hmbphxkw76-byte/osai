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
