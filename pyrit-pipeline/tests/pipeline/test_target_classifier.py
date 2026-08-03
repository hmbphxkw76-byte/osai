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

    def test_load_owasp_local_default_true(self) -> None:
        """--load-owasp-local 默认为 True。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py"]):
            args = parse_args()
            assert args.load_owasp_local is True

    def test_no_owasp_local_disables(self) -> None:
        """--no-owasp-local 禁用 OWASP 加载。"""
        from pipeline.config import parse_args

        with patch("sys.argv", ["main.py", "--no-owasp-local"]):
            args = parse_args()
            assert args.load_owasp_local is False

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
