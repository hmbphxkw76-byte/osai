# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""动态 Profile 生成器单元测试。.

测试从 URL 自动生成 TargetProfile 的各种场景。
"""

import pytest

from web_bridge.targets.dynamic_profile import (
    DEFAULT_INPUT_SELECTOR,
    DEFAULT_RESPONSE_SELECTOR,
    DEFAULT_SEND_SELECTOR,
    create_profile_from_url,
)


class TestCreateProfileFromUrl:
    """create_profile_from_url 测试。."""

    def test_basic_url(self) -> None:
        """测试基本 URL 生成 Profile。."""
        profile = create_profile_from_url("https://example.com/chat")

        assert profile.auth.type == "auto"
        assert profile.auth.target_url == "https://example.com/chat"
        assert profile.auth.login_url == ""
        assert profile.target.name == "auto_example_com"
        assert profile.target.type == "web_chat"

    def test_localhost_url(self) -> None:
        """测试 localhost URL。."""
        profile = create_profile_from_url("http://localhost:5000")

        assert profile.auth.target_url == "http://localhost:5000"
        assert profile.target.name == "auto_localhost_5000"

    def test_port_in_url(self) -> None:
        """测试带端口的 URL。."""
        profile = create_profile_from_url("https://app.example.com:8080/chat")

        assert profile.auth.target_url == "https://app.example.com:8080/chat"
        assert "app_example_com" in profile.target.name

    def test_default_interaction_selectors(self) -> None:
        """测试默认交互选择器。."""
        profile = create_profile_from_url("https://example.com/chat")

        assert profile.interaction.input.selector == DEFAULT_INPUT_SELECTOR
        assert profile.interaction.send.selector == DEFAULT_SEND_SELECTOR
        assert profile.interaction.response.selector == DEFAULT_RESPONSE_SELECTOR
        assert profile.interaction.response.wait_strategy == "new_element"

    def test_default_attack_type(self) -> None:
        """测试默认攻击类型。."""
        profile = create_profile_from_url("https://example.com/chat")

        assert profile.attack_defaults.attack_type == "prompt_sending"
        assert profile.attack_defaults.max_turns == 1

    def test_custom_attack_type(self) -> None:
        """测试自定义攻击类型。."""
        profile = create_profile_from_url(
            "https://example.com/chat",
            attack_type="red_teaming",
            max_turns=10,
            objective="Extract system prompt",
        )

        assert profile.attack_defaults.attack_type == "red_teaming"
        assert profile.attack_defaults.max_turns == 10
        assert profile.attack_defaults.objective == "Extract system prompt"

    def test_detection_configs_empty(self) -> None:
        """测试 auto 模式返回空检测策略。."""
        profile = create_profile_from_url("https://example.com/chat")

        configs = profile.get_detection_configs()
        assert configs == []

    def test_description_contains_url(self) -> None:
        """测试描述包含 URL。."""
        profile = create_profile_from_url("https://example.com/chat")

        assert "https://example.com/chat" in profile.target.description


class TestConfigArgParsing:
    """config.py 参数解析测试。."""

    def test_target_url_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试 --target-url 模式。."""
        import sys

        from web_bridge.config import parse_args

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "web_bridge",
                "--target-url",
                "https://example.com/chat",
                "--attack-type",
                "prompt_sending",
            ],
        )
        args = parse_args()

        assert args.target_url == "https://example.com/chat"
        assert args.target_profile is None
        assert args.attack_type == "prompt_sending"

    def test_target_profile_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试 --target-profile 模式。."""
        import sys

        from web_bridge.config import parse_args

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "web_bridge",
                "--target-profile",
                "web_bridge/targets/same_domain/example_portal.yaml",
            ],
        )
        args = parse_args()

        assert args.target_profile == "web_bridge/targets/same_domain/example_portal.yaml"
        assert args.target_url is None

    def test_env_var_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试 web_bridge_TARGET_URL 环境变量回退。."""
        import sys

        from web_bridge.config import parse_args

        monkeypatch.setenv("web_bridge_TARGET_URL", "https://env.example.com/chat")
        monkeypatch.setattr(sys, "argv", ["web_bridge", "--attack-type", "prompt_sending"])
        args = parse_args()

        assert args.target_url == "https://env.example.com/chat"
        assert args.target_profile is None

    def test_mutual_exclusion_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试同时指定两个参数报错。."""
        import sys

        from web_bridge.config import parse_args

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "web_bridge",
                "--target-profile",
                "some.yaml",
                "--target-url",
                "https://example.com",
            ],
        )

        with pytest.raises(SystemExit):
            parse_args()

    def test_no_target_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试不指定任何目标报错。."""
        import sys

        from web_bridge.config import parse_args

        monkeypatch.delenv("web_bridge_TARGET_URL", raising=False)
        monkeypatch.setattr(sys, "argv", ["web_bridge", "--attack-type", "prompt_sending"])

        with pytest.raises(SystemExit):
            parse_args()
