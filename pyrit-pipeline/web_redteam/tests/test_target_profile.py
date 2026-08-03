# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""TargetProfile 单元测试。.

测试 YAML 加载、字段解析、环境变量展开、校验逻辑。
"""

import os
from pathlib import Path

import pytest

from web_redteam.targets.target_profile import TargetProfile

# ── 测试数据 ──

SAME_DOMAIN_YAML = r"""
target:
  name: "test_portal"
  description: "Test same-domain target"
  type: "web_chat"

auth:
  type: "same_domain"
  login_url: "https://test.example.com/login"
  target_url: "https://test.example.com/chat"
  same_domain:
    detection:
      - strategy: "url_pattern"
        pattern: 'test\.example\.com/chat'
      - strategy: "dom_element"
        selector: ".chat-container"
        timeout_seconds: 120
      - strategy: "cookie_presence"
        cookie_names: ["session_id"]
        domain: "test.example.com"
  auto_fill:
    "#username": "${TEST_USER}"
    "#password": "${TEST_PASS}"
  human_assisted_steps:
    - "captcha"
    - "slider"

interaction:
  input:
    selector: "textarea#chat-input"
    type: "textarea"
  send:
    selector: "button.send-btn"
  response:
    selector: "div.ai-message"
    wait_strategy: "new_element"
    stability_threshold_ms: 1500
    loading_selector: ".typing"
  extraction:
    text_selector: "p.text"
    wait_for_images: false

attack_defaults:
  attack_type: "red_teaming"
  max_turns: 5
  objective: "Test objective"
"""

CROSS_DOMAIN_YAML = r"""
target:
  name: "test_sso"
  description: "Test cross-domain target"
  type: "web_chat"

auth:
  type: "cross_domain"
  login_url: "https://app.test.com/login"
  target_url: "https://app.test.com/ai-chat"
  cross_domain:
    redirect_chain:
      - domain: "app.test.com"
        auth_action: "redirect_to_idp"
      - domain: "sso.idp.test.com"
        auth_action: "login_form"
        human_steps: ["captcha", "otp"]
      - domain: "app.test.com"
        auth_action: "callback"
    detection:
      - strategy: "url_pattern"
        pattern: 'app\.test\.com/ai-chat'
      - strategy: "dom_element"
        selector: ".chat-window"
  auto_fill:
    "#username": "static_user"
  human_assisted_steps:
    - "otp"

interaction:
  input:
    selector: "textarea.chat-input"
  send:
    selector: "button.btn-send"
  response:
    selector: "div.bot-response"

attack_defaults:
  attack_type: "crescendo"
  max_turns: 8
"""


class TestSameDomainProfile:
    """同域认证 Profile 测试。."""

    def test_load_same_domain_profile(self, tmp_path: Path) -> None:
        """测试加载同域 Profile。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)

        assert profile.target.name == "test_portal"
        assert profile.target.description == "Test same-domain target"
        assert profile.target.type == "web_chat"

        assert profile.auth.type == "same_domain"
        assert profile.auth.login_url == "https://test.example.com/login"
        assert profile.auth.target_url == "https://test.example.com/chat"

    def test_detection_configs(self, tmp_path: Path) -> None:
        """测试检测策略解析。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)
        configs = profile.get_detection_configs()

        assert len(configs) == 3
        assert configs[0].strategy == "url_pattern"
        assert configs[0].pattern == "test\\.example\\.com/chat"

        assert configs[1].strategy == "dom_element"
        assert configs[1].selector == ".chat-container"
        assert configs[1].timeout_seconds == 120

        assert configs[2].strategy == "cookie_presence"
        assert configs[2].cookie_names == ["session_id"]
        assert configs[2].domain == "test.example.com"

    def test_interaction_config(self, tmp_path: Path) -> None:
        """测试交互配置解析。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)

        assert profile.interaction.input.selector == "textarea#chat-input"
        assert profile.interaction.input.type == "textarea"
        assert profile.interaction.send.selector == "button.send-btn"
        assert profile.interaction.response.selector == "div.ai-message"
        assert profile.interaction.response.wait_strategy == "new_element"
        assert profile.interaction.response.stability_threshold_ms == 1500
        assert profile.interaction.response.loading_selector == ".typing"
        assert profile.interaction.extraction.text_selector == "p.text"

    def test_attack_defaults(self, tmp_path: Path) -> None:
        """测试攻击默认参数。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)

        assert profile.attack_defaults.attack_type == "red_teaming"
        assert profile.attack_defaults.max_turns == 5
        assert profile.attack_defaults.objective == "Test objective"

    def test_human_assisted_steps(self, tmp_path: Path) -> None:
        """测试人工辅助步骤。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)

        assert "captcha" in profile.auth.human_assisted_steps
        assert "slider" in profile.auth.human_assisted_steps

    def test_env_var_expansion(self, tmp_path: Path) -> None:
        """测试环境变量展开。."""
        os.environ["TEST_USER"] = "env_user_123"
        os.environ["TEST_PASS"] = "env_pass_456"
        try:
            yaml_file = tmp_path / "test.yaml"
            yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")

            profile = TargetProfile.from_yaml_file(yaml_file)

            assert profile.auth.auto_fill["#username"] == "env_user_123"
            assert profile.auth.auto_fill["#password"] == "env_pass_456"
        finally:
            del os.environ["TEST_USER"]
            del os.environ["TEST_PASS"]


class TestCrossDomainProfile:
    """跨域认证 Profile 测试。."""

    def test_load_cross_domain_profile(self, tmp_path: Path) -> None:
        """测试加载跨域 Profile。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(CROSS_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)

        assert profile.target.name == "test_sso"
        assert profile.auth.type == "cross_domain"

    def test_redirect_chain(self, tmp_path: Path) -> None:
        """测试重定向链解析。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(CROSS_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)
        chain = profile.auth.cross_domain.redirect_chain

        assert len(chain) == 3
        assert chain[0].domain == "app.test.com"
        assert chain[0].auth_action == "redirect_to_idp"
        assert chain[1].domain == "sso.idp.test.com"
        assert chain[1].auth_action == "login_form"
        assert "captcha" in chain[1].human_steps
        assert "otp" in chain[1].human_steps
        assert chain[2].domain == "app.test.com"
        assert chain[2].auth_action == "callback"

    def test_cross_domain_detection(self, tmp_path: Path) -> None:
        """测试跨域检测策略。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(CROSS_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)
        configs = profile.get_detection_configs()

        assert len(configs) == 2
        assert configs[0].strategy == "url_pattern"
        assert configs[1].strategy == "dom_element"

    def test_static_auto_fill(self, tmp_path: Path) -> None:
        """测试静态值 (非环境变量) 的 auto_fill。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(CROSS_DOMAIN_YAML, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)

        assert profile.auth.auto_fill["#username"] == "static_user"


class TestProfileValidation:
    """Profile 校验测试。."""

    def test_missing_login_url_raises(self, tmp_path: Path) -> None:
        """测试缺少 login_url 时抛出异常 (same_domain 需要 login_url)。."""
        yaml_content = """
target:
  name: "test"
auth:
  type: "same_domain"
  target_url: "https://example.com/chat"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        with pytest.raises(ValueError, match="login_url is required"):
            TargetProfile.from_yaml_file(yaml_file)

    def test_missing_target_url_raises(self, tmp_path: Path) -> None:
        """测试缺少 target_url 时抛出异常。."""
        yaml_content = """
target:
  name: "test"
auth:
  type: "same_domain"
  login_url: "https://example.com/login"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        with pytest.raises(ValueError, match="target_url is required"):
            TargetProfile.from_yaml_file(yaml_file)

    def test_invalid_auth_type_raises(self, tmp_path: Path) -> None:
        """测试无效 auth type 时抛出异常。."""
        yaml_content = """
target:
  name: "test"
auth:
  type: "invalid_type"
  login_url: "https://example.com/login"
  target_url: "https://example.com/chat"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        with pytest.raises(ValueError, match="auth.type must be"):
            TargetProfile.from_yaml_file(yaml_file)

    def test_auto_type_no_login_url_required(self, tmp_path: Path) -> None:
        """测试 auto 类型不需要 login_url。."""
        yaml_content = """
target:
  name: "test_auto"
auth:
  type: "auto"
  target_url: "https://example.com/chat"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)
        assert profile.auth.type == "auto"
        assert profile.auth.login_url == ""
        assert profile.auth.target_url == "https://example.com/chat"

    def test_none_type_no_login_url_required(self, tmp_path: Path) -> None:
        """测试 none 类型不需要 login_url。."""
        yaml_content = """
target:
  name: "test_none"
auth:
  type: "none"
  target_url: "https://example.com/open"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)
        assert profile.auth.type == "none"
        assert profile.auth.login_url == ""

    def test_none_type_get_detection_configs_empty(self, tmp_path: Path) -> None:
        """测试 none 类型返回空检测策略列表。."""
        yaml_content = """
target:
  name: "test_none"
auth:
  type: "none"
  target_url: "https://example.com/open"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)
        configs = profile.get_detection_configs()
        assert configs == []

    def test_auto_type_get_detection_configs_empty(self, tmp_path: Path) -> None:
        """测试 auto 类型返回空检测策略列表 (由 AuthProbe 动态生成)。."""
        yaml_content = """
target:
  name: "test_auto"
auth:
  type: "auto"
  target_url: "https://example.com/chat"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)
        configs = profile.get_detection_configs()
        assert configs == []

    def test_example_profiles_load(self) -> None:
        """测试示例 Profile 文件能正确加载。."""
        same_domain_path = Path("web_redteam/targets/same_domain/example_portal.yaml")
        cross_domain_path = Path("web_redteam/targets/cross_domain/example_sso.yaml")

        if same_domain_path.exists():
            profile = TargetProfile.from_yaml_file(same_domain_path)
            assert profile.target.name == "example_portal"
            assert profile.auth.type == "same_domain"

        if cross_domain_path.exists():
            profile = TargetProfile.from_yaml_file(cross_domain_path)
            assert profile.target.name == "example_sso"
            assert profile.auth.type == "cross_domain"

    def test_auto_example_profile_loads(self) -> None:
        """测试 auto 示例 Profile 能正确加载。."""
        auto_path = Path("web_redteam/targets/same_domain/example_auto_detect.yaml")
        if auto_path.exists():
            profile = TargetProfile.from_yaml_file(auto_path)
            assert profile.auth.type == "auto"
            assert profile.auth.target_url == "https://example.com/chat"

    def test_none_example_profile_loads(self) -> None:
        """测试 none 示例 Profile 能正确加载。."""
        none_path = Path("web_redteam/targets/same_domain/example_open_target.yaml")
        if none_path.exists():
            profile = TargetProfile.from_yaml_file(none_path)
            assert profile.auth.type == "none"
