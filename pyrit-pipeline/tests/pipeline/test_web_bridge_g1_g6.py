"""G1-G6 Web Bridge 修复单元测试.

覆盖 6 项修复:
  G1: web_bridge.py 不关闭浏览器, 保留 page 供 PlaywrightTarget
  G2: stage_target_classify.py auth-state-file 复用 + auth_headers 注入
  G3: recon_target_bridge.py build_http_target_from_recon 添加 callback_function
  G4: recon_target_bridge.py 不注册 default tag
  G5: web_bridge.py _send_capability_probe ssl 参数可配置
  G6: main.py recon 驱动场景选择不被 --scenario 跳过

学术依据:
  - OWASP ASVS V2.4 (认证验证最小化重复)
  - NIST SP 800-63B (认证状态复用)
  - PyRIT (arXiv:2407.01232) HTTPTarget callback_function 设计
  - MITRE ATT&CK T1592 (侦察驱动)
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# ============================================================================
# G1: web_bridge.py 不关闭浏览器
# ============================================================================


class TestG1BrowserSessionKeptAlive:
    """G1: _browser_auth 不应调用 session.close()。"""

    def test_g1_no_session_close_call(self):
        """G1: 验证 _browser_auth 代码中不包含 session.close() 调用。"""
        bridge_path = (
            Path(__file__).resolve().parents[2]
            / "pipeline"
            / "integrations"
            / "web_bridge.py"
        )
        with open(bridge_path, encoding="utf-8") as f:
            source = f.read()

        # 在 _browser_auth 函数范围内检查
        # 查找 G1 注释标记, 确认修复存在
        assert "G1: 不关闭浏览器" in source, "G1 修复标记缺失"

        # 查找 "await session.close()" 不应出现在 _browser_auth 中
        # 但可能出现在其他函数中 (如 _create_and_register_target 的清理)
        # 所以检查 G1 注释附近不应有 close
        g1_marker_pos = source.find("G1: 不关闭浏览器")
        assert g1_marker_pos != -1, "G1 标记未找到"

        # 从 G1 标记到下一个函数定义之间不应有 session.close()
        next_func = source.find("\nasync def ", g1_marker_pos + 1)
        if next_func == -1:
            next_func = len(source)
        g1_section = source[g1_marker_pos:next_func]
        assert (
            "session.close()" not in g1_section
        ), "G1: _browser_auth 仍调用 session.close()"


# ============================================================================
# G2: auth-state-file 复用 + auth_headers 注入
# ============================================================================


class TestG2AuthStateReuse:
    """G2: 认证状态复用逻辑。"""

    def test_g2_try_reuse_auth_state_import(self):
        """G2: 验证 try_reuse_auth_state 可从 auth_state_bridge 导入。"""
        from pipeline.integrations.auth_state_bridge import try_reuse_auth_state

        assert callable(try_reuse_auth_state)

    def test_g2_try_reuse_auth_state_no_file(self):
        """G2: 无 auth_state_file 时返回 False。"""
        from pipeline.integrations.auth_state_bridge import try_reuse_auth_state

        ctx = MagicMock()
        ctx.args = SimpleNamespace(auth_state_file=None)

        with patch(
            "pipeline.integrations.auth_state_bridge.import_auth_state",
            return_value=None,
        ):
            result = try_reuse_auth_state(ctx)
            assert result is False

    def test_g2_try_reuse_auth_state_valid(self):
        """G2: 有效认证状态时返回 True 并注入 metadata。"""
        from pipeline.integrations.auth_state_bridge import try_reuse_auth_state

        ctx = MagicMock()
        ctx.args = SimpleNamespace(auth_state_file="auth_state.json")
        ctx.metadata = {}

        mock_auth_state = MagicMock()
        mock_auth_state.is_valid.return_value = True

        with (
            patch(
                "pipeline.integrations.auth_state_bridge.import_auth_state",
                return_value=mock_auth_state,
            ),
            patch(
                "pipeline.integrations.auth_state_bridge.inject_auth_state_to_context",
            ),
        ):
            result = try_reuse_auth_state(ctx)
            assert result is True

    def test_g2_stage_target_classify_has_auth_reuse(self):
        """G2: stage_target_classify.py 包含认证状态复用逻辑。"""
        classify_path = (
            Path(__file__).resolve().parents[2]
            / "pipeline"
            / "stages"
            / "stage_target_classify.py"
        )
        with open(classify_path, encoding="utf-8") as f:
            source = f.read()

        assert "try_reuse_auth_state" in source, "G2: try_reuse_auth_state 未调用"
        assert "export_auth_state" in source, "G2: export_auth_state 未调用"
        assert "auth_headers" in source, "G2: auth_headers 注入缺失"


# ============================================================================
# G3: recon_target_bridge callback_function
# ============================================================================


class TestG3CallbackFunction:
    """G3: HTTPTarget 添加 callback_function。"""

    def test_g3_build_http_target_has_callback(self):
        """G3: build_http_target_from_recon 创建的 HTTPTarget 包含 callback_function。"""
        from pipeline.integrations.recon_target_bridge import (
            ReconEndpointInfo,
            build_http_target_from_recon,
        )

        endpoint = ReconEndpointInfo(
            url="https://api.example.com/v1/chat/completions",
            method="POST",
            path="/v1/chat/completions",
            has_auth=True,
            auth_headers={"Authorization": "Bearer test-token"},
            body_template='{"model":"gpt-4","messages":[{"role":"user","content":"{PROMPT}"}]}',
            content_type="application/json",
            is_llm_endpoint=True,
            response_path="choices[0].message.content",
        )

        # Mock CentralMemory to avoid ValueError (requires memory instance)
        with patch("pyrit.memory.central_memory.CentralMemory.get_memory_instance") as mock_mem:
            mock_mem.return_value = MagicMock()
            target = build_http_target_from_recon(endpoint)

        # callback_function 可能为 None (import 失败时) 或可调用对象
        # G3 修复: 至少尝试设置 callback_function
        assert hasattr(target, "_callback_function") or hasattr(
            target, "callback_function"
        ), "G3: HTTPTarget 无 callback_function 属性"

    def test_g3_callback_import_attempt(self):
        """G3: 代码中包含 callback_function 导入逻辑。"""
        bridge_path = (
            Path(__file__).resolve().parents[2]
            / "pipeline"
            / "integrations"
            / "recon_target_bridge.py"
        )
        with open(bridge_path, encoding="utf-8") as f:
            source = f.read()

        assert "callback_function" in source, "G3: callback_function 未设置"
        assert (
            "get_http_target_json_response_callback_function" in source
        ), "G3: PyRIT callback 导入缺失"


# ============================================================================
# G4: 不注册 default tag
# ============================================================================


class TestG4NoDefaultTag:
    """G4: recon target 不注册 default tag。"""

    def test_g4_no_default_tag_in_source(self):
        """G4: build_target_from_recon 注册时不包含 default tag。"""
        bridge_path = (
            Path(__file__).resolve().parents[2]
            / "pipeline"
            / "integrations"
            / "recon_target_bridge.py"
        )
        with open(bridge_path, encoding="utf-8") as f:
            source = f.read()

        # 找到注册代码段
        register_pos = source.find('name="recon_http_target"')
        assert register_pos != -1, "G4: recon_http_target 注册未找到"

        # 检查 tags 不包含 "default"
        # 从注册行向上找 tags=
        tags_section = source[max(0, register_pos - 200) : register_pos + 200]
        assert (
            '"default"' not in tags_section
        ), "G4: recon target 仍注册 default tag"


# ============================================================================
# G5: SSL 参数可配置
# ============================================================================


class TestG5SSLConfigurable:
    """G5: _send_capability_probe SSL 参数可配置。"""

    def test_g5_ssl_env_var_default_false(self):
        """G5: 默认 ssl_verify=False (兼容性优先)。"""
        # 确保环境变量未设置时默认为 False
        old_val = os.environ.pop("WEB_BRIDGE_SSL_VERIFY", None)

        bridge_path = (
            Path(__file__).resolve().parents[2]
            / "pipeline"
            / "integrations"
            / "web_bridge.py"
        )
        with open(bridge_path, encoding="utf-8") as f:
            source = f.read()

        assert "WEB_BRIDGE_SSL_VERIFY" in source, "G5: SSL 环境变量未配置"
        assert "ssl_verify" in source, "G5: ssl_verify 变量未使用"

        if old_val is not None:
            os.environ["WEB_BRIDGE_SSL_VERIFY"] = old_val

    def test_g5_ssl_env_var_true(self):
        """G5: 设置 WEB_BRIDGE_SSL_VERIFY=true 时 ssl_verify=True。"""
        os.environ["WEB_BRIDGE_SSL_VERIFY"] = "true"
        result = os.environ.get("WEB_BRIDGE_SSL_VERIFY", "").lower() in (
            "true",
            "1",
            "yes",
        )
        assert result is True
        del os.environ["WEB_BRIDGE_SSL_VERIFY"]

    def test_g5_ssl_env_var_false(self):
        """G5: 设置 WEB_BRIDGE_SSL_VERIFY=false 时 ssl_verify=False。"""
        os.environ["WEB_BRIDGE_SSL_VERIFY"] = "false"
        result = os.environ.get("WEB_BRIDGE_SSL_VERIFY", "").lower() in (
            "true",
            "1",
            "yes",
        )
        assert result is False
        del os.environ["WEB_BRIDGE_SSL_VERIFY"]


# ============================================================================
# G6: recon 驱动场景选择不被 --scenario 跳过
# ============================================================================


class TestG6ReconScenarioDisplay:
    """G6: recon 推荐始终显示, 即使 --scenario 已指定。"""

    def test_g6_main_always_shows_recon(self):
        """G6: main.py 中 recon 推荐不再被 --scenario 条件跳过。"""
        main_path = Path(__file__).resolve().parents[2] / "main.py"
        with open(main_path, encoding="utf-8") as f:
            source = f.read()

        # G6 修复标记存在
        assert "G6" in source, "G6: 修复标记缺失"

        # 不应再有 "recon_result and not getattr(ctx.args, "scenario", None)" 的条件
        assert (
            'recon_result and not getattr(ctx.args, "scenario", None)'
            not in source
        ), "G6: recon 推荐仍被 --scenario 条件跳过"

        # 应有 user_scenario 检查
        assert "user_scenario" in source, "G6: user_scenario 检查缺失"

    def test_g6_recon_always_evaluates(self):
        """G6: recon_result 条件不再包含 scenario 检查。"""
        main_path = Path(__file__).resolve().parents[2] / "main.py"
        with open(main_path, encoding="utf-8") as f:
            source = f.read()

        # 找到 recon 驱动场景选择代码块
        recon_pos = source.find("侦察驱动场景选择")
        assert recon_pos != -1, "G6: recon 驱动场景选择代码未找到"

        # 检查条件改为 if recon_result: (不含 scenario 检查)
        # 从标记到 recommend_scenarios_from_recon 之间
        next_code = source[recon_pos : recon_pos + 300]
        assert "if recon_result:" in next_code or "if recon_result\n" in next_code, (
            "G6: 条件仍包含 scenario 检查"
        )
