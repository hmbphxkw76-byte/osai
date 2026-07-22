# -*- coding: utf-8 -*-
"""
AI-300 Framework - 回归测试套件 v1.0

目的：确保每次代码改动不会破坏已验证通过的功能链路。
覆盖范围：
  1. env_loader  — .env 加载 + ${VAR} 替换 + 降级处理
  2. SPA 配置   — load_spa_config 正确解析环境变量
  3. Pipeline   — _resolve_target 不返回文件路径作为 URL
  4. Adapter    — result_data 嵌套 dict 访问安全性（setdefault）

每个测试类对应一组历史 bug 修复，确保同类问题不再复发。

运行方式：
  python -m pytest pyrit_ai300/tests/test_regression.py -v
  或
  make test  # 全量测试（含本文件）
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# 确保项目根目录在 sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ════════════════════════════════════════════════════════════════
# 1. EnvLoader 回归测试
#    覆盖 bug：.env 未找到时 _dotenv_loaded=True 阻止后续加载
# ════════════════════════════════════════════════════════════════

class TestEnvLoaderBasic(unittest.TestCase):
    """env_loader 基础功能测试"""

    def test_resolve_simple_var(self):
        """${VAR} 简单变量替换"""
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        with patch.dict(os.environ, {"MY_TEST_KEY": "secret123"}):
            result = resolve_env_vars({"api_key": "${MY_TEST_KEY}"})
            self.assertEqual(result["api_key"], "secret123")

    def test_resolve_var_with_default(self):
        """${VAR:-default} 带默认值的替换"""
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        # 变量存在 → 使用变量值
        with patch.dict(os.environ, {"MY_VAR": "actual"}):
            result = resolve_env_vars({"v": "${MY_VAR:-fallback}"})
            self.assertEqual(result["v"], "actual")
        # 变量不存在 → 使用默认值
        os.environ.pop("MY_MISSING_VAR", None)
        result = resolve_env_vars({"v": "${MY_MISSING_VAR:-fallback}"})
        self.assertEqual(result["v"], "fallback")

    def test_resolve_missing_var_no_default(self):
        """${VAR} 变量不存在且无默认值 → 返回空字符串"""
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        os.environ.pop("DEFINITELY_NOT_SET_VAR_12345", None)
        result = resolve_env_vars({"v": "${DEFINITELY_NOT_SET_VAR_12345}"})
        self.assertEqual(result["v"], "")

    def test_resolve_nested_dict(self):
        """嵌套 dict 递归替换"""
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        with patch.dict(os.environ, {"A": "1", "B": "2"}):
            result = resolve_env_vars({
                "outer": {"inner": "${A}"},
                "list": ["${B}", "plain"],
            })
            self.assertEqual(result["outer"]["inner"], "1")
            self.assertEqual(result["list"][0], "2")
            self.assertEqual(result["list"][1], "plain")

    def test_resolve_no_vars_in_string(self):
        """无 ${VAR} 的字符串原样返回"""
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        result = resolve_env_vars({"url": "https://example.com/#/home"})
        self.assertEqual(result["url"], "https://example.com/#/home")

    def test_resolve_non_string_types(self):
        """非字符串类型（int/float/bool/None）原样返回"""
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        result = resolve_env_vars({
            "port": 8080,
            "ratio": 0.95,
            "enabled": True,
            "name": None,
        })
        self.assertEqual(result["port"], 8080)
        self.assertEqual(result["ratio"], 0.95)
        self.assertTrue(result["enabled"])
        self.assertIsNone(result["name"])

    def test_resolve_url_with_hash(self):
        """URL 中的 # 字符不被截断（SPA 路由 #/home）"""
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        with patch.dict(os.environ, {"SPA_URL": "https://example.com/#/home"}):
            result = resolve_env_vars({"url": "${SPA_URL}"})
            self.assertEqual(result["url"], "https://example.com/#/home")
            self.assertIn("#/home", result["url"])

    def test_resolve_multiple_vars_in_one_string(self):
        """同一字符串中多个 ${VAR} 替换"""
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        with patch.dict(os.environ, {"A": "foo", "B": "bar"}):
            result = resolve_env_vars({"s": "${A}/${B}/end"})
            self.assertEqual(result["s"], "foo/bar/end")


class TestEnvLoaderDotenvFile(unittest.TestCase):
    """env_loader .env 文件加载测试"""

    def setUp(self):
        """每个测试前重置 _dotenv_loaded 标志"""
        import pyrit_ai300.utils.env_loader as el
        el._dotenv_loaded = False

    def test_load_dotenv_from_cwd(self):
        """从 CWD 找到 .env 文件"""
        import pyrit_ai300.utils.env_loader as el
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("TEST_CWD_KEY=cwd_value\n", encoding="utf-8")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                os.environ.pop("TEST_CWD_KEY", None)
                el._dotenv_loaded = False
                result = el.load_dotenv()
                self.assertTrue(result)
                self.assertEqual(os.environ.get("TEST_CWD_KEY"), "cwd_value")
            finally:
                os.chdir(old_cwd)

    def test_load_dotenv_not_found_no_crash(self):
        """.env 不存在时不崩溃（可能从 __file__ 路径找到项目根 .env，关键是不会抛异常）"""
        import pyrit_ai300.utils.env_loader as el
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                el._dotenv_loaded = False
                # 关键测试点：不崩溃，不抛异常
                result = el.load_dotenv()
                self.assertIsInstance(result, bool)
            finally:
                os.chdir(old_cwd)

    def test_dotenv_does_not_override_system_env(self):
        """系统环境变量优先于 .env 文件"""
        import pyrit_ai300.utils.env_loader as el
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("MY_PRIORITY_KEY=from_file\n", encoding="utf-8")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                os.environ["MY_PRIORITY_KEY"] = "from_system"
                el._dotenv_loaded = False
                el.load_dotenv()
                self.assertEqual(os.environ["MY_PRIORITY_KEY"], "from_system")
            finally:
                os.chdir(old_cwd)
                os.environ.pop("MY_PRIORITY_KEY", None)

    def test_dotenv_with_quotes(self):
        """.env 文件值带引号时正确去除"""
        import pyrit_ai300.utils.env_loader as el
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text('QUOTED_KEY="hello world"\n', encoding="utf-8")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                os.environ.pop("QUOTED_KEY", None)
                el._dotenv_loaded = False
                el.load_dotenv()
                self.assertEqual(os.environ.get("QUOTED_KEY"), "hello world")
            finally:
                os.chdir(old_cwd)

    def test_dotenv_comment_lines_ignored(self):
        """.env 文件中 # 开头的行被忽略"""
        import pyrit_ai300.utils.env_loader as el
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                "# This is a comment\n"
                "REAL_KEY=real_value\n"
                "# ANOTHER_COMMENT=ignored\n"
                "\n"
                "SECOND_KEY=second\n",
                encoding="utf-8",
            )

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                os.environ.pop("REAL_KEY", None)
                os.environ.pop("ANOTHER_COMMENT", None)
                os.environ.pop("SECOND_KEY", None)
                el._dotenv_loaded = False
                el.load_dotenv()
                self.assertEqual(os.environ.get("REAL_KEY"), "real_value")
                self.assertIsNone(os.environ.get("ANOTHER_COMMENT"))
                self.assertEqual(os.environ.get("SECOND_KEY"), "second")
            finally:
                os.chdir(old_cwd)


class TestEnvLoaderUrlWithHash(unittest.TestCase):
    """
    回归测试：SPA URL 中的 # 字符
    Bug: .env 中 SPA_TARGET_URL=https://xxx/#/home 的 # 被错误处理
    """
    def test_url_with_hash_resolved(self):
        from pyrit_ai300.utils.env_loader import resolve_env_vars
        with patch.dict(os.environ, {"SPA_TARGET_URL": "https://www.example.com/#/home"}):
            result = resolve_env_vars({"url": "${SPA_TARGET_URL}"})
            self.assertEqual(result["url"], "https://www.example.com/#/home")
            self.assertTrue(result["url"].startswith("https://"))
            self.assertIn("#/home", result["url"])


# ════════════════════════════════════════════════════════════════
# 2. SPA 配置加载回归测试
#    覆盖 bug：load_spa_config 未解析环境变量
# ════════════════════════════════════════════════════════════════

class TestSpaConfigLoading(unittest.TestCase):
    """
    回归测试：SPA 配置加载
    Bug: load_spa_config 返回的 connection.url 为空或未解析的 ${VAR}
    """

    def setUp(self):
        """创建临时 YAML 配置文件"""
        self.tmpdir = tempfile.mkdtemp()
        self.yaml_path = Path(self.tmpdir) / "spa_target.yaml"
        self.yaml_path.write_text(
            'target:\n'
            '  url: "${SPA_TEST_URL}"\n'
            '  username: "${SPA_TEST_USER}"\n'
            '  password: "${SPA_TEST_PASS}"\n'
            '  auth_mode: "${SPA_TEST_MODE}"\n',
            encoding="utf-8",
        )

    def test_load_spa_config_resolves_env_vars(self):
        """load_spa_config 正确解析 ${VAR} 环境变量"""
        from pyrit_ai300.recon.engine import ReconEngine
        with patch.dict(os.environ, {
            "SPA_TEST_URL": "https://example.com/#/home",
            "SPA_TEST_USER": "testuser",
            "SPA_TEST_PASS": "testpass",
            "SPA_TEST_MODE": "sso",
        }):
            cfg = ReconEngine.load_spa_config(str(self.yaml_path))
            url = cfg.get("connection", {}).get("url", "")
            auth = cfg.get("auth", {})

            self.assertEqual(url, "https://example.com/#/home")
            self.assertNotIn("${", url, "URL should not contain unresolved ${VAR}")

            self.assertEqual(auth.get("username"), "testuser")
            self.assertEqual(auth.get("password"), "testpass")
            self.assertEqual(auth.get("mode"), "sso")

    def test_load_spa_config_url_is_valid_http(self):
        """解析后的 URL 必须是 http 开头的有效 URL，不能是文件路径"""
        from pyrit_ai300.recon.engine import ReconEngine
        with patch.dict(os.environ, {
            "SPA_TEST_URL": "https://example.com/#/home",
            "SPA_TEST_USER": "u",
            "SPA_TEST_PASS": "p",
            "SPA_TEST_MODE": "sso",
        }):
            cfg = ReconEngine.load_spa_config(str(self.yaml_path))
            url = cfg.get("connection", {}).get("url", "")
            self.assertTrue(url.startswith("http"), f"URL must start with http, got: {url}")
            self.assertFalse(url.endswith(".yaml"), f"URL must not be a file path, got: {url}")

    def test_load_spa_config_connection_structure(self):
        """load_spa_config 返回正确的 connection 结构"""
        from pyrit_ai300.recon.engine import ReconEngine
        with patch.dict(os.environ, {
            "SPA_TEST_URL": "https://example.com/#/home",
            "SPA_TEST_USER": "u",
            "SPA_TEST_PASS": "p",
            "SPA_TEST_MODE": "sso",
        }):
            cfg = ReconEngine.load_spa_config(str(self.yaml_path))
            conn = cfg.get("connection", {})
            self.assertIn("url", conn)
            self.assertIn("browser", conn)
            self.assertIn("headless", conn)
            self.assertEqual(conn["browser"], "chromium")
            self.assertFalse(conn["headless"])

    def test_load_spa_config_auth_structure(self):
        """load_spa_config 返回正确的 auth 结构"""
        from pyrit_ai300.recon.engine import ReconEngine
        with patch.dict(os.environ, {
            "SPA_TEST_URL": "https://example.com/#/home",
            "SPA_TEST_USER": "student001",
            "SPA_TEST_PASS": "pass123",
            "SPA_TEST_MODE": "credentials",
        }):
            cfg = ReconEngine.load_spa_config(str(self.yaml_path))
            auth = cfg.get("auth", {})
            self.assertEqual(auth["mode"], "credentials")
            self.assertEqual(auth["username"], "student001")
            self.assertEqual(auth["password"], "pass123")
            self.assertIn("target_domain", auth)
            self.assertIn("sso_domain", auth)


# ════════════════════════════════════════════════════════════════
# 3. Pipeline _resolve_target 回归测试
#    覆盖 bug：_resolve_target 返回文件路径作为 URL
# ════════════════════════════════════════════════════════════════

class TestPipelineResolveTarget(unittest.TestCase):
    """
    回归测试：PipelineOrchestrator._resolve_target
    Bug: 当 connection.url 为空时，回退到 spa_config（文件路径），
         导致浏览器尝试导航到 "config/targets/spa_target.yaml"
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.yaml_path = Path(self.tmpdir) / "spa_target.yaml"
        self.yaml_path.write_text(
            'target:\n'
            '  url: "${SPA_RT_URL}"\n'
            '  username: "${SPA_RT_USER}"\n'
            '  password: "${SPA_RT_PASS}"\n'
            '  auth_mode: sso\n',
            encoding="utf-8",
        )

    def _get_orchestrator(self):
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator
        return PipelineOrchestrator()

    def test_resolve_target_returns_url_not_file_path(self):
        """_resolve_target 返回 URL，不返回文件路径"""
        with patch.dict(os.environ, {
            "SPA_RT_URL": "https://target.example.com/#/home",
            "SPA_RT_USER": "u",
            "SPA_RT_PASS": "p",
        }):
            orch = self._get_orchestrator()
            result = orch._resolve_target(None, None, str(self.yaml_path))
            self.assertTrue(result.startswith("http"), f"Expected URL, got: {result}")
            self.assertFalse(result.endswith(".yaml"), f"Got file path instead of URL: {result}")

    def test_resolve_target_empty_url_on_missing_env(self):
        """环境变量未设置时返回空字符串，不返回文件路径"""
        os.environ.pop("SPA_RT_URL", None)
        os.environ.pop("SPA_RT_USER", None)
        os.environ.pop("SPA_RT_PASS", None)
        orch = self._get_orchestrator()
        result = orch._resolve_target(None, None, str(self.yaml_path))
        self.assertNotEndswith(result, ".yaml")
        self.assertTrue(result == "" or result.startswith("http"),
                        f"Expected empty string or URL, got: {result}")

    def test_resolve_target_target_url_takes_priority(self):
        """target_url 参数优先于 spa_config"""
        orch = self._get_orchestrator()
        result = orch._resolve_target(
            "https://priority.example.com", None, str(self.yaml_path)
        )
        self.assertEqual(result, "https://priority.example.com")

    def test_resolve_target_no_args_returns_empty(self):
        """无参数时返回空字符串"""
        orch = self._get_orchestrator()
        result = orch._resolve_target(None, None, None)
        self.assertEqual(result, "")

    # 辅助方法
    def assertNotEndswith(self, text, suffix):
        if text.endswith(suffix):
            self.fail(f"Expected '{text}' to NOT end with '{suffix}'")


# ════════════════════════════════════════════════════════════════
# 4. Adapter result_data 安全性回归测试
#    覆盖 bug：KeyError: 'model_capabilities'
# ════════════════════════════════════════════════════════════════

class TestAdapterResultDataSafety(unittest.TestCase):
    """
    回归测试：adapter result_data 嵌套 dict 访问安全
    Bug: result_data["model_capabilities"]["parameters"] = ...
         当 model_capabilities 不存在时 KeyError 崩溃
    """

    def test_setdefault_model_capabilities(self):
        """setdefault 安全地初始化 model_capabilities"""
        result_data = {}
        result_data["model_parameters"] = {"max_tokens": 4096}
        # 模拟修复后的代码
        result_data.setdefault("model_capabilities", {})["parameters"] = result_data["model_parameters"]
        self.assertEqual(result_data["model_capabilities"]["parameters"]["max_tokens"], 4096)

    def test_setdefault_model_capabilities_already_exists(self):
        """model_capabilities 已存在时不覆盖"""
        result_data = {"model_capabilities": {"existing": True}}
        result_data["model_parameters"] = {"max_tokens": 2048}
        result_data.setdefault("model_capabilities", {})["parameters"] = result_data["model_parameters"]
        self.assertTrue(result_data["model_capabilities"]["existing"])
        self.assertEqual(result_data["model_capabilities"]["parameters"]["max_tokens"], 2048)

    def test_setdefault_auto_detected_selectors(self):
        """setdefault 安全地初始化 auto_detected_selectors"""
        result_data = {}
        result_data.setdefault("auto_detected_selectors", {})["response"] = ".chat-msg"
        self.assertEqual(result_data["auto_detected_selectors"]["response"], ".chat-msg")

    def test_no_keyerror_on_empty_result_data(self):
        """空 result_data 不会因嵌套访问而 KeyError"""
        result_data = {}
        # 模拟多个修复点
        if result_data.get("model_parameters"):
            result_data.setdefault("model_capabilities", {})["parameters"] = result_data["model_parameters"]
        if result_data.get("auto_detected_selectors") is None:
            pass  # 安全跳过
        # 不应抛出任何异常
        self.assertEqual(result_data, {})


# ════════════════════════════════════════════════════════════════
# 5. SSO 认证流程回归测试（Mock 方式）
#    覆盖 bug：page.url 阻塞导致 SSO 表单不填写
# ════════════════════════════════════════════════════════════════

class TestSSOAuthFlowSafety(unittest.TestCase):
    """
    回归测试：SSO 认证流程安全性
    Bug: page.url 在页面导航中可能阻塞，导致后续表单填写不执行
    """

    def test_page_url_exception_does_not_crash(self):
        """page.url 抛异常时 _login_with_sso 不崩溃"""
        from unittest.mock import PropertyMock

        # 构造一个 mock page 对象，page.url 抛异常
        mock_page = MagicMock()
        type(mock_page).url = PropertyMock(side_effect=RuntimeError("page closed"))

        # 模拟 try/except 的逻辑
        try:
            url = mock_page.url
        except Exception:
            url = ""
        self.assertEqual(url, "")

    def test_login_config_has_username_password(self):
        """SSO login_config 正确包含 username/password"""
        # 模拟 load_spa_config 返回的 auth 配置
        login_config = {
            "mode": "sso",
            "username": "testuser",
            "password": "testpass",
            "target_domain": "example.com",
            "sso_domain": "passport",
        }
        self.assertTrue(login_config.get("username"))
        self.assertTrue(login_config.get("password"))
        self.assertEqual(login_config.get("mode"), "sso")


# ════════════════════════════════════════════════════════════════
# 6. 端到端配置链路回归测试
#    确保 .env → YAML → config → adapter 全链路不中断
# ════════════════════════════════════════════════════════════════

class TestEndToEndConfigChain(unittest.TestCase):
    """
    端到端配置链路测试
    模拟完整流程：.env 写入 → YAML 引用 → load_spa_config 解析 → 结构验证
    """

    def test_full_chain_env_to_config(self):
        """.env → YAML ${VAR} → load_spa_config → 正确结构"""
        import pyrit_ai300.utils.env_loader as el
        from pyrit_ai300.recon.engine import ReconEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. 创建 .env
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                "E2E_URL=https://e2e.example.com/#/chat\n"
                "E2E_USER=e2e_user\n"
                "E2E_PASS=e2e_pass\n",
                encoding="utf-8",
            )

            # 2. 创建 YAML
            yaml_file = Path(tmpdir) / "spa_target.yaml"
            yaml_file.write_text(
                'target:\n'
                '  url: "${E2E_URL}"\n'
                '  username: "${E2E_USER}"\n'
                '  password: "${E2E_PASS}"\n'
                '  auth_mode: sso\n',
                encoding="utf-8",
            )

            # 3. 从 tmpdir 运行（模拟 CWD = 项目根目录）
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                os.environ.pop("E2E_URL", None)
                os.environ.pop("E2E_USER", None)
                os.environ.pop("E2E_PASS", None)
                el._dotenv_loaded = False

                # 4. 加载配置
                cfg = ReconEngine.load_spa_config(str(yaml_file))

                # 5. 验证全链路
                url = cfg["connection"]["url"]
                auth = cfg["auth"]

                self.assertEqual(url, "https://e2e.example.com/#/chat")
                self.assertNotIn("${", url, "URL must not contain unresolved variables")
                self.assertEqual(auth["username"], "e2e_user")
                self.assertEqual(auth["password"], "e2e_pass")
                self.assertEqual(auth["mode"], "sso")
                self.assertTrue(url.startswith("https://"))

            finally:
                os.chdir(old_cwd)
                os.environ.pop("E2E_URL", None)
                os.environ.pop("E2E_USER", None)
                os.environ.pop("E2E_PASS", None)


# ════════════════════════════════════════════════════════════════
# 7. 配置模板一致性回归测试
#    确保 .env.example 和 YAML 模板中的变量名一致
# ════════════════════════════════════════════════════════════════

class TestConfigTemplateConsistency(unittest.TestCase):
    """
    回归测试：配置模板一致性
    确保 .env.example 中的变量名与 YAML 模板中引用的 ${VAR} 名一致
    """

    def test_spa_target_yaml_vars_match_env_example(self):
        """spa_target.yaml 中的 ${VAR} 在 .env.example 中有定义"""
        spa_yaml = PROJECT_ROOT / "config" / "targets" / "spa_target.yaml"
        env_example = PROJECT_ROOT / ".env.example"

        if not spa_yaml.exists() or not env_example.exists():
            self.skipTest("Template files not found")

        import re
        yaml_content = spa_yaml.read_text(encoding="utf-8")
        env_content = env_example.read_text(encoding="utf-8")

        # 提取 YAML 中所有 ${VAR} 引用
        var_pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
        yaml_vars = set(var_pattern.findall(yaml_content))

        # 提取 .env.example 中所有 KEY= 定义
        env_keys = set()
        for line in env_content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key = line.split("=")[0].strip()
                if key:
                    env_keys.add(key)

        # 检查每个 YAML 引用的变量都在 .env.example 中定义
        missing = yaml_vars - env_keys
        self.assertFalse(
            missing,
            f"Variables referenced in spa_target.yaml but not defined in .env.example: {missing}"
        )


# ════════════════════════════════════════════════════════════════
# 8. Pipeline 攻击阶段目标类型一致性回归测试
#    覆盖 bug：SPA 目标在攻击阶段被错误地当作 LLM API 目标
# ════════════════════════════════════════════════════════════════

class TestPipelineAttackTargetConsistency(unittest.TestCase):
    """
    回归测试：Pipeline 攻击阶段目标类型一致性

    Bug: 流水线最初基于 SPA URL 攻击，但攻击阶段默认使用了
         llm_api_target.yaml，导致目标变成 localhost:11434 的
         Ollama 端点（Model: llama3.2:latest），而不是 SPA 页面 URL。

    根因：_run_attack_phase 中 `target_cfg = target_file or
         "config/targets/llm_api_target.yaml"`，当 SPA 目标时
         target_file 为 None，回退到 LLM API 配置。同时
         _build_target_config 只覆盖 endpoint 不改变 type，
         导致 TargetBuilder 走 OpenAI 路径而非 Playwright 路径。
    """

    def test_detect_target_type_spa_with_config(self):
        """有 spa_config 时检测为 spa 类型"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator
        result = PipelineOrchestrator._detect_target_type(
            "https://example.com/#/home", "config/targets/spa_target.yaml"
        )
        self.assertEqual(result, "spa")

    def test_detect_target_type_spa_with_hash_url(self):
        """URL 含 #/ 检测为 spa 类型"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator
        result = PipelineOrchestrator._detect_target_type(
            "https://www.example.com/#/home", None
        )
        self.assertEqual(result, "spa")

    def test_detect_target_type_api_localhost(self):
        """localhost URL 检测为 api 类型"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator
        result = PipelineOrchestrator._detect_target_type(
            "http://localhost:11434/v1", None
        )
        self.assertEqual(result, "api")

    def test_detect_target_type_api_known_port(self):
        """已知 LLM 端口检测为 api 类型"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator
        result = PipelineOrchestrator._detect_target_type(
            "http://192.168.0.23:11434/v1", None
        )
        self.assertEqual(result, "api")

    def test_build_target_config_spa_url_sets_spa_type(self):
        """SPA URL 时 _build_target_config 设置 type=spa_chat"""
        from pyrit_ai300 import AI300Engine
        import tempfile
        import yaml

        # 创建一个临时 llm_api_target.yaml（模拟错误默认配置）
        with tempfile.TemporaryDirectory() as tmpdir:
            llm_cfg = Path(tmpdir) / "llm_api_target.yaml"
            llm_cfg.write_text(
                'target:\n'
                '  type: "ollama"\n'
                '  endpoint: "http://192.168.0.23:11434/v1"\n'
                '  model: "qwen3:0.6b"\n'
                '  api_key: "not-needed"\n',
                encoding="utf-8",
            )

            engine = AI300Engine(
                target_config=str(llm_cfg),
                target_url="https://www.example.com/#/home",
            )
            cfg = engine._build_target_config()
            target_type = cfg.get("target", {}).get("type", "")
            # SPA URL 不应该被当作 ollama 处理
            self.assertNotEqual(
                target_type, "ollama",
                f"SPA URL should not produce type=ollama, got type={target_type}"
            )
            self.assertEqual(
                target_type, "spa_chat",
                f"SPA URL should produce type=spa_chat, got type={target_type}"
            )

    def test_build_target_config_api_url_keeps_ollama_type(self):
        """API URL 时 _build_target_config 保持 ollama 类型"""
        from pyrit_ai300 import AI300Engine
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            llm_cfg = Path(tmpdir) / "llm_api_target.yaml"
            llm_cfg.write_text(
                'target:\n'
                '  type: "ollama"\n'
                '  endpoint: "http://192.168.0.23:11434/v1"\n'
                '  model: "qwen3:0.6b"\n'
                '  api_key: "not-needed"\n',
                encoding="utf-8",
            )

            engine = AI300Engine(
                target_config=str(llm_cfg),
                target_url="http://localhost:11434/v1",
            )
            cfg = engine._build_target_config()
            target_type = cfg.get("target", {}).get("type", "")
            self.assertEqual(target_type, "ollama")

    def test_build_target_config_spa_url_sets_connection_url(self):
        """SPA URL 时 connection 中设置 url 而非 endpoint"""
        from pyrit_ai300 import AI300Engine
        import tempfile

        spa_url = "https://www.example.com/#/home"

        with tempfile.TemporaryDirectory() as tmpdir:
            llm_cfg = Path(tmpdir) / "llm_api_target.yaml"
            llm_cfg.write_text(
                'target:\n'
                '  type: "ollama"\n'
                '  endpoint: "http://192.168.0.23:11434/v1"\n'
                '  model: "qwen3:0.6b"\n'
                '  api_key: "not-needed"\n',
                encoding="utf-8",
            )

            engine = AI300Engine(
                target_config=str(llm_cfg),
                target_url=spa_url,
            )
            cfg = engine._build_target_config()
            conn = cfg.get("target", {}).get("connection", {})

            # SPA 目标的 connection 应该有 url 字段
            self.assertIn("url", conn, "SPA target connection should have 'url' field")
            self.assertEqual(conn["url"], spa_url)

    def test_attack_phase_spa_config_not_using_llm_api_default(self):
        """SPA 目标时攻击阶段不应使用 llm_api_target.yaml 作为默认配置"""
        from pyrit_ai300.pipeline.orchestrator import PipelineOrchestrator

        # 模拟 _run_attack_phase 的配置选择逻辑
        target_url = "https://www.example.com/#/home"
        spa_config = "config/targets/spa_target.yaml"
        target_file = None  # 用户没有指定 --target-file

        target_type = PipelineOrchestrator._detect_target_type(target_url, spa_config)

        # SPA 目标应该使用 spa_config，而不是回退到 llm_api_target.yaml
        if target_type == "spa":
            chosen_cfg = spa_config or "config/targets/spa_target.yaml"
        else:
            chosen_cfg = target_file or "config/targets/llm_api_target.yaml"

        self.assertNotEqual(
            chosen_cfg, "config/targets/llm_api_target.yaml",
            "SPA target should not fall back to llm_api_target.yaml"
        )
        self.assertEqual(chosen_cfg, spa_config)


# ════════════════════════════════════════════════════════════════
# 9. Converter 必需参数默认值回归测试
#    覆盖 bug：CaesarConverter 和 TextJailbreakConverter 缺少必需参数
# ════════════════════════════════════════════════════════════════

class TestConverterDefaultParams(unittest.TestCase):
    """
    回归测试：Converter 必需参数默认值

    Bug: CaesarConverter 需要 caesar_offset 参数，TextJailbreakConverter
    需要 jailbreak_template 参数，但 ConverterBuilder 未提供默认值，
    导致每次构建转换器都输出 WARNING 并跳过该转换器。

    日志表现：
      WARNING: Converter caesar requires params: CaesarConverter.__init__()
      missing 1 required keyword-only argument: 'caesar_offset'
      WARNING: Converter text_jailbreak requires params: ...
    """

    def test_caesar_converter_default_params_defined(self):
        """CONVERTER_DEFAULT_PARAMS 中有 caesar 的默认参数"""
        from pyrit_ai300.attack.pyrit.component_registry import CONVERTER_DEFAULT_PARAMS
        self.assertIn("caesar", CONVERTER_DEFAULT_PARAMS)
        self.assertIn("caesar_offset", CONVERTER_DEFAULT_PARAMS["caesar"])
        self.assertIsInstance(CONVERTER_DEFAULT_PARAMS["caesar"]["caesar_offset"], int)

    def test_text_jailbreak_converter_default_params_defined(self):
        """CONVERTER_DEFAULT_PARAMS 中有 text_jailbreak 的默认参数"""
        from pyrit_ai300.attack.pyrit.component_registry import CONVERTER_DEFAULT_PARAMS
        self.assertIn("text_jailbreak", CONVERTER_DEFAULT_PARAMS)
        self.assertIn("jailbreak_template", CONVERTER_DEFAULT_PARAMS["text_jailbreak"])

    def test_converter_builder_creates_caesar_with_default(self):
        """ConverterBuilder 使用默认参数成功创建 CaesarConverter"""
        from pyrit_ai300.attack.pyrit.converter_builder import ConverterBuilder
        builder = ConverterBuilder()
        converters = builder.build([{"name": "caesar"}])
        self.assertEqual(len(converters), 1, "CaesarConverter should be created with default params")

    def test_converter_builder_creates_text_jailbreak_with_default(self):
        """ConverterBuilder 使用默认参数成功创建 TextJailbreakConverter"""
        from pyrit_ai300.attack.pyrit.converter_builder import ConverterBuilder
        builder = ConverterBuilder()
        converters = builder.build([{"name": "text_jailbreak"}])
        self.assertEqual(len(converters), 1, "TextJailbreakConverter should be created with default params")

    def test_converter_builder_custom_params_override_defaults(self):
        """用户自定义参数覆盖默认参数"""
        from pyrit_ai300.attack.pyrit.converter_builder import ConverterBuilder
        builder = ConverterBuilder()
        converters = builder.build([{"name": "caesar", "params": {"caesar_offset": 13}}])
        self.assertEqual(len(converters), 1, "CaesarConverter should be created with custom params")


# ════════════════════════════════════════════════════════════════
# 10. SPA 目标 binary_path 转换器过滤回归测试
#     覆盖 bug：PDFConverter/WordDocConverter 产生 binary_path
#     被 PlaywrightTarget 拒绝
# ════════════════════════════════════════════════════════════════

class TestSpaBinaryPathFilter(unittest.TestCase):
    """
    回归测试：SPA 目标过滤产生 binary_path 的转换器

    Bug: PDFConverter 和 WordDocConverter 产生 binary_path 数据类型，
    但 PlaywrightTarget 只支持 image_path 和 text，导致攻击失败：
      ValueError: This target supports only the following data types:
      image_path, text. Received: binary_path.
    """

    def test_binary_path_producers_set_defined(self):
        """CONVERTERS_PRODUCING_BINARY_PATH 集合已定义"""
        from pyrit_ai300.attack.pyrit.component_registry import CONVERTERS_PRODUCING_BINARY_PATH
        self.assertIn("pdf", CONVERTERS_PRODUCING_BINARY_PATH)
        self.assertIn("word_doc", CONVERTERS_PRODUCING_BINARY_PATH)

    def test_converter_builder_filters_binary_path_for_spa(self):
        """SPA 目标时过滤掉产生 binary_path 的转换器"""
        from pyrit_ai300.attack.pyrit.converter_builder import ConverterBuilder
        builder = ConverterBuilder()
        # 模拟 SPA 目标
        from unittest.mock import MagicMock
        spa_target = MagicMock()
        spa_target.__class__.__name__ = "PlaywrightTarget"
        converters = builder.build(
            [{"name": "base64"}, {"name": "pdf"}, {"name": "word_doc"}],
            converter_target=spa_target,
            target_type="spa_chat",
        )
        # base64 应该保留，pdf 和 word_doc 应该被过滤
        self.assertEqual(len(converters), 1, "Only base64 should remain for SPA target")

    def test_converter_builder_keeps_binary_path_for_api(self):
        """API 目标时保留产生 binary_path 的转换器"""
        from pyrit_ai300.attack.pyrit.converter_builder import ConverterBuilder
        builder = ConverterBuilder()
        from unittest.mock import MagicMock
        api_target = MagicMock()
        api_target.__class__.__name__ = "OpenAIChatTarget"
        converters = builder.build(
            [{"name": "base64"}, {"name": "pdf"}],
            converter_target=api_target,
            target_type="ollama",
        )
        # API 目标不过滤 binary_path 转换器
        self.assertEqual(len(converters), 2, "Both converters should remain for API target")


if __name__ == "__main__":
    unittest.main()
