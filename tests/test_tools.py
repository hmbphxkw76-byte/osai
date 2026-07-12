"""ToolResolver 测试。"""
import tempfile
from pathlib import Path


from redteam.core.tools import ToolResolver


class TestToolResolverLoad:
    """测试 ToolResolver 加载配置。"""

    def test_load_default(self):
        resolver = ToolResolver()
        assert isinstance(resolver.settings, dict)
        assert isinstance(resolver.tools, dict)

    def test_load_missing_file(self):
        resolver = ToolResolver(Path("/nonexistent/config.yaml"))
        assert resolver.settings == {}
        assert resolver.tools == {}

    def test_load_custom_settings(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("tools:\n  aimap: /custom/path/aimap\n  mcp_scan: /opt/mcp-scan\n")
            f.flush()
            resolver = ToolResolver(Path(f.name))
            assert resolver.tools["aimap"] == "/custom/path/aimap"
            assert resolver.tools["mcp_scan"] == "/opt/mcp-scan"


class TestToolResolverResolve:
    """测试 resolve() 方法。"""

    def test_resolve_from_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("tools:\n  mytool: /usr/bin/mytool\n")
            f.flush()
            resolver = ToolResolver(Path(f.name))
            # /usr/bin/mytool doesn't exist on Windows but shutil.which falls back to cmd
            result = resolver.resolve("mytool")
            assert result == "/usr/bin/mytool" or result == "mytool"

    def test_resolve_unknown_falls_back_to_name(self):
        resolver = ToolResolver(Path("/nonexistent/config.yaml"))
        result = resolver.resolve("nonexistent_tool_xyz")
        assert result == "nonexistent_tool_xyz"

    def test_resolve_uses_shutil_which(self):
        """Python 自身应该可通过 shutil.which 找到。"""
        resolver = ToolResolver(Path("/nonexistent/config.yaml"))
        result = resolver.resolve("python")
        assert "python" in result.lower()


class TestToolResolverAvailable:
    """测试 available() 方法。"""

    def test_python_is_available(self):
        resolver = ToolResolver(Path("/nonexistent/config.yaml"))
        assert resolver.available("python") is True

    def test_nonexistent_is_not_available(self):
        resolver = ToolResolver(Path("/nonexistent/config.yaml"))
        assert resolver.available("nonexistent_tool_xyz_12345") is False


class TestToolResolverEnabled:
    """测试 enabled() 方法。"""

    def test_enabled_bool_true(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("recon:\n  enable_aimap: true\n")
            f.flush()
            resolver = ToolResolver(Path(f.name))
            assert resolver.enabled("enable_aimap") is True

    def test_enabled_bool_false(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("recon:\n  enable_aimap: false\n")
            f.flush()
            resolver = ToolResolver(Path(f.name))
            assert resolver.enabled("enable_aimap") is False

    def test_enabled_auto_available(self):
        """auto 模式下，python 应该可用。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("recon:\n  enable_python: auto\n")
            f.flush()
            resolver = ToolResolver(Path(f.name))
            assert resolver.enabled("enable_python") is True

    def test_enabled_auto_not_available(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("recon:\n  enable_xyz_unknown_tool: auto\n")
            f.flush()
            resolver = ToolResolver(Path(f.name))
            assert resolver.enabled("enable_xyz_unknown_tool") is False

    def test_enabled_truthy_string(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("recon:\n  enable_test: 'yes'\n")
            f.flush()
            resolver = ToolResolver(Path(f.name))
            assert resolver.enabled("enable_test") is True

    def test_enabled_unknown_key_defaults(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("recon:\n  something_else: true\n")
            f.flush()
            resolver = ToolResolver(Path(f.name))
            # key not in recon → auto → tool name = "unknown" → shutil.which fails → False
            assert resolver.enabled("enable_unknown_key_defaults") is False
