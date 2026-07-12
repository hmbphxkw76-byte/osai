"""mcp-scan 封装测试。"""
from unittest.mock import patch, MagicMock

from redteam.recon.mcp_scan_runner import scan
from redteam.core.models import Finding


class TestMCPScanRunner:
    """mcp_scan_runner.scan 单元测试。"""

    def test_scan_returns_findings(self):
        """正常扫描返回 Finding 列表。"""
        mock_result = MagicMock()
        mock_result.stdout = "[INFO] Scanning MCP endpoint...\n[VULN] prompt injection detected"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            findings = scan("http://localhost:8080/mcp")
            assert len(findings) == 1
            assert isinstance(findings[0], Finding)
            assert findings[0].source == "mcp_scan"
            assert findings[0].category == "mcp_security"
            assert findings[0].severity == "medium"
            assert "prompt injection" in findings[0].evidence

    def test_scan_with_tool_resolver(self):
        """使用自定义 ToolResolver 的扫描。"""
        from redteam.core.tools import ToolResolver
        from pathlib import Path

        mock_result = MagicMock()
        mock_result.stdout = "No vulnerabilities found"
        mock_result.stderr = ""

        resolver = ToolResolver(Path("/nonexistent/config.yaml"))
        with patch("subprocess.run", return_value=mock_result):
            findings = scan("http://test:9090/mcp", resolver=resolver)
            assert len(findings) == 1
            assert findings[0].severity == "medium"

    def test_scan_error_graceful(self):
        """扫描异常时返回空列表。"""
        with patch("subprocess.run", side_effect=FileNotFoundError("mcp-scan not found")):
            findings = scan("http://test:7070/mcp", timeout=1)
            assert findings == []

    def test_scan_timeout_graceful(self):
        """超时异常时返回空列表。"""
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="mcp-scan", timeout=1)):
            findings = scan("http://test:6060/mcp", timeout=1)
            assert findings == []

    def test_evidence_truncated(self):
        """过长输出应被截断到 2000 字符。"""
        long_output = "X" * 5000
        mock_result = MagicMock()
        mock_result.stdout = long_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            findings = scan("http://test:5050/mcp")
            assert len(findings) == 1
            assert len(findings[0].evidence) <= 2000

    def test_combined_output(self):
        """stdout + stderr 合并输出。"""
        mock_result = MagicMock()
        mock_result.stdout = "STDOUT content"
        mock_result.stderr = "STDERR content"

        with patch("subprocess.run", return_value=mock_result):
            findings = scan("http://test:4040/mcp")
            evidence = findings[0].evidence
            # 输出较短时，两者都包含在 2000 字符内
            assert len(evidence) > 0
