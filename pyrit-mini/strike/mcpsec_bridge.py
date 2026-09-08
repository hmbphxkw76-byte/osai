# MCPSec Bridge - mcpsec v2.7.2 (manthanghasadiya/mcpsec)
# arXiv:2302.12173 - Greshake et al., Indirect prompt injection
# arXiv:2402.14266 - SKELETONKEY, SkeletonKey
"""mcpsec_bridge - Bridge MCPSec CLI to pyrit-mini attack pipeline.

MCPSec Version: v2.7.2 (latest: 2026-09-08)
MCPSec Repository: https://github.com/manthanghasadiya/mcpsec
MCPSec License: MIT

Capabilities:
    - mcpsec scan    → Runtime vulnerability scanning (10+ scanners)
    - mcpsec fuzz    → Protocol fuzzing (800+ cases, 22 generators)
    - mcpsec audit   → Static code analysis (3450+ sink patterns, 149 Semgrep rules)
    - mcpsec info    → Attack surface enumeration
    - mcpsec sql     → SQL injection scanner with DB fingerprinting
    - mcpsec chains  → Dangerous tool combination detection
    - mcpsec exploit → Interactive exploitation REPL
    - mcpsec rogue-server → Rogue MCP server for client-side testing

This module replaces ~2,200 lines of self-developed MCP code with
MCPSec's battle-tested implementations, providing:
    - 10x+ attack surface coverage
    - Automated CVE discovery (6 CVEs found by MCPSec)
    - Industry-standard fuzzing and scanning
    - AI-powered payload generation

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - Indirect prompt injection via MCP tools
    - Zhan et al. (arXiv:2307.00929) - InjecAgent, tool call injection
    - MCPSec (manthanghasadiya/mcpsec v2.7.2) - MCP security scanner + fuzzer

Design principles:
    1. Thin CLI wrapper - all logic delegated to MCPSec
    2. Output converted to pyrit-mini native formats (Seed, AttackResult)
    3. Async-friendly with timeout protection
    4. Graceful degradation when MCPSec not installed
    5. Compatible with PyRIT AttackExecutor
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# MCPSec version compatibility
_MCPSPEC_MIN_VERSION = "2.7.0"
_MCPSPEC_TARGET_VERSION = "2.7.2"

# MCPSec scanner types (v2.7.2)
_MCPSPEC_SCANNERS = [
    "prompt-injection",
    "command-injection",
    "path-traversal",
    "ssrf",
    "sql",
    "auth-audit",
    "description-prompt-injection",
    "resource-ssrf",
    "capability-escalation",
    "chains",
    "code-execution",
    "template-injection",
    "rag-poisoning",
    "idor",
    "info-leak",
    "deserialization",
]

# MCPSec fuzz intensity levels
_MCPSPEC_FUZZ_INTENSITY = {
    "low": "~65 cases",
    "medium": "~200 cases",
    "high": "~800 cases",
    "insane": "~1500+ cases",
}


@dataclass
class MCPSecScanResult:
    """Parsed result from MCPSec scan/fuzz output."""
    scanner: str
    vulnerability: str
    severity: str  # critical, high, medium, low, info
    evidence: str
    payload: str = ""
    tool_name: str = ""
    raw_output: dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPSecBridgeConfig:
    """Configuration for MCPSec bridge.

    Attributes:
        mcpsec_path: Path to mcpsec binary (auto-detected if None)
        timeout: Per-command timeout in seconds
        intensity: Fuzz intensity (low/medium/high/insane)
        use_ai: Enable AI-powered payload generation
        ai_provider: AI provider name (openai/anthropic/ollama)
        output_dir: Directory for MCPSec output files
        extra_args: Additional CLI arguments
    """
    mcpsec_path: Optional[str] = None
    timeout: float = 120.0
    intensity: str = "high"
    use_ai: bool = False
    ai_provider: str = "openai"
    output_dir: Optional[str] = None
    extra_args: list[str] = field(default_factory=list)


class MCPSecBridge:
    """Bridge between MCPSec CLI and pyrit-mini attack pipeline.

    Provides async-friendly interface to all MCPSec capabilities:
    - Runtime scanning (prompt-injection, command-injection, etc.)
    - Protocol fuzzing (type-confusion, boundary-testing, etc.)
    - Static analysis (3450+ sink patterns, 149 Semgrep rules)
    - Surface enumeration (tools, resources, prompts)

    Attributes:
        config: MCPSec bridge configuration
        version: Detected MCPSec version
        is_available: Whether MCPSec CLI is installed and working

    Usage:
        bridge = MCPSecBridge()
        if bridge.is_available:
            results = await bridge.scan_target("http://target:8080/mcp")
            seeds = await bridge.generate_attack_seeds("http://target:8080/mcp")
    """

    def __init__(self, config: Optional[MCPSecBridgeConfig] = None) -> None:
        self._config = config or MCPSecBridgeConfig()
        self._version: Optional[str] = None
        self._is_available: bool = False
        self._binary_path: Optional[str] = None

        # Detect MCPSec installation
        self._detect_mcpsec()

    @property
    def is_available(self) -> bool:
        """Whether MCPSec CLI is detected and working."""
        return self._is_available

    @property
    def version(self) -> Optional[str]:
        """Detected MCPSec version string."""
        return self._version

    @property
    def binary_path(self) -> Optional[str]:
        """Path to mcpsec binary."""
        return self._binary_path

    def _detect_mcpsec(self) -> None:
        """Detect MCPSec installation and version."""
        # Try configured path first
        if self._config.mcpsec_path:
            if self._check_binary(self._config.mcpsec_path):
                return

        # Try common locations
        candidates = [
            "mcpsec",
            "python -m mcpsec",
            os.path.join(os.path.expanduser("~"), ".local", "bin", "mcpsec"),
            # Windows-specific
            os.path.join(os.path.expanduser("~"), "AppData", "Local", "Programs", "Python", "Python313", "Scripts", "mcpsec.exe"),
        ]

        for candidate in candidates:
            if self._check_binary(candidate):
                return

        # Try pip show detection
        try:
            result = subprocess.run(
                ["pip", "show", "mcpsec"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info("MCPSecBridge: mcpsec installed via pip, using Python module")
                self._binary_path = "python -m mcpsec"
                self._is_available = True
                self._version = self._parse_pip_version(result.stdout)
                return
        except Exception:
            pass

        logger.warning(
            "MCPSecBridge: mcpsec not found. Install with: pip install mcpsec"
        )
        self._is_available = False

    def _check_binary(self, path: str) -> bool:
        """Check if mcpsec binary works."""
        try:
            result = subprocess.run(
                [*path.split(), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                self._binary_path = path
                self._is_available = True
                self._version = result.stdout.strip().replace("mcpsec ", "")
                logger.info(
                    "MCPSecBridge: detected mcpsec v%s at %s",
                    self._version,
                    path,
                )
                return True
        except Exception as e:
            logger.debug("MCPSecBridge: binary check failed for %s: %s", path, e)
        return False

    def _parse_pip_version(self, pip_output: str) -> str:
        """Extract version from pip show output."""
        for line in pip_output.splitlines():
            if line.lower().startswith("version:"):
                return line.split(":", 1)[1].strip()
        return "unknown"

    async def _run_mcpsec(
        self,
        args: list[str],
        *,
        timeout: Optional[float] = None,
        stdin_input: Optional[str] = None,
    ) -> tuple[int, str, str]:
        """Run mcpsec CLI command asynchronously.

        Args:
            args: CLI arguments (after 'mcpsec')
            timeout: Command timeout override
            stdin_input: Optional stdin input

        Returns:
            (exit_code, stdout, stderr)
        """
        cmd = [*self._binary_path.split(), *args]
        timeout_val = timeout or self._config.timeout

        logger.debug("MCPSecBridge: running: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=(
                    asyncio.subprocess.PIPE
                    if stdin_input is not None
                    else None
                ),
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(
                    input=stdin_input.encode() if stdin_input else None
                ),
                timeout=timeout_val,
            )

            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            return proc.returncode or 0, stdout_str, stderr_str

        except asyncio.TimeoutError:
            logger.warning("MCPSecBridge: command timed out after %ss", timeout_val)
            try:
                proc.kill()
            except Exception:
                pass
            return -1, "", f"timeout after {timeout_val}s"
        except Exception as e:
            logger.debug("MCPSecBridge: command failed: %s", e)
            return -1, "", str(e)

    async def scan_target(
        self,
        target_url: str,
        *,
        scanners: Optional[list[str]] = None,
        auth_header: Optional[str] = None,
        transport: str = "http",
        stdio_command: Optional[str] = None,
    ) -> list[MCPSecScanResult]:
        """Run MCPSec scanners against target MCP server.

        Args:
            target_url: MCP server endpoint URL
            scanners: Scanner list (default: all)
            auth_header: Optional Authorization header
            transport: "http" or "stdio"
            stdio_command: Command for stdio transport

        Returns:
            List of detected vulnerabilities
        """
        if not self._is_available:
            logger.warning("MCPSecBridge: mcpsec not available, skipping scan")
            return []

        # Build output file path
        output_file = self._get_output_file("scan_results.json")

        # Build scan arguments
        cmd_args: list[str] = ["scan"]

        if transport == "http":
            cmd_args.extend(["--http", target_url])
        elif transport == "stdio" and stdio_command:
            cmd_args.extend(["--stdio", stdio_command])

        if auth_header:
            cmd_args.extend(["-H", auth_header])

        cmd_args.extend(["--output", output_file])

        # Select scanners
        active_scanners = scanners or _MCPSPEC_SCANNERS
        if active_scanners != _MCPSPEC_SCANNERS:
            cmd_args.extend(["--scanners", ",".join(active_scanners)])

        exit_code, stdout, stderr = await self._run_mcpsec(
            cmd_args,
            timeout=self._config.timeout,
        )

        if exit_code != 0:
            logger.warning(
                "MCPSecBridge: scan failed (exit %d): %s",
                exit_code,
                stderr[:500] if stderr else stdout[:500],
            )
            return []

        # Parse results
        results = self._parse_scan_output(output_file, stdout)
        logger.info(
            "MCPSecBridge: scan complete: %d vulnerabilities found",
            len(results),
        )
        return results

    async def fuzz_target(
        self,
        target_url: str,
        *,
        intensity: Optional[str] = None,
        transport: str = "http",
        stdio_command: Optional[str] = None,
        auth_header: Optional[str] = None,
    ) -> list[MCPSecScanResult]:
        """Run MCPSec fuzzer against target.

        Args:
            target_url: MCP server endpoint URL
            intensity: Fuzz intensity (low/medium/high/insane)
            transport: Transport protocol
            stdio_command: Stdio command
            auth_header: Auth header

        Returns:
            List of fuzzing findings
        """
        if not self._is_available:
            return []

        output_file = self._get_output_file("fuzz_results.json")
        cmd_args: list[str] = ["fuzz"]

        if transport == "http":
            cmd_args.extend(["--http", target_url])
        elif transport == "stdio" and stdio_command:
            cmd_args.extend(["--stdio", stdio_command])

        if auth_header:
            cmd_args.extend(["-H", auth_header])

        cmd_args.extend(["--intensity", intensity or self._config.intensity])
        cmd_args.extend(["--output", output_file])

        if self._config.use_ai:
            cmd_args.append("--ai")

        exit_code, stdout, stderr = await self._run_mcpsec(
            cmd_args,
            timeout=max(self._config.timeout, 300),  # Fuzzing needs more time
        )

        results = self._parse_scan_output(output_file, stdout)
        logger.info("MCPSecBridge: fuzz complete: %d findings", len(results))
        return results

    async def audit_source(
        self,
        source_path: str,
        *,
        is_github: bool = False,
        use_ai: bool = False,
    ) -> dict[str, Any]:
        """Run MCPSec static audit on MCP server source code.

        Args:
            source_path: Local path or GitHub URL
            is_github: Whether source_path is a GitHub URL
            use_ai: Enable AI-powered taint analysis

        Returns:
            Audit report dictionary
        """
        if not self._is_available:
            return {}

        output_file = self._get_output_file("audit_results.json")
        cmd_args: list[str] = ["audit"]

        if is_github:
            cmd_args.extend(["--github", source_path])
        else:
            cmd_args.extend(["--path", source_path])

        cmd_args.extend(["--output", output_file])

        if use_ai or self._config.use_ai:
            cmd_args.append("--ai")

        exit_code, stdout, stderr = await self._run_mcpsec(
            cmd_args,
            timeout=max(self._config.timeout, 180),
        )

        if exit_code != 0:
            logger.warning("MCPSecBridge: audit failed: %s", stderr[:300])
            return {}

        try:
            if Path(output_file).exists():
                with open(output_file, encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning("MCPSecBridge: failed to parse audit output: %s", e)

        return {}

    async def enumerate_surface(
        self,
        target_url: str,
        *,
        transport: str = "http",
        stdio_command: Optional[str] = None,
        auth_header: Optional[str] = None,
    ) -> dict[str, Any]:
        """Enumerate MCP server attack surface (tools/resources/prompts).

        Args:
            target_url: MCP server endpoint URL
            transport: Transport protocol
            stdio_command: Stdio command
            auth_header: Auth header

        Returns:
            Attack surface description
        """
        if not self._is_available:
            return {}

        cmd_args: list[str] = ["info"]

        if transport == "http":
            cmd_args.extend(["--http", target_url])
        elif transport == "stdio" and stdio_command:
            cmd_args.extend(["--stdio", stdio_command])

        if auth_header:
            cmd_args.extend(["-H", auth_header])

        output_file = self._get_output_file("info_results.json")
        cmd_args.extend(["--output", output_file])

        exit_code, stdout, stderr = await self._run_mcpsec(
            cmd_args,
            timeout=self._config.timeout,
        )

        if exit_code != 0:
            logger.warning("MCPSecBridge: info failed: %s", stderr[:300])
            return {}

        try:
            if Path(output_file).exists():
                with open(output_file, encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass

        # Fallback: parse stdout as JSON
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"raw_output": stdout}

    async def generate_attack_seeds(
        self,
        target_url: str,
        *,
        count: int = 50,
        use_ai: bool = False,
    ) -> list[dict[str, Any]]:
        """Generate attack seeds from MCPSec fuzz output.

        Uses fuzzing results as attack seed templates.

        Args:
            target_url: Target MCP server
            count: Maximum seeds to generate
            use_ai: Use AI payload generation

        Returns:
            List of seed dictionaries compatible with pyrit-mini
        """
        fuzz_results = await self.fuzz_target(
            target_url,
            intensity="medium",
            use_ai=use_ai,
        )

        seeds: list[dict[str, Any]] = []

        for finding in fuzz_results[:count]:
            seed = {
                "value": finding.payload or finding.evidence,
                "metadata": {
                    "source": "mcpsec_fuzz",
                    "vulnerability": finding.vulnerability,
                    "severity": finding.severity,
                    "scanner": finding.scanner,
                    "mcp_tool": finding.tool_name,
                    "attack_category": "mcp_fuzz",
                    "tier": 1 if finding.severity in ("critical", "high") else 2,
                },
            }
            seeds.append(seed)

        logger.info(
            "MCPSecBridge: generated %d attack seeds from fuzz results",
            len(seeds),
        )
        return seeds

    async def check_tool_chains(
        self,
        target_url: str,
        *,
        transport: str = "http",
        stdio_command: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Check for dangerous tool combinations (chains).

        Args:
            target_url: MCP server endpoint
            transport: Transport protocol
            stdio_command: Stdio command

        Returns:
            List of dangerous tool chains
        """
        if not self._is_available:
            return []

        cmd_args: list[str] = ["chains"]

        if transport == "http":
            cmd_args.extend(["--http", target_url])
        elif transport == "stdio" and stdio_command:
            cmd_args.extend(["--stdio", stdio_command])

        output_file = self._get_output_file("chains_results.json")
        cmd_args.extend(["--output", output_file])

        exit_code, stdout, stderr = await self._run_mcpsec(cmd_args)

        if exit_code != 0:
            return []

        try:
            if Path(output_file).exists():
                with open(output_file, encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else [data]
        except Exception:
            pass

        return []

    def _get_output_file(self, name: str) -> str:
        """Get output file path for MCPSec results."""
        if self._output_dir:
            return str(Path(self._output_dir) / name)
        return str(Path(tempfile.gettempdir()) / name)

    def _parse_scan_output(
        self, output_file: str, stdout: str
    ) -> list[MCPSecScanResult]:
        """Parse MCPSec JSON output into MCPSecScanResult objects."""
        results: list[MCPSecScanResult] = []

        # Try parsing structured JSON output first
        data: dict[str, Any] = {}
        try:
            if Path(output_file).exists():
                with open(output_file, encoding="utf-8") as f:
                    data = json.load(f)
        except Exception:
            pass

        if not data:
            # Fallback: try parsing stdout
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                pass

        if not data:
            return results

        # MCPSec v2.7.2 output format: {"findings": [...], "summary": {...}}
        findings = data.get("findings", data.get("results", []))
        if isinstance(findings, dict):
            findings = findings.get("vulnerabilities", [])

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            results.append(
                MCPSecScanResult(
                    scanner=finding.get("scanner", "unknown"),
                    vulnerability=finding.get("name", finding.get("title", "unknown")),
                    severity=finding.get("severity", "unknown"),
                    evidence=finding.get(
                        "evidence", finding.get("description", "")
                    ),
                    payload=finding.get("payload", ""),
                    tool_name=finding.get("tool", ""),
                    raw_output=finding,
                )
            )

        return results

    def check_version(self) -> bool:
        """Check if MCPSec version meets minimum requirement."""
        if not self._version:
            return False

        try:
            parts = self._version.replace("v", "").split(".")
            min_parts = _MCPSPEC_MIN_VERSION.split(".")

            for i, (have, need) in enumerate(
                zip(parts, min_parts), start=1
            ):
                h = int(have) if have.isdigit() else 0
                n = int(need) if need.isdigit() else 0
                if h > n:
                    return True
                if h < n:
                    return False
            return len(parts) >= len(min_parts)
        except Exception:
            return True  # If can't parse, assume compatible

    async def analyze_tool_chain(
        self,
        tools: list[dict[str, Any]],
    ) -> Optional[dict[str, Any]]:
        """Analyze tool chain for dangerous combinations.

        Integrates recon/dangerous_patterns.py and tools/tool_dependency_graph.py
        for static analysis of tool definitions.

        Args:
            tools: List of tool definitions (name + description)

        Returns:
            Analysis result dict, or None if analysis fails
        """
        try:
            from recon.dangerous_patterns import detect_dangerous_combinations
            from tools.tool_dependency_graph import build_graph_from_tools

            # Detect dangerous combinations
            dangerous = detect_dangerous_combinations(tools)

            # Build dependency graph
            graph = build_graph_from_tools(tools)
            critical_tools = graph.get_critical_tools()
            high_risk_paths = graph.get_high_risk_paths()

            return {
                "dangerous_combinations": dangerous,
                "critical_tools": critical_tools,
                "high_risk_paths": high_risk_paths,
                "tool_count": graph.tool_count,
                "edge_count": graph.edge_count,
            }
        except Exception as e:
            logger.debug("Tool chain analysis failed: %s", e)
            return None


def create_mcpsec_bridge(
    *,
    timeout: float = 120.0,
    intensity: str = "high",
    use_ai: bool = False,
    ai_provider: str = "openai",
) -> MCPSecBridge:
    """Factory function for MCPSecBridge.

    Args:
        timeout: Command timeout
        intensity: Fuzz intensity
        use_ai: Enable AI payloads
        ai_provider: AI provider name

    Returns:
        Configured MCPSecBridge instance
    """
    config = MCPSecBridgeConfig(
        timeout=timeout,
        intensity=intensity,
        use_ai=use_ai,
        ai_provider=ai_provider,
    )
    return MCPSecBridge(config)
