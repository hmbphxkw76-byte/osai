# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Agent Workspace Probe — filesystem permissions, sandbox, knowledge-base detection.

Discovers:
  1. Filesystem read/write permissions from tool descriptions/responses
  2. Sandbox isolation level (container, chroot, restricted paths)
  3. External knowledge-base connections (OWASP, NVD, CVE, exploitdb, etc.)

Non-LLM guarantee: pure regex + keyword matching; zero ML dependencies.

Academic basis:
  - OWASP LLM06: Excessive Agency — FS write tools are highest-risk
  - MITRE ATT&CK T1059: command execution from within agent sandbox
  - RedAmon recon/main_recon_modules/ai_surface_recon.py: OS-intel patterns
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# ── Filesystem risk pattern groups ──

# Patterns indicating READ-WRITE filesystem access (highest risk)
_FS_READ_WRITE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(write|save|create|overwrite|append|modify|edit|patch)\s+(file|path|dir)", re.I),
    re.compile(r"\b(mkdir|rmdir|makedirs|shutil|pathlib)\b", re.I),
    re.compile(r"\b(open\(|fs\.writeFile|fs\.appendFile|write_to_file)\b", re.I),
    re.compile(r"\b(rm\s+-rf|remove|delete|unlink)\s+(file|path|dir)", re.I),
    re.compile(r"\b(chmod|chown|mv|cp|rename|move)\b", re.I),
]

# Patterns indicating READ-ONLY filesystem access (medium risk)
_FS_READ_ONLY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(read|get|list|cat|head|tail|view)\s+(file|path|dir)", re.I),
    re.compile(r"\b(ls|dir|glob|walk|scandir|listdir)\b", re.I),
    re.compile(r"\b(fs\.readFile|fs\.readFileSync|open\(.*['\"']r['\"'])\b", re.I),
    re.compile(r"\b(os\.listdir|os\.walk|glob\.glob|pathlib\.Path)\b", re.I),
]

# ── Sandbox detection patterns ──

_SANDBOX_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\b(docker|container|podman|kubernetes|k8s)\b", re.I),
     "container", "Container-based sandbox detected"),
    (re.compile(r"\b(chroot|jail|sandbox|isolated)\b", re.I),
     "chroot", "Chroot/jail sandbox detected"),
    (re.compile(r"\b(restricted|read.only|no.?write|immutable)\s+(filesystem|path|directory)\b", re.I),
     "restricted_fs", "Restricted filesystem access detected"),
    (re.compile(r"\b(/tmp|/var/tmp|/dev/shm)\b", re.I),
     "temp_only", "Write access likely limited to temp directories"),
    (re.compile(r"\b(no.?network|offline|air.?gapped|isolated)\b", re.I),
     "network_isolated", "Network isolation detected"),
    (re.compile(r"\b(deno|gvisor|firecracker|kata|nabla)\b", re.I),
     "microvm", "MicroVM sandbox detected"),
]

# ── Knowledge base integration patterns ──

_KNOWLEDGE_BASE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\b(owasp\.org|owasp\s+top\s+10)", re.I),
     "owasp", "OWASP knowledge base integration"),
    (re.compile(r"\b(nvd\.nist\.gov|nist\.gov/vuln|cve\.mitre\.org|cve-\d{4}-\d{4,})", re.I),
     "nvd_cve", "NVD/CVE vulnerability database integration"),
    (re.compile(r"\b(exploit[\s-]?db|exploit-db\.com|rapid7|metasploit)", re.I),
     "exploitdb", "ExploitDB / Metasploit knowledge integration"),
    (re.compile(r"\b(github\.com/advisories|GHSA-|security\s+advisory)", re.I),
     "ghsa", "GitHub Security Advisory integration"),
    (re.compile(r"\b(wikipedia\.org|wiki|knowledge\s+base|rag|vector\s+(db|store))", re.I),
     "general_kb", "General knowledge base / RAG integration"),
    (re.compile(r"\b(arxiv\.org|acm\.org|ieee\.org|scholar\.google)", re.I),
     "academic", "Academic paper database integration"),
    (re.compile(r"\b(censys\.io|shodan\.io|fofa\.info|zoomeye\.org)", re.I),
     "osint", "OSINT platform integration"),
    (re.compile(r"\b(huggingface\.co|pypi\.org|npmjs\.com|modelscope)", re.I),
     "model_registry", "Model/package registry integration"),
]


@dataclass
class WorkspaceFinding:
    """A single workspace security finding."""

    category: str = ""   # "fs_rw" | "fs_ro" | "sandbox" | "knowledge_base"
    subcategory: str = ""  # sandbox type or KB source
    severity: str = ""   # "critical" | "high" | "medium" | "low" | "info"
    detail: str = ""
    source_url: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "subcategory": self.subcategory,
            "severity": self.severity,
            "detail": self.detail,
            "source_url": self.source_url,
            "evidence": self.evidence[:200],
        }


@dataclass
class WorkspaceReport:
    """Aggregate workspace security report."""

    findings: list[WorkspaceFinding] = field(default_factory=list)
    fs_read_write_tools: list[str] = field(default_factory=list)
    fs_read_only_tools: list[str] = field(default_factory=list)
    sandbox_type: str = "unknown"
    knowledge_bases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "fs_read_write_tools": self.fs_read_write_tools,
            "fs_read_only_tools": self.fs_read_only_tools,
            "sandbox_type": self.sandbox_type,
            "knowledge_bases": self.knowledge_bases,
            "total_findings": len(self.findings),
            "critical_findings": sum(1 for f in self.findings if f.severity == "critical"),
            "high_findings": sum(1 for f in self.findings if f.severity == "high"),
        }


class AgentWorkspaceProbe(ReconProbe):
    """Agent workspace security probe.

    Analyzes agent tool descriptions and HTTP responses for:
      1. Filesystem permission scope (read-only vs read-write)
      2. Sandbox isolation level
      3. External knowledge-base connections

    Usage::
        probe = AgentWorkspaceProbe()
        result = await probe.probe(session)
        # result["workspace"] → WorkspaceReport
    """

    @property
    def name(self) -> str:
        return "AgentWorkspaceProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute workspace security analysis.

        Args:
            session: Recon session.

        Returns:
            Dict with workspace report and summary.
        """
        report = WorkspaceReport()

        # 1. Analyze MCP tools
        for tool in session.report.mcp_tools:
            text = f"{tool.tool_name} {tool.description}"
            self._analyze_tool_text(text, tool.tool_name, tool.server_url, report)

        # 2. Analyze agent endpoints (from endpoint body previews)
        for ep in session.report.endpoints:
            if ep.response_body_preview:
                self._analyze_tool_text(
                    ep.response_body_preview,
                    ep.ai_framework_name or ep.url,
                    ep.url,
                    report,
                )

        # 3. Also check probe_results for tool descriptions
        for probe_name, result in session.report.probe_results.items():
            tools = result.get("mcp_tools", [])
            if isinstance(tools, list):
                for tool_data in tools:
                    if isinstance(tool_data, dict):
                        text = f"{tool_data.get('tool_name', '')} {tool_data.get('description', '')}"
                        self._analyze_tool_text(
                            text,
                            tool_data.get("tool_name", "unknown"),
                            tool_data.get("server_url", ""),
                            report,
                        )

        logger.info(
            "AgentWorkspaceProbe: %d findings, %d RW tools, %d KB sources, sandbox=%s",
            len(report.findings), len(report.fs_read_write_tools),
            len(report.knowledge_bases), report.sandbox_type,
        )

        return {
            "workspace": report.to_dict(),
            "summary": {
                "total_findings": len(report.findings),
                "fs_read_write_tools": report.fs_read_write_tools,
                "fs_read_only_tools": report.fs_read_only_tools,
                "sandbox_type": report.sandbox_type,
                "knowledge_bases": report.knowledge_bases,
                "critical_count": sum(1 for f in report.findings if f.severity == "critical"),
                "high_count": sum(1 for f in report.findings if f.severity == "high"),
            },
        }

    def _analyze_tool_text(
        self,
        text: str,
        tool_name: str,
        source_url: str,
        report: WorkspaceReport,
    ) -> None:
        """Analyze tool text for workspace security findings."""
        if not text:
            return

        # ── Filesystem: Read-Write ──
        for pattern in _FS_READ_WRITE_PATTERNS:
            m = pattern.search(text)
            if m:
                report.fs_read_write_tools.append(tool_name)
                report.findings.append(WorkspaceFinding(
                    category="fs_rw",
                    subcategory="read_write",
                    severity="critical",
                    detail=f"Tool '{tool_name}' enables filesystem write: {m.group()}",
                    source_url=source_url,
                    evidence=m.group(),
                ))
                break  # One RW match is enough

        # ── Filesystem: Read-Only ──
        if tool_name not in report.fs_read_write_tools:
            for pattern in _FS_READ_ONLY_PATTERNS:
                m = pattern.search(text)
                if m:
                    report.fs_read_only_tools.append(tool_name)
                    report.findings.append(WorkspaceFinding(
                        category="fs_ro",
                        subcategory="read_only",
                        severity="medium",
                        detail=f"Tool '{tool_name}' has filesystem read access: {m.group()}",
                        source_url=source_url,
                        evidence=m.group(),
                    ))
                    break

        # ── Sandbox detection ──
        for pattern, sandbox_type, detail in _SANDBOX_PATTERNS:
            if pattern.search(text):
                if report.sandbox_type == "unknown":
                    report.sandbox_type = sandbox_type
                report.findings.append(WorkspaceFinding(
                    category="sandbox",
                    subcategory=sandbox_type,
                    severity="info",
                    detail=detail,
                    source_url=source_url,
                    evidence=pattern.search(text).group() if pattern.search(text) else "",
                ))

        # ── Knowledge base integration ──
        for pattern, kb_type, detail in _KNOWLEDGE_BASE_PATTERNS:
            if pattern.search(text):
                if kb_type not in report.knowledge_bases:
                    report.knowledge_bases.append(kb_type)
                report.findings.append(WorkspaceFinding(
                    category="knowledge_base",
                    subcategory=kb_type,
                    severity="medium",
                    detail=detail,
                    source_url=source_url,
                    evidence=pattern.search(text).group() if pattern.search(text) else "",
                ))
