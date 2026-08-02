# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""供应链安全模块 — SBOM 依赖扫描 (LLM03).

扫描项目依赖文件 (requirements.txt, pyproject.toml, package.json),
与已知漏洞库比对, 识别供应链安全风险。

OWASP 2025 映射:
  - LLM03: Supply Chain Vulnerabilities — 第三方依赖中的已知漏洞

学术依据:
  - OWASP Top 10 for LLM Applications 2025: LLM03 Supply Chain
  - MITRE ATT&CK T1195: Supply Chain Compromise
  - NIST SP 800-161: Supply Chain Risk Management Practices

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DependencyVulnerability:
    """依赖漏洞信息.

    Attributes:
        package: 包名。
        installed_version: 已安装版本。
        vulnerability_id: 漏洞 ID (CVE/GHSA)。
        severity: 严重程度 (critical/high/medium/low)。
        description: 漏洞描述。
        fixed_version: 修复版本 (如有)。
    """

    package: str = ""
    installed_version: str = ""
    vulnerability_id: str = ""
    severity: str = "unknown"
    description: str = ""
    fixed_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "vulnerability_id": self.vulnerability_id,
            "severity": self.severity,
            "description": self.description,
            "fixed_version": self.fixed_version,
        }


@dataclass
class SBOMReport:
    """SBOM 扫描报告.

    Attributes:
        total_dependencies: 总依赖数。
        vulnerable_dependencies: 有漏洞的依赖数。
        vulnerabilities: 漏洞列表。
        scan_duration_seconds: 扫描耗时。
        source_file: 依赖文件路径。
    """

    total_dependencies: int = 0
    vulnerable_dependencies: int = 0
    vulnerabilities: list[DependencyVulnerability] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    source_file: str = ""

    @property
    def critical_count(self) -> int:
        """CRITICAL 漏洞数。."""
        return sum(1 for v in self.vulnerabilities if v.severity == "critical")

    @property
    def high_count(self) -> int:
        """HIGH 漏洞数。."""
        return sum(1 for v in self.vulnerabilities if v.severity == "high")

    @property
    def risk_score(self) -> int:
        """供应链风险评分 (0-100)。."""
        score = (
            self.critical_count * 30
            + self.high_count * 15
            + sum(1 for v in self.vulnerabilities if v.severity == "medium") * 5
            + sum(1 for v in self.vulnerabilities if v.severity == "low") * 1
        )
        return min(score, 100)

    def summary(self) -> str:
        """人类可读摘要。."""
        lines = [
            "SBOM Report Summary:",
            f"  Source: {self.source_file}",
            f"  Total dependencies: {self.total_dependencies}",
            f"  Vulnerable: {self.vulnerable_dependencies}",
            f"  CRITICAL: {self.critical_count}",
            f"  HIGH: {self.high_count}",
            f"  Risk Score: {self.risk_score}/100",
        ]
        for v in self.vulnerabilities[:10]:
            lines.append(
                f"  [{v.severity.upper():>8}] {v.package} {v.installed_version} — {v.vulnerability_id}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "total_dependencies": self.total_dependencies,
            "vulnerable_dependencies": self.vulnerable_dependencies,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_duration_seconds": self.scan_duration_seconds,
            "source_file": self.source_file,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "risk_score": self.risk_score,
        }


# ── 已知漏洞规则 (简化版, 实际应使用 pip-audit / safety 数据库) ──
# (包名正则, 受影响版本范围, CVE ID, 严重程度, 描述, 修复版本)
_KNOWN_VULNERABILITIES: list[tuple[str, str, str, str, str, str | None]] = [
    ("transformers", "<4.36.0", "CVE-2023-7104", "high",
     "Barney Pelchat 模型反序列化 RCE", "4.36.0"),
    ("torch", "<2.1.2", "CVE-2024-2197", "high",
     "PyTorch RPC 远程代码执行", "2.1.2"),
    ("langchain", "<0.0.315", "CVE-2023-36188", "critical",
     "LangChain arbitrary code execution via prompt injection", "0.0.315"),
    ("llama-index", "<0.9.15", "CVE-2024-1023", "high",
     "LlamaIndex SSRF via document loader", "0.9.15"),
    ("openai", "<1.0.0", "CVE-2023-6796", "medium",
     "OpenAI Python SDK 密钥泄露 (日志记录)", "1.0.0"),
    ("pillow", "<10.0.1", "CVE-2023-44271", "high",
     "Pillow DoS via crafted image", "10.0.1"),
    ("aiohttp", "<3.9.0", "CVE-2023-49083", "high",
     "aioHTTP HTTP 请求走私", "3.9.0"),
    ("requests", "<2.31.0", "CVE-2023-32681", "medium",
     "Requests Proxy-Authorization 泄露", "2.31.0"),
    ("pyyaml", "<6.0.1", "CVE-2020-1747", "high",
     "PyYAML 任意代码执行 (load 函数)", "6.0.1"),
    ("jinja2", "<3.1.3", "CVE-2024-22195", "medium",
     "Jinja2 XSS via xmlattr filter", "3.1.3"),
]


class SBOMScanner:
    """SBOM 依赖扫描器.

    扫描依赖文件, 与已知漏洞库比对。

    用法::
        scanner = SBOMScanner()
        report = scanner.scan("requirements.txt")
        print(report.summary())
    """

    def scan(self, dependency_file: str | Path) -> SBOMReport:
        """扫描依赖文件.

        Args:
            dependency_file: 依赖文件路径 (requirements.txt / pyproject.toml / package.json)。

        Returns:
            SBOMReport 扫描报告。
        """
        import time

        start = time.time()
        file_path = Path(dependency_file)

        if not file_path.exists():
            logger.warning(f"SBOMScanner: file not found: {file_path}")
            return SBOMReport(source_file=str(file_path))

        # 尝试使用 pip-audit (如果可用)
        report = self._try_pip_audit(file_path)
        if report:
            report.scan_duration_seconds = round(time.time() - start, 2)
            return report

        # 回退到内置规则
        report = self._scan_with_builtin_rules(file_path)
        report.scan_duration_seconds = round(time.time() - start, 2)
        return report

    def _try_pip_audit(self, file_path: Path) -> SBOMReport | None:
        """尝试使用 pip-audit 进行扫描。."""
        try:
            import json as json_module
            import subprocess

            result = subprocess.run(
                ["pip-audit", "-r", str(file_path), "-f", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
            )
            if result.returncode == 0 and result.stdout:
                data = json_module.loads(result.stdout)
                report = SBOMReport(source_file=str(file_path))
                report.total_dependencies = len(data.get("dependencies", []))
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        report.vulnerabilities.append(DependencyVulnerability(
                            package=dep.get("name", ""),
                            installed_version=dep.get("version", ""),
                            vulnerability_id=vuln.get("id", ""),
                            severity=(
                                vuln.get("fix_versions", ["unknown"])[0]
                                if vuln.get("fix_versions") else "unknown"
                            ),
                            description=vuln.get("description", ""),
                            fixed_version=vuln.get("fix_versions", [None])[0] if vuln.get("fix_versions") else None,
                        ))
                report.vulnerable_dependencies = len({v.package for v in report.vulnerabilities})
                logger.info(f"SBOMScanner: pip-audit found {len(report.vulnerabilities)} vulnerabilities")
                return report
        except (ImportError, FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            logger.debug(f"SBOMScanner: pip-audit not available or failed: {e}")

        return None

    def _scan_with_builtin_rules(self, file_path: Path) -> SBOMReport:
        """使用内置规则扫描依赖文件。."""
        report = SBOMReport(source_file=str(file_path))

        # 解析依赖文件
        dependencies = self._parse_dependency_file(file_path)
        report.total_dependencies = len(dependencies)

        # 与已知漏洞比对
        for package_name, version in dependencies.items():
            for pkg_pattern, version_range, cve_id, severity, description, fixed_version in _KNOWN_VULNERABILITIES:
                if not re.search(pkg_pattern, package_name, re.IGNORECASE):
                    continue
                if self._version_matches(version, version_range):
                    report.vulnerabilities.append(DependencyVulnerability(
                        package=package_name,
                        installed_version=version,
                        vulnerability_id=cve_id,
                        severity=severity,
                        description=description,
                        fixed_version=fixed_version,
                    ))

        report.vulnerable_dependencies = len({v.package for v in report.vulnerabilities})
        logger.info(
            f"SBOMScanner: builtin rules found {len(report.vulnerabilities)} vulnerabilities "
            f"in {report.vulnerable_dependencies} packages"
        )
        return report

    @staticmethod
    def _parse_dependency_file(file_path: Path) -> dict[str, str]:
        """解析依赖文件, 返回 {包名: 版本} 字典。."""
        dependencies: dict[str, str] = {}

        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"SBOMScanner: cannot read {file_path}: {e}")
            return dependencies

        if file_path.suffix == ".toml":
            # pyproject.toml 简化解析
            for match in re.finditer(
                r'["\']([a-zA-Z0-9_-]+)["\']\s*=\s*["\']([^"\']+)["\']', content
            ):
                pkg, ver = match.group(1), match.group(2)
                if pkg and ver and not pkg.startswith("_"):
                    dependencies[pkg] = ver
        elif file_path.suffix == ".json":
            # package.json 简化解析
            import json as json_module

            try:
                data = json_module.loads(content)
                for section in ("dependencies", "devDependencies"):
                    for pkg, ver in data.get(section, {}).items():
                        # npm 版本格式: ^1.0.0, ~2.3.0, >=3.0.0
                        clean_ver = re.sub(r"[^0-9.]", "", ver)
                        if clean_ver:
                            dependencies[pkg] = clean_ver
            except json_module.JSONDecodeError:
                pass
        else:
            # requirements.txt 格式: package==version
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                # package==1.0.0 或 package>=1.0.0
                match = re.match(r"^([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([0-9][0-9a-zA-Z.\-]*)", line)
                if match:
                    dependencies[match.group(1)] = match.group(2)

        return dependencies

    @staticmethod
    def _version_matches(version: str, version_range: str) -> bool:
        """检查版本是否在受影响范围内 (简化实现)。."""
        try:
            range_op = version_range[:2] if version_range[:2] in ("<", ">", ">=", "<=", "==", "!=") else "<"
            range_ver_str = version_range.lstrip("<>=!~")

            # 简化比较: 按数字段比较
            installed_parts = [int(x) for x in re.findall(r"\d+", version)]
            range_parts = [int(x) for x in re.findall(r"\d+", range_ver_str)]

            if not installed_parts or not range_parts:
                return False

            # 填充到相同长度
            max_len = max(len(installed_parts), len(range_parts))
            installed_parts.extend([0] * (max_len - len(installed_parts)))
            range_parts.extend([0] * (max_len - len(range_parts)))

            _compare_ops = {
                "<": lambda a, b: a < b,
                "<=": lambda a, b: a <= b,
                ">": lambda a, b: a > b,
                ">=": lambda a, b: a >= b,
                "==": lambda a, b: a == b,
            }
            if range_op in _compare_ops:
                return _compare_ops[range_op](installed_parts, range_parts)
            return False
        except (ValueError, IndexError):
            return False


# ── 模型权重校验 (LLM03 增强) ──
# 从 weight_verifier 模块导入
from pipeline.supply_chain.weight_verifier import (  # noqa: E402
    WeightVerificationReport,
    WeightVerificationResult,
    WeightVerifier,
)

__all__ = [
    "DependencyVulnerability",
    "SBOMReport",
    "SBOMScanner",
    "WeightVerificationReport",
    "WeightVerificationResult",
    "WeightVerifier",
]
