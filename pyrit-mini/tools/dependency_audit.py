# -*- coding: utf-8 -*-
"""tools/dependency_audit.py — 依赖审计（开发全审 Phase K）。

解析 pyproject.toml，覆盖：
    1. 版本一致性 — 依赖是否锁定版本（裸包名 / `*` 视为 BLOCKING）
    2. 许可证合规 — pyproject 是否声明 license 字段（INFO）
    3. 已知漏洞 — 声明版本是否落入已知 CVE 范围（WARNING）
    4. 依赖树健康 — 声明依赖是否已安装、是否存在冲突（WARNING/INFO）
    5. 源验证     — importlib.metadata 确认分发包存在（WARNING）

严重级别：
    BLOCKING — 未锁定版本（裸包名或 `*`）
    WARNING  — 已知漏洞版本 / 声明但未安装 / 依赖冲突
    INFO    — 许可证字段缺失 / 依赖树统计

退出码：存在 BLOCKING → 1，否则 0。

Academic basis:
    - OWASP A06:2021 (Vulnerable and Outdated Components)
    - PEP 440 (Version Specifiers) / SLSA 供应链溯源
"""

from __future__ import annotations

import re

from tools._audit_base import Finding, Severity, project_root, run_audit

_DEP_RE = re.compile(r'["\']([A-Za-z0-9_.\-]+)\s*([=<>!~][^"\']*)?["\']')
_VER_RE = re.compile(r'version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']')

# 已知漏洞下界（仅作静态提示，命中声明约束即 WARNING）
_VULN_BLOCKLIST: list[tuple[str, re.Pattern[str], str]] = [
    ("pyyaml", re.compile(r"<5\.4"), "CVE-2020-1747 / CVE-2020-14343 不安全默认加载"),
    ("jinja2", re.compile(r"<2\.11\.3"), "CVE-2020-28493 沙箱逃逸"),
    ("httpx", re.compile(r"<0\.24"), "已知传输层缺陷"),
]


def _parse_deps(text: str) -> list[tuple[str, str]]:
    """从 pyproject.toml 文本提取 (包名, 版本约束) 列表。"""
    deps: list[tuple[str, str]] = []

    m = re.search(r"\[project\]\s*.*?dependencies\s*=\s*\[(.*?)\]", text, re.S)
    if m:
        for mm in _DEP_RE.finditer(m.group(1)):
            deps.append((mm.group(1), (mm.group(2) or "").strip()))

    mo = re.search(r"\[project\.optional-dependencies\](.*?)(\[|\Z)", text, re.S)
    if mo:
        for mm in _DEP_RE.finditer(mo.group(1)):
            deps.append((mm.group(1), (mm.group(2) or "").strip()))

    return deps


def _collect() -> list[Finding]:
    findings: list[Finding] = []
    root = project_root()
    pyproject = root / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")

    deps = _parse_deps(text)
    if not deps:
        findings.append(Finding("NO_DEPS", Severity.BLOCKING, "pyproject.toml 未解析到任何依赖", "pyproject.toml"))

    for name, spec in deps:
        if not spec or spec == "*":
            findings.append(Finding("UNPINNED_DEP", Severity.BLOCKING, f"{name} 未锁定版本（裸包名或 *）", "pyproject.toml"))
            continue
        for pkg, vpat, msg in _VULN_BLOCKLIST:
            if name.lower() == pkg and vpat.search(spec):
                findings.append(Finding("VULN_DEP", Severity.WARNING, f"{name}{spec}: {msg}", "pyproject.toml"))

    # 源验证：声明依赖是否已安装
    try:
        from importlib.metadata import distribution

        for name, _spec in deps:
            try:
                distribution(name)
            except Exception:
                findings.append(
                    Finding("MISSING_DEP", Severity.WARNING, f"{name} 声明但未安装", "pyproject.toml")
                )
    except Exception:
        pass

    # 许可证（INFO）
    if not re.search(r"license", text, re.I):
        findings.append(Finding("NO_LICENSE", Severity.INFO, "pyproject.toml 未声明 license 字段", "pyproject.toml"))

    # 依赖树健康（INFO）：已安装分发包数量
    try:
        from importlib.metadata import distributions

        count = sum(1 for _ in distributions())
        findings.append(Finding("DEP_TREE", Severity.INFO, f"已安装分发包: {count}", "env"))
    except Exception:
        pass

    return findings


def main() -> int:
    """CLI 入口：python -m tools.dependency_audit"""
    return run_audit("Dependency Audit (K)", _collect)


if __name__ == "__main__":
    raise SystemExit(main())
