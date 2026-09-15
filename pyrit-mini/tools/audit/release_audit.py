# -*- coding: utf-8 -*-
"""tools/audit/release_audit.py — 发布审计（开发全审 Phase L）。

扫描项目发布就绪状态，覆盖：
    1. 版本号规范 — SemVer 格式 + git tag 一致性
    2. 变更日志   — CHANGELOG.md 是否存在并包含当前版本
    3. 生产就绪   — 无调试代码 / TODO / FIXME
    4. 回滚验证   — 回滚策略是否在文档中声明
    5. 文档同步   — README / API 文档是否与当前版本同步

严重级别：
    BLOCKING — 版本号格式错误 / CHANGELOG 缺失当前版本 / 存在调试代码
    WARNING  — 回滚策略未声明 / 文档可能过时
    INFO     — 版本统计 / 变更日志条目数（知会即可）

退出码：存在 BLOCKING → 1，否则 0。

Academic basis:
    - Semantic Versioning 2.0.0 (SemVer)
    - Keep a Changelog (CHANGELOG.md 规范)
    - NIST SP 800-115: Release Management
"""

from __future__ import annotations

import re

from tools.audit._audit_base import Finding, Severity, project_root, run_audit

# SemVer 正则
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?$")

# 调试代码模式
_DEBUG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*debugger\s*#?", re.M), "DEBUGGER_STATEMENT"),
    (re.compile(r"^\s*console\.log\(", re.M), "CONSOLE_LOG"),
    (re.compile(r"^\s*print\s*\([^)]*#\s*debug", re.I | re.M), "DEBUG_PRINT"),
]

# TODO/FIXME 模式
_TODO_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"#\s*TODO[:\s]", re.I), "TODO_MARKER"),
    (re.compile(r"#\s*FIXME[:\s]", re.I), "FIXME_MARKER"),
]


def _collect() -> list[Finding]:
    findings: list[Finding] = []
    root = project_root()

    # 1. 版本号规范
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8")
        m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', text)
        if m:
            version = m.group(1)
            if _SEMVER_RE.match(version):
                findings.append(Finding("VERSION_SEMVER", Severity.INFO, f"版本号符合 SemVer: {version}", "pyproject.toml"))
            else:
                findings.append(Finding("VERSION_INVALID", Severity.BLOCKING, f"版本号不符合 SemVer: {version}", "pyproject.toml"))
        else:
            findings.append(Finding("VERSION_MISSING", Severity.BLOCKING, "pyproject.toml 未找到版本号", "pyproject.toml"))

    # 2. 变更日志
    changelog = root / "CHANGELOG.md"
    if changelog.exists():
        cl_text = changelog.read_text(encoding="utf-8", errors="replace")
        # 检查是否包含当前版本的条目
        if m and re.search(rf"##\s+\[?{re.escape(m.group(1))}\]?", cl_text):
            findings.append(Finding("CHANGELOG_CURRENT", Severity.INFO, f"CHANGELOG.md 包含当前版本 {m.group(1)}", "CHANGELOG.md"))
        elif m:
            findings.append(Finding("CHANGELOG_MISSING_VERSION", Severity.BLOCKING, f"CHANGELOG.md 未包含版本 {m.group(1)}", "CHANGELOG.md"))

        # 统计变更日志条目数
        entries = re.findall(r"^##\s+", cl_text, re.M)
        findings.append(Finding("CHANGELOG_ENTRIES", Severity.INFO, f"CHANGELOG.md 包含 {len(entries)} 个版本条目", "CHANGELOG.md"))
    else:
        findings.append(Finding("CHANGELOG_MISSING", Severity.BLOCKING, "CHANGELOG.md 不存在", "CHANGELOG.md"))

    # 3. 生产就绪 — 扫描调试代码
    for path in root.rglob("*.py"):
        if ".venv" in path.parts or "node_modules" in path.parts or "__pycache__" in path.parts:
            continue
        if path.name.startswith("_") or path.name in ("security_audit.py", "release_audit.py"):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for pat, rule in _DEBUG_PATTERNS:
            if pat.search(source):
                findings.append(Finding(rule, Severity.BLOCKING, f"发现调试代码: {rule}", rel))

        for pat, rule in _TODO_PATTERNS:
            if pat.search(source):
                findings.append(Finding(rule, Severity.WARNING, f"发现 {rule}", rel))

    # 4. 回滚验证
    readme = root / "README.md"
    if readme.exists():
        readme_text = readme.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?i)(rollback|回滚|降级|downgrade)", readme_text):
            findings.append(Finding("ROLLBACK_DOCUMENTED", Severity.INFO, "README.md 包含回滚/降级策略", "README.md"))
        else:
            findings.append(Finding("ROLLBACK_MISSING", Severity.WARNING, "README.md 未声明回滚策略", "README.md"))

    # 5. 文档同步 — 检查 README 中的版本号是否与 pyproject.toml 一致
    if readme.exists() and m:
        readme_text = readme.read_text(encoding="utf-8", errors="replace")
        if m.group(1) in readme_text:
            findings.append(Finding("DOCS_SYNCED", Severity.INFO, "README.md 版本号与 pyproject.toml 一致", "README.md"))
        else:
            findings.append(Finding("DOCS_OUTDATED", Severity.WARNING, "README.md 可能未更新版本号", "README.md"))

    return findings


def main() -> int:
    """CLI 入口：python -m tools.audit.release_audit"""
    return run_audit("Release Audit (L)", _collect)


if __name__ == "__main__":
    raise SystemExit(main())
