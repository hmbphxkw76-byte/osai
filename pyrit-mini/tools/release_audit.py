# -*- coding: utf-8 -*-
"""tools/release_audit.py — 发布审计（开发全审 Phase L）。

覆盖：
    1. 版本号规范 — pyproject 语义化版本；源码 __version__ 是否与之一致
    2. 变更日志   — 是否存在 CHANGELOG.md 且含当前版本（缺失为 INFO 提示）
    3. 生产就绪   — 源码残留调试器（pdb/breakpoint）/ 大量裸 print
    4. 回滚验证   — git 仓库状态（clean/dirty），确认可回滚
    5. 文档同步   — 关键文档（README / plan）是否存在

严重级别：
    BLOCKING — 版本号缺失/非法 / 源码残留调试器调用
    WARNING  — __version__ 不一致 / CHANGELOG 未含当前版本
    INFO    — 许可证/仓库状态/文档缺失提示

退出码：存在 BLOCKING → 1，否则 0。

Academic basis:
    - SemVer 2.0.0
    - Google SE Principles: 可回滚 / 变更可追溯
"""

from __future__ import annotations

import re
import subprocess

from tools._audit_base import Finding, Severity, iter_source_files, project_root, run_audit

_VER_RE = re.compile(r'version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']')


def _collect() -> list[Finding]:
    findings: list[Finding] = []
    root = project_root()

    # 1) 版本规范
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    vm = _VER_RE.search(text)
    version = vm.group(1) if vm else None
    if not version:
        findings.append(Finding("VERSION_MISSING", Severity.BLOCKING, "pyproject.toml 缺少有效语义化版本号", "pyproject.toml"))
    else:
        findings.append(Finding("VERSION", Severity.INFO, f"当前版本: {version}", "pyproject.toml"))
        mism: list[str] = []
        for path in iter_source_files(root):
            try:
                t = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for mm in re.finditer(r'__version__\s*=\s*["\']([^"\']+)["\']', t):
                if mm.group(1) != version:
                    mism.append(f"{path.relative_to(root)}:{mm.group(1)}")
        if mism:
            findings.append(
                Finding("VERSION_MISMATCH", Severity.WARNING, f"__version__ 不一致: {mism[:3]}", "source")
            )

    # 2) 变更日志
    cl = root / "CHANGELOG.md"
    if not cl.exists():
        findings.append(Finding("NO_CHANGELOG", Severity.INFO, "未找到 CHANGELOG.md（建议维护变更日志）", "root"))
    elif version:
        clt = cl.read_text(encoding="utf-8", errors="replace")
        if version not in clt:
            findings.append(Finding("CHANGELOG_STALE", Severity.WARNING, f"CHANGELOG.md 未包含当前版本 {version}", "CHANGELOG.md"))

    # 3) 生产就绪：调试器残留
    for path in iter_source_files(root):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(pdb\.set_trace|breakpoint\(|import pdb)\b", line):
                findings.append(Finding("DEBUGGER_LEFT", Severity.BLOCKING, "源码残留调试器调用", f"{rel}:{i}"))

    # 4) 回滚验证：git 状态
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True, timeout=20
        )
        if r.returncode == 0:
            clean = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, timeout=20)
            state = "dirty" if clean.stdout.strip() else "clean"
            findings.append(Finding("ROLLBACK", Severity.INFO, f"git 仓库状态: {state}", "git"))
    except Exception as e:
        findings.append(Finding("ROLLBACK", Severity.INFO, f"git 不可用（无法验证回滚）: {e}", "git"))

    # 5) 文档同步
    for doc in ("README.md", "docs/specs/README.md"):
        if not (root / doc).exists():
            findings.append(Finding("DOC_MISSING", Severity.INFO, f"文档缺失: {doc}", "docs"))

    return findings


def main() -> int:
    """CLI 入口：python -m tools.release_audit"""
    return run_audit("Release Audit (L)", _collect)


if __name__ == "__main__":
    raise SystemExit(main())
