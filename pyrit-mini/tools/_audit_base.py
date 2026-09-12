# -*- coding: utf-8 -*-
"""tools/_audit_base.py — 开发全审 I–L 四个审计模块（安全/测试/依赖/发布）共享的轻量基座。

提供统一的严重级别、发现项结构、源码遍历与报告打印，避免四个模块重复样板。
各审计模块只需实现 `_collect() -> list[Finding]` 并调用 `run_audit(title, _collect)`。

Constitution: C9（诚实汇报：发现项按 BLOCKING/WARNING/INFO 分级，不静默吞掉）。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Callable, Iterable


class Severity(IntEnum):
    """审计发现项严重级别（数值越大越严重）。"""

    INFO = 0
    WARNING = 1
    BLOCKING = 2


@dataclass
class Finding:
    """单条审计发现。"""

    rule: str
    severity: Severity
    message: str
    location: str = ""


# 扫描时需跳过的目录（非项目源码 / 生成物 / 第三方）
_EXCLUDE_DIRS = {
    "outputs",
    ".assistant_pyrit",
    ".venv",
    "node_modules",
    "__pycache__",
    ".git",
    "tests",
    "data",
    "build",
    "dist",
}

# 审计基础设施自身：避免审计模块扫描自身源码造成误报（如检测规则文本中的字面量）
_EXCLUDE_FILES = {
    "_audit_base.py",
    "security_audit.py",
    "test_audit.py",
    "dependency_audit.py",
    "release_audit.py",
}


def project_root() -> Path:
    """返回项目根目录（tools/ 的上一级）。"""
    return Path(__file__).resolve().parent.parent


def iter_source_files(root: Path | None = None, include_tests: bool = False) -> Iterable[Path]:
    """遍历项目内所有 .py 源文件。

    Args:
        root: 根目录（默认项目根）。
        include_tests: 是否包含 tests/ 与 data/（默认仅扫描生产源码）。
    """
    base = root or project_root()
    for path in base.rglob("*.py"):
        if path.name in _EXCLUDE_FILES:
            continue
        parts = set(path.parts)
        if not include_tests and (parts & _EXCLUDE_DIRS):
            continue
        if ".venv" in path.parts or "node_modules" in path.parts:
            continue
        yield path


def print_report(title: str, findings: list[Finding]) -> int:
    """打印分级报告并返回退出码（存在 BLOCKING → 1，否则 0）。"""
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    width = 70
    print("=" * width)
    print(f"{title:^{width}}")
    print("=" * width)
    for sev in (Severity.BLOCKING, Severity.WARNING, Severity.INFO):
        for f in findings:
            if f.severity == sev:
                loc = f" ({f.location})" if f.location else ""
                print(f"  [{sev.name}] {f.rule}: {f.message}{loc}")
    if not findings:
        print("  (no findings)")

    print("-" * width)
    print(
        f"  BLOCKING={counts[Severity.BLOCKING]} "
        f"WARNING={counts[Severity.WARNING]} "
        f"INFO={counts[Severity.INFO]}"
    )
    print("=" * width)
    return 1 if counts[Severity.BLOCKING] > 0 else 0


def run_audit(title: str, collect: Callable[[], list[Finding]]) -> int:
    """执行收集并输出报告，返回退出码。"""
    try:
        findings = collect()
    except Exception as e:  # 审计自身异常不应静默通过
        findings = [Finding("AUDIT_ERROR", Severity.BLOCKING, f"审计执行异常: {e}")]
    return print_report(title, findings)
