# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Python 临时文件清理器 (规则 R-005)。.

运行后 (含异常退出) 自动清理 __pycache__ 目录、
.pyc/.pyo 文件和 .pytest_cache 目录，确保下次运行从干净状态开始。

运行前不清理 — Python 通过 mtime+size 校验自动管理缓存失效,
编辑代码后仅需重编译被修改的文件, 避免每次全量重编译的开销 (~8s)。

报告文件 (outputs/) 不受影响，保留供人工审查。
"""

from __future__ import annotations

import shutil
from pathlib import Path

#: 项目根目录
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

#: 需要清理的临时目录模式
_TEMP_DIR_PATTERNS = ("__pycache__", ".pytest_cache")

#: 需要清理的临时文件模式
_TEMP_FILE_PATTERNS = ("*.pyc", "*.pyo")


def clean_temp_files(phase: str = "pre") -> int:
    """清理项目中的 Python 临时文件。.

    规则 R-005: 静默执行，不输出到 stdout。

    Args:
        phase: 清理阶段 ("post" — 运行后/异常退出后清理; "pre" 保留兼容但不主动调用)

    Returns:
        清理的文件/目录数
    """
    removed = 0

    for pattern in _TEMP_DIR_PATTERNS:
        for temp_dir in _PROJECT_ROOT.rglob(pattern):
            if temp_dir.is_dir():
                shutil.rmtree(temp_dir, ignore_errors=True)
                removed += 1

    for pattern in _TEMP_FILE_PATTERNS:
        for temp_file in _PROJECT_ROOT.rglob(pattern):
            if temp_file.is_file():
                temp_file.unlink(missing_ok=True)
                removed += 1

    return removed
