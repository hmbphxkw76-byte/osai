# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Python 临时文件清理器 (规则 R-008)。

每次运行流水线前和运行后自动清理 __pycache__ 目录、
.pyc/.pyo 文件和 .pytest_cache 目录，确保干净的字节码缓存。

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
    """清理项目中的 Python 临时文件。

    规则 R-008: 静默执行，不输出到 stdout。

    Args:
        phase: 清理阶段 ("pre" 或 "post")

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
