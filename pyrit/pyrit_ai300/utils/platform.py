# -*- coding: utf-8 -*-
"""
AI-300 Framework - Platform Utilities
Windows UTF-8 兼容性设置

解决 Windows 默认 GBK 编码导致 Rich Console、logging 输出中文时
报 UnicodeEncodeError 的问题。

只需在包入口 __init__.py 中调用一次 setup_windows_utf8()，
无需在每个模块文件中重复编写。
"""

from __future__ import annotations

import os
import sys


def setup_windows_utf8() -> None:
    """
    在 Windows 平台上配置 UTF-8 编码

    在所有平台调用是安全的，仅在 win32 上执行实际配置。
    建议在包的 __init__.py 中最先调用。
    """
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        os.environ["PYTHONIOENCODING"] = "utf-8"


# 模块导入时自动执行（确保子模块也能正常输出中文）
setup_windows_utf8()
