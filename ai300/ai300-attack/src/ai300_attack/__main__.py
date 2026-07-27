# -*- coding: utf-8 -*-
"""
支持 `python -m ai300_attack` 直接运行 CLI。
"""

from __future__ import annotations

import sys

from .main import main

if __name__ == "__main__":
    sys.exit(main())
