# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""代理文件: 实际实现已迁移到 core.auth.auth_detector。

此文件仅用于向后兼容, 保证 web_bridge 内部的
from web_bridge.auth.auth_detector import AuthDetector 仍然可用。
"""

from core.auth.auth_detector import *  # noqa: F401,F403
