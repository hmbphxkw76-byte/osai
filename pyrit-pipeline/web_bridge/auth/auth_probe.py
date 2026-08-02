# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""代理文件: 实际实现已迁移到 core.auth.auth_probe。"""

from core.auth.auth_probe import *  # noqa: F401,F403
from core.auth.auth_probe import (  # noqa: F401
    _extract_domain,
    _is_login_path,
)
