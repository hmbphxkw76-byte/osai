"""PyRIT 集成模块（向后兼容 shim）—— AI-300 攻击引擎核心。

**注意**：此文件为向后兼容层，实际实现已迁移到 attack/core/runner.py。
请使用新的导入路径：
    from redteam.attack.core import PyRITAttackRunner

保留原有 API 签名以确保向后兼容。
"""

from redteam.attack.core.runner import (
    PyRITAttackRunner,
    is_pyrit_available,
    pyrit_version,
    CONVERTER_MAP,
)

__all__ = [
    "PyRITAttackRunner",
    "is_pyrit_available",
    "pyrit_version",
    "CONVERTER_MAP",
]