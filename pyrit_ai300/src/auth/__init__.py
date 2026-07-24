"""
Auth Module
============

本模块负责认证适配层，为不同认证类型创建已认证的 PromptTarget。
"""

from src.auth.auth_adapter import (
    AuthAdapter,
    create_authenticated_target,
)

__all__ = [
    "AuthAdapter",
    "create_authenticated_target",
]