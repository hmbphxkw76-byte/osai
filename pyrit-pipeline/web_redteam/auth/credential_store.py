# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""凭据集中管理 — 从 ``.env`` / YAML / 运行时统一加载认证凭据。

设计原则 (R-022: PyRIT 原生优先):
  - 纯数据层模块, 不执行认证操作
  - 消除硬编码凭据, 所有凭据从环境变量或配置文件加载

> **日期**: 2026-8-4
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class CredentialStore:
    """凭据集中管理 — 从 ``.env`` / YAML / 运行时统一加载。

    消除散落在各模块中的硬编码凭据和 ``os.environ.get`` 调用。
    所有凭据获取都通过此模块统一入口。

    用法:::

        from web_redteam.auth.credential_store import CredentialStore

        # 获取环境变量凭据
        api_key = CredentialStore.get_credential("API_KEY")
    """

    @staticmethod
    def get_credential(name: str, default: str = "") -> str:
        """从环境变量获取凭据。

        Args:
            name: 环境变量名 (如 ``API_KEY``, ``OPENAI_CHAT_KEY``)。
            default: 默认值 (环境变量未设置时返回)。

        Returns:
            凭据字符串。
        """
        return os.getenv(name, default)

    @staticmethod
    def get_required_credential(name: str) -> str:
        """从环境变量获取必需凭据。

        Args:
            name: 环境变量名。

        Returns:
            凭据字符串。

        Raises:
            ValueError: 环境变量未设置。
        """
        value = os.getenv(name, "")
        if not value:
            raise ValueError(f"Required credential '{name}' not set in environment")
        return value

    @staticmethod
    def load_from_env(prefix: str = "") -> dict[str, str]:
        """加载所有以指定前缀开头的环境变量。

        Args:
            prefix: 环境变量前缀 (如 ``TARGET_``)。

        Returns:
            环境变量字典 (键去除前缀)。
        """
        result: dict[str, str] = {}
        for key, value in os.environ.items():
            if prefix and key.startswith(prefix):
                result[key[len(prefix):].lower()] = value
            elif not prefix:
                result[key] = value
        return result

    @classmethod
    def from_args(cls, args: Any) -> dict[str, str]:
        """从 CLI 参数提取凭据相关字段。

        Args:
            args: argparse.Namespace。

        Returns:
            凭据字典。
        """
        creds: dict[str, str] = {}
        for attr in ("api_key", "api_oauth_client_id", "api_oauth_client_secret"):
            val = getattr(args, attr, None)
            if val:
                creds[attr] = val
        return creds
