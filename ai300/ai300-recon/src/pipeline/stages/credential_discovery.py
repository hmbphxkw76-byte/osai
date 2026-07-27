# -*- coding: utf-8 -*-
"""
阶段 1：凭据发现

检查目标域名下是否存在已保存的凭据文件或 storage_state，
决定后续是否需要人工登录。
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from src.auth import find_credential_file
from src.credential_manager import CredentialManager

from ..base import PipelineStage
from ..context import PipelineContext, StageResult


class CredentialDiscoveryStage(PipelineStage):
    """凭据发现阶段"""

    name = "credential_discovery"
    description = "发现已有凭据与浏览器状态"

    async def run(self, context: PipelineContext) -> StageResult:
        cred_dir = self._config(context, "credentials_dir", "credentials")
        results_dir = self._config(context, "results_dir", "results")
        storage_dir = os.path.join(results_dir, "recon", "storage_states")

        cm = CredentialManager(cred_dir)
        resolution = cm.resolve(context.target_url)
        context.credential_resolution = resolution
        context.auth_profile = resolution.profile

        data: Dict[str, Any] = {
            "credential_file": resolution.source_file,
            "auth_type": resolution.profile.auth_type if resolution.profile else "none",
            "storage_dir": storage_dir,
        }

        # 查找最近的 storage_state
        latest_state = self._find_latest_storage_state(storage_dir, context.target_url)
        if latest_state:
            data["latest_storage_state"] = latest_state
            context.config["latest_storage_state"] = latest_state

        if context.auth_profile:
            return StageResult(
                success=True,
                message=f"发现已保存凭据: {resolution.source_file}",
                data=data,
            )

        return StageResult(
            success=True,
            skipped=True,
            message="未找到已保存凭据，将尝试无认证侦察或等待人工登录",
            data=data,
        )

    def _find_latest_storage_state(self, storage_dir: str, target_url: str) -> str:
        """查找目标域名下最新的 storage_state 文件"""
        from src.auth.header_parser import normalize_domain

        if not os.path.isdir(storage_dir):
            return ""
        domain = normalize_domain(target_url)
        candidates: List[str] = []
        for fname in os.listdir(storage_dir):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(storage_dir, fname)
            if domain.replace(".", "_") in fname or domain in fname:
                candidates.append(fpath)
        if not candidates:
            return ""
        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return candidates[0]
