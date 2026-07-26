# -*- coding: utf-8 -*-
"""
阶段 2：认证初始化

根据凭据发现结果和 CLI 参数，决定认证方式：
  - 已有凭据：直接注入
  - 无凭据但启用 manual_login：标记需要人工登录
  - 无凭据：无认证
"""

from __future__ import annotations

from src.auth import AuthProfile

from ..base import PipelineStage
from ..context import PipelineContext, StageResult


class AuthenticationStage(PipelineStage):
    """认证初始化阶段"""

    name = "authentication"
    description = "初始化认证方式"

    async def run(self, context: PipelineContext) -> StageResult:
        auth_mode = self._config(context, "auth_mode", "auto")
        manual_login = self._spa_config(context, "manual_login", False)

        if context.auth_profile and auth_mode in ("auto", "header"):
            profile: AuthProfile = context.auth_profile
            source_file = ""
            if context.credential_resolution:
                source_file = context.credential_resolution.source_file
            return StageResult(
                success=True,
                message=f"将使用已保存凭据进行认证注入，类型: {profile.auth_type}",
                data={
                    "auth_type": profile.auth_type,
                    "credential_file": source_file,
                },
            )

        if manual_login:
            return StageResult(
                success=True,
                message="未找到凭据，将在检测到登录页时启用人工登录等待",
                data={"manual_login": True},
            )

        return StageResult(
            success=True,
            skipped=True,
            message="无认证模式，直接侦察",
            data={"auth_mode": "none"},
        )
