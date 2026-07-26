# -*- coding: utf-8 -*-
"""
阶段 9：凭据提取

从浏览器上下文和拦截流量中提取认证凭据并保存到 credentials/，
供后续侦察或攻击阶段复用。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from src.auth import CredentialExtractor
from src.utils import truncate_stage_error

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class CredentialExtractionStage(PipelineStage):
    """凭据自动提取阶段"""

    name = "credential_extraction"
    description = "提取并保存浏览器凭据"

    async def run(self, context: PipelineContext) -> StageResult:
        browser_manager = context.browser_manager
        interceptor = context.interceptor
        target_url = context.target_url

        # API 目标没有浏览器上下文，跳过
        if context.target_type == "api":
            return StageResult(
                success=True,
                skipped=True,
                message="API 目标无需浏览器凭据提取",
                data={},
            )

        if not browser_manager or not browser_manager.context:
            return StageResult(
                success=True,
                skipped=True,
                message="无浏览器上下文，跳过凭据提取",
                data={},
            )

        captured: List[Dict[str, Any]] = []
        if interceptor:
            captured = getattr(interceptor, "captured", []) or []

        credentials_dir = self._config(context, "credentials_dir", "credentials")
        extractor = CredentialExtractor(credentials_dir=credentials_dir, config=context.config)

        try:
            saved_path = await extractor.extract_from_browser(
                context=browser_manager.context,
                target_url=target_url,
                captured_entries=captured,
                page=context.page,
            )
        except Exception as exc:
            logger.exception("Credential extraction failed")
            return StageResult(
                success=False,
                message=f"凭据提取失败: {truncate_stage_error(str(exc), context.config)}",
                data={},
            )

        if saved_path:
            if context.profile:
                auth_mode = self._detect_auth_mode(saved_path)
                context.profile.fingerprint.auth_mode = auth_mode
                context.profile.raw_results["extracted_credentials_path"] = saved_path
            return StageResult(
                success=True,
                message=f"凭据已保存: {saved_path}",
                data={"saved_path": saved_path},
            )

        return StageResult(
            success=True,
            skipped=True,
            message="未从浏览器中提取到有效凭据",
            data={},
        )

    def _detect_auth_mode(self, saved_path: str) -> str:
        """根据保存的凭据文件内容推断认证模式"""
        try:
            with open(saved_path, "r", encoding="utf-8") as f:
                content = f.read().lower()
            if "authorization: bearer" in content:
                return "bearer"
            if "authorization:" in content:
                return "header"
            if "cookie:" in content:
                return "cookie"
        except Exception:
            pass
        return "none"
