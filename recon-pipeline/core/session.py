# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ReconSession: 贯穿整个侦察生命周期的状态容器。

认证态在所有探针间共享, 探针结果累积到 report 中。
ReconSession 是 recon-kit 的核心, 连接 Auth → Probes → Exporters。

数据流:
    1. authenticate(provider) → auth_state 被填充
    2. run_probe(probe) → 探针读取 auth_state, 结果合并到 report
    3. export(exporter) → report 被转换为下游可消费的格式

用法::

    session = ReconSession(target_url="http://example.com")
    await session.authenticate(APIKeyAuthProvider(key="sk-xxx"))
    await session.run_probe(LLMProbe())
    await session.run_probe(MCPProbe())
    session.export(PyRITExporter(), pipeline_ctx)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from core.models.auth_state import AuthState
from core.models.recon_report import ReconReport

if TYPE_CHECKING:
    from core.auth.provider import AuthProvider
    from core.exporters.base import ReconExporter
    from core.probes.base import ReconProbe

logger = logging.getLogger(__name__)


@dataclass
class ReconSession:
    """侦察会话状态容器。

    Attributes:
        target_url: 目标 URL。
        auth_state: 认证态 (cookies, tokens, headers, browser_context)。
        browser_page: Playwright Page (如目标需要浏览器)。
        report: 累积的侦察结果。
        metadata: 自由扩展字段。
    """

    target_url: str = ""
    auth_state: AuthState | None = None
    browser_page: Any | None = None
    report: ReconReport = field(default_factory=ReconReport)
    metadata: dict[str, Any] = field(default_factory=dict)

    async def authenticate(self, provider: AuthProvider, **kwargs: Any) -> AuthState:
        """使用 AuthProvider 执行认证。

        Args:
            provider: 认证提供方实例。
            **kwargs: 传递给 provider.authenticate() 的额外参数。

        Returns:
            填充后的 AuthState。
        """
        self.auth_state = await provider.authenticate(self.target_url, **kwargs)
        logger.info(f"Authenticated: {provider.name} (authenticated={self.auth_state.is_authenticated()})")

        # 如果 provider 持有 browser_page, 复用
        if hasattr(provider, "page") and provider.page is not None:
            self.browser_page = provider.page

        # 更新 report 的 auth_type
        self.report.auth_type = self.auth_state.auth_type
        self.report.target_url = self.target_url
        return self.auth_state

    async def run_probe(self, probe: ReconProbe) -> dict[str, Any]:
        """运行一个探针, 结果自动合并到 report。

        Args:
            probe: 探针实例。

        Returns:
            探针结果字典。
        """
        # 前置检查
        if probe.requires_auth and (self.auth_state is None or not self.auth_state.is_authenticated()):
            logger.warning(f"Probe {probe.name} requires auth but session is not authenticated")
        if probe.requires_browser and self.browser_page is None:
            logger.warning(f"Probe {probe.name} requires browser but no page available")

        # 执行探针
        result = await probe.probe(self)

        # 合并到 report
        self.report.merge(probe.name, result)

        logger.info(f"Probe {probe.name} completed: {len(result.get('endpoints', []))} endpoints")
        return result

    def export(self, exporter: ReconExporter, *args: Any, **kwargs: Any) -> Any:
        """将 report 导出为下游可消费的格式。

        Args:
            exporter: 导出器实例。
            *args, **kwargs: 传递给 exporter.export() 的额外参数。

        Returns:
            导出器返回值。
        """
        return exporter.export(self.report, *args, **kwargs)

    @property
    def auth_headers(self) -> dict[str, str]:
        """便捷访问: 认证 HTTP 头。"""
        if self.auth_state:
            return self.auth_state.to_headers()
        return {}

    @property
    def is_authenticated(self) -> bool:
        """是否已认证。"""
        return self.auth_state is not None and self.auth_state.is_authenticated()
