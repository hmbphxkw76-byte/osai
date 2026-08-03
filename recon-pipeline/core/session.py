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

        Raises:
            RuntimeError: 如果认证后 auth_state 显示未认证 (非 NoAuthProvider)。
        """
        self.auth_state = await provider.authenticate(self.target_url, **kwargs)
        logger.info(
            f"Authenticated: {provider.name} (authenticated={self.auth_state.is_authenticated()})"
        )

        # 如果 provider 暴露了 browser_page, 复用 (通过公共接口而非 duck-typing)
        page = getattr(provider, "page", None)
        if page is not None:
            self.browser_page = page

        # 更新 report 的 auth_type
        self.report.auth_type = self.auth_state.auth_type
        self.report.target_url = self.target_url

        # 验证: 非 NoAuthProvider 但认证失败 → 警告
        if not self.auth_state.is_authenticated() and provider.name != "none":
            logger.warning(
                f"Auth provider '{provider.name}' reported unauthenticated state — "
                f"probes requiring auth will be skipped"
            )

        return self.auth_state

    async def run_probe(self, probe: ReconProbe) -> dict[str, Any]:
        """运行一个探针, 结果自动合并到 report。

        前置条件由 ReconPipeline.run() 保证:
          - requires_auth: session 必须已认证
          - requires_browser: session 必须有 browser_page

        直接调用此方法时, 调用者自行负责前置条件检查。

        Args:
            probe: 探针实例。

        Returns:
            探针结果字典。
        """
        # 执行探针 (前置检查由 ReconPipeline.run() 负责, 避免双重检查导致 skipped/failed 混淆)
        result = await probe.probe(self)

        # 合并到 report
        self.report.merge(probe.name, result)

        # 日志摘要 — 根据结果中实际含有的字段
        endpoint_count = len(result.get("endpoints", []))
        surface_count = len(result.get("injection_surfaces", []))
        fp_count = len(result.get("llm_fingerprints", []))
        tool_count = len(result.get("mcp_tools", []))

        parts = []
        if endpoint_count:
            parts.append(f"{endpoint_count} endpoints")
        if surface_count:
            parts.append(f"{surface_count} surfaces")
        if fp_count:
            parts.append(f"{fp_count} fingerprints")
        if tool_count:
            parts.append(f"{tool_count} MCP tools")
        summary = ", ".join(parts) if parts else "no results"

        logger.info(f"Probe {probe.name} completed: {summary}")
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
