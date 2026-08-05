# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Port scan probe — discover AI services on non-standard ports.

Scans AI-specific ports on the target host to discover:
  1. AI runtimes (Ollama, vLLM, TGI, LiteLLM, LocalAI, LM Studio)
  2. Vector databases (Chroma, Qdrant, Weaviate, Milvus, Pinecone)
  3. AI frontends (Open WebUI, LibreChat, Langflow, Flowise)
  4. AI proxies/gateways (Portkey, LiteLLM Proxy)
  5. MLOps tools (MLflow, Ray Dashboard, W&B)

Uses the AI_PORTS catalog from ai_signal_catalog.py as the candidate list.
Only probes ports that are likely to host AI services (not a full port scan).

Architecture:
  - Input: target hostname from session.target_url
  - Output: discovered AI services on non-standard ports
  - Browser: False
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING, Any

import httpx

from core.probes.ai_signal_catalog import AI_PORTS, lookup_ai_port
from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# Common AI ports to scan (subset of AI_PORTS that are most likely)
# Ordered by priority: dedicated AI ports first, shared ports last
_AI_SCAN_PORTS: list[int] = [
    11434,  # Ollama (dedicated)
    1234,   # LM Studio (dedicated)
    4891,   # LocalAI (dedicated)
    6334,   # Qdrant REST (dedicated)
    6333,   # Qdrant gRPC (dedicated)
    8001,   # Chroma (dedicated)
    8086,   # Weaviate (dedicated)
    19530,  # Milvus/Zilliz (dedicated)
    8787,   # Portkey AI Gateway (dedicated)
    4000,   # LiteLLM Proxy (dedicated)
    8265,   # Ray Dashboard (dedicated)
    8081,   # MLflow (dedicated)
    5001,   # MLflow alt (dedicated)
    8000,   # vLLM/TGI/LiteLLM/FastAPI (shared)
    8080,   # LM Studio/LocalAI/generic (shared)
    3000,   # Open WebUI/LibreChat (shared)
    5173,   # Vite dev (shared)
    7860,   # Gradio (shared)
    8501,   # Streamlit (shared)
    8888,   # Jupyter (shared)
]

# G10: 内网部署额外端口集 — 覆盖企业内部常见的 AI 服务端口
_INTRANET_EXTRA_PORTS: list[int] = [
    5000,   # Flask/FastAPI 内网部署
    9000,   # 内网 API 网关
    9001,   # MinIO/S3 兼容存储
    9090,   # Prometheus/内网监控
    9091,   # 内网推流
    23333,  # vLLM 分布式部署
    24000,  # Triton Inference Server
    9997,   # Dify 内网
    5002,   # Flowise 内网
    3001,   # Next.js 内网前端
    3010,   # 自定义 AI 网关
    7011,   # Xinference
    9999,   # 内网通用
    443,    # HTTPS
    80,     # HTTP
]

# Ports that always need HTTP verification (not just TCP)
_HTTP_VERIFY_PORTS: set[int] = {
    8000, 8080, 3000, 5173, 7860, 8501, 8888, 11434,
    1234, 4891, 6334, 8001, 8086, 19530, 8787, 4000,
    8265, 8081, 5001,
}

# Timeouts
_TCP_TIMEOUT = 2.0     # seconds for TCP connect
_HTTP_TIMEOUT = 5.0    # seconds for HTTP verification


class PortScanProbe(ReconProbe):
    """AI service port scanner.

    Scans AI-specific ports on the target host to discover
    AI services running on non-standard ports.

    Usage::
        probe = PortScanProbe()
        result = await probe.probe(session)
        # result["discovered_services"] -> list of AI services
    """

    def __init__(
        self,
        ports: list[int] | None = None,
        tcp_timeout: float = _TCP_TIMEOUT,
        http_timeout: float = _HTTP_TIMEOUT,
        concurrency: int = 10,
        intranet_mode: bool = False,
    ) -> None:
        # G10: 内网模式自动扩展端口集
        if ports is None:
            if intranet_mode:
                self._ports = list(set(_AI_SCAN_PORTS + _INTRANET_EXTRA_PORTS))
                self._ports.sort()
            else:
                self._ports = _AI_SCAN_PORTS
        else:
            self._ports = ports
        self._tcp_timeout = tcp_timeout
        self._http_timeout = http_timeout
        self._concurrency = concurrency
        self._intranet_mode = intranet_mode

    @property
    def name(self) -> str:
        return "PortScanProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute AI port scan.

        Args:
            session: Recon session.

        Returns:
            Dict with discovered_services and scan_summary.
        """
        from urllib.parse import urlparse

        host = urlparse(session.target_url).hostname
        if not host:
            return {"discovered_services": [], "scan_summary": {"error": "Could not extract hostname"}}

        # Phase 1: TCP connect scan
        open_ports = await self._tcp_scan(host)

        # Phase 2: HTTP verification for open ports
        discovered = await self._http_verify(host, open_ports)

        logger.info(
            "PortScanProbe: %d/%d ports open, %d AI services discovered on %s",
            len(open_ports), len(self._ports), len(discovered), host,
        )

        return {
            "discovered_services": discovered,
            "scan_summary": {
                "host": host,
                "ports_scanned": len(self._ports),
                "ports_open": len(open_ports),
                "services_discovered": len(discovered),
                "open_ports": open_ports,
            },
        }

    async def _tcp_scan(self, host: str) -> list[int]:
        """TCP connect scan for AI ports."""
        semaphore = asyncio.Semaphore(self._concurrency)
        open_ports: list[int] = []

        async def check_port(port: int) -> None:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self._tcp_timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(port)
                    logger.debug("PortScanProbe: port %d OPEN on %s", port, host)
                except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                    pass

        tasks = [check_port(port) for port in self._ports]
        await asyncio.gather(*tasks)

        return sorted(open_ports)

    async def _http_verify(
        self, host: str, open_ports: list[int]
    ) -> list[dict[str, Any]]:
        """HTTP verification of open ports to confirm AI services."""
        discovered: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=self._http_timeout, verify=False, follow_redirects=False) as client:
            for port in open_ports:
                port_info = lookup_ai_port(port)
                if not port_info:
                    continue

                # Try HTTPS first, then HTTP
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}:{port}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code < 500:
                            # Check for AI-specific indicators in response
                            ai_indicators = self._check_ai_indicators(resp, port_info)
                            discovered.append({
                                "host": host,
                                "port": port,
                                "scheme": scheme,
                                "service": port_info["descriptor"],
                                "category": port_info.get("category", "unknown"),
                                "status_code": resp.status_code,
                                "content_type": resp.headers.get("content-type", ""),
                                "server": resp.headers.get("server", ""),
                                "ai_indicators": ai_indicators,
                                "url": url,
                            })
                            break  # Found working scheme
                    except (httpx.RequestError, asyncio.TimeoutError):
                        continue

        return discovered

    @staticmethod
    def _check_ai_indicators(resp: httpx.Response, port_info: dict[str, Any]) -> list[str]:
        """Check HTTP response for AI-specific indicators."""
        indicators: list[str] = []
        text = resp.text[:500].lower()
        headers_text = " ".join(resp.headers.keys()).lower()

        # Ollama indicators
        if "ollama" in text or "ollama" in headers_text:
            indicators.append("ollama_response")

        # vLLM indicators
        if "vllm" in text or "x-vllm" in headers_text or "x-served-by" in headers_text:
            indicators.append("vllm_response")

        # OpenAI-compatible API
        if '"object"' in text and ('"model"' in text or '"data"' in text):
            indicators.append("openai_compatible")

        # MCP indicators
        if '"jsonrpc"' in text or "mcp" in headers_text:
            indicators.append("mcp_response")

        # Vector DB indicators
        if any(kw in text for kw in ("collection", "vector", "embedding", "namespace")):
            indicators.append("vector_db_response")

        # Gradio
        if "gradio" in text or "gr-box" in text:
            indicators.append("gradio_response")

        # Streamlit
        if "streamlit" in text or "stApp" in text:
            indicators.append("streamlit_response")

        # Jupyter
        if "jupyter" in text or "jupyter" in headers_text:
            indicators.append("jupyter_response")

        # MLflow
        if "mlflow" in text or "experiment" in text:
            indicators.append("mlflow_response")

        return indicators
