"""跨端口端点发现 — 探测同主机其他端口上的 AI 服务。

学术依据:
    - Arbis et al. (arXiv:2306.01943) §4.5 — API 端点发现应覆盖
      同主机的不同端口, Agent 服务常部署在非标准端口。
    - OWASP WSTG-INFO-03 — 框架指纹识别后的针对性探测
      应包含端口维度。
    - PTES (Penetration Testing Execution Standard) §2 — 情报收集
      阶段应做端口服务发现。
    - A2A Protocol (Google, 2025) — Agent Card 通常部署在
      /.well-known/agent.json, 可能在不同端口。

设计原则 (Rule 2: 胶水层, 不替换):
    使用 httpx 直接探测 (不使用 PyRIT HTTPTarget, 因为这不是
    prompt 交互, 而是端口探测)。httpx 是 PyRIT 已有依赖。

探测策略:
    1. 常见 AI 服务端口优先 (3000-3010, 8000-8100, 9000-9100, 11434)
    2. 对每个端口探测 /.well-known/agent.json + /mcp + /health
    3. 发现的端口端点生成新的 ParsedBurpRequest 供后续攻击
    4. 并发控制 + 早期终止 (发现 N 个即停止)

效率优化:
    - 每端口只探测 5 个路径 (不是全量端点发现)
    - 超时 3s (端口可能关闭, 快速失败)
    - 并发控制 10
    - 早期终止: 发现 3 个端口端点即停止
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════
# 常见 AI 服务端口 (按优先级排序)
# ══════════════════════════════════════════════════════════════

_AI_SERVICE_PORTS: list[int] = [
    # MCP Server 常见端口
    3001, 3002, 3003,           # Node.js MCP Server
    8000, 8001, 8080, 8081,     # Python MCP Server
    9000, 9001, 9090,           # gRPC MCP Server
    # LLM 推理服务
    11434,                       # Ollama
    1234,                        # LM Studio
    5000, 5001,                  # text-generation-webui
    # Agent 编排
    3000, 4000, 4001,            # LangChain, CrewAI
    # A2A Agent
    5002, 5003, 5004,            # A2A Agent
    # 额外常见端口
    7860,                        # Gradio
    8501,                        # Triton Inference Server
    9696,                        # TorchServe
]

# 每个端口探测的路径 (按优先级排序)
_PORT_PROBE_PATHS: list[str] = [
    "/.well-known/agent.json",   # A2A Agent Card
    "/mcp",                       # MCP endpoint
    "/health",                    # 健康检查
    "/api/health",                # API 健康检查
    "/v1/models",                 # OpenAI 兼容 API
]

# 服务类型推断关键词
_SERVICE_TYPE_KEYWORDS: dict[str, list[str]] = {
    "mcp": ["mcp", "model context protocol", "jsonrpc", "json-rpc"],
    "a2a": ["agent card", "a2a", "agent-to-agent", "capabilities", "skills"],
    "llm_api": ["models", "openai", "completion", "chat", "inference"],
    "agent": ["agent", "tool", "function", "workflow"],
}


@dataclass
class DiscoveredPortEndpoint:
    """发现的端口端点。

    属性:
        port: 端口号。
        path: 探测路径。
        status_code: HTTP 状态码。
        content_type: 响应 Content-Type。
        response_preview: 响应体预览 (前 200 字符)。
        service_type: 推断的服务类型 (mcp/a2a/llm_api/agent/unknown)。
        use_tls: 是否使用 TLS。
    """

    port: int
    path: str
    status_code: int
    content_type: str = ""
    response_preview: str = ""
    service_type: str = "unknown"
    use_tls: bool = False


async def discover_port_endpoints(
    parsed: Any,
    *,
    timeout: float = 3.0,
    max_concurrent: int = 10,
    early_stop: int = 3,
    custom_ports: list[int] | None = None,
) -> list[DiscoveredPortEndpoint]:
    """探测同主机其他端口上的 AI 服务。

    学术依据:
        - Arbis et al. (arXiv:2306.01943) §4.5 — 跨端口端点发现
        - PTES §2 — 情报收集阶段端口发现

    策略:
        1. 从原始请求提取 host
        2. 对常见 AI 服务端口并发探测
        3. 每个端口探测 5 个关键路径
        4. 从响应推断服务类型
        5. 发现的端点返回供后续构建 HTTPTarget

    效率优化:
        - 每端口只探测 5 个路径 (不是全量端点发现)
        - 超时 3s (端口可能关闭, 快速失败)
        - 并发控制 max_concurrent (默认 10)
        - 早期终止: 发现 early_stop 个端口端点即停止

    Args:
        parsed: ParsedBurpRequest 实例 (提取 host 和 TLS 信息)。
        timeout: 每个探测请求的超时秒数。
        max_concurrent: 最大并发探测数。
        early_stop: 发现 N 个端口端点即停止。
        custom_ports: 自定义端口列表 (None = 使用默认 AI 端口列表)。

    Returns:
        发现的端口端点列表。
    """
    host = _extract_host(parsed)
    use_tls = _extract_tls(parsed)

    if not host:
        logger.warning("Port discovery: no host found in parsed request")
        return []

    ports = custom_ports if custom_ports else _AI_SERVICE_PORTS

    logger.info(
        "Port discovery: scanning %d ports on %s (TLS=%s)",
        len(ports), host, use_tls,
    )

    # 并发探测所有端口
    semaphore = asyncio.Semaphore(max_concurrent)
    results: list[DiscoveredPortEndpoint] = []
    results_lock = asyncio.Lock()

    async def _probe_port(port: int) -> None:
        nonlocal results

        # 早期终止检查
        if len(results) >= early_stop:
            return

        async with semaphore:
            port_endpoints = await _probe_port_paths(
                host=host,
                port=port,
                use_tls=use_tls,
                timeout=timeout,
            )

            if port_endpoints:
                async with results_lock:
                    results.extend(port_endpoints)
                    if len(results) >= early_stop:
                        logger.info(
                            "Port discovery: early stop at %d endpoints",
                            len(results),
                        )

    tasks = [_probe_port(port) for port in ports]
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info(
        "Port discovery: %d endpoints found on %s",
        len(results), host,
    )

    return results


async def _probe_port_paths(
    host: str,
    port: int,
    use_tls: bool,
    timeout: float,
) -> list[DiscoveredPortEndpoint]:
    """探测单个端口的多个路径。

    Args:
        host: 主机名。
        port: 端口号。
        use_tls: 是否使用 TLS。
        timeout: 超时秒数。

    Returns:
        发现的端点列表 (可能为空)。
    """
    import httpx

    scheme = "https" if use_tls else "http"
    base_url = f"{scheme}://{host}:{port}"
    results: list[DiscoveredPortEndpoint] = []

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            for path in _PORT_PROBE_PATHS:
                url = f"{base_url}{path}"
                try:
                    response = await client.get(url)

                    # 只记录有意义的响应 (非 404/连接失败)
                    if response.status_code == 404:
                        continue

                    # 推断服务类型
                    body_preview = response.text[:200] if response.text else ""
                    service_type = _infer_service_type(
                        response.status_code,
                        response.headers.get("content-type", ""),
                        body_preview,
                    )

                    endpoint = DiscoveredPortEndpoint(
                        port=port,
                        path=path,
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type", ""),
                        response_preview=body_preview,
                        service_type=service_type,
                        use_tls=use_tls,
                    )
                    results.append(endpoint)

                    logger.info(
                        "Port %d: %s → HTTP %d (%s)",
                        port, path, response.status_code, service_type,
                    )

                    # 首个有意义响应即可代表该端口
                    break

                except (httpx.TimeoutException, httpx.ConnectError):
                    # 端口关闭或不支持, 跳过
                    break
                except Exception as e:
                    logger.debug("Port %d probe error: %s", port, e)
                    break

    except Exception as e:
        logger.debug("Port %d connection failed: %s", port, e)

    return results


def _infer_service_type(
    status_code: int,
    content_type: str,
    body_preview: str,
) -> str:
    """从响应推断服务类型。

    Args:
        status_code: HTTP 状态码。
        content_type: Content-Type header。
        body_preview: 响应体预览。

    Returns:
        服务类型 (mcp/a2a/llm_api/agent/unknown)。
    """
    text = f"{content_type} {body_preview}".lower()

    for service_type, keywords in _SERVICE_TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                return service_type

    # JSON 响应但无法确定类型
    if "json" in content_type.lower() and status_code == 200:
        return "unknown"

    return "unknown"


def _extract_host(parsed: Any) -> str:
    """从 ParsedBurpRequest 提取 host。

    优先级:
        1. parsed.host (已解析)
        2. 从 Host header 中提取
        3. 从 raw_request 第一行中提取
    """
    # 直接属性
    host = getattr(parsed, "host", None)
    if host:
        # 去除端口号
        if ":" in str(host):
            return str(host).split(":")[0]
        return str(host)

    # 从 headers 提取
    headers = getattr(parsed, "headers", {})
    host_header = headers.get("host", headers.get("Host", ""))
    if host_header:
        if ":" in host_header:
            return host_header.split(":")[0]
        return host_header

    # 从 raw_request 提取
    raw = getattr(parsed, "raw_request", "")
    if raw:
        for line in raw.split("\n"):
            if line.lower().startswith("host:"):
                host_value = line.split(":", 1)[1].strip()
                if ":" in host_value:
                    return host_value.split(":")[0]
                return host_value

    return ""


def _extract_tls(parsed: Any) -> bool:
    """从 ParsedBurpRequest 提取 TLS 信息。

    优先级:
        1. parsed.use_tls / parsed.is_https
        2. 从 raw_request 第一行判断 (HTTPS)
        3. 从端口判断 (443 = TLS)
    """
    # 直接属性
    for attr in ("use_tls", "is_https", "tls"):
        val = getattr(parsed, attr, None)
        if val is not None:
            return bool(val)

    # 从 raw_request 判断
    raw = getattr(parsed, "raw_request", "")
    if raw:
        first_line = raw.split("\n")[0].upper()
        if "HTTPS" in first_line:
            return True

    # 从端口判断
    port = getattr(parsed, "port", None)
    if port == 443:
        return True

    return False


def build_port_parsed_request(
    original_parsed: Any,
    port_endpoint: DiscoveredPortEndpoint,
) -> dict[str, Any]:
    """从端口端点构建请求参数 (供后续构建 HTTPTarget)。

    Args:
        original_parsed: 原始 ParsedBurpRequest。
        port_endpoint: 发现的端口端点。

    Returns:
        请求参数字典 (host, port, path, use_tls, method, headers)。
    """
    host = _extract_host(original_parsed)
    original_headers = getattr(original_parsed, "headers", {})

    # 保留原始认证 headers, 去掉 Host
    port_headers: dict[str, str] = {}
    for k, v in original_headers.items():
        if k.lower() != "host" and k.lower() != "content-length":
            port_headers[k] = v

    return {
        "host": host,
        "port": port_endpoint.port,
        "path": port_endpoint.path,
        "use_tls": port_endpoint.use_tls,
        "method": "GET",
        "headers": port_headers,
        "service_type": port_endpoint.service_type,
    }
