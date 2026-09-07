""" - AI 

Academic basis:
    - Arbis et al. (arXiv:2306.01943) Sec4.5 - API 
      , Agent 
    - OWASP WSTG-INFO-03 - 
      
    - PTES (Penetration Testing Execution Standard) Sec2 - 
      
    - A2A Protocol (Google, 2025) - Agent Card 
      /.well-known/agent.json, 

 (Rule 2: Layer, ):
     httpx  ( PyRIT HTTPTarget, 
    prompt , )httpx  PyRIT 

:
    1.  AI  (3000-3010, 8000-8100, 9000-9100, 11434)
    2. converter(s) /.well-known/agent.json + /mcp + /health
    3.  ParsedBurpRequest 
    4.  +  ( N converter(s))

:
    -  5 converter(s) ()
    -  3s (, )
    -  10
    - :  3 converter(s)

[WARN] DEPRECATED (2026-09-06):
     import  ()
    :  AI 
    :  core/orchestrator.py  'from recon.port_expander import discover_port_endpoints'
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml as _yaml

# P2-06: TLS verify (SSOT)
from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

_TLS_VERIFY = _get_tls_verify_from_config()

logger = logging.getLogger(__name__)

# R7: config/defaults.yaml SSOT ()
_SSOT_PATH = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"


def _load_ssot_int(key: str, default: int) -> int:
 """imports defaults.yaml (R7 SSOT )."""
    try:
        if _SSOT_PATH.exists():
            with open(_SSOT_PATH, encoding="utf-8") as _f:
                _cfg = _yaml.safe_load(_f) or {}
            return int(_cfg.get(key, default))
    except Exception:
        pass
    return default

# ======================================================================
# AI ()
# ======================================================================

_AI_SERVICE_PORTS: list[int] = [
 # MCP Server 
    3001, 3002, 3003,           # Node.js MCP Server
    8000, 8001, 8080, 8081,     # Python MCP Server
    9000, 9001, 9090,           # gRPC MCP Server
 # LLM 
    11434,                       # Ollama
    1234,                        # LM Studio
    5000, 5001,                  # text-generation-webui
 # Agent 
    3000, 4000, 4001,            # LangChain, CrewAI
 # A2A Agent
    5002, 5003, 5004,            # A2A Agent
 # 
    7860,                        # Gradio
    8501,                        # Triton Inference Server
    9696,                        # TorchServe
 # P2-3: - gRPC/WebSocket/
 # gRPC 
    50051, 50052, 50053,         # gRPC AI Server
    9091, 9092,                  # gRPC reflection
 # WebSocket 
    8765, 8766,                  # WebSocket AI Server
    4200, 4201,                  # WebSocket Agent
 # (Docker/K8s)
    31100, 31101,               # K8s NodePort
    31000, 31001,               # K8s NodePort
 # LLM 
    8082, 8083, 8084,            # Python Server
    6000, 6001,                  # vLLM / TGI
    7000, 7001,                  # vLLM
]

# ()
_PORT_PROBE_PATHS: list[str] = [
    "/.well-known/agent.json",   # A2A Agent Card
    "/mcp",                       # MCP endpoint
    "/health",                    # 
    "/api/health",                # API 
    "/v1/models",                 # OpenAI API
 # P2-3: 
    "/openapi.json",              # OpenAPI/Swagger 
    "/swagger.json",              # Swagger 
    "/grpc.health.v1.Health/Check", # gRPC health check (HTTP/2)
    "/ws",                        # WebSocket 
    "/v1/chat/completions",       # OpenAI chat 
]

# 
_SERVICE_TYPE_KEYWORDS: dict[str, list[str]] = {
    "mcp": ["mcp", "model context protocol", "jsonrpc", "json-rpc"],
    "a2a": ["agent card", "a2a", "agent-to-agent", "capabilities", "skills"],
    "llm_api": ["models", "openai", "completion", "chat", "inference"],
    "agent": ["agent", "tool", "function", "workflow"],
 # P2-3: 
    "grpc": ["grpc", "protobuf", "rpc", "trailers", "status"],
    "websocket": ["websocket", "ws", "upgrade", "sec-websocket"],
    "openapi": ["swagger", "openapi", "api-docs", "spec"],
}


@dataclass
class DiscoveredPortEndpoint:
 """

    :
        port: 
        path: 
        status_code: HTTP 
        content_type:  Content-Type
        response_preview:  ( 200 )
        service_type:  (mcp/a2a/llm_api/agent/unknown)
        use_tls:  TLS
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
 """ AI 

    Academic basis:
        - Arbis et al. (arXiv:2306.01943) Sec4.5 - 
        - PTES Sec2 - 

    :
        1. imports host
        2.  AI 
        3. converter(s) 5 converter(s)
        4. imports
        5.  HTTPTarget

    :
        -  5 converter(s) ()
        -  3s (, )
        -  max_concurrent ( 10)
        - :  early_stop converter(s)

    Args:
        parsed: ParsedBurpRequest  ( host  TLS )
        timeout: converter(s)
        max_concurrent: 
        early_stop:  N converter(s)
        custom_ports:  (None =  AI )

    Returns:
        
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

 # 
    semaphore = asyncio.Semaphore(max_concurrent)
    results: list[DiscoveredPortEndpoint] = []
    results_lock = asyncio.Lock()

    async def _probe_port(port: int) -> None:
        nonlocal results

 # 
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
 """converter(s)converter(s)

    Args:
        host: 
        port: 
        use_tls:  TLS
        timeout: 

    Returns:
         ()
 """
    import httpx

    scheme = "https" if use_tls else "http"
    base_url = f"{scheme}://{host}:{port}"
    results: list[DiscoveredPortEndpoint] = []

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=_TLS_VERIFY,
        ) as client:
            for path in _PORT_PROBE_PATHS:
                url = f"{base_url}{path}"
                try:
                    response = await client.get(url)

 # ( 404/)
                    if response.status_code == 404:
                        continue

 # 
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
                        "Port %d: %s -> HTTP %d (%s)",
                        port, path, response.status_code, service_type,
                    )

 # 
                    break

                except (httpx.TimeoutException, httpx.ConnectError):
 # , Skip
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
 """imports

    Args:
        status_code: HTTP 
        content_type: Content-Type header
        body_preview: 

    Returns:
         (mcp/a2a/llm_api/agent/unknown)
 """
    text = f"{content_type} {body_preview}".lower()

    for service_type, keywords in _SERVICE_TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                return service_type

 # JSON 
    if "json" in content_type.lower() and status_code == 200:
        return "unknown"

    return "unknown"


def _extract_host(parsed: Any) -> str:
 """imports ParsedBurpRequest host

    :
        1. parsed.host ()
        2. imports Host header 
        3. imports raw_request 
 """
 # 
    host = getattr(parsed, "host", None)
    if host:
 # 
        if ":" in str(host):
            return str(host).split(":")[0]
        return str(host)

 # headers 
    headers = getattr(parsed, "headers", {})
    host_header = headers.get("host", headers.get("Host", ""))
    if host_header:
        if ":" in host_header:
            return host_header.split(":")[0]
        return host_header

 # raw_request 
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
 """imports ParsedBurpRequest TLS 

    :
        1. parsed.use_tls / parsed.is_https
        2. imports raw_request  (HTTPS)
        3. imports (443 = TLS)
 """
 # 
    for attr in ("use_tls", "is_https", "tls"):
        val = getattr(parsed, attr, None)
        if val is not None:
            return bool(val)

 # raw_request 
    raw = getattr(parsed, "raw_request", "")
    if raw:
        first_line = raw.split("\n")[0].upper()
        if "HTTPS" in first_line:
            return True

 # 
    port = getattr(parsed, "port", None)
    if port == 443:
        return True

    return False


def build_port_parsed_request(
    original_parsed: Any,
    port_endpoint: DiscoveredPortEndpoint,
) -> dict[str, Any]:
 """imports ( HTTPTarget)

    Args:
        original_parsed:  ParsedBurpRequest
        port_endpoint: 

    Returns:
         (host, port, path, use_tls, method, headers)
 """
    host = _extract_host(original_parsed)
    original_headers = getattr(original_parsed, "headers", {})

 # headers, Host
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


# ====================================================================
# Confirmation ( RedAmon _confirm_vector_dbs )
# Academic basis: Morris et al. (arXiv:2310.06870) - 
# ====================================================================

# Confirmation (benign unauthenticated read)
# (tech_name, [(path, expected_substring), ...])
_VECTOR_DB_READS: dict[str, list[tuple[str, str]]] = {
    "qdrant": [
        ("/collections", "result"),
        ("/", "qdrant"),
    ],
    "milvus": [
        ("/collections", "collections"),
        ("/v1/collections", "collections"),
    ],
    "weaviate": [
        ("/v1/schema", "classes"),
        ("/v1/.well-known/ready", "ready"),
    ],
    "chroma": [
        ("/api/v1/collections", "collections"),
        ("/api/v2/collections", "collections"),
    ],
    "elasticsearch": [
        ("/_cat/indices", "indices"),
        ("/", "cluster_name"),
    ],
    "redis": [
        ("/info", "redis_version"),
    ],
}

# ( _AI_SERVICE_PORTS DB )
_VECTOR_DB_PORTS: dict[int, str] = {
    6333: "qdrant",
    6334: "qdrant",
    19530: "milvus",
    8080: "weaviate",  # web , Confirmation
    8000: "chroma",    # web , Confirmation
    9200: "elasticsearch",
    6379: "redis",
}


@dataclass
class VectorDBConfirmation:
 """Confirmation

    :
        tech:  (qdrant/milvus/weaviate/chroma/elasticsearch/redis)
        host: 
        port: 
        confirmed_via: Confirmation ( "/collections")
        response_preview:  ( 200 )
 """

    tech: str
    host: str
    port: int
    confirmed_via: str = ""
    response_preview: str = ""


async def confirm_vector_dbs(
    parsed: Any,
    *,
    timeout: float = 3.0,
    port_endpoints: list[DiscoveredPortEndpoint] | None = None,
) -> list[VectorDBConfirmation]:
 """Confirmation

    Academic basis:
        - Morris et al. (arXiv:2310.06870) - 
        - RedAmon _confirm_vector_dbs - benign unauthenticated read Confirmation

    :
        1. imports port_endpoints 
        2. converter(s) benign read  (GET /collections, /v1/schema )
        3. Confirmation

    Args:
        parsed: ParsedBurpRequest  ( host  TLS )
        timeout: converter(s)
        port_endpoints:  (,  None  DB )

    Returns:
        Confirmation
 """
    import httpx

    host = _extract_host(parsed)
    use_tls = _extract_tls(parsed)

    if not host:
        return []

 # R8-1 : httpx.AsyncClient
 # R8-6 : Semaphore (R7: SSOT )
    _vdb_concurrency = _load_ssot_int("max_concurrent_probes", 10)
    semaphore = asyncio.Semaphore(_vdb_concurrency)

 # (tech, port) 
    candidates: list[tuple[str, int]] = []

    if port_endpoints:
 # DB 
        for pe in port_endpoints:
            tech = _VECTOR_DB_PORTS.get(pe.port)
            if tech:
                candidates.append((tech, pe.port))

 # port_endpoints , 
    if not candidates:
        for port, tech in _VECTOR_DB_PORTS.items():
            candidates.append((tech, port))

    if not candidates:
        return []

 # 
    seen = set()
    unique_candidates: list[tuple[str, int]] = []
    for tech, port in candidates:
        key = (tech, port)
        if key not in seen:
            seen.add(key)
            unique_candidates.append((tech, port))

    logger.info(
        "Vector DB confirmation: probing %d candidates on %s",
        len(unique_candidates),
        host,
    )

 # Confirmation
    confirmed: list[VectorDBConfirmation] = []
    confirmed_lock = asyncio.Lock()

 # R8-1 : httpx.AsyncClient (LIFO+/)
    scheme = "https" if use_tls else "http"
    probe_headers: dict[str, str] = {}
    for key, value in getattr(parsed, "raw_headers", []):
        if key.lower() not in ("content-length", "host"):
            probe_headers[key] = value

    async def _confirm_one(client: httpx.AsyncClient, tech: str, port: int) -> None:
        reads = _VECTOR_DB_READS.get(tech, [])
        if not reads:
            return

        async with semaphore:
            for path, expected in reads:
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    response = await client.get(url, headers=probe_headers)
                    if response.status_code == 200:
                        body_text = response.text[:500]
                        if not expected or expected.lower() in body_text.lower():
                            async with confirmed_lock:
                                confirmed.append(VectorDBConfirmation(
                                    tech=tech,
                                    host=host,
                                    port=port,
                                    confirmed_via=path,
                                    response_preview=body_text[:200],
                                ))
                            logger.info(
                                "Vector DB confirmed: %s on %s:%d via %s",
                                tech,
                                host,
                                port,
                                path,
                            )
                            return
                except Exception:
                    continue

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=_TLS_VERIFY,
    ) as shared_client:
        tasks = [_confirm_one(shared_client, tech, port) for tech, port in unique_candidates]
        await asyncio.gather(*tasks, return_exceptions=True)

    if confirmed:
        logger.info(
            "Vector DB confirmation: %d databases confirmed",
            len(confirmed),
        )
    else:
        logger.debug("Vector DB confirmation: no databases confirmed")

    return confirmed
