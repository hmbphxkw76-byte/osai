"""璺ㄧ鍙ｇ鐐瑰彂鐜?鈥?鎺㈡祴鍚屼富鏈哄叾浠栫鍙ｄ笂鐨?AI 鏈嶅姟銆?

瀛︽湳渚濇嵁:
    - Arbis et al. (arXiv:2306.01943) 搂4.5 鈥?API 绔偣鍙戠幇搴旇鐩?
      鍚屼富鏈虹殑涓嶅悓绔彛, Agent 鏈嶅姟甯搁儴缃插湪闈炴爣鍑嗙鍙ｃ€?
    - OWASP WSTG-INFO-03 鈥?妗嗘灦鎸囩汗璇嗗埆鍚庣殑閽堝鎬ф帰娴?
      搴斿寘鍚鍙ｇ淮搴︺€?
    - PTES (Penetration Testing Execution Standard) 搂2 鈥?鎯呮姤鏀堕泦
      闃舵搴斿仛绔彛鏈嶅姟鍙戠幇銆?
    - A2A Protocol (Google, 2025) 鈥?Agent Card 閫氬父閮ㄧ讲鍦?
      /.well-known/agent.json, 鍙兘鍦ㄤ笉鍚岀鍙ｃ€?

璁捐鍘熷垯 (Rule 2: 鑳舵按灞? 涓嶆浛鎹?:
    浣跨敤 httpx 鐩存帴鎺㈡祴 (涓嶄娇鐢?PyRIT HTTPTarget, 鍥犱负杩欎笉鏄?
    prompt 浜や簰, 鑰屾槸绔彛鎺㈡祴)銆俬ttpx 鏄?PyRIT 宸叉湁渚濊禆銆?

鎺㈡祴绛栫暐:
    1. 甯歌 AI 鏈嶅姟绔彛浼樺厛 (3000-3010, 8000-8100, 9000-9100, 11434)
    2. 瀵规瘡涓鍙ｆ帰娴?/.well-known/agent.json + /mcp + /health
    3. 鍙戠幇鐨勭鍙ｇ鐐圭敓鎴愭柊鐨?ParsedBurpRequest 渚涘悗缁敾鍑?
    4. 骞跺彂鎺у埗 + 鏃╂湡缁堟 (鍙戠幇 N 涓嵆鍋滄)

鏁堢巼浼樺寲:
    - 姣忕鍙ｅ彧鎺㈡祴 5 涓矾寰?(涓嶆槸鍏ㄩ噺绔偣鍙戠幇)
    - 瓒呮椂 3s (绔彛鍙兘鍏抽棴, 蹇€熷け璐?
    - 骞跺彂鎺у埗 10
    - 鏃╂湡缁堟: 鍙戠幇 3 涓鍙ｇ鐐瑰嵆鍋滄
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲
# 甯歌 AI 鏈嶅姟绔彛 (鎸変紭鍏堢骇鎺掑簭)
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲

_AI_SERVICE_PORTS: list[int] = [
    # MCP Server 甯歌绔彛
    3001, 3002, 3003,           # Node.js MCP Server
    8000, 8001, 8080, 8081,     # Python MCP Server
    9000, 9001, 9090,           # gRPC MCP Server
    # LLM 鎺ㄧ悊鏈嶅姟
    11434,                       # Ollama
    1234,                        # LM Studio
    5000, 5001,                  # text-generation-webui
    # Agent 缂栨帓
    3000, 4000, 4001,            # LangChain, CrewAI
    # A2A Agent
    5002, 5003, 5004,            # A2A Agent
    # 棰濆甯歌绔彛
    7860,                        # Gradio
    8501,                        # Triton Inference Server
    9696,                        # TorchServe
]

# 姣忎釜绔彛鎺㈡祴鐨勮矾寰?(鎸変紭鍏堢骇鎺掑簭)
_PORT_PROBE_PATHS: list[str] = [
    "/.well-known/agent.json",   # A2A Agent Card
    "/mcp",                       # MCP endpoint
    "/health",                    # 鍋ュ悍妫€鏌?
    "/api/health",                # API 鍋ュ悍妫€鏌?
    "/v1/models",                 # OpenAI 鍏煎 API
]

# 鏈嶅姟绫诲瀷鎺ㄦ柇鍏抽敭璇?
_SERVICE_TYPE_KEYWORDS: dict[str, list[str]] = {
    "mcp": ["mcp", "model context protocol", "jsonrpc", "json-rpc"],
    "a2a": ["agent card", "a2a", "agent-to-agent", "capabilities", "skills"],
    "llm_api": ["models", "openai", "completion", "chat", "inference"],
    "agent": ["agent", "tool", "function", "workflow"],
}


@dataclass
class DiscoveredPortEndpoint:
    """鍙戠幇鐨勭鍙ｇ鐐广€?

    灞炴€?
        port: 绔彛鍙枫€?
        path: 鎺㈡祴璺緞銆?
        status_code: HTTP 鐘舵€佺爜銆?
        content_type: 鍝嶅簲 Content-Type銆?
        response_preview: 鍝嶅簲浣撻瑙?(鍓?200 瀛楃)銆?
        service_type: 鎺ㄦ柇鐨勬湇鍔＄被鍨?(mcp/a2a/llm_api/agent/unknown)銆?
        use_tls: 鏄惁浣跨敤 TLS銆?
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
    """鎺㈡祴鍚屼富鏈哄叾浠栫鍙ｄ笂鐨?AI 鏈嶅姟銆?

    瀛︽湳渚濇嵁:
        - Arbis et al. (arXiv:2306.01943) 搂4.5 鈥?璺ㄧ鍙ｇ鐐瑰彂鐜?
        - PTES 搂2 鈥?鎯呮姤鏀堕泦闃舵绔彛鍙戠幇

    绛栫暐:
        1. 浠庡師濮嬭姹傛彁鍙?host
        2. 瀵瑰父瑙?AI 鏈嶅姟绔彛骞跺彂鎺㈡祴
        3. 姣忎釜绔彛鎺㈡祴 5 涓叧閿矾寰?
        4. 浠庡搷搴旀帹鏂湇鍔＄被鍨?
        5. 鍙戠幇鐨勭鐐硅繑鍥炰緵鍚庣画鏋勫缓 HTTPTarget

    鏁堢巼浼樺寲:
        - 姣忕鍙ｅ彧鎺㈡祴 5 涓矾寰?(涓嶆槸鍏ㄩ噺绔偣鍙戠幇)
        - 瓒呮椂 3s (绔彛鍙兘鍏抽棴, 蹇€熷け璐?
        - 骞跺彂鎺у埗 max_concurrent (榛樿 10)
        - 鏃╂湡缁堟: 鍙戠幇 early_stop 涓鍙ｇ鐐瑰嵆鍋滄

    Args:
        parsed: ParsedBurpRequest 瀹炰緥 (鎻愬彇 host 鍜?TLS 淇℃伅)銆?
        timeout: 姣忎釜鎺㈡祴璇锋眰鐨勮秴鏃剁鏁般€?
        max_concurrent: 鏈€澶у苟鍙戞帰娴嬫暟銆?
        early_stop: 鍙戠幇 N 涓鍙ｇ鐐瑰嵆鍋滄銆?
        custom_ports: 鑷畾涔夌鍙ｅ垪琛?(None = 浣跨敤榛樿 AI 绔彛鍒楄〃)銆?

    Returns:
        鍙戠幇鐨勭鍙ｇ鐐瑰垪琛ㄣ€?
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

    # 骞跺彂鎺㈡祴鎵€鏈夌鍙?
    semaphore = asyncio.Semaphore(max_concurrent)
    results: list[DiscoveredPortEndpoint] = []
    results_lock = asyncio.Lock()

    async def _probe_port(port: int) -> None:
        nonlocal results

        # 鏃╂湡缁堟妫€鏌?
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
    """鎺㈡祴鍗曚釜绔彛鐨勫涓矾寰勩€?

    Args:
        host: 涓绘満鍚嶃€?
        port: 绔彛鍙枫€?
        use_tls: 鏄惁浣跨敤 TLS銆?
        timeout: 瓒呮椂绉掓暟銆?

    Returns:
        鍙戠幇鐨勭鐐瑰垪琛?(鍙兘涓虹┖)銆?
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

                    # 鍙褰曟湁鎰忎箟鐨勫搷搴?(闈?404/杩炴帴澶辫触)
                    if response.status_code == 404:
                        continue

                    # 鎺ㄦ柇鏈嶅姟绫诲瀷
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
                        "Port %d: %s 鈫?HTTP %d (%s)",
                        port, path, response.status_code, service_type,
                    )

                    # 棣栦釜鏈夋剰涔夊搷搴斿嵆鍙唬琛ㄨ绔彛
                    break

                except (httpx.TimeoutException, httpx.ConnectError):
                    # 绔彛鍏抽棴鎴栦笉鏀寔, 璺宠繃
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
    """浠庡搷搴旀帹鏂湇鍔＄被鍨嬨€?

    Args:
        status_code: HTTP 鐘舵€佺爜銆?
        content_type: Content-Type header銆?
        body_preview: 鍝嶅簲浣撻瑙堛€?

    Returns:
        鏈嶅姟绫诲瀷 (mcp/a2a/llm_api/agent/unknown)銆?
    """
    text = f"{content_type} {body_preview}".lower()

    for service_type, keywords in _SERVICE_TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                return service_type

    # JSON 鍝嶅簲浣嗘棤娉曠‘瀹氱被鍨?
    if "json" in content_type.lower() and status_code == 200:
        return "unknown"

    return "unknown"


def _extract_host(parsed: Any) -> str:
    """浠?ParsedBurpRequest 鎻愬彇 host銆?

    浼樺厛绾?
        1. parsed.host (宸茶В鏋?
        2. 浠?Host header 涓彁鍙?
        3. 浠?raw_request 绗竴琛屼腑鎻愬彇
    """
    # 鐩存帴灞炴€?
    host = getattr(parsed, "host", None)
    if host:
        # 鍘婚櫎绔彛鍙?
        if ":" in str(host):
            return str(host).split(":")[0]
        return str(host)

    # 浠?headers 鎻愬彇
    headers = getattr(parsed, "headers", {})
    host_header = headers.get("host", headers.get("Host", ""))
    if host_header:
        if ":" in host_header:
            return host_header.split(":")[0]
        return host_header

    # 浠?raw_request 鎻愬彇
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
    """浠?ParsedBurpRequest 鎻愬彇 TLS 淇℃伅銆?

    浼樺厛绾?
        1. parsed.use_tls / parsed.is_https
        2. 浠?raw_request 绗竴琛屽垽鏂?(HTTPS)
        3. 浠庣鍙ｅ垽鏂?(443 = TLS)
    """
    # 鐩存帴灞炴€?
    for attr in ("use_tls", "is_https", "tls"):
        val = getattr(parsed, attr, None)
        if val is not None:
            return bool(val)

    # 浠?raw_request 鍒ゆ柇
    raw = getattr(parsed, "raw_request", "")
    if raw:
        first_line = raw.split("\n")[0].upper()
        if "HTTPS" in first_line:
            return True

    # 浠庣鍙ｅ垽鏂?
    port = getattr(parsed, "port", None)
    if port == 443:
        return True

    return False


def build_port_parsed_request(
    original_parsed: Any,
    port_endpoint: DiscoveredPortEndpoint,
) -> dict[str, Any]:
    """浠庣鍙ｇ鐐规瀯寤鸿姹傚弬鏁?(渚涘悗缁瀯寤?HTTPTarget)銆?

    Args:
        original_parsed: 鍘熷 ParsedBurpRequest銆?
        port_endpoint: 鍙戠幇鐨勭鍙ｇ鐐广€?

    Returns:
        璇锋眰鍙傛暟瀛楀吀 (host, port, path, use_tls, method, headers)銆?
    """
    host = _extract_host(original_parsed)
    original_headers = getattr(original_parsed, "headers", {})

    # 淇濈暀鍘熷璁よ瘉 headers, 鍘绘帀 Host
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

