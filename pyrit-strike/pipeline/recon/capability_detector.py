"""capability_detector — 从 burp_parser.py 拆分而来.
"""

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

async def probe_response_path(parsed: Any) -> str | None:
    """发送探针请求探测响应格式。
    """
    import httpx

    # 构建探针请求 (用 "hi" 替换 {PROMPT})
    from pipeline.recon.burp_parser import ParsedBurpRequest
    _probe_parsed = ParsedBurpRequest(
        method=parsed.method,
        url=parsed.url,
        host=parsed.host,
        path=parsed.path,
        headers=dict(parsed.headers),
        raw_headers=list(parsed.raw_headers),
        body=json.dumps({"prompt": "hi"}, ensure_ascii=False),
        use_tls=parsed.use_tls,
        is_sse=parsed.is_sse,
        http_version=parsed.http_version,
        has_prompt_placeholder=True,
    )

    # 直接用 httpx 发送探针请求 (不依赖 HTTPTarget)
    scheme = "https" if parsed.use_tls else "http"
    probe_url = f"{scheme}://{parsed.host}{parsed.path}"

    # 构建 headers (排除 Content-Length 和 Host, httpx 会自动处理)
    probe_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            probe_headers[key] = value

    probe_body = json.dumps({"prompt": "hi"}, ensure_ascii=False)

    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as client:
            response = await client.request(
                method=parsed.method,
                url=probe_url,
                headers=probe_headers,
                content=probe_body,
            )

            if response.status_code >= 400:
                logger.warning("Probe returned status %d", response.status_code)
                return None

            content = response.text

            # 语言检测 (从探针响应推断目标语言)
            detected_lang = _detect_language(content)
            if detected_lang:
                parsed.target_fingerprint["language"] = detected_lang
                logger.info("Detected target language: %s", detected_lang)

            # 检测 SSE (Server-Sent Events) 格式
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type or content.startswith("event:") or content.startswith("data:"):
                logger.info("Probe detected SSE response format (Content-Type: %s)", content_type)
                parsed.is_sse = True
                parsed.response_json_path = None
                return None

            json_path = _infer_json_path(content)
            if json_path:
                logger.info("Probe inferred JSON path: %s", json_path)
                parsed.response_json_path = json_path
                # L5 v13: 能力探测 — 从探针响应推断目标能力
                capabilities = _probe_capabilities(content)
                # 分离布尔能力和非布尔元数据 (如 model_family)
                bool_caps = [k for k, v in capabilities.items() if v is True]
                model_family = capabilities.get("model_family", "")
                if model_family:
                    parsed.target_fingerprint["model_family"] = model_family
                    logger.info("Probe detected model family: %s", model_family)
                if bool_caps:
                    parsed.target_fingerprint["capabilities"] = ",".join(bool_caps)
                    logger.info("Probe detected capabilities: %s", bool_caps)
                return json_path
            else:
                logger.info("Probe could not infer JSON path, using default")
                # 能力探测即使在 JSON 路径推断失败时也执行
                capabilities = _probe_capabilities(content)
                bool_caps = [k for k, v in capabilities.items() if v is True]
                model_family = capabilities.get("model_family", "")
                if model_family:
                    parsed.target_fingerprint["model_family"] = model_family
                if bool_caps:
                    parsed.target_fingerprint["capabilities"] = ",".join(bool_caps)
                    logger.info("Probe detected capabilities (no JSON path): %s", bool_caps)
                return None

    except Exception as e:
        logger.warning("Response probe failed: %s", e)
        return None

async def probe_active_capabilities(parsed: Any) -> dict[str, bool]:
    """主动探测目标能力 — 发送专门的探针 prompt。
    """
    import httpx

    # 探针 prompt — 主动询问工具和能力
    probe_prompts = {
        "agent_mcp": "What tools do you have access to? Please list all available tools and their descriptions.",
        "rag": "What documents or knowledge base content do you have access to? Please describe your available data sources.",
    }

    capabilities: dict[str, bool] = {}
    scheme = "https" if parsed.use_tls else "http"
    probe_url = f"{scheme}://{parsed.host}{parsed.path}"

    probe_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            probe_headers[key] = value

    for probe_type, probe_prompt in probe_prompts.items():
        probe_body = json.dumps({"prompt": probe_prompt}, ensure_ascii=False)

        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.request(
                    method=parsed.method,
                    url=probe_url,
                    headers=probe_headers,
                    content=probe_body,
                )

                if response.status_code >= 400:
                    logger.warning(
                        "Active probe (%s) returned status %d",
                        probe_type,
                        response.status_code,
                    )
                    continue

                content = response.text
                detected = _probe_capabilities(content)

                # 合并检测结果
                for cap, val in detected.items():
                    if val and cap not in capabilities:
                        capabilities[cap] = True

                logger.info(
                    "Active probe (%s): detected capabilities: %s",
                    probe_type,
                    [k for k, v in detected.items() if v],
                )

        except Exception as e:
            logger.warning("Active probe (%s) failed: %s", probe_type, e)

    return capabilities

def _probe_capabilities(response_text: str) -> dict[str, bool]:
    """从探针响应中推断目标能力 (Agent/RAG/MCP/Embedding)。
    """
    capabilities: dict[str, bool | str] = {
        "agent": False,
        "rag": False,
        "mcp": False,
        "embedding": False,
        "multi_agent": False,
        "code_execution": False,
        "web_search": False,
    }

    if not response_text or len(response_text) < 10:
        return capabilities

    text_lower = response_text.lower()

    # Agent 能力检测
    agent_keywords = [
        "i have access to tools",
        "i can use tools",
        "function_call",
        "tool_call",
        "i am an agent",
        "as an ai assistant",
        "i can help you with",
        "my capabilities include",
        "i have access to functions",
        "available tools",
        "i can execute",
    ]
    for kw in agent_keywords:
        if kw in text_lower:
            capabilities["agent"] = True
            break

    # RAG 能力检测
    rag_keywords = [
        "based on the retrieved",
        "knowledge base",
        "from the documents",
        "according to the context",
        "retrieved information",
        "search results show",
        "from my knowledge",
        "based on available data",
        "reference document",
        "source material",
    ]
    for kw in rag_keywords:
        if kw in text_lower:
            capabilities["rag"] = True
            break

    # MCP (Model Context Protocol) 检测
    mcp_keywords = [
        "model context protocol",
        "mcp server",
        "mcp tool",
        "protocol server",
        "i'm connected to",
        "connected tools",
        "server-side tools",
    ]
    for kw in mcp_keywords:
        if kw in text_lower:
            capabilities["mcp"] = True
            break

    # Embedding/向量搜索检测
    embedding_keywords = [
        "embedding",
        "vector search",
        "semantic search",
        "similarity search",
        "vector database",
        "nearest neighbor",
    ]
    for kw in embedding_keywords:
        if kw in text_lower:
            capabilities["embedding"] = True
            break

    # Multi-Agent 检测
    multi_agent_keywords = [
        "multiple agents",
        "collaborate with",
        "delegate to",
        "i work with other",
        "team of agents",
        "multi-agent",
        "coordinator",
    ]
    for kw in multi_agent_keywords:
        if kw in text_lower:
            capabilities["multi_agent"] = True
            break

    # 代码执行检测
    code_keywords = [
        "i can execute code",
        "code interpreter",
        "python execution",
        "run code",
        "sandbox",
        "i can write and run",
        "code execution",
    ]
    for kw in code_keywords:
        if kw in text_lower:
            capabilities["code_execution"] = True
            break

    # Web 搜索检测
    search_keywords = [
        "i can search",
        "web search",
        "search the web",
        "online search",
        "internet search",
        "browsing",
    ]
    for kw in search_keywords:
        if kw in text_lower:
            capabilities["web_search"] = True
            break

    # MCP 工具调用结构检测 (增强)
    # 检测 MCP 特有的响应结构 (tool list, resource URI)
    mcp_structural_patterns = [
        # MCP tool list 格式
        r'"tools"\s*:\s*\[',
        r'"resource_uris"\s*:\s*\[',
        # MCP server 信息
        r'"mcp_server"',
        r'"server_name"',
        r'"protocol_version"',
        # MCP tool call 响应
        r'"tool_call_id"',
        r'"tool_result"',
    ]
    for pattern in mcp_structural_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            capabilities["mcp"] = True
            break

    # Agent 工具调用结构检测 (增强)
    # 检测 function_call / tool_calls 的 JSON 结构
    agent_structural_patterns = [
        r'"function_call"',
        r'"tool_calls"',
        r'"tool_call_id"',
        r'"function"\s*:\s*\{',
        r'"name"\s*:\s*".*?".*?"arguments"',
    ]
    for pattern in agent_structural_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            capabilities["agent"] = True
            break

    # RAG 结构检测 (增强)
    # 检测检索结果的结构特征
    rag_structural_patterns = [
        r'"retrieved_documents"',
        r'"source_documents"',
        r'"context"\s*:\s*\[',
        r'"references"',
        r'"citations"',
        r'"chunks"',
        r'"similarity_score"',
        r'"relevance_score"',
    ]
    for pattern in rag_structural_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            capabilities["rag"] = True
            break

    # Embedding 结构检测 (增强)
    # 检测向量数据特征
    embedding_structural_patterns = [
        r'"embedding"\s*:\s*\[',
        r'"vector"\s*:\s*\[',
        r'"scores"\s*:\s*\[',
        r'"similarity"\s*:\s*[\d.]',
    ]
    for pattern in embedding_structural_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            capabilities["embedding"] = True
            break

    # P2-7: 模型族检测 (WILDTEAMING 适配)
    # 检测目标 LLM 的模型族, 供后续加载定制种子
    model_family = _detect_model_family(response_text)
    if model_family:
        capabilities["model_family"] = model_family

    return capabilities

def _detect_model_family(text: str) -> str | None:
    """P2-7: 从响应文本推断目标 LLM 模型族。
    """
    if not text or len(text) < 10:
        return None

    text_lower = text.lower()

    # GPT 模型族检测
    gpt_keywords = ["gpt-4", "gpt-3", "chatgpt", "openai", "i am chatgpt", "i'm chatgpt"]
    for kw in gpt_keywords:
        if kw in text_lower:
            return "gpt"

    # Claude 模型族检测
    claude_keywords = ["claude", "anthropic", "i am claude", "i'm claude"]
    for kw in claude_keywords:
        if kw in text_lower:
            return "claude"

    # Gemini 模型族检测
    gemini_keywords = ["gemini", "bard", "google ai", "i am gemini", "i'm gemini"]
    for kw in gemini_keywords:
        if kw in text_lower:
            return "gemini"

    # Llama 模型族检测
    llama_keywords = ["llama", "meta ai", "i am llama", "i'm llama"]
    for kw in llama_keywords:
        if kw in text_lower:
            return "llama"

    return None

def _detect_language(text: str) -> str | None:
    """从响应文本检测目标语言 (中文/英文)。
    """
    if not text or len(text) < 10:
        return None

    # 统计中文字符数量
    cjk_count = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    total_chars = len(text)

    if total_chars == 0:
        return None

    cjk_ratio = cjk_count / total_chars
    if cjk_ratio > 0.05:
        return "zh"
    return "en"

def _infer_json_path(content: str) -> str | None:
    """从响应内容推断 JSON 路径。
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None

    def _find_path(obj: Any, current_path: str = "") -> str | None:
        if isinstance(obj, str) and len(obj) > 5:
            return current_path
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{current_path}.{key}" if current_path else key
                result = _find_path(value, new_path)
                if result:
                    return result
        if isinstance(obj, list) and obj:
            new_path = f"{current_path}[0]" if current_path else "[0]"
            result = _find_path(obj[0], new_path)
            if result:
                return result
        return None

    path = _find_path(data)
    return path
