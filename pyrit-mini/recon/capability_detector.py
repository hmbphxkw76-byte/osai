"""capability_detector 鈥?浠?burp_parser.py 鎷嗗垎鑰屾潵.

鍖呭惈鍝嶅簲璺緞鎺㈡祴, 涓诲姩鑳藉姏鎺㈡祴, 妯″瀷瀹舵棌妫€娴? 璇█妫€娴?
"""

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

async def probe_response_path(parsed: Any) -> str | None:
    """鍙戦€佹帰閽堣姹傛帰娴嬪搷搴旀牸寮忋€?

    鍙戦€佹祴璇曡姹?``"hi"``锛屽垎鏋愬搷搴?JSON 缁撴瀯锛?
    鑷姩鎺ㄦ柇鍐呭璺緞 (濡?``choices[0].message.content``)銆?

    Args:
        parsed: 瑙ｆ瀽鍚庣殑 Burp 璇锋眰銆?

    Returns:
        鎺ㄦ柇鐨?JSON 璺緞锛屽け璐ヨ繑鍥?None銆?
    """
    import httpx

    # 鏋勫缓鎺㈤拡璇锋眰 (鐢?"hi" 鏇挎崲 {PROMPT})
    from recon.burp_parser import ParsedBurpRequest
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

    # 鐩存帴鐢?httpx 鍙戦€佹帰閽堣姹?(涓嶄緷璧?HTTPTarget)
    scheme = "https" if parsed.use_tls else "http"
    probe_url = f"{scheme}://{parsed.host}{parsed.path}"

    # 鏋勫缓 headers (鎺掗櫎 Content-Length 鍜?Host, httpx 浼氳嚜鍔ㄥ鐞?
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

            # 璇█妫€娴?(浠庢帰閽堝搷搴旀帹鏂洰鏍囪瑷€)
            detected_lang = _detect_language(content)
            if detected_lang:
                parsed.target_fingerprint["language"] = detected_lang
                logger.info("Detected target language: %s", detected_lang)

            # 妫€娴?SSE (Server-Sent Events) 鏍煎紡
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
                # L5 v13: 鑳藉姏鎺㈡祴 鈥?浠庢帰閽堝搷搴旀帹鏂洰鏍囪兘鍔?
                # 瀛︽湳渚濇嵁: Greshake et al. (arXiv:2302.12173), Zhan et al. (arXiv:2307.00929)
                capabilities = _probe_capabilities(content)
                # 鍒嗙甯冨皵鑳藉姏鍜岄潪甯冨皵鍏冩暟鎹?(濡?model_family)
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
                # 鑳藉姏鎺㈡祴鍗充娇鍦?JSON 璺緞鎺ㄦ柇澶辫触鏃朵篃鎵ц
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
    """涓诲姩鎺㈡祴鐩爣鑳藉姏 鈥?鍙戦€佷笓闂ㄧ殑鎺㈤拡 prompt銆?

    瀛︽湳渚濇嵁:
        - Greshake et al. (arXiv:2302.12173) 鈥?闂存帴鎻愮ず娉ㄥ叆
        - Zhan et al. (arXiv:2307.00929) 鈥?InjecAgent
        - Anthropic MCP Specification (2024)

    绛栫暐 (涓诲姩鎺㈡祴):
        1. 鍙戦€?"list available tools" 妫€娴?Agent/MCP 宸ュ叿
        2. 鍙戦€?"what documents are in your knowledge base" 妫€娴?RAG
        3. 鍒嗘瀽鍝嶅簲缁撴瀯鍜屽唴瀹瑰叧閿瘝

    姣旇鍔ㄥ叧閿瘝鍖归厤鏇村彲闈? 鍥犱负:
        - 鐩爣 LLM 鍙兘涓嶄細鍦ㄦ櫘閫氬搷搴斾腑鎻愬強宸ュ叿
        - 浣嗗綋琚洿鎺ヨ闂椂浼氬垪鍑哄彲鐢ㄥ伐鍏?
        - MCP server 鐨勫伐鍏峰垪琛ㄦ湁鐗瑰畾 JSON 缁撴瀯

    Args:
        parsed: 瑙ｆ瀽鍚庣殑 Burp 璇锋眰銆?

    Returns:
        澧炲己鍚庣殑鑳藉姏妫€娴嬪瓧鍏搞€?
    """
    import httpx

    # 鎺㈤拡 prompt 鈥?涓诲姩璇㈤棶宸ュ叿鍜岃兘鍔?
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

                # 鍚堝苟妫€娴嬬粨鏋?
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
    """浠庢帰閽堝搷搴斾腑鎺ㄦ柇鐩爣鑳藉姏 (Agent/RAG/MCP/Embedding)銆?

    瀛︽湳渚濇嵁:
        - Greshake et al. (arXiv:2302.12173) 鈥?闂存帴鎻愮ず娉ㄥ叆, Agent 鍦烘櫙
        - Zhan et al. (arXiv:2307.00929) 鈥?InjecAgent, Agent 娉ㄥ叆鏀诲嚮
        - arXiv:2402.04249 鈥?HarmBench 鑳藉姏璇勪及

    鎺㈡祴绛栫暐 (鍏抽敭璇嶅尮閰?:
        1. Agent: 鍝嶅簲涓彁鍙?tools, function_call, agent, assistant
        2. RAG: 鍝嶅簲涓彁鍙?retrieve, knowledge_base, context, documents
        3. MCP: 鍝嶅簲涓彁鍙?model_context_protocol, mcp_server, tools
        4. Embedding: 鍝嶅簲涓彁鍙?embedding, vector_search, semantic_search
        5. Multi-Agent: 鍝嶅簲涓彁鍙?multiple agents, collaborate, delegate

    Args:
        response_text: 鎺㈤拡鍝嶅簲鏂囨湰銆?

    Returns:
        鑳藉姏妫€娴嬪瓧鍏?{capability: detected}銆俶odel_family 涓哄瓧绗︿覆, 鍏朵綑涓?bool銆?
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

    # Agent 鑳藉姏妫€娴?
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

    # RAG 鑳藉姏妫€娴?
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

    # MCP (Model Context Protocol) 妫€娴?
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

    # Embedding/鍚戦噺鎼滅储妫€娴?
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

    # Multi-Agent 妫€娴?
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

    # 浠ｇ爜鎵ц妫€娴?
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

    # Web 鎼滅储妫€娴?
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

    # MCP 宸ュ叿璋冪敤缁撴瀯妫€娴?(澧炲己)
    # 瀛︽湳渚濇嵁: Anthropic MCP Specification (2024)
    # 妫€娴?MCP 鐗规湁鐨勫搷搴旂粨鏋?(tool list, resource URI)
    mcp_structural_patterns = [
        # MCP tool list 鏍煎紡
        r'"tools"\s*:\s*\[',
        r'"resource_uris"\s*:\s*\[',
        # MCP server 淇℃伅
        r'"mcp_server"',
        r'"server_name"',
        r'"protocol_version"',
        # MCP tool call 鍝嶅簲
        r'"tool_call_id"',
        r'"tool_result"',
    ]
    for pattern in mcp_structural_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            capabilities["mcp"] = True
            break

    # Agent 宸ュ叿璋冪敤缁撴瀯妫€娴?(澧炲己)
    # 瀛︽湳渚濇嵁: Zhan et al. (arXiv:2307.00929) 鈥?InjecAgent
    # 妫€娴?function_call / tool_calls 鐨?JSON 缁撴瀯
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

    # RAG 缁撴瀯妫€娴?(澧炲己)
    # 瀛︽湳渚濇嵁: Shafran et al. (arXiv:2402.07967) 鈥?RAG 瀹夊叏
    # 妫€娴嬫绱㈢粨鏋滅殑缁撴瀯鐗瑰緛
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

    # Embedding 缁撴瀯妫€娴?(澧炲己)
    # 妫€娴嬪悜閲忔暟鎹壒寰?
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

    # P2-7: 妯″瀷鏃忔娴?(WILDTEAMING 閫傞厤)
    # 瀛︽湳渚濇嵁: Mazeika et al. (arXiv:2406.18510) 鈥?涓嶅悓妯″瀷鏃忓畨鍏ㄥ榻愮瓥鐣ヤ笉鍚?
    # 妫€娴嬬洰鏍?LLM 鐨勬ā鍨嬫棌, 渚涘悗缁姞杞藉畾鍒剁瀛?
    model_family = _detect_model_family(response_text)
    if model_family:
        capabilities["model_family"] = model_family

    return capabilities

def _detect_model_family(text: str) -> str | None:
    """P2-7: 浠庡搷搴旀枃鏈帹鏂洰鏍?LLM 妯″瀷鏃忋€?

    瀛︽湳渚濇嵁: Mazeika et al. (arXiv:2406.18510) 鈥?WILDTEAMING
        涓嶅悓妯″瀷鏃?(GPT/Claude/Gemini/Llama) 鐨勫畨鍏ㄥ榻愮瓥鐣ヤ笉鍚?
        瀹氬埗绉嶅瓙鍙彁鍗?ASR銆?

    妫€娴嬬瓥鐣?
        1. GPT: 鍝嶅簲涓彁鍙?"GPT", "OpenAI", "ChatGPT"
        2. Claude: 鍝嶅簲涓彁鍙?"Claude", "Anthropic"
        3. Gemini: 鍝嶅簲涓彁鍙?"Gemini", "Bard", "Google"
        4. Llama: 鍝嶅簲涓彁鍙?"Llama", "Meta AI"

    Args:
        text: 鎺㈤拡鍝嶅簲鏂囨湰銆?

    Returns:
        妯″瀷鏃忔爣璇?("gpt"/"claude"/"gemini"/"llama"), 鏃犳硶鍒ゆ柇鏃惰繑鍥?None銆?
    """
    if not text or len(text) < 10:
        return None

    text_lower = text.lower()

    # GPT 妯″瀷鏃忔娴?
    gpt_keywords = ["gpt-4", "gpt-3", "chatgpt", "openai", "i am chatgpt", "i'm chatgpt"]
    for kw in gpt_keywords:
        if kw in text_lower:
            return "gpt"

    # Claude 妯″瀷鏃忔娴?
    claude_keywords = ["claude", "anthropic", "i am claude", "i'm claude"]
    for kw in claude_keywords:
        if kw in text_lower:
            return "claude"

    # Gemini 妯″瀷鏃忔娴?
    gemini_keywords = ["gemini", "bard", "google ai", "i am gemini", "i'm gemini"]
    for kw in gemini_keywords:
        if kw in text_lower:
            return "gemini"

    # Llama 妯″瀷鏃忔娴?
    llama_keywords = ["llama", "meta ai", "i am llama", "i'm llama"]
    for kw in llama_keywords:
        if kw in text_lower:
            return "llama"

    return None

def _detect_language(text: str) -> str | None:
    """浠庡搷搴旀枃鏈娴嬬洰鏍囪瑷€ (涓枃/鑻辨枃)銆?

    閫氳繃 Unicode 瀛楃鑼冨洿鍒ゆ柇:
        - 涓枃瀛楃 (CJK Unified Ideographs U+4E00-U+9FFF) 鍗犳瘮 > 10% 鈫?"zh"
        - 鍚﹀垯 鈫?"en"

    Args:
        text: 鍝嶅簲鏂囨湰銆?

    Returns:
        "zh" 鎴?"en", 鏃犳硶鍒ゆ柇鏃惰繑鍥?None銆?
    """
    if not text or len(text) < 10:
        return None

    # 缁熻涓枃瀛楃鏁伴噺
    cjk_count = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    total_chars = len(text)

    if total_chars == 0:
        return None

    cjk_ratio = cjk_count / total_chars
    if cjk_ratio > 0.05:
        return "zh"
    return "en"

def _infer_json_path(content: str) -> str | None:
    """浠庡搷搴斿唴瀹规帹鏂?JSON 璺緞銆?

    閫掑綊鏌ユ壘绗竴涓湁鎰忎箟鐨勫瓧绗︿覆鍊硷紝杩斿洖鍏?JSON 璺緞銆?
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

