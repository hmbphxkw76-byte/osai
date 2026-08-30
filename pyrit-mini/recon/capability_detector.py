"""capability_detector — 从 burp_parser.py 拆分而来。

包含响应路径探测, 主动能力探测, 模型族检测, 语言检测。

适配任意 LLM 应用:
    探针请求使用 parsed.body 模板 (已含 {PROMPT} 占位符),
    替换 {PROMPT} 为探针文本, 而非硬编码 body 格式,
    确保 Baidu/Qwen/DeepSeek 等不同 body 结构都能正确探测。
"""

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def _build_probe_body(parsed: Any, probe_text: str) -> str:
    """从 parsed.body 模板构建探针请求 body。

    使用 parsed.body (已含 {PROMPT} 和 {CHAT_ID} 占位符),
    替换 {PROMPT} 为探针文本, {CHAT_ID} 为当前会话 ID。
    如果 parsed.body 不存在, fallback 到 {"prompt": probe_text}。

    Args:
        parsed: 解析后的 Burp 请求。
        probe_text: 探针文本 (如 "hi" 或能力探测 prompt)。

    Returns:
        探针请求 body 字符串。
    """
    if parsed.body and "{PROMPT}" in parsed.body:
        body = parsed.body.replace("{PROMPT}", probe_text)
        # 替换 {CHAT_ID} 占位符
        if "{CHAT_ID}" in body:
            chat_id_val = parsed.chat_id or ""
            body = body.replace("{CHAT_ID}", chat_id_val)
        return body
    # fallback: 简单 JSON body
    return json.dumps({"prompt": probe_text}, ensure_ascii=False)


async def probe_response_path(parsed: Any) -> str | None:
    """发送探针请求探测响应格式。

    发送测试请求 (用 "hi" 替换 {PROMPT}), 分析响应 JSON 结构,
    自动推断内容路径 (如 ``choices[0].message.content``)。

    适配任意 LLM 应用的 body 结构:
        使用 parsed.body (已含 {PROMPT} 占位符) 替换 {PROMPT} 为探针文本,
        而非硬编码 body 格式, 确保 Baidu/Qwen/DeepSeek 等都能正确探测。

    Args:
        parsed: 解析后的 Burp 请求。

    Returns:
        推断的 JSON 路径, 失败返回 None。
    """
    import httpx

    # 构建探针 body: 用 parsed.body 模板替换 {PROMPT}
    probe_body = _build_probe_body(parsed, "hi")

    # 直接用 httpx 发送探针请求 (不依赖 HTTPTarget)
    scheme = "https" if parsed.use_tls else "http"
    probe_url = f"{scheme}://{parsed.host}{parsed.path}"

    # 构建 headers (排除 Content-Length 和 Host, httpx 会自动处理)
    probe_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            probe_headers[key] = value

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
                # 从 SSE 响应中提取 chat_id (用于后续多轮攻击的会话继承)
                from recon.burp_parser import _extract_chat_id_from_response, _extract_model_info_from_response
                probe_chat_id = _extract_chat_id_from_response(content)
                if probe_chat_id:
                    parsed.chat_id = probe_chat_id
                    parsed.target_fingerprint["chat_id"] = probe_chat_id
                    logger.info("Probe extracted chat_id from SSE response: %s", probe_chat_id)
                # L5 v53: 从探针响应中提取模型信息
                probe_model_name, probe_model_list = _extract_model_info_from_response(content)
                if probe_model_name:
                    parsed.burp_model_name = probe_model_name
                    parsed.target_fingerprint["burp_model_name"] = probe_model_name
                    logger.info("Probe extracted model name from response: %s", probe_model_name)
                if probe_model_list:
                    parsed.burp_model_list = probe_model_list
                    parsed.target_fingerprint["burp_model_list"] = "yes"
                    logger.info("Probe extracted model list from response")
                return None

            json_path = _infer_json_path(content)
            if json_path:
                logger.info("Probe inferred JSON path: %s", json_path)
                parsed.response_json_path = json_path
                # L5 v53: 从探针响应中提取模型信息
                from recon.burp_parser import _extract_model_info_from_response
                probe_model_name, probe_model_list = _extract_model_info_from_response(content)
                if probe_model_name:
                    parsed.burp_model_name = probe_model_name
                    parsed.target_fingerprint["burp_model_name"] = probe_model_name
                    logger.info("Probe extracted model name from JSON response: %s", probe_model_name)
                if probe_model_list:
                    parsed.burp_model_list = probe_model_list
                    parsed.target_fingerprint["burp_model_list"] = "yes"
                    logger.info("Probe extracted model list from JSON response")
                # 能力探测 — 从探针响应推断目标能力
                # 学术依据: Greshake et al. (arXiv:2302.12173), Zhan et al. (arXiv:2307.00929)
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

    学术依据:
        - Greshake et al. (arXiv:2302.12173) — 间接提示注入
        - Zhan et al. (arXiv:2307.00929) — InjecAgent
        - Anthropic MCP Specification (2024)

    策略 (主动探测):
        1. 发送 "list available tools" 探测 Agent/MCP 工具
        2. 发送 "what documents are in your knowledge base" 探测 RAG
        3. 分析响应结构和内容关键词

    适配任意 LLM 应用:
        探针请求使用 parsed.body 模板替换 {PROMPT},
        而非硬编码 {"prompt": "..."} body 格式。

    Args:
        parsed: 解析后的 Burp 请求。

    Returns:
        增强后的能力探测字典。
    """
    import httpx

    # 探针 prompt — 主动询问工具和能力
    # P2-20: 新增 model_identity 探针 — 从响应文本中推断模型族
    # 学术依据: Mazeika et al. (arXiv:2406.18510) — WILDTEAMING
    #   不同模型族安全对齐策略不同, 定制种子可提升 ASR
    probe_prompts = {
        "agent_mcp": "What tools do you have access to? Please list all available tools and their descriptions.",
        "rag": "What documents or knowledge base content do you have access to? Please describe your available data sources.",
        "model_identity": "What AI model are you? State your exact model name, version number, and developer company. Are you GPT, Claude, Gemini, Llama, Qwen, DeepSeek, ERNIE, or another model?",
    }

    capabilities: dict[str, bool] = {}
    scheme = "https" if parsed.use_tls else "http"
    probe_url = f"{scheme}://{parsed.host}{parsed.path}"

    probe_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            probe_headers[key] = value

    # 复用单个 AsyncClient 实例, 避免重复 TCP 连接开销
    # 学术依据: Arbis et al. (arXiv:2306.01943) §4.5 — 探测效率优化
    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=True,
        verify=False,
    ) as client:
        for probe_type, probe_prompt in probe_prompts.items():
            # 使用 parsed.body 模板替换 {PROMPT}, 而非硬编码 body 格式
            probe_body = _build_probe_body(parsed, probe_prompt)

            try:
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

                # 合并探测结果
                # model_family 是字符串 (如 "gpt"), 其余是 bool
                for cap, val in detected.items():
                    if not val:
                        continue
                    if cap == "model_family":
                        capabilities["model_family"] = val
                    elif cap not in capabilities:
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

    学术依据:
        - Greshake et al. (arXiv:2302.12173) — 间接提示注入, Agent 场景
        - Zhan et al. (arXiv:2307.00929) — InjecAgent, Agent 注入攻击
        - arXiv:2402.04249 — HarmBench 能力评估

    探测策略 (关键词匹配):
        1. Agent: 响应中提及 tools, function_call, agent, assistant
        2. RAG: 响应中提及 retrieve, knowledge_base, context, documents
        3. MCP: 响应中提及 model_context_protocol, mcp_server, tools
        4. Embedding: 响应中提及 embedding, vector_search, semantic_search
        5. Multi-Agent: 响应中提及 multiple agents, collaborate, delegate

    Args:
        response_text: 探针响应文本。

    Returns:
        能力探测字典 {capability: detected}。model_family 为字符串, 其余为 bool。
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

    # Agent 能力探测
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

    # RAG 能力探测
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

    # MCP (Model Context Protocol) 探测
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

    # Embedding/向量搜索探测
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

    # Multi-Agent 探测
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

    # 代码执行探测
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

    # Web 搜索探测
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

    # MCP 工具调用结构探测 (增强)
    # 学术依据: Anthropic MCP Specification (2024)
    # 探测 MCP 特有的响应结果 (tool list, resource URI)
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

    # Agent 工具调用结构探测 (增强)
    # 学术依据: Zhan et al. (arXiv:2307.00929) — InjecAgent
    # 探测 function_call / tool_calls 的 JSON 结构
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

    # RAG 结构探测 (增强)
    # 学术依据: Shafran et al. (arXiv:2402.07967) — RAG 安全
    # 探测检索结果的结构特征
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

    # Embedding 结构探测 (增强)
    # 探测向量数据特征
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

    # 模型族检测 (WILDTEAMING 适配)
    # 学术依据: Mazeika et al. (arXiv:2406.18510) — WILDTEAMING
    # 不同模型族 (GPT/Claude/Gemini/Llama) 的安全对齐策略略不同
    # 定制种子可提升 ASR
    model_family = _detect_model_family(response_text)
    if model_family:
        capabilities["model_family"] = model_family

    return capabilities


def _detect_model_family(text: str) -> str | None:
    """从响应文本推断目标 LLM 模型族。

    学术依据: Mazeika et al. (arXiv:2406.18510) — WILDTEAMING
        不同模型族 (GPT/Claude/Gemini/Llama) 的安全对齐策略略不同
        定制种子可提升 ASR

    探测策略 (覆盖国内外近3年最新模型, 22 模型族):
        国际 (2023-2026):
        1. OpenAI/GPT: "GPT-5", "GPT-4o", "GPT-4.1", "o1", "o3", "o4-mini", "ChatGPT"
        2. Anthropic/Claude: "Claude Sonnet 4.5", "Claude Opus 4", "Claude 4.5", "Claude 4", "Claude 3.5", "Haiku"
        3. Google/Gemini: "Gemini 2.5", "Gemini 2.0", "Gemini Flash", "Gemini Pro"
        4. Meta/Llama: "Llama 4", "Llama 3.3", "Llama Scout", "Llama Maverick"
        5. xAI/Grok: "Grok 4", "Grok 3", "Grok 2"
        6. Mistral: "Magistral", "Mistral Large 2", "Mistral Small", "Codestral"
        7. Cohere/Command: "Command A", "Command R+"
        8. Amazon/Nova: "Amazon Nova Pro", "Nova Lite", "Nova Micro"
        9. Microsoft/Phi: "Phi-4", "Phi-3.5"
        10. Reka: "Reka Core", "Reka Flash"
        11. Inflection/Pi: "Inflection-3", "Inflection-2.5"
        国内 (2023-2026):
        12. Qwen/通义: "Qwen3", "Qwen2.5", "Qwen-Max", "通义", "千问"
        13. DeepSeek/深度求索: "DeepSeek-V3", "DeepSeek-R1", "深度求索"
        14. ERNIE/文心: "ERNIE X1", "ERNIE 4.5", "文心", "文心一言"
        15. Spark/星火: "Spark 4.0 Ultra", "Spark 4.0", "星火", "讯飞"
        16. Doubao/豆包: "Doubao-1.5", "豆包", "Seed-Talk"
        17. Kimi: "Kimi K2", "月之暗面", "Moonshot"
        18. GLM/智谱: "GLM-5.2", "GLM-5", "GLM-4.6", "GLM-Z1", "智谱", "ChatGLM"
        19. Yi/零一: "Yi-Lightning", "Yi-Large", "零一万物"
        20. MiniMax/abab: "MiniMax-01", "abab"
        21. Baichuan/百川: "Baichuan-4", "百川"
        22. Step/阶越星辰: "Step-3", "Step-2", "阶跃", "StepFun"

    Args:
        text: 探针响应文本。

    Returns:
        模型族标签, 无法判断时返回 None。
    """
    if not text or len(text) < 3:
        return None

    text_lower = text.lower()

    # OpenAI / GPT 模型族 (GPT-4o/4.1/5 + o1/o3/o4 推理模型, 2023-2026)
    gpt_keywords = [
        "gpt-5", "gpt-4o", "gpt-4.1", "gpt-4",
        "chatgpt", "openai", "o1", "o3", "o4-mini", "o3-mini",
        "i am chatgpt", "i'm chatgpt", "i am an openai",
    ]
    for kw in gpt_keywords:
        if kw in text_lower:
            return "gpt"

    # Anthropic / Claude 模型族 (Claude 3.5/4/4.5 + Sonnet/Opus/Haiku, 2023-2026)
    claude_keywords = [
        "claude", "anthropic",
        "claude 4.5", "claude 4", "claude 3.5",
        "claude sonnet 4.5", "claude sonnet 4", "claude opus 4",
        "claude haiku", "claude sonnet", "claude opus",
        "i am claude", "i'm claude",
    ]
    for kw in claude_keywords:
        if kw in text_lower:
            return "claude"

    # Google / Gemini 模型族 (Gemini 2.0/2.5 Flash/Pro, 2023-2026)
    gemini_keywords = [
        "gemini", "google ai", "gemini 2.5", "gemini 2.0",
        "gemini flash", "gemini pro",
        "i am gemini", "i'm gemini",
    ]
    for kw in gemini_keywords:
        if kw in text_lower:
            return "gemini"

    # Meta / Llama 模型族 (Llama 3.3/4 Scout/Maverick, 2023-2026)
    llama_keywords = [
        "llama", "meta ai", "llama 4", "llama 3.3",
        "llama scout", "llama maverick",
        "i am llama", "i'm llama",
    ]
    for kw in llama_keywords:
        if kw in text_lower:
            return "llama"

    # xAI / Grok 模型族 (Grok 2/3/4, 2023-2026)
    grok_keywords = ["grok 4", "grok 3", "grok 2", "grok", "xai", "i am grok", "i'm grok"]
    for kw in grok_keywords:
        if kw in text_lower:
            return "grok"

    # Mistral 模型族 (Magistral/Large 2/Small/Codestral, 2023-2026)
    mistral_keywords = [
        "magistral", "mistral", "mistral large 2", "mistral small", "codestral",
    ]
    for kw in mistral_keywords:
        if kw in text_lower:
            return "mistral"

    # Cohere / Command 模型族 (Command A/R+, 2024-2026)
    cohere_keywords = ["command a", "command r+", "command-a", "command-r+", "cohere"]
    for kw in cohere_keywords:
        if kw in text_lower:
            return "cohere"

    # Amazon / Nova 模型族 (Nova Pro/Lite/Micro, 2024-2026)
    nova_keywords = ["amazon nova", "nova pro", "nova lite", "nova micro", "amazon bedrock"]
    for kw in nova_keywords:
        if kw in text_lower:
            return "nova"

    # Microsoft / Phi 模型族 (Phi-3.5/4, 2024-2026)
    phi_keywords = ["phi-4", "phi-3.5", "microsoft phi"]
    for kw in phi_keywords:
        if kw in text_lower:
            return "phi"

    # Reka 模型族 (Reka Core/Flash, 2024-2026)
    reka_keywords = ["reka core", "reka flash", "reka"]
    for kw in reka_keywords:
        if kw in text_lower:
            return "reka"

    # Inflection / Pi 模型族 (Inflection-2.5/3, 2023-2026)
    inflection_keywords = ["inflection-3", "inflection-2.5", "inflection", "i am pi", "i'm pi", "pi by inflection"]
    for kw in inflection_keywords:
        if kw in text_lower:
            return "inflection"

    # Qwen / 通义千问 模型族 (Qwen3/2.5/Max, 2023-2026)
    qwen_keywords = [
        "qwen3", "qwen2.5", "qwen-max", "qwen", "通义", "千问",
        "tongyi", "tongyi-qwen",
    ]
    for kw in qwen_keywords:
        if kw in text_lower:
            return "qwen"

    # DeepSeek / 深度求索 模型族 (V3/R1, 2024-2026)
    deepseek_keywords = ["deepseek-v3", "deepseek-r1", "deepseek", "深度求索"]
    for kw in deepseek_keywords:
        if kw in text_lower:
            return "deepseek"

    # ERNIE / 文心一言 模型族 (ERNIE X1/4.5, 2023-2026)
    ernie_keywords = [
        "ernie x1", "ernie 4.5",
        "文心", "文心一言", "baidu ai", "百度",
    ]
    for kw in ernie_keywords:
        if kw in text_lower:
            return "ernie"

    # Spark / 讯飞星火 模型族 (Spark 4.0 Ultra/4.0, 2023-2026)
    spark_keywords = ["spark 4.0 ultra", "spark 4.0", "spark", "星火", "讯飞", "iflytek"]
    for kw in spark_keywords:
        if kw in text_lower:
            return "spark"

    # Doubao / 豆包 模型族 (Doubao-1.5/Seed-Talk, 2024-2026)
    doubao_keywords = ["doubao-1.5", "doubao", "豆包", "seed-talk", "seed_talk"]
    for kw in doubao_keywords:
        if kw in text_lower:
            return "doubao"

    # Kimi / 月之暗面 模型族 (Kimi K2, 2023-2026)
    kimi_keywords = ["kimi k2", "kimi", "月之暗面", "moonshot"]
    for kw in kimi_keywords:
        if kw in text_lower:
            return "kimi"

    # GLM / 智谱 模型族 (GLM-5.2/5/4.6/Z1, 2023-2026)
    glm_keywords = ["glm-5.2", "glm-5", "glm-4.6", "glm-z1", "glm", "智谱", "chatglm", "zhipu"]
    for kw in glm_keywords:
        if kw in text_lower:
            return "glm"

    # Yi / 零一万物 模型族 (Yi-Lightning/Large, 2023-2026)
    yi_keywords = ["yi-lightning", "yi-large", "yi-", "零一万物", "01.ai"]
    for kw in yi_keywords:
        if kw in text_lower:
            return "yi"

    # MiniMax / abab 模型族 (MiniMax-01, 2023-2026)
    minimax_keywords = ["minimax-01", "minimax", "abab"]
    for kw in minimax_keywords:
        if kw in text_lower:
            return "minimax"

    # Baichuan / 百川 模型族 (Baichuan-4, 2023-2026)
    baichuan_keywords = ["baichuan-4", "baichuan", "百川"]
    for kw in baichuan_keywords:
        if kw in text_lower:
            return "baichuan"

    # Step / 阶跃星辰 模型族 (Step-3/2, 2023-2026)
    step_keywords = ["step-3", "step-2", "阶跃", "stepfun"]
    for kw in step_keywords:
        if kw in text_lower:
            return "step"

    return None


def _detect_language(text: str) -> str | None:
    """从响应文本检测目标语言 (中文/英文)。

    通过 Unicode 字符范围判断:
        - 中文字符 (CJK Unified Ideographs U+4E00-U+9FFF) 占比 > 5% → "zh"
        - 否则 → "en"

    Args:
        text: 响应文本。

    Returns:
        "zh" 或 "en", 无法判断时返回 None。
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

    递归查找第一个有意义的字符串值, 返回其 JSON 路径。
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
