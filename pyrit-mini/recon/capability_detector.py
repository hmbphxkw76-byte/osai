"""capability_detector — 从 burp_parser.py 拆分而来。

包含响应路径探测, 主动能力探测, 模型族检测, 语言检测。

能力评分统一委托给 ``recon.confidence_scorer`` (SSOT),
本模块保留探测请求构造与模型族/语言检测等非评分逻辑。

适配任意 LLM 应用:
    探针请求使用 parsed.body 模板 (已含 {PROMPT} 占位符),
    替换 {PROMPT} 为探针文本, 而非硬编码 body 格式,
    确保 Baidu/Qwen/DeepSeek 等不同 body 结构都能正确探测。
"""

import json
import logging
from typing import Any

# SSOT: 能力评分统一调用 confidence_scorer
from recon.confidence_scorer import get_all_capability_names, score_capability

# P2-06: TLS verify 配置化 (SSOT)
from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

_TLS_VERIFY = _get_tls_verify_from_config()

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
            verify=_TLS_VERIFY,
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
                # P1-05: 使用属性赋值
                parsed.target_fingerprint.language = detected_lang
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
                    # P1-05: 使用属性赋值
                    parsed.target_fingerprint.chat_id = probe_chat_id
                    logger.info("Probe extracted chat_id from SSE response: %s", probe_chat_id)
                # L5 v53: 从探针响应中提取模型信息
                probe_model_name, probe_model_list = _extract_model_info_from_response(content)
                if probe_model_name:
                    parsed.burp_model_name = probe_model_name
                    # P1-05: 使用属性赋值
                    parsed.target_fingerprint.burp_model_name = probe_model_name
                    logger.info("Probe extracted model name from response: %s", probe_model_name)
                if probe_model_list:
                    parsed.burp_model_list = probe_model_list
                    # P1-05: 使用 extra dict 存储非 Schema 字段
                    parsed.target_fingerprint.extra["burp_model_list"] = "yes"
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
                    # P1-05: 使用属性赋值
                    parsed.target_fingerprint.burp_model_name = probe_model_name
                    logger.info("Probe extracted model name from JSON response: %s", probe_model_name)
                if probe_model_list:
                    parsed.burp_model_list = probe_model_list
                    # P1-05: 使用 extra dict 存储非 Schema 字段
                    parsed.target_fingerprint.extra["burp_model_list"] = "yes"
                    logger.info("Probe extracted model list from JSON response")
                # 能力探测 — 从探针响应推断目标能力
                # 学术依据: Greshake et al. (arXiv:2302.12173), Zhan et al. (arXiv:2307.00929)
                capabilities = _probe_capabilities(content)
                # 分离布尔能力和非布尔元数据 (如 model_family)
                bool_caps = [k for k, v in capabilities.items() if v is True]
                model_family = capabilities.get("model_family", "")
                if model_family:
                    # P1-05: 使用属性赋值
                    parsed.target_fingerprint.model_family = model_family
                    logger.info("Probe detected model family: %s", model_family)
                if bool_caps:
                    # P1-05: 使用 extra dict 存储 (capabilities 是 list, 不是 Schema 中的字段类型)
                    parsed.target_fingerprint.extra["capabilities"] = ",".join(bool_caps)
                    logger.info("Probe detected capabilities: %s", bool_caps)
                return json_path
            else:
                logger.info("Probe could not infer JSON path, using default")
                # 能力探测即使在 JSON 路径推断失败时也执行
                capabilities = _probe_capabilities(content)
                bool_caps = [k for k, v in capabilities.items() if v is True]
                model_family = capabilities.get("model_family", "")
                if model_family:
                    # P1-05: 使用属性赋值
                    parsed.target_fingerprint.model_family = model_family
                if bool_caps:
                    # P1-05: 使用 extra dict 存储
                    parsed.target_fingerprint.extra["capabilities"] = ",".join(bool_caps)
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
        verify=_TLS_VERIFY,
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
    """从探针响应中推断目标能力 — 委托给 ``confidence_scorer`` SSOT。

    学术依据:
        - Greshake et al. (arXiv:2302.12173) — 间接提示注入, Agent 场景
        - Zhan et al. (arXiv:2307.00929) — InjecAgent, Agent 注入攻击
        - arXiv:2402.04249 — HarmBench 能力评估

    实现说明:
        关键词库与正则模式统一维护在 ``confidence_scorer.py``,
        本函数作为 SSOT 的薄包装, 返回 {capability: bool} 字典。
        初级 7 维度 (agent/rag/mcp/embedding/multi_agent/code_execution/web_search)
        使用基础关键词库; 深度维度 (function_calling/memory/workflow 等) 由
        capability_probe.py 的 ``deep_probe_capabilities`` 独立处理。

    Args:
        response_text: 探针响应文本。

    Returns:
        能力探测字典。model_family 为字符串, 其余为 bool。
    """
    if not response_text or len(response_text) < 10:
        return {}

    capabilities: dict[str, bool | str] = {}

    # ── SSOT: 遍历置信度评分器的所有基础能力维度 ──
    for cap_name in get_all_capability_names():
        # 排除深度探测维度 (由 deep_probe_capabilities 独立处理)
        if cap_name.startswith(("function_calling", "memory", "workflow",
                                "multi_tenant", "session_auth",
                                "mcp_protocol", "a2a_protocol", "embedding_rag")):
            continue
        result = score_capability(response_text, cap_name, source="active")
        capabilities[cap_name] = result.detected

    # ── 模型族检测 (WILDTEAMING 适配, 非评分器职责) ──
    # 学术依据: Mazeika et al. (arXiv:2406.18510) — WILDTEAMING
    # 不同模型族 (GPT/Claude/Gemini/Llama) 的安全对齐策略不同
    model_family = _detect_model_family(response_text)
    if model_family:
        capabilities["model_family"] = model_family

    return capabilities


# v58: 精确模型匹配表 — key 为 yaml 中 asr_priors 的精确模型名,
# patterns 为响应文本中的匹配模式 (按优先级从高到低排列).
# 匹配策略: 先精确型号, 后族标签 (最保守的 yaml key).
# 例如 "I am Claude 3.5 Sonnet" → "claude-3.5-sonnet" (精确)
#       "I am Claude" → "claude-3" (族标签 fallback, yaml 中最保守的 claude 条目)
_MODEL_PATTERNS: list[tuple[str, list[str]]] = [
    # ── OpenAI / GPT ── 精确 → 族标签
    ("gpt-5", ["gpt-5", "gpt5"]),
    ("gpt-4o-mini", ["gpt-4o-mini", "gpt4o-mini"]),
    ("gpt-4o", ["gpt-4o", "gpt4o"]),
    ("gpt-4.1", ["gpt-4.1", "gpt-4.1"]),
    ("gpt-4", ["gpt-4", "gpt4"]),
    ("o4-mini", ["o4-mini"]),
    ("o3", ["o3"]),
    ("o1", ["o1"]),
    ("gpt-4", ["chatgpt", "openai", "i am chatgpt", "i'm chatgpt", "i am an openai"]),
    # ── Anthropic / Claude ──
    ("claude-4.5-sonnet", ["claude 4.5 sonnet", "claude-4.5-sonnet", "claude 4.5"]),
    ("claude-4-sonnet", ["claude 4 sonnet", "claude-4-sonnet", "claude sonnet 4", "claude-sonnet-4"]),
    ("claude-4-opus", ["claude 4 opus", "claude-4-opus", "claude opus 4", "claude-opus-4"]),
    ("claude-3.5-haiku", ["claude 3.5 haiku", "claude-3.5-haiku", "claude haiku"]),
    ("claude-3.5-sonnet", ["claude 3.5 sonnet", "claude-3.5-sonnet"]),
    ("claude-3.5", ["claude 3.5", "claude-3.5"]),
    ("claude-3", ["claude 3", "claude-3"]),
    ("claude-3", ["claude", "anthropic", "i am claude", "i'm claude"]),
    # ── Google / Gemini ──
    ("gemini-2.5-pro", ["gemini 2.5 pro", "gemini-2.5-pro"]),
    ("gemini-2.5-flash", ["gemini 2.5 flash", "gemini-2.5-flash"]),
    ("gemini-2.0-flash", ["gemini 2.0 flash", "gemini-2.0-flash"]),
    ("gemini-1.5-pro", ["gemini 1.5 pro", "gemini-1.5-pro", "gemini pro"]),
    ("gemini-2.0-flash", ["gemini flash"]),
    ("gemini-1.5-pro", ["gemini", "google ai", "i am gemini", "i'm gemini"]),
    # ── Meta / Llama ──
    ("llama-4-maverick", ["llama 4 maverick", "llama maverick", "llama-4-maverick"]),
    ("llama-4", ["llama 4", "llama-4", "llama scout"]),
    ("llama-3.1-405b", ["llama 3.1", "llama-3.1"]),
    ("llama-3-70b", ["llama 3", "llama-3"]),
    ("llama-2-70b", ["llama 2", "llama-2"]),
    ("llama-4", ["llama", "meta ai", "i am llama", "i'm llama"]),
    # ── xAI / Grok ──
    ("grok-3", ["grok 4", "grok 3", "grok-4", "grok-3"]),
    ("grok-3", ["grok", "xai", "i am grok", "i'm grok"]),
    # ── Mistral ──
    ("mistral-large-2", ["mistral large 2", "mistral-large-2", "magistral"]),
    ("mistral-large-2", ["mistral", "mistral large", "mistral small", "codestral"]),
    # ── Cohere / Command ──
    ("command-r-plus", ["command r+", "command-r-plus"]),
    ("command-a", ["command a", "command-a"]),
    ("command-a", ["cohere"]),
    # ── Amazon / Nova ──
    ("nova-micro", ["nova micro"]),
    ("nova-lite", ["nova lite"]),
    # nova 精确型号不在 yaml 中, 用 bedrock fallback → default
    ("nova-micro", ["amazon nova", "amazon bedrock", "nova pro"]),
    # ── Microsoft / Phi ──
    ("phi-4", ["phi-4"]),
    ("phi-4", ["phi-3.5", "microsoft phi"]),
    # ── Qwen / 通义 ──
    ("qwen3-235b", ["qwen3-235b", "qwen3 235b"]),
    ("qwen3-72b", ["qwen3-72b", "qwen3 72b"]),
    ("qwen3-32b", ["qwen3-32b", "qwen3 32b"]),
    ("qwen3-32b", ["qwen3", "qwen 3"]),
    ("qwen2-72b", ["qwen2-72b", "qwen2 72b", "qwen2.5"]),
    ("qwen-max", ["qwen-max", "qwen max"]),
    ("qwen-32b", ["qwen-32b", "qwen 32b"]),
    ("qwen3-32b", ["qwen", "通义", "千问", "tongyi"]),
    # ── DeepSeek / 深度求索 ──
    ("deepseek-v3.1", ["deepseek-v3.1", "deepseek v3.1"]),
    ("deepseek-r1", ["deepseek-r1", "deepseek r1"]),
    ("deepseek-v3", ["deepseek-v3", "deepseek v3"]),
    ("deepseek-v3", ["deepseek", "深度求索"]),
    # ── ERNIE / 文心 ──
    ("ernie-4.5", ["ernie x1", "ernie 4.5", "ernie-4.5"]),
    ("ernie-4.5", ["文心", "文心一言", "baidu ai", "百度"]),
    # ── Doubao / 豆包 ──
    ("doubao-pro", ["doubao-1.5", "doubao 1.5", "doubao", "豆包", "seed-talk", "seed_talk"]),
    # ── Kimi / 月之暗面 ──
    ("kimi-k2", ["kimi k2", "kimi-k2"]),
    ("kimi-k2", ["kimi", "月之暗面", "moonshot"]),
    # ── GLM / 智谱 ──
    ("glm-5", ["glm-5.2", "glm-5", "glm 5", "glm-4.6", "glm-z1"]),
    ("glm-5", ["glm", "智谱", "chatglm", "zhipu"]),
    # ── Yi / 零一 ──
    ("yi-lightning", ["yi-lightning", "yi lightning"]),
    ("yi-large", ["yi-large", "yi large"]),
    ("yi-large", ["yi-", "零一万物", "01.ai"]),
    # ── MiniMax ──
    ("minimax-text-01", ["minimax-01", "minimax 01", "minimax-text-01"]),
    ("minimax-text-01", ["minimax", "abab"]),
    # ── InternLM ──
    ("internlm3", ["internlm3", "internlm 3", "internlm-3"]),
    ("internlm3", ["internlm"]),
    # ── Gemma (Google open) ──
    ("gemma-3", ["gemma 3", "gemma-3"]),
    ("gemma-2", ["gemma 2", "gemma-2"]),
    ("gemma-2", ["gemma"]),
    # ── Baichuan (不在 yaml, fallback to default) ──
    ("baichuan-4", ["baichuan-4", "baichuan", "百川"]),
    # ── Step (不在 yaml, fallback to default) ──
    ("step-3", ["step-3", "step-2", "阶跃", "stepfun"]),
]


def _detect_model_family(text: str) -> str | None:
    """从响应文本推断目标 LLM 模型名称 (精确到 yaml key 级别).

    v58 修复: 原实现只返回族标签 (如 "claude"), 双向子串匹配会
    匹配到 yaml 中第一个含 "claude" 的 key (claude-3, ASR=73.6%),
    而非实际模型 (如 claude-3.5-sonnet, ASR=14%), 导致 prior 严重偏高.

    新策略: 从具体到一般匹配, 返回与 asr_priors.yaml key 一致的精确模型名.
    匹配顺序: 精确型号 (如 "claude-3.5-sonnet") → 族标签 fallback (如 "claude-3")
    族标签选择 yaml 中最保守的 key (通常是该族最早/最低 ASR 的条目).

    学术依据: Mazeika et al. (arXiv:2406.18510) — WILDTEAMING
        不同模型族安全对齐策略不同, 精确型号匹配可提升 ASR 先验准确性

    Args:
        text: 探针响应文本。

    Returns:
        精确模型名 (如 "claude-3.5-sonnet"), 无法判断时返回 None。
    """
    if not text or len(text) < 3:
        return None

    text_lower = text.lower()

    for model_key, patterns in _MODEL_PATTERNS:
        for pat in patterns:
            if pat in text_lower:
                return model_key

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
