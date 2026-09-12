"""capability_detector - imports burp_parser.py

, , ,

 ''recon.confidence_scorer'' (SSOT),
/

 LLM :
     parsed.body  ( {PROMPT} ),
     {PROMPT} ,  body ,
    Ensure Baidu/Qwen/DeepSeek  body
"""

import json
import logging
from typing import Any

# SSOT: confidence_scorer
from recon.confidence_scorer import get_all_capability_names, score_capability

# P2-06: TLS verify (SSOT)
from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

_TLS_VERIFY = _get_tls_verify_from_config()

logger = logging.getLogger(__name__)


def _build_probe_body(parsed: Any, probe_text: str) -> str:
    """imports parsed.body body

     parsed.body ( {PROMPT}  {CHAT_ID} ),
     {PROMPT} , {CHAT_ID}  ID
     parsed.body , fallback  {"prompt": probe_text}

    Args:
        parsed:  Burp
        probe_text:  ( "hi"  prompt)

    Returns:
         body
    """
    if parsed.body and "{PROMPT}" in parsed.body:
        body = parsed.body.replace("{PROMPT}", probe_text)
        # {CHAT_ID}
        if "{CHAT_ID}" in body:
            chat_id_val = parsed.chat_id or ""
            body = body.replace("{CHAT_ID}", chat_id_val)
        return body
    # fallback: JSON body
    return json.dumps({"prompt": probe_text}, ensure_ascii=False)


async def probe_response_path(parsed: Any) -> str | None:
    """

     ( "hi"  {PROMPT}),  JSON ,
     ( ''choices[0].message.content'')

     LLM  body :
         parsed.body ( {PROMPT} )  {PROMPT} ,
         body , Ensure Baidu/Qwen/DeepSeek

    Args:
        parsed:  Burp

    Returns:
         JSON ,  None
    """
    import httpx

    # body: parsed.body {PROMPT}
    probe_body = _build_probe_body(parsed, "hi")

    # httpx ( HTTPTarget)
    scheme = "https" if parsed.use_tls else "http"
    probe_url = f"{scheme}://{parsed.host}{parsed.path}"

    # headers ( Content-Length Host, httpx )
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

            # ()
            detected_lang = _detect_language(content)
            if detected_lang:
                # P1-05:
                parsed.target_fingerprint.language = detected_lang
                logger.info("Detected target language: %s", detected_lang)

            # SSE (Server-Sent Events)
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type or content.startswith("event:") or content.startswith("data:"):
                logger.info("Probe detected SSE response format (Content-Type: %s)", content_type)
                parsed.is_sse = True
                parsed.response_json_path = None
                # SSE chat_id ()
                from recon.burp_parser import extract_chat_id_from_response, extract_model_info_from_response

                probe_chat_id = extract_chat_id_from_response(content)
                if probe_chat_id:
                    parsed.chat_id = probe_chat_id
                    # P1-05:
                    parsed.target_fingerprint.chat_id = probe_chat_id
                    logger.info("Probe extracted chat_id from SSE response: %s", probe_chat_id)
                # L5 v53:
                probe_model_name, probe_model_list = extract_model_info_from_response(content)
                if probe_model_name:
                    parsed.burp_model_name = probe_model_name
                    # P1-05:
                    parsed.target_fingerprint.burp_model_name = probe_model_name
                    logger.info("Probe extracted model name from response: %s", probe_model_name)
                if probe_model_list:
                    parsed.burp_model_list = probe_model_list
                    # P1-05: extra dict Schema
                    parsed.target_fingerprint.extra["burp_model_list"] = "yes"
                    logger.info("Probe extracted model list from response")
                return None

            json_path = _infer_json_path(content)
            if json_path:
                logger.info("Probe inferred JSON path: %s", json_path)
                parsed.response_json_path = json_path
                # L5 v53:
                from recon.burp_parser import extract_model_info_from_response

                probe_model_name, probe_model_list = extract_model_info_from_response(content)
                if probe_model_name:
                    parsed.burp_model_name = probe_model_name
                    # P1-05:
                    parsed.target_fingerprint.burp_model_name = probe_model_name
                    logger.info("Probe extracted model name from JSON response: %s", probe_model_name)
                if probe_model_list:
                    parsed.burp_model_list = probe_model_list
                    # P1-05: extra dict Schema
                    parsed.target_fingerprint.extra["burp_model_list"] = "yes"
                    logger.info("Probe extracted model list from JSON response")
                # -
                # Academic basis: Greshake et al. (arXiv:2302.12173), Zhan et al. (arXiv:2307.00929)
                capabilities = _probe_capabilities(content)
                # ( model_family)
                bool_caps = [k for k, v in capabilities.items() if v is True]
                model_family = capabilities.get("model_family", "")
                if model_family:
                    # P1-05:
                    parsed.target_fingerprint.model_family = model_family
                    logger.info("Probe detected model family: %s", model_family)
                if bool_caps:
                    # P1-05: extra dict (capabilities list, Schema )
                    parsed.target_fingerprint.extra["capabilities"] = ",".join(bool_caps)
                    logger.info("Probe detected capabilities: %s", bool_caps)
                return json_path
            else:
                logger.info("Probe could not infer JSON path, using default")
                # Even if JSON
                capabilities = _probe_capabilities(content)
                bool_caps = [k for k, v in capabilities.items() if v is True]
                model_family = capabilities.get("model_family", "")
                if model_family:
                    # P1-05:
                    parsed.target_fingerprint.model_family = model_family
                if bool_caps:
                    # P1-05: extra dict
                    parsed.target_fingerprint.extra["capabilities"] = ",".join(bool_caps)
                    logger.info("Probe detected capabilities (no JSON path): %s", bool_caps)
                return None

    except Exception as e:
        logger.warning("Response probe failed: %s", e)
        return None


async def probe_active_capabilities(parsed: Any) -> dict[str, bool]:
    """- prompt

    Academic basis:
        - Greshake et al. (arXiv:2302.12173) -
        - Zhan et al. (arXiv:2307.00929) - InjecAgent
        - Anthropic MCP Specification (2024)

     ():
        1.  "list available tools"  Agent/MCP
        2.  "what documents are in your knowledge base"  RAG
        3.

     LLM :
         parsed.body  {PROMPT},
         {"prompt": "..."} body

    Args:
        parsed:  Burp

    Returns:

    """
    import httpx

    # prompt -
    # P2-20: model_identity -
    # Academic basis: Mazeika et al. (arXiv:2406.18510) - WILDTEAMING
    # , ASR
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

    # AsyncClient , TCP
    # Academic basis: Arbis et al. (arXiv:2306.01943) Sec4.5 -
    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=True,
        verify=_TLS_VERIFY,
    ) as client:
        for probe_type, probe_prompt in probe_prompts.items():
            # parsed.body {PROMPT}, body
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

                #
                # model_family ( "gpt"), bool
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
    """imports - ''confidence_scorer'' SSOT

    Academic basis:
        - Greshake et al. (arXiv:2302.12173) - , Agent
        - Zhan et al. (arXiv:2307.00929) - InjecAgent, Agent
        - arXiv:2402.04249 - HarmBench

    :
         ''confidence_scorer.py'',
         SSOT ,  {capability: bool}
         7  (agent/rag/mcp/embedding/multi_agent/code_execution/web_search)
        ;  (function_calling/memory/workflow )
        capability_probe.py  ''deep_probe_capabilities''

    Args:
        response_text:

    Returns:
        model_family ,  bool
    """
    if not response_text or len(response_text) < 10:
        # Return all capabilities as False for empty/short input
        return {
            cap: False
            for cap in get_all_capability_names()
            if not cap.startswith(
                (
                    "function_calling",
                    "memory",
                    "workflow",
                    "multi_tenant",
                    "session_auth",
                    "mcp_protocol",
                    "a2a_protocol",
                    "embedding_rag",
                )
            )
        }

    capabilities: dict[str, bool | str] = {}

    # == SSOT: ==
    for cap_name in get_all_capability_names():
        # ( deep_probe_capabilities )
        if cap_name.startswith(
            (
                "function_calling",
                "memory",
                "workflow",
                "multi_tenant",
                "session_auth",
                "mcp_protocol",
                "a2a_protocol",
                "embedding_rag",
            )
        ):
            continue
        result = score_capability(response_text, cap_name, source="active")
        capabilities[cap_name] = result.detected

    # == (WILDTEAMING , ) ==
    # Academic basis: Mazeika et al. (arXiv:2406.18510) - WILDTEAMING
    # (GPT/Claude/Gemini/Llama)
    model_family = _detect_model_family(response_text)
    if model_family:
        capabilities["model_family"] = model_family

    return capabilities


# v58: - key yaml asr_priors ,
# patterns ().
# : , ( yaml key).
# "I am Claude 3.5 Sonnet" -> "claude-3.5-sonnet" ()
# "I am Claude" -> "claude-3" ( fallback, yaml claude )
_MODEL_PATTERNS: list[tuple[str, list[str]]] = [
    # == OpenAI / GPT == ->
    ("gpt-5", ["gpt-5", "gpt5"]),
    ("gpt-4o-mini", ["gpt-4o-mini", "gpt4o-mini"]),
    ("gpt-4o", ["gpt-4o", "gpt4o"]),
    ("gpt-4.1", ["gpt-4.1", "gpt-4.1"]),
    ("gpt-4", ["gpt-4", "gpt4"]),
    ("o4-mini", ["o4-mini"]),
    ("o3", ["o3"]),
    ("o1", ["o1"]),
    ("gpt-4", ["chatgpt", "openai", "i am chatgpt", "i'm chatgpt", "i am an openai"]),
    # == Anthropic / Claude ==
    ("claude-4.5-sonnet", ["claude 4.5 sonnet", "claude-4.5-sonnet", "claude 4.5"]),
    ("claude-4-sonnet", ["claude 4 sonnet", "claude-4-sonnet", "claude sonnet 4", "claude-sonnet-4"]),
    ("claude-4-opus", ["claude 4 opus", "claude-4-opus", "claude opus 4", "claude-opus-4"]),
    ("claude-3.5-haiku", ["claude 3.5 haiku", "claude-3.5-haiku", "claude haiku"]),
    ("claude-3.5-sonnet", ["claude 3.5 sonnet", "claude-3.5-sonnet"]),
    ("claude-3.5", ["claude 3.5", "claude-3.5"]),
    ("claude-3", ["claude 3", "claude-3"]),
    ("claude-3", ["claude", "anthropic", "i am claude", "i'm claude"]),
    # == Google / Gemini ==
    ("gemini-2.5-pro", ["gemini 2.5 pro", "gemini-2.5-pro"]),
    ("gemini-2.5-flash", ["gemini 2.5 flash", "gemini-2.5-flash"]),
    ("gemini-2.0-flash", ["gemini 2.0 flash", "gemini-2.0-flash"]),
    ("gemini-1.5-pro", ["gemini 1.5 pro", "gemini-1.5-pro", "gemini pro"]),
    ("gemini-2.0-flash", ["gemini flash"]),
    ("gemini-1.5-pro", ["gemini", "google ai", "i am gemini", "i'm gemini"]),
    # == Meta / Llama ==
    ("llama-4-maverick", ["llama 4 maverick", "llama maverick", "llama-4-maverick"]),
    ("llama-4", ["llama 4", "llama-4", "llama scout"]),
    ("llama-3.1-405b", ["llama 3.1", "llama-3.1"]),
    ("llama-3-70b", ["llama 3", "llama-3"]),
    ("llama-2-70b", ["llama 2", "llama-2"]),
    ("llama-4", ["llama", "meta ai", "i am llama", "i'm llama"]),
    # == xAI / Grok ==
    ("grok-3", ["grok 4", "grok 3", "grok-4", "grok-3"]),
    ("grok-3", ["grok", "xai", "i am grok", "i'm grok"]),
    # == Mistral ==
    ("mistral-large-2", ["mistral large 2", "mistral-large-2", "magistral"]),
    ("mistral-large-2", ["mistral", "mistral large", "mistral small", "codestral"]),
    # == Cohere / Command ==
    ("command-r-plus", ["command r+", "command-r-plus"]),
    ("command-a", ["command a", "command-a"]),
    ("command-a", ["cohere"]),
    # == Amazon / Nova ==
    ("nova-micro", ["nova micro"]),
    ("nova-lite", ["nova lite"]),
    # nova yaml , bedrock fallback -> default
    ("nova-micro", ["amazon nova", "amazon bedrock", "nova pro"]),
    # == Microsoft / Phi ==
    ("phi-4", ["phi-4"]),
    ("phi-4", ["phi-3.5", "microsoft phi"]),
    # == Qwen / ==
    ("qwen3-235b", ["qwen3-235b", "qwen3 235b"]),
    ("qwen3-72b", ["qwen3-72b", "qwen3 72b"]),
    ("qwen3-32b", ["qwen3-32b", "qwen3 32b"]),
    ("qwen3-32b", ["qwen3", "qwen 3"]),
    ("qwen2-72b", ["qwen2-72b", "qwen2 72b", "qwen2.5"]),
    ("qwen-max", ["qwen-max", "qwen max"]),
    ("qwen-32b", ["qwen-32b", "qwen 32b"]),
    ("qwen3-32b", ["qwen", "", "", "tongyi"]),
    # == DeepSeek / ==
    ("deepseek-v3.1", ["deepseek-v3.1", "deepseek v3.1"]),
    ("deepseek-r1", ["deepseek-r1", "deepseek r1"]),
    ("deepseek-v3", ["deepseek-v3", "deepseek v3"]),
    ("deepseek-v3", ["deepseek", ""]),
    # == ERNIE / ==
    ("ernie-4.5", ["ernie x1", "ernie 4.5", "ernie-4.5"]),
    ("ernie-4.5", ["", "", "baidu ai", ""]),
    # == Doubao / ==
    ("doubao-pro", ["doubao-1.5", "doubao 1.5", "doubao", "", "seed-talk", "seed_talk"]),
    # == Kimi / ==
    ("kimi-k2", ["kimi k2", "kimi-k2"]),
    ("kimi-k2", ["kimi", "", "moonshot"]),
    # == GLM / ==
    ("glm-5", ["glm-5.2", "glm-5", "glm 5", "glm-4.6", "glm-z1"]),
    ("glm-5", ["glm", "", "chatglm", "zhipu"]),
    # == Yi / ==
    ("yi-lightning", ["yi-lightning", "yi lightning"]),
    ("yi-large", ["yi-large", "yi large"]),
    ("yi-large", ["yi-", "", "01.ai"]),
    # == MiniMax ==
    ("minimax-text-01", ["minimax-01", "minimax 01", "minimax-text-01"]),
    ("minimax-text-01", ["minimax", "abab"]),
    # == InternLM ==
    ("internlm3", ["internlm3", "internlm 3", "internlm-3"]),
    ("internlm3", ["internlm"]),
    # == Gemma (Google open) ==
    ("gemma-3", ["gemma 3", "gemma-3"]),
    ("gemma-2", ["gemma 2", "gemma-2"]),
    ("gemma-2", ["gemma"]),
    # == Baichuan ( yaml, fallback to default) ==
    ("baichuan-4", ["baichuan-4", "baichuan", ""]),
    # == Step ( yaml, fallback to default) ==
    ("step-3", ["step-3", "step-2", "", "stepfun"]),
]


def _detect_model_family(text: str) -> str | None:
    """imports LLM ( yaml key ).

    v58 :  ( "claude"),
     yaml converter(s) "claude"  key (claude-3, ASR=73.6%),
     ( claude-3.5-sonnet, ASR=14%),  prior .

    : imports,  asr_priors.yaml key .
    :  ( "claude-3.5-sonnet") ->  fallback ( "claude-3")
     yaml  key (/ ASR ).

    Academic basis: Mazeika et al. (arXiv:2406.18510) - WILDTEAMING
        ,  ASR

    Args:
        text:

    Returns:
         ( "claude-3.5-sonnet"),  None
    """
    if not text or len(text) < 3:
        return None

    text_lower = text.lower()

    for model_key, patterns in _MODEL_PATTERNS:
        for pat in patterns:
            if pat and pat in text_lower:  # skip empty patterns
                return model_key

    return None


def _detect_language(text: str) -> str | None:
    """imports (/)

     Unicode :
        -  (CJK Unified Ideographs U+4E00-U+9FFF)  > 5% -> "zh"
        -  -> "en"

    Args:
        text:

    Returns:
        "zh"  "en",  None
    """
    if not text or len(text) < 10:
        return None

    #
    cjk_count = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    total_chars = len(text)

    if total_chars == 0:
        return None

    cjk_ratio = cjk_count / total_chars
    if cjk_ratio > 0.05:
        return "zh"
    return "en"


def _infer_json_path(content: str) -> str | None:
    """imports JSON

    converter(s),  JSON
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
