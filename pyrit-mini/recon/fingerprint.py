"""AI /SDK - imports Burp Response (0 )

Academic basis:
    - PTES Sec2 -
    - OWASP WSTG-INFO-03 -
    - RedAmon ai_signal_catalog.py - AI Layer

Layer:
    1. Response Header  (x-vllm-*, x-langchain-*, )
    2. HTML <title>  (Open WebUI, LibreChat, Gradio, )
    3. Body Wappalyzer  (LangChain globals, SDK import, )
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# AI Header ( header , )
_AI_HEADER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # == AI ==
    (re.compile(r"^x-vllm-", re.I), "vllm", "ai-runtime"),
    (re.compile(r"^x-tgi-", re.I), "tgi", "ai-runtime"),
    (re.compile(r"^x-tei-", re.I), "text-embeddings-inference", "ai-runtime"),
    (re.compile(r"^x-bentoml-", re.I), "bentoml", "ai-runtime"),
    (re.compile(r"^x-baseten-", re.I), "baseten", "ai-runtime"),
    (re.compile(r"^x-modal-", re.I), "modal", "ai-runtime"),
    (re.compile(r"^x-replicate-", re.I), "replicate", "ai-runtime"),
    (re.compile(r"^x-runpod-", re.I), "runpod", "ai-runtime"),
    # == AI / ==
    (re.compile(r"^x-langchain-", re.I), "langchain", "ai-framework"),
    (re.compile(r"^x-llamaindex-", re.I), "llamaindex", "ai-framework"),
    (re.compile(r"^langfuse-", re.I), "langfuse", "ai-framework"),
    # == AI / ==
    (re.compile(r"^x-litellm-", re.I), "litellm", "ai-proxy"),
    (re.compile(r"^x-helicone-", re.I), "helicone", "ai-proxy"),
    (re.compile(r"^x-portkey-", re.I), "portkey", "ai-proxy"),
    (re.compile(r"^x-omniroute-", re.I), "omniroute", "ai-proxy"),
    (re.compile(r"^cf-aig-", re.I), "cloudflare-ai-gateway", "ai-proxy"),
    (re.compile(r"^together-", re.I), "together", "ai-proxy"),
    # == AI SDK ==
    (re.compile(r"^openai-(organization|version|processing-ms)", re.I), "openai", "ai-sdk-client"),
    (re.compile(r"^anthropic-(version|beta|ratelimit-)", re.I), "anthropic", "ai-sdk-client"),
    (re.compile(r"^x-ms-region$|^azureml-model-session$", re.I), "azure-openai", "ai-sdk-client"),
    (re.compile(r"^x-ratelimit-limit-tokens-cache-adjusted-prompt$|^x-fireworks-account-id$", re.I), "fireworks", "ai-sdk-client"),
    # == MCP ==
    (re.compile(r"^x-mcp-", re.I), "mcp", "ai-framework"),
]

# AI Title (HTML <title> , )
_AI_TITLE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bOpen WebUI\b", re.I), "open-webui"),
    (re.compile(r"\bLibreChat\b", re.I), "librechat"),
    (re.compile(r"\bAnythingLLM\b", re.I), "anythingllm"),
    (re.compile(r"\bFlowise\b", re.I), "flowise"),
    (re.compile(r"\bLangflow\b", re.I), "langflow"),
    (re.compile(r"\bDify\b", re.I), "dify"),
    (re.compile(r"\bComfyUI\b", re.I), "comfyui"),
    (re.compile(r"\bGradio\b", re.I), "gradio"),
    (re.compile(r"\bStreamlit\b", re.I), "streamlit"),
    (re.compile(r"\bBetterChatGPT\b", re.I), "betterchatgpt"),
    (re.compile(r"\bOnyx\b|\bDanswer\b", re.I), "onyx"),
    (re.compile(r"\bChatGPT\b", re.I), "chatgpt-clone"),
    (re.compile(r"\bHuggingFace Chat UI\b", re.I), "hf-chat-ui"),
    (re.compile(r"\bLobeChat\b|\bLobeHub\b", re.I), "lobechat"),
    (re.compile(r"\bNextChat\b", re.I), "nextchat"),
    (re.compile(r"\bSillyTavern\b", re.I), "sillytavern"),
    (re.compile(r"\bh2oGPT\b", re.I), "h2ogpt"),
    (re.compile(r"\bPrivateGPT\b", re.I), "privategpt"),
    (re.compile(r"\bQuivr\b", re.I), "quivr"),
    (re.compile(r"\bInvoke\s*-\s*Community Edition\b", re.I), "invokeai"),
    (re.compile(r"^Stable Diffusion$", re.I), "automatic1111"),
    (re.compile(r"^MLflow$", re.I), "mlflow"),
    (re.compile(r"^Labelstudio$", re.I), "label-studio"),
    (re.compile(r"\bRay Dashboard\b", re.I), "ray-dashboard"),
    (re.compile(r"\bRedisInsight\b", re.I), "redis-insight"),
    (re.compile(r"\bAutoGen Studio\b", re.I), "autogen-studio"),
    (re.compile(r"\bLangfuse\b", re.I), "langfuse-ui"),
    (re.compile(r"\bArize Phoenix\b|^Phoenix$", re.I), "phoenix-arize"),
    (re.compile(r"\bArgilla\b", re.I), "argilla"),
    (re.compile(r"\bGPT Researcher\b", re.I), "gpt-researcher"),
]

# AI Body (Wappalyzer , )
_AI_BODY_FINGERPRINTS: list[tuple[re.Pattern[str], str, str]] = [
    # == ==
    (re.compile(r"""(?:action|href|fetch\()\s*=?\s*["']/generate_stream["']""", re.I), "tgi", "ai-runtime"),
    (re.compile(r"\bvllm_session\b", re.I), "vllm", "ai-runtime"),
    (re.compile(r"\bOllama is running\b", re.I), "ollama", "ai-runtime"),
    # == ==
    (re.compile(r"window\.__LANGCHAIN__|window\.__LANGCHAIN_TRACING_V2__", re.I), "langchain", "ai-framework"),
    (re.compile(r"""@langchain/(core|community|langgraph|openai|anthropic)["']""", re.I), "langchain", "ai-framework"),
    (re.compile(r"""@llamaindex/(core|flow|langchain)["']""", re.I), "llamaindex", "ai-framework"),
    # == ==
    (re.compile(r"\btxt2img_textarea\b", re.I), "automatic1111", "ai-frontend"),
    (re.compile(r'"flowise_"', re.I), "flowise", "ai-frontend"),
    (re.compile(r"\bstreamlit_\b", re.I), "streamlit", "ai-frontend"),
    (re.compile(r'\bgradio\b', re.I), "gradio", "ai-frontend"),
    # == SDK ==
    (re.compile(r"""from openai import|import openai""", re.I), "openai-sdk", "ai-sdk-client"),
    (re.compile(r"""from anthropic import|import anthropic""", re.I), "anthropic-sdk", "ai-sdk-client"),
    (re.compile(r"""from litellm import|import litellm""", re.I), "litellm", "ai-proxy"),
]

def split_response_headers_body(
    response_section: str,
) -> tuple[list[tuple[str, str]], str]:
    """ Response headers body

    Args:
        response_section: Burp Response
            (: "HTTP/1.x status\\r?\\nheaders\\r?\\n\\r?\\nbody")

    Returns:
        (headers_list, body_text)
    """
    normalized = response_section.replace("\r\n", "\n").replace("\r", "\n")

    split_idx = normalized.find("\n\n")
    if split_idx == -1:
        return [], normalized

    header_section = normalized[:split_idx]
    body = normalized[split_idx + 2:]

    headers_list: list[tuple[str, str]] = []
    for line in header_section.split("\n"):
        line = line.strip()
        if not line or line.startswith("HTTP/"):
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers_list.append((name.strip(), value.strip()))

    return headers_list, body

def extract_ai_framework_fingerprint(
    response_section: str,
) -> tuple[str | None, str | None]:
    """imports Burp Response AI (Layer)

    Args:
        response_section: Burp Response

    Returns:
        (framework_name, category) ,  (None, None)
    """
    if not response_section or not response_section.strip():
        return None, None

    resp_headers, resp_body = split_response_headers_body(response_section)

 # == Layer 1: Response Header ==
    for header_name, _header_value in resp_headers:
        for pattern, fw_name, fw_category in _AI_HEADER_PATTERNS:
            if pattern.search(header_name):
                logger.debug(
                    "AI framework detected from response header '%s': %s (%s)",
                    header_name, fw_name, fw_category,
                )
                return fw_name, fw_category

 # == Layer 2: HTML <title> ==
    title_match = re.search(r"<title[^>]*>(.*?)</title>", resp_body, re.I | re.DOTALL)
    if title_match:
        title_text = title_match.group(1).strip()
        for pattern, fw_name in _AI_TITLE_PATTERNS:
            if pattern.search(title_text):
                logger.debug("AI framework detected from <title>: %s", fw_name)
                return fw_name, "ai-frontend"

 # == Layer 3: Body Wappalyzer ==
    for pattern, fw_name, fw_category in _AI_BODY_FINGERPRINTS:
        if pattern.search(resp_body):
            logger.debug(
                "AI framework detected from body fingerprint: %s (%s)",
                fw_name, fw_category,
            )
            return fw_name, fw_category

    return None, None

def extract_ai_sdk_from_request_headers(
    request_headers: dict[str, str],
) -> tuple[str | None, str | None]:
    """imports headers AI SDK

     header  header  header  SDK :
        - Authorization: Bearer sk-xxx -> OpenAI
        - x-api-key: xxx -> Azure OpenAI
        - api-key: xxx -> Azure OpenAI

    Args:
        request_headers:  headers

    Returns:
        (framework_name, category)
    """
 # header
    header_keys_lower = {k.lower() for k in request_headers}

 # Anthropic SDK
    for key in request_headers:
        if key.lower().startswith("anthropic-"):
            return "anthropic", "ai-sdk-client"

 # OpenAI SDK
    for key in request_headers:
        if key.lower().startswith("openai-"):
            return "openai", "ai-sdk-client"

 # Azure OpenAI ()
    if "api-key" in header_keys_lower or "x-ms-region" in header_keys_lower:
        return "azure-openai", "ai-sdk-client"

 # MCP
    for key in request_headers:
        if key.lower().startswith("x-mcp-"):
            return "mcp", "ai-framework"

    return None, None
