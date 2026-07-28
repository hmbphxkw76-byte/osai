"""
Burp Target Builder — L5 Expert
================================

从 Burp Suite 导出的原始 HTTP 请求创建 HTTPTarget。

适用场景：
  - OWASP LLM05 (Improper Output Handling) - 测试 XSS/SSRF 注入
  - OWASP LLM10 (Unbounded Consumption) - 测试资源耗尽
  - Web 漏洞测试（CSRF、API 认证绕过等）
  - 非标准 HTTP 协议目标

充分利用 PyRIT 1.0.0 原生能力：
  - HTTPTarget.parse_raw_http_request() 自动解析原始请求
  - get_http_target_json_response_callback_function() 解析 JSON 响应
  - get_http_target_regex_matching_callback_function() 正则匹配响应
  - prompt_regex_string="{PROMPT}" 自动注入提示词
  - httpx_client_kwargs 透传（超时 / SSL / 代理 / HTTP/2）
"""

import json
import logging
from typing import Any, Dict, Optional

from pyrit.prompt_target import HTTPTarget
from pyrit.prompt_target.http_target.http_target_callback_functions import (
    get_http_target_json_response_callback_function,
    get_http_target_regex_matching_callback_function,
)

logger = logging.getLogger(__name__)


# ============================================================
# 常量
# ============================================================

# OpenAI 兼容响应的常见 JSON 路径
_JSON_RESPONSE_PATHS = [
    "choices[0].message.content",       # OpenAI Chat Completions
    "choices[0].text",                   # OpenAI Completions
    "output[0].content[0].text",         # OpenAI Responses API
    "response",                          # 通用
    "result",                            # 通用
    "answer",                            # 通用
    "message",                           # 通用
    "data",                              # 通用
]

# 默认正则匹配模式
DEFAULT_REGEX_PATTERN = r"[\s\S]*"

# 常见 Content-Type → 回调策略映射
_CONTENT_TYPE_CALLBACK_MAP = {
    "application/json": "json",
    "text/html": "regex",
    "text/plain": "none",
    "application/xml": "regex",
    "application/soap+xml": "regex",
}


# ============================================================
# Burp Target 构建器
# ============================================================


def create_http_target_from_burp(
    burp_request: str,
    api_key: Optional[str] = None,
    callback_function: Optional[Any] = None,
    max_requests_per_minute: Optional[int] = None,
    httpx_client_kwargs: Optional[Dict[str, Any]] = None,
    model_name: str = "",
) -> HTTPTarget:
    """
    从 Burp Suite 导出的 HTTP 请求创建 HTTPTarget

    Burp 请求格式示例（POST + JSON body）::

        POST /api/chat HTTP/1.1
        Host: 192.168.0.22:11434
        Content-Type: application/json
        Authorization: Bearer sk-xxx

        {"model": "llama3", "messages": [{"role": "user", "content": "{PROMPT}"}]}

    注意：请求体中需要包含 {PROMPT} 占位符，攻击时会被自动替换为实际提示词。

    L5 改进：
    - 新增 httpx_client_kwargs 透传（超时 / SSL / 代理）
    - 新增 model_name 参数（用于 Target 标识）
    - 增强回调函数自动检测

    Args:
        burp_request: Burp 导出的原始 HTTP 请求字符串
        api_key: API Key（可选，也可在请求头中直接包含）
        callback_function: 自定义响应解析函数
        max_requests_per_minute: 速率限制
        httpx_client_kwargs: httpx.AsyncClient 构造参数（如 {"timeout": 180, "verify": False}）
        model_name: 模型名称（用于 Target 标识，默认空字符串）

    Returns:
        HTTPTarget 实例
    """
    # 自动注入 API Key
    if api_key and "authorization" not in burp_request.lower():
        lines = burp_request.split("\n")
        for i, line in enumerate(lines):
            if line.lower().startswith("host:"):
                lines.insert(i + 1, f"Authorization: Bearer {api_key}")
                break
        burp_request = "\n".join(lines)

    # 自动检测回调函数
    if callback_function is None:
        callback_function = _auto_detect_callback(burp_request)

    # 构建 kwargs
    kwargs: Dict[str, Any] = {
        "http_request": burp_request,
        "prompt_regex_string": "{PROMPT}",
        "callback_function": callback_function,
        "model_name": model_name,
    }

    if max_requests_per_minute:
        kwargs["max_requests_per_minute"] = max_requests_per_minute

    # httpx_client_kwargs 作为 **kwargs 传递给 HTTPTarget
    if httpx_client_kwargs:
        kwargs.update(httpx_client_kwargs)

    target = HTTPTarget(**kwargs)

    logger.info(
        f"Created HTTPTarget from Burp request "
        f"(callback={getattr(callback_function, '__name__', 'None')}, "
        f"httpx_kwargs={list(httpx_client_kwargs.keys()) if httpx_client_kwargs else 'none'})"
    )
    return target


def create_http_target_from_raw_request(
    raw_request: str,
    prompt_regex_string: str = "{PROMPT}",
    response_key: Optional[str] = None,
    use_regex: bool = False,
    regex_pattern: Optional[str] = None,
    api_key: Optional[str] = None,
    max_requests_per_minute: Optional[int] = None,
    httpx_client_kwargs: Optional[Dict[str, Any]] = None,
    model_name: str = "",
    use_tls: bool = True,
) -> HTTPTarget:
    """
    从原始 HTTP 请求字符串创建 HTTPTarget（更灵活的构造方式）

    L5 改进：
    - 新增 httpx_client_kwargs 透传
    - 新增 model_name / use_tls 参数
    - 增强响应路径自动检测

    Args:
        raw_request: 原始 HTTP 请求字符串
        prompt_regex_string: 提示词占位符（默认 {PROMPT}）
        response_key: JSON 响应提取路径（如 "choices[0].message.content"）
        use_regex: 是否使用正则匹配（而非 JSON 路径）
        regex_pattern: 正则表达式模式（use_regex=True 时生效）
        api_key: API Key（可选）
        max_requests_per_minute: 速率限制
        httpx_client_kwargs: httpx.AsyncClient 构造参数
        model_name: 模型名称（用于 Target 标识）
        use_tls: 是否使用 TLS（默认 True）

    Returns:
        HTTPTarget 实例
    """
    # 自动注入 API Key
    if api_key and "authorization" not in raw_request.lower():
        lines = raw_request.split("\n")
        for i, line in enumerate(lines):
            if line.lower().startswith("host:"):
                lines.insert(i + 1, f"Authorization: Bearer {api_key}")
                break
        raw_request = "\n".join(lines)

    # 创建回调函数
    callback_function = None
    if use_regex:
        pattern = regex_pattern or DEFAULT_REGEX_PATTERN
        callback_function = get_http_target_regex_matching_callback_function(pattern)
    elif response_key:
        callback_function = get_http_target_json_response_callback_function(response_key)
    else:
        callback_function = _auto_detect_callback(raw_request)

    # 构建 kwargs
    kwargs: Dict[str, Any] = {
        "http_request": raw_request,
        "prompt_regex_string": prompt_regex_string,
        "use_tls": use_tls,
        "callback_function": callback_function,
        "model_name": model_name,
    }

    if max_requests_per_minute:
        kwargs["max_requests_per_minute"] = max_requests_per_minute

    # httpx_client_kwargs 作为 **kwargs 传递
    if httpx_client_kwargs:
        kwargs.update(httpx_client_kwargs)

    return HTTPTarget(**kwargs)


# ============================================================
# 辅助函数
# ============================================================


def _auto_detect_callback(raw_request: str) -> Optional[Any]:
    """
    自动检测响应解析回调函数

    L5 增强：
    1. 解析请求 Content-Type 头
    2. 如果是 JSON，尝试从请求体推断响应路径
    3. 支持 SSE 流式响应检测
    4. 多级回退策略

    检测策略：
    - application/json → JSON 响应解析（自动推断路径）
    - text/event-stream → 正则匹配（SSE 流式响应）
    - text/html → 正则匹配
    - 无明确类型 → 不使用回调（返回原始响应）

    Args:
        raw_request: 原始 HTTP 请求字符串

    Returns:
        回调函数，或 None
    """
    request_lower = raw_request.lower()

    # 检测 SSE 流式响应
    if "text/event-stream" in request_lower:
        logger.info("Auto-detected SSE stream request, using regex callback")
        return get_http_target_regex_matching_callback_function(r"data:\s*(.*?)(?:\n\n|$)")

    # 检测 JSON API 请求
    if "application/json" in request_lower:
        # 尝试从请求体推断响应路径
        response_key = _infer_json_response_key(raw_request)
        if response_key:
            logger.info(f"Auto-detected JSON API request, using callback key: {response_key}")
            return get_http_target_json_response_callback_function(response_key)
        # 回退到默认 OpenAI 格式
        logger.info(f"Auto-detected JSON API request, using default callback key: {_JSON_RESPONSE_PATHS[0]}")
        return get_http_target_json_response_callback_function(_JSON_RESPONSE_PATHS[0])

    # 检测 HTML 请求
    if "text/html" in request_lower:
        logger.info("Auto-detected HTML request, using regex callback")
        return get_http_target_regex_matching_callback_function(DEFAULT_REGEX_PATTERN)

    # 检测 XML 请求
    if "xml" in request_lower:
        logger.info("Auto-detected XML request, using regex callback")
        return get_http_target_regex_matching_callback_function(DEFAULT_REGEX_PATTERN)

    # 默认不使用回调
    logger.info("No callback auto-detected, returning raw response")
    return None


def _infer_json_response_key(raw_request: str) -> Optional[str]:
    """
    从请求体推断 JSON 响应路径

    通过分析请求体结构推断最可能的响应路径：
    - 请求体包含 "messages" → OpenAI Chat 格式 → choices[0].message.content
    - 请求体包含 "prompt" → OpenAI Completions 格式 → choices[0].text
    - 请求体包含 "input" → Responses API 格式 → output[0].content[0].text
    - 其他 → None（使用默认）

    Args:
        raw_request: 原始 HTTP 请求字符串

    Returns:
        推断的 JSON 响应路径，或 None
    """
    try:
        # 提取请求体（双换行后的部分）
        normalized = raw_request.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)
        if len(parts) < 2:
            return None

        body = parts[1].strip()
        body_json = json.loads(body)

        # OpenAI Chat Completions 格式
        if "messages" in body_json:
            return "choices[0].message.content"

        # OpenAI Completions 格式
        if "prompt" in body_json:
            return "choices[0].text"

        # Responses API 格式
        if "input" in body_json:
            return "output[0].content[0].text"

        # 通用格式
        return None

    except (json.JSONDecodeError, IndexError, TypeError):
        return None
