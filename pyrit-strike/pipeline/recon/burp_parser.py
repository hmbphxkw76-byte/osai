"""Burp Suite HTTP 请求解析 → PyRIT 原生 HTTPTarget 构建。

纯黑盒场景:
    - 全量保留浏览器 header (Cookie, User-Agent, Origin, Referer 等)
    - 自动检测 SSE (text/event-stream)
    - 自动注入 {PROMPT} 占位符 (支持 JSON body 中的常见字段名)
    - 响应路径自动探测 (发送探针请求, 推断 JSON 响应结构)
    - 支持 HTTP/2

真实样本::

    POST /api/chat HTTP/1.1
    Host: target.example.com
    Content-Type: application/json
    Cookie: session_id=xxx
    ...

    {"prompt":"介绍自己"}
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _make_sse_callback() -> Any:
    """创建 SSE 流式响应解析 callback。

    SSE 格式 (多种变体):
        格式1 — 标准 SSE:
            event: meta
            data: {"request_id": "..."}

            data: {"content": "你好"}

            data: {"content": "我可以帮你"}

        格式2 — OpenAI 兼容:
            data: {"choices":[{"delta":{"content":"Hello"}}]}

            data: {"choices":[{"delta":{"content":" world"}}]}

            data: [DONE]

        格式3 — 纯 JSON:
            {"content": "完整响应"}

    策略 (3层 fallback):
        1. 尝试逐行解析 SSE data: 行，提取 content/delta.content
        2. 如果逐行解析失败，用正则全局匹配 content 字段
        3. 如果都失败，返回原始文本 (去掉 SSE 前缀)
    """

    def parse_sse_response(response: Any) -> str:
        """解析 SSE 流式响应，拼接所有 content 片段。"""
        import json as json_mod

        # 获取响应文本
        text = None
        if hasattr(response, "text") and response.text is not None:
            text = response.text
        elif hasattr(response, "content"):
            if isinstance(response.content, bytes):
                text = response.content.decode("utf-8", errors="replace")
            else:
                text = str(response.content)
        else:
            text = str(response)

        if not text or not text.strip():
            return ""

        # 策略1: 逐行解析 SSE data: 行 (最准确)
        content_parts: list[str] = []
        for line in text.split("\n"):
            line = line.strip()
            if not line.startswith("data:"):
                continue

            # 提取 data: 后的内容
            data_content = line[5:].strip()

            # 跳过 [DONE] 标记
            if data_content == "[DONE]" or data_content == "[STOP]":
                continue

            # 尝试 JSON 解析
            try:
                data_obj = json_mod.loads(data_content)
                # 提取 content (多种路径)
                content_val = (
                    _extract_nested(data_obj, "content")
                    or _extract_nested(data_obj, "delta", "content")
                    or _extract_nested(data_obj, "choices", 0, "delta", "content")
                    or _extract_nested(data_obj, "choices", 0, "message", "content")
                    or _extract_nested(data_obj, "answer")
                    or _extract_nested(data_obj, "response")
                    or _extract_nested(data_obj, "text")
                )
                if content_val and isinstance(content_val, str):
                    content_parts.append(content_val)
            except (json_mod.JSONDecodeError, ValueError):
                # 非 JSON 格式，尝试正则
                pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"')
                match = pattern.search(data_content)
                if match:
                    content_parts.append(match.group(1))

        if content_parts:
            full_content = "".join(content_parts)
            # 反转义 JSON 字符串
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

        # 策略2: 正则全局匹配 content 字段
        pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"')
        matches = pattern.findall(text)
        if matches:
            full_content = "".join(matches)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

        # 策略3: 返回原始文本 (清理 SSE 前缀)
        cleaned = re.sub(r"^(event:|data:)\s*", "", text, flags=re.MULTILINE)
        cleaned = cleaned.replace("[DONE]", "").replace("[STOP]", "")
        return cleaned.strip()

    return parse_sse_response


def _extract_nested(obj: Any, *keys: Any) -> Any:
    """从嵌套 dict/list 中提取值。

    Args:
        obj: 起始对象。
        keys: 逐层 key/index 路径。

    Returns:
        找到的值，或 None。
    """
    current = obj
    for key in keys:
        if current is None:
            return None
        if isinstance(key, int):
            if isinstance(current, list) and 0 <= key < len(current):
                current = current[key]
            else:
                return None
        else:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
    return current


@dataclass
class ParsedBurpRequest:
    """解析后的 Burp 请求。"""

    method: str
    url: str
    host: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    # 原始 header 顺序保留 (重建 HTTP 请求时使用)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    use_tls: bool = True
    is_sse: bool = False
    http_version: str = "HTTP/1.1"
    has_prompt_placeholder: bool = False
    # 探测到的 JSON 响应路径
    response_json_path: str | None = None
    # 目标指纹信息
    target_fingerprint: dict[str, str] = field(default_factory=dict)


def parse_burp_request(file_path: str | Path) -> ParsedBurpRequest:
    """解析 Burp 原始 HTTP 请求文件。

    支持格式::

        POST /api/chat HTTP/1.1
        Host: target.example.com
        Content-Type: application/json
        Cookie: session=xxx

        {"prompt":"{PROMPT}"}

    Args:
        file_path: Burp 请求文件路径。

    Returns:
        ParsedBurpRequest: 解析结果。

    Raises:
        FileNotFoundError: 文件不存在。
        ValueError: HTTP 请求格式无效。
    """
    raw = Path(file_path).read_text(encoding="utf-8", errors="replace")
    return _parse_raw_http(raw)


def _parse_raw_http(raw: str) -> ParsedBurpRequest:
    """解析原始 HTTP 请求字符串。

    L5 v19 修复: 某些 Burp 导出格式 header 与 body 间无空行分隔
    (如 ``Connection: keep-alive\\r\\n{"prompt":"{PROMPT}"}``),
    导致 body 行被误判为 header。修复策略: 在逐行解析 header 时,
    如果某行不匹配 ``key: value`` 格式 (不以字母开头, 或以 ``{`` 开头),
    则将其及后续所有行视为 body。
    """
    normalized = raw.replace("\r\n", "\n")
    parts = normalized.split("\n\n", 1)

    header_section = parts[0].strip()
    body = parts[1] if len(parts) > 1 else ""

    header_lines = header_section.split("\n")
    request_line = header_lines[0].split(" ")
    if len(request_line) < 3:
        raise ValueError(f"Invalid HTTP request line: {header_lines[0]}")

    method = request_line[0]
    path = request_line[1]
    http_version = request_line[2]

    # 全量保留 header (保持原始顺序 + 大小写)
    # L5 v19: 智能识别 body 行 (非 header 格式的行视为 body 开始)
    headers: dict[str, str] = {}
    raw_headers: list[tuple[str, str]] = []
    body_from_headers: list[str] = []  # 从 header 段提取的 body 行
    in_body = False

    for line in header_lines[1:]:
        if in_body:
            body_from_headers.append(line)
            continue
        # 检测是否为 body 行 (JSON body, XML body 等)
        # 特征: 以 { 开头, 或不含冒号, 或冒号前有特殊字符
        if line.startswith("{") or line.startswith("<"):
            in_body = True
            body_from_headers.append(line)
            continue
        # 检测是否为有效 header: key 必须是 token (字母/数字/-'_)
        # 且包含冒号
        if ":" in line:
            potential_key = line.split(":", 1)[0].strip()
            # HTTP header name 只允许 token 字符
            if potential_key and all(
                c.isalnum() or c in "-_" for c in potential_key
            ):
                key, value = line.split(":", 1)
                raw_headers.append((key.strip(), value.strip()))
                headers[key.strip().lower()] = value.strip()
                continue
        # 不匹配 header 格式, 视为 body
        in_body = True
        body_from_headers.append(line)

    # 如果从 header 段提取到了 body, 合并到 body
    if body_from_headers:
        extracted_body = "\n".join(body_from_headers).strip()
        if body:
            body = extracted_body + "\n" + body
        else:
            body = extracted_body

    host = headers.get("host", "")
    use_tls = _infer_tls(path, headers)
    full_url = _build_full_url(path, host, use_tls)

    # SSE 检测: Accept: text/event-stream 或 body 中含 stream:true
    accept_header = headers.get("accept", "")
    is_sse = "text/event-stream" in accept_header
    if not is_sse and body:
        try:
            body_data = json.loads(body)
            if isinstance(body_data, dict) and body_data.get("stream"):
                is_sse = True
        except json.JSONDecodeError:
            pass

    # 占位符检测 + 自动注入
    has_placeholder = "{PROMPT}" in body or "{PROMPT}" in path
    if not has_placeholder and body:
        body = _inject_placeholder(body)
        has_placeholder = True

    # 目标指纹
    fingerprint = _extract_fingerprint(headers, path, host)

    return ParsedBurpRequest(
        method=method,
        url=full_url,
        host=host,
        path=path,
        headers=headers,
        raw_headers=raw_headers,
        body=body,
        use_tls=use_tls,
        is_sse=is_sse,
        http_version=http_version,
        has_prompt_placeholder=has_placeholder,
        target_fingerprint=fingerprint,
    )


def _infer_tls(path: str, headers: dict[str, str]) -> bool:
    """从 URL scheme 或 TLS header 推断。"""
    if path.startswith("https://"):
        return True
    if path.startswith("http://"):
        return False
    # localhost 默认 http
    host = headers.get("host", "")
    if "localhost" in host or "127.0.0.1" in host or "0.0.0.0" in host:
        return False
    return headers.get("x-forwarded-proto", "https") == "https"


def _build_full_url(path: str, host: str, use_tls: bool) -> str:
    """构建完整 URL。"""
    if path.startswith(("http://", "https://")):
        return path
    scheme = "https" if use_tls else "http"
    return f"{scheme}://{host}{path}"


def _inject_placeholder(body: str) -> str:
    """自动注入 {PROMPT} 占位符到 JSON body。

    策略:
        1. 如果 body 是 JSON 且包含 "prompt" / "message" / "input" 等字段，替换其值
        2. 如果是 OpenAI messages 数组格式，替换最后一条 user message 的 content
        3. 否则在 JSON body 中添加 "prompt": "{PROMPT}"
    """
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body

    # 查找常见 prompt 字段 (按优先级排序)
    prompt_fields = [
        "prompt", "message", "input", "query", "text",
        "content", "user_input", "question", "user_message",
    ]
    for field_name in prompt_fields:
        if field_name in data:
            data[field_name] = "{PROMPT}"
            logger.info("Auto-injected {PROMPT} into JSON field: '%s'", field_name)
            return json.dumps(data, ensure_ascii=False)

    # OpenAI messages 数组格式
    if "messages" in data and isinstance(data["messages"], list) and data["messages"]:
        last_msg = data["messages"][-1]
        if isinstance(last_msg, dict) and "content" in last_msg:
            last_msg["content"] = "{PROMPT}"
            logger.info("Auto-injected {PROMPT} into messages[-1].content")
            return json.dumps(data, ensure_ascii=False)

    # 默认添加 prompt 字段
    data["prompt"] = "{PROMPT}"
    logger.info("Auto-injected {PROMPT} as new 'prompt' field")
    return json.dumps(data, ensure_ascii=False)


def _extract_fingerprint(headers: dict[str, str], path: str, host: str) -> dict[str, str]:
    """从 HTTP 请求中提取目标指纹信息。

    用于报告中的目标识别:
        - framework: 从 header 推断前端框架
        - api_path: API 路径
        - auth_type: 认证方式
        - content_type: 请求内容类型
    """
    fp: dict[str, str] = {}

    # 框架推断
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    if "next" in (server + x_powered).lower():
        fp["framework"] = "Next.js"
    elif "express" in (server + x_powered).lower():
        fp["framework"] = "Express.js"
    elif "fastapi" in (server + x_powered).lower():
        fp["framework"] = "FastAPI"
    elif "django" in (server + x_powered).lower():
        fp["framework"] = "Django"
    else:
        fp["framework"] = "Unknown"

    fp["api_path"] = path
    fp["host"] = host

    # 认证方式
    if "authorization" in headers:
        auth = headers["authorization"]
        if auth.lower().startswith("bearer"):
            fp["auth_type"] = "Bearer Token"
        elif auth.lower().startswith("basic"):
            fp["auth_type"] = "Basic Auth"
        else:
            fp["auth_type"] = "Custom Auth Header"
    elif "cookie" in headers:
        fp["auth_type"] = "Cookie-based"
    else:
        fp["auth_type"] = "None"

    fp["content_type"] = headers.get("content-type", "unknown")

    # 从路径推断应用类型 (通用分类, 适配任意 LLM Agent 应用)
    # 顺序: 最具体的路径先匹配, 避免宽泛路径拦截
    if "/challenges/" in path or "/scenarios/" in path or "/arena/" in path:
        fp["app_type"] = "Testing/Arena"
    elif "/agent" in path or "/mcp" in path or "/tool" in path:
        fp["app_type"] = "Agent Application"
    elif "/chat" in path or "/completion" in path or "/message" in path:
        fp["app_type"] = "Chat Application"
    elif "/rag" in path or "/knowledge" in path or "/retriev" in path or "/embed" in path:
        fp["app_type"] = "RAG Application"
    else:
        fp["app_type"] = "Web Application"

    return fp


def build_raw_http_request(parsed: ParsedBurpRequest) -> str:
    """重建原始 HTTP 请求字符串 (CRLF 格式)。

    使用原始 header 顺序, 自动更新 Content-Length。
    """
    lines = [f"{parsed.method} {parsed.path} {parsed.http_version}"]

    for key, value in parsed.raw_headers:
        if key.lower() == "content-length":
            continue
        lines.append(f"{key}: {value}")

    if parsed.body:
        lines.append(f"Content-Length: {len(parsed.body.encode('utf-8'))}")

    request = "\r\n".join(lines)
    if parsed.body:
        request += "\r\n\r\n" + parsed.body
    else:
        request += "\r\n\r\n"
    return request


# Re-exports from split modules for backwards compatibility (at end to avoid circular imports)
from pipeline.recon.capability_detector import (  # noqa: F401, E402
    _detect_language,
    _detect_model_family,
    _infer_json_path,
    _probe_capabilities,
    probe_active_capabilities,
    probe_response_path,
)
from pipeline.recon.target_builder import (  # noqa: F401, E402
    JSONSafeHTTPTarget,
    _select_callback,
    build_http_target,
)
