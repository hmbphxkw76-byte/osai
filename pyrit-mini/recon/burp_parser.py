"""Burp Suite HTTP 请求解析 → PyRIT 原生 HTTPTarget 构建。

子模块拆分:
    - sse_parser: SSE 流式响应解析
    - fingerprint: AI 框架/SDK 指纹识别
    - prompt_injector: Prompt 注入 & 会话ID管理
    - api_classifier: API 端点类别检测

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

from recon.api_classifier import detect_api_category
from recon.fingerprint import (
    extract_ai_framework_fingerprint,
    extract_ai_sdk_from_request_headers,
)
from recon.prompt_injector import (
    build_full_url,
    detect_and_inject_chat_id_placeholder,
    extract_chat_id_from_response,
    extract_model_info_from_response,
    extract_original_prompt_value,
    infer_tls,
    inject_prompt_placeholder,
)

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════════════
# P1-05: TargetFingerprint Schema 显式化
# 学术依据: C3 显式优于隐式 — dict[str, str] 缺乏编译时检查,
# 字段名 typo (如 "chat_id" vs "chatid") 和类型混乱 (str/int/bool 混存)
# 是 2024-2025 年 Python AI 安全工具中常见报告数据损坏根因。
# ════════════════════════════════════════════════════════════════════


@dataclass
class TargetFingerprint:
    """目标指纹信息 — 显式 Schema, 两阶段写入隔离。

    两阶段写入契约:
        Phase 1 (parse-time): 由 ``burp_parser._parse_raw_http`` 填充
            (HTTP 静态解析阶段, 不发送网络请求)
        Phase 2 (probe-time): 由探测模块 (capability_detector/target_router) 填充
            (发送探测请求后动态收集, 字段默认 None / 空 / False)

    向后兼容: 提供 ``get`` / ``__getitem__`` / ``__setitem__`` 接口, 允许
    旧式 ``fp["key"]`` 写法继续工作, 但新增字段强烈推荐 attribute 访问。
    """

    # ── Phase 1: HTTP 请求解析 (必填, _extract_fingerprint 写入) ──
    framework: str = "Unknown"
    api_path: str = ""
    host: str = ""
    auth_type: str = "None"
    content_type: str = "unknown"
    app_type: str = "Web Application"
    api_category: str = "chat"

    # ── Phase 1: HTTP 请求解析 (可选, _parse_raw_http 写入) ──
    ai_framework: str | None = None
    ai_framework_category: str | None = None
    chat_id: str | None = None
    burp_model_name: str | None = None
    has_model_list: bool = False

    # ── Phase 2: 主动探测 (capability_detector / target_router 写入) ──
    language: str | None = None
    model_family: str | None = None
    capabilities: list[str] = field(default_factory=list)
    probe_count: int = 0
    probe_duration_seconds: float = 0.0

    # ── Phase 2: 深度探测 (target_router 后处理写入) ──
    mcp_tools: list[str] = field(default_factory=list)
    mcp_resources: list[str] = field(default_factory=list)
    mcp_prompts: list[str] = field(default_factory=list)
    system_prompt_leaked: bool = False
    extracted_system_prompt: str | None = None
    system_prompt_extraction_method: str | None = None
    openapi_spec_path: str | None = None
    openapi_endpoints: list[str] = field(default_factory=list)
    original_prompt: str | None = None
    session_type: str | None = None

    # ── 动态扩展 (非预期字段落地点, 运行时探测的未知键) ──
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """向后兼容 dict.get()。"""
        if hasattr(self, key) and not key.startswith("_"):
            val = getattr(self, key)
            return val if val is not None else default
        return self.extra.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """向后兼容 dict[key] 读。"""
        if hasattr(self, key) and not key.startswith("_"):
            return getattr(self, key)
        return self.extra[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """向后兼容 dict[key] = value 写。优先 attribute, 否则 extra。"""
        if hasattr(self, key) and not key.startswith("_"):
            setattr(self, key, value)
        else:
            self.extra[key] = value

    def to_dict(self) -> dict[str, Any]:
        """序列化为 JSON 兼容字典 (用于报告输出)。"""
        from dataclasses import asdict

        result = asdict(self)
        extra = result.pop("extra", {})
        result.update(extra)
        # 过滤 None / 空 / False, 保留有意义的字段
        return {k: v for k, v in result.items() if v not in (None, "", [], False, 0, 0.0)}


@dataclass
class ParsedBurpRequest:
    """解析后的 Burp 请求。"""

    method: str
    url: str
    host: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    use_tls: bool = True
    is_sse: bool = False
    http_version: str = "HTTP/1.1"
    has_prompt_placeholder: bool = False
    response_json_path: str | None = None
    target_fingerprint: TargetFingerprint = field(default_factory=TargetFingerprint)
    chat_id: str | None = None
    chat_id_field: str | None = None
    has_chat_id_placeholder: bool = False
    original_prompt_value: str | None = None
    burp_model_name: str | None = None
    burp_model_list: str | None = None
    api_category: str = "chat"


# ════════════════════════════════════════════════════════════════════
# 主入口函数
# ════════════════════════════════════════════════════════════════════


def parse_burp_request(file_path: str | Path) -> ParsedBurpRequest:
    """解析 Burp 原始 HTTP 请求文件。

    支持格式::

        POST /api/chat HTTP/1.1
        Host: target.example.com
        Content-Type: application/json
        Cookie: session=xxx

        {"prompt":"{PROMPT}"}

    也支持 Burp 导出的完整 HTTP 交互 (Request + Response)。

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


def build_raw_http_request(parsed: ParsedBurpRequest) -> str:
    """重建原始 HTTP 请求字符串 (CRLF 格式)。"""
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


# ════════════════════════════════════════════════════════════════════
# 内部实现
# ════════════════════════════════════════════════════════════════════


def _parse_raw_http(raw: str) -> ParsedBurpRequest:
    """解析原始 HTTP 请求字符串。

    L5 v19 修复: 某些 Burp 导出格式 header 与 body 间无空行分隔,
    导致 body 行被误判为 header。

    P2-20 增强: 支持 Burp 导出的完整 HTTP 交互 (Request + Response)。
    """
    normalized = raw.replace("\r\n", "\n")

    request_section, response_section = _split_request_response(normalized)

    parts = request_section.split("\n\n", 1)

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
    headers: dict[str, str] = {}
    raw_headers: list[tuple[str, str]] = []
    body_from_headers: list[str] = []
    in_body = False

    for line in header_lines[1:]:
        if in_body:
            body_from_headers.append(line)
            continue
        if line.startswith("{") or line.startswith("<"):
            in_body = True
            body_from_headers.append(line)
            continue
        if ":" in line:
            potential_key = line.split(":", 1)[0].strip()
            if potential_key and all(
                c.isalnum() or c in "-_" for c in potential_key
            ):
                key, value = line.split(":", 1)
                raw_headers.append((key.strip(), value.strip()))
                headers[key.strip().lower()] = value.strip()
                continue
        in_body = True
        body_from_headers.append(line)

    if body_from_headers:
        extracted_body = "\n".join(body_from_headers).strip()
        if body:
            body = extracted_body + "\n" + body
        else:
            body = extracted_body

    host = headers.get("host", "")
    use_tls = infer_tls(path, headers)
    full_url = build_full_url(path, host, use_tls)

    # SSE 检测 (3 层策略)
    accept_header = headers.get("accept", "")
    is_sse = "text/event-stream" in accept_header
    if not is_sse and body:
        try:
            body_data = json.loads(body)
            if isinstance(body_data, dict):
                stream_val = body_data.get("stream") or body_data.get("Stream")
                if stream_val:
                    is_sse = True
        except json.JSONDecodeError:
            pass
    if not is_sse and response_section:
        resp_lines = response_section.split("\n")
        for line in resp_lines[:20]:
            if line.strip().lower().startswith("content-type:") and "text/event-stream" in line.lower():
                is_sse = True
                break

    # API 端点类别检测 (委托给 api_classifier)
    api_category = detect_api_category(path, body)

    # 提取原始 prompt 值 (侦察分析)
    original_prompt_value: str | None = None
    if api_category == "chat" and body and "{PROMPT}" not in body:
        original_prompt_value = extract_original_prompt_value(body)
        if original_prompt_value:
            logger.info(
                "Extracted original prompt value from body: %s",
                original_prompt_value[:80],
            )

    # 占位符检测 + 自动注入
    has_placeholder = "{PROMPT}" in body or "{PROMPT}" in path
    if not has_placeholder and body and api_category == "chat":
        body = inject_prompt_placeholder(body)
        has_placeholder = True
    elif api_category == "metadata":
        has_placeholder = False
        logger.info(
            "Metadata API detected (path=%s), skipping {PROMPT} injection",
            path,
        )

    # 目标指纹 (委托给 fingerprint 模块)
    fingerprint = _extract_fingerprint(headers, path, host, response_section)
    fingerprint.api_category = api_category

    # 从 Response 部分提取会话 ID
    chat_id: str | None = None
    chat_id_field: str | None = None
    has_chat_id_placeholder = False
    initial_chat_id_from_body: str | None = None

    # 从 Burp Response 中提取模型信息
    burp_model_name: str | None = None
    burp_model_list: str | None = None

    if response_section:
        chat_id = extract_chat_id_from_response(response_section)
        if chat_id:
            logger.info("Extracted chat_id from Burp Response: %s", chat_id)
            fingerprint.chat_id = chat_id

        burp_model_name, burp_model_list = extract_model_info_from_response(response_section)
        if burp_model_name:
            logger.info("Extracted model name from Burp Response: %s", burp_model_name)
            fingerprint.burp_model_name = burp_model_name
        if burp_model_list:
            logger.info("Extracted model list from Burp Response (length=%d)", len(burp_model_list))
            fingerprint.extra["burp_model_list"] = "yes"

    # 检测 Request body 中的会话 ID 字段名并注入 {CHAT_ID} 占位符
    if body:
        try:
            orig_body_data = json.loads(body)
            if isinstance(orig_body_data, dict):
                for k, v in orig_body_data.items():
                    if k.lower() in _CHAT_ID_FIELD_NAMES:
                        if isinstance(v, str) and v.strip():
                            initial_chat_id_from_body = v.strip()
                        break
        except (json.JSONDecodeError, TypeError):
            pass

        body, chat_id_field, has_chat_id_placeholder = detect_and_inject_chat_id_placeholder(body)
        if chat_id_field:
            logger.info(
                "Detected chat ID field '%s' in request body, injected {CHAT_ID} placeholder",
                chat_id_field,
            )

    if not chat_id and initial_chat_id_from_body:
        chat_id = initial_chat_id_from_body
        fingerprint.chat_id = chat_id
        logger.info("Using chat_id from request body as initial value: %s", chat_id)

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
        chat_id=chat_id,
        chat_id_field=chat_id_field,
        has_chat_id_placeholder=has_chat_id_placeholder,
        original_prompt_value=original_prompt_value,
        burp_model_name=burp_model_name,
        burp_model_list=burp_model_list,
        api_category=api_category,
    )


def _extract_fingerprint(
    headers: dict[str, str],
    path: str,
    host: str,
    response_section: str | None = None,
) -> TargetFingerprint:
    """从 HTTP 请求和响应中提取目标指纹信息 (Phase 1 解析输出)。"""
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    if "next" in (server + x_powered).lower():
        framework = "Next.js"
    elif "express" in (server + x_powered).lower():
        framework = "Express.js"
    elif "fastapi" in (server + x_powered).lower():
        framework = "FastAPI"
    elif "django" in (server + x_powered).lower():
        framework = "Django"
    else:
        framework = "Unknown"

    if "authorization" in headers:
        auth = headers["authorization"]
        if auth.lower().startswith("bearer"):
            auth_type = "Bearer Token"
        elif auth.lower().startswith("basic"):
            auth_type = "Basic Auth"
        else:
            auth_type = "Custom Auth Header"
    elif "cookie" in headers:
        auth_type = "Cookie-based"
    else:
        auth_type = "None"

    content_type = headers.get("content-type", "unknown")

    # 从路径推断应用类型
    path_lower = path.lower()
    if "/challenges/" in path_lower or "/scenarios/" in path_lower or "/arena/" in path_lower:
        app_type = "Testing/Arena"
    elif "/agent" in path_lower or "/mcp" in path_lower or "/tool" in path_lower:
        app_type = "Agent Application"
    elif "/chat" in path_lower or "/completion" in path_lower or "/message" in path_lower:
        app_type = "Chat Application"
    elif "/rag" in path_lower or "/knowledge" in path_lower or "/retriev" in path_lower or "/embed" in path_lower:
        app_type = "RAG Application"
    else:
        app_type = "Web Application"

    # AI 框架/SDK 指纹识别 (委托给 fingerprint 模块)
    ai_fw: str | None = None
    ai_fw_cat: str | None = None
    if response_section:
        ai_fw, ai_fw_cat = extract_ai_framework_fingerprint(response_section)
    sdk_fw, sdk_fw_cat = extract_ai_sdk_from_request_headers(headers)
    if sdk_fw and not ai_fw:
        ai_fw, ai_fw_cat = sdk_fw, sdk_fw_cat

    return TargetFingerprint(
        framework=framework,
        api_path=path,
        host=host,
        auth_type=auth_type,
        content_type=content_type,
        app_type=app_type,
        ai_framework=ai_fw,
        ai_framework_category=ai_fw_cat,
    )


def _split_request_response(normalized: str) -> tuple[str, str | None]:
    """分离 Burp 导出的完整 HTTP 交互中的 Request 和 Response 部分。

    通过检测 ``HTTP/<digit>`` 开头的行来识别 Response 起始位置。
    """
    lines = normalized.split("\n")

    response_start_idx: int | None = None
    for i, line in enumerate(lines):
        if i == 0:
            continue
        if re.match(r"^HTTP/\d", line.strip()):
            response_start_idx = i
            break

    if response_start_idx is None:
        return normalized, None

    request_end_idx = response_start_idx
    while request_end_idx > 0 and not lines[request_end_idx - 1].strip():
        request_end_idx -= 1

    request_section = "\n".join(lines[:request_end_idx])
    response_section = "\n".join(lines[response_start_idx:])

    return request_section, response_section


# 会话 ID 字段名匹配列表 (大小写不敏感)
_CHAT_ID_FIELD_NAMES = frozenset({
    "chatid", "chat_id", "chatidvalue", "chatsessionid", "chat_session_id",
    "sessionid", "session_id", "sessionidvalue",
    "conversationid", "conversation_id", "convid", "conv_id",
    "dialogid", "dialog_id",
    "threadid", "thread_id",
    "req_id", "requestid", "request_id",
})


# Re-exports from capability_detector and target_builder for backwards compatibility
from recon.capability_detector import (  # noqa: F401, E402
    _detect_language,
    _detect_model_family,
    _infer_json_path,
    _probe_capabilities,
    probe_active_capabilities,
    probe_response_path,
)
from recon.target_builder import (  # noqa: F401, E402
    ChatIdStateManager,
    RequestPreprocessor,
    build_http_target,
    build_httpx_api_target,
)
