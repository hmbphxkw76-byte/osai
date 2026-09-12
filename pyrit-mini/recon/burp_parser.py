"""Burp Suite HTTP -> PyRIT HTTPTarget

:
    - sse_parser: SSE
    - fingerprint: AI /SDK
    - prompt_injector: Prompt  & ID
    - api_classifier: API

::

    POST /api/chat HTTP/1.1
    Host: <target_host>
    Content-Type: application/json
    Cookie: session_id=xxx
    ...

    {"prompt":""}
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from recon.fingerprint import (
    extract_ai_framework_fingerprint,
    extract_ai_sdk_from_request_headers,
    split_response_headers_body,
)
from recon.model.api_classifier import detect_api_category
from recon.model.prompt_injector import (
    build_full_url,
    detect_and_inject_chat_id_placeholder,
    extract_chat_id_from_response,
    extract_model_info_from_response,
    extract_original_prompt_value,
    infer_tls,
    inject_prompt_placeholder,
)

logger = logging.getLogger(__name__)

# ====================================================================
# P1-05: TargetFingerprint Schema
# Academic basis: C3 - dict[str, str] ,
# typo ( "chat_id" vs "chatid") (str/int/bool )
# 2024-2025 Python AI
# ====================================================================


@dataclass
class TargetFingerprint:
    """- Schema,

    :
        Phase 1 (parse-time):  ''burp_parser._parse_raw_http''
            (HTTP , )
        Phase 2 (probe-time):  (capability_detector/target_router)
            (,  None /  / False)

    :  ''get'' / ''__getitem__'' / ''__setitem__'' ,
     ''fp["key"]'' ,  attribute
    """

    # == Phase 1: HTTP (, _extract_fingerprint ) ==
    framework: str = "Unknown"
    api_path: str = ""
    host: str = ""
    auth_type: str = "None"
    content_type: str = "unknown"
    app_type: str = "Web Application"
    api_category: str = "chat"

    # == Phase 1: HTTP (, _parse_raw_http ) ==
    ai_framework: str | None = None
    ai_framework_category: str | None = None
    chat_id: str | None = None
    burp_model_name: str | None = None
    has_model_list: bool = False

    # == Phase 2: (capability_detector / target_router ) ==
    language: str | None = None
    model_family: str | None = None
    capabilities: list[str] = field(default_factory=list)
    probe_count: int = 0
    probe_duration_seconds: float = 0.0

    # == Phase 2: (target_router ) ==
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

    # == (, ) ==
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like .get() with attribute + extra fallback."""
        if hasattr(self, key) and not key.startswith("_"):
            val = getattr(self, key)
            return val if val is not None else default
        return self.extra.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """Dict-like [key] access with attribute + extra fallback."""
        if hasattr(self, key) and not key.startswith("_"):
            return getattr(self, key)
        return self.extra[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Dict-like [key] = value with attribute + extra storage."""
        if hasattr(self, key) and not key.startswith("_"):
            setattr(self, key, value)
        else:
            self.extra[key] = value

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict, filtering empty values."""
        from dataclasses import asdict

        result = asdict(self)
        extra = result.pop("extra", {})
        result.update(extra)
        # Filter None/empty/False/zero values for compact output
        return {k: v for k, v in result.items() if v not in (None, "", [], False, 0, 0.0)}


@dataclass
class ParsedBurpRequest:
    """Burp"""

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
    # 会话枚举攻击计划 (ASI09): 当非 None 时启用枚举模式
    enumeration_plan: dict[str, Any] | None = None


# ====================================================================
#
# ====================================================================


def parse_burp_request(file_path: str | Path) -> ParsedBurpRequest:
    """Burp HTTP (single) — first request of the input.

    Backward-compatible facade over `parse_burp_requests`. Existing callers that
    expect exactly one request keep working; multi-request/HAR inputs yield the
    first entry.

    Raises:
        FileNotFoundError: file missing.
        ValueError: no valid HTTP request found.
    """
    return parse_burp_requests(file_path)[0]


# HTTP request-line detector for multi-request splitting (REQ-160 ②)
_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/\d",
    re.IGNORECASE,
)


def parse_burp_requests(file_path: str | Path) -> list[ParsedBurpRequest]:
    """Parse any supported Burp input into a list of `ParsedBurpRequest` (REQ-160).

    Supported inputs:
        - Raw HTTP request (+ optional response) — single or multiple requests
          concatenated in one file (① multi-request, ② HAR-less raw).
        - HAR export (`.har` or JSON with `log.entries`) — request/response
          timing preserved per entry (③).

    All entries converge into the existing `ParsedBurpRequest` contract; no
    parallel data structure is introduced (I12).

    Raises:
        FileNotFoundError: file missing.
        ValueError: input contains no parseable HTTP request.
    """
    path = Path(file_path)
    raw = path.read_text(encoding="utf-8", errors="replace")

    fmt = _detect_input_format(path, raw)
    if fmt == "har":
        entries = _parse_har(raw)
        if entries:
            return entries
        raise ValueError(f"HAR file contained no usable request entries: {path}")
    if fmt == "sitemap":
        entries = _parse_sitemap(raw)
        if entries:
            return entries
        raise ValueError(f"Site Map contained no usable endpoints: {path}")
    if fmt == "postman":
        entries = _parse_postman(raw)
        if entries:
            return entries
        raise ValueError(f"Postman collection contained no usable requests: {path}")

    chunks = _split_multi_requests(raw)
    entries = []
    for chunk in chunks:
        try:
            entries.append(_parse_raw_http(chunk))
        except ValueError as e:
            logger.warning("Skipping unparseable HTTP block in %s: %s", path.name, e)
    if not entries:
        raise ValueError(f"No valid HTTP request found in: {path}")
    return entries


def _detect_input_format(path: Path, raw: str) -> str:
    """Classify the input file: 'har' | 'sitemap' | 'postman' | 'raw' (REQ-160).

    Ordering matters: HAR and Postman are both JSON, so we inspect content rather
    than trusting the extension alone (`capture.json` may be either).
    """
    suffix = path.suffix.lower()
    if suffix == ".har":
        return "har"
    if suffix == ".xml":
        return "sitemap"

    stripped = raw.lstrip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        return "raw"
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return "raw"
    if isinstance(data, dict):
        if isinstance((data.get("log") or {}).get("entries"), list):
            return "har"
        if "item" in data and "info" in data:
            return "postman"
        if isinstance(data.get("items"), list):
            return "sitemap"
    if isinstance(data, list) and data and isinstance(data[0], (str, dict)):
        return "sitemap"
    return "raw"


def _split_multi_requests(raw: str) -> list[str]:
    """Split a raw Burp dump containing several request/response pairs.

    Burp "Save items" can emit multiple requests concatenated. We split on
    lines that start a new HTTP request; each block is parsed independently.
    A single-request input is returned as-is (zero behavior change).
    """
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    starts = [i for i, line in enumerate(lines) if _REQUEST_LINE_RE.match(line.strip())]
    if len(starts) <= 1:
        return [normalized]
    chunks: list[str] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        chunk = "\n".join(lines[start:end]).strip("\n")
        if chunk:
            chunks.append(chunk)
    return chunks


def _request_from_url(
    method: str,
    url: str,
    header_pairs: list[tuple[str, str]],
    body: str,
) -> ParsedBurpRequest | None:
    """Build a `ParsedBurpRequest` from an absolute URL + method + headers + body.

    Shared by HAR / Site Map / Postman importers (REQ-160 ③). Returns None when
    the URL is unusable. The absolute URL is authoritative for scheme.
    """
    from urllib.parse import urlparse

    if not url:
        return None
    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        return None

    path = parsed_url.path or "/"
    if parsed_url.query:
        path = f"{path}?{parsed_url.query}"
    host = parsed_url.netloc

    lines = [f"{method} {path} HTTP/1.1"]
    if not any(k.lower() == "host" for k, _ in header_pairs) and host:
        lines.append(f"Host: {host}")
    for name, value in header_pairs:
        if not name or name.lower() == "content-length":
            continue
        lines.append(f"{name}: {value}")
    raw_request = "\n".join(lines) + "\n\n" + body

    try:
        parsed = _parse_raw_http(raw_request)
    except ValueError as e:
        logger.warning("Skipping unparseable entry (%s %s): %s", method, path, e)
        return None

    if parsed_url.scheme:
        parsed.use_tls = parsed_url.scheme.lower() == "https"
    parsed.url = url
    parsed.http_version = "HTTP/1.1"
    return parsed


def _parse_har(raw: str) -> list[ParsedBurpRequest]:
    """Convert HAR `log.entries[*]` into `ParsedBurpRequest` list (REQ-160 ③)."""
    data = json.loads(raw)
    entries = (data.get("log") or {}).get("entries") or []

    out: list[ParsedBurpRequest] = []
    for entry in entries:
        req = entry.get("request") or {}
        method = str(req.get("method") or "POST").upper()
        url = str(req.get("url") or "")
        headers = [
            (str(h.get("name") or ""), str(h.get("value") or ""))
            for h in (req.get("headers") or [])
            if h.get("name")
        ]
        body = str((req.get("postData") or {}).get("text") or "")
        parsed = _request_from_url(method, url, headers, body)
        if parsed is not None:
            out.append(parsed)
    return out


def _parse_sitemap(raw: str) -> list[ParsedBurpRequest]:
    """Import a Burp Site Map export (XML or JSON) as endpoint stubs (REQ-160 ③).

    A Site Map has no bodies, so each entry becomes a request with an empty body;
    it is used for endpoint enumeration, not for replay.
    """
    stripped = raw.lstrip()
    out: list[ParsedBurpRequest] = []

    if stripped.startswith("<"):
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(stripped)
        except ET.ParseError as e:
            logger.warning("Site Map XML parse failed: %s", e)
            return []

        def _local(tag: str) -> str:
            return tag.rsplit("}", 1)[-1].lower()

        for item in root.iter():
            if _local(item.tag) != "item":
                continue
            url: str | None = None
            method = "GET"
            for child in item:
                ctag = _local(child.tag)
                if ctag == "url":
                    url = (child.text or "").strip() or child.get("url")
                elif ctag == "method":
                    method = (child.text or "").strip().upper() or "GET"
            if not url:
                url = item.get("url")
            if url:
                parsed = _request_from_url(method or "GET", url, [], "")
                if parsed is not None:
                    out.append(parsed)
        return out

    data = json.loads(stripped)
    items = data.get("items") if isinstance(data, dict) else data
    for it in items or []:
        url: str | None
        method = "GET"
        if isinstance(it, str):
            url = it
        elif isinstance(it, dict):
            url = it.get("url") or it.get("URL")
            method = str(it.get("method") or "GET").upper()
        else:
            continue
        if url:
            parsed = _request_from_url(method, str(url), [], "")
            if parsed is not None:
                out.append(parsed)
    return out


def _parse_postman(raw: str) -> list[ParsedBurpRequest]:
    """Import a Postman v2.x collection (recursively flattened) — REQ-160 ③."""
    data = json.loads(raw)
    out: list[ParsedBurpRequest] = []

    def _walk(items: Any) -> None:
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if isinstance(it.get("item"), list):
                _walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method") or "GET").upper()
            raw_url = req.get("url")
            url = str((raw_url or {}).get("raw") or "") if isinstance(raw_url, dict) else str(raw_url or "")
            headers = [
                (str(h.get("key") or ""), str(h.get("value") or ""))
                for h in (req.get("header") or [])
                if h.get("key")
            ]
            body_obj = req.get("body") or {}
            body = str(body_obj.get("raw") or "") if isinstance(body_obj, dict) else ""
            if url:
                parsed = _request_from_url(method, url, headers, body)
                if parsed is not None:
                    out.append(parsed)

    _walk(data.get("item"))
    return out


def build_raw_http_request(parsed: ParsedBurpRequest) -> str:
    """HTTP (CRLF )"""
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


# ====================================================================
#
# ====================================================================


def _parse_raw_http(raw: str) -> ParsedBurpRequest:
    """HTTP

    L5 v19 :  Burp  header  body ,
     body  header

    P2-20 :  Burp  HTTP  (Request + Response)
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

    # header ( + )
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
            if potential_key and all(c.isalnum() or c in "-_" for c in potential_key):
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

    # SSE (3 Layer)
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

    # API ( api_classifier)
    api_category = detect_api_category(path, body)

    # prompt ()
    original_prompt_value: str | None = None
    if api_category == "chat" and body and "{PROMPT}" not in body:
        original_prompt_value = extract_original_prompt_value(body)
        if original_prompt_value:
            logger.info(
                "Extracted original prompt value from body: %s",
                original_prompt_value[:80],
            )

    # +
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

    # ( fingerprint )
    fingerprint = _extract_fingerprint(headers, path, host, response_section)
    fingerprint.api_category = api_category

    # Response ID
    chat_id: str | None = None
    chat_id_field: str | None = None
    has_chat_id_placeholder = False
    initial_chat_id_from_body: str | None = None

    # Burp Response
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

    # Request body ID and inject into {CHAT_ID}
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

    # 解析会话枚举计划 (从 CLI 参数传入)
    enumeration_plan: dict[str, Any] | None = None
    if _ENUMERATION_ARGS:
        enumeration_plan = _build_enumeration_plan(chat_id_field)

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
        enumeration_plan=enumeration_plan,
    )


def _extract_fingerprint(
    headers: dict[str, str],
    path: str,
    host: str,
    response_section: str | None = None,
) -> TargetFingerprint:
    """imports HTTP (Phase 1 )"""
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

    #
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

    # AI /SDK ( fingerprint )
    ai_fw: str | None = None
    ai_fw_cat: str | None = None
    if response_section:
        ai_fw, ai_fw_cat = extract_ai_framework_fingerprint(response_section)
    sdk_fw, sdk_fw_cat = extract_ai_sdk_from_request_headers(headers)
    if sdk_fw and not ai_fw:
        ai_fw, ai_fw_cat = sdk_fw, sdk_fw_cat

    # WAF / 限流指纹（REQ-161 ②③）：从 Burp 响应头/体/状态码同步识别，
    # 结果写入 fingerprint.extra（recon 输出总线，不新建并行通道，I12）。
    extra: dict[str, Any] = {}
    if response_section:
        try:
            from recon.waf_detector import fingerprint_waf, waf_to_fingerprint_fields

            resp_pairs, resp_body = split_response_headers_body(response_section)
            resp_headers = {k.lower(): v for k, v in resp_pairs}
            cookies: dict[str, str] = {}
            for name, value in resp_pairs:
                if name.lower() == "set-cookie":
                    ck, _, cv = value.split(";")[0].strip().partition("=")
                    if ck:
                        cookies[ck] = cv
            status_code: int | None = None
            first_line = response_section.strip().split("\n", 1)[0].split(" ")
            if len(first_line) >= 2 and first_line[1].isdigit():
                status_code = int(first_line[1])
            report = fingerprint_waf(resp_headers, resp_body, status_code, cookies)
            extra.update(waf_to_fingerprint_fields(report))
        except Exception as e:
            logger.debug("WAF detection skipped: %s", e)

    return TargetFingerprint(
        framework=framework,
        api_path=path,
        host=host,
        auth_type=auth_type,
        content_type=content_type,
        app_type=app_type,
        ai_framework=ai_fw,
        ai_framework_category=ai_fw_cat,
        extra=extra,
    )


def _split_request_response(normalized: str) -> tuple[str, str | None]:
    """Burp HTTP Request Response

    ''HTTP/<digit>''  Response
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


# ID ()
_CHAT_ID_FIELD_NAMES = frozenset(
    {
        "chatid",
        "chat_id",
        "chatidvalue",
        "chatsessionid",
        "chat_session_id",
        "sessionid",
        "session_id",
        "sessionidvalue",
        "conversationid",
        "conversation_id",
        "convid",
        "conv_id",
        "dialogid",
        "dialog_id",
        "threadid",
        "thread_id",
        "req_id",
        "requestid",
        "request_id",
    }
)


# ---------------------------------------------------------------------------
#  (ASI09):  CLI
# ---------------------------------------------------------------------------
_ENUMERATION_ARGS: dict[str, Any] = {}


def set_enumeration_args(args: dict[str, Any]) -> None:
    """CLI ( main.py )."""
    global _ENUMERATION_ARGS
    _ENUMERATION_ARGS = args


def _build_enumeration_plan(chat_id_field: str | None) -> dict[str, Any] | None:
    """(CLI ).

    None  。
    """
    if not _ENUMERATION_ARGS.get("enabled"):
        return None

    plan: dict[str, Any] = {
        "pattern_template": _ENUMERATION_ARGS.get("pattern_template", "MC-{date:%Y%m%d}-{counter:04d}"),
        "days_back": _ENUMERATION_ARGS.get("days_back", 14),
        "counter_max": _ENUMERATION_ARGS.get("counter_max", 20),
        "extraction_prompt": _ENUMERATION_ARGS.get("extraction_prompt", "What notes do I have saved?"),
        "max_concurrency": _ENUMERATION_ARGS.get("max_concurrency", 1),
        "request_delay": _ENUMERATION_ARGS.get("request_delay", 2.0),
        "session_field": chat_id_field or "session_id",
    }

    #
    if _ENUMERATION_ARGS.get("date_start"):
        plan["date_start"] = _ENUMERATION_ARGS["date_start"]
    if _ENUMERATION_ARGS.get("date_end"):
        plan["date_end"] = _ENUMERATION_ARGS["date_end"]
    if _ENUMERATION_ARGS.get("sensitive_keywords"):
        plan["sensitive_keywords"] = _ENUMERATION_ARGS["sensitive_keywords"]
    if _ENUMERATION_ARGS.get("empty_indicators"):
        plan["empty_indicators"] = _ENUMERATION_ARGS["empty_indicators"]
    if _ENUMERATION_ARGS.get("max_requests"):
        plan["max_requests"] = _ENUMERATION_ARGS["max_requests"]

    return plan


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
)
