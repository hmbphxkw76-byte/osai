"""recon/_burp_fingerprint — Raw HTTP parsing + target fingerprint extraction.

Extracted from `recon/burp_parser.py` (SRP). Depends on the shared
`_burp_models` / `_burp_enumeration` modules and the lower-level
`recon.fingerprint` / `recon.model.*` helpers (which do not import back, so there
is no import cycle).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from recon._burp_enumeration import (
    _CHAT_ID_FIELD_NAMES,
    _ENUMERATION_ARGS,
    _build_enumeration_plan,
)
from recon._burp_models import ParsedBurpRequest, TargetFingerprint
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

    'HTTP/<digit>'  Response
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
