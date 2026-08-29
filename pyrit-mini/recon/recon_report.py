"""recon_report — 侦察结果格式化输出。

将 ParsedBurpRequest 的完整指纹信息以卡片格式输出到终端，
供 `mini_strike.py --stage recon` 使用。

输出内容 (精简, 突出攻击者关心的信息):
    1. 目标卡片 (Host/Path/Model/Auth/Capabilities)
    2. HTTP 请求解析 (关键字段)
    3. 请求 Body (注入后, 可折叠)
    4. 完整指纹 JSON (可复制)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from recon.burp_parser import ParsedBurpRequest

from utils.display import (
    _C_BOLD,
    _C_CYAN,
    _C_DIM,
    _C_GREEN,
    _C_RESET,
    _C_YELLOW,
    _card_line,
    _pad_line,
    _BOTTOM_LEFT,
    _BOTTOM_RIGHT,
    _H,
    _INNER,
    _TOP_LEFT,
    _TOP_RIGHT,
    _V,
)


def print_recon_report(parsed: "ParsedBurpRequest") -> None:
    """输出完整的侦察结果报告 (卡片式, 精简).

    Args:
        parsed: 解析后的 Burp 请求 (含 target_fingerprint)。
    """
    fp = parsed.target_fingerprint

    # ════════════════════════════════════════════════════════════════
    # 1. 目标卡片 (核心信息)
    # ════════════════════════════════════════════════════════════════
    prompt_status = f"{_C_GREEN}✓{_C_RESET}" if parsed.has_prompt_placeholder else f"{_C_YELLOW}✗{_C_RESET}"

    rows = [
        ("Host", parsed.host),
        ("Path", parsed.path),
        ("Method", parsed.method),
        ("TLS", "是" if parsed.use_tls else "否"),
        ("SSE", "是" if parsed.is_sse else "否"),
        ("App Type", fp.get("app_type", "Unknown")),
        ("Auth", fp.get("auth_type", "Unknown")),
        ("Framework", fp.get("framework", "Unknown")),
        ("Content-Type", fp.get("content_type", "unknown")),
        ("{PROMPT}", f"{'已注入' if parsed.has_prompt_placeholder else '未注入'} {prompt_status}"),
    ]

    # 模型信息 (攻击者最关心)
    model_display = fp.get("burp_model_name", "") or fp.get("model_family", "") or "Unknown"
    rows.append(("Model", model_display))

    if parsed.api_category != "chat":
        rows.append(("API Category", f"{parsed.api_category} (非 chat)"))

    if parsed.chat_id_field:
        rows.append(("Chat ID Field", parsed.chat_id_field))

    _print_card_block("RECON — Target Profile", rows, _C_CYAN)

    # ════════════════════════════════════════════════════════════════
    # 2. HTTP Headers (精简: 只显示关键 header)
    # ════════════════════════════════════════════════════════════════
    _key_headers = {"authorization", "cookie", "content-type", "accept", "x-api-key", "x-request-id"}
    important_headers = [
        (k, v) for k, v in parsed.raw_headers
        if k.lower() in _key_headers
    ]
    other_headers = [
        (k, v) for k, v in parsed.raw_headers
        if k.lower() not in _key_headers
    ]

    if important_headers:
        header_rows = []
        for key, value in important_headers:
            display_val = value
            if len(value) > 60 and key.lower() in ("authorization", "cookie"):
                display_val = value[:20] + "..." + value[-10:]
            header_rows.append((key, display_val))
        if other_headers:
            header_rows.append(("(+ others)", f"{len(other_headers)} more headers"))
        _print_card_block("Key Headers", header_rows, _C_YELLOW)

    # ════════════════════════════════════════════════════════════════
    # 3. 请求 Body (注入后, JSON 格式化)
    # ════════════════════════════════════════════════════════════════
    if parsed.body:
        print(f"\n{_C_BOLD}Request Body ({'{{PROMPT}}'} injected):{_C_RESET}")
        try:
            body_json = json.loads(parsed.body)
            print(json.dumps(body_json, indent=2, ensure_ascii=False))
        except (json.JSONDecodeError, TypeError):
            print(parsed.body)

    # ════════════════════════════════════════════════════════════════
    # 4. 重建 HTTP 请求 (攻击者可直接使用)
    # ════════════════════════════════════════════════════════════════
    from recon.burp_parser import build_raw_http_request
    raw_http = build_raw_http_request(parsed)
    print(f"\n{_C_BOLD}Rebuilt HTTP Request (for PyRIT HTTPTarget):{_C_RESET}")
    print(f"{_C_DIM}{raw_http}{_C_RESET}")

    # ════════════════════════════════════════════════════════════════
    # 5. 完整指纹 JSON (可复制)
    # ════════════════════════════════════════════════════════════════
    print(f"\n{_C_BOLD}Full Fingerprint (JSON):{_C_RESET}")
    print(json.dumps(fp, indent=2, ensure_ascii=False))


def _print_card_block(
    title: str,
    rows: list[tuple[str, str]],
    color: str,
) -> None:
    """打印卡片块 (带边框和颜色)."""
    print()
    tl = f"{color}{_TOP_LEFT}{_H * _INNER}{_TOP_RIGHT}{_C_RESET}"
    bl = f"{color}{_BOTTOM_LEFT}{_H * _INNER}{_BOTTOM_RIGHT}{_C_RESET}"
    print(tl)
    print(_card_line(title, color + _C_BOLD))
    print(f"{_V} {'─' * _INNER} {_V}")
    for label, value in rows:
        print(_card_line(f"{label}: {value}", color))
    print(bl)
