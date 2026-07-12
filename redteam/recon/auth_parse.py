"""解析浏览器 F12 复制的原始 HTTP 请求头 → AuthContext。

Library-First：纯标准库实现（不引入第三方库）。理由：请求头解析是简单文本处理，
无成熟专用库必要，且需精确控制 Cookie/JWT/Basic Auth/API Key 的抽取逻辑以支撑后续认证回填。

支持输入形态：
  1. 完整请求块（含 `GET /path HTTP/1.1` 首行）
  2. 仅请求头块（`Key: Value` 逐行）
  3. 纯 Cookie 字符串（`key=value; key2=value2`，如 document.cookie）
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

from redteam.core.models import AuthContext, BasicAuth

_HEADER_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9\-_]*)\s*:\s*(.+?)\s*$")
_REQUEST_LINE_RE = re.compile(r"^(?:[A-Z]+\s+\S+\s+HTTP/[\d.]+|HTTP/[\d.]+\s+\d+)", re.IGNORECASE)
_BARE_BEARER_RE = re.compile(r"^Bearer\s+(.+)", re.IGNORECASE)
_BARE_BASIC_RE = re.compile(r"^Basic\s+(.+)", re.IGNORECASE)

# 视为「API Key 类」的请求头（不区分大小写）
_API_KEY_HEADERS = {
    "x-api-key",
    "api-key",
    "x-api-token",
    "api-token",
    "x-auth-token",
    "authorization",  # 仅当非 Bearer/Basic 时归入（Bearer/Basic 单独处理）
}



def _is_cookie_string(line: str) -> bool:
    """检测是否为 document.cookie 直接复制格式（无 'Cookie:' 前缀）。

    特征：分号分隔、每个片段含 '='，且不匹配标准 HTTP 头格式。
    """
    stripped = line.strip()
    if not stripped or _HEADER_RE.match(stripped):
        return False
    return any("=" in p for p in stripped.split(";") if p.strip())


def _decode_basic_auth(value: str) -> BasicAuth | None:
    """解码 HTTP Basic Auth 的 base64(user:pass)，返回 BasicAuth 模型。"""
    try:
        encoded = value.strip()
        # 补齐可能的 base64 填充
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding
        decoded = base64.b64decode(encoded).decode("utf-8")
        if ":" in decoded:
            username, password = decoded.split(":", 1)
            return BasicAuth(username=username, password=password)
        # 尝试以 latin-1 回退（某些老旧服务）
        decoded_latin = base64.b64decode(encoded).decode("latin-1")
        if ":" in decoded_latin:
            username, password = decoded_latin.split(":", 1)
            return BasicAuth(username=username, password=password)
    except Exception:
        pass
    return None


def parse_headers(raw: str) -> AuthContext:
    """从原始 header 文本解析出 AuthContext。"""
    cookies: dict[str, str] = {}
    api_keys: dict[str, str] = {}
    extra: dict[str, str] = {}
    bearer: str | None = None
    basic_auth: BasicAuth | None = None

    for line in raw.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        # 跳过请求行（GET/POST ... HTTP/1.1）
        if _REQUEST_LINE_RE.match(line):
            continue
        m = _HEADER_RE.match(line)
        if not m:
            # 检测裸 Bearer/Basic 行（缺少 Authorization: 前缀），优先于 Cookie 回退
            bare_bearer = _BARE_BEARER_RE.match(line)
            if bare_bearer:
                bearer = bare_bearer.group(1).strip()
                continue
            bare_basic = _BARE_BASIC_RE.match(line)
            if bare_basic:
                decoded = _decode_basic_auth(bare_basic.group(1))
                if decoded:
                    basic_auth = decoded
                continue
            # 可能是 document.cookie 直接复制粘贴（如浏览器控制台复制）
            if _is_cookie_string(line):
                cookies.update(_split_cookie(line))
            continue
        name = m.group(1)
        value = m.group(2)
        low = name.lower()

        if low == "cookie":
            cookies.update(_split_cookie(value))
        elif low == "authorization":
            if value.lower().startswith("bearer "):
                bearer = value[len("bearer ") :].strip()
            elif value.lower().startswith("basic "):
                decoded = _decode_basic_auth(value[len("basic ") :])
                if decoded:
                    basic_auth = decoded
                else:
                    extra[name] = value  # 解码失败仍保留原始头
            else:
                # 其他 Authorization 类型作为额外头保留
                extra[name] = value
        elif low in {
            "x-api-key",
            "api-key",
            "x-api-token",
            "api-token",
            "x-auth-token",
        }:
            api_keys[name] = value
        else:
            extra[name] = value

    return AuthContext(
        cookies=cookies,
        bearer=bearer,
        basic_auth=basic_auth,
        api_keys=api_keys,
        extra_headers=extra,
    )


def _split_cookie(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_headers_file(path: str | Path) -> AuthContext:
    return parse_headers(Path(path).read_text(encoding="utf-8"))


def summarize(auth: AuthContext) -> dict[str, int]:
    """给 UI/日志用：脱敏统计。"""
    return {
        "cookies": len(auth.cookies),
        "bearer": 1 if auth.bearer else 0,
        "basic_auth": 1 if auth.basic_auth else 0,
        "api_keys": len(auth.api_keys),
        "extra_headers": len(auth.extra_headers),
    }
