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
import json
import re
from pathlib import Path

from redteam.core.models import AuthContext, BasicAuth

_HEADER_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9\-_]*)\s*:\s*(.+?)\s*$")
_REQUEST_LINE_RE = re.compile(r"^(?:[A-Z]+\s+\S+\s+HTTP/[\d.]+|HTTP/[\d.]+\s+\d+)", re.IGNORECASE)
_BARE_BEARER_RE = re.compile(r"^Bearer\s+(.+)", re.IGNORECASE)
_BARE_BASIC_RE = re.compile(r"^Basic\s+(.+)", re.IGNORECASE)
# JWT 三段式快速检测正则
_JWT_RE = re.compile(r"^[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+$")

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


def is_jwt(token: str) -> bool:
    """检测 token 是否为 JWT 格式（三段 base64url 由 '.' 分隔）。

    Args:
        token: 待检测的 token 字符串。

    Returns:
        True 如果 token 符合 JWT 格式（不验证签名有效性）。
    """
    return bool(_JWT_RE.match(token.strip()))


def decode_jwt(token: str) -> tuple[dict | None, dict | None]:
    """解码 JWT 的 header 和 payload（不验证签名）。

    仅做 base64url 解码，用于查看 JWT 中的声明信息。
    不进行签名验证，适合红队侦察场景下快速理解认证上下文。

    Args:
        token: JWT token 字符串。

    Returns:
        (header_dict, payload_dict)，解码失败则对应位置为 None。
    """
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None, None

        def _b64url_decode(s: str) -> dict:
            # 补齐填充
            padding = 4 - len(s) % 4
            if padding != 4:
                s += "=" * padding
            # 替换 URL-safe 字符为标准 base64
            s = s.replace("-", "+").replace("_", "/")
            decoded = base64.b64decode(s)
            return json.loads(decoded)

        header = _b64url_decode(parts[0])
        payload = _b64url_decode(parts[1])
        return header, payload
    except Exception:
        return None, None


def encode_basic_auth(username: str, password: str) -> str:
    """将用户名和密码编码为 HTTP Basic Auth 凭据。

    Args:
        username: 用户名。
        password: 密码。

    Returns:
        base64 编码的 `username:password` 字符串。
    """
    return base64.b64encode(f"{username}:{password}".encode()).decode()


def describe_auth(auth: AuthContext) -> str:
    """生成认证上下文的详细描述信息，用于控制台输出。

    包含以下内容：
      - 认证类型标签（jwt/cookie/basic/api_key 组合）
      - Cookie 数量和关键 cookie 名称
      - JWT header 与 payload 解码（如适用）
      - Basic Auth 用户名
      - API Key 头名称列表
      - 其他含编码凭据的可疑请求头检测

    Args:
        auth: 解析后的 AuthContext。

    Returns:
        格式化的多行描述字符串。
    """
    lines: list[str] = []
    atype = auth.auth_type

    # 认证类型标签
    type_label = {
        "jwt": "JWT (JSON Web Token)",
        "jwt+cookie": "JWT + Cookie 组合认证",
        "jwt+api_key": "JWT + API Key 组合认证",
        "jwt+cookie+api_key": "JWT + Cookie + API Key 组合认证",
        "bearer": "Bearer Token (非 JWT 格式)",
        "bearer+cookie": "Bearer Token + Cookie",
        "cookie": "Cookie 认证",
        "basic": "HTTP Basic Auth",
        "api_key": "API Key 认证",
        "none": "无认证信息",
    }
    label = type_label.get(atype, atype.replace("+", " + "))
    lines.append(f"[Auth] 认证类型: {label}")

    # Cookie 信息
    if auth.cookies:
        cookie_names = list(auth.cookies.keys())
        lines.append(f"[Auth] Cookie ({len(cookie_names)} 个): {', '.join(cookie_names[:10])}")
        if len(cookie_names) > 10:
            lines.append(f"       ... 以及其他 {len(cookie_names) - 10} 个")

    # JWT 解码
    if auth.bearer and is_jwt(auth.bearer):
        header, payload = decode_jwt(auth.bearer)
        if header:
            lines.append(f"[Auth] JWT Header: {json.dumps(header, ensure_ascii=False)}")
        if payload:
            # 脱敏处理：标记敏感字段但保留结构
            sensitive_keys = {"sub", "email", "name", "preferred_username", "upn", "unique_name"}
            masked_payload = {
                k: ("***" if k.lower() in sensitive_keys else v)
                for k, v in payload.items()
            }
            lines.append(f"[Auth] JWT Payload: {json.dumps(masked_payload, ensure_ascii=False, default=str)}")

            # 检查过期时间
            import time
            exp = payload.get("exp")
            if exp and isinstance(exp, (int, float)):
                remaining = exp - time.time()
                if remaining > 0:
                    hours = remaining / 3600
                    lines.append(f"[Auth] JWT 有效期: {hours:.1f} 小时后过期")
                else:
                    lines.append(f"[Auth] JWT 已过期 ({abs(remaining):.0f} 秒前)")

    # 非 JWT Bearer token
    if auth.bearer and not is_jwt(auth.bearer):
        token_preview = auth.bearer[:30] + "..." if len(auth.bearer) > 30 else auth.bearer
        lines.append(f"[Auth] Bearer Token: {token_preview}")

    # Basic Auth 解码
    if auth.basic_auth:
        lines.append(f"[Auth] Basic Auth: username={auth.basic_auth.username}")
        encoded = encode_basic_auth(auth.basic_auth.username, auth.basic_auth.password)
        lines.append(f"[Auth] Basic Auth 编码: Basic {encoded}")

    # API Keys
    if auth.api_keys:
        for key_name in sorted(auth.api_keys.keys()):
            val = auth.api_keys[key_name]
            preview = val[:8] + "..." if len(val) > 8 else val
            lines.append(f"[Auth] API Key ({key_name}): {preview}")

    # 含编码凭据的可疑请求头
    cred_headers = _detect_credential_headers(auth.extra_headers)
    if cred_headers:
        lines.append(f"[Auth] 含编码凭据的请求头 ({len(cred_headers)} 个):")
        for name, decoded in cred_headers.items():
            lines.append(f"       {name}: {decoded}")

    return "\n".join(lines)


def _detect_credential_headers(headers: dict[str, str]) -> dict[str, str]:
    """检测 extra_headers 中可能包含编码凭据的请求头。

    包括：Base64 编码的用户名:密码、URL 编码凭据等。

    Args:
        headers: extra_headers 字典。

    Returns:
        {header_name: 解码后描述} 的字典，仅包含检测到凭据的请求头。
    """
    result: dict[str, str] = {}
    for name, value in headers.items():
        description = _try_decode_credential_value(value)
        if description:
            result[name] = description
    return result


def _try_decode_credential_value(value: str) -> str | None:
    """尝试将字符串值解码为凭据信息。

    依次尝试 Base64 解码（Basic Auth 格式）和 URL 解码检测。
    """
    # 尝试 Base64 解码
    try:
        # 补齐填充
        val = value.strip()
        padding = 4 - len(val) % 4
        if padding != 4:
            val += "=" * padding
        decoded = base64.b64decode(val, validate=False)
        text = decoded.decode("utf-8", errors="ignore")
        if ":" in text and len(text) < 256:
            parts = text.split(":", 1)
            if parts[0] and parts[1]:
                return f"Base64 → {parts[0]}:****"
    except Exception:
        pass

    # 尝试 URL 编码检测
    try:
        from urllib.parse import unquote
        decoded = unquote(value)
        if decoded != value and ("=" in decoded or "&" in decoded):
            return f"URL 编码 → {decoded[:100]}"
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


def summarize(auth: AuthContext) -> dict[str, int | str]:
    """给 UI/日志用：脱敏统计。"""
    return {
        "auth_type": auth.auth_type,
        "cookies": len(auth.cookies),
        "bearer": 1 if auth.bearer else 0,
        "basic_auth": 1 if auth.basic_auth else 0,
        "api_keys": len(auth.api_keys),
        "extra_headers": len(auth.extra_headers),
    }
