import base64
import os
import tempfile

from redteam.recon.auth_parse import (
    parse_headers, parse_headers_file, summarize,
    _is_cookie_string, _decode_basic_auth,
    is_jwt, decode_jwt, encode_basic_auth, describe_auth,
    _detect_credential_headers, _try_decode_credential_value,
)

SAMPLE = """GET /api/chat HTTP/1.1
Host: example.ai
Cookie: session=abc123; csrftoken=xyz
Authorization: Bearer eyJabc.def.ghi
X-API-Key: sk-123456
User-Agent: Mozilla/5.0
"""


# ===== 现有基础测试 =====

def test_parse_headers():
    a = parse_headers(SAMPLE)
    assert a.cookies == {"session": "abc123", "csrftoken": "xyz"}
    assert a.bearer == "eyJabc.def.ghi"
    assert a.api_keys.get("X-API-Key") == "sk-123456"
    assert a.extra_headers.get("User-Agent") == "Mozilla/5.0"


def test_to_header_dict():
    a = parse_headers(SAMPLE)
    h = a.to_header_dict()
    assert h["Authorization"] == "Bearer eyJabc.def.ghi"
    assert h["Cookie"] == "session=abc123; csrftoken=xyz"
    assert "X-API-Key" in h


def test_mask():
    a = parse_headers(SAMPLE)
    m = a.mask()
    assert m.bearer == "***"
    assert all(v == "***" for v in m.cookies.values())
    assert all(v == "***" for v in m.api_keys.values())


# ===== 新增测试：_is_cookie_string =====

def test_is_cookie_string_true():
    """纯 Cookie 字符串格式应被识别。"""
    assert _is_cookie_string("session=abc; token=xyz") is True
    assert _is_cookie_string("key=value") is True


def test_is_cookie_string_false_for_headers():
    """标准 HTTP 头格式不应被识别为 Cookie 字符串。"""
    assert _is_cookie_string("Content-Type: application/json") is False
    assert _is_cookie_string("Authorization: Bearer xxx") is False


def test_is_cookie_string_empty():
    assert _is_cookie_string("") is False
    assert _is_cookie_string("   ") is False


# ===== 新增测试：_decode_basic_auth =====

def test_decode_basic_auth_valid():
    """标准 base64(user:pass) 解码。"""
    encoded = base64.b64encode(b"admin:password123").decode()
    result = _decode_basic_auth(encoded)
    assert result is not None
    assert result.username == "admin"
    assert result.password == "password123"


def test_decode_basic_auth_invalid():
    """无效 Base64 返回 None。"""
    assert _decode_basic_auth("!!!not-valid-base64!!!") is None
    assert _decode_basic_auth("") is None


def test_decode_basic_auth_no_colon():
    """无冒号分隔符的 base64 返回 None。"""
    encoded = base64.b64encode(b"just_a_string_without_colon").decode()
    result = _decode_basic_auth(encoded)
    assert result is None


def test_decode_basic_auth_padded():
    """补齐填充后应能正常解码。"""
    # "u:p" = base64 "djpw" (3 chars, no padding needed)
    encoded = base64.b64encode(b"u:p").decode()
    # remove padding
    encoded_no_pad = encoded.rstrip("=")
    result = _decode_basic_auth(encoded_no_pad)
    assert result is not None
    assert result.username == "u"
    assert result.password == "p"


# ===== 新增测试：parse_headers_file =====

def test_parse_headers_file():
    """从文件读取请求头并解析。"""
    content = "Authorization: Bearer file_token_123\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(content)
        tmp_path = f.name

    try:
        auth = parse_headers_file(tmp_path)
        assert auth.bearer == "file_token_123"
    finally:
        os.unlink(tmp_path)


# ===== 新增测试：summarize =====

def test_summarize_full():
    """完整 AuthContext 的摘要统计。"""
    a = parse_headers(SAMPLE)
    stats = summarize(a)
    assert stats["cookies"] == 2
    assert stats["bearer"] == 1
    assert stats["basic_auth"] == 0
    assert stats["api_keys"] == 1
    assert stats["extra_headers"] >= 1


def test_summarize_empty():
    """空 AuthContext 的摘要统计。"""
    from redteam.core.models import AuthContext
    stats = summarize(AuthContext())
    assert stats["cookies"] == 0
    assert stats["bearer"] == 0
    assert stats["basic_auth"] == 0
    assert stats["api_keys"] == 0
    assert stats["extra_headers"] == 0


# ===== 新增测试：Basic Auth 解析 =====

def test_parse_basic_auth_header():
    """解析 Authorization: Basic 头。"""
    encoded = base64.b64encode(b"admin:secret").decode()
    raw = f"GET / HTTP/1.1\nAuthorization: Basic {encoded}\n"
    auth = parse_headers(raw)
    assert auth.basic_auth is not None
    assert auth.basic_auth.username == "admin"
    assert auth.basic_auth.password == "secret"
    # Bearer 应为 None
    assert auth.bearer is None


def test_parse_bare_bearer_line():
    """解析裸 Bearer 行（缺少 Authorization: 前缀）。"""
    raw = "Bearer standalone_token_value\n"
    auth = parse_headers(raw)
    assert auth.bearer == "standalone_token_value"


def test_parse_bare_basic_line():
    """解析裸 Basic 行。"""
    encoded = base64.b64encode(b"user:pass").decode()
    raw = f"Basic {encoded}\n"
    auth = parse_headers(raw)
    assert auth.basic_auth is not None
    assert auth.basic_auth.username == "user"
    assert auth.basic_auth.password == "pass"


def test_parse_empty_string():
    """空字符串解析返回空 AuthContext。"""
    auth = parse_headers("")
    assert auth.bearer is None
    assert auth.cookies == {}
    assert auth.api_keys == {}
    assert auth.extra_headers == {}


def test_parse_other_api_key_headers():
    """解析多种 API Key 变体头。"""
    raw = (
        "X-API-Key: key1\n"
        "api-key: key2\n"
        "X-API-Token: token1\n"
        "api-token: token2\n"
        "X-Auth-Token: authtoken1\n"
    )
    auth = parse_headers(raw)
    assert auth.api_keys["X-API-Key"] == "key1"
    assert auth.api_keys["api-key"] == "key2"
    assert auth.api_keys["X-API-Token"] == "token1"
    assert auth.api_keys["api-token"] == "token2"
    assert auth.api_keys["X-Auth-Token"] == "authtoken1"


def test_parse_document_cookie_format():
    """解析 document.cookie 直接复制格式（无 'Cookie:' 前缀）。"""
    raw = "session=abc123; token=xyz\n"
    auth = parse_headers(raw)
    assert auth.cookies == {"session": "abc123", "token": "xyz"}


def test_basic_auth_to_header_dict():
    """Basic Auth 应生成正确的 Authorization 头。"""
    auth = parse_headers(f"Authorization: Basic {base64.b64encode(b'admin:pass').decode()}\n")
    headers = auth.to_header_dict()
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Basic ")
    # 验证解码回来
    b64 = headers["Authorization"][6:]
    decoded = base64.b64decode(b64).decode()
    assert decoded == "admin:pass"


# ===== JWT 检测与解码测试 =====

def test_is_jwt_valid():
    """标准三段式 JWT 应返回 True。"""
    assert is_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature") is True


def test_is_jwt_invalid():
    """非三段式 token 应返回 False。"""
    assert is_jwt("just_a_random_string") is False
    assert is_jwt("sk-1234567890abcdef") is False
    assert is_jwt("") is False
    assert is_jwt("a.b") is False
    assert is_jwt("a.b.c.d") is False


def test_decode_jwt():
    """解码 JWT 应返回 header 和 payload。"""
    # 构造一个简单的 JWT: header={"alg":"HS256"}, payload={"sub":"test","exp":9999999999}
    import json
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps({"sub": "test", "exp": 9999999999}).encode()).rstrip(b"=").decode()
    token = f"{header_b64}.{payload_b64}.sig"

    h, p = decode_jwt(token)
    assert h is not None
    assert p is not None
    assert h["alg"] == "HS256"
    assert p["sub"] == "test"
    assert p["exp"] == 9999999999


def test_decode_jwt_invalid():
    """无效 JWT 字符串应返回 (None, None)。"""
    assert decode_jwt("not-a-jwt") == (None, None)
    assert decode_jwt("") == (None, None)
    assert decode_jwt("a.b") == (None, None)


def test_decode_jwt_padded_payload():
    """带填充的 JWT 也应正常解码。"""
    import json
    # 构造需要填充的 payload
    payload = {"sub": "user123", "role": "admin"}
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
    token = f"{header_b64}.{payload_b64}.sig"

    h, p = decode_jwt(token)
    assert p is not None
    assert p["sub"] == "user123"
    assert p["role"] == "admin"


# ===== Basic Auth 编码测试 =====

def test_encode_basic_auth():
    """编码 Basic Auth 凭据。"""
    encoded = encode_basic_auth("admin", "secret")
    decoded = base64.b64decode(encoded).decode()
    assert decoded == "admin:secret"


def test_encode_basic_auth_special_chars():
    """包含特殊字符的用户名/密码也能正确编码。"""
    encoded = encode_basic_auth("user@domain", "p@ss:word!")
    decoded = base64.b64decode(encoded).decode()
    assert decoded == "user@domain:p@ss:word!"


# ===== AuthContext.auth_type 测试 =====

def test_auth_type_jwt():
    """JWT Bearer token 应识别为 jwt 类型。"""
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"
    raw = f"Authorization: Bearer {token}\n"
    auth = parse_headers(raw)
    assert auth.auth_type == "jwt"


def test_auth_type_jwt_cookie():
    """JWT + Cookie 组合。"""
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"
    raw = f"Authorization: Bearer {token}\nCookie: session=abc\n"
    auth = parse_headers(raw)
    assert auth.auth_type == "jwt+cookie"


def test_auth_type_cookie():
    """纯 Cookie 认证。"""
    raw = "Cookie: session=abc; token=xyz\n"
    auth = parse_headers(raw)
    assert auth.auth_type == "cookie"


def test_auth_type_basic():
    """Basic Auth 认证。"""
    encoded = base64.b64encode(b"admin:pass").decode()
    raw = f"Authorization: Basic {encoded}\n"
    auth = parse_headers(raw)
    assert auth.auth_type == "basic"


def test_auth_type_api_key():
    """API Key 认证。"""
    raw = "X-API-Key: sk-abc123\n"
    auth = parse_headers(raw)
    assert auth.auth_type == "api_key"


def test_auth_type_none():
    """无认证信息。"""
    from redteam.core.models import AuthContext
    assert AuthContext().auth_type == "none"


# ===== describe_auth 测试 =====

def test_describe_auth_jwt():
    """describe_auth 应包含 JWT 解码信息。"""
    import json
    payload = {"sub": "admin", "role": "admin", "exp": 9999999999}
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    token = f"{header_b64}.{payload_b64}.sig"
    raw = f"Authorization: Bearer {token}\n"
    auth = parse_headers(raw)

    desc = describe_auth(auth)
    assert "JWT" in desc
    assert "HS256" in desc
    assert "role" in desc
    assert "***" in desc  # sub 应被脱敏


def test_describe_auth_cookie():
    """describe_auth 应列出 cookie 信息。"""
    raw = "Cookie: session=abc; csrftoken=xyz\n"
    auth = parse_headers(raw)
    desc = describe_auth(auth)
    assert "Cookie" in desc
    assert "session" in desc
    assert "csrftoken" in desc


def test_describe_auth_basic():
    """describe_auth 应展示 Basic Auth 用户名和编码。"""
    encoded = base64.b64encode(b"admin:secret").decode()
    raw = f"Authorization: Basic {encoded}\n"
    auth = parse_headers(raw)
    desc = describe_auth(auth)
    assert "Basic Auth" in desc
    assert "admin" in desc


def test_describe_auth_none():
    """无认证时的输出。"""
    from redteam.core.models import AuthContext
    desc = describe_auth(AuthContext())
    assert "无认证信息" in desc


# ===== 凭据检测测试 =====

def test_detect_credential_headers_base64():
    """检测 Base64 编码的凭据。"""
    encoded = base64.b64encode(b"user:password123").decode()
    headers = {"X-Custom-Auth": encoded}
    result = _detect_credential_headers(headers)
    assert "X-Custom-Auth" in result
    assert "Base64" in result["X-Custom-Auth"]
    assert "user" in result["X-Custom-Auth"]
    assert "password123" not in result["X-Custom-Auth"]  # 密码应被遮蔽


def test_detect_credential_headers_none():
    """无凭据的请求头应返回空字典。"""
    headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    result = _detect_credential_headers(headers)
    assert result == {}


# ===== summarize 包含 auth_type =====

def test_summarize_includes_auth_type():
    """summarize 现在应包含 auth_type 字段。"""
    auth = parse_headers(SAMPLE)
    stats = summarize(auth)
    assert "auth_type" in stats
    assert stats["auth_type"] in ("jwt+cookie", "jwt+cookie+api_key")
    assert stats["cookies"] == 2
    assert stats["bearer"] == 1
