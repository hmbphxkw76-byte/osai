import base64
import os
import tempfile

from redteam.recon.auth_parse import (
    parse_headers, parse_headers_file, summarize,
    _is_cookie_string, _decode_basic_auth,
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
