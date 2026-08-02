"""Auth 模块单元测试 — Cookie 解析/按域过滤 + Provider 工厂

不依赖真实登录 / Playwright / 网络。
"""

import json

import pytest

from pipeline.auth.cookie_session import (
    _domain_matches,
    api_domain_from_endpoint,
    cookie_header_for,
    load_cookies,
    save_cookies,
)
from pipeline.auth.provider import (
    CookieFileProvider,
    NoAuthProvider,
    StaticKeyProvider,
    from_config,
)


# ---------------------------------------------------------------------------
# Cookie 加载 / 按域过滤
# ---------------------------------------------------------------------------
def _sample_browser_cookies():
    return [
        {"name": "session", "value": "abc123", "domain": ".syxy.ouchn.cn",
         "path": "/", "secure": True, "httpOnly": True, "expires": 9999999999},
        {"name": "token", "value": "xyz", "domain": "student.syxy.ouchn.cn",
         "path": "/", "secure": True, "httpOnly": False, "expires": 9999999999},
        {"name": "passport_sid", "value": "ppp", "domain": "passport.syxy.ouchn.cn",
         "path": "/", "secure": True, "httpOnly": True, "expires": 9999999999},
    ]


def test_load_json_cookies(tmp_path):
    f = tmp_path / "c.json"
    f.write_text(json.dumps(_sample_browser_cookies()), encoding="utf-8")
    cookies = load_cookies(str(f))
    assert len(cookies) == 3
    assert cookies[0]["name"] == "session"


def test_domain_matches():
    assert _domain_matches(".syxy.ouchn.cn", "student.syxy.ouchn.cn")
    assert _domain_matches("student.syxy.ouchn.cn", "student.syxy.ouchn.cn")
    assert not _domain_matches(".syxy.ouchn.cn", "other.com")
    assert not _domain_matches("passport.syxy.ouchn.cn", "student.syxy.ouchn.cn")


def test_cookie_header_for_filters_by_domain():
    cookies = _sample_browser_cookies()
    header = cookie_header_for(cookies, "student.syxy.ouchn.cn")
    # 只含 .syxy.ouchn.cn 与 student.syxy.ouchn.cn，不应含 passport 域
    assert "session=abc123" in header
    assert "token=xyz" in header
    assert "passport_sid" not in header


def test_save_cookies_writes_file(tmp_path):
    f = tmp_path / "out.json"
    save_cookies(_sample_browser_cookies(), str(f))
    assert f.exists()
    loaded = json.loads(f.read_text(encoding="utf-8"))
    assert len(loaded) == 3


def test_api_domain_from_endpoint():
    assert api_domain_from_endpoint("https://student.syxy.ouchn.cn/openai/v1") == \
        "student.syxy.ouchn.cn"


# ---------------------------------------------------------------------------
# AuthProvider 工厂
# ---------------------------------------------------------------------------
def test_from_config_none():
    p = from_config({"type": "none"}, {"endpoint": "x", "model": "m"})
    assert isinstance(p, NoAuthProvider)
    assert p.get_request_headers() == {}


def test_from_config_static_key():
    p = from_config({"type": "static"}, {"endpoint": "x", "model": "m", "api_key": "sk-123"})
    assert isinstance(p, StaticKeyProvider)
    assert p.get_request_headers() == {"Authorization": "Bearer sk-123"}


def test_from_config_static_bearer_passthrough():
    p = StaticKeyProvider("bearer mytoken")
    assert p.get_request_headers() == {"Authorization": "bearer mytoken"}


def test_from_config_cookie_file(tmp_path):
    f = tmp_path / "c.json"
    f.write_text(json.dumps(_sample_browser_cookies()), encoding="utf-8")
    p = from_config(
        {"type": "cookie_file", "cookie_source": str(f),
         "cookie_domain": "student.syxy.ouchn.cn"},
        {"endpoint": "https://student.syxy.ouchn.cn/openai/v1", "model": "m"},
    )
    assert isinstance(p, CookieFileProvider)
    h = p.get_request_headers()
    assert "Cookie" in h
    assert "passport_sid" not in h["Cookie"]


def test_from_config_cookie_source_derived_from_domain():
    # cookie_source 留空时按 cookie_domain 自动推导 sessions/<domain>.json
    p = from_config(
        {"type": "cookie_file", "cookie_domain": "student.syxy.ouchn.cn"},
        {"endpoint": "https://student.syxy.ouchn.cn/openai/v1", "model": "m"},
    )
    assert isinstance(p, CookieFileProvider)
    assert p.cookie_source == "sessions/student_syxy_ouchn_cn.json"


def test_from_config_missing_cookie_source_and_domain_raises():
    with pytest.raises(ValueError):
        from_config({"type": "cookie_file"}, {"endpoint": "x", "model": "m"})
