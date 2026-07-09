"""
===============================================================================
PyRIT Config Center — Web 认证捕获与复用模块
===============================================================================
解决场景：
  1. 目标首页是登录页（如 "AI 安全训练靶机"），需要用户名/密码登录。
  2. 登录成功后，服务端下发 Cookie / JWT / API Key。
  3. 后续端点探测需要携带这些认证信息才能访问。

能力：
  ✅ 自动检测目标是否需要认证（401/403/登录表单/重定向到登录页）
  ✅ 自动解析 HTML 登录表单，支持用户自定义字段名
  ✅ 提交登录并捕获 Set-Cookie、响应中的 JWT/API Key
  ✅ 手动录入 Cookie / JWT / API Key 并持久化
  ✅ 自动保存到 configs/tokens/ 目录，供后续探测读取最新值
  ✅ 为后续探测构造 Authorization / Cookie 请求头

安全提示：
  - 本模块不执行任何暴力破解；账号密码由用户在 Web 界面主动填写。
  - 所有凭证仅保存在本地 configs/tokens/，不上传。
===============================================================================
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from utils.http_transport import create_http_client
from utils.token_manager import inspect_token

logger = logging.getLogger(__name__)

_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent.parent
_TOKENS_DIR = _PROJECT_ROOT / "configs" / "tokens"

# 常见的登录表单字段名
_USERNAME_CANDIDATES = ["username", "user", "email", "login", "name", "account"]
_PASSWORD_CANDIDATES = ["password", "passwd", "pwd", "pass"]
_CSRF_CANDIDATES = ["csrf_token", "csrf", "_csrf", "_token", "authenticity_token", "xsrf_token"]

# 常见登录路径（当表单未显式提供 action 时回退）
_COMMON_LOGIN_PATHS = ["/login", "/auth/login", "/api/auth/login", "/signin", "/auth/signin"]

# JWT 与 API Key 正则
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")
_API_KEY_RE = re.compile(
    r"\b(?:sk-|gsk-|ak-|bk-|rk-|pk-|NK-|AKID|ghp_|gho_|glpat-|live_|twilio_|xai-)[A-Za-z0-9_\-]{8,}\b"
)



# ═══════════════════════════════════════════════════════════════════════════
# 数据模型
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class LoginForm:
    """解析出的登录表单信息。"""
    action: str = ""
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    found: bool = False
    raw_html: str = ""


@dataclass
class AuthSnapshot:
    """一次捕获/保存的认证信息快照。"""
    target_url: str = ""
    requires_auth: bool = False
    auth_type: str = "none"          # none | cookie | jwt | api_key | session | mixed
    cookie_string: str = ""          # 可直接放入 Cookie 头的字符串
    jwt_token: str = ""              # JWT
    api_key: str = ""                # API Key / Bearer Token
    username: str = ""               # 仅记录，不保存密码
    captured_at: str = ""            # ISO 8601
    source: str = ""                 # login | manual
    extra_headers: dict = field(default_factory=dict)

    def to_headers(self) -> dict[str, str]:
        """根据快照构造请求头。"""
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.jwt_token and not self.api_key:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        if self.cookie_string:
            headers["Cookie"] = self.cookie_string
        headers.update(self.extra_headers)
        return headers


# ═══════════════════════════════════════════════════════════════════════════
# 文件持久化
# ═══════════════════════════════════════════════════════════════════════════

def _ensure_tokens_dir() -> Path:
    _TOKENS_DIR.mkdir(parents=True, exist_ok=True)
    return _TOKENS_DIR


def _token_path(name: str) -> Path:
    return _ensure_tokens_dir() / name


def save_auth_snapshot(snapshot: AuthSnapshot) -> dict:
    """将认证快照保存到 configs/tokens/ 下多个文件。

    会先清空旧的认证 token 文件，避免不同目标/不同凭据混用。

    Returns:
        {"ok": bool, "saved": [文件名列表], "error": str|None}
    """
    try:
        _ensure_tokens_dir()
        saved: list[str] = []

        # 先清空旧 token 文件，避免旧凭据干扰
        for name in ("cookie.txt", "jwt.txt", "api_key.txt"):
            p = _token_path(name)
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

        # 结构化元数据
        meta = {

            "target_url": snapshot.target_url,
            "requires_auth": snapshot.requires_auth,
            "auth_type": snapshot.auth_type,
            "username": snapshot.username,
            "captured_at": snapshot.captured_at,
            "source": snapshot.source,
            "extra_headers": snapshot.extra_headers,
        }
        meta_path = _token_path("auth_state.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        saved.append("auth_state.json")

        if snapshot.cookie_string:
            with open(_token_path("cookie.txt"), "w", encoding="utf-8") as f:
                f.write(snapshot.cookie_string)
            saved.append("cookie.txt")

        if snapshot.jwt_token:
            with open(_token_path("jwt.txt"), "w", encoding="utf-8") as f:
                f.write(snapshot.jwt_token)
            saved.append("jwt.txt")

        if snapshot.api_key:
            with open(_token_path("api_key.txt"), "w", encoding="utf-8") as f:
                f.write(snapshot.api_key)
            saved.append("api_key.txt")

        logger.info(f"认证快照已保存: {saved}")
        return {"ok": True, "saved": saved, "error": None}
    except Exception as e:
        logger.exception("保存认证快照失败")
        return {"ok": False, "saved": [], "error": str(e)[:400]}


def load_auth_snapshot() -> AuthSnapshot:
    """从 configs/tokens/ 读取最新认证快照。"""
    snapshot = AuthSnapshot()
    meta_path = _token_path("auth_state.json")

    if meta_path.exists():
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            snapshot.target_url = meta.get("target_url", "")
            snapshot.requires_auth = meta.get("requires_auth", False)
            snapshot.auth_type = meta.get("auth_type", "none")
            snapshot.username = meta.get("username", "")
            snapshot.captured_at = meta.get("captured_at", "")
            snapshot.source = meta.get("source", "")
            snapshot.extra_headers = meta.get("extra_headers", {}) or {}
        except Exception:
            pass

    cookie_path = _token_path("cookie.txt")
    if cookie_path.exists():
        snapshot.cookie_string = cookie_path.read_text(encoding="utf-8").strip()

    jwt_path = _token_path("jwt.txt")
    if jwt_path.exists():
        snapshot.jwt_token = jwt_path.read_text(encoding="utf-8").strip()

    api_key_path = _token_path("api_key.txt")
    if api_key_path.exists():
        snapshot.api_key = api_key_path.read_text(encoding="utf-8").strip()

    return snapshot


def clear_auth_snapshot() -> dict:
    """清空已保存的认证快照。"""
    removed: list[str] = []
    for name in ("auth_state.json", "cookie.txt", "jwt.txt", "api_key.txt"):
        p = _token_path(name)
        if p.exists():
            try:
                p.unlink()
                removed.append(name)
            except Exception:
                pass
    return {"ok": True, "removed": removed}


# ═══════════════════════════════════════════════════════════════════════════
# 认证检测
# ═══════════════════════════════════════════════════════════════════════════

async def detect_auth_requirement(
    url: str,
    verify_ssl: bool = False,
    timeout: float = 10.0,
) -> dict:
    """检测目标 URL 是否需要认证。

    Returns:
        {
          "requires_auth": bool,
          "auth_type": str,        # none | form | basic | bearer | unknown
          "status_code": int,
          "redirect_url": str,
          "login_form": {...},
          "hints": [str],
          "error": str|None,
        }
    """
    try:
        async with create_http_client(verify_ssl=verify_ssl, timeout=timeout) as client:
            resp = await client.get(url, follow_redirects=True)
    except Exception as e:
        return {"requires_auth": False, "auth_type": "unknown", "status_code": 0,
                "redirect_url": "", "login_form": None, "hints": [], "error": str(e)[:400]}

    status = resp.status_code
    final_url = str(resp.url)
    text = resp.text or ""
    lower_text = text.lower()
    hints: list[str] = []

    # 1. HTTP 401/403 直接表示需要认证
    if status == 401:
        return _build_auth_required(final_url, "basic", status, hints=["HTTP 401，需要认证"])
    if status == 403:
        hints.append("HTTP 403，可能被禁止或需要认证")

    # 2. 重定向到登录页
    parsed_final = urlparse(final_url)
    path_lower = parsed_final.path.lower()
    if "/login" in path_lower or "/signin" in path_lower or "/auth" in path_lower:
        hints.append(f"重定向到登录路径: {parsed_final.path}")
        return _build_auth_required(final_url, "form", status, hints=hints)

    # 3. HTML 登录表单检测
    form = _parse_login_form(text, final_url)
    if form.found:
        hints.append(f"检测到登录表单 (action={form.action}, method={form.method})")
        return _build_auth_required(final_url, "form", status, login_form=form, hints=hints)

    # 4. 页面文本关键词
    login_keywords = ["登录", "login", "用户名", "username", "密码", "password", "账号"]
    if any(kw in lower_text for kw in login_keywords) and "password" in lower_text:
        hints.append("页面文本包含登录相关关键词")
        return _build_auth_required(final_url, "form", status, hints=hints)

    # 5. 默认认为无需认证
    return {
        "requires_auth": False,
        "auth_type": "none",
        "status_code": status,
        "redirect_url": final_url,
        "login_form": None,
        "hints": ["未检测到登录页或 401/403，目标可能无需认证"],
        "error": None,
    }


def _build_auth_required(
    final_url: str,
    auth_type: str,
    status_code: int,
    login_form: Optional[LoginForm] = None,
    hints: Optional[list[str]] = None,
) -> dict:
    return {
        "requires_auth": True,
        "auth_type": auth_type,
        "status_code": status_code,
        "redirect_url": final_url,
        "login_form": {
            "found": login_form.found if login_form else False,
            "action": login_form.action if login_form else "",
            "method": login_form.method if login_form else "POST",
            "username_field": login_form.username_field if login_form else "username",
            "password_field": login_form.password_field if login_form else "password",
        },
        "hints": hints or ["目标需要认证"],
        "error": None,
    }


# ═══════════════════════════════════════════════════════════════════════════
# HTML 表单解析
# ═══════════════════════════════════════════════════════════════════════════

def _parse_login_form(html: str, base_url: str) -> LoginForm:
    """从 HTML 中解析登录表单。优先使用 lxml，回退正则。"""
    try:
        import lxml.html as lh
        doc = lh.fromstring(html)
        forms = doc.forms
        for form in forms:
            fields = {f.name: f for f in form.fields if f.name}
            has_user = any(c in fields for c in _USERNAME_CANDIDATES)
            has_pass = any(c in fields for c in _PASSWORD_CANDIDATES)
            if has_pass or (has_user and "pass" in " ".join(fields.keys()).lower()):
                action = urljoin(base_url, form.action or "")
                method = (form.method or "POST").upper()
                user_field = next((c for c in _USERNAME_CANDIDATES if c in fields), "username")
                pass_field = next((c for c in _PASSWORD_CANDIDATES if c in fields), "password")
                return LoginForm(
                    action=action,
                    method=method,
                    username_field=user_field,
                    password_field=pass_field,
                    found=True,
                    raw_html=html[:200],
                )
    except Exception:
        pass

    # 正则回退：找包含 password input 的 form
    form_re = re.compile(
        r"<form[^>]*?(?:id|class|action)=[^>]*?>(.*?)</form>",
        re.IGNORECASE | re.DOTALL,
    )
    input_re = re.compile(r"<input[^>]*name=[\"']([^\"']+)[\"']", re.IGNORECASE)
    action_re = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"']", re.IGNORECASE)
    method_re = re.compile(r"<form[^>]*method=[\"']([^\"']*)[\"']", re.IGNORECASE)

    for m in form_re.finditer(html):
        form_html = m.group(1)
        if re.search(r"<input[^>]*type=[\"']password[\"']", form_html, re.IGNORECASE):
            action = action_re.search(m.group(0))
            action_url = urljoin(base_url, action.group(1) if action else "")
            method = method_re.search(m.group(0))
            method_str = (method.group(1) if method else "POST").upper()
            inputs = input_re.findall(form_html)
            user_field = next((c for c in _USERNAME_CANDIDATES if c in inputs), "username")
            pass_field = next((c for c in _PASSWORD_CANDIDATES if c in inputs), "password")
            return LoginForm(
                action=action_url,
                method=method_str,
                username_field=user_field,
                password_field=pass_field,
                found=True,
                raw_html=html[:200],
            )

    return LoginForm()


# ═══════════════════════════════════════════════════════════════════════════
# 登录执行与凭证捕获
# ═══════════════════════════════════════════════════════════════════════════

async def perform_login(
    url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    login_url: str = "",
    login_method: str = "POST",
    verify_ssl: bool = False,
    timeout: float = 15.0,
) -> dict:
    """执行登录并捕获 Cookie / JWT / API Key。

    Args:
        url: 目标首页/登录页 URL（用于解析表单 action）
        username/password: 用户提供的凭据（不保存密码）
        username_field/password_field: 表单字段名
        login_url: 显式指定的登录提交地址，为空则自动探测
        login_method: 登录请求方法

    Returns:
        {"ok": bool, "snapshot": AuthSnapshot dict, "error": str|None}
    """
    try:
        async with create_http_client(verify_ssl=verify_ssl, timeout=timeout) as client:
            # 获取登录页，解析表单
            home_resp = await client.get(url, follow_redirects=True)
            base_url = str(home_resp.url)
            form = _parse_login_form(home_resp.text, base_url)

            # 确定登录提交地址
            target_login_url = login_url or form.action or _guess_login_url(base_url)
            if not target_login_url:
                return {"ok": False, "snapshot": None, "error": "无法确定登录提交地址"}

            method = login_method or form.method or "POST"
            data = {
                username_field or "username": username,
                password_field or "password": password,
            }

            # 提交登录
            if method.upper() == "GET":
                login_resp = await client.get(target_login_url, params=data, follow_redirects=True)
            else:
                login_resp = await client.post(target_login_url, data=data, follow_redirects=True)

            # 判断登录是否成功：2xx 且没有返回登录表单
            success = login_resp.status_code < 400 and not _parse_login_form(login_resp.text, str(login_resp.url)).found

            # 捕获 cookies
            cookies = _extract_cookie_string(login_resp)

            # 提取响应中的 token
            tokens = _extract_tokens_from_response(login_resp)

            from datetime import datetime, timezone
            snapshot = AuthSnapshot(
                target_url=url,
                requires_auth=True,
                auth_type=_classify_auth_type(cookies, tokens),
                cookie_string=cookies,
                jwt_token=tokens.get("jwt", ""),
                api_key=tokens.get("api_key", ""),
                username=username,
                captured_at=datetime.now(timezone.utc).isoformat(),
                source="login",
            )

            result = {"ok": success, "snapshot": snapshot, "error": None}
            if not success:
                result["error"] = (
                    f"登录可能失败（状态码 {login_resp.status_code}），"
                    f"请检查用户名/密码或登录地址"
                )
            return result
    except Exception as e:
        logger.exception("执行登录失败")
        return {"ok": False, "snapshot": None, "error": str(e)[:400]}


def _guess_login_url(base_url: str) -> str:
    """根据 base_url 猜测常见登录地址。"""
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for path in _COMMON_LOGIN_PATHS:
        candidate = urljoin(root + "/", path)
        # 这里只是返回第一个候选；实际调用方可在探测中逐一尝试
        return candidate
    return ""


def _extract_cookie_string(resp: httpx.Response) -> str:
    """从响应中提取 Cookie 字符串。"""
    cookies = resp.headers.get_list("set-cookie")
    if not cookies:
        return ""
    # 取 name=value 部分
    parts = []
    for c in cookies:
        # Set-Cookie 格式: name=value; Path=...; HttpOnly
        kv = c.split(";")[0].strip()
        if kv and "=" in kv:
            parts.append(kv)
    return "; ".join(parts)


def _extract_tokens_from_response(resp: httpx.Response) -> dict[str, str]:
    """从响应头/体中提取 JWT 和 API Key。"""
    text = resp.text or ""
    headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    combined = text + "\n" + headers_text

    tokens: dict[str, str] = {}

    # JWT
    jwt_match = _JWT_RE.search(combined)
    if jwt_match:
        tokens["jwt"] = jwt_match.group(0)

    # API Key（仅在不是 JWT 时记录）
    if not tokens.get("jwt"):
        ak_match = _API_KEY_RE.search(combined)
        if ak_match:
            tokens["api_key"] = ak_match.group(0)

    return tokens


def _classify_auth_type(cookies: str, tokens: dict[str, str]) -> str:
    has_cookie = bool(cookies)
    has_jwt = bool(tokens.get("jwt"))
    has_api_key = bool(tokens.get("api_key"))
    if has_cookie and (has_jwt or has_api_key):
        return "mixed"
    if has_cookie:
        return "cookie"
    if has_jwt:
        return "jwt"
    if has_api_key:
        return "api_key"
    return "session"


# ═══════════════════════════════════════════════════════════════════════════
# 手动保存与状态查询
# ═══════════════════════════════════════════════════════════════════════════

def save_manual_auth(
    target_url: str,
    cookie: str = "",
    jwt: str = "",
    api_key: str = "",
    extra_headers: Optional[dict] = None,
) -> dict:
    """手动保存用户提供的认证信息。"""
    from datetime import datetime, timezone
    snapshot = AuthSnapshot(
        target_url=target_url,
        requires_auth=True,
        auth_type=_classify_auth_type(cookie, {"jwt": jwt, "api_key": api_key}),
        cookie_string=cookie.strip(),
        jwt_token=jwt.strip(),
        api_key=api_key.strip(),
        captured_at=datetime.now(timezone.utc).isoformat(),
        source="manual",
        extra_headers=extra_headers or {},
    )
    return save_auth_snapshot(snapshot)


def get_auth_state() -> dict:
    """返回当前认证状态，供 Web 端展示。

    出于安全考虑，**不返回**凭证原文，避免不必要的泄露。
    如需原文（用于前端自动回填），请使用 :func:`get_latest_credentials`。
    """
    snapshot = load_auth_snapshot()
    jwt_info = {}
    if snapshot.jwt_token:
        info = inspect_token(snapshot.jwt_token)
        jwt_info = {
            "valid": info.is_valid,
            "expired": info.is_expired,
            "summary": info.summary,
            "subject": info.subject,
            "expires_at": info.expires_at_str,
        }
    return {
        "has_auth": bool(snapshot.cookie_string or snapshot.jwt_token or snapshot.api_key),
        "target_url": snapshot.target_url,
        "auth_type": snapshot.auth_type,
        "cookie_present": bool(snapshot.cookie_string),
        "jwt_present": bool(snapshot.jwt_token),
        "api_key_present": bool(snapshot.api_key),
        "jwt_info": jwt_info,
        "captured_at": snapshot.captured_at,
        "source": snapshot.source,
    }


def get_latest_credentials() -> dict:
    """返回 ``configs/tokens/`` 下最新保存的 Cookie / JWT / API Key 原文。

    前端在打开"步骤 2 认证配置"时调用此接口，自动回填输入框，避免用户每次都
    重复粘贴。若文件不存在或为空，对应字段返回空字符串，前端保持原样
    （显示 placeholder，由用户主动填写）。
    """
    snapshot = load_auth_snapshot()
    return {
        "has_auth": bool(snapshot.cookie_string or snapshot.jwt_token or snapshot.api_key),
        "cookie": snapshot.cookie_string or "",
        "jwt": snapshot.jwt_token or "",
        "api_key": snapshot.api_key or "",
        "captured_at": snapshot.captured_at,
        "source": snapshot.source,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 验证已保存的认证信息
# ═══════════════════════════════════════════════════════════════════════════

async def verify_saved_auth(
    target_url: str,
    verify_ssl: bool = False,
    timeout: float = 10.0,
) -> dict:
    """用已保存的认证信息主动访问目标，验证「程序能否正常读取并通过认证」。

    策略：
      1. 先做一次"无认证"请求，记录状态码 / 是否重定向到登录 / 响应体是否含登录表单
      2. 用已保存的 Cookie / JWT / API Key 注入请求头，再做一次"带认证"请求
      3. 对比两次结果，给出明确结论：
         - 状态码从 401/403 → 200/2xx：✅ 认证生效
         - 仍 401/403 或仍被重定向到登录：❌ 认证无效
         - 目标本身无需认证（两次都 200）：⚠️ 无需认证也能访问，认证值可能是多余的

    Returns:
        {
          "ok": bool,                     # 是否有任何已保存的认证信息
          "has_auth": bool,               # 是否有 Cookie/JWT/API Key
          "auth_type": str,
          "target_url": str,
          "headers_used": {...},          # 实际注入的请求头（值会被截断以防泄露）
          "no_auth": {                    # 无认证请求结果
              "status_code": int,
              "redirected_to_login": bool,
              "has_login_form": bool,
              "content_length": int,
              "final_url": str,
          },
          "with_auth": {                  # 带已保存认证请求结果
              "status_code": int,
              "redirected_to_login": bool,
              "has_login_form": bool,
              "content_length": int,
              "final_url": str,
          },
          "verdict": str,                 # pass | fail | no_auth_needed | no_target
          "verdict_label": str,           # 中文结论
          "suggestion": str,              # 修复建议
          "error": str|None,
        }
    """
    try:
        snapshot = load_auth_snapshot()

        # 1. 没有任何已保存认证
        if not (snapshot.cookie_string or snapshot.jwt_token or snapshot.api_key):
            return {
                "ok": False,
                "has_auth": False,
                "auth_type": snapshot.auth_type,
                "target_url": target_url or snapshot.target_url,
                "headers_used": {},
                "no_auth": None,
                "with_auth": None,
                "verdict": "no_auth",
                "verdict_label": "⚠️ 尚未保存任何认证信息",
                "suggestion": "请先在上方填写 Cookie / JWT / API Key 后保存，再点击验证。",
                "error": None,
            }

        # 2. 没有目标 URL
        if not target_url:
            target_url = snapshot.target_url
        if not target_url:
            return {
                "ok": False,
                "has_auth": True,
                "auth_type": snapshot.auth_type,
                "target_url": "",
                "headers_used": {},
                "no_auth": None,
                "with_auth": None,
                "verdict": "no_target",
                "verdict_label": "⚠️ 未指定验证目标 URL",
                "suggestion": "请先在「步骤 1」或本步骤填写目标 URL。",
                "error": None,
            }

        # 构造完整请求头（值会被截断展示）
        full_headers = snapshot.to_headers()
        display_headers = {
            k: (v[:20] + "…(len=" + str(len(v)) + ")") if len(v) > 20 else v
            for k, v in full_headers.items()
        }

        # 3. 发起两次请求对比
        async with create_http_client(verify_ssl=verify_ssl, timeout=timeout) as client:
            # (a) 无认证
            try:
                r1 = await client.get(target_url, follow_redirects=True)
                no_auth = _summarize_response(r1)
            except Exception as e:
                no_auth = {"error": str(e)[:300]}

            # (b) 带已保存认证
            try:
                r2 = await client.get(target_url, headers=full_headers, follow_redirects=True)
                with_auth = _summarize_response(r2)
            except Exception as e:
                with_auth = {"error": str(e)[:300]}

        # 4. 给出结论
        verdict, verdict_label, suggestion = _judge_verdict(no_auth, with_auth)

        return {
            "ok": True,
            "has_auth": True,
            "auth_type": snapshot.auth_type,
            "target_url": target_url,
            "headers_used": display_headers,
            "no_auth": no_auth,
            "with_auth": with_auth,
            "verdict": verdict,
            "verdict_label": verdict_label,
            "suggestion": suggestion,
            "error": None,
        }
    except Exception as e:
        logger.exception("验证已保存认证失败")
        return {"ok": False, "error": str(e)[:400]}


def _summarize_response(resp) -> dict:
    """从 httpx.Response 提取关键字段。"""
    text = resp.text or ""
    final_url = str(resp.url)
    path_lower = urlparse(final_url).path.lower()
    return {
        "status_code": resp.status_code,
        "redirected_to_login": ("/login" in path_lower or "/signin" in path_lower),
        "has_login_form": _parse_login_form(text, final_url).found,
        "content_length": len(text),
        "final_url": final_url,
    }


def _judge_verdict(no_auth: dict, with_auth: dict) -> tuple[str, str, str]:
    """根据两次请求结果判定认证是否有效。"""
    # 异常情况
    if no_auth and "error" in no_auth:
        return "fail", "❌ 访问目标失败（无认证请求异常）", \
               f"网络或目标问题: {no_auth.get('error','')[:200]}"
    if with_auth and "error" in with_auth:
        return "fail", "❌ 携带认证后访问失败", \
               f"带认证请求异常: {with_auth.get('error','')[:200]}，" \
               f"可能是认证值被服务端拒绝。请检查 Cookie/JWT/API Key 是否正确。"

    s1 = no_auth.get("status_code", 0) if no_auth else 0
    s2 = with_auth.get("status_code", 0) if with_auth else 0
    redir1 = no_auth.get("redirected_to_login", False) if no_auth else False
    redir2 = with_auth.get("redirected_to_login", False) if with_auth else False
    form1 = no_auth.get("has_login_form", False) if no_auth else False
    form2 = with_auth.get("has_login_form", False) if with_auth else False
    len1 = no_auth.get("content_length", 0) if no_auth else 0
    len2 = with_auth.get("content_length", 0) if with_auth else 0

    # 目标本身可能无需认证
    if s1 < 400 and s2 < 400 and not redir1 and not form1 and not redir2 and not form2:
        if abs(len2 - len1) < 50:
            return "no_auth_needed", "⚠️ 目标无需认证即可访问（两次结果几乎一致）", \
                   "说明目标当前页面是公开的，你保存的认证值可能用不到。" \
                   "如要验证受保护端点，请尝试在 URL 后加受保护路径（如 /api/users、/admin）后重新验证。"
        else:
            return "pass", "✅ 认证信息已生效（响应内容发生变化）", \
                   "带认证后能正确访问目标，且响应与无认证不同，说明程序可正常读取并使用你保存的认证。"

    # 带认证后从失败变成功
    failed_codes = {401, 403}
    if (s1 in failed_codes or redir1 or form1) and s2 < 400 and not redir2 and not form2:
        return "pass", \
               f"✅ 认证信息已生效（{s1} → {s2}）", \
               f"无认证时返回 {s1}/登录页，携带保存的认证后正常返回 {s2}，" \
               f"程序可正常读取并使用你保存的 Cookie/JWT/API Key。"

    # 仍失败
    if s2 in failed_codes or redir2 or form2:
        suggestion = (
            f"带认证请求仍返回 {s2}。"
            f"可能原因：① Cookie 已过期或字段名拼写错误；"
            f"② JWT 格式不合法或已失效；"
            f"③ API Key 不匹配；"
            f"④ 目标实际需要账号密码登录（非 Cookie/JWT/API Key）。"
            f"建议重新抓包获取最新值，或切换到「账号密码登录」模式。"
        )
        return "fail", f"❌ 认证未生效（仍返回 {s2}）", suggestion

    # 其他情况
    return "partial", f"⚠️ 部分生效（{s1} → {s2}）", \
           f"请人工对比两次响应内容判断是否正常。建议在浏览器中直接粘贴 Cookie/JWT/API Key 验证。"


# ═══════════════════════════════════════════════════════════════════════════
# 为探测提供请求头
# ═══════════════════════════════════════════════════════════════════════════

def get_auth_headers_for_probe() -> dict[str, str]:
    """供后续探测自动读取最新认证信息。"""
    snapshot = load_auth_snapshot()
    return snapshot.to_headers()
