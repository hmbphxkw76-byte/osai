"""
===============================================================================
PyRIT Red Team — 攻击场景预设（Scenario Presets）
===============================================================================
将常见的认证/传输/格式组合封装为命名预设，消除 CLI 参数记忆负担。

⚠️ 注意: 本模块由 scenarios/__init__.py 懒加载。
         主入口请使用 targets/scenarios.py（已被 targets.factories 和 target_builder 引用）。

使用方式:
  CLI:  python main.py --scenario jwt-bearer --target-url https://...
  Code: from targets.scenarios import SCENARIO_PRESETS, build_custom_target, register_scenario

扩展模式（渗透场景零改动原则）:
  from targets.scenarios import register_scenario
  register_scenario("my-scenario", {
      "name": "My Custom Scenario",
      "api_format": "raw",
      "http_method": "POST",
  })

设计原则:
  - 每个场景是纯数据的 dict，不包含业务逻辑
  - CLI 参数始终可覆盖场景默认值（开闭原则）
  - requires 字段用于启动时校验，防止静默错误

Target 选型标准（SDK 优先，不重复造轮子）:
  openai/ollama → OpenAICompatibleTarget (openai SDK)
  gemini         → GeminiTarget (google-genai SDK)
  claude         → ClaudeTarget (anthropic SDK)
  raw            → CustomHttpChatTarget (仅非标准 API 兜底)
===============================================================================
"""
from __future__ import annotations

from typing import Optional

from rich.console import Console

from targets.http_target import CustomHttpChatTarget
from targets.openai_sdk_target import OpenAICompatibleTarget
from targets.gemini_target import GeminiTarget
from targets.claude_target import ClaudeTarget
from utils import DEFAULT_MODEL_NAME

console = Console()

# ── 场景预设定义 ──────────────────────────────────────────────────────────────

SCENARIO_PRESETS: dict = {
    "cookie-jwt-dual": {
        "name": "Cookie + JWT 双重认证",
        "description": "同时使用 Cookie Session 和 JWT Bearer Token 两种认证方式，"
                       "适配既有 Web Session 又需要 API Token 的内部应用",
        "api_format": "raw",
        "http_method": "POST",
        "content_type": "application/json",
        "verify_ssl": False,
        "requires": ["cookie", "jwt"],
    },
    "cookie-ua-spoof": {
        "name": "Cookie 认证 + 浏览器 UA 伪装",
        "description": "携带 Session Cookie 并使用 Chrome 浏览器 User-Agent 伪装，"
                       "绕过基于 UA 的 WAF/反爬检测",
        "api_format": "raw",
        "http_method": "POST",
        "content_type": "application/json",
        "verify_ssl": False,
        "browser_ua": True,
        "requires": ["cookie"],
    },
    "https-selfsigned-custom-header": {
        "name": "HTTPS 自签证书 + 自定义认证头",
        "description": "跳过 SSL 证书验证的同时使用自定义 HTTP 头认证"
                       "（如 X-API-Key, X-CSRF-Token 等），适配内网自签证书的内部应用",
        "api_format": "raw",
        "http_method": "POST",
        "content_type": "application/json",
        "verify_ssl": False,
        "requires": ["extra_headers"],
    },
    "get-recon": {
        "name": "GET 信息收集/探测",
        "description": "使用 GET 方法进行信息收集和端点探测，prompt 拼接为 URL query 参数，"
                       "适配搜索/查询类 GET API",
        "api_format": "raw",
        "http_method": "GET",
        "content_type": None,
        "verify_ssl": False,
    },
    "jwt-bearer": {
        "name": "JWT Bearer Token 认证",
        "description": "使用 JWT Token 作为 Bearer 认证（Authorization: Bearer <jwt>），"
                       "适配 RESTful API 的 JWT 认证场景",
        "api_format": "raw",
        "http_method": "POST",
        "content_type": "application/json",
        "verify_ssl": False,
        "requires": ["jwt"],
    },
    "form-cookie": {
        "name": "form-urlencoded POST + Cookie 认证",
        "description": "使用 application/x-www-form-urlencoded 编码 POST body，"
                       "同时携带 Cookie 认证，适配传统 Web 表单类 Chat API",
        "api_format": "raw",
        "http_method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "verify_ssl": False,
        "requires": ["cookie"],
    },
}


# ── 公共 API ──────────────────────────────────────────────────────────────────

def register_scenario(scenario_id: str, config: dict) -> None:
    """动态注册新场景预设（渗透场景零改动原则）。"""
    SCENARIO_PRESETS[scenario_id] = config
    console.print(f"[dim]📋 已注册场景预设: {scenario_id} ({config.get('name', 'unnamed')})[/dim]")


# ── Target 构建（场景合并 + 校验） ─────────────────────────────────────────────

def build_custom_target(
    endpoint: str,
    *,
    scenario: str = "",
    api_key: str = "",
    model: str = DEFAULT_MODEL_NAME,
    api_format: str = "openai",
    http_method: str = "POST",
    content_type: str = "application/json",
    verify_ssl: bool = False,
    cookie: str = "",
    jwt_token: str = "",
    user_agent: str = "",
    extra_headers: Optional[dict] = None,
) -> CustomHttpChatTarget | OpenAICompatibleTarget | GeminiTarget | ClaudeTarget:
    """根据场景预设 + CLI 覆盖参数构建 Target（SDK 优先，不重复造轮子）。

    优先级: CLI 显式参数 > 场景预设 > 函数默认值

    Target 选型:
      openai/ollama → OpenAICompatibleTarget (openai SDK)
      gemini         → GeminiTarget (google-genai SDK)
      claude         → ClaudeTarget (anthropic SDK)
      raw            → CustomHttpChatTarget (仅非标准 API 兜底)
    """
    extra_headers = dict(extra_headers or {})

    # ── 1. 加载场景预设 ──
    preset = SCENARIO_PRESETS.get(scenario) if scenario else None
    if scenario and not preset:
        available = ", ".join(SCENARIO_PRESETS.keys())
        raise ValueError(f"未知场景 '{scenario}'。可用场景: {available}")

    if preset:
        console.print(f"[bold cyan]🎬 场景预设: {preset['name']}[/bold cyan]")

    # ── 2. 合并参数: 预设为底，CLI 显式传入覆盖 ──
    effective = {
        "api_format": api_format,
        "http_method": http_method,
        "content_type": content_type,
        "verify_ssl": verify_ssl,
    }

    if preset:
        if api_format == "openai":
            effective["api_format"] = preset.get("api_format", api_format)
        if http_method == "POST":
            effective["http_method"] = preset.get("http_method", http_method)
        if content_type == "application/json":
            effective["content_type"] = preset.get("content_type", content_type)
        if not verify_ssl:
            effective["verify_ssl"] = preset.get("verify_ssl", verify_ssl)

    # ── 3. 组装 headers ──
    final_headers: dict = {}
    if preset and preset.get("browser_ua") and not user_agent:
        user_agent = CustomHttpChatTarget._BROWSER_HEADERS.get("User-Agent", "")
    final_headers.update(extra_headers)
    if cookie:
        existing_cookie = final_headers.get("Cookie", "")
        merged_cookie = f"{existing_cookie}; {cookie}".strip("; ")
        final_headers["Cookie"] = merged_cookie
    if user_agent:
        final_headers["User-Agent"] = user_agent
    if "Content-Type" not in final_headers and effective["content_type"]:
        final_headers["Content-Type"] = effective["content_type"]

    # ── 4. 场景约束校验 ──
    if preset and "requires" in preset:
        missing = _validate_requirements(preset, cookie, jwt_token, extra_headers)
        if missing:
            required_list = ", ".join(missing)
            console.print(
                f"[bold yellow]⚠️ 场景 '{preset['name']}' 需要以下参数但未提供: "
                f"{required_list}[/bold yellow]"
            )
            console.print(f"[dim]   提示: {_requirement_hints(missing)}[/dim]")

    # ── 5. SSL 协议校验 ──
    is_http = endpoint.lower().startswith("http://")
    if is_http:
        effective["verify_ssl"] = False

    # ── 6. 构建 Target（SDK 优先） ──
    scenario_name = preset["name"] if preset else "手动配置"

    # OpenAI 兼容格式 → OpenAI SDK
    if effective["api_format"] in ("openai", "ollama"):
        base_url = _to_openai_base_url(endpoint, effective["api_format"])
        ssl_status = "skip" if not effective["verify_ssl"] else "verify"
        proto = "HTTP" if endpoint.lower().startswith("http://") else "HTTPS"
        console.print(
            f"[bold magenta]🎯 攻击目标 (OpenAI SDK): {base_url} "
            f"({proto}, SSL={ssl_status}, 格式: {effective['api_format']}, "
            f"场景: {scenario_name})[/bold magenta]"
        )
        return OpenAICompatibleTarget(
            base_url=base_url,
            api_key=api_key,
            model=model,
            temperature=0.9,
            timeout=60,
            verify_ssl=effective["verify_ssl"],
            extra_headers=final_headers if final_headers else None,
        )

    # Gemini → Google Generative AI SDK
    if effective["api_format"] == "gemini":
        console.print(
            f"[bold magenta]🎯 攻击目标 (Gemini SDK): {model} "
            f"(场景: {scenario_name})[/bold magenta]"
        )
        return GeminiTarget(
            api_key=api_key,
            model=model,
            temperature=0.9,
            timeout=60,
        )

    # Claude → Anthropic SDK
    if effective["api_format"] == "claude":
        console.print(
            f"[bold magenta]🎯 攻击目标 (Claude SDK): {model} "
            f"(场景: {scenario_name})[/bold magenta]"
        )
        return ClaudeTarget(
            api_key=api_key,
            model=model,
            temperature=0.9,
            timeout=60,
            verify_ssl=effective["verify_ssl"],
        )

    # raw → CustomHttpChatTarget（仅非标准 API 兜底）
    target = CustomHttpChatTarget(
        endpoint=endpoint,
        api_key=api_key,
        model=model,
        temperature=0.9,
        timeout=60,
        verify_ssl=effective["verify_ssl"],
        api_format=effective["api_format"],
        extra_headers=final_headers if final_headers else None,
        content_type=effective["content_type"],
        http_method=effective["http_method"],
        jwt_token=jwt_token,
    )

    _log_target_summary(target, preset)
    return target


# ── 内部辅助 ──────────────────────────────────────────────────────────────────

def _validate_requirements(preset: dict, cookie: str, jwt_token: str, extra_headers: dict) -> list[str]:
    missing = []
    for req in preset.get("requires", []):
        if req == "cookie" and not cookie:
            if not extra_headers or "Cookie" not in extra_headers:
                missing.append("cookie (--target-cookie)")
        elif req == "jwt" and not jwt_token:
            missing.append("jwt (--target-jwt)")
        elif req == "extra_headers" and not extra_headers:
            missing.append("extra_headers (--target-extra-headers)")
    return missing


def _requirement_hints(missing: list[str]) -> str:
    hints = {
        "cookie": "--target-cookie 'session_id=abc; csrf=xyz'",
        "jwt": "--target-jwt 'eyJhbGciOi...'",
        "extra_headers": "--target-extra-headers '{\"X-API-Key\":\"sk-xxx\"}'",
    }
    return "; ".join(hints.get(m.split(" ")[0], m) for m in missing)


def _log_target_summary(target: CustomHttpChatTarget, preset: Optional[dict]) -> None:
    scenario_name = preset["name"] if preset else "手动配置"
    auth_methods = []
    if target._jwt_token:
        auth_methods.append("JWT")
    if target._api_key:
        auth_methods.append("API-Key")
    h = target._extra_headers or {}
    if "Cookie" in h:
        auth_methods.append("Cookie")
    if not auth_methods:
        auth_methods.append("无")

    ssl = "skip" if not target._verify_ssl else "verify"
    proto = "HTTP" if target._endpoint.lower().startswith("http://") else "HTTPS"

    console.print(
        f"[bold magenta]🎯 攻击目标: {target._endpoint} "
        f"({proto}, SSL={ssl}, 认证: {'+'.join(auth_methods)}, "
        f"格式: {target._api_format}, 方法: {target._http_method}, "
        f"场景: {scenario_name})[/bold magenta]"
    )


def _to_openai_base_url(raw_url: str, api_format: str) -> str:
    """将用户输入的 URL 标准化为 OpenAI 兼容 base_url（供 AsyncOpenAI 使用）。"""
    from urllib.parse import urlparse
    import re

    url = raw_url.rstrip("/")
    parsed = urlparse(url)

    if api_format == "ollama":
        base = f"{parsed.scheme}://{parsed.netloc}"
        return f"{base}/v1"

    if not url.endswith("/v1"):
        url = re.sub(r'/(chat/completions|completions)$', '', url)
        if not url.endswith("/v1"):
            url = url.rstrip("/") + "/v1"
    return url
