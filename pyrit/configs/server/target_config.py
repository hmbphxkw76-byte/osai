"""
===============================================================================
Config Center — Web 端目标配置（Target Config）后端逻辑
===============================================================================
为 Web GUI 提供：
  1. AI 应用端点枚举（复用 targets.model_probe._discover_endpoints）
  2. 通过官方 SDK 测试连接（OpenAI / Ollama / Gemini / Claude）
  3. 读取/写入 shared.env 的 6 个核心变量

设计原则：
  - 复用既有 targets/ 模块，不重复实现探测逻辑
  - SDK 直接调用：openai / google.genai / anthropic
  - 所有持久化只落 configs/shared.env，与现有代码路径一致
===============================================================================
"""
from __future__ import annotations

import logging
from dataclasses import asdict
from pathlib import Path

from utils.target_url import (
    normalize_target_url,
    derive_test_base_url,
    validate_target_url,
)
from utils.http_transport import create_http_client

# 延迟导入以避免触发 targets.__init__ 的 SDK 依赖链
# from targets.model_probe import _discover_endpoints, _normalize_base_url

logger = logging.getLogger(__name__)


# ── 端点枚举 ────────────────────────────────────────────────────────────────

async def enumerate_ai_app_endpoints(
    base_url: str,
    verify_ssl: bool = False,
    timeout: float = 5.0,
    api_key: str = "",
    cookies: str = "",
    extra_headers: dict[str, str] | None = None,
    api_type: str | None = None,
) -> dict:
    """枚举 AI 应用常见端点，返回结构化结果供 Web UI 展示。

    Args:
        api_key: 可选认证令牌，部分 Web AI 应用首页/API 需要认证才返回有效信息。
        cookies: 可选 Cookie 字符串（如 lab_session=xxx）。
        extra_headers: 额外请求头，与 api_key/cookies 合并后发送。
        api_type: 已知 API 类型（如 openai/ollama），来自探测缓存。传入后优先探测对应路径。

    Returns:
        {
            "ok": bool,
            "endpoints": [DiscoveredEndpoint dict, ...],
            "summary": dict,
            "error": str | None,
        }
    """
    try:
        from targets.model_probe import _discover_endpoints  # noqa: E402 — 延迟导入
        normalized = normalize_target_url(base_url)

        auth_headers: dict[str, str] = dict(extra_headers) if extra_headers else {}
        if api_key:
            auth_headers["Authorization"] = f"Bearer {api_key}"
        if cookies:
            auth_headers["Cookie"] = cookies

        discovered, summary = await _discover_endpoints(
            normalized.full_url,
            verify_ssl=verify_ssl or normalized.verify_ssl,
            timeout=timeout,
            initial_concurrency=3,
            api_key=api_key,
            extra_auth_headers=auth_headers if auth_headers else None,
            api_type=api_type,
        )
        return {
            "ok": True,
            "endpoints": [_endpoint_to_dict(e) for e in discovered],
            "summary": summary,
            "error": None,
        }
    except Exception as e:
        logger.exception("端点枚举失败")
        return {"ok": False, "endpoints": [], "summary": {}, "error": str(e)[:400]}



# ── API Key 侦察 ──────────────────────────────────────────────────────────────

async def scan_app_secrets(
    base_url: str,
    verify_ssl: bool = False,
    timeout: float = 20.0,
    api_key: str = "",
    do_verify: bool = True,
    cookies: str = "",
    extra_headers: dict[str, str] | None = None,
) -> dict:
    """一站式 API Key 侦察：获取首页 → 解析 JS → 扫描密钥 → 验证凭证。

    Args:
        base_url: 目标根 URL
        verify_ssl: SSL 验证
        timeout: 总超时
        api_key: 可选认证头
        do_verify: 是否对发现的凭据执行远程验证（TruffleHog 核心功能）
        cookies: 可选 Cookie 字符串。
        extra_headers: 额外请求头。

    Returns:
        {"ok": bool, "findings": [dict, ...], "summary": dict, "error": str|None}
    """
    try:
        from utils.secret_finder import run_secret_recon  # noqa: E402 延迟导入
        normalized = normalize_target_url(base_url)

        headers: dict[str, str] = dict(extra_headers) if extra_headers else {}
        if cookies:
            headers["Cookie"] = cookies

        result = await run_secret_recon(
            normalized.full_url,
            verify_ssl=verify_ssl or normalized.verify_ssl,
            timeout=timeout,
            api_key=api_key,
            do_verify=do_verify,
            extra_headers=headers if headers else None,
        )
        return result
    except ImportError as e:
        return {"ok": False, "findings": [], "summary": {}, "error": f"模块不可用: {e}"}
    except Exception as e:
        logger.exception("API Key 侦察失败")
        return {"ok": False, "findings": [], "summary": {}, "error": str(e)[:400]}



def _endpoint_to_dict(e) -> dict:
    """DiscoveredEndpoint dataclass → JSON 安全 dict。"""
    data = asdict(e)
    # 限制 body 摘要长度，避免响应过大
    if data.get("body_snippet"):
        data["body_snippet"] = data["body_snippet"][:200]
    return data


# ── 连接测试（官方 SDK）────────────────────────────────────────────────────

def _derive_test_base_url(url: str, api_format: str) -> str:
    """根据 URL 和类型推导测试时使用的 API 基础 URL。

    委托给 utils.target_url.derive_test_base_url()。
    """
    return derive_test_base_url(url, api_format)


async def test_openai_compatible_connection(
    base_url: str,
    api_key: str,
    model: str,
    timeout: int = 30,
    verify_ssl: bool = False,
) -> dict:
    """用 openai SDK 测试 OpenAI 兼容 / Ollama 端点。

    Args:
        verify_ssl: 是否验证 SSL 证书（默认 False，内网目标常有自签名证书）
    """
    from openai import AsyncOpenAI, AuthenticationError, APIConnectionError

    test_url = _derive_test_base_url(base_url, "openai")
    httpx_client = create_http_client(verify_ssl=verify_ssl, timeout=timeout)

    try:
        client = AsyncOpenAI(
            base_url=test_url,
            api_key=api_key or "not-needed",
            http_client=httpx_client,
            max_retries=0,
        )

        # 先尝试 /v1/models
        try:
            models_resp = await client.models.list()
            models = [m.id for m in models_resp.data]
            return {
                "ok": True,
                "message": f"连接成功 ({test_url})",
                "models": models[:10],
                "model_count": len(models),
                "test_url": test_url,
            }
        except Exception:
            # fallback：用聊天接口
            if not model:
                raise
            resp = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=20,
                temperature=0.1,
            )
            return {
                "ok": True,
                "message": f"聊天接口连接成功 ({test_url})",
                "response": (resp.choices[0].message.content or "")[:100],
                "models": [model],
                "test_url": test_url,
            }
    except AuthenticationError as e:
        return {"ok": False, "error": f"认证失败: {e}", "test_url": test_url}
    except APIConnectionError as e:
        return {"ok": False, "error": f"连接失败: {e}", "test_url": test_url}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "test_url": test_url}
    finally:
        await httpx_client.aclose()


async def test_gemini_connection(
    api_key: str,
    model: str,
    timeout: int = 30,
) -> dict:
    """用 google-genai SDK 测试 Gemini。"""
    from google import genai

    if not api_key:
        return {"ok": False, "error": "Gemini 需要 API Key"}
    if not model:
        return {"ok": False, "error": "Gemini 需要模型名称"}

    try:
        client = genai.Client(
            api_key=api_key,
            http_options={"timeout": timeout * 1000},
        )
        response = await client.aio.models.generate_content(
            model=model,
            contents="Hello",
            config={"temperature": 0.1, "max_output_tokens": 20},
        )
        return {
            "ok": True,
            "message": "Gemini 连接成功",
            "response": (response.text or "")[:100],
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def test_claude_connection(
    api_key: str,
    model: str,
    timeout: int = 30,
    verify_ssl: bool = False,
) -> dict:
    """用 anthropic SDK 测试 Claude。

    Args:
        verify_ssl: 是否验证 SSL 证书（默认 False）
    """
    from anthropic import AsyncAnthropic, AuthenticationError

    if not api_key:
        return {"ok": False, "error": "Claude 需要 API Key"}
    if not model:
        return {"ok": False, "error": "Claude 需要模型名称"}

    httpx_client = create_http_client(verify_ssl=verify_ssl, timeout=timeout)
    try:
        client = AsyncAnthropic(api_key=api_key, http_client=httpx_client, max_retries=0)
        response = await client.messages.create(
            model=model,
            max_tokens=20,
            temperature=0.1,
            messages=[{"role": "user", "content": "Hello"}],
        )
        content = ""
        if response.content and len(response.content) > 0:
            first = response.content[0]
            content = getattr(first, "text", first.get("text", "")) if isinstance(first, dict) else getattr(first, "text", "")
        return {
            "ok": True,
            "message": "Claude 连接成功",
            "response": content[:100],
        }
    except AuthenticationError as e:
        return {"ok": False, "error": f"认证失败: {e}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        await httpx_client.aclose()


async def test_target_connection(
    api_format: str,
    url: str,
    api_key: str,
    model: str,
    timeout: int = 30,
    verify_ssl: bool = False,
) -> dict:
    """统一入口：根据 api_format 选择对应 SDK 测试。

    Args:
        verify_ssl: 是否验证 SSL 证书（默认 False，内网目标常有自签名证书）
    """
    api_format = api_format.lower()
    if api_format in ("openai", "ollama"):
        return await test_openai_compatible_connection(url, api_key, model, timeout, verify_ssl=verify_ssl)
    if api_format == "gemini":
        return await test_gemini_connection(api_key, model, timeout)
    if api_format == "claude":
        return await test_claude_connection(api_key, model, timeout, verify_ssl=verify_ssl)
    return {"ok": False, "error": f"不支持的 API 格式: {api_format}"}
