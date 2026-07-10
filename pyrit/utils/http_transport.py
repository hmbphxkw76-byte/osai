"""
===============================================================================
PyRIT Red Team — HTTP 传输层工厂 (httpx 核心 + curl_cffi TLS 伪装降级)
===============================================================================

设计哲学:
  ✅ httpx.AsyncClient — 默认核心，处理所有异步 HTTP 请求/会话/SSL
  ✅ curl_cffi — 按需降级，当 TLS 指纹被 WAF/反爬拦截时无缝切换
  ✅ 统一接口 — create_http_client() 始终返回 httpx.AsyncClient，
     对上层代码完全透明（包括 openai/anthropic SDK）

架构:
  ┌─────────────────────────────────────────────────┐
  │  create_http_client()                            │
  │    ├─ tls_impersonate=None  → 纯 httpx           │
  │    └─ tls_impersonate=...   → httpx + CurlCffiTransport │
  └─────────────────────────────────────────────────┘

使用方式:
  from utils.http_transport import create_http_client, is_tls_block_error, TLSProfile

  # 正常请求
  client = create_http_client(verify_ssl=False)
  
  # TLS 伪装请求（Cloudflare/Akamai 反爬绕过）
  client = create_http_client(verify_ssl=False, tls_impersonate="chrome124")

  # 自动检测降级
  try:
      resp = await client.get(url)
  except Exception as e:
      if is_tls_block_error(e) and not tls_active:
          client = create_http_client(verify_ssl=False, tls_impersonate="chrome124")
===============================================================================
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import httpx

from .target_url import (
    DEFAULT_OPEN_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    DEFAULT_MAX_REDIRECTS,
)

# ═══════════════════════════════════════════════════════════════════════════
# TLS 指纹伪装 Profile（与 curl_cffi 对齐）
# ═══════════════════════════════════════════════════════════════════════════

class TLSProfile(str, Enum):
    """curl_cffi 支持的 TLS 指纹伪装 profile。

    取值覆盖主流浏览器/平台:
    - Chrome 110/120/124: 最常用，Cloudflare/Akamai 兼容性最佳
    - Safari 17.0: iOS/macOS Safari 17 的 TLS 指纹
    - Firefox 120: Firefox 浏览器的 TLS 指纹
    - Edge 110: Microsoft Edge 基于 Chromium 110

    注意:
    - NONE = 纯 httpx 原生 TLS（无伪装）
    - AI 值如 chrome124_ai 需要 curl_cffi >= 0.8 才支持
    """
    NONE = "none"
    CHROME_110 = "chrome110"
    CHROME_120 = "chrome120"
    CHROME_124 = "chrome124"
    SAFARI_17 = "safari17_0"
    FIREFOX_120 = "firefox120"
    EDGE_110 = "edge110"


# ═══════════════════════════════════════════════════════════════════════════
# TLS 拦截检测
# ═══════════════════════════════════════════════════════════════════════════

# 常见 TLS 指纹拦截错误特征
_TLS_BLOCK_PATTERNS: list[str] = [
    # 连接层
    "connection reset by peer",
    "connection refused",
    "connection aborted",
    "connection closed",
    "connection reset",
    "tls handshake",
    "ssl handshake",
    "sslv3 alert",
    "certificate verify failed",
    "bad record mac",
    "unexpected eof",
    "eof occurred",
    "peer closed connection",
    "incomplete chunked",
    "remote disconnect",
    # 协议层
    "server disconnected",
    "no response",
    "empty reply from server",
    "connection was forcibly closed",
    # WAF 特征
    "403 forbidden",
    "blocked",
    "access denied",
    "captcha",
    "challenge",
    # 超时类（可能是慢速阻断）
    "connect timeout",
    "read timeout",
]


def is_tls_block_error(exc: Exception, response_text: str = "") -> bool:
    """判断异常/响应是否暗示 TLS 指纹被拦截。

    检测策略:
      1. 异常消息匹配已知 TLS 阻断特征
      2. 响应内容包含 WAF/反爬关键词
      3. 特定 HTTP 状态码 (430/403 空响应)

    Args:
        exc: 捕获的异常对象
        response_text: 响应文本（如有）

    Returns:
        大概率是 TLS 指纹拦截时返回 True
    """
    err_lower = str(exc).lower()

    # 检查异常类型
    exc_type = type(exc).__qualname__.lower()

    # httpx 特定异常
    if any(kw in exc_type for kw in ("connecterror", "readerror", "remoteprotocolerror",
                                       "proxyerror", "tlserror", "ssl", "readtimeout")):
        for pattern in _TLS_BLOCK_PATTERNS[:12]:  # 只检查连接层模式
            if pattern in err_lower:
                return True

    # 泛用异常匹配
    for pattern in _TLS_BLOCK_PATTERNS:
        if pattern in err_lower:
            return True

    # 检查响应内容中的 WAF 特征
    if response_text:
        resp_lower = response_text.lower()
        waf_keywords = ["captcha", "challenge", "blocked",
                        "access denied", "are you human",
                        "enable javascript", "please enable cookies",
                        "ddos protection", "checking your browser"]
        if any(kw in resp_lower for kw in waf_keywords):
            return True

    return False


# ═══════════════════════════════════════════════════════════════════════════
# curl_cffi → httpx Transport 适配器
# ═══════════════════════════════════════════════════════════════════════════

class CurlCffiTransport(httpx.AsyncBaseTransport):
    """将 curl_cffi.requests.AsyncSession 包装为 httpx transport。

    这使 openai / anthropic SDK 和其他所有依赖 httpx 的代码
    能够透明地获得 curl_cffi 的 TLS 指纹伪装能力，无需任何代码修改。

    工作原理:
      - httpx.AsyncClient 通过 transport.handle_async_request() 发送所有请求
      - 此 transport 将 httpx.Request 转换为 curl_cffi 请求
      - 将 curl_cffi Response 转换回 httpx.Response
    """

    def __init__(
        self,
        impersonate: str = "chrome124",
        verify: bool = True,
        timeout: float = 60.0,
    ):
        self._impersonate = impersonate
        self._verify = verify
        self._timeout = timeout
        self._session: Optional["object"] = None  # curl_cffi.requests.AsyncSession

    async def _ensure_session(self):
        """延迟创建 curl_cffi AsyncSession。"""
        if self._session is not None:
            return self._session
        try:
            from curl_cffi.requests import AsyncSession
        except ImportError as e:
            raise ImportError(
                "curl_cffi 未安装。请运行: pip install curl_cffi>=0.7"
            ) from e
        self._session = AsyncSession(
            impersonate=self._impersonate,
            verify=self._verify,
            timeout=self._timeout,
        )
        return self._session

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """将 httpx.Request 转换为 curl_cffi 请求，返回 httpx.Response。"""
        session = await self._ensure_session()

        # 提取 headers（httpx.Headers → dict）
        headers = dict(request.headers)

        # 构建 curl_cffi 请求参数
        kwargs: dict = {
            "method": request.method,
            "url": str(request.url),
            "headers": headers,
        }

        # 处理 request body
        if request.content:
            kwargs["content"] = request.content

        try:
            curl_resp = await session.request(**kwargs)
        except Exception as e:
            # 映射 curl_cffi 异常到 httpx 异常
            from curl_cffi.requests.errors import RequestsError
            if isinstance(e, RequestsError):
                raise httpx.ConnectError(str(e)) from e
            raise

        # 转换响应 headers 为 httpx 格式: list[tuple[bytes, bytes]]
        httpx_headers: list[tuple[bytes, bytes]] = []
        for k, v in curl_resp.headers.items():
            httpx_headers.append((k.encode("latin-1"), v.encode("latin-1")))

        # 处理 cookies
        if hasattr(curl_resp, "cookies"):
            try:
                for cookie in curl_resp.cookies.jar:
                    httpx_headers.append(
                        (b"set-cookie", str(cookie).encode("latin-1"))
                    )
            except Exception:
                pass

        return httpx.Response(
            status_code=curl_resp.status_code,
            headers=httpx_headers,
            content=curl_resp.content,
            request=request,
        )

    async def aclose(self) -> None:
        """关闭 curl_cffi session。"""
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None


# ═══════════════════════════════════════════════════════════════════════════
# 公共工厂
# ═══════════════════════════════════════════════════════════════════════════

# 默认浏览器 headers（所有 client 共享）— 模拟 Chrome 131 完整请求头
BROWSER_HEADERS: dict = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Priority": "u=0, i",
}

# API 探测 headers（用于 model_probe/target_type_probe — JSON 优先）
API_HEADERS: dict = {
    "User-Agent": BROWSER_HEADERS["User-Agent"],
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
}


def create_http_client(
    verify_ssl: bool = True,
    tls_impersonate: Optional[str] = None,
    timeout: float = 60.0,
    connect_timeout: float = DEFAULT_OPEN_TIMEOUT,
    headers: Optional[dict] = None,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    limits: Optional[httpx.Limits] = None,
) -> httpx.AsyncClient:
    """创建 HTTP 客户端（httpx 核心 + 可选 curl_cffi TLS 伪装）。

    Args:
        verify_ssl: SSL 证书验证
        tls_impersonate: TLS 指纹伪装 profile (chrome124/safari17_0/firefox120/...)
                         None 表示使用纯 httpx
        timeout: 请求超时（秒）
        connect_timeout: 连接超时（秒）
        headers: 默认请求头
        follow_redirects: 是否跟随重定向
        max_redirects: 最大重定向次数
        limits: httpx 连接限制配置

    Returns:
        httpx.AsyncClient（底层 transport 可能是 curl_cffi）
    """
    kwargs: dict = {
        "timeout": httpx.Timeout(timeout, connect=connect_timeout),
        "verify": verify_ssl,
        "follow_redirects": follow_redirects,
        "max_redirects": max_redirects,
    }

    if headers:
        kwargs["headers"] = headers
    if limits:
        kwargs["limits"] = limits

    # TLS 指纹伪装
    if tls_impersonate and tls_impersonate not in (TLSProfile.NONE.value, ""):
        kwargs["transport"] = CurlCffiTransport(
            impersonate=tls_impersonate,
            verify=verify_ssl,
            timeout=timeout,
        )

    return httpx.AsyncClient(**kwargs)


# ═══════════════════════════════════════════════════════════════════════════
# 便捷工具
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TransportConfig:
    """传输层配置（方便在各模块间传递）。"""
    verify_ssl: bool = True
    tls_impersonate: Optional[str] = None
    timeout: float = 60.0
    connect_timeout: float = DEFAULT_OPEN_TIMEOUT
    follow_redirects: bool = True
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    headers: Optional[dict] = None

    def create_client(self) -> httpx.AsyncClient:
        """从配置创建客户端。"""
        return create_http_client(
            verify_ssl=self.verify_ssl,
            tls_impersonate=self.tls_impersonate,
            timeout=self.timeout,
            connect_timeout=self.connect_timeout,
            headers=self.headers,
            follow_redirects=self.follow_redirects,
            max_redirects=self.max_redirects,
        )


def check_curl_cffi_available() -> bool:
    """检查 curl_cffi 是否已安装。"""
    try:
        import curl_cffi  # noqa: F401
        return True
    except ImportError:
        return False


def get_default_tls_profile() -> str:
    """获取推荐的默认 TLS 伪装 profile。

    返回 'chrome124'（当前兼容性最广的 profile）。
    """
    return TLSProfile.CHROME_124.value
