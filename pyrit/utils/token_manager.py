"""
===============================================================================
PyRIT Red Team — Token 管理器 (PyJWT 集成)
===============================================================================

职责:
  ✅ JWT 解码与检查（不验证签名，仅提取 payload 信息）
  ✅ Token 过期检测及提前预警
  ✅ Token 生命周期管理：刷新回调注册、TTL 监控
  ✅ 与 bootstrap.py 认证归一化流程无缝集成

设计原则:
  ✅ 非侵入 — 不影响现有 --auth 字符串传递逻辑
  ✅ 静默增强 — 仅在检测到 JWT 时激活，其余情况无开销
  ✅ 红队友好 — 自动显示 warning 而非 block（红队场景时效性很重要）

使用方式:
  from utils.token_manager import inspect_token, TokenInspector

  # 快速检查
  info = inspect_token("eyJhbGciOi...")
  if info.is_expired:
      print("Token 已过期！")
  if info.ttl_seconds and info.ttl_seconds < 3600:
      print(f"Token 将在 {info.ttl_minutes:.0f} 分钟后过期")
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Callable, Optional, Awaitable


# ═══════════════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TokenInfo:
    """JWT Token 的解析信息。

    Attributes:
        raw: 原始 Token 字符串（截断显示）
        header: JWT Header 部分 (alg, typ, kid 等)
        payload: JWT Payload 声明 (sub, iss, exp, iat 等)
        is_expired: 是否已过期
        expires_at: 过期时间（UTC）
        issued_at: 签发时间（UTC）
        issuer: 签发者 (iss claim)
        subject: 主题 (sub claim)
        audience: 受众 (aud claim)
        token_id: Token ID (jti claim)
        ttl_seconds: 剩余有效时间（秒），None 表示无 exp 声明或已过期
        ttl_minutes: 剩余有效时间（分）
        is_valid: Token 是否有效（格式可解析）
        error: 解析错误信息（如有）
    """
    raw: str = ""
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    is_expired: bool = False
    expires_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    issuer: str = ""
    subject: str = ""
    audience: str = ""
    token_id: str = ""
    ttl_seconds: Optional[float] = None
    ttl_minutes: Optional[float] = None
    is_valid: bool = False
    error: str = ""

    @property
    def summary(self) -> str:
        """人类可读的 Token 摘要。"""
        if not self.is_valid:
            return f"Token 无效: {self.error}"
        parts = []
        if self.subject:
            parts.append(f"sub={self.subject}")
        if self.issuer:
            parts.append(f"iss={self.issuer}")
        if self.expires_at:
            if self.is_expired:
                parts.append(f"已过期 ({self.expires_at_str})")
            else:
                parts.append(f"有效期至 {self.expires_at_str} (剩余 {self.ttl_minutes:.0f}分)")
        else:
            parts.append("无过期时间")
        if self.audience:
            aud_str = self.audience if isinstance(self.audience, str) else ",".join(self.audience)
            parts.append(f"aud={aud_str}")
        if self.token_id:
            parts.append(f"jti={self.token_id[:8]}...")
        return " | ".join(parts)

    @property
    def expires_at_str(self) -> str:
        """格式化过期时间。"""
        if self.expires_at is None:
            return "N/A"
        return self.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    @property
    def issued_at_str(self) -> str:
        """格式化签发时间。"""
        if self.issued_at is None:
            return "N/A"
        return self.issued_at.strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class TokenRefreshResult:
    """Token 刷新结果。"""
    success: bool = False
    new_token: str = ""
    new_token_info: Optional[TokenInfo] = None
    error: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# 核心 JWT 解析（PyJWT）
# ═══════════════════════════════════════════════════════════════════════════

def inspect_token(token: str) -> TokenInfo:
    """检查 JWT Token 的有效性和过期状态。

    使用 PyJWT 解码但不验证签名 — 红队场景下我们只需要
    提取 payload 信息来判断 token 是否仍在有效期内，
    无需验证签发者的签名。

    Args:
        token: 原始 JWT Token 字符串

    Returns:
        TokenInfo 包含完整解析结果
    """
    if not token or not token.strip():
        return TokenInfo(error="空 Token")

    token = token.strip()
    info = TokenInfo(raw=_truncate_token(token), is_valid=False)

    # 快速检测是否为 JWT 格式
    if not token.startswith("eyJ"):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return TokenInfo(raw=_truncate_token(token),
                                 error="非 JWT 格式（不是三段式 Base64）")
        except Exception:
            return TokenInfo(raw=_truncate_token(token),
                             error="非 JWT 格式")

    try:
        import jwt as _jwt
    except ImportError:
        return TokenInfo(raw=_truncate_token(token),
                         error="PyJWT 未安装。请运行: pip install pyjwt>=2.8")

    try:
        # 不验证签名，只解码 — 红队场景不需要验证
        info.header = _jwt.get_unverified_header(token)
        info.payload = _jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False},
        )

        # 提取标准 claims
        info.issuer = info.payload.get("iss", "")
        info.subject = info.payload.get("sub", "")
        info.audience = _extract_audience(info.payload.get("aud", ""))
        info.token_id = info.payload.get("jti", "")
        info.is_valid = True

        # 时间解析
        now = datetime.now(timezone.utc)

        exp = info.payload.get("exp")
        if exp is not None:
            info.expires_at = datetime.fromtimestamp(int(exp), tz=timezone.utc)
            delta = info.expires_at - now
            info.ttl_seconds = max(0, delta.total_seconds())
            info.ttl_minutes = info.ttl_seconds / 60
            info.is_expired = info.ttl_seconds <= 0

        iat = info.payload.get("iat")
        if iat is not None:
            info.issued_at = datetime.fromtimestamp(int(iat), tz=timezone.utc)

    except _jwt.DecodeError as e:
        info.error = f"JWT 解码失败: {e}"
    except _jwt.InvalidTokenError as e:
        info.error = f"无效 Token: {e}"
    except Exception as e:
        info.error = f"解析异常: {e}"

    return info


def _extract_audience(aud) -> str:
    """规范化 aud claim 为字符串。"""
    if isinstance(aud, list):
        return ",".join(str(a) for a in aud)
    return str(aud) if aud else ""


def _truncate_token(token: str, head: int = 15, tail: int = 10) -> str:
    """截断 Token 用于安全显示。"""
    if len(token) <= head + tail + 3:
        return token
    return f"{token[:head]}...{token[-tail:]}"


# ═══════════════════════════════════════════════════════════════════════════
# Token 生命周期管理
# ═══════════════════════════════════════════════════════════════════════════

class TokenInspector:
    """Token 生命周期管理器。

    功能:
      - 持有当前 Token 及解析结果
      - 注册刷新回调（红队自定义获取新 Token 的逻辑）
      - 自动过期预警
      - 按需刷新

    使用方式:
      inspector = TokenInspector(jwt_token)
      inspector.on_refresh = my_refresh_function  # async callback
      if inspector.needs_refresh(warn_before_minutes=30):
          await inspector.refresh()
    """

    def __init__(self, token: str = ""):
        self._token: str = token
        self._info: TokenInfo = inspect_token(token) if token else TokenInfo()
        self._refresh_callback: Optional[Callable[[], Awaitable[TokenRefreshResult]]] = None

    # ── 属性 ──

    @property
    def token(self) -> str:
        return self._token

    @property
    def info(self) -> TokenInfo:
        return self._info

    @property
    def is_active(self) -> bool:
        """Token 是否有效且未过期。"""
        return self._info.is_valid and not self._info.is_expired

    @property
    def ttl_minutes(self) -> Optional[float]:
        """剩余有效时间（分钟）。"""
        return self._info.ttl_minutes

    # ── 刷新回调 ──

    def on_refresh(
        self, callback: Callable[[], Awaitable[TokenRefreshResult]]
    ) -> None:
        """注册 Token 刷新回调。

        callback 应为 async 函数，返回 TokenRefreshResult。
        典型实现:
          async def my_refresh():
              # 向认证服务器请求新 token
              new_token = await fetch_new_token()
              return TokenRefreshResult(success=True, new_token=new_token)
        """
        self._refresh_callback = callback

    # ── 状态检查 ──

    def needs_refresh(self, warn_before_minutes: int = 30) -> bool:
        """判断 Token 是否需要在过期前刷新。

        Args:
            warn_before_minutes: 提前多少分钟开始预警

        Returns:
            True 如果 Token 已过期或即将过期
        """
        if not self._info.is_valid:
            return True
        if self._info.is_expired:
            return True
        if self._info.ttl_minutes is None:
            return False  # 无过期时间，不触发
        return self._info.ttl_minutes <= warn_before_minutes

    def get_expiry_warning(self, warn_before_minutes: int = 30) -> str:
        """获取过期警告信息（供 Rich console 显示）。"""
        if not self._info.is_valid:
            return "[bold red]⚠ Token 无效或无法解析[/bold red]"
        if self._info.is_expired:
            return "[bold red]❌ Token 已过期！攻击可能失败[/bold red]"
        if self._info.ttl_minutes is not None and self._info.ttl_minutes <= warn_before_minutes:
            return (
                f"[bold yellow]⚠ Token 即将过期 "
                f"(剩余 {self._info.ttl_minutes:.0f} 分钟)[/bold yellow]"
            )
        if self._info.ttl_minutes is not None:
            return (
                f"[dim]✓ Token 有效 "
                f"(剩余 {self._info.ttl_minutes:.0f} 分钟)[/dim]"
            )
        return "[dim]✓ Token 有效（无过期时间声明）[/dim]"

    # ── 刷新 ──

    async def refresh(self) -> TokenRefreshResult:
        """尝试刷新 Token。

        Returns:
            TokenRefreshResult 包含新 Token 或错误信息
        """
        if self._refresh_callback is None:
            return TokenRefreshResult(
                success=False,
                error="未注册刷新回调。请使用 inspector.on_refresh(callback) 注册",
            )

        try:
            result = await self._refresh_callback()
            if result.success and result.new_token:
                self._token = result.new_token
                self._info = inspect_token(result.new_token)
                result.new_token_info = self._info
            return result
        except Exception as e:
            return TokenRefreshResult(success=False, error=str(e))

    def update(self, new_token: str) -> None:
        """手动更新 Token（不调用刷新回调）。"""
        self._token = new_token
        self._info = inspect_token(new_token)


# ═══════════════════════════════════════════════════════════════════════════
# 便捷函数
# ═══════════════════════════════════════════════════════════════════════════

def is_jwt_format(token: str) -> bool:
    """快速检测字符串是否为 JWT 格式。"""
    if not token or not token.strip():
        return False
    token = token.strip()
    if not token.startswith("eyJ"):
        return False
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def get_token_summary_for_display(token: str) -> str:
    """生成 Token 的 Rich 友好摘要字符串。

    Returns:
        Rich markup 字符串，适合 console.print() 直接使用
    """
    if not token:
        return "[dim]无认证信息[/dim]"

    if not is_jwt_format(token):
        return f"[dim]API Key ({_truncate_token(token)})[/dim]"

    info = inspect_token(token)
    if not info.is_valid:
        return f"[yellow]JWT 解析失败: {info.error}[/yellow]"

    inspector = TokenInspector(token)
    warning = inspector.get_expiry_warning()

    return f"[dim]JWT {info.summary} | {warning}[/dim]"
