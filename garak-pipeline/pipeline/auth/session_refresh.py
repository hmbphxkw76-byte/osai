"""会话刷新守卫 — 长扫描中自动检测并恢复过期 Cookie

Web 认证目标（特别是教育/政务类单体 SPA）的会话有效期通常很短
（30-60 分钟），而 garak 全量扫描（数百次请求）必然跨过期。
一旦 Cookie 过期，目标返回 401/403 或重定向登录页 → garak 视为
"模型返回 null" → Stage4 nones 飙升 → ASR 假性 0%/DEFCON 5，
触发 MEMORY 记录的"nones 假阴性陷阱"。

本模块提供：
1. 过期检测：通过 HTTP 响应状态码 / 响应体特征判断会话失效
2. 自动重登录：利用保存的 .env 凭证重新运行 AuthBootstrap（无头模式）
3. 冷却机制：避免连续重试导致的账号风控锁定

设计约束：
  - 无头模式重登录（headless=True）不弹出浏览器窗口，仅 Cookie 刷新
  - 冷却期内不重复登录（默认 60s）
  - 二次验证（OTP/滑窗）在无头模式下无法自动通过 → 跳过并告警
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from .cookie_session import cookie_header_for, load_cookies, save_cookies  # noqa: F401

logger = logging.getLogger(__name__)

# HTTP 状态码 — 明确的认证失效信号
_AUTH_FAILURE_STATUSES = {401, 403}

# 响应体关键词 — 捕获 JSON/HTML 中的登录页特征
_AUTH_FAILURE_BODY_HINTS = [
    "请登录", "请先登录", "未登录", "登录已过期", "token expired",
    "session expired", "unauthorized", "authentication required",
    "login required", "please login", "invalid session",
    "access denied", "forbidden", "<title>登录</title>",
    "window.location.href.*login", "window.location.replace.*login",
]


class SessionRefresher:
    """会话刷新守卫 — 检测过期 + 自动重登录"""

    def __init__(
        self,
        cookie_path: str,
        target_url: str,
        auth_cfg: dict[str, Any] | None = None,
        sessions_dir: str = "sessions",
        cooldown_seconds: float = 60.0,
    ) -> None:
        self.cookie_path = cookie_path
        self.target_url = target_url
        self.auth_cfg = auth_cfg or {}
        self.sessions_dir = sessions_dir
        self.cooldown_seconds = cooldown_seconds
        self._cooldown_until: float = 0.0
        self._refresh_count: int = 0

    # ------------------------------------------------------------------
    # 过期检测
    # ------------------------------------------------------------------

    def is_session_expired(self, response_or_error: Any) -> bool:
        """检测 HTTP 响应是否指示会话过期

        输入可以是 httpx.Response、requests.Response，或 Exception 对象。
        对 Exception 返回 False（网络错误 ≠ 会话过期，留给自适应速率处理）。

        :param response_or_error: HTTP 响应对象或异常
        :returns: True 表示需要刷新会话
        """
        # 异常不触发刷新（留给自适应速率控制器的熔断/重试逻辑）
        if isinstance(response_or_error, Exception):
            return False

        # 尝试取 status_code
        status = getattr(response_or_error, "status_code", None)
        if status in _AUTH_FAILURE_STATUSES:
            logger.debug("会话过期检测: HTTP %d", status)
            return True

        # 尝试读响应体
        body = ""
        try:
            body = getattr(response_or_error, "text", "")
            if not body:
                body = str(response_or_error)
        except Exception:
            pass

        if body:
            import re

            body_lower = body.lower()
            for hint in _AUTH_FAILURE_BODY_HINTS:
                if re.search(hint, body_lower):
                    logger.debug("会话过期检测: 响应体匹配 '%s'", hint)
                    return True

        return False

    # ------------------------------------------------------------------
    # 自动重登录
    # ------------------------------------------------------------------

    def refresh(self) -> dict[str, str] | None:
        """重新登录并返回新的 Cookie 请求头

        使用无头模式（headless=True）避免弹出浏览器窗口，
        但 OTP/滑窗/扫码等二次验证无法自动通过 — 这些场景下
        会跳过并告警，然后尝试使用旧 Cookie 继续（best-effort）。

        :returns: 新的认证头 dict，或 None（刷新失败）
        """
        now = time.time()
        if now < self._cooldown_until:
            remaining = int(self._cooldown_until - now)
            logger.warning("会话刷新冷却中，剩余 %ds", remaining)
            return None

        logger.info("会话已过期，触发自动重登录 (第 %d 次)", self._refresh_count + 1)

        try:
            from .bootstrap import AuthBootstrap

            bootstrap = AuthBootstrap(
                target_url=self.target_url,
                cfg=self.auth_cfg,
                sessions_dir=self.sessions_dir,
            )
            # 无头模式：不弹出浏览器，仅后台刷新 Cookie
            profile = bootstrap.run()
            self._refresh_count += 1
            self._cooldown_until = time.time() + self.cooldown_seconds

            new_headers: dict[str, str] = {}
            if profile.cookie_header:
                new_headers["Cookie"] = profile.cookie_header

            logger.info(
                "会话刷新成功: endpoint=%s model=%s cookies=%d",
                profile.endpoint, profile.model,
                len(profile.raw_cookies),
            )
            return new_headers

        except Exception as exc:
            logger.error("会话刷新失败: %s", exc)
            self._cooldown_until = time.time() + self.cooldown_seconds * 2
            return None

    # ------------------------------------------------------------------
    # 便捷方法：刷新并更新 generator 的 extra_headers
    # ------------------------------------------------------------------

    def refresh_into_generator(self, generator: Any) -> bool:
        """刷新会话并写入 generator 的 extra_headers

        :param generator: AuthenticatedOpenAICompatible 实例
        :returns: True 表示刷新成功
        """
        new_headers = self.refresh()
        if new_headers is None:
            return False

        if hasattr(generator, "_extra_headers"):
            generator._extra_headers = new_headers
        elif hasattr(generator, "extra_headers"):
            generator.extra_headers = new_headers
        else:
            logger.warning("generator 不支持 extra_headers，无法注入新会话")
            return False
        return True

    @property
    def is_in_cooldown(self) -> bool:
        return time.time() < self._cooldown_until


# ------------------------------------------------------------------
# 从 config 构造 SessionRefresher
# ------------------------------------------------------------------

def create_session_refresher(
    target: dict[str, Any],
    sessions_dir: str = "sessions",
    cooldown_seconds: float = 60.0,
) -> SessionRefresher | None:
    """从 target.yaml 配置构造 SessionRefresher

    仅当 auth.type == "cookie_file" 且有 cookie_source 时才启用。

    :param target: config["target"] 段
    :param sessions_dir: Cookie 落盘目录
    :param cooldown_seconds: 两次刷新间最小冷却时间
    :returns: SessionRefresher 实例，或 None（不需要刷新）
    """
    auth_cfg = target.get("auth", {}) or {}
    auth_type = auth_cfg.get("type", "")
    if auth_type != "cookie_file":
        return None

    cookie_source = auth_cfg.get("cookie_source") or ""
    target_url = target.get("target_url") or ""

    if not cookie_source:
        # 尝试从 cookie_domain 自动推导
        domain = auth_cfg.get("cookie_domain", "")
        if domain:
            import re
            safe = re.sub(r"\W+", "_", domain)
            cookie_source = f"{sessions_dir}/{safe}.json"

    if not cookie_source or not Path(cookie_source).exists():
        logger.debug("Cookie 文件 %s 不存在，跳过会话刷新守卫", cookie_source)
        return None

    return SessionRefresher(
        cookie_path=cookie_source,
        target_url=target_url,
        auth_cfg=auth_cfg,
        sessions_dir=sessions_dir,
        cooldown_seconds=cooldown_seconds,
    )
