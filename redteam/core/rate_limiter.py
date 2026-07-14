"""自适应速率限制调速器（RateLimitGovernor） — AI-300 Ch2.4 Detection and Evasion。

在每个 HTTP 请求周期中持续感知和自适应调整速率，避免因超速触发目标
限速而导致攻击效果受影响。

核心设计：
  - per-endpoint 独立追踪：不同 URL/路径维护独立的速率状态
  - 指数退避：收到 429 后自动递增等待时间
  - 安全余量：建议速率 = 探测阈值 × 0.7（30% 安全余量）
  - Recon 种子注入：从 Phase 1 侦察结果预填充已知速率限制阈值

对齐 OWASP LLM Top 10: LLM10 (Unbounded Consumption)
对齐 MITRE ATLAS: Defense Evasion
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# 每端点速率状态
# ---------------------------------------------------------------------------
class EndpointRateState:
    """单个端点的速率限制状态。"""

    def __init__(self, url: str):
        self.url = url
        self.base_domain = _extract_base(url)

        # 探针注入的已知阈值
        self.known_threshold_rpm: float = 0.0  # 0 = 未探测/无限制
        self.rate_limit_detected: bool = False
        self.rate_limit_status_code: int = 0
        self.rate_limit_retry_after: str = ""

        # 动态退避
        self.current_backoff_ms: int = 0      # 当前退避延迟
        self.min_backoff_ms: int = 300        # 最小退避
        self.max_backoff_ms: int = 30000      # 最大退避（30 秒）
        self.backoff_multiplier: float = 2.0  # 退避倍增因子

        # 统计
        self.total_requests: int = 0
        self.total_429: int = 0
        self.consecutive_429: int = 0
        self.last_request_time: float = 0.0
        self.last_429_time: float = 0.0

    # ------------------------------------------------------------------
    # 调速决策
    # ------------------------------------------------------------------
    def govern(self) -> float:
        """返回当前需要等待的秒数（请求前调用）。

        优先级：
          1. 已知探测阈值 → 计算基于 RPM 的固定延迟
          2. 动态退避中 → 返回退避延迟
          3. 无限制 → 返回最小延迟（300ms 基线，模拟人工）

        Returns:
            需要等待的秒数，0 表示无需等待
        """
        # 如果已知阈值，使用 RPM 安全速率
        if self.known_threshold_rpm > 0:
            safe_rpm = self.known_threshold_rpm * 0.7
            safe_delay_ms = (60.0 / safe_rpm) * 1000
            elapsed_ms = _elapsed_since(self.last_request_time)
            if elapsed_ms < safe_delay_ms:
                return (safe_delay_ms - elapsed_ms) / 1000.0

        # 动态退避模式
        if self.current_backoff_ms > 0:
            elapsed_ms = _elapsed_since(self.last_request_time)
            if elapsed_ms < self.current_backoff_ms:
                return (self.current_backoff_ms - elapsed_ms) / 1000.0
            # 退避时间已过，允许发射，但维持退避级别
            return 0.0

        # 无限制模式：最小基线延迟
        if self.min_backoff_ms > 0:
            elapsed_ms = _elapsed_since(self.last_request_time)
            if elapsed_ms < self.min_backoff_ms:
                return (self.min_backoff_ms - elapsed_ms) / 1000.0

        return 0.0

    # ------------------------------------------------------------------
    # 响应反馈
    # ------------------------------------------------------------------
    def report(self, status: int, headers: dict[str, str] | None = None) -> None:
        """请求完成后的响应反馈，更新速率状态。

        Args:
            status: HTTP 状态码
            headers: 响应头字典
        """
        self.total_requests += 1
        self.last_request_time = time.time()

        headers = headers or {}

        if status == 429:
            self.total_429 += 1
            self.consecutive_429 += 1
            self.last_429_time = time.time()

            # 解析 Retry-After
            retry_after = headers.get("retry-after", "")
            if retry_after:
                self.rate_limit_retry_after = retry_after
                try:
                    self.current_backoff_ms = int(retry_after) * 1000
                except ValueError:
                    self.current_backoff_ms = self.min_backoff_ms
            else:
                # 指数退避
                if self.current_backoff_ms == 0:
                    self.current_backoff_ms = self.min_backoff_ms
                else:
                    self.current_backoff_ms = min(
                        int(self.current_backoff_ms * self.backoff_multiplier),
                        self.max_backoff_ms,
                    )

            # 从多次 429 中推断阈值
            if self.consecutive_429 >= 3:
                recent_rpm = _estimate_rpm(self.total_requests, self.total_429)
                if recent_rpm > 0 and (self.known_threshold_rpm == 0 or recent_rpm < self.known_threshold_rpm):
                    self.known_threshold_rpm = recent_rpm
                    self.rate_limit_detected = True
                    self.rate_limit_status_code = status

        elif status == 200:
            self.consecutive_429 = 0
            # 成功后缓慢降低退避（不立即清零）
            if self.current_backoff_ms > self.min_backoff_ms:
                self.current_backoff_ms = max(
                    self.min_backoff_ms,
                    int(self.current_backoff_ms * 0.75),
                )

        elif status >= 500:
            # 服务端错误也视为速率限制信号
            self.consecutive_429 += 1

    # ------------------------------------------------------------------
    # 种子注入
    # ------------------------------------------------------------------
    def seed_from_probe(self, probe_result: dict[str, Any]) -> None:
        """从 Phase 1 速率限制探测结果注入初始状态。

        Args:
            probe_result: probe_rate_limit() 返回的结果字典
        """
        threshold = float(probe_result.get("threshold_rpm", 0))
        stop_reason = probe_result.get("stop_reason", "")
        is_safe_confirmed = stop_reason.startswith("safe_at_")

        if probe_result.get("rate_limit_detected"):
            self.rate_limit_detected = True
            self.known_threshold_rpm = threshold
            self.rate_limit_status_code = probe_result.get("status_code", 0)
            self.rate_limit_retry_after = probe_result.get("retry_after", "")
            # 探测阈值设置安全基线（阈值 × 0.5 作为最小间隔）
            if self.known_threshold_rpm > 0:
                safe_delay = (60.0 / (self.known_threshold_rpm * 0.5)) * 1000
                self.min_backoff_ms = max(int(safe_delay), self.min_backoff_ms)
        elif is_safe_confirmed and threshold > 0:
            # 够用即停：已确认安全，不需要触发限速
            # 这里不打 0.5 惩罚，直接用阈值作为已知安全速率
            self.known_threshold_rpm = threshold
            self.rate_limit_detected = False
            self.min_backoff_ms = max(
                int((60.0 / (threshold * 0.8)) * 1000),
                self.min_backoff_ms,
            )

    def get_safe_rate(self) -> tuple[float, bool]:
        """返回安全请求速率（RPM）和是否有限制。

        Returns:
            (safe_rpm, has_limit)
        """
        if self.known_threshold_rpm > 0:
            return self.known_threshold_rpm * 0.7, True
        return 0.0, False

    def summary(self) -> dict[str, Any]:
        """返回速率状态摘要。"""
        safe_rpm, has_limit = self.get_safe_rate()
        return {
            "url": self.url,
            "base_domain": self.base_domain,
            "rate_limit_detected": self.rate_limit_detected,
            "known_threshold_rpm": self.known_threshold_rpm,
            "safe_rpm": round(safe_rpm, 1),
            "has_limit": has_limit,
            "current_backoff_ms": self.current_backoff_ms,
            "total_requests": self.total_requests,
            "total_429": self.total_429,
            "consecutive_429": self.consecutive_429,
        }


# ---------------------------------------------------------------------------
# RateLimitGovernor — 全局自适应调速器
# ---------------------------------------------------------------------------
class RateLimitGovernor:
    """全局自适应速率限制调速器。

    管理所有端点的速率状态，为 HTTP 客户端和攻击执行器提供统一的
    调速接口。

    使用方式：
        governor = RateLimitGovernor()

        # Phase 1 侦察完成后注入探测结果
        for url, probe in recon.rate_limit_info.items():
            governor.seed_endpoint(url, probe)

        # 请求前调速
        governor.govern("https://target/v1/chat/completions")

        # 响应后反馈
        governor.report("https://target/v1/chat/completions", 200, headers)
    """

    def __init__(self):
        self._endpoints: dict[str, EndpointRateState] = {}
        self._domain_defaults: dict[str, EndpointRateState] = {}
        self._global_min_delay_ms: int = 300  # 全局最小延迟
        self._enabled: bool = True

    # ------------------------------------------------------------------
    # 端点管理
    # ------------------------------------------------------------------
    def _get_or_create(self, url: str) -> EndpointRateState:
        """获取或创建端点状态。

        优先精确匹配，回退到域名级别共享状态。
        """
        url = url.rstrip("/")
        if url in self._endpoints:
            return self._endpoints[url]

        domain = _extract_base(url)
        if domain in self._domain_defaults:
            return self._domain_defaults[domain]

        state = EndpointRateState(url)
        self._endpoints[url] = state
        return state

    def seed_endpoint(self, url: str, probe_result: dict[str, Any]) -> EndpointRateState:
        """从侦察探测结果注入端点的初始速率状态。

        Args:
            url: 端点 URL
            probe_result: probe_rate_limit() 结果

        Returns:
            创建或已存在的 EndpointRateState
        """
        state = self._get_or_create(url)
        state.seed_from_probe(probe_result)

        # 同时注册域名级默认
        domain = _extract_base(url)
        if domain not in self._domain_defaults:
            self._domain_defaults[domain] = state

        return state

    def seed_from_recon(self, rate_limit_info: dict[str, Any]) -> None:
        """从 ReconResult.rate_limit_info 批量注入探测结果。

        Args:
            rate_limit_info: ReconResult.rate_limit_info 字典
        """
        for url, probe in rate_limit_info.items():
            self.seed_endpoint(url, probe)

    # ------------------------------------------------------------------
    # 调速与反馈
    # ------------------------------------------------------------------
    def govern(self, url: str) -> float:
        """请求前调用，返回需要等待的秒数。

        实际等待由调用方执行。

        Args:
            url: 请求 URL

        Returns:
            需要等待的秒数，0 表示无需等待
        """
        if not self._enabled:
            return 0.0
        return self._get_or_create(url).govern()

    def govern_and_wait(self, url: str) -> float:
        """请求前调用，自动等待并返回实际等待的秒数。"""
        wait = self.govern(url)
        if wait > 0:
            time.sleep(wait)
        return wait

    def report(
        self,
        url: str,
        status: int,
        headers: dict[str, str] | None = None,
    ) -> None:
        """请求完成后的响应反馈。

        Args:
            url: 请求 URL
            status: HTTP 状态码
            headers: 响应头字典
        """
        if not self._enabled:
            return
        state = self._get_or_create(url)
        state.report(status, headers)

        # 域名级同步
        domain = _extract_base(url)
        if domain in self._domain_defaults and self._domain_defaults[domain].current_backoff_ms > 0:
            state.current_backoff_ms = max(
                state.current_backoff_ms,
                self._domain_defaults[domain].current_backoff_ms,
            )

    # ------------------------------------------------------------------
    # 查询接口
    # ------------------------------------------------------------------
    def get_safe_rate(self, url: str) -> tuple[float, bool]:
        """查询 URL 的安全请求速率。

        Returns:
            (safe_rpm, has_limit)
        """
        return self._get_or_create(url).get_safe_rate()

    def get_all_summaries(self) -> list[dict[str, Any]]:
        """返回所有端点速率状态摘要。"""
        return [s.summary() for s in self._endpoints.values()]

    def has_any_rate_limit(self) -> bool:
        """是否有任何端点检测到速率限制。"""
        return any(s.rate_limit_detected for s in self._endpoints.values())

    def get_global_min_delay_ms(self) -> int:
        """返回建议的全局最小请求间隔（ms）。

        取所有端点中最大安全延迟的下限。
        """
        max_safe = self._global_min_delay_ms
        for state in self._endpoints.values():
            if state.known_threshold_rpm > 0:
                safe_delay = int((60.0 / (state.known_threshold_rpm * 0.7)) * 1000)
                max_safe = max(max_safe, safe_delay)
        return max_safe

    # ------------------------------------------------------------------
    # 控制
    # ------------------------------------------------------------------
    def enable(self) -> None:
        """启用调速。"""
        self._enabled = True

    def disable(self) -> None:
        """禁用调速（调试用）。"""
        self._enabled = False

    def override_safe_rpm(self, url: str, rpm: float) -> None:
        """手动覆写端点的安全 RPM（用户交互调整）。

        将 rpm 作为最终安全 RPM 保存：调用 get_safe_rate() 后将返回 rpm 值。
        内部通过反向换算 known_threshold_rpm = rpm / 0.7 实现。

        Args:
            url: 端点 URL
            rpm: 用户指定的安全 RPM（即 get_safe_rate 将返回的值）
        """
        state = self._get_or_create(url)
        # get_safe_rate() 返回 known_threshold_rpm * 0.7
        # 要让最终返回值等于 rpm，需反向计算阈值
        state.known_threshold_rpm = rpm / 0.7
        state.rate_limit_detected = False
        # 按 rpm 计算最小安全延迟（直接以安全速率为基准）
        state.min_backoff_ms = max(int((60.0 / rpm) * 1000), 300)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def _extract_base(url: str) -> str:
    """从 URL 提取 scheme+netloc 基础部分。"""
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return url


def _elapsed_since(timestamp: float) -> float:
    """计算自 timestamp 以来经过的毫秒数。"""
    if timestamp <= 0:
        return float("inf")
    return (time.time() - timestamp) * 1000


def _estimate_rpm(total_requests: int, total_429: int) -> float:
    """从请求统计中估算触发速率限制的 RPM。"""
    if total_429 < 3 or total_requests < 10:
        return 0.0
    # 简单估算：假设 429 发生在前 80% 的请求中触发
    return total_requests * 0.8


# ---------------------------------------------------------------------------
# 模块级单例
# ---------------------------------------------------------------------------
_governor: RateLimitGovernor | None = None


def get_governor() -> RateLimitGovernor:
    """获取全局 RateLimitGovernor 单例。"""
    global _governor
    if _governor is None:
        _governor = RateLimitGovernor()
    return _governor


def reset_governor() -> None:
    """重置全局调速器（测试用）。"""
    global _governor
    _governor = RateLimitGovernor()


__all__ = [
    "RateLimitGovernor",
    "EndpointRateState",
    "get_governor",
    "reset_governor",
]
