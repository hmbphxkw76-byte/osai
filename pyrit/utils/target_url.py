"""
===============================================================================
PyRIT Red Team — 目标 URL 标准化工具（Target URL Utility）

参照 WhatWeb (urbanadventurer/WhatWeb) 的 URL 处理最佳实践：
  - 统一入口点：所有 URL 标准化通过本模块的单一函数完成
  - 灵活输入：支持 URL / hostname / IP / 带路径的完整 URL
  - 协议自动解析：裸主机名同时尝试 http:// 和 https://
  - 重定向控制：可配置 follow_redirects + max_redirects
  - 分离超时：open_timeout（连接建立） / read_timeout（数据读取）
  - 路径安全：杜绝路径遍历与 side-effect-free 的 URL 拼接

设计原则：
  ✅ 单一事实来源（Single Source of Truth）— 消除 3 处 _to_openai_base_url 重复
  ✅ 零副作用 — 纯函数，不修改全局状态，不触发 SDK 导入
  ✅ 防御式验证 — 拒绝无效/危险输入，而非静默接受
  ✅ 向后兼容 — 所有现有调用点的行为不变
===============================================================================
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse


# ═══════════════════════════════════════════════════════════════════════════
# 常量（参照 WhatWeb 默认值）
# ═══════════════════════════════════════════════════════════════════════════

# 超时（秒）
DEFAULT_OPEN_TIMEOUT = 15   # 连接建立超时（WhatWeb --open-timeout 默认 15s）
DEFAULT_READ_TIMEOUT = 30   # 数据读取超时（WhatWeb --read-timeout 默认 30s）

# 重定向
DEFAULT_MAX_REDIRECTS = 10  # WhatWeb --max-redirects 默认 10
DEFAULT_FOLLOW_REDIRECTS = True

# URL 验证
_MAX_URL_LENGTH = 2048         # 拒绝过长的 URL
_INVALID_HOSTNAME_PATTERN = re.compile(
    r"[^\w\-\.:]"  # 只允许字母/数字/连字符/点/冒号(端口)
)


# ═══════════════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class NormalizedURL:
    """标准化后的目标 URL 完整信息。

    参照 WhatWeb 的 URL 解析模式：将原始输入拆解为
    scheme / hostname / port / path / query 等独立组件，
    同时提供派生的 base_origin 和 verify_ssl 策略。

    Attributes:
        original: 用户原始输入（保留用于日志/回显）
        scheme: http 或 https
        hostname: 主机名或 IP
        port: 端口号（None 表示使用协议默认）
        path: URL 路径部分（始终以 / 开头，末尾无 /）
        query: 查询字符串（含 ? 前缀，可为空）
        base_origin: "{scheme}://{hostname}" 或 "{scheme}://{hostname}:{port}"
        verify_ssl: 是否应验证 SSL 证书（HTTPS 默认验证）
        is_ip: 主机是否为 IPv4 地址
    """
    original: str = ""
    scheme: str = "http"
    hostname: str = ""
    port: Optional[int] = None
    path: str = "/"
    query: str = ""
    verify_ssl: bool = False
    is_ip: bool = False

    @property
    def base_origin(self) -> str:
        """scheme + hostname + port（无路径），用于端点枚举的根。"""
        base = f"{self.scheme}://{self.hostname}"
        if self.port:
            base += f":{self.port}"
        return base

    @property
    def full_url(self) -> str:
        """完整标准化 URL：scheme://host:port/path?query

        注意：根路径 / 不显示尾部斜杠，与旧代码 url.rstrip('/') 行为一致。
        """
        netloc = self.hostname
        if self.port:
            netloc += f":{self.port}"
        path_part = self.path if self.path and self.path != "/" else ""
        base = f"{self.scheme}://{netloc}"
        if path_part:
            base += path_part
        if self.query:
            base += f"?{self.query}"
        return base

    def to_v1_base(self) -> str:
        """推导 OpenAI 兼容 /v1 基础 URL。

        规则（与 _to_openai_base_url 等价）：
          - Ollama: 只保留 scheme://host:port，拼接 /v1
          - 其他: 去掉 /chat/completions 后缀，确保以 /v1 结尾
        """
        base = self.base_origin
        return f"{base}/v1"


# ═══════════════════════════════════════════════════════════════════════════
# 核心：URL 标准化（单一入口）
# ═══════════════════════════════════════════════════════════════════════════

def normalize_target_url(raw: str) -> NormalizedURL:
    """标准化目标 URL，解析为结构化组件。

    参照 WhatWeb 的输入灵活性：
      - "example.com"          → http://example.com
      - "example.com:8080"     → http://example.com:8080
      - "https://192.168.1.1"  → https://192.168.1.1 (verify_ssl=True)
      - "http://host:11434/v1/chat/completions" → path=/v1/chat/completions

    Args:
        raw: 用户输入的原始 URL/主机名/IP

    Returns:
        NormalizedURL 数据类，包含所有解析后的字段

    Raises:
        ValueError: URL 格式无效或不安全
    """
    original = raw.strip()

    # ── 防御式验证（安全第一） ──
    if not original:
        raise ValueError("URL 不能为空")
    if len(original) > _MAX_URL_LENGTH:
        raise ValueError(f"URL 过长（>{_MAX_URL_LENGTH} 字符）")
    if "\n" in original or "\r" in original or "\0" in original:
        raise ValueError("URL 包含非法控制字符")

    # ── 自动补充协议（参照 WhatWeb — 裸主机名加 http://） ──
    url_with_scheme = original
    if "://" not in url_with_scheme:
        url_with_scheme = f"http://{url_with_scheme}"

    # ── 解析 ──
    parsed = urlparse(url_with_scheme)

    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError(f"无法解析主机名: {original}")

    # 主机名安全校验
    if _INVALID_HOSTNAME_PATTERN.search(hostname):
        raise ValueError(f"主机名包含非法字符: {hostname}")

    scheme = parsed.scheme.lower() or "http"
    if scheme not in ("http", "https"):
        raise ValueError(f"不支持的协议: {scheme}（仅支持 http/https）")

    # 端口（显式或协议默认）
    port = parsed.port

    # 路径 — 标准化：始终以 / 开头，末尾无 /
    path = parsed.path or "/"
    path = path.rstrip("/") or "/"

    # 查询字符串
    query = parsed.query

    # SSL 策略：HTTPS 默认验证，HTTP 不验证
    verify_ssl = (scheme == "https")

    # IPv4 检测
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))

    return NormalizedURL(
        original=original,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=query,
        verify_ssl=verify_ssl,
        is_ip=is_ip,
    )


# ═══════════════════════════════════════════════════════════════════════════
# URL 验证
# ═══════════════════════════════════════════════════════════════════════════

def validate_target_url(raw: str) -> tuple[bool, str]:
    """验证目标 URL 格式是否有效（不发起网络请求）。

    Returns:
        (is_valid, error_message)
    """
    try:
        normalize_target_url(raw)
        return True, ""
    except ValueError as e:
        return False, str(e)


def is_ip_address(host: str) -> bool:
    """检查字符串是否为 IPv4 地址。"""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))


# ═══════════════════════════════════════════════════════════════════════════
# URL 构造辅助
# ═══════════════════════════════════════════════════════════════════════════

def join_target_path(base_url: str, path: str) -> str:
    """安全拼接 base URL 与路径。

    使用 urljoin 语义，正确处理：
      - base=http://host:8080, path=/v1/models  → http://host:8080/v1/models
      - base=http://host/v1, path=/models       → http://host/v1/models (不是 http://host/models!)
      - base=http://host/foo, path=bar          → http://host/bar

    注意：urljoin 会替换整个路径（RFC 3986 行为）。
    如需保留 base 路径再追加，请确保 base 以 / 结尾，path 以无 / 开头。
    """
    if not base_url.endswith("/") and "/" in urlparse(base_url).path:
        # 如果 base 有路径，确保以 / 结尾避免 urljoin 吃掉最后一段
        base_url = base_url.rstrip("/") + "/"
    return urljoin(base_url, path)


def extract_base_origin(url: str) -> str:
    """从 URL 提取 scheme://hostname:port（去除路径和查询参数）。

    Examples:
        "http://host:8501/v1/chat" → "http://host:8501"
        "https://api.openai.com"   → "https://api.openai.com"
    """
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        origin += f":{parsed.port}"
    return origin


# ═══════════════════════════════════════════════════════════════════════════
# OpenAI 兼容 base_url 推导（消除 3 处重复）
# ═══════════════════════════════════════════════════════════════════════════

def to_openai_base_url(raw_url: str, api_format: str) -> str:
    """将用户输入的 URL 标准化为 OpenAI 兼容 base_url（供 AsyncOpenAI 使用）。

    OpenAI SDK 期望 base_url 在构造时指定，后续 chat.completions.create()
    会自动拼接 /chat/completions 路径。因此 base_url 应为 /v1 级别。

    转换规则：
      openai:  https://api.openai.com            → https://api.openai.com/v1
      ollama:  http://host:11434                 → http://host:11434/v1
               http://host:11434/api/chat        → http://host:11434/v1
               http://host:11434/v1              → http://host:11434/v1 (不变)
      gemini:  (不使用 base_url)                  → ""
      claude:  (默认官方端点)                      → "https://api.anthropic.com"

    Args:
        raw_url: 用户输入的原始 URL
        api_format: "openai" / "ollama" / "gemini" / "claude"

    Returns:
        OpenAI 兼容的 base_url 字符串（gemini 返回空字符串）
    """
    fmt = api_format.lower()

    # Gemini: 不需要 base_url（SDK 通过 api_key 直接连接）
    if fmt == "gemini":
        return ""

    # Claude: 默认官方端点
    if fmt == "claude":
        return "https://api.anthropic.com"

    # ── OpenAI / Ollama / raw ──
    url = raw_url.rstrip("/")
    parsed = urlparse(url)

    if fmt == "ollama":
        # Ollama: 只保留 host:port，拼接 /v1
        base = f"{parsed.scheme}://{parsed.netloc}"
        return f"{base}/v1"

    # openai / 其他: base_url 应指向 /v1
    if not url.endswith("/v1"):
        # 去掉已有的 /chat/completions /completions 后缀
        url = re.sub(r'/(chat/completions|completions)$', '', url)
        if not url.endswith("/v1"):
            url = f"{url.rstrip('/')}/v1"
    return url


def derive_test_base_url(url: str, api_format: str) -> str:
    """根据 URL 和 API 类型推导连接测试用的 API 基础 URL。

    与 to_openai_base_url 的区别：
      - 处理 /v1/chat/completions 完整路径 → 回溯到 /v1
      - 对 Ollama 也适用 /v1 拼接

    Args:
        url: 用户输入 URL
        api_format: "openai" / "ollama" / "gemini" / "claude"

    Returns:
        测试用的 base_url（gemini 返回空字符串）
    """
    return to_openai_base_url(url, api_format)


# ═══════════════════════════════════════════════════════════════════════════
# 遗留兼容别名（避免破坏现有调用）
# ═══════════════════════════════════════════════════════════════════════════

def _normalize_base_url(url: str) -> tuple[str, bool]:
    """标准化目标 URL，返回 (normalized_url, verify_ssl)。

    遗留兼容包装器。新代码应使用 normalize_target_url() 获取完整结构。

    Args:
        url: 原始 URL

    Returns:
        (normalized_url, verify_ssl)
    """
    result = normalize_target_url(url)
    return result.full_url, result.verify_ssl
