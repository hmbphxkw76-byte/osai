"""Cookie 会话搬运 — 加载 / 按域过滤 / 导出请求头

负责把浏览器导出的 Cookie（Netscape txt / 浏览器 JSON）转换为
garak generator 可直接注入的 ``Cookie`` 请求头字符串。

跨域关键点：只取目标推理域（api_domain）匹配的 Cookie，
不泄漏其他域的 Cookie（尤其中间 passport 域的临时票据）。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = __import__("logging").getLogger(__name__)

# Netscape cookies.txt 各列含义：
# domain \t flag \t path \t secure \t expiry \t name \t value
_NETSCAPE_HEADER = "# Netscape HTTP Cookie File"


def _domain_matches(cookie_domain: str, target_domain: str) -> bool:
    """判断 Cookie 的 domain 是否适用于目标推理域

    Cookie domain 可能带前导点（如 ``.syxy.ouchn.cn``），表示其子域均适用。
    匹配规则：
      - 完全相等
      - target_domain 以 cookie_domain（去点）结尾（含子域）
    """
    cd = cookie_domain.lstrip(".")
    return target_domain == cd or target_domain.endswith("." + cd)


def load_cookies(source: str) -> list[dict[str, Any]]:
    """加载 Cookie 文件，支持两种格式

    :param source: Cookie 文件路径（.txt = Netscape, .json = 浏览器导出）
    :returns: 统一结构的 Cookie 列表，每项含
              {name, value, domain, path, secure, httpOnly, expiry}
    """
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Cookie 文件不存在: {source}")

    text = path.read_text(encoding="utf-8")
    if source.endswith(".json"):
        return _load_json_cookies(json.loads(text))
    return _load_netscape_cookies(text)


def _load_json_cookies(data: Any) -> list[dict[str, Any]]:
    """浏览器 DevTools / Cookie-Editor 导出的 JSON

    浏览器 ``context.cookies()`` 返回字段：
    name, value, domain, path, expires (epoch 秒或 -1), httpOnly, secure, sameSite
    """
    cookies = data if isinstance(data, list) else data.get("cookies", [])
    out: list[dict[str, Any]] = []
    for c in cookies:
        out.append({
            "name": c.get("name", ""),
            "value": c.get("value", ""),
            "domain": c.get("domain", ""),
            "path": c.get("path", "/"),
            "secure": bool(c.get("secure", False)),
            "httpOnly": bool(c.get("httpOnly", False)),
            "expiry": c.get("expires", c.get("expiry", None)),
        })
    return out


def _load_netscape_cookies(text: str) -> list[dict[str, Any]]:
    """Netscape cookies.txt 格式解析"""
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        domain, _flag, path, secure, expiry, name, value = parts[:7]
        out.append({
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
            "secure": secure.lower() == "true",
            "httpOnly": False,
            "expiry": int(expiry) if expiry and expiry.isdigit() else None,
        })
    return out


def cookie_header_for(cookies: list[dict[str, Any]], target_domain: str) -> str:
    """生成仅含目标域 Cookie 的 ``Cookie`` 头字符串

    :param cookies: load_cookies 产出的统一结构
    :param target_domain: 目标推理域名（如 student.syxy.ouchn.cn）
    :returns: ``name1=val1; name2=val2`` 形式，空则空串
    """
    picked = [
        c for c in cookies
        if c.get("domain") and _domain_matches(c["domain"], target_domain)
    ]
    if not picked:
        logger.warning(
            "未找到匹配域 %s 的 Cookie，将发送无 Cookie 请求（目标可能拒绝）",
            target_domain,
        )
    return "; ".join(f'{c["name"]}={c["value"]}' for c in picked)


def save_cookies(cookies: list[dict[str, Any]], dest: str) -> None:
    """将 Cookie 落盘为浏览器 JSON 格式，并限制文件权限为 600

    :param cookies: 统一结构 Cookie 列表
    :param dest: 输出路径（建议 sessions/ 下）
    """
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cookies, indent=2, ensure_ascii=False), encoding="utf-8")
    # 敏感数据：仅属主可读写
    try:
        os.chmod(path, 0o600)
    except OSError:
        logger.debug("无法设置权限 600: %s", path)


def session_expiry(cookies: list[dict[str, Any]]) -> float | None:
    """返回最近过期时间（epoch 秒），用于会话时效预警

    :returns: 最近 expiry；无有效期 Cookie 则返回 None（视为会话级）
    """
    exps = [c["expiry"] for c in cookies if c.get("expiry") and c["expiry"] > 0]
    return min(exps) if exps else None


def api_domain_from_endpoint(endpoint: str) -> str:
    """从 endpoint URL 提取域名，作为 Cookie 匹配目标域"""
    return urlparse(endpoint).netloc
