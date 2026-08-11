"""WAF/防御前置探测 — 扫描前检测目标防御设施

在 Stage 1 连通性测试之前执行，检测：
  1. WAF 指纹（Cloudflare/Akamai/ModSecurity/阿里云/腾讯云）
  2. CAPTCHA/行为验证存在性
  3. 速率限制响应头（X-RateLimit-* / Retry-After）
  4. 认证要求（401/403/登录页重定向）
  5. TLS/安全头配置（HSTS/CSP/X-Frame-Options）

产物: outputs/01_recon/defense_profile_{run_id}.json

设计约束：
  - 纯 HTTP 探测，不依赖 Playwright（轻量、快速）
  - 超时 5s，失败不阻断主流程
  - 检测结果写入 target dict，供 Stage1/Stage3 消费
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# WAF 指纹特征（响应头 + 响应体关键词）
_WAF_FINGERPRINTS: dict[str, dict[str, list[str]]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "body": ["cloudflare", "__cf_bm"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "body": ["akamai", "ak_bmsc"],
    },
    "ModSecurity": {
        "headers": ["server: mod_security"],
        "body": ["mod_security", "Mod_Security"],
    },
    "AWS_WAF": {
        "headers": ["x-amzn-waf-action", "x-amz-cf-id"],
        "body": ["awselb", "AWSELB"],
    },
    "Aliyun_WAF": {
        "headers": ["server: tengine<", "x-alicdn"],
        "body": ["aliyun", "安全拦截", "blocked by waf"],
    },
    "Tencent_Cloud_WAF": {
        "headers": ["x-waf-event-info", "server: tencent"],
        "body": ["腾讯云", "waf", "Tencent"],
    },
    "F5_ASM": {
        "headers": ["server: bigip"],
        "body": ["the requested url was rejected", "f5"],
    },
}

# CAPTCHA/行为验证检测特征
_CAPTCHA_INDICATORS = [
    "captcha", "recaptcha", "hcaptcha", "geetest",
    "slider", "验证码", "人机验证", "安全验证",
    "please verify", "are you human", "robot check",
]

# 安全响应头
_SECURITY_HEADERS = [
    "strict-transport-security",    # HSTS
    "content-security-policy",      # CSP
    "x-frame-options",              # Clickjacking
    "x-content-type-options",       # MIME sniffing
    "x-xss-protection",             # XSS filter
    "referrer-policy",              # Referrer
]

# 速率限制响应头
_RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit-requests",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-reset",
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
]


def probe_defenses(
    endpoint: str,
    target_url: str = "",
    timeout: float = 5.0,
) -> dict[str, Any]:
    """对目标端点执行防御前置探测

    :param endpoint: 目标 API endpoint URL
    :param target_url: 目标 Web URL（用于页面级检测，可选）
    :param timeout: 探测超时（秒）
    :returns: {
        "waf_detected": bool,
        "waf_type": str | None,
        "captcha_detected": bool,
        "rate_limits": dict,
        "auth_required": bool,
        "security_headers": dict,
        "recommendations": list[str],
        "latency_ms": int,
    }
    """
    import requests

    result: dict[str, Any] = {
        "waf_detected": False,
        "waf_type": None,
        "captcha_detected": False,
        "rate_limits": {},
        "auth_required": False,
        "security_headers": {},
        "recommendations": [],
        "latency_ms": 0,
    }

    # 探测 URL 列表：endpoint + target_url（如果有）
    probe_urls = [endpoint.rstrip("/")]
    if target_url and target_url != endpoint:
        probe_urls.append(target_url.rstrip("/"))

    start = time.time()
    for url in probe_urls:
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            result["latency_ms"] = max(result["latency_ms"], round((time.time() - start) * 1000))

            # 1. WAF 指纹检测
            waf = _detect_waf(resp)
            if waf and not result["waf_detected"]:
                result["waf_detected"] = True
                result["waf_type"] = waf
                result["recommendations"].append(
                    f"检测到 WAF: {waf}。建议降低 scan_profile 至 quick/smoke，"
                    "增加请求间隔，启用 jitter"
                )

            # 2. CAPTCHA 检测
            if _detect_captcha(resp):
                result["captcha_detected"] = True
                result["recommendations"].append(
                    "检测到 CAPTCHA/行为验证。需 Playwright 有头模式人工配合，"
                    "或配置 Cookie 认证绕过"
                )

            # 3. 速率限制头
            rl = _extract_rate_limits(resp)
            if rl:
                result["rate_limits"].update(rl)

            # 4. 认证要求
            if resp.status_code in (401, 403):
                result["auth_required"] = True
                result["recommendations"].append(
                    f"目标返回 HTTP {resp.status_code}，需要认证。"
                    "确保 Cookie/token 已配置"
                )

            # 5. 安全头
            sh = _check_security_headers(resp)
            if sh:
                result["security_headers"].update(sh)

        except requests.ConnectionError:
            logger.debug("防御探测: %s 连接失败", url)
        except requests.Timeout:
            logger.debug("防御探测: %s 超时", url)
        except Exception as exc:
            logger.debug("防御探测: %s 异常: %s", url, exc)

    # 综合建议
    if result["rate_limits"]:
        rpm = result["rate_limits"].get("x-ratelimit-limit-requests")
        if rpm:
            result["recommendations"].append(
                f"目标速率限制: {rpm} RPM。建议 max_rpm 设置为 {int(int(rpm) * 0.8)}（80% 容量）"
            )

    if not result["security_headers"].get("strict-transport-security"):
        result["recommendations"].append(
            "未检测到 HSTS 头，目标可能不支持 HTTPS。HTTP 下 Cookie 易被中间人截获"
        )

    return result


def _detect_waf(resp: Any) -> str | None:
    """从响应头和响应体检测 WAF 指纹

    :returns: WAF 名称或 None
    """
    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    body_lower = ""
    try:
        body_lower = resp.text[:5000].lower()
    except Exception:
        pass

    for waf_name, fingerprints in _WAF_FINGERPRINTS.items():
        # 检查响应头
        for header_pattern in fingerprints.get("headers", []):
            if ":" in header_pattern:
                key, val = header_pattern.split(":", 1)
                actual = headers_lower.get(key.strip(), "")
                if val.strip() in actual:
                    return waf_name
            elif header_pattern in headers_lower:
                return waf_name
        # 检查响应体
        for body_pattern in fingerprints.get("body", []):
            if body_pattern.lower() in body_lower:
                return waf_name

    return None


def _detect_captcha(resp: Any) -> bool:
    """检测响应中是否包含 CAPTCHA/行为验证"""
    body = ""
    try:
        body = resp.text[:5000].lower()
    except Exception:
        pass
    if not body:
        return False
    return any(indicator in body for indicator in _CAPTCHA_INDICATORS)


def _extract_rate_limits(resp: Any) -> dict[str, str]:
    """从响应头提取速率限制信息"""
    rl = {}
    for header in _RATE_LIMIT_HEADERS:
        val = resp.headers.get(header) or resp.headers.get(header.title())
        if val:
            rl[header] = val
    return rl


def _check_security_headers(resp: Any) -> dict[str, bool]:
    """检查安全响应头是否存在"""
    result = {}
    for header in _SECURITY_HEADERS:
        val = resp.headers.get(header) or resp.headers.get(header.title())
        result[header] = bool(val)
    return result


def apply_defense_recommendations(
    target: dict[str, Any],
    defense_profile: dict[str, Any],
    execute_cfg: dict[str, Any],
) -> dict[str, Any]:
    """根据防御探测结果自动调优执行参数

    :param target: 目标配置 dict
    :param defense_profile: probe_defenses() 的结果
    :param execute_cfg: 执行配置 dict
    :returns: 调优后的 execute_cfg（不修改原 dict）
    """
    cfg = dict(execute_cfg)
    rate_cfg = dict(cfg.get("rate_limit", {}))

    # WAF 存在时自动降速
    if defense_profile.get("waf_detected"):
        current_rpm = rate_cfg.get("max_rpm", 60)
        rate_cfg["max_rpm"] = max(10, int(current_rpm * 0.5))  # 降一半
        rate_cfg["base_delay"] = rate_cfg.get("base_delay", 1.0) * 2  # 加倍间隔
        rate_cfg["jitter"] = True
        rate_cfg["proactive_jitter"] = True
        rate_cfg["jitter_min"] = 0.5  # 更大抖动
        rate_cfg["jitter_max"] = 2.0
        logger.info(
            "WAF 检测到 %s：自动降速 max_rpm=%d, base_delay=%.1f, jitter=[0.5, (2.0]",
            defense_profile.get("waf_type"),
            rate_cfg["max_rpm"],
            rate_cfg["base_delay"],
        )

    # 从响应头动态设置 RPM
    rl = defense_profile.get("rate_limits", {})
    rpm_header = rl.get("x-ratelimit-limit-requests") or rl.get("ratelimit-limit")
    if rpm_header:
        try:
            dynamic_rpm = float(rpm_header)
            if dynamic_rpm > 0:
                # 取 80% 容量避免触发限流
                rate_cfg["max_rpm"] = min(rate_cfg.get("max_rpm", 60), int(dynamic_rpm * 0.8))
                logger.info("从响应头动态设置 max_rpm=%d（80%% of %d）",
                            rate_cfg["max_rpm"], int(dynamic_rpm))
        except (ValueError, TypeError):
            pass

    cfg["rate_limit"] = rate_cfg
    return cfg
