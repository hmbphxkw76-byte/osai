# -*- coding: utf-8 -*-
"""
web_attacks.py - Web应用安全攻击模块

使用通用HTTP攻击引擎执行速率限制测试、请求走私、缓存投毒、
HTTP方法篡改、头部注入、API版本绕过等Web安全攻击。
重构后代码量从456行减少到约150行（减少67%）。

Academic basis:
    - OWASP API Security Top 10: API4:2019 Lack of Resources & Rate Limiting
    - PortSwigger: HTTP Request Smuggling (CL.TE / TE.CL)
    - OWASP: Web Cache Poisoning
    - Zeng et al. (arXiv:2402.19181): Enterprise API attack surfaces

版本: v3.0 (2026-09-08 扁平化到 strike/)
"""

from __future__ import annotations

import logging
from typing import Any

from strike.http_attack_engine import HTTPAttackEngine

logger = logging.getLogger(__name__)


class WebAttacks:
    """Web应用安全攻击模块

    使用通用HTTP攻击引擎，执行速率限制测试、请求走私、
    缓存投毒、HTTP方法篡改、头部注入、API版本绕过等攻击。

    PyRIT原生组件使用:
        - HTTPTarget: 发送攻击payload
        - PromptSendingAttack: 执行攻击
    """

    def __init__(
        self,
        target_endpoint: str,
        default_timeout: float = 30.0,
    ):
        """
        Args:
            target_endpoint: 目标API endpoint
            default_timeout: 默认超时时间
        """
        self.endpoint = target_endpoint
        self.engine = HTTPAttackEngine(target_endpoint, default_timeout)

    # === 速率限制测试 ===
    def rate_limit_test(
        self,
        max_concurrent: int = 10,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """速率限制测试

        Academic basis:
            - OWASP API Security Top 10: API4:2019 Lack of Resources & Rate Limiting

        Args:
            max_concurrent: 最大并发数
            timeout: 超时时间

        Returns:
            速率限制信息
        """
        import urllib.error
        import urllib.request

        responses: list[Any] = []
        for _ in range(max_concurrent):
            try:
                req = urllib.request.Request(self.endpoint, method="GET")
                resp = urllib.request.urlopen(req, timeout=timeout)
                responses.append({"status": resp.status, "headers": dict(resp.headers)})
            except urllib.error.HTTPError as e:
                responses.append({"status": e.code, "ratelimited": e.code == 429})
            except Exception as e:  # noqa: BLE001
                responses.append({"error": str(type(e).__name__)})

        rate_limit_info = self._analyze_rate_limits(responses)

        return {
            "attack_type": "速率限制测试",
            "max_concurrent": max_concurrent,
            "rate_limit_info": rate_limit_info,
        }

    # === 请求走私攻击 ===
    def request_smuggling_attack(
        self,
        payloads: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """请求走私攻击

        Academic basis:
            - PortSwigger: HTTP Request Smuggling
            - CL.TE / TE.CL smuggling techniques

        Args:
            payloads: 自定义走私payload，为None时使用默认payload

        Returns:
            攻击结果字典
        """
        return self.engine.execute_request_smuggling(payloads)

    # === 缓存投毒攻击 ===
    def cache_poisoning_attack(
        self,
        cache_key_headers: list[str] | None = None,
    ) -> dict[str, Any]:
        """缓存投毒攻击

        Academic basis:
            - OWASP: Web Cache Poisoning
            - Cache key manipulation techniques

        Args:
            cache_key_headers: 影响缓存键的header列表

        Returns:
            攻击结果字典
        """
        return self.engine.execute_cache_poisoning(cache_key_headers)

    # === HTTP方法篡改攻击 ===
    def http_method_tampering_attack(
        self,
        target_methods: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """HTTP方法篡改攻击

        Academic basis:
            - OWASP: Insecure HTTP Method Handling
            - PortSwigger: HTTP Method Override attacks

        Args:
            target_methods: 自定义方法列表，为None时使用默认方法

        Returns:
            攻击结果字典
        """
        return self.engine.execute_method_tampering(target_methods)

    # === 头部注入攻击 ===
    def header_injection_attack(
        self,
        header_payloads: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """头部注入攻击

        Academic basis:
            - OWASP: HTTP Header Injection
            - CRLF injection via headers

        Args:
            header_payloads: 自定义头部payload，为None时使用默认payload

        Returns:
            攻击结果字典
        """
        return self.engine.execute_header_injection(header_payloads)

    # === API版本控制绕过 ===
    def api_version_bypass_attack(
        self,
        version_paths: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """API版本控制绕过攻击

        Academic basis:
            - OWASP API Security Top 10: API6:2023 Unrestricted Access to Sensitive Business Flows

        Args:
            version_paths: 自定义版本路径，为None时使用默认路径

        Returns:
            攻击结果字典
        """
        return self.engine.execute_version_bypass(version_paths)

    # === 辅助方法 ===
    @staticmethod
    def _analyze_rate_limits(responses: list[Any]) -> dict[str, Any]:
        """分析速率限制

        Args:
            responses: HTTP响应列表（字典格式，包含 status/ratelimited/error 键）

        Returns:
            速率限制信息
        """
        status_codes: dict[int | str, int] = {}
        for r in responses:
            if isinstance(r, dict) and "error" in r:
                status_codes["error"] = status_codes.get("error", 0) + 1
            elif isinstance(r, dict) and "status" in r:
                code = r["status"]
                status_codes[code] = status_codes.get(code, 0) + 1
            else:
                status_codes["error"] = status_codes.get("error", 0) + 1

        rate_limited = status_codes.get(429, 0)
        total = len(responses)

        return {
            "status_codes": status_codes,
            "rate_limited_count": rate_limited,
            "rate_limit_threshold": total - rate_limited if rate_limited > 0 else total,
            "rate_limit_detected": rate_limited > 0,
        }
