# -*- coding: utf-8 -*-
"""
AI-300 Framework - API Target Builder
REST API / SSE Chat 目标构建模块

职责：
- 构建 rest_api 类型目标（JSON 请求/响应，如 OWASP DonkAI）
- 构建 sse_chat 类型目标（SSE 流式响应，如 AIVP）
- 支持 URL 路径参数化（{lab_id}, {category_id} 等占位符）
- 支持认证流程（登录 → 获取 token → 注入到请求头）
- 集成响应解析器（JSON 字段提取 / SSE 内容拼接）

支持的两种靶机：

1. OWASP DonkAI (REST JSON)
   - POST /chat {message, user_id} → {response, session_id, vulnerability_detected}
   - POST /auth/login {username, password} → {token, user}
   - POST /challenges/{category_id}/attempt {challenge_id, payload, user_id}

2. AIVP (SSE Streaming)
   - POST /api/labs/{lab_id}/chat {prompt} → SSE data: {content: ...}
   - POST /api/secrets/validate {labId, answer} → {success, message}

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

from ..interactions.response_parser import ResponseParser, ResponseParserRegistry
from ...utils.async_helper import run_async

logger = logging.getLogger(__name__)


class ApiTargetConfig:
    """
    API 目标配置

    封装 REST API / SSE Chat 目标的完整配置。
    """

    def __init__(
        self,
        base_url: str,
        endpoint_path: str,
        method: str = "POST",
        request_body_template: str = '{"prompt": "{PROMPT}"}',
        content_type: str = "application/json",
        auth_token: Optional[str] = None,
        auth_header_name: str = "Authorization",
        auth_header_prefix: str = "Bearer ",
        extra_headers: Optional[Dict[str, str]] = None,
        use_tls: bool = False,
        response_format: str = "json",
        response_field: str = "response",
        url_params: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.endpoint_path = endpoint_path
        self.method = method.upper()
        self.request_body_template = request_body_template
        self.content_type = content_type
        self.auth_token = auth_token
        self.auth_header_name = auth_header_name
        self.auth_header_prefix = auth_header_prefix
        self.extra_headers = extra_headers or {}
        self.use_tls = use_tls
        self.response_format = response_format
        self.response_field = response_field
        self.url_params = url_params or {}
        self.cookies = cookies or {}

    def resolve_endpoint(self, params: Optional[Dict[str, str]] = None) -> str:
        """
        解析完整端点 URL（替换路径参数）

        Args:
            params: 额外的 URL 参数（覆盖默认值）

        Returns:
            完整端点 URL
        """
        merged = {**self.url_params, **(params or {})}
        path = self.endpoint_path
        for key, value in merged.items():
            path = path.replace(f"{{{key}}}", str(value))
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def build_headers(self) -> Dict[str, str]:
        """构建请求头"""
        headers = {"Content-Type": self.content_type}
        if self.auth_token:
            headers[self.auth_header_name] = self.auth_header_prefix + self.auth_token
        headers.update(self.extra_headers)
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = cookie_str
        return headers

    def build_body(self, prompt: str, params: Optional[Dict[str, str]] = None) -> str:
        """
        构建请求体（替换 {PROMPT} 和其他占位符）

        Args:
            prompt: 攻击载荷文本
            params: 额外占位符参数

        Returns:
            请求体字符串
        """
        body = self.request_body_template
        # JSON 转义 prompt 中的特殊字符
        escaped_prompt = json.dumps(prompt, ensure_ascii=False)[1:-1]
        body = body.replace("{PROMPT}", escaped_prompt)

        # 替换其他占位符
        merged = {**self.url_params, **(params or {})}
        for key, value in merged.items():
            body = body.replace(f"{{{key}}}", str(value))

        return body

    def get_response_parser(self) -> ResponseParser:
        """获取响应解析器"""
        return ResponseParser.create(
            format=self.response_format,
            field=self.response_field,
        )


class ApiTargetAdapter:
    """
    API 目标适配器

    将 ApiTargetConfig 转换为 PyRIT 可用的 PromptTarget。
    使用 requests/httpx 发送 HTTP 请求，返回解析后的纯文本响应。

    设计原则：
    - 薄壳模式：封装 HTTP 请求逻辑，返回纯文本供评分器使用
    - URL 参数化：支持运行时动态替换路径参数
    - 响应解析：自动解析 JSON/SSE 响应，提取内容字段
    - 认证注入：支持 Bearer Token / Cookie 认证
    """

    def __init__(self, config: ApiTargetConfig):
        self.config = config
        self._response_parser = config.get_response_parser()
        self._session: Optional[Any] = None

    def send_prompt(
        self,
        prompt: str,
        url_params: Optional[Dict[str, str]] = None,
        timeout: int = 60,
    ) -> str:
        """
        发送 prompt 到 API 端点并返回解析后的响应文本

        Args:
            prompt: 攻击载荷文本
            url_params: URL 路径参数（如 {"lab_id": "PI_01"}）
            timeout: 请求超时时间（秒）

        Returns:
            解析后的响应文本
        """
        import requests

        url = self.config.resolve_endpoint(url_params)
        headers = self.config.build_headers()
        body = self.config.build_body(prompt, url_params)

        logger.debug(
            "ApiTarget send: %s %s, body_len=%d",
            self.config.method, url, len(body),
        )

        try:
            response = requests.request(
                method=self.config.method,
                url=url,
                headers=headers,
                data=body.encode("utf-8") if isinstance(body, str) else body,
                timeout=timeout,
                verify=not self.config.use_tls or True,  # 实验环境允许自签证书
            )
            response.raise_for_status()
            raw_body = response.text
            parsed = self._response_parser.parse(raw_body)
            logger.debug("ApiTarget response: %d chars raw → %d chars parsed",
                         len(raw_body), len(parsed))
            return parsed
        except requests.exceptions.RequestException as e:
            logger.error("ApiTarget request failed: %s", e)
            return f"[API_TARGET_ERROR] {type(e).__name__}: {e}"
        except Exception as e:
            logger.error("ApiTarget unexpected error: %s", e)
            return f"[API_TARGET_ERROR] {type(e).__name__}: {e}"

    def send_prompt_async(
        self,
        prompt: str,
        url_params: Optional[Dict[str, str]] = None,
        timeout: int = 60,
    ):
        """异步发送 prompt（返回协程）"""
        return run_async(self._send_prompt_async(prompt, url_params, timeout))

    async def _send_prompt_async(
        self,
        prompt: str,
        url_params: Optional[Dict[str, str]],
        timeout: int,
    ) -> str:
        """异步发送 prompt 的内部实现"""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.send_prompt(prompt, url_params, timeout),
        )

    def validate_secret(
        self,
        lab_id: str,
        answer: str,
        validate_endpoint: str = "/api/secrets/validate",
        timeout: int = 10,
    ) -> tuple[bool, str]:
        """
        验证提取的 secret（AIVP 专用）

        Args:
            lab_id: Lab ID（如 "PI_01"）
            answer: 提取到的 secret
            validate_endpoint: 验证端点路径
            timeout: 超时时间

        Returns:
            (success, message)
        """
        import requests

        url = self.config.resolve_endpoint({})  # base_url
        url = urljoin(url + "/", validate_endpoint.lstrip("/"))

        try:
            response = requests.post(
                url,
                json={"labId": lab_id, "answer": answer},
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("success", False), data.get("message", "")
        except Exception as e:
            logger.error("Secret validation failed: %s", e)
            return False, str(e)


class AuthFlowExecutor:
    """
    认证流程执行器

    执行目标靶机的登录流程，获取认证 token。
    支持 OWASP DonkAI 的 /auth/login 端点。
    """

    @staticmethod
    def login(
        base_url: str,
        login_path: str = "/auth/login",
        username: str = "",
        password: str = "",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """
        执行登录流程

        Args:
            base_url: 目标基础 URL
            login_path: 登录端点路径
            username: 用户名
            password: 密码
            timeout: 超时时间

        Returns:
            登录响应字典（包含 token 和 user 信息）
        """
        import requests

        url = urljoin(base_url.rstrip("/") + "/", login_path.lstrip("/"))

        try:
            response = requests.post(
                url,
                json={"username": username, "password": password},
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            response.raise_for_status()
            data = response.json()
            logger.info("Auth flow success: user=%s", data.get("user", {}).get("username", "unknown"))
            return data
        except Exception as e:
            logger.error("Auth flow failed: %s", e)
            return {}

    @staticmethod
    def create_api_config_from_login(
        base_url: str,
        login_response: Dict[str, Any],
        endpoint_path: str,
        request_body_template: str,
        response_format: str = "json",
        response_field: str = "response",
        extra_url_params: Optional[Dict[str, str]] = None,
    ) -> ApiTargetConfig:
        """
        从登录响应创建 ApiTargetConfig

        Args:
            base_url: 目标基础 URL
            login_response: 登录响应（包含 token 和 user.id）
            endpoint_path: API 端点路径
            request_body_template: 请求体模板
            response_format: 响应格式
            response_field: 响应字段
            extra_url_params: 额外 URL 参数

        Returns:
            ApiTargetConfig 实例
        """
        token = login_response.get("token", "")
        user_id = login_response.get("user", {}).get("id", 1)

        # 将 user_id 注入到请求体模板
        body_template = request_body_template.replace("{user_id}", str(user_id))

        url_params = extra_url_params or {}

        return ApiTargetConfig(
            base_url=base_url,
            endpoint_path=endpoint_path,
            request_body_template=body_template,
            auth_token=token,
            response_format=response_format,
            response_field=response_field,
            url_params=url_params,
            extra_headers={"X-Auth-Token": token} if token else None,
        )


def build_api_target(target_config: Dict[str, Any]) -> ApiTargetAdapter:
    """
    从目标配置字典构建 API 目标适配器

    支持的配置格式：

    ```yaml
    target:
      type: rest_api  # 或 sse_chat
      base_url: "http://localhost:8000"
      endpoint_path: "/chat"  # 或 "/api/labs/{lab_id}/chat"
      method: POST
      request_body: '{"message": "{PROMPT}", "user_id": 1}'
      content_type: application/json
      use_tls: false
      response:
        format: json  # json / sse / text
        field: response  # JSON 字段名
      auth:
        type: login  # login / token / none
        login_path: /auth/login
        username: alice
        password: password123
      url_params:
        lab_id: PI_01  # 默认 URL 参数
    ```

    Args:
        target_config: 目标配置字典

    Returns:
        ApiTargetAdapter 实例
    """
    target = target_config.get("target", target_config)
    connection = target.get("connection", target)

    base_url = connection.get("base_url", connection.get("endpoint", "http://localhost:8000"))
    endpoint_path = connection.get("endpoint_path", connection.get("path", "/chat"))
    method = connection.get("method", "POST")
    request_body = connection.get("request_body", connection.get("body", '{"prompt": "{PROMPT}"}'))
    content_type = connection.get("content_type", "application/json")
    use_tls = connection.get("use_tls", False)

    # 响应解析配置
    response_config = connection.get("response", {})
    response_format = response_config.get("format", "sse" if target.get("type") == "sse_chat" else "json")
    response_field = response_config.get("field", "response")

    # URL 参数
    url_params = connection.get("url_params", {})

    # 认证配置
    auth_config = connection.get("auth", target.get("auth", {}))
    auth_token = ""
    extra_headers: Dict[str, str] = {}

    auth_type = auth_config.get("type", "none") if auth_config else "none"
    if auth_type == "login":
        # 执行登录流程
        login_response = AuthFlowExecutor.login(
            base_url=base_url,
            login_path=auth_config.get("login_path", "/auth/login"),
            username=auth_config.get("username", ""),
            password=auth_config.get("password", ""),
        )
        if login_response:
            auth_token = login_response.get("token", "")
            user_id = login_response.get("user", {}).get("id", 1)
            # 将 user_id 注入请求体
            request_body = request_body.replace("{user_id}", str(user_id))
            if auth_token:
                extra_headers["X-Auth-Token"] = auth_token
    elif auth_type == "token":
        auth_token = auth_config.get("token", "")
    elif auth_type == "bearer":
        auth_token = auth_config.get("token", "")
    elif auth_type == "cookie":
        cookie_name = auth_config.get("cookie_name", "session")
        cookie_value = auth_config.get("cookie_value", "")
        if cookie_value:
            extra_headers["Cookie"] = f"{cookie_name}={cookie_value}"

    config = ApiTargetConfig(
        base_url=base_url,
        endpoint_path=endpoint_path,
        method=method,
        request_body_template=request_body,
        content_type=content_type,
        auth_token=auth_token,
        use_tls=use_tls,
        response_format=response_format,
        response_field=response_field,
        url_params=url_params,
        extra_headers=extra_headers,
    )

    return ApiTargetAdapter(config)
