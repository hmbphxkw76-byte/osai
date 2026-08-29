"""target_builder — 对齐 PyRIT 1.0.1 官方 HTTP Target 标准.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

import httpx
from pyrit.models import MessagePiece
from pyrit.prompt_target import (
    HTTPTarget,
    HTTPXAPITarget,
    TargetCapabilities,
    TargetConfiguration,
    get_http_target_json_response_callback_function,
)

if TYPE_CHECKING:
    from pipeline.recon.burp_parser import ParsedBurpRequest

logger = logging.getLogger(__name__)

# JSONSafeHTTPTarget — 对齐 PyRIT 1.0.1 的 MessagePiece API

class JSONSafeHTTPTarget(HTTPTarget):
    """JSON 安全的 HTTPTarget — 正确转义 prompt 中的特殊字符。
    """

    def __init__(
        self,
        *,
        http_request: str,
        prompt_regex_string: str = "{PROMPT}",
        use_tls: bool = True,
        callback_function: Any = None,
        max_requests_per_minute: int | None = None,
        client: httpx.AsyncClient | None = None,
        model_name: str = "",
        custom_configuration: TargetConfiguration | None = None,
        **httpx_client_kwargs: Any,
    ) -> None:
        super().__init__(
            http_request=http_request,
            prompt_regex_string=prompt_regex_string,
            use_tls=use_tls,
            callback_function=callback_function,
            max_requests_per_minute=max_requests_per_minute,
            client=client,
            model_name=model_name,
            custom_configuration=custom_configuration,
            **httpx_client_kwargs,
        )

    def _inject_prompt_into_request(self, request: MessagePiece) -> str:
        """注入 prompt 到 HTTP 请求，JSON body 安全转义。
        """
        re_pattern = re.compile(self.prompt_regex_string)
        if not re.search(self.prompt_regex_string, self.http_request):
            return self.http_request

        # 获取 prompt 文本 — 对齐 PyRIT 1.0.1 MessagePiece API
        # 生产级防护: converted_value 可能为 None (空消息片段)
        prompt_text = request.converted_value
        if prompt_text is None:
            prompt_text = ""
        else:
            prompt_text = str(prompt_text)

        # 尝试 JSON 安全注入
        normalized = self.http_request.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)
        if len(parts) < 2 or not parts[1].strip():
            # 无 body，走原始路径
            injected = re_pattern.sub(lambda m: prompt_text, self.http_request)
            return self._update_content_length(injected)

        body_text = parts[1]

        # 尝试解析为 JSON
        try:
            body_obj = json.loads(body_text)
        except (json.JSONDecodeError, TypeError):
            # 非 JSON body，走原始路径 (官方行为)
            injected = re_pattern.sub(lambda m: prompt_text, self.http_request)
            return self._update_content_length(injected)

        # JSON body: 递归替换所有 {PROMPT} 值
        def _replace_in_obj(obj: Any) -> Any:
            if isinstance(obj, str):
                if obj == "{PROMPT}":
                    return prompt_text
                return obj.replace("{PROMPT}", prompt_text)
            elif isinstance(obj, dict):
                return {k: _replace_in_obj(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_replace_in_obj(item) for item in obj]
            return obj

        body_replaced = _replace_in_obj(body_obj)
        new_body = json.dumps(body_replaced, ensure_ascii=False)

        # 重建 HTTP 请求 (保持 CRLF 格式)
        raw_headers = parts[0].replace("\n", "\r\n")
        result = raw_headers + "\r\n\r\n" + new_body

        # 生产级修复: 更新 Content-Length 头以匹配新 body 长度
        return self._update_content_length(result)

    @staticmethod
    def _update_content_length(http_request: str) -> str:
        """更新 HTTP 请求中的 Content-Length 头以匹配实际 body 长度。
        """
        normalized = http_request.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        body_bytes_len = len(body.encode("utf-8"))

        header_lines = header_section.split("\n")
        updated_lines: list[str] = []
        found_cl = False
        for line in header_lines:
            if line.lower().startswith("content-length:"):
                updated_lines.append(f"Content-Length: {body_bytes_len}")
                found_cl = True
            else:
                updated_lines.append(line)

        # 如果没有 Content-Length 头且有 body, 添加一个
        if not found_cl and body:
            updated_lines.append(f"Content-Length: {body_bytes_len}")

        result = "\r\n".join(updated_lines)
        if body:
            result += "\r\n\r\n" + body
        else:
            result += "\r\n\r\n"
        return result

# HTTP Target 构建 — 对齐 PyRIT 1.0.1 TargetConfiguration

def build_http_target(
    parsed: ParsedBurpRequest,
    *,
    enable_multi_turn: bool = False,
    enable_system_prompt_adapt: bool = True,
    auto_discover_capabilities: bool = False,
) -> JSONSafeHTTPTarget:
    """从解析结果构建 PyRIT 原生 HTTPTarget。
    """
    from pyrit.prompt_target.common.target_capabilities import (
        CapabilityHandlingPolicy,
        CapabilityName,
        UnsupportedCapabilityBehavior,
    )

    from pipeline.recon.burp_parser import build_raw_http_request

    raw_request = build_raw_http_request(parsed)
    callback = _select_callback(parsed)

    # 构建 httpx.AsyncClient 参数
    httpx_kwargs: dict[str, Any] = {
        "timeout": 120.0,
        "follow_redirects": True,
        "verify": False,  # 黑盒场景: 跳过 TLS 验证
    }

    # HTTP/2 检测
    if parsed.http_version and "HTTP/2" in parsed.http_version:
        httpx_kwargs["http2"] = True

    # 构建 TargetConfiguration
    if enable_multi_turn:
        # 多轮: 声明 multi_turn + editable_history
        # system_prompt 使用 ADAPT 策略 (GenericSystemSquashNormalizer)
        policy = CapabilityHandlingPolicy(
            behaviors={
                CapabilityName.SYSTEM_PROMPT: UnsupportedCapabilityBehavior.ADAPT,
                CapabilityName.MULTI_TURN: UnsupportedCapabilityBehavior.RAISE,
                CapabilityName.JSON_SCHEMA: UnsupportedCapabilityBehavior.ADAPT,
            }
        ) if enable_system_prompt_adapt else CapabilityHandlingPolicy()

        custom_config = TargetConfiguration(
            capabilities=TargetCapabilities(
                supports_multi_turn=True,
                supports_editable_history=True,
                input_modalities=frozenset({frozenset({"text"})}),
            ),
            policy=policy,
        )
    else:
        # 单轮: 仅声明 text 输入
        # system_prompt 缺失时用 ADAPT 策略 (squash 到 user)
        policy = CapabilityHandlingPolicy(
            behaviors={
                CapabilityName.SYSTEM_PROMPT: UnsupportedCapabilityBehavior.ADAPT,
                CapabilityName.MULTI_TURN: UnsupportedCapabilityBehavior.RAISE,
                CapabilityName.JSON_SCHEMA: UnsupportedCapabilityBehavior.ADAPT,
            }
        ) if enable_system_prompt_adapt else None

        custom_config = TargetConfiguration(
            capabilities=TargetCapabilities(
                input_modalities=frozenset({frozenset({"text"})}),
            ),
            policy=policy,
        ) if enable_system_prompt_adapt else None

    target = JSONSafeHTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        callback_function=callback,
        use_tls=parsed.use_tls,
        custom_configuration=custom_config,
        **httpx_kwargs,
    )

    logger.info(
        "JSONSafeHTTPTarget built: %s %s (TLS=%s, HTTP2=%s, SSE=%s, "
        "placeholder=%s, callback=%s, multi_turn=%s, system_adapt=%s)",
        parsed.method,
        parsed.url,
        parsed.use_tls,
        httpx_kwargs.get("http2", False),
        parsed.is_sse,
        parsed.has_prompt_placeholder,
        getattr(callback, "__name__", "None"),
        enable_multi_turn,
        enable_system_prompt_adapt,
    )

    # L5 v52: PyRIT 原生能力探测 (可选)
    # 在构建 HTTPTarget 后, 使用 PyRIT 原生 discover_target_capabilities_async
    # 自动探测目标的实际能力, 覆盖手动声明的 custom_configuration。
    # 这使 HTTPTarget 的能力声明与目标实际行为一致,
    # 避免因过度声明能力导致 normalization pipeline 错误。
    if auto_discover_capabilities:
        _run_capability_discovery_sync(target)

    return target

def _run_capability_discovery_sync(target: JSONSafeHTTPTarget) -> None:
    """同步触发 PyRIT 原生能力探测 (L5 v52).
    """
    try:
        import asyncio

        # 检查是否已在事件循环中
        try:
            asyncio.get_running_loop()
            # 已在事件循环中, 跳过同步探测
            # 异步探测由 RateLimitedTarget.apply_discovered_capabilities 处理
            logger.debug(
                "L5 v52: Skipping sync capability discovery "
                "(event loop already running); "
                "use RateLimitedTarget.apply_discovered_capabilities() instead"
            )
            return
        except RuntimeError:
            pass

        # 无事件循环, 安全使用 asyncio.run
        asyncio.run(_async_discover_capabilities(target))
    except Exception as e:
        logger.debug("L5 v52: Sync capability discovery skipped: %s", e)

async def _async_discover_capabilities(target: JSONSafeHTTPTarget) -> None:
    """异步运行 PyRIT 原生能力探测 (L5 v52)."""
    try:
        from pyrit.prompt_target.common.discover_target_capabilities import (
            discover_target_capabilities_async,
        )

        logger.info(
            "L5 v52: Running PyRIT native capability discovery on %s",
            type(target).__name__,
        )
        discovered = await discover_target_capabilities_async(
            target=target,
            per_probe_timeout_s=15.0,
            retries=1,
            apply=True,
        )
        logger.info(
            "L5 v52: Discovered: multi_turn=%s, system_prompt=%s, "
            "json_output=%s, input_modalities=%s",
            discovered.supports_multi_turn,
            discovered.supports_system_prompt,
            discovered.supports_json_output,
            [sorted(s) for s in sorted(discovered.input_modalities)],
        )
    except Exception as e:
        logger.warning(
            "L5 v52: Native capability discovery failed (non-fatal): %s", e
        )

# HTTPXAPITarget 构建 — 对齐 PyRIT 1.0.1 官方 API 模式

def build_httpx_api_target(
    parsed: ParsedBurpRequest,
    *,
    method: str = "POST",
    json_data: dict[str, Any] | None = None,
    form_data: dict[str, Any] | None = None,
    file_path: str | None = None,
    params: dict[str, Any] | None = None,
    max_requests_per_minute: int | None = None,
    enable_multi_turn: bool = False,
) -> HTTPXAPITarget:
    """构建 PyRIT 1.0.1 原生 HTTPXAPITarget — API 模式 (无原始 HTTP 请求)。
    """
    # 生产级验证: HTTP method 合法性
    _VALID_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
    method_upper = method.upper().strip()
    if method_upper not in _VALID_METHODS:
        raise ValueError(
            f"Invalid HTTP method '{method}'. "
            f"Valid methods: {sorted(_VALID_METHODS)}"
        )

    # 生产级验证: file_path 仅允许 POST/PUT
    if file_path and method_upper not in ("POST", "PUT"):
        raise ValueError(
            f"File upload requires POST or PUT, got {method_upper}"
        )

    # 生产级验证: json_data + form_data 互斥
    if json_data is not None and form_data is not None:
        raise ValueError("json_data and form_data are mutually exclusive")

    scheme = "https" if parsed.use_tls else "http"
    http_url = f"{scheme}://{parsed.host}{parsed.path}"

    # 提取认证相关 headers
    headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host", "content-type"):
            headers[key] = value

    # 构建 TargetConfiguration
    custom_config = None
    if enable_multi_turn:
        from pyrit.prompt_target.common.target_capabilities import (
            CapabilityHandlingPolicy,
            CapabilityName,
            UnsupportedCapabilityBehavior,
        )
        custom_config = TargetConfiguration(
            capabilities=TargetCapabilities(
                supports_multi_turn=True,
                supports_editable_history=True,
                input_modalities=frozenset({
                    frozenset({"text"}),
                    frozenset({"image_path"}),
                    frozenset({"text", "image_path"}),
                }),
            ),
            policy=CapabilityHandlingPolicy(
                behaviors={
                    CapabilityName.SYSTEM_PROMPT: UnsupportedCapabilityBehavior.ADAPT,
                }
            ),
        )

    target = HTTPXAPITarget(
        http_url=http_url,
        method=method_upper,
        file_path=file_path,
        json_data=json_data,
        form_data=form_data,
        params=params,
        headers=headers,
        http2="HTTP/2" in (parsed.http_version or ""),
        callback_function=_select_callback(parsed),
        max_requests_per_minute=max_requests_per_minute,
        custom_configuration=custom_config,
        timeout=120.0,
        verify=False,
    )

    logger.info(
        "HTTPXAPITarget built: %s %s (method=%s, file=%s, json=%s, form=%s, multi_turn=%s)",
        parsed.url,
        http_url,
        method,
        file_path is not None,
        json_data is not None,
        form_data is not None,
        enable_multi_turn,
    )
    return target

# 回调函数选择 — 对齐 PyRIT 1.0.1 官方 callback 体系

def _select_callback(parsed: ParsedBurpRequest) -> Any:
    """根据响应格式选择回调函数。
    """
    # 1. 已探测的 JSON 路径 → 官方 JSON callback
    if parsed.response_json_path:
        callback = get_http_target_json_response_callback_function(key=parsed.response_json_path)
        logger.info("Using probed JSON callback with path: %s", parsed.response_json_path)
        return callback

    # 2. SSE → 自定义 SSE callback (多格式 fallback)
    if parsed.is_sse:
        from pipeline.recon.burp_parser import _make_sse_callback
        logger.info("Using custom SSE callback for response parsing")
        return _make_sse_callback()

    # 3. 自适应多路径 JSON callback
    # 对齐 PyRIT 1.0.1: 官方 _fetch_key 支持嵌套路径 (如 choices[0].message.content)
    # 增强: 尝试多个常见路径, 第一个成功提取的路径返回结果
    return _make_adaptive_json_callback()

def _make_adaptive_json_callback() -> Any:
    """创建自适应 JSON 回调函数 — 尝试多个常见路径提取响应内容。
    """
    # 候选 JSON 路径 (按 API 类型优先级排序)
    # 每个路径预编译为键序列, 便于快速查找
    _CANDIDATE_PATHS: list[tuple[str, tuple[Any, ...]]] = [
        ("choices[0].message.content", ("choices", 0, "message", "content")),
        ("choices[0].delta.content", ("choices", 0, "delta", "content")),
        ("data.content", ("data", "content")),
        ("data.choices[0].message.content", ("data", "choices", 0, "message", "content")),
        ("response", ("response",)),
        ("result", ("result",)),
        ("output", ("output",)),
        ("message", ("message",)),
        ("text", ("text",)),
        ("content", ("content",)),
        ("answer", ("answer",)),
        ("reply", ("reply",)),
        ("data.message", ("data", "message")),
        ("data.response", ("data", "response")),
        ("data.answer", ("data", "answer")),
        ("data.text", ("data", "text")),
        ("data.output", ("data", "output")),
        ("data.result", ("data", "result")),
    ]

    def parse_adaptive_json_response(response: Any) -> str:
        """自适应 JSON 响应解析 — 一次解析, 逐路径查找。"""
        # 获取响应内容
        content = None
        if hasattr(response, "content"):
            content = response.content
        elif hasattr(response, "text"):
            content = response.text
        else:
            content = str(response)

        if not content:
            return ""

        # 解码 bytes
        if isinstance(content, bytes):
            content_str = content.decode("utf-8", errors="replace")
        else:
            content_str = str(content)

        # 尝试解析为 JSON (只解析一次)
        try:
            json_obj = json.loads(content_str)
        except (json.JSONDecodeError, TypeError):
            # 非 JSON 响应, 直接返回原始文本
            return content_str

        # 生产级优化: 一次解析, 逐路径查找 (避免重复创建 callback 对象)
        from pipeline.recon.burp_parser import _extract_nested
        for _path_name, keys in _CANDIDATE_PATHS:
            result = _extract_nested(json_obj, *keys)
            if result is not None and str(result).strip() and str(result) != "None":
                return str(result)

        # 全部路径失败, 返回原始文本
        return content_str

    return parse_adaptive_json_response
