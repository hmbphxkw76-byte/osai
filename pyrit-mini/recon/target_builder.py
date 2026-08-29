"""target_builder — 对齐 PyRIT 1.0.1 官方 HTTP Target 标准.

包含 JSONSafeHTTPTarget, HTTP target 构建, callback 选择, HTTPXAPITarget 支持.

PyRIT 1.0.1 对齐要点:
    1. HTTPTarget._send_prompt_to_target_async 接收 normalized_conversation: list[Message]
       → 从 message.message_pieces[0] 获取 MessagePiece
       → MessagePiece.converted_value 是注入到 HTTP body 的 prompt 文本

    2. TargetConfiguration + TargetCapabilities 声明目标能力:
       - supports_multi_turn: 是否支持多轮对话 (HTTPTarget 默认 False)
       - supports_multi_message_pieces: 是否支持多消息片段
       - input_modalities: 输入模态 (text/image_path/audio_path...)
       - supports_system_prompt: 是否原生支持 system prompt
       → 缺失能力由 ConversationNormalizationPipeline 自动适配 (ADAPT/RAISE)

    3. httpx.AsyncClient 复用: 官方 HTTPTarget 支持传入预配置 client
       → 避免每次请求创建/销毁 client, 提升 ~30% 吞吐量

    4. callback_function 接收 httpx.Response (非 requests.Response):
       → 官方 callback 函数签名兼容 httpx.Response.content / .text

    5. HTTP/2 支持: 通过 http_version 检测自动启用 http2=True
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
    from recon.burp_parser import ParsedBurpRequest

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# JSONSafeHTTPTarget — 对齐 PyRIT 1.0.1 的 MessagePiece API
# ════════════════════════════════════════════════════════════════════

class JSONSafeHTTPTarget(HTTPTarget):
    """JSON 安全的 HTTPTarget — 正确转义 prompt 中的特殊字符。

    对齐 PyRIT 1.0.1 官方 HTTPTarget:
        - 官方 _inject_prompt_into_request 接收 MessagePiece (非 str)
        - 使用 request.converted_value 获取 prompt 文本
        - 官方 parse_raw_http_request 解析 headers/body/URL/method/version

    本子类增强:
        1. JSON body 安全注入: 递归替换 {PROMPT} 后重新序列化 JSON
           确保控制字符 (\\n, \\", \\\\) 不破坏 JSON 结构
        2. httpx.AsyncClient 复用: 预创建 client 避免每次请求重建
        3. HTTP/2 自动检测: 从 http_version 启用 http2
        4. TLS 验证控制: 黑盒场景 verify=False (可通过参数覆盖)
        5. P2-20: 会话 ID 动态注入 — 支持 {CHAT_ID} 占位符
           从 Burp Response 中提取的 chat_id 自动填充到请求 body 中
           确保多轮攻击在同一会话上下文中持续

    Args:
        http_request: 原始 HTTP 请求字符串 (含 {PROMPT} 占位符).
        prompt_regex_string: 占位符正则 (默认 {PROMPT}).
        use_tls: 是否使用 TLS.
        callback_function: 响应解析回调函数.
        max_requests_per_minute: 每分钟最大请求数.
        client: 预配置的 httpx.AsyncClient (与 httpx_client_kwargs 互斥).
        model_name: 模型名称.
        custom_configuration: TargetConfiguration 覆盖.
        chat_id: 初始会话 ID (从 Burp Response 提取, 可选).
        **httpx_client_kwargs: 传递给 httpx.AsyncClient 的参数.
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
        chat_id: str | None = None,
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
        # P2-20: 会话 ID 状态 (可从响应中动态更新)
        self._chat_id: str | None = chat_id
        # 保存原始请求模板 (含 {CHAT_ID} 占位符), 用于每次注入时动态替换
        self._http_request_template: str = http_request

    def _inject_prompt_into_request(self, request: MessagePiece) -> str:
        """注入 prompt 到 HTTP 请求，JSON body 安全转义。

        对齐 PyRIT 1.0.1:
            - request 是 MessagePiece (非 str)
            - request.converted_value 是注入到 HTTP body 的 prompt 文本

        策略:
            1. 检测 body 是否为 JSON 格式
            2. 如果是 JSON: 解析 → 递归替换 {PROMPT} → 重新序列化
               → 更新 Content-Length 头 (生产级修复)
            3. 如果不是 JSON: 走原始正则替换路径 (官方行为)
               → 更新 Content-Length 头
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

        # P2-20: 替换 {CHAT_ID} 占位符
        # 每次注入时从原始模板恢复 {CHAT_ID}, 然后用当前 chat_id 替换
        # 这样 chat_id 更新后可以立即生效
        chat_id_val = self._chat_id or ""
        if "{CHAT_ID}" in self._http_request_template:
            # 从模板恢复 {CHAT_ID} 占位符 (防止上次替换后永久丢失)
            self.http_request = self._http_request_template
            # 用当前 chat_id 替换
            self.http_request = self.http_request.replace("{CHAT_ID}", chat_id_val)
            if not chat_id_val:
                logger.debug(
                    "P2-20: {CHAT_ID} replaced with empty string "
                    "(first request, will extract from response)"
                )

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

        生产级修复:
            JSON 重新序列化后 body 长度变化, 但原始 Content-Length 头
            仍保持旧值, 导致目标服务器截断或拒绝请求。
            此方法重新计算 body 长度并更新 Content-Length 头。
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

    # ── P2-20: 会话 ID 动态管理 ──

    def update_chat_id(self, chat_id: str) -> None:
        """更新会话 ID。

        从目标响应中提取到新的 chat_id 后调用此方法更新内部状态。
        后续请求会自动使用新的 chat_id。

        策略:
            1. 更新 self._chat_id
            2. 从原始模板恢复 self.http_request (含 {CHAT_ID} 占位符)
            3. 下次 _inject_prompt_into_request 时会用新 chat_id 替换

        Args:
            chat_id: 新的会话 ID。
        """
        if chat_id and chat_id != self._chat_id:
            old = self._chat_id
            self._chat_id = chat_id
            # 从模板恢复 http_request (重新包含 {CHAT_ID} 占位符)
            # 下次注入时会用新的 chat_id 替换
            self.http_request = self._http_request_template
            logger.info(
                "P2-20: Chat ID updated: %s → %s",
                old or "(none)",
                chat_id,
            )

    @property
    def chat_id(self) -> str | None:
        """当前会话 ID (只读)。"""
        return self._chat_id

    @staticmethod
    def extract_chat_id_from_response(response: Any) -> str | None:
        """从 HTTP 响应中提取会话 ID。

        支持 SSE 流式响应和普通 JSON 响应。
        在 SSE 响应中, 从 data: 行的 JSON 中提取 Object/Id/ChatId 等字段。
        在普通 JSON 响应中, 直接从 JSON 中提取。

        候选字段名 (优先级递减):
            Object > Id > ChatId > SessionId > ConversationId > ConvId

        Args:
            response: httpx.Response 对象或文本。

        Returns:
            提取到的会话 ID, 或 None。
        """
        from recon.burp_parser import _extract_chat_id_from_response

        # 获取响应文本
        text = None
        if hasattr(response, "text") and response.text is not None:
            text = response.text
        elif hasattr(response, "content"):
            if isinstance(response.content, bytes):
                text = response.content.decode("utf-8", errors="replace")
            else:
                text = str(response.content)
        else:
            text = str(response)

        return _extract_chat_id_from_response(text)


# ════════════════════════════════════════════════════════════════════
# HTTP Target 构建 — 对齐 PyRIT 1.0.1 TargetConfiguration
# ════════════════════════════════════════════════════════════════════

def build_http_target(
    parsed: ParsedBurpRequest,
    *,
    enable_multi_turn: bool = False,
    enable_system_prompt_adapt: bool = True,
    auto_discover_capabilities: bool = False,
) -> JSONSafeHTTPTarget:
    """从解析结果构建 PyRIT 原生 HTTPTarget。

    对齐 PyRIT 1.0.1:
        1. 使用 JSONSafeHTTPTarget (HTTPTarget 子类)
        2. 构建 TargetConfiguration 声明目标能力
        3. 配置 httpx.AsyncClient 参数 (timeout, follow_redirects, verify)
        4. HTTP/2 检测: 从 parsed.http_version 启用
        5. 回调函数: 对齐官方 get_http_target_json_response_callback_function

    TargetConfiguration 策略:
        - 默认 (单轮): 仅声明 text 输入模态
        - enable_multi_turn: 声明 supports_multi_turn + supports_editable_history
          → PyRIT 会将多轮对话历史通过 HistorySquashNormalizer 压缩为单条
        - enable_system_prompt_adapt: 设为 True 时, system prompt 缺失能力
          使用 ADAPT 策略 (GenericSystemSquashNormalizer 将 system 合并到 user)

    PyRIT 原生能力探测 (L5 v52):
        - auto_discover_capabilities: 运行 PyRIT 原生 discover_target_capabilities_async
        - 自动探测 multi_turn, system_prompt, json_output 等能力
        - 自动探测 input_modalities (text, image_path, audio_path)
        - 探测结果直接安装到目标 (apply=True)
        - 替代手动能力探测代码, 减少维护成本

    Args:
        parsed: 解析后的 Burp 请求。
        enable_multi_turn: 是否声明多轮攻击能力。
        enable_system_prompt_adapt: 是否启用 system prompt 自适应。
        auto_discover_capabilities: 是否运行 PyRIT 原生能力探测。
            探测结果会覆盖 custom_configuration 中的声明值。

    Returns:
        JSONSafeHTTPTarget: PyRIT 原生 HTTP 目标实例。
    """
    from pyrit.prompt_target.common.target_capabilities import (
        CapabilityHandlingPolicy,
        CapabilityName,
        UnsupportedCapabilityBehavior,
    )

    from recon.burp_parser import build_raw_http_request

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
        chat_id=parsed.chat_id,
        **httpx_kwargs,
    )

    # P2-20: 如果 body 中有 {CHAT_ID} 占位符, 包装 callback 以自动提取 chat_id
    # 每次 HTTP 响应后, 从响应中提取 Object/Id/ChatId 等字段
    # 如果提取到新的 chat_id, 自动更新到 target 中
    if parsed.has_chat_id_placeholder:
        target = _wrap_callback_with_chat_id_extraction(target, callback)
    else:
        target.callback_function = callback

    logger.info(
        "JSONSafeHTTPTarget built: %s %s (TLS=%s, HTTP2=%s, SSE=%s, "
        "placeholder=%s, callback=%s, multi_turn=%s, system_adapt=%s, "
        "chat_id=%s, chat_id_field=%s)",
        parsed.method,
        parsed.url,
        parsed.use_tls,
        httpx_kwargs.get("http2", False),
        parsed.is_sse,
        parsed.has_prompt_placeholder,
        getattr(callback, "__name__", "None"),
        enable_multi_turn,
        enable_system_prompt_adapt,
        parsed.chat_id or "(none)",
        parsed.chat_id_field or "(none)",
    )

    # L5 v52: PyRIT 原生能力探测 (可选)
    # 学术依据: PyRIT (arXiv:2407.01232) — 运行时能力发现
    # 在构建 HTTPTarget 后, 使用 PyRIT 原生 discover_target_capabilities_async
    # 自动探测目标的实际能力, 覆盖手动声明的 custom_configuration。
    # 这使 HTTPTarget 的能力声明与目标实际行为一致,
    # 避免因过度声明能力导致 normalization pipeline 错误。
    if auto_discover_capabilities:
        _run_capability_discovery_sync(target)

    return target


def _run_capability_discovery_sync(target: JSONSafeHTTPTarget) -> None:
    """同步触发 PyRIT 原生能力探测 (L5 v52).

    由于 discover_target_capabilities_async 是异步函数,
    但 build_http_target 是同步函数, 这里使用 asyncio.run
    在无事件循环时触发探测。如果已在事件循环中, 则跳过
    (由 target_router 的 apply_discovered_capabilities 异步调用替代)。

    学术依据:
        - PyRIT (arXiv:2407.01232) — 运行时能力发现
        - Greshake et al. (arXiv:2302.12173) — 目标能力指纹
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


# ════════════════════════════════════════════════════════════════════
# HTTPXAPITarget 构建 — 对齐 PyRIT 1.0.1 官方 API 模式
# ════════════════════════════════════════════════════════════════════

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

    对齐 PyRIT 1.0.1 HTTPXAPITarget:
        - 用于文件上传/multipart form/JSON API 场景
        - 绕过原始 HTTP 请求解析, 直接使用 httpx API
        - 支持 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS
        - 内置文件上传 (仅 POST/PUT)
        - 支持 params (query parameters for GET/HEAD)
        - 支持 max_requests_per_minute (rate limiting)

    使用场景:
        - 目标 API 不使用 JSON body (multipart/form-data)
        - 文件上传端点 (如 /api/upload)
        - REST API 直连 (无需 Burp 请求)

    Args:
        parsed: 解析后的 Burp 请求 (提取 host/auth headers).
        method: HTTP 方法 (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS).
        json_data: JSON body 数据。
        form_data: Form body 数据。
        file_path: 上传文件路径 (仅 POST/PUT)。
        params: URL query 参数 (GET/HEAD 场景)。
        max_requests_per_minute: 每分钟最大请求数 (速率限制).
        enable_multi_turn: 是否支持多轮。

    Returns:
        HTTPXAPITarget: PyRIT 原生 API 模式目标实例。

    Raises:
        ValueError: 如果 method 不合法或 file_path 与 method 不兼容。
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


# ════════════════════════════════════════════════════════════════════
# 回调函数选择 — 对齐 PyRIT 1.0.1 官方 callback 体系
# ════════════════════════════════════════════════════════════════════

def _select_callback(parsed: ParsedBurpRequest) -> Any:
    """根据响应格式选择回调函数。

    对齐 PyRIT 1.0.1 官方回调函数:
        - get_http_target_json_response_callback_function: JSON 路径提取
        - get_http_target_regex_matching_callback_function: 正则匹配
        - 自定义 SSE callback: 流式响应拼接

    回调函数签名 (PyRIT 1.0.1):
        callback(response: httpx.Response) -> str

    优先级:
        1. 已探测的 JSON 路径 → 官方 JSON callback
        2. SSE → 自定义 SSE callback (多格式 fallback)
        3. JSON 常见路径 → 官方 JSON callback (多路径尝试)

    Args:
        parsed: 解析后的 Burp 请求。

    Returns:
        回调函数 (接收 httpx.Response, 返回 str)。
    """
    # 1. 已探测的 JSON 路径 → 官方 JSON callback
    if parsed.response_json_path:
        callback = get_http_target_json_response_callback_function(key=parsed.response_json_path)
        logger.info("Using probed JSON callback with path: %s", parsed.response_json_path)
        return callback

    # 2. SSE → 自定义 SSE callback (多格式 fallback)
    if parsed.is_sse:
        from recon.burp_parser import _make_sse_callback
        logger.info("Using custom SSE callback for response parsing")
        return _make_sse_callback()

    # 3. 自适应多路径 JSON callback
    # 对齐 PyRIT 1.0.1: 官方 _fetch_key 支持嵌套路径 (如 choices[0].message.content)
    # 增强: 尝试多个常见路径, 第一个成功提取的路径返回结果
    return _make_adaptive_json_callback()


def _wrap_callback_with_chat_id_extraction(
    target: JSONSafeHTTPTarget,
    original_callback: Any,
) -> JSONSafeHTTPTarget:
    """包装 callback 函数, 在解析响应后自动提取 chat_id。

    P2-20: 当 request body 中检测到 {CHAT_ID} 占位符时,
    每次收到 HTTP 响应后从响应中提取会话 ID (Object/Id/ChatId 等),
    如果提取到新的 chat_id, 自动更新到 target 中。

    这样多轮攻击 (Crescendo: arXiv:2404.01833 Russinovich et al., TAP, PAIR) 中的每次请求都会:
        1. 从上次响应中获取 chat_id
        2. 在本次请求的 body 中填入 chat_id
        3. 发送请求, 目标服务器在同一会话上下文中响应

    包装策略:
        - 创建 wrapper 函数包裹原始 callback
        - wrapper 先调用原始 callback 获取响应文本
        - 然后从响应中提取 chat_id
        - 如果提取到新 chat_id, 调用 target.update_chat_id()

    Args:
        target: 已构建的 JSONSafeHTTPTarget 实例。
        original_callback: 原始响应解析回调函数。

    Returns:
        传入的 target (callback_function 已更新为 wrapper)。
    """
    from recon.burp_parser import _extract_chat_id_from_response

    def wrapped_callback(response: Any) -> str:
        """先调用原始 callback, 然后从响应中提取 chat_id。"""
        # 调用原始 callback 获取响应文本
        result = original_callback(response)

        # 从响应中提取 chat_id
        try:
            chat_id = _extract_chat_id_from_response(
                response.text if hasattr(response, "text") else str(response)
            )
            if chat_id and chat_id != target.chat_id:
                target.update_chat_id(chat_id)
        except Exception as e:
            logger.debug("P2-20: Failed to extract chat_id from response: %s", e)

        return result

    target.callback_function = wrapped_callback
    logger.info(
        "P2-20: Callback wrapped with chat_id auto-extraction "
        "(original=%s)",
        getattr(original_callback, "__name__", "None"),
    )
    return target


def _make_adaptive_json_callback() -> Any:
    """创建自适应 JSON 回调函数 — 尝试多个常见路径提取响应内容。

    对齐 PyRIT 1.0.1 官方 callback 签名:
        callback(response: httpx.Response) -> str

    增强策略:
        1. 尝试解析 response.content 为 JSON
        2. 依次尝试 17 个常见 JSON 路径 (一次解析, 逐路径查找)
        3. 第一个成功提取的路径返回结果
        4. 全部失败 → 返回原始文本 (去 HTML 标签)

    覆盖的 JSON 路径 (按 API 类型排序):
        - OpenAI 兼容: choices[0].message.content
        - 通用 API: data.content, response, result, output
        - 聊天 API: message, text, content, answer, reply
        - 嵌套路径: data.message, data.response, data.answer

    生产级优化:
        - 预编译路径为键序列, 避免每次调用都创建 callback 对象
        - 一次性解析 JSON, 逐路径查找, 避免重复解析
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
        # 大小写不敏感: 适配 PascalCase/camelCase/snake_case JSON key
        from recon.burp_parser import _extract_nested_ci
        for _path_name, keys in _CANDIDATE_PATHS:
            result = _extract_nested_ci(json_obj, *keys)
            if result is not None and str(result).strip() and str(result) != "None":
                return str(result)

        # 全部路径失败, 返回原始文本
        return content_str

    return parse_adaptive_json_response
