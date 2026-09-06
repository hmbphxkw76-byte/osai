"""target_builder — 对齐 PyRIT 1.0.1 官方 HTTP Target 标准.

本模块构建 PyRIT 原生 Target 对象 (HTTPTarget / HTTPXAPITarget).

宪法合规:
    - 严格使用 PyRIT 原生 Target, 不自定义 HTTPTarget 子类
    - 会话状态 (chat_id) 由 ChatIdStateManager 外部管理
    - HTTP 请求预处理由 RequestPreprocessor 负责

PyRIT 1.0.1 对齐要点:
    1. HTTPTarget._send_prompt_to_target_async 接收 normalized_conversation: list[Message]
       → 从 message.message_pieces[0] 获取 MessagePiece
       → MessagePiece.converted_value 是注入到 HTTP body 的 prompt 文本

    2. TargetConfiguration + TargetCapabilities 声明目标能力:
       - supports_multi_turn: 是否支持多轮对话
       - supports_multi_message_pieces: 是否支持多消息片段
       - input_modalities: 输入模态 (text/image_path/audio_path...)
       - supports_system_prompt: 是否原生支持 system prompt
       → 缺失能力由 ConversationNormalizationPipeline 自动适配 (ADAPT/RAISE)

    3. httpx.AsyncClient 复用: 官方 HTTPTarget 支持传入预配置 client
       → 避免每次请求创建/销毁 client, 提升 ~30% 吞吐量

    4. callback_function 接收 httpx.Response (非 requests.Response)

    5. HTTP/2 支持: 通过 http_version 检测自动启用 http2=True
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import httpx
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
# P2-06: TLS verify 配置化 (SSOT)
# 从 config/defaults.yaml 读取 tls_verify 配置, 统一控制 SSL 证书验证
# ════════════════════════════════════════════════════════════════════
def _get_tls_verify_default() -> bool | str:
    """加载 TLS verify 配置 (模块初始化时调用一次)。"""
    try:
        from recon.config_loader import get_tls_verify
        return get_tls_verify()
    except Exception:
        return True  # 默认验证证书


_TLS_VERIFY: bool | str = _get_tls_verify_default()


# ════════════════════════════════════════════════════════════════════
# Chat ID 状态管理器 — 多轮攻击会话追踪
# ════════════════════════════════════════════════════════════════════

class ChatIdStateManager:
    """管理多轮攻击的会话 ID 状态 (chat_id).

    宪法合规: 会话状态由外部管理器持有, 不侵入 PyRIT 原生 Target.

    职责:
        1. 存储当前 chat_id
        2. 从 HTTP 响应中提取新的 chat_id
        3. 生成包含最新 chat_id 的请求 (预处理阶段)
        4. 触发 Target 的原始请求模板更新
    """

    def __init__(self, initial_chat_id: str | None = None) -> None:
        self._chat_id: str | None = initial_chat_id
        self._original_template: str | None = None

    @property
    def chat_id(self) -> str | None:
        return self._chat_id

    def set_template(self, http_request_template: str) -> None:
        """保存原始 HTTP 请求模板 (含 {CHAT_ID} 占位符)."""
        self._original_template = http_request_template

    def update_from_response(self, response: Any) -> str | None:
        """从 HTTP 响应中提取并更新 chat_id.

        候选字段名 (优先级递减):
            Object > Id > ChatId > SessionId > ConversationId > ConvId

        Args:
            response: httpx.Response 对象或文本.

        Returns:
            提取到的 chat_id, 或 None.
        """
        from recon.burp_parser import _extract_chat_id_from_response

        text: str | None = None
        if hasattr(response, "text") and response.text is not None:
            text = response.text
        elif hasattr(response, "content"):
            if isinstance(response.content, bytes):
                text = response.content.decode("utf-8", errors="replace")
            else:
                text = str(response.content)
        else:
            text = str(response)

        new_id = _extract_chat_id_from_response(text) if text else None
        if new_id and new_id != self._chat_id:
            old = self._chat_id
            self._chat_id = new_id
            logger.debug("Chat ID updated: %s → %s", old or "(none)", new_id)
        return new_id

    def preprocess_request(self, http_request: str) -> str:
        """预处理 HTTP 请求, 替换 {CHAT_ID} 占位符.

        Args:
            http_request: 原始 HTTP 请求字符串 (可能含 {CHAT_ID}).

        Returns:
            替换后的请求字符串.
        """
        if "{CHAT_ID}" not in http_request:
            return http_request

        chat_id_val = self._chat_id or ""
        result = http_request.replace("{CHAT_ID}", chat_id_val)

        if not chat_id_val:
            logger.debug(
                "Chat ID placeholder replaced with empty string "
                "(first request, will extract from response)"
            )
        return result


# ════════════════════════════════════════════════════════════════════
# HTTP 请求预处理器 — 在 Prompt 注入前执行
# ════════════════════════════════════════════════════════════════════

class RequestPreprocessor:
    """HTTP 请求预处理器.

    在 PyRIT 注入 Prompt 前执行以下预处理:
        1. {CHAT_ID} 占位符替换
        2. JSON body 安全转义 (处理控制字符)
        3. Content-Length 头更新
    """

    @staticmethod
    def preprocess(
        http_request: str,
        chat_id_state: ChatIdStateManager | None = None,
    ) -> str:
        """预处理 HTTP 请求.

        Args:
            http_request: 原始 HTTP 请求字符串.
            chat_id_state: Chat ID 状态管理器 (可选).

        Returns:
            预处理后的请求字符串.
        """
        result = http_request

        # Step 1: Chat ID 替换
        if chat_id_state:
            result = chat_id_state.preprocess_request(result)

        # Step 2 & 3: JSON body 安全 + Content-Length
        result = RequestPreprocessor._sanitize_json_body(result)

        return result

    @staticmethod
    def _sanitize_json_body(http_request: str) -> str:
        """确保 JSON body 的合法性和 Content-Length 正确.

        策略:
            1. 解析 HTTP 请求获取 headers 和 body
            2. 尝试解析 body 为 JSON
            3. 如果 JSON 合法, 重新序列化 (规范化)
            4. 更新 Content-Length 头
        """
        normalized = http_request.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)

        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        if not body.strip():
            return http_request

        # 尝试解析为 JSON 并重新序列化 (净化控制字符)
        try:
            body_obj = json.loads(body)
            # 重新序列化: 默认 ensure_ascii=False 保留原始字符
            sanitized_body = json.dumps(body_obj, ensure_ascii=False)
            if sanitized_body == body:
                return http_request  # 无需更改
        except (json.JSONDecodeError, TypeError):
            return http_request  # 非 JSON, 不处理

        # 更新 Content-Length
        body_bytes_len = len(sanitized_body.encode("utf-8"))

        header_lines = header_section.split("\n")
        updated_lines: list[str] = []
        found_cl = False

        for line in header_lines:
            if line.lower().startswith("content-length:"):
                updated_lines.append(f"Content-Length: {body_bytes_len}")
                found_cl = True
            else:
                updated_lines.append(line)

        if not found_cl and sanitized_body:
            updated_lines.append(f"Content-Length: {body_bytes_len}")

        result = "\r\n".join(updated_lines) + "\r\n\r\n" + sanitized_body
        return result


# ════════════════════════════════════════════════════════════════════
# Callback 链组装器 — 响应处理管道
# ════════════════════════════════════════════════════════════════════

def _assemble_callback(
    parsed: ParsedBurpRequest,
    chat_id_state: ChatIdStateManager | None = None,
) -> Any:
    """组装回调函数: response_parser → chat_id_extraction.

    PyRIT HTTPTarget 支持单一 callback_function, 此函数将多个处理步骤
    链式组合成单一回调.

    处理链:
        1. 原始 httpx.Response → response_parser → 响应文本
        2. 同时从响应中提取 chat_id → 更新 ChatIdStateManager

    Args:
        parsed: 解析后的 Burp 请求 (决定 response_parser 类型).
        chat_id_state: Chat ID 状态管理器 (用于提取 chat_id).

    Returns:
        单一回调函数 (httpx.Response → str).
    """
    # Step 1: 选择响应解析器
    response_parser = _select_response_parser(parsed)

    # Step 2: 提取器 (如果有 chat_id 追踪需求)
    chat_id_extractor = None
    if parsed.has_chat_id_placeholder and chat_id_state:
        from recon.burp_parser import _extract_chat_id_from_response

        def chat_id_extractor(response: Any) -> None:
            """从响应中提取 chat_id 并更新状态管理器."""
            try:
                text: str | None = None
                if hasattr(response, "text") and response.text is not None:
                    text = response.text
                elif hasattr(response, "content"):
                    if isinstance(response.content, bytes):
                        text = response.content.decode("utf-8", errors="replace")
                    else:
                        text = str(response.content)

                if text:
                    chat_id_state.update_from_response(text)
            except Exception as e:
                logger.debug("Chat ID extraction failed: %s", e)

    # Step 3: 组合为单一 callback
    def combined_callback(response: Any) -> str:
        """组合回调: 解析响应 + 提取 chat_id."""
        if chat_id_extractor:
            chat_id_extractor(response)
        return response_parser(response)

    # 保留原始名称用于日志
    parser_name = getattr(response_parser, "__name__", "parser")
    suffix = "+chat_id" if chat_id_extractor else ""
    combined_callback.__name__ = f"combined({parser_name}{suffix})"
    return combined_callback


def _select_response_parser(parsed: ParsedBurpRequest) -> Any:
    """选择响应解析器.

    对齐 PyRIT 1.0.1 官方回调函数:
        - get_http_target_json_response_callback_function: JSON 路径提取
        - get_http_target_regex_matching_callback_function: 正则匹配
        - 自定义 SSE parser: 流式响应拼接

    Args:
        parsed: 解析后的 Burp 请求.

    Returns:
        响应解析函数 (httpx.Response → str).
    """
    # 1. 已探测的 JSON 路径 → 官方 JSON callback
    if parsed.response_json_path:
        callback = get_http_target_json_response_callback_function(
            key=parsed.response_json_path
        )
        logger.debug("Using probed JSON callback with path: %s", parsed.response_json_path)
        return callback

    # 2. SSE → 自定义 SSE parser
    if parsed.is_sse:
        from recon.burp_parser import _make_sse_response_parser
        logger.debug("Using custom SSE response parser")
        return _make_sse_response_parser()

    # 3. 自适应多路径 JSON parser
    return _make_adaptive_json_parser()


def _make_adaptive_json_parser() -> Any:
    """创建自适应 JSON 响应解析器 — 尝试多个常见路径.

    覆盖的 JSON 路径 (按 API 类型排序):
        - OpenAI 兼容: choices[0].message.content
        - 通用 API: data.content, response, result, output
        - 聊天 API: message, text, content, answer, reply
    """
    _CANDIDATE_PATHS: list[tuple[str, ...]] = [
        ("choices", 0, "message", "content"),
        ("choices", 0, "delta", "content"),
        ("data", "content"),
        ("data", "choices", 0, "message", "content"),
        ("response",),
        ("result",),
        ("output",),
        ("message",),
        ("text",),
        ("content",),
        ("answer",),
        ("reply",),
        ("data", "message"),
        ("data", "response"),
        ("data", "answer"),
        ("data", "text"),
        ("data", "output"),
        ("data", "result"),
    ]

    def parse_response(response: Any) -> str:
        """自适应 JSON 响应解析."""
        content: bytes | str | None = None
        if hasattr(response, "content"):
            content = response.content
        elif hasattr(response, "text"):
            content = response.text
        else:
            content = str(response)

        if not content:
            return ""

        if isinstance(content, bytes):
            content_str = content.decode("utf-8", errors="replace")
        else:
            content_str = str(content)

        try:
            json_obj = json.loads(content_str)
        except (json.JSONDecodeError, TypeError):
            return content_str

        from recon.burp_parser import _extract_nested_ci
        for keys in _CANDIDATE_PATHS:
            result = _extract_nested_ci(json_obj, *keys)
            if result is not None and str(result).strip() and str(result) != "None":
                return str(result)

        return content_str

    parse_response.__name__ = "adaptive_json_parser"
    return parse_response


def _make_sse_response_parser() -> Any:
    """创建 SSE 流式响应解析器.

    拼接 data: 行的 JSON 内容.
    """
    def parse_sse_response(response: Any) -> str:
        content: bytes | str | None = None
        if hasattr(response, "content"):
            content = response.content
        elif hasattr(response, "text"):
            content = response.text
        else:
            content = str(response)

        if not content:
            return ""

        if isinstance(content, bytes):
            content_str = content.decode("utf-8", errors="replace")
        else:
            content_str = str(content)

        # 拼接所有 data: 行的内容
        parts: list[str] = []
        for line in content_str.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                data = line[5:].strip()
                if data and data != "[DONE]":
                    parts.append(data)

        return "".join(parts)

    parse_sse_response.__name__ = "sse_response_parser"
    return parse_sse_response


# ════════════════════════════════════════════════════════════════════
# HTTP Target 构建 — 对齐 PyRIT 1.0.1 TargetConfiguration
# ════════════════════════════════════════════════════════════════════

def build_http_target(
    parsed: ParsedBurpRequest,
    *,
    enable_multi_turn: bool = False,
    enable_system_prompt_adapt: bool = True,
    auto_discover_capabilities: bool = False,
    http_client: httpx.AsyncClient | None = None,
) -> HTTPTarget:
    """从解析结果构建 PyRIT 原生 HTTPTarget.

    宪法合规: 仅使用 PyRIT 原生 Target, 不自定义子类.

    对齐 PyRIT 1.0.1:
        1. 使用原生 HTTPTarget (非子类)
        2. 构建 TargetConfiguration 声明目标能力
        3. 配置 httpx.AsyncClient 参数 (timeout, follow_redirects, verify)
        4. HTTP/2 检测: 从 parsed.http_version 启用
        5. 回调函数: 对齐官方 get_http_target_json_response_callback_function

    Args:
        parsed: 解析后的 Burp 请求.
        enable_multi_turn: 是否声明多轮攻击能力.
        enable_system_prompt_adapt: 是否启用 system prompt 自适应.
        auto_discover_capabilities: 是否运行 PyRIT 原生能力探测.
        http_client: 预配置的 httpx.AsyncClient (复用).

    Returns:
        HTTPTarget: PyRIT 原生 HTTP 目标实例.
    """
    from recon.burp_parser import build_raw_http_request

    raw_request = build_raw_http_request(parsed)

    # ── Chat ID 状态管理器 ──
    chat_id_state: ChatIdStateManager | None = None
    if parsed.has_chat_id_placeholder or parsed.chat_id:
        chat_id_state = ChatIdStateManager(initial_chat_id=parsed.chat_id)

    # ── 创建共享 Client (如果未提供) ──
    shared_client = http_client
    if shared_client is None:
        http2 = "HTTP/2" in (parsed.http_version or "")
        # P2-06: TLS verify 配置化 (SSOT) — 使用模块级缓存
        shared_client = httpx.AsyncClient(
            timeout=120.0,
            follow_redirects=True,
            verify=_TLS_VERIFY,
            http2=http2,
        )

    # ── Callback 链 ──
    callback = _assemble_callback(parsed, chat_id_state)

    # ── TargetConfiguration ──
    custom_config = _build_target_configuration(
        enable_multi_turn=enable_multi_turn,
        enable_system_prompt_adapt=enable_system_prompt_adapt,
    )

    # ── 构建 Target (原生 HTTPTarget) ──
    target = HTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        callback_function=callback,
        use_tls=parsed.use_tls,
        client=shared_client,
        custom_configuration=custom_config,
    )

    # ── 附加状态管理器 (通过 target 的 __dict__ 传递) ──
    # 注意: 这是一种轻量级方式, 将状态管理器与 target 关联, 但不侵入 target 自身逻辑
    target._recon_chat_id_state = chat_id_state  # type: ignore[attr-defined]
    if chat_id_state:
        chat_id_state.set_template(raw_request)

    logger.debug(
        "PyRIT native HTTPTarget built: %s %s (TLS=%s, HTTP2=%s, SSE=%s, "
        "placeholder=%s, callback=%s, multi_turn=%s, system_adapt=%s, "
        "chat_id_state=%s)",
        parsed.method,
        parsed.url,
        parsed.use_tls,
        "HTTP/2" in (parsed.http_version or ""),
        parsed.is_sse,
        parsed.has_prompt_placeholder,
        getattr(callback, "__name__", "None"),
        enable_multi_turn,
        enable_system_prompt_adapt,
        "enabled" if chat_id_state else "disabled",
    )

    # L5 v52: PyRIT 原生能力探测 (可选)
    if auto_discover_capabilities:
        _run_capability_discovery_sync(target)

    return target


def _build_target_configuration(
    *,
    enable_multi_turn: bool,
    enable_system_prompt_adapt: bool,
) -> TargetConfiguration | None:
    """构建 TargetConfiguration.

    根据 multi_turn 和 system_prompt_adapt 配置声明目标能力.
    """
    from pyrit.prompt_target.common.target_capabilities import (
        CapabilityHandlingPolicy,
        CapabilityName,
        UnsupportedCapabilityBehavior,
    )

    if enable_multi_turn:
        # 多轮: 声明 multi_turn + editable_history
        policy = CapabilityHandlingPolicy(
            behaviors={
                CapabilityName.SYSTEM_PROMPT: UnsupportedCapabilityBehavior.ADAPT,
                CapabilityName.MULTI_TURN: UnsupportedCapabilityBehavior.RAISE,
                CapabilityName.JSON_SCHEMA: UnsupportedCapabilityBehavior.ADAPT,
            }
        ) if enable_system_prompt_adapt else CapabilityHandlingPolicy()

        return TargetConfiguration(
            capabilities=TargetCapabilities(
                supports_multi_turn=True,
                supports_editable_history=True,
                input_modalities=frozenset({frozenset({"text"})}),
            ),
            policy=policy,
        )
    else:
        # 单轮: 仅声明 text 输入
        if enable_system_prompt_adapt:
            policy = CapabilityHandlingPolicy(
                behaviors={
                    CapabilityName.SYSTEM_PROMPT: UnsupportedCapabilityBehavior.ADAPT,
                    CapabilityName.MULTI_TURN: UnsupportedCapabilityBehavior.RAISE,
                    CapabilityName.JSON_SCHEMA: UnsupportedCapabilityBehavior.ADAPT,
                }
            )
            return TargetConfiguration(
                capabilities=TargetCapabilities(
                    input_modalities=frozenset({frozenset({"text"})}),
                ),
                policy=policy,
            )
        return None


def _run_capability_discovery_sync(target: HTTPTarget) -> None:
    """同步触发 PyRIT 原生能力探测 (L5 v52).

    由于 discover_target_capabilities_async 是异步函数,
    但 build_http_target 是同步函数, 这里使用 asyncio.run
    在无事件循环时触发探测。如果已在事件循环中, 则跳过.

    Args:
        target: PyRIT HTTPTarget 实例.
    """
    try:
        import asyncio

        try:
            asyncio.get_running_loop()
            logger.debug(
                "Skipping sync capability discovery "
                "(event loop already running)"
            )
            return
        except RuntimeError:
            pass

        asyncio.run(_async_discover_capabilities(target))
    except Exception as e:
        logger.debug("Sync capability discovery skipped: %s", e)


async def _async_discover_capabilities(target: HTTPTarget) -> None:
    """异步运行 PyRIT 原生能力探测 (L5 v52).

    Args:
        target: PyRIT HTTPTarget 实例.
    """
    try:
        from pyrit.prompt_target.common.discover_target_capabilities import (
            discover_target_capabilities_async,
        )

        logger.info(
            "Running PyRIT native capability discovery on %s",
            type(target).__name__,
        )
        discovered = await discover_target_capabilities_async(
            target=target,
            per_probe_timeout_s=15.0,
            retries=1,
            apply=True,
        )
        logger.info(
            "Discovered: multi_turn=%s, system_prompt=%s, "
            "json_output=%s, input_modalities=%s",
            discovered.supports_multi_turn,
            discovered.supports_system_prompt,
            discovered.supports_json_output,
            [sorted(s) for s in sorted(discovered.input_modalities)],
        )
    except Exception as e:
        logger.warning(
            "Native capability discovery failed (non-fatal): %s", e
        )


# ════════════════════════════════════════════════════════════════════
# HTTPXAPITarget 构建 — API 模式
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
    """构建 PyRIT 原生 HTTPXAPITarget — API 模式.

    对齐 PyRIT 1.0.1 HTTPXAPITarget:
        - 用于文件上传/multipart form/JSON API 场景
        - 支持 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS
        - 内置文件上传 (仅 POST/PUT)

    Args:
        parsed: 解析后的 Burp 请求 (提取 host/auth headers).
        method: HTTP 方法.
        json_data: JSON body 数据.
        form_data: Form body 数据.
        file_path: 上传文件路径 (仅 POST/PUT).
        params: URL query 参数.
        max_requests_per_minute: 每分钟最大请求数.
        enable_multi_turn: 是否支持多轮.

    Returns:
        HTTPXAPITarget: PyRIT 原生 API 模式目标实例.

    Raises:
        ValueError: 如果 method 不合法或 file_path 与 method 不兼容.
    """
    _VALID_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
    method_upper = method.upper().strip()
    if method_upper not in _VALID_METHODS:
        raise ValueError(
            f"Invalid HTTP method '{method}'. "
            f"Valid methods: {sorted(_VALID_METHODS)}"
        )

    if file_path and method_upper not in ("POST", "PUT"):
        raise ValueError(f"File upload requires POST or PUT, got {method_upper}")

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
        callback_function=_select_response_parser(parsed),
        max_requests_per_minute=max_requests_per_minute,
        custom_configuration=custom_config,
        timeout=120.0,
        # P2-06: TLS verify 配置化 (SSOT)
        verify=_TLS_VERIFY,
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
# 向后兼容: 保留导入 (标记为 deprecated)
# ════════════════════════════════════════════════════════════════════

def __getattr__(name: str) -> Any:
    """向后兼容层, 警告用户迁移至新 API."""
    if name == "JSONSafeHTTPTarget":
        import warnings
        warnings.warn(
            "JSONSafeHTTPTarget is deprecated and will be removed. "
            "Use native HTTPTarget via build_http_target() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        # 返回原生 HTTPTarget 作为替代
        return HTTPTarget
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
