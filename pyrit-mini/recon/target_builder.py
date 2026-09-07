"""target_builder —  PyRIT 1.0.1  HTTP Target .

 PyRIT  Target  (HTTPTarget / HTTPXAPITarget).

:
    -  PyRIT  Target,  HTTPTarget 
    -  (chat_id)  ChatIdStateManager 
    - HTTP  RequestPreprocessor 

PyRIT 1.0.1 :
    1. HTTPTarget._send_prompt_to_target_async  normalized_conversation: list[Message]
       → imports message.message_pieces[0]  MessagePiece
       → MessagePiece.converted_value  HTTP body  prompt 

    2. TargetConfiguration + TargetCapabilities :
       - supports_multi_turn: 
       - supports_multi_message_pieces: 
       - input_modalities:  (text/image_path/audio_path...)
       - supports_system_prompt:  system prompt
       →  ConversationNormalizationPipeline  (ADAPT/RAISE)

    3. httpx.AsyncClient :  HTTPTarget  client
       → / client,  ~30% 

    4. callback_function  httpx.Response ( requests.Response)

    5. HTTP/2 :  http_version  http2=True
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


# ====================================================================
# P2-06: TLS verify  (SSOT)
#  config/defaults.yaml  tls_verify ,  SSL 
# ====================================================================
def _get_tls_verify_default() -> bool | str:
    """Load TLS verify  ()"""
    try:
        from recon.config_loader import get_tls_verify
        return get_tls_verify()
    except Exception:
        return True  # 


_TLS_VERIFY: bool | str = _get_tls_verify_default()


# ====================================================================
# Chat ID  — 
# ====================================================================

class ChatIdStateManager:
    """ ID  (chat_id).

    : ,  PyRIT  Target.

    :
        1.  chat_id
        2. imports HTTP  chat_id
        3.  chat_id  ()
        4.  Target 
    """

    def __init__(self, initial_chat_id: str | None = None) -> None:
        self._chat_id: str | None = initial_chat_id
        self._original_template: str | None = None

    @property
    def chat_id(self) -> str | None:
        return self._chat_id

    def set_template(self, http_request_template: str) -> None:
        """ HTTP  ( {CHAT_ID} )."""
        self._original_template = http_request_template

    def update_from_response(self, response: Any) -> str | None:
        """imports HTTP  chat_id.

         ():
            Object > Id > ChatId > SessionId > ConversationId > ConvId

        Args:
            response: httpx.Response .

        Returns:
             chat_id,  None.
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
        """ HTTP ,  {CHAT_ID} .

        Args:
            http_request:  HTTP  ( {CHAT_ID}).

        Returns:
            .
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


# ====================================================================
# HTTP  —  Prompt 
# ====================================================================

class RequestPreprocessor:
    """HTTP .

     PyRIT  Prompt :
        1. {CHAT_ID} 
        2. JSON body  ()
        3. Content-Length 
    """

    @staticmethod
    def preprocess(
        http_request: str,
        chat_id_state: ChatIdStateManager | None = None,
    ) -> str:
        """ HTTP .

        Args:
            http_request:  HTTP .
            chat_id_state: Chat ID  ().

        Returns:
            .
        """
        result = http_request

        # Step 1: Chat ID 
        if chat_id_state:
            result = chat_id_state.preprocess_request(result)

        # Step 2 & 3: JSON body  + Content-Length
        result = RequestPreprocessor._sanitize_json_body(result)

        return result

    @staticmethod
    def _sanitize_json_body(http_request: str) -> str:
        """Ensure JSON body  Content-Length .

        :
            1.  HTTP  headers  body
            2.  body  JSON
            3.  JSON ,  ()
            4.  Content-Length 
        """
        normalized = http_request.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)

        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        if not body.strip():
            return http_request

        #  JSON  ()
        try:
            body_obj = json.loads(body)
            # :  ensure_ascii=False 
            sanitized_body = json.dumps(body_obj, ensure_ascii=False)
            if sanitized_body == body:
                return http_request  # 
        except (json.JSONDecodeError, TypeError):
            return http_request  #  JSON, 

        #  Content-Length
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


# ====================================================================
# Callback  — 
# ====================================================================

def _assemble_callback(
    parsed: ParsedBurpRequest,
    chat_id_state: ChatIdStateManager | None = None,
) -> Any:
    """: response_parser → chat_id_extraction.

    PyRIT HTTPTarget  callback_function, converter(s)
    .

    :
        1.  httpx.Response → response_parser → 
        2. imports chat_id →  ChatIdStateManager

    Args:
        parsed:  Burp  ( response_parser ).
        chat_id_state: Chat ID  ( chat_id).

    Returns:
         (httpx.Response → str).
    """
    # Step 1: 
    response_parser = _select_response_parser(parsed)

    # Step 2:  ( chat_id )
    chat_id_extractor = None
    if parsed.has_chat_id_placeholder and chat_id_state:

        def chat_id_extractor(response: Any) -> None:
            """imports chat_id ."""
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

    # Step 3:  callback
    def combined_callback(response: Any) -> str:
        """:  +  chat_id."""
        if chat_id_extractor:
            chat_id_extractor(response)
        return response_parser(response)

    # 
    parser_name = getattr(response_parser, "__name__", "parser")
    suffix = "+chat_id" if chat_id_extractor else ""
    combined_callback.__name__ = f"combined({parser_name}{suffix})"
    return combined_callback


def _select_response_parser(parsed: ParsedBurpRequest) -> Any:
    """.

     PyRIT 1.0.1 :
        - get_http_target_json_response_callback_function: JSON 
        - get_http_target_regex_matching_callback_function: 
        -  SSE parser: 

    Args:
        parsed:  Burp .

    Returns:
         (httpx.Response → str).
    """
    # 1.  JSON  →  JSON callback
    if parsed.response_json_path:
        callback = get_http_target_json_response_callback_function(
            key=parsed.response_json_path
        )
        logger.debug("Using probed JSON callback with path: %s", parsed.response_json_path)
        return callback

    # 2. SSE →  SSE parser
    if parsed.is_sse:
        from recon.burp_parser import _make_sse_response_parser
        logger.debug("Using custom SSE response parser")
        return _make_sse_response_parser()

    # 3.  JSON parser
    return _make_adaptive_json_parser()


def _make_adaptive_json_parser() -> Any:
    """ JSON  — converter(s).

     JSON  ( API ):
        - OpenAI : choices[0].message.content
        -  API: data.content, response, result, output
        -  API: message, text, content, answer, reply
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
        """ JSON ."""
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
    """ SSE .

     data:  JSON .
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

        #  data: 
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


# ====================================================================
# HTTP Target  —  PyRIT 1.0.1 TargetConfiguration
# ====================================================================

def build_http_target(
    parsed: ParsedBurpRequest,
    *,
    enable_multi_turn: bool = False,
    enable_system_prompt_adapt: bool = True,
    auto_discover_capabilities: bool = False,
    http_client: httpx.AsyncClient | None = None,
) -> HTTPTarget:
    """imports PyRIT  HTTPTarget.

    :  PyRIT  Target, .

    Aligned with PyRIT 1.0.1:
        1.  HTTPTarget ()
        2.  TargetConfiguration 
        3.  httpx.AsyncClient  (timeout, follow_redirects, verify)
        4. HTTP/2 : imports parsed.http_version 
        5. :  get_http_target_json_response_callback_function

    Args:
        parsed:  Burp .
        enable_multi_turn: .
        enable_system_prompt_adapt:  system prompt .
        auto_discover_capabilities:  PyRIT .
        http_client:  httpx.AsyncClient ().

    Returns:
        HTTPTarget: PyRIT  HTTP .
    """
    from recon.burp_parser import build_raw_http_request

    raw_request = build_raw_http_request(parsed)

    # == Chat ID  ==
    chat_id_state: ChatIdStateManager | None = None
    if parsed.has_chat_id_placeholder or parsed.chat_id:
        chat_id_state = ChatIdStateManager(initial_chat_id=parsed.chat_id)

    # ==  Client () ==
    shared_client = http_client
    if shared_client is None:
        http2 = "HTTP/2" in (parsed.http_version or "")
        # P2-06: TLS verify  (SSOT) — 
        shared_client = httpx.AsyncClient(
            timeout=120.0,
            follow_redirects=True,
            verify=_TLS_VERIFY,
            http2=http2,
        )

    # == Callback  ==
    callback = _assemble_callback(parsed, chat_id_state)

    # == TargetConfiguration ==
    custom_config = _build_target_configuration(
        enable_multi_turn=enable_multi_turn,
        enable_system_prompt_adapt=enable_system_prompt_adapt,
    )

    # ==  Target ( HTTPTarget) ==
    target = HTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        callback_function=callback,
        use_tls=parsed.use_tls,
        client=shared_client,
        custom_configuration=custom_config,
    )

    # ==  ( target  __dict__ ) ==
    # : ,  target ,  target 
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

    # L5 v52: PyRIT  ()
    if auto_discover_capabilities:
        _run_capability_discovery_sync(target)

    return target


def _build_target_configuration(
    *,
    enable_multi_turn: bool,
    enable_system_prompt_adapt: bool,
) -> TargetConfiguration | None:
    """ TargetConfiguration.

     multi_turn  system_prompt_adapt .
    """
    from pyrit.prompt_target.common.target_capabilities import (
        CapabilityHandlingPolicy,
        CapabilityName,
        UnsupportedCapabilityBehavior,
    )

    if enable_multi_turn:
        # :  multi_turn + editable_history
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
        # :  text 
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
    """ PyRIT  (L5 v52).

     discover_target_capabilities_async ,
     build_http_target ,  asyncio.run
    , Skip.

    Args:
        target: PyRIT HTTPTarget .
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
    """ PyRIT  (L5 v52).

    Args:
        target: PyRIT HTTPTarget .
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


# ====================================================================
# HTTPXAPITarget  — API 
# ====================================================================

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
    """ PyRIT  HTTPXAPITarget — API .

     PyRIT 1.0.1 HTTPXAPITarget:
        - /multipart form/JSON API 
        -  GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS
        -  ( POST/PUT)

    Args:
        parsed:  Burp  ( host/auth headers).
        method: HTTP .
        json_data: JSON body .
        form_data: Form body .
        file_path:  ( POST/PUT).
        params: URL query .
        max_requests_per_minute: .
        enable_multi_turn: .

    Returns:
        HTTPXAPITarget: PyRIT  API .

    Raises:
        ValueError:  method  file_path  method .
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

    #  headers
    headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host", "content-type"):
            headers[key] = value

    #  TargetConfiguration
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
        # P2-06: TLS verify  (SSOT)
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


# ====================================================================
# :  ( deprecated)
# ====================================================================

def __getattr__(name: str) -> Any:
    """Layer,  API."""
    if name == "JSONSafeHTTPTarget":
        import warnings
        warnings.warn(
            "JSONSafeHTTPTarget is deprecated and will be removed. "
            "Use native HTTPTarget via build_http_target() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        #  HTTPTarget 
        return HTTPTarget
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
