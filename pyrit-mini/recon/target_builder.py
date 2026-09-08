"""Target Builder - Construct PyRIT HTTPTarget from ParsedBurpRequest.

Converts parsed Burp HTTP requests into PyRIT HTTPTarget objects suitable
for attack execution. Handles:
1. Chat ID state management (multi-turn session persistence)
2. Request preprocessing (JSON body sanitization, Content-Length)
3. Response parsing (JSON path, SSE, adaptive)
4. TargetConfiguration (multi-turn, system prompt adapt)

Constitution compliance:
    - R-IMPORT-1: No httpx/aiohttp conflict (uses httpx internally for target build)
    - R-SIZE: < 800 lines
    - R-H3: Single-file module, no dual-track redundancy
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import httpx
from pyrit.prompt_target import (
    HTTPTarget,
    TargetCapabilities,
    TargetConfiguration,
    get_http_target_json_response_callback_function,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ====================================================================
# TLS verify (SSOT)
# ====================================================================
def _get_tls_verify_default() -> bool | str:
    """Get TLS verification setting from SSOT config."""
    from recon.config_loader import get_tls_verify
    try:
        return get_tls_verify()
    except Exception:
        return True


_TLS_VERIFY: bool | str = _get_tls_verify_default()


# ====================================================================
# Chat ID State Manager - Session persistence for multi-turn attacks
# ====================================================================

class ChatIdStateManager:
    """Manages chat ID state for multi-turn conversation attacks.

    Extracts chat_id from responses and injects into subsequent requests.
    """

    def __init__(self, initial_chat_id: str | None = None) -> None:
        self._chat_id: str | None = initial_chat_id
        self._original_template: str | None = None

    @property
    def chat_id(self) -> str | None:
        """Get current chat ID."""
        return self._chat_id

    def set_template(self, http_request_template: str) -> None:
        """Store original HTTP request template with {CHAT_ID} placeholder."""
        self._original_template = http_request_template

    def update_from_response(self, response: Any) -> str | None:
        """Extract chat_id from HTTP response.

        Priority: Object > Id > ChatId > SessionId > ConversationId > ConvId
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

        new_id = _extract_chat_id_from_response(text) if text else None
        if new_id and new_id != self._chat_id:
            old = self._chat_id
            self._chat_id = new_id
            logger.debug("Chat ID updated: %s -> %s", old or "(none)", new_id)
        return new_id

    def preprocess_request(self, http_request: str) -> str:
        """Replace {CHAT_ID} placeholder in HTTP request."""
        if "{CHAT_ID}" not in http_request:
            return http_request
        chat_id_val = self._chat_id or ""
        result = http_request.replace("{CHAT_ID}", chat_id_val)
        if not chat_id_val:
            logger.debug("Chat ID placeholder replaced with empty string (first request)")
        return result


# ====================================================================
# Request Preprocessor - HTTP request sanitization
# ====================================================================

class RequestPreprocessor:
    """Sanitizes HTTP requests for PyRIT HTTPTarget consumption.

    Steps:
        1. Replace {CHAT_ID} placeholder
        2. Sanitize JSON body (ensure valid JSON)
        3. Update Content-Length
    """

    @staticmethod
    def preprocess(
        http_request: str,
        chat_id_state: ChatIdStateManager | None = None,
    ) -> str:
        """Preprocess HTTP request."""
        result = http_request

        # Step 1: Chat ID
        if chat_id_state:
            result = chat_id_state.preprocess_request(result)

        # Step 2 & 3: JSON body + Content-Length
        result = RequestPreprocessor._sanitize_json_body(result)

        return result

    @staticmethod
    def _sanitize_json_body(http_request: str) -> str:
        """Ensure JSON body has correct Content-Length."""
        normalized = http_request.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)

        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        if not body.strip():
            return http_request

        # Parse and reserialize JSON
        sanitized_body = body
        try:
            body_obj = json.loads(body)
            sanitized_body = json.dumps(body_obj, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass

        # Update Content-Length
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
# Response Parser Selection
# ====================================================================

def _select_response_parser(parsed: Any) -> Any:
    """Select appropriate response parser based on parsed request.

    PyRIT 1.0.1 callbacks:
        - JSON path: get_http_target_json_response_callback_function
        - Regex: get_http_target_regex_matching_callback_function
        - SSE: custom SSE parser
        - Fallback: adaptive JSON parser
    """
    # 1. JSON path callback
    if parsed.response_json_path:
        callback = get_http_target_json_response_callback_function(
            key=parsed.response_json_path
        )
        logger.debug("Using probed JSON callback with path: %s", parsed.response_json_path)
        return callback

    # 2. SSE parser
    if parsed.is_sse:
        logger.debug("Using custom SSE response parser")
        return _make_sse_response_parser()

    # 3. Adaptive JSON parser (fallback)
    return _make_adaptive_json_parser()


def _make_adaptive_json_parser() -> Any:
    """Create adaptive JSON response parser.

    Tries multiple JSON paths from common API formats:
        - OpenAI: choices[0].message.content
        - Generic: data.content, response, result, output
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
        """Parse JSON response and extract content."""
        content: str | bytes | None = None
        if hasattr(response, "content"):
            content = response.content
        elif hasattr(response, "text"):
            content = response.text
        else:
            return ""

        if not content:
            return ""

        if isinstance(content, bytes):
            content_str = content.decode("utf-8", errors="replace")
        else:
            content_str = str(content)

        try:
            data = json.loads(content_str)
        except (json.JSONDecodeError, TypeError):
            return content_str

        if not isinstance(data, dict):
            return content_str

        from recon.burp_parser import _extract_nested_ci
        for keys in _CANDIDATE_PATHS:
            result = _extract_nested_ci(data, keys)
            if result is not None and str(result).strip() and str(result) != "None":
                return str(result)

        return content_str

    parse_response.__name__ = "adaptive_json_parser"
    return parse_response


def _make_sse_response_parser() -> Any:
    """Create SSE (Server-Sent Events) response parser.

    Extracts JSON from data: lines in SSE stream.
    """
    def parse_sse_response(response: Any) -> str:
        content: str | None = None
        if hasattr(response, "content"):
            if isinstance(response.content, bytes):
                content = response.content.decode("utf-8", errors="replace")
            else:
                content = str(response.content)
        elif hasattr(response, "text"):
            content = response.text

        if not content:
            return ""

        # Parse SSE data: lines
        result_parts: list[str] = []
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("data: "):
                data_str = line[6:]
                if data_str == "[DONE]":
                    continue
                try:
                    data = json.loads(data_str)
                    # Extract model and content from SSE JSON
                    if isinstance(data, dict):
                        if "choices" in data and data["choices"]:
                            choice = data["choices"][0]
                            if "delta" in choice and "content" in choice["delta"]:
                                result_parts.append(choice["delta"]["content"])
                            elif "message" in choice and "content" in choice["message"]:
                                result_parts.append(choice["message"]["content"])
                        elif "content" in data:
                            result_parts.append(str(data["content"]))
                        elif "response" in data:
                            result_parts.append(str(data["response"]))
                except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                    continue

        return "".join(result_parts)

    parse_sse_response.__name__ = "sse_response_parser"
    return parse_sse_response


# ====================================================================
# Callback Assembly
# ====================================================================

def _assemble_callback(
    parsed: Any,
    chat_id_state: ChatIdStateManager | None = None,
) -> Any:
    """Assemble combined callback: response_parser + chat_id_extraction."""
    # Step 1: Select response parser
    response_parser = _select_response_parser(parsed)

    # Step 2: Create chat_id extractor if needed
    chat_id_extractor = None
    if parsed.has_chat_id_placeholder and chat_id_state:
        def chat_id_extractor(response: Any) -> None:
            """Extract chat_id from response and update state."""
            text: str | None = None
            if hasattr(response, "text") and response.text is not None:
                text = response.text
            elif hasattr(response, "content"):
                if isinstance(response.content, bytes):
                    text = response.content.decode("utf-8", errors="replace")
                else:
                    text = str(response.content)

            if text:
                chat_id_state.update_from_response(response)

    # Step 3: Combine callbacks
    def combined_callback(response: Any) -> str:
        """Combined: extract chat_id then parse response."""
        if chat_id_extractor:
            try:
                chat_id_extractor(response)
            except Exception:
                pass
        return response_parser(response)

    parser_name = getattr(response_parser, "__name__", "parser")
    suffix = "+chat_id" if chat_id_extractor else ""
    combined_callback.__name__ = f"combined({parser_name}{suffix})"
    return combined_callback


# ====================================================================
# Main Entry Point - build_http_target
# ====================================================================

def build_http_target(
    parsed: Any,
    *,
    http_client: Any = None,
    http2: bool = False,
    chat_id_state: ChatIdStateManager | None = None,
    enable_multi_turn: bool = False,
    enable_system_prompt_adapt: bool = True,
    auto_discover_capabilities: bool = True,
) -> HTTPTarget:
    """Build PyRIT HTTPTarget from ParsedBurpRequest.

    This is the primary entry point for converting parsed Burp requests
    into PyRIT-compatible targets for attack execution.

    Args:
        parsed: Parsed Burp request
        http_client: Optional shared httpx.AsyncClient
        http2: Enable HTTP/2
        chat_id_state: Chat ID state manager for multi-turn
        enable_multi_turn: Enable multi-turn conversation support
        enable_system_prompt_adapt: Adapt system prompt if unsupported
        auto_discover_capabilities: Run PyRIT native capability discovery

    Returns:
        Configured HTTPTarget ready for attack execution
    """
    raw_request = parsed.raw_request

    # Chat ID state
    if chat_id_state is None and (parsed.has_chat_id_placeholder or parsed.chat_id):
        chat_id_state = ChatIdStateManager(initial_chat_id=parsed.chat_id)

    # Client
    shared_client = http_client
    if shared_client is None:
        shared_client = httpx.AsyncClient(
            timeout=120.0,
            follow_redirects=True,
            verify=_TLS_VERIFY,
            http2=http2,
        )

    # Callback
    callback = _assemble_callback(parsed, chat_id_state)

    # TargetConfiguration
    custom_config = _build_target_configuration(
        enable_multi_turn=enable_multi_turn,
        enable_system_prompt_adapt=enable_system_prompt_adapt,
    )

    # Build target
    target = HTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        callback_function=callback,
        use_tls=parsed.use_tls,
        client=shared_client,
        custom_configuration=custom_config,
    )

    # Attach chat_id_state to target
    target._recon_chat_id_state = chat_id_state  # type: ignore[attr-defined]
    if chat_id_state:
        chat_id_state.set_template(raw_request)

    logger.debug(
        "PyRIT native HTTPTarget built: %s %s (TLS=%s, HTTP2=%s, SSE=%s, "
        "callback=%s, multi_turn=%s)",
        parsed.method, parsed.url, parsed.use_tls,
        "HTTP/2" in (parsed.http_version or ""),
        parsed.is_sse, getattr(callback, "__name__", "None"),
        enable_multi_turn,
    )

    return target


def _build_target_configuration(
    *,
    enable_multi_turn: bool,
    enable_system_prompt_adapt: bool,
) -> TargetConfiguration | None:
    """Build TargetConfiguration for multi-turn and system prompt adaptation."""
    from pyrit.prompt_target.common.target_capabilities import (
        CapabilityHandlingPolicy,
        CapabilityName,
        UnsupportedCapabilityBehavior,
    )

    if enable_multi_turn:
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
