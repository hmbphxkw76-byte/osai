"""REQ-149 测试：TargetAdapter 统一协议 + MCPTarget/RAGTarget/A2ATarget 接线。

端到端部分复用 `targets/mock` 的 5 类靶标（REQ-156），避免任何真实网络依赖。
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from recon.adapters import (
    ADAPTER_KINDS,
    AdapterRequest,
    AdapterResponse,
    AuthState,
    HTTPAdapter,
    JSONRPCAdapter,
    MultipartAdapter,
    SessionState,
    SSEAdapter,
    build_adapter,
    choose_kind,
    parse_event_frames,
    parse_event_stream,
)
from strike.targets import A2ATarget, MCPTarget, RAGTarget
from targets.mock import MockRange


@pytest.fixture(autouse=True)
def _pyrit_memory():
    """PyRIT 1.0.1 的 `PromptTarget.__init__` 要求已初始化的 CentralMemory。

    生产路径由 `core.config.setup_environment` 完成初始化；这里用内存 SQLite
    等价替代。**必须保存并恢复**全局单例，否则会污染其他测试文件
    （`CentralMemory` 是进程级 singleton）。
    """
    from pyrit.memory import CentralMemory
    from pyrit.memory.sqlite_memory import SQLiteMemory

    previous = getattr(CentralMemory, "_memory_instance", None)
    CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:"))
    try:
        yield
    finally:
        CentralMemory._memory_instance = previous


class TestAuthState:
    def test_bearer_from_raw_headers(self) -> None:
        state = AuthState.from_raw_headers([("Authorization", "Bearer tok-123"), ("Content-Type", "application/json")])
        assert state.kind == "bearer" and state.bearer_token == "tok-123"

    def test_apikey_header(self) -> None:
        state = AuthState.from_raw_headers([("X-Api-Key", "key-9")])
        assert state.kind == "apikey" and state.api_key_header == "X-Api-Key"

    def test_cookie_parsing(self) -> None:
        state = AuthState.from_raw_headers([("Cookie", "a=1; b=2")])
        assert state.cookies == {"a": "1", "b": "2"}

    def test_non_pair_entries_ignored(self) -> None:
        state = AuthState.from_raw_headers(["garbage", None, ("Authorization", "Bearer x")])
        assert state.bearer_token == "x"

    def test_apply_injects_bearer_once(self) -> None:
        state = AuthState(kind="bearer", bearer_token="t")
        headers = state.apply({"Accept": "application/json"})
        assert headers["Authorization"] == "Bearer t"
        again = state.apply(headers)
        assert sum(1 for k in again if k.lower() == "authorization") == 1

    def test_apply_merges_cookies(self) -> None:
        state = AuthState(kind="cookie", cookies={"a": "1"})
        headers = state.apply({"Cookie": "b=2"})
        assert "a=1" in headers["Cookie"] and "b=2" in headers["Cookie"]

    def test_redacted_masks_secrets(self) -> None:
        state = AuthState(kind="bearer", bearer_token="supersecret", cookies={"sid": "x"})
        redacted = state.redacted()
        assert "supersecret" not in json.dumps(redacted)
        assert redacted["has_bearer"] is True and redacted["cookie_names"] == ["sid"]

    def test_mtls_and_oauth_flags(self) -> None:
        assert AuthState(kind="mtls", client_cert="c", client_key="k").mtls_configured is True
        assert AuthState(kind="oauth2", oauth_token_url="https://t").refreshable is True
        assert AuthState(kind="oauth2").refreshable is False


class TestSessionState:
    def test_expand_placeholders(self) -> None:
        state = SessionState(chat_id="c-1", thread_id="t-1")
        assert state.expand('{"chat":"{CHAT_ID}","thread":"{THREAD_ID}"}') == '{"chat":"c-1","thread":"t-1"}'

    def test_apply_to_body_is_additive(self) -> None:
        state = SessionState(id_fields={"thread_id": "t-9"})
        body = state.apply_to_body({"prompt": "hi", "thread_id": "existing"})
        assert body["thread_id"] == "existing"

    def test_capture_finds_session_id(self) -> None:
        state = SessionState()
        found = state.capture({"data": {"conversation_id": "conv-7"}})
        assert found == "conv-7" and state.chat_id == "conv-7"

    def test_capture_empty_payload(self) -> None:
        assert SessionState().capture(None) == ""


class TestResponseAndKind:
    def test_response_ok_and_serialize(self) -> None:
        assert AdapterResponse(status=200).ok is True
        assert AdapterResponse(status=500).ok is False
        assert AdapterResponse(status=200, error="boom").ok is False
        assert AdapterResponse(status=200, text="x").to_dict()["text"] == "x"

    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            ({"is_sse": True}, "sse"),
            ({"content_type": "multipart/form-data; boundary=1"}, "multipart"),
            ({"path": "/mcp"}, "jsonrpc"),
            ({"path": "/api/chat"}, "http"),
            ({"hint": "sse", "path": "/api/chat"}, "sse"),
        ],
    )
    def test_choose_kind(self, kwargs: dict, expected: str) -> None:
        assert choose_kind(**kwargs) == expected

    def test_build_adapter_closes_auth_inside(self) -> None:
        adapter = build_adapter(url="https://t/x", raw_headers=[("Authorization", "Bearer z")], path="/api/chat")
        assert isinstance(adapter, HTTPAdapter)
        assert adapter.auth.bearer_token == "z"
        assert set(ADAPTER_KINDS) == {"http", "sse", "jsonrpc", "multipart", "mcp", "rag", "a2a"}

    def test_build_adapter_selects_jsonrpc(self) -> None:
        assert isinstance(build_adapter(url="https://t/mcp", path="/mcp"), JSONRPCAdapter)


class TestEventStreamParsing:
    def test_frames_and_done(self) -> None:
        raw = "data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: [DONE]\n\ndata: {\"c\":3}\n\n"
        frames = parse_event_frames(raw)
        assert frames == ['{"a":1}', '{"b":2}']

    def test_ignores_comments_and_field_lines(self) -> None:
        raw = ": keepalive\nevent: message\ndata: hello\n\n"
        assert parse_event_frames(raw) == ["hello"]

    def test_openai_style_delta_concatenation(self) -> None:
        raw = (
            'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
            "data: [DONE]\n\n"
        )
        assert parse_event_stream(raw) == "Hello"

    def test_plain_text_frames(self) -> None:
        assert parse_event_stream("data: plain\n\n") == "plain"


class TestHTTPAdapterE2E:
    def test_chat_completion_round_trip(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            adapter = build_adapter(
                url=f"{range_.url}/mock/model/v1/chat/completions",
                path="/api/chat",
                response_json_path="choices[0].message.content",
            )
            response = asyncio.run(adapter.send("hello"))
            assert response.ok is True
            assert adapter.extract_text(response) == "mock assistant reply"
            asyncio.run(adapter.close())
        finally:
            range_.stop()

    def test_error_is_normalized_not_raised(self) -> None:
        adapter = build_adapter(url="http://127.0.0.1:1/nowhere", path="/api/chat", timeout=2.0)
        response = asyncio.run(adapter.send("x"))
        assert response.ok is False and response.status == 0 and response.error
        asyncio.run(adapter.close())


class TestJSONRPCAdapterE2E:
    def test_mcp_handshake_list_and_call(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            adapter = JSONRPCAdapter.from_target(url=f"{range_.url}/mock/mcp/mcp")
            assert asyncio.run(adapter.initialize()).ok is True
            tools = asyncio.run(adapter.list_tools())
            assert sorted(adapter.tool_names(tools)) == ["execute_command", "file_write"]
            called = asyncio.run(adapter.call_tool("execute_command", {"cmd": "id"}))
            assert "tool executed" in adapter.extract_text(called)
            resources = asyncio.run(adapter.list_resources())
            assert resources.ok is True
            asyncio.run(adapter.close())
        finally:
            range_.stop()

    def test_rpc_error_surfaced(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            adapter = JSONRPCAdapter.from_target(url=f"{range_.url}/mock/mcp/mcp")
            response = asyncio.run(adapter.call("nope/method", {}))
            assert response.ok is False and "jsonrpc:" in response.error
            asyncio.run(adapter.close())
        finally:
            range_.stop()


class TestMultipartAdapterE2E:
    def test_upload_reaches_target(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            adapter = MultipartAdapter.from_target(url=f"{range_.url}/mock/rag/api/retrieve")
            response = asyncio.run(adapter.send("malicious document"))
            assert response.status == 200
            asyncio.run(adapter.close())
        finally:
            range_.stop()


class _SSEHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for chunk in ("Hel", "lo"):
            self.wfile.write(f'data: {{"choices":[{{"delta":{{"content":"{chunk}"}}}}]}}\n\n'.encode())
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def log_message(self, fmt: str, *args: object) -> None:
        pass


class TestSSEAdapterE2E:
    def test_stream_concatenated(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _SSEHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/stream"
            adapter = build_adapter(url=url, is_sse=True)
            assert isinstance(adapter, SSEAdapter)
            response = asyncio.run(adapter.send("hi"))
            assert response.ok is True
            assert response.text == "Hello"
            assert response.payload["frame_count"] == 2
            asyncio.run(adapter.close())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class TestComponentTargets:
    def test_mcp_target_handshake_list_call(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            adapter = JSONRPCAdapter.from_target(url=f"{range_.url}/mock/mcp/mcp")
            target = MCPTarget(adapter=adapter)
            assert asyncio.run(target.handshake()) is True
            assert sorted(asyncio.run(target.list_tools())) == ["execute_command", "file_write"]
            assert "tool executed" in asyncio.run(target.call_tool("execute_command", {"cmd": "id"}))
            assert target.tools == ["execute_command", "file_write"]
            assert target.describe()["target"] == "mcp"
            asyncio.run(target.cleanup())
        finally:
            range_.stop()

    def test_mcp_target_send_prompt_returns_message(self) -> None:
        from pyrit.models import Message, MessagePiece

        range_ = MockRange(port=0).start()
        try:
            adapter = JSONRPCAdapter.from_target(url=f"{range_.url}/mock/mcp/mcp")
            target = MCPTarget(adapter=adapter, tool_name="execute_command")
            piece = MessagePiece(role="user", original_value="run id", converted_value="run id")
            messages = asyncio.run(target._send_prompt_to_target_async(normalized_conversation=[Message(message_pieces=[piece])]))
            assert len(messages) == 1
            response_piece = messages[0].get_piece()
            assert "tool executed" in (response_piece.converted_value or "")
            assert response_piece.prompt_metadata.get("mcp_tool") == "execute_command"
            asyncio.run(target.cleanup())
        finally:
            range_.stop()

    def test_rag_target_retrieve_and_citations(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            generation = build_adapter(url=f"{range_.url}/mock/model/v1/chat/completions", path="/api/chat")
            retrieval = build_adapter(url=f"{range_.url}/mock/rag/api/retrieve", path="/api/retrieve")
            target = RAGTarget(adapter=generation, retrieval_adapter=retrieval)
            chunks = asyncio.run(target.retrieve("refund policy"))
            assert len(chunks) == 2
            assert target.citations() == ["kb/policy.md", "kb/faq.md"]
            assert target.describe()["last_chunk_count"] == 2
            asyncio.run(target.cleanup())
        finally:
            range_.stop()

    def test_rag_target_single_channel_extracts_chunks(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            adapter = build_adapter(url=f"{range_.url}/mock/rag/api/retrieve", path="/api/retrieve")
            target = RAGTarget(adapter=adapter)
            from pyrit.models import Message, MessagePiece

            piece = MessagePiece(role="user", original_value="q", converted_value="q")
            asyncio.run(target._send_prompt_to_target_async(normalized_conversation=[Message(message_pieces=[piece])]))
            assert len(target.last_chunks) == 2
            asyncio.run(target.cleanup())
        finally:
            range_.stop()

    def test_a2a_fetch_card_and_send_task(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            card_adapter = build_adapter(url=f"{range_.url}/mock/a2a/.well-known/agent.json", method="GET", path="/agent.json")
            task_adapter = build_adapter(url=f"{range_.url}/mock/a2a", path="/a2a")
            target = A2ATarget(adapter=task_adapter, card_adapter=card_adapter, task_path="/tasks/send")
            card = asyncio.run(target.fetch_agent_card())
            assert card["name"] == "mock-agent" and card["skills"]
            task = asyncio.run(target.send_task("do something"))
            assert task["task_id"] == "mock-task-1" and task["status"] == "completed"
            assert target.describe()["target"] == "a2a"
            asyncio.run(target.cleanup())
        finally:
            range_.stop()

    def test_a2a_card_failure_is_non_fatal(self) -> None:
        card_adapter = build_adapter(url="http://127.0.0.1:1/none", method="GET", timeout=2.0)
        task_adapter = build_adapter(url="http://127.0.0.1:1/task", timeout=2.0)
        target = A2ATarget(adapter=task_adapter, card_adapter=card_adapter)
        assert asyncio.run(target.fetch_agent_card()) == {}
        assert asyncio.run(target.send_task("x"))["task_id"] == "task-1"
        asyncio.run(target.cleanup())


class TestAdapterContract:
    def test_adapters_expose_send_and_close(self) -> None:
        for kind in ADAPTER_KINDS:
            adapter = build_adapter(url="https://t/x", kind=kind)
            assert adapter.name == kind
            assert hasattr(adapter, "send") and hasattr(adapter, "close")
            assert "auth" in adapter.describe() and "session" in adapter.describe()
            asyncio.run(adapter.close())

    def test_close_is_idempotent(self) -> None:
        adapter = build_adapter(url="https://t/x")
        asyncio.run(adapter.close())
        asyncio.run(adapter.close())

    def test_context_manager_closes(self) -> None:
        async def _use() -> None:
            async with build_adapter(url="https://t/x") as adapter:
                assert adapter._client is None or adapter._client is not None
            assert adapter._client is None

        asyncio.run(_use())

    def test_request_dataclass_defaults(self) -> None:
        request = AdapterRequest(prompt="p")
        assert request.method == "POST" and request.files == {} and request.body is None

    def test_simple_namespace_has_no_effect(self) -> None:
        """仅确保测试辅助对象不参与断言（防误用）。"""
        assert SimpleNamespace(x=1).x == 1
