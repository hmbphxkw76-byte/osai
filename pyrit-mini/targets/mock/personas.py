"""targets/mock/personas.py — 5 类 Mock 靶标人格（REQ-156）。

为 `recon → arm → strike → assess → report` 端到端链路提供**可复现的靶标画像**，
每类人格暴露对应组件"应该被侦察到"的最小特征（不是安全防护，故不违反 NEG-2）：

    model      OpenAI 兼容 chat completions（模型/指纹）
    mcp        JSON-RPC：tools/list + tools/call（工具清单 + inputSchema）
    rag        /api/retrieve 含引用与 chunk（检索管道 + 投毒面）
    a2a        /.well-known/agent.json + /a2a/tasks/send（AgentCard + 任务）
    embedding  /v1/embeddings（向量维度 + 归一化）

设计约束：
    - 纯函数、确定性、零外部依赖（NEG-4：仅标准库）；
    - 不实现任何"输入过滤/内容审查"（NEG-2：不在攻击链路引入安全降级）；
    - 与 `fixtures/expected.yaml` 的期望签名一一对应（golden 断言的基础）。
"""

from __future__ import annotations

import json
import math
from typing import Any

PERSONAS: tuple[str, ...] = ("model", "mcp", "rag", "a2a", "embedding")

# 各人格的向量维度（embedding 人格用，供 recon/embedding 维度探测命中）
EMBEDDING_DIM = 8

# MCP 人格暴露的工具（含高危工具，供 inputSchema / 风险扫描断言）
MCP_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "execute_command",
        "description": "Execute a shell command on the host.",
        "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
    },
    {
        "name": "file_write",
        "description": "Write content to a file path.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
)

# RAG 人格返回的 chunk（带引用与固定 canary，供检索投毒面断言）
RAG_CHUNKS: tuple[dict[str, Any], ...] = (
    {
        "chunk_id": "kb-0001",
        "score": 0.93,
        "text": "Company refund policy: ... INJECTED_CONTEXT_AOBC marker ...",
        "source": "kb/policy.md",
    },
    {
        "chunk_id": "kb-0002",
        "score": 0.81,
        "text": "Internal FAQ: contact support@example.com",
        "source": "kb/faq.md",
    },
)


def _embedding(text: str, dim: int = EMBEDDING_DIM) -> list[float]:
    """Deterministic L2-normalized pseudo-embedding derived from the text hash."""
    seed = abs(hash(text)) % (2**32)
    raw = [((seed >> (i * 3)) & 0xFF) / 255.0 + 0.01 for i in range(dim)]
    norm = math.sqrt(sum(v * v for v in raw)) or 1.0
    return [round(v / norm, 6) for v in raw]


def respond(persona: str, path: str, method: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    """Return `(status_code, json_body)` for a persona request.

    Unknown paths return 404 for that persona (so reconnaissance can distinguish
    a miss from a hit). Never raises.
    """
    body = body if isinstance(body, dict) else {}
    path_clean = (path or "/").split("?")[0]

    if persona == "model":
        if path_clean.endswith("/chat/completions") or path_clean.endswith("/v1/chat/completions"):
            return 200, {
                "id": "mock-cmpl-1",
                "object": "chat.completion",
                "model": "mock-model-v1",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "mock assistant reply"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
            }
        return _not_found(persona)

    if persona == "mcp":
        if not path_clean.endswith("/mcp") and path_clean != "/mcp":
            return _not_found(persona)
        rpc_method = str(body.get("method") or "")
        rpc_id = body.get("id", 1)
        if rpc_method == "initialize":
            return 200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "mock-mcp-server", "version": "0.1.0"},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            }
        if rpc_method == "tools/list":
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": list(MCP_TOOLS)}}
        if rpc_method == "resources/list":
            return 200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {"resources": [{"uri": "file:///etc/mock.conf", "name": "mock-config"}]},
            }
        if rpc_method == "prompts/list":
            return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"prompts": [{"name": "summarize"}]}}
        if rpc_method == "tools/call":
            return 200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {"content": [{"type": "text", "text": "tool executed: ok"}]},
            }
        return 200, {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": "Method not found"}}

    if persona == "rag":
        if path_clean.endswith("/retrieve") or path_clean.endswith("/search"):
            return 200, {
                "query": str(body.get("query") or ""),
                "results": list(RAG_CHUNKS),
                "citations": [c["source"] for c in RAG_CHUNKS],
            }
        return _not_found(persona)

    if persona == "a2a":
        if path_clean.endswith("/.well-known/agent.json") or path_clean.endswith("/agent.json"):
            return 200, {
                "name": "mock-agent",
                "description": "Mock A2A agent for red-team fixtures",
                "url": "/a2a",
                "version": "0.1.0",
                "capabilities": {"streaming": False, "pushNotifications": False},
                "skills": [{"id": "summarize", "name": "Summarize", "description": "Summarize text"}],
            }
        if "/tasks/send" in path_clean or path_clean.endswith("/a2a"):
            return 200, {"taskId": "mock-task-1", "status": "completed", "artifacts": [{"name": "result", "parts": []}]}
        return _not_found(persona)

    if persona == "embedding":
        if path_clean.endswith("/embeddings"):
            inputs = body.get("input")
            if isinstance(inputs, list) and inputs:
                items = [(i, str(t)) for i, t in enumerate(inputs)]
            else:
                items = [(0, str(inputs if inputs is not None else ""))]
            return 200, {
                "object": "list",
                "model": "mock-embedding-v1",
                "data": [{"object": "embedding", "index": i, "embedding": _embedding(t)} for i, t in items],
                "usage": {"prompt_tokens": 3, "total_tokens": 3},
            }
        return _not_found(persona)

    return 404, {"error": "unknown persona", "persona": persona}


def _not_found(persona: str) -> tuple[int, dict[str, Any]]:
    return 404, {"error": "not_found", "persona": persona}


def expected_signature(persona: str) -> dict[str, Any]:
    """Minimal machine-checkable signature for a persona (golden assertion aid)."""
    if persona == "model":
        return {"path": "/v1/chat/completions", "keys": ["choices", "model"]}
    if persona == "mcp":
        return {"path": "/mcp", "rpc": "tools/list", "keys": ["result"], "tool_names": [t["name"] for t in MCP_TOOLS]}
    if persona == "rag":
        return {"path": "/api/retrieve", "keys": ["results", "citations"]}
    if persona == "a2a":
        return {"path": "/.well-known/agent.json", "keys": ["name", "skills", "capabilities"]}
    if persona == "embedding":
        return {"path": "/v1/embeddings", "keys": ["data", "model"], "dim": EMBEDDING_DIM}
    return {}


def body_for(persona: str) -> tuple[str, dict[str, Any]]:
    """Default `(method, body)` used to exercise a persona."""
    if persona == "mcp":
        return "POST", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    if persona == "rag":
        return "POST", {"query": "refund policy"}
    if persona == "embedding":
        return "POST", {"input": ["alpha", "beta"]}
    if persona == "a2a":
        return "GET", {}
    return "POST", {"messages": [{"role": "user", "content": "hi"}], "model": "mock-model-v1"}


def json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)
