# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""TargetUrlClassifier: identify the AI component category of a target URL."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class TargetUrlClassification:
    """Classification result for a target URL."""

    raw_url: str = ""
    primary_category: str = "unknown"
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_url": self.raw_url,
            "primary_category": self.primary_category,
            "tags": self.tags,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
        }


class TargetUrlClassifier:
    """Identify LLM / RAG / Agent / MCP / Embedding components from URL paths and host context."""

    def classify(self, url: str, *, method: str = "GET", response_body: str = "") -> TargetUrlClassification:
        parsed = urlparse(url)
        path = parsed.path.lower()
        full = f"{path}?{parsed.query}".lower()

        evidence: list[str] = []
        tags: list[str] = []

        if any(token in path for token in ("/mcp/", "/jsonrpc", "/.well-known/mcp", "/mcp-server")):
            primary = "mcp"
            tags.extend(["mcp", "rpc", "tool-surface"])
            evidence.append("matched mcp path")
        elif any(token in path for token in ("/api/tools", "/api/functions", "/api/actions", "/api/execute", "/api/invoke", "/agent", "/assistant", "/copilot", "/browse", "/fetch")):
            primary = "agent"
            tags.extend(["agent", "tool-calling", "indirect-injection"])
            evidence.append("matched agent/tool path")
        elif any(token in path for token in ("/api/search", "/api/retrieve", "/api/query", "/rag/", "/retrieval/", "/knowledge")):
            primary = "rag"
            tags.extend(["rag", "retrieval", "knowledge-base"])
            evidence.append("matched rag path")
        elif any(token in path for token in ("/v1/embeddings", "/api/embed", "/api/embedding", "/api/vector", "/vectors", "/collections", "/index")):
            primary = "embedding"
            tags.extend(["embedding", "vector-db", "retrieval"])
            evidence.append("matched embedding/vector path")
        elif any(token in path for token in ("/v1/chat/completions", "/v1/responses", "/api/chat", "/api/completion", "/api/generate", "/api/inference", "/llm")):
            primary = "llm"
            tags.extend(["llm", "chat", "prompt-surface"])
            evidence.append("matched llm/chat path")
        elif any(token in path for token in ("/oauth", "/token", "/login", "/signin", "/sso", "/authorize", "/callback")):
            primary = "auth"
            tags.extend(["auth", "login", "sso"])
            evidence.append("matched auth path")
        elif any(token in path for token in ("/upload", "/files", "/media", "/attachments")):
            primary = "upload"
            tags.extend(["upload", "multi-modal", "poisoning"])
            evidence.append("matched upload path")
        else:
            primary = "unknown"
            evidence.append("no ai-specific pattern matched")

        if response_body:
            lowered = response_body.lower()
            if '"jsonrpc"' in lowered or '"tools"' in lowered:
                if primary == "unknown":
                    primary = "mcp"
                    tags.extend(["mcp", "rpc"])
                    evidence.append("matched jsonrpc body")
            if '"embedding"' in lowered or '"data"' in lowered and '"object"' in lowered:
                if primary == "unknown":
                    primary = "embedding"
                    tags.extend(["embedding", "vector-db"])
                    evidence.append("matched embedding body")

        confidence = 0.75 if primary != "unknown" else 0.25
        if primary != "unknown" and tags:
            confidence = min(0.98, confidence + 0.1)

        return TargetUrlClassification(
            raw_url=url,
            primary_category=primary,
            tags=sorted(set(tags)),
            confidence=confidence,
            evidence=evidence,
        )
