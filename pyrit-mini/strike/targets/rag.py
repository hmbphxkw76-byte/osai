"""strike/targets/rag.py — RAGTarget：RAG 管道 PyRIT Target（REQ-149 ④）。

封装 RAG 的三段式交互（`query → retrieve → generate`）：
    - `retrieve()` 走检索端点，返回 chunk/citation（知识库投毒与检索绕过的证据源）；
    - `_send_prompt_to_target_async()` 走生成端点，并把检索证据写入 `prompt_metadata`，
      使 assess 层的 `RetrievalPoisoningScorer` 可直接判定 L3（检索投毒达成）。

职责边界：只做协议适配，不做内容过滤（NEG-2）。
"""

from __future__ import annotations

import logging
from typing import Any

from pyrit.models import Message, construct_response_from_request
from pyrit.prompt_target.common.prompt_target import PromptTarget

from recon.adapters.base import BaseAdapter

logger = logging.getLogger(__name__)

# 检索响应中常见的结果容器键
_CHUNK_CONTAINER_KEYS = ("results", "chunks", "documents", "matches", "contexts", "sources")


class RAGTarget(PromptTarget):
    """RAG 应用 PyRIT Target（生成通道 + 可选检索通道）。

    Args:
        adapter: 生成（chat）通道适配器。
        retrieval_adapter: 检索通道适配器；为空时退化为"单通道 RAG"
            （检索证据只能从生成响应中提取）。
        endpoint / model_name: 标识与报告展示。
    """

    def __init__(
        self,
        *,
        adapter: BaseAdapter,
        retrieval_adapter: BaseAdapter | None = None,
        endpoint: str = "",
        model_name: str = "rag",
        system_prompt: str = "",
        max_requests_per_minute: int | None = None,
        **kwargs: Any,
    ) -> None:
        self._adapter = adapter
        self._retrieval_adapter = retrieval_adapter
        self._last_chunks: list[dict[str, Any]] = []
        # PyRIT 1.0.1 的 PromptTarget 不接收 system_prompt 形参，仅作实例属性保留
        self._system_prompt = system_prompt
        super().__init__(
            endpoint=endpoint or adapter.url,
            model_name=model_name,
            max_requests_per_minute=max_requests_per_minute,
            **kwargs,
        )

    # -- 检索通道 --------------------------------------------------------
    async def retrieve(self, query: str) -> list[dict[str, Any]]:
        """Query the retrieval endpoint and normalize chunks (empty list on failure)."""
        adapter = self._retrieval_adapter or self._adapter
        response = await adapter.send(query)
        chunks = self._extract_chunks(response.payload)
        self._last_chunks = chunks
        return chunks

    @staticmethod
    def _extract_chunks(payload: Any) -> list[dict[str, Any]]:
        """Pull chunk objects from a retrieval payload (depth-limited, never raises)."""
        if not isinstance(payload, dict):
            return []
        for key in _CHUNK_CONTAINER_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                return [item if isinstance(item, dict) else {"text": str(item)} for item in value]
        return []

    @property
    def last_chunks(self) -> list[dict[str, Any]]:
        return list(self._last_chunks)

    def citations(self) -> list[str]:
        return [str(c.get("source") or c.get("url") or c.get("doc_id") or "") for c in self._last_chunks if c]

    async def query(self, text: str) -> dict[str, Any]:
        """PlaybookEngine 语义动作（REQ-151）：检索 + 生成，返回 {answer, chunks, citations}。"""
        chunks = await self.retrieve(text)
        response = await self._adapter.send(text)
        answer = self._adapter.extract_text(response)
        return {"answer": answer, "chunks": chunks, "citations": self.citations(), "status": "ok"}

    def describe(self) -> dict[str, Any]:
        return {
            "target": "rag",
            "adapter": self._adapter.describe(),
            "retrieval_adapter": self._retrieval_adapter.describe() if self._retrieval_adapter else None,
            "last_chunk_count": len(self._last_chunks),
        }

    # -- PyRIT 契约 ------------------------------------------------------
    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        request_piece = normalized_conversation[-1].get_piece()
        prompt = request_piece.converted_value or request_piece.original_value or ""

        response = await self._adapter.send(prompt)
        text = self._adapter.extract_text(response)

        # 单通道模式：生成响应里若含检索证据，一并抽取（供 L3 判定）
        if not self._retrieval_adapter and not self._last_chunks:
            self._last_chunks = self._extract_chunks(response.payload)

        return [
            construct_response_from_request(
                request=request_piece,
                response_text_pieces=[text],
                prompt_metadata={
                    "rag_target": 1,
                    "rag_status": response.status,
                    "rag_error": response.error[:200] if response.error else "",
                    "rag_chunk_count": len(self._last_chunks),
                },
            )
        ]

    async def cleanup(self) -> None:
        await self._adapter.close()
        if self._retrieval_adapter is not None:
            await self._retrieval_adapter.close()
