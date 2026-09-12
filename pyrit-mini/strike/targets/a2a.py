"""strike/targets/a2a.py — A2ATarget：A2A Agent 的 PyRIT Target（REQ-149 ④）。

封装 A2A 交互（`agent card → tasks/send`）：
    - `fetch_agent_card()` 读取 `/.well-known/agent.json`（技能/能力/信任链分析输入）；
    - `send_task()` 提交任务；`_send_prompt_to_target_async()` 即任务提交，
      响应附 `prompt_metadata`（task_id/status）供跨 Agent 欺骗与信任链判定。

职责边界：只做协议适配，不做内容过滤（NEG-2）。
"""

from __future__ import annotations

import logging
from typing import Any

from pyrit.models import Message, construct_response_from_request
from pyrit.prompt_target.common.prompt_target import PromptTarget

from recon.adapters.base import AdapterResponse, BaseAdapter
from recon.adapters.http import HTTPAdapter

logger = logging.getLogger(__name__)

AGENT_CARD_PATH = "/.well-known/agent.json"
DEFAULT_TASK_PATH = "/a2a/tasks/send"


class A2ATarget(PromptTarget):
    """A2A Agent 的 PyRIT Target（AgentCard + 任务提交）。

    Args:
        adapter: 任务提交通道（POST `tasks/send`）。
        card_adapter: AgentCard 读取通道（GET）；为空时按 `adapter.url` 推导。
        task_path: 任务提交路径。
    """

    def __init__(
        self,
        *,
        adapter: BaseAdapter,
        card_adapter: BaseAdapter | None = None,
        endpoint: str = "",
        model_name: str = "a2a",
        task_path: str = DEFAULT_TASK_PATH,
        system_prompt: str = "",
        max_requests_per_minute: int | None = None,
        **kwargs: Any,
    ) -> None:
        self._adapter = adapter
        self._task_path = task_path
        self._agent_card: dict[str, Any] = {}
        self._last_task: dict[str, Any] = {}
        self._card_adapter = card_adapter
        if self._card_adapter is None:
            base = adapter.url.split("//", 1)[-1].split("/", 1)[0]
            scheme = adapter.url.split("//", 1)[0] or "http:"
            self._card_adapter = HTTPAdapter(url=f"{scheme}//{base}{AGENT_CARD_PATH}", method="GET", verify=adapter.verify)
        # PyRIT 1.0.1 的 PromptTarget 不接收 system_prompt 形参，仅作实例属性保留
        self._system_prompt = system_prompt
        super().__init__(
            endpoint=endpoint or adapter.url,
            model_name=model_name,
            max_requests_per_minute=max_requests_per_minute,
            **kwargs,
        )

    # -- 协议操作 --------------------------------------------------------
    async def fetch_agent_card(self) -> dict[str, Any]:
        """Fetch `/.well-known/agent.json`; returns `{}` on failure (never raises)."""
        response = await self._card_adapter.send("")
        if isinstance(response.payload, dict):
            self._agent_card = response.payload
        elif response.ok:
            logger.debug("[A2ATarget] agent card non-JSON payload")
        return dict(self._agent_card)

    async def send_task(self, text: str, *, task_id: str = "task-1") -> dict[str, Any]:
        """Submit a task; returns the decoded payload (`{}` when not JSON)."""
        request = self._adapter.build_request(text)
        if self._task_path and not request.url.endswith(self._task_path):
            request.url = f"{request.url.rstrip('/')}{self._task_path}"
        response = await self._adapter.send_request(request)
        payload = response.payload if isinstance(response.payload, dict) else {}
        self._last_task = {
            "task_id": payload.get("taskId") or payload.get("task_id") or task_id,
            "status": payload.get("status", ""),
            **payload,
        }
        return dict(self._last_task)

    @property
    def agent_card(self) -> dict[str, Any]:
        return dict(self._agent_card)

    @property
    def last_task(self) -> dict[str, Any]:
        return dict(self._last_task)

    def describe(self) -> dict[str, Any]:
        return {
            "target": "a2a",
            "adapter": self._adapter.describe(),
            "agent_card": self._agent_card,
            "last_task": self._last_task,
        }

    # -- PyRIT 契约 ------------------------------------------------------
    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        request_piece = normalized_conversation[-1].get_piece()
        prompt = request_piece.converted_value or request_piece.original_value or ""

        task = await self.send_task(prompt)
        text = self._adapter.extract_text(AdapterResponse(status=200, payload=task, text=str(task.get("status") or ""))) or str(
            task.get("status") or ""
        )

        return [
            construct_response_from_request(
                request=request_piece,
                response_text_pieces=[text],
                prompt_metadata={
                    "a2a_target": 1,
                    "a2a_task_id": str(task.get("task_id") or ""),
                    "a2a_status": str(task.get("status") or ""),
                },
            )
        ]

    async def cleanup(self) -> None:
        await self._adapter.close()
        if self._card_adapter is not None:
            await self._card_adapter.close()
