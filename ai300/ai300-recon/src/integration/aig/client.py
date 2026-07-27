# -*- coding: utf-8 -*-
"""
AI-Infra-Guard HTTP Client
==========================

封装 AIG 的任务创建、状态轮询、结果拉取接口。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class AIGClientError(Exception):
    """AIG 客户端错误"""

    pass


class AIGClient:
    """AI-Infra-Guard HTTP API 客户端"""

    def __init__(
        self,
        base_url: str = "http://localhost:8088",
        timeout: float = 30.0,
        poll_interval: float = 2.0,
        max_poll_time: float = 600.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_poll_time = max_poll_time
        self._client = httpx.AsyncClient(timeout=timeout)

    async def close(self):
        """关闭 HTTP 客户端"""
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """发送请求并解析通用响应"""
        url = f"{self.base_url}{path}"
        try:
            response = await self._client.request(method, url, **kwargs)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            raise AIGClientError(f"HTTP {exc.response.status_code}: {exc.response.text}") from exc
        except Exception as exc:
            raise AIGClientError(f"Request failed: {exc}") from exc

        if data.get("status") != 0:
            raise AIGClientError(f"AIG API error: {data.get('message')} (status={data.get('status')})")
        return data.get("data", {})

    async def upload_file(self, file_path: str) -> str:
        """
        上传文件到 AIG，返回 fileUrl。
        """
        import pathlib

        path = pathlib.Path(file_path)
        if not path.exists():
            raise AIGClientError(f"File not found: {file_path}")

        with path.open("rb") as f:
            files = {"file": (path.name, f, "application/octet-stream")}
            data = await self._request("POST", "/api/v1/app/taskapi/upload", files=files)

        file_url = data.get("fileUrl")
        if not file_url:
            raise AIGClientError("Upload response missing fileUrl")
        logger.info("AIG file uploaded: %s -> %s", file_path, file_url)
        return file_url

    async def create_task(
        self,
        task_type: str,
        content: Dict[str, Any],
    ) -> str:
        """
        创建扫描任务，返回 session_id。

        Args:
            task_type: mcp_scan / ai_infra_scan / model_redteam_report / agent_scan
            content: 任务内容，由 AIGTaskBuilder 构造
        """
        payload = {"type": task_type, "content": content}
        data = await self._request("POST", "/api/v1/app/taskapi/tasks", json=payload)
        session_id = data.get("session_id")
        if not session_id:
            raise AIGClientError("Create task response missing session_id")
        logger.info("AIG task created: type=%s session_id=%s", task_type, session_id)
        return session_id

    async def get_task_status(self, session_id: str) -> Dict[str, Any]:
        """获取任务状态"""
        # 优先尝试 /tasks/{id}/status，再回退 /tasks/{id}
        for path in [f"/api/v1/app/taskapi/tasks/{session_id}/status", f"/api/v1/app/taskapi/tasks/{session_id}"]:
            try:
                return await self._request("GET", path)
            except AIGClientError as exc:
                if "404" in str(exc):
                    continue
                raise
        raise AIGClientError(f"Task status endpoint not found for {session_id}")

    async def get_task_result(self, session_id: str) -> Dict[str, Any]:
        """获取任务结果"""
        for path in [f"/api/v1/app/taskapi/tasks/{session_id}/result", f"/api/v1/app/taskapi/tasks/{session_id}"]:
            try:
                return await self._request("GET", path)
            except AIGClientError as exc:
                if "404" in str(exc):
                    continue
                raise
        raise AIGClientError(f"Task result endpoint not found for {session_id}")

    async def wait_for_task(
        self,
        session_id: str,
        terminal_statuses: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        轮询任务直到完成或超时。

        Returns:
            最终任务状态/结果字典
        """
        terminal_statuses = terminal_statuses or ["completed", "failed", "error", "done", "success"]
        deadline = asyncio.get_event_loop().time() + self.max_poll_time

        while asyncio.get_event_loop().time() < deadline:
            status_data = await self.get_task_status(session_id)
            status = status_data.get("status", "").lower()
            logger.debug("AIG task %s status: %s", session_id, status)

            if status in terminal_statuses:
                # 尝试同时拉取结果
                try:
                    result_data = await self.get_task_result(session_id)
                except AIGClientError:
                    result_data = {}
                return {"status": status_data, "result": result_data}

            await asyncio.sleep(self.poll_interval)

        raise AIGClientError(f"Polling timed out for task {session_id} after {self.max_poll_time}s")

    async def submit_and_wait(
        self,
        task_type: str,
        content: Dict[str, Any],
    ) -> Dict[str, Any]:
        """创建任务并等待完成（同步风格）"""
        session_id = await self.create_task(task_type, content)
        return await self.wait_for_task(session_id)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
