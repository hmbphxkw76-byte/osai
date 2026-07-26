# -*- coding: utf-8 -*-
"""
RedAmon HTTP Client
===================

封装 RedAmon API 的调用，包括：
- 写入 pyrit-web-recon 的 TargetProfile（种子导入）
- 触发外部侦察 / AI Gauntlet
- 查询知识图谱（Cypher）

注意：RedAmon 应通过 Docker Compose 部署，
本客户端只通过 HTTP 与其交互，不直接 import RedAmon 代码。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class RedAmonClientError(Exception):
    """RedAmon 客户端错误"""

    pass


class RedAmonClient:
    """RedAmon HTTP API 客户端"""

    def __init__(
        self,
        base_url: str = "http://localhost:8010",
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "redamon",
        timeout: float = 30.0,
    ):
        """
        初始化 RedAmon 客户端。

        Args:
            base_url: RedAmon API 地址，默认 http://localhost:8010
            neo4j_uri: Neo4j Bolt 地址，用于直接查询图数据库
            neo4j_user: Neo4j 用户名
            neo4j_password: Neo4j 密码
            timeout: HTTP 超时时间
        """
        self.base_url = base_url.rstrip("/")
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.timeout = timeout
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
            return response.json()
        except httpx.HTTPStatusError as exc:
            raise RedAmonClientError(f"HTTP {exc.response.status_code}: {exc.response.text}") from exc
        except Exception as exc:
            raise RedAmonClientError(f"Request failed: {exc}") from exc

    async def ingest_profile(
        self,
        project_id: str,
        profile_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        将 pyrit-web-recon 的 Profile 写入 RedAmon，作为侦察种子。

        Args:
            project_id: RedAmon 项目 ID
            profile_dict: TargetProfile 序列化后的字典

        Returns:
            RedAmon 返回的写入结果
        """
        payload = {
            "project_id": project_id,
            "profile": profile_dict,
            "source_tool": "pyrit-web-recon",
        }
        data = await self._request(
            "POST",
            f"/api/v1/projects/{project_id}/ingest/profile",
            json=payload,
        )
        logger.info("RedAmon profile ingested: project=%s", project_id)
        return data

    async def trigger_recon(
        self,
        project_id: str,
        target: str,
        depth: str = "standard",
    ) -> Dict[str, Any]:
        """
        触发 RedAmon 外部侦察管线。

        Args:
            project_id: RedAmon 项目 ID
            target: 目标域名或 IP
            depth: 扫描深度，如 quick / standard / deep
        """
        payload = {
            "target": target,
            "depth": depth,
            "source": "pyrit-web-recon",
        }
        data = await self._request(
            "POST",
            f"/api/v1/projects/{project_id}/recon/run",
            json=payload,
        )
        logger.info("RedAmon recon triggered: project=%s target=%s", project_id, target)
        return data

    async def trigger_gauntlet(
        self,
        project_id: str,
        target_endpoint: str,
        model_name: str = "unknown",
    ) -> Dict[str, Any]:
        """
        触发 RedAmon AI Gauntlet（模型红队测试）。

        Args:
            project_id: RedAmon 项目 ID
            target_endpoint: AI 模型 endpoint URL
            model_name: 模型名
        """
        payload = {
            "target_endpoint": target_endpoint,
            "model_name": model_name,
        }
        data = await self._request(
            "POST",
            f"/api/v1/projects/{project_id}/gauntlet/run",
            json=payload,
        )
        logger.info("RedAmon gauntlet triggered: project=%s endpoint=%s", project_id, target_endpoint)
        return data

    async def query_graph(
        self,
        project_id: str,
        cypher: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        通过 RedAmon API 执行 Cypher 查询。

        Args:
            project_id: RedAmon 项目 ID
            cypher: Cypher 查询语句
            parameters: 查询参数
        """
        payload = {
            "project_id": project_id,
            "query": cypher,
            "parameters": parameters or {},
        }
        data = await self._request("POST", "/api/v1/graph/query", json=payload)
        return data.get("results", [])

    async def get_project_summary(self, project_id: str) -> Dict[str, Any]:
        """获取 RedAmon 项目中资产与漏洞的汇总信息"""
        return await self._request("GET", f"/api/v1/projects/{project_id}/summary")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
