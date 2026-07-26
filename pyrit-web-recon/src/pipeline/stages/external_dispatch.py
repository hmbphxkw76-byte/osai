# -*- coding: utf-8 -*-
"""
阶段 11：外部调度（External Dispatch）

在 ExportStage 之后运行，将 pyrit-web-recon 生成的 TargetProfile
发布到共享层（消息总线 / 对象存储 / 事件文件），供 AI-Infra-Guard 与 RedAmon 消费。

设计原则：
- 不阻塞原流水线：外部调度失败不影响 recon 主流程成功。
- 解耦：不直接 import AIG/RedAmon 代码，只发布标准化事件。
- 可扩展：通过配置决定是否启用 AIG/RedAmon 调度。
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List

from src.pipeline.base import PipelineStage
from src.pipeline.context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class ExternalDispatchStage(PipelineStage):
    """外部调度阶段"""

    name = "external_dispatch"
    description = "将 TargetProfile 发布到消息总线，触发 AIG / RedAmon 后续侦察"

    async def run(self, context: PipelineContext) -> StageResult:
        # 1. 获取 Profile 与导出路径
        profile = context.profile
        export_result = context.get_result("export")

        if not profile:
            return StageResult(
                success=False,
                message="未生成 TargetProfile，跳过外部调度",
                data={},
            )

        # 2. 读取 export 阶段产出的 profile 文件路径
        profile_path = ""
        if export_result and export_result.data:
            profile_path = export_result.data.get("profile_path", "")

        # 3. 构造标准事件
        event = self._build_event(context, profile_path)

        # 4. 发布事件（多种通道，按配置启用）
        dispatched: List[str] = []

        # 4a. 写入本地事件文件（最简实现，不依赖外部中间件）
        if self._config(context, "dispatch_event_file", True):
            event_path = self._write_event_file(context, event)
            dispatched.append(f"event_file:{event_path}")

        # 4b. 如果启用 Redis/NATS，发布到消息总线
        if self._config(context, "dispatch_message_bus", False):
            await self._publish_to_bus(context, event)
            dispatched.append("message_bus")

        # 4c. 如果启用直接 AIG 调度，则立即提交任务（异步不阻塞）
        if self._config(context, "dispatch_aig", False):
            aig_session_ids = await self._dispatch_aig(context, profile)
            event["aig_session_ids"] = aig_session_ids
            dispatched.append(f"aig:{len(aig_session_ids)} tasks")

        # 4d. 如果启用直接 RedAmon 调度，则立即写入图
        if self._config(context, "dispatch_redamon", False):
            redamon_result = await self._dispatch_redamon(context, profile)
            event["redamon_result"] = redamon_result
            dispatched.append("redamon")

        return StageResult(
            success=True,
            message=f"外部调度完成: {', '.join(dispatched) or '无'}" ,
            data={
                "event": event,
                "dispatched_channels": dispatched,
            },
        )

    def _build_event(self, context: PipelineContext, profile_path: str) -> Dict[str, Any]:
        """构造标准化 recon.profile.created 事件"""
        profile = context.profile
        artifacts = {}
        if profile:
            artifacts = {
                "profile_path": profile_path,
                "screenshot_path": profile.raw_results.get("screenshot_path", ""),
                "storage_state_path": profile.raw_results.get("storage_state_path", ""),
            }

        return {
            "event_type": "recon.profile.created",
            "version": "1.0",
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "project_id": self._config(context, "project_id", "default"),
            "target_url": context.target_url,
            "target_type": context.target_type,
            "profile_uri": profile_path,
            "artifacts": artifacts,
            "tags": [context.target_type, profile.fingerprint.model_family if profile else ""],
        }

    def _write_event_file(self, context: PipelineContext, event: Dict[str, Any]) -> str:
        """将事件写入本地 results/recon/events/ 目录"""
        events_dir = self._config(context, "events_dir", "results/recon/events")
        os.makedirs(events_dir, exist_ok=True)

        # 文件名包含时间戳和目标域名
        from src.auth import normalize_domain
        domain = normalize_domain(context.target_url)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{domain}_{timestamp}_{event['event_id'][:8]}.json"
        path = os.path.join(events_dir, filename)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(event, f, ensure_ascii=False, indent=2)

        logger.info("External dispatch event written: %s", path)
        return path

    async def _publish_to_bus(self, context: PipelineContext, event: Dict[str, Any]) -> None:
        """发布到消息总线（Redis / NATS）"""
        # 占位实现：实际应根据配置初始化 redis-py 或 nats-py 客户端
        bus_url = self._config(context, "message_bus_url", "")
        if not bus_url:
            logger.warning("message_bus_url 未配置，跳过消息总线发布")
            return

        # TODO: 接入 redis-py / nats-py 客户端
        logger.info("Publishing event to message bus: %s", bus_url)

    async def _dispatch_aig(
        self,
        context: PipelineContext,
        profile: Any,
    ) -> List[str]:
        """直接调度 AI-Infra-Guard 任务"""
        from src.integration.aig.client import AIGClient
        from src.integration.aig.task_builder import AIGTaskBuilder

        base_url = self._config(context, "aig_base_url", "http://localhost:8088")
        session_ids: List[str] = []

        async with AIGClient(base_url=base_url) as client:
            builder = AIGTaskBuilder(profile)
            tasks = builder.build_all()
            for task in tasks:
                try:
                    session_id = await client.create_task(task["type"], task["content"])
                    session_ids.append(session_id)
                    logger.info("Dispatched AIG task: type=%s session=%s", task["type"], session_id)
                except Exception as exc:
                    logger.warning("Failed to dispatch AIG task %s: %s", task["type"], exc)

        return session_ids

    async def _dispatch_redamon(
        self,
        context: PipelineContext,
        profile: Any,
    ) -> Dict[str, Any]:
        """直接调度 RedAmon 图写入"""
        from src.integration.redamon.client import RedAmonClient
        from src.integration.redamon.profile_to_graph_adapter import ProfileToGraphAdapter

        project_id = self._config(context, "project_id", "default")
        base_url = self._config(context, "redamon_base_url", "http://localhost:8010")

        adapter = ProfileToGraphAdapter(project_id=project_id)
        payload = adapter.to_redamon_payload(profile)

        async with RedAmonClient(base_url=base_url) as client:
            try:
                result = await client.ingest_profile(project_id, payload)
                logger.info("Dispatched RedAmon profile ingest: project=%s", project_id)
                return {"success": True, "result": result}
            except Exception as exc:
                logger.warning("Failed to dispatch RedAmon ingest: %s", exc)
                return {"success": False, "error": str(exc)}
