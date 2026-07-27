# -*- coding: utf-8 -*-
"""
Job Scheduler / Orchestrator
============================

一体化侦察作业编排器：
1. 接收目标 (target_url) 与配置
2. 校验 RoE（Rules of Engagement）
3. 运行 ai300-recon 11 阶段流水线
4. 将结果分发到 AI-Infra-Guard 与 RedAmon
5. 异步轮询 AIG 任务结果
6. 收集、去重、关联发现，写入统一结果存储

设计原则：
- 共享层核心组件，不耦合具体工具实现。
- 通过 Adapter 模式支持未来扩展其他扫描工具。
- 失败隔离：AIG/RedAmon 失败不影响主 recon 流程。
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.integration.aig.client import AIGClient
from src.integration.aig.result_normalizer import AIGResultNormalizer
from src.integration.aig.task_builder import AIGTaskBuilder
from src.integration.redamon.client import RedAmonClient
from src.integration.redamon.profile_to_graph_adapter import ProfileToGraphAdapter
from src.integration.schemas.unified_finding import UnifiedFinding, dedup_findings
from src.integration.skillspector.client import SkillSpectorClient, SkillSpectorMode
from src.integration.skillspector.result_normalizer import SkillSpectorResultNormalizer
from src.pipeline.context import PipelineContext
from src.pipeline.runner import PipelineRunner
from src.pipeline.stages import (
    APIProbeStage,
    AnalysisStage,
    AuthenticationStage,
    CredentialDiscoveryStage,
    CredentialExtractionStage,
    DOMReconStage,
    EntryDiscoveryStage,
    ExportStage,
    NavigationStage,
    NetworkInterceptionStage,
    ProbeInteractionStage,
)
from src.recon.target_profile import TargetProfile

logger = logging.getLogger(__name__)


@dataclass
class JobConfig:
    """作业配置"""

    target_url: str = ""
    target_type: str = "auto"
    project_id: str = "default"
    user_id: str = ""
    headless: bool = False

    # 各工具开关
    enable_ai300_recon: bool = True
    enable_aig: bool = False
    enable_redamon: bool = False
    enable_skillspector: bool = False

    # AIG 配置
    aig_base_url: str = "http://localhost:8088"
    aig_poll_interval: float = 2.0
    aig_max_poll_time: float = 600.0

    # RedAmon 配置
    redamon_base_url: str = "http://localhost:8010"

    # SkillSpector 配置
    skillspector_mode: SkillSpectorMode = SkillSpectorMode.SUBPROCESS
    skillspector_docker_image: str = "skillspector:latest"
    skillspector_inputs: List[str] = field(default_factory=list)
    skillspector_no_llm: bool = True
    skillspector_timeout: float = 300.0

    # ai300-recon 配置
    pipeline_config: Dict[str, Any] = field(default_factory=dict)

    # 认证信息（用于登录页自动填充）
    username: str = ""
    password: str = ""


@dataclass
class JobResult:
    """作业执行结果"""

    job_id: str = ""
    success: bool = False
    message: str = ""
    profile: Optional[TargetProfile] = None
    aig_findings: List[UnifiedFinding] = field(default_factory=list)
    redamon_findings: List[UnifiedFinding] = field(default_factory=list)
    skillspector_findings: List[UnifiedFinding] = field(default_factory=list)
    all_findings: List[UnifiedFinding] = field(default_factory=list)
    aig_session_ids: List[str] = field(default_factory=list)
    redamon_result: Optional[Dict[str, Any]] = None
    skillspector_reports: List[Dict[str, Any]] = field(default_factory=list)


class JobScheduler:
    """一体化侦察作业调度器"""

    def __init__(self, job_config: JobConfig):
        """
        初始化调度器。

        Args:
            job_config: 作业配置
        """
        self.config = job_config

    async def run(self) -> JobResult:
        """
        执行完整的一体化侦察作业。

        Returns:
            JobResult，包含 Profile、AIG/RedAmon 发现与统一发现列表
        """
        result = JobResult(job_id=self.config.project_id)

        # 1. 如果 config.target_url 为空，尝试从环境变量读取
        if not self.config.target_url:
            env_target = os.getenv("RECON_TARGET_URL", "").strip()
            if env_target:
                self.config.target_url = env_target
                logger.info("从 RECON_TARGET_URL 环境变量读取目标: %s", env_target)

        # 2. RoE 校验
        if not self._check_roe(self.config.target_url):
            result.message = "RoE 校验失败：目标未授权"
            return result

        # 3. 运行 ai300-recon 流水线
        profile: Optional[TargetProfile] = None
        if self.config.enable_ai300_recon:
            profile = await self._run_recon_pipeline()
            result.profile = profile

        if not profile:
            result.message = "ai300-recon 未生成 Profile"
            return result

        # 3. 并行分发到 AIG、RedAmon 与 SkillSpector
        tasks: List[asyncio.Task] = []

        if self.config.enable_aig:
            tasks.append(asyncio.create_task(self._run_aig(profile)))

        if self.config.enable_redamon:
            tasks.append(asyncio.create_task(self._run_redamon(profile)))

        if self.config.enable_skillspector:
            tasks.append(asyncio.create_task(self._run_skillspector(profile)))

        # 等待所有分发任务完成
        if tasks:
            gathered = await asyncio.gather(*tasks, return_exceptions=True)
            for item in gathered:
                if isinstance(item, Exception):
                    logger.warning("分发任务异常: %s", item)
                    continue

                if not isinstance(item, dict):
                    continue

                if "aig_session_ids" in item:
                    result.aig_session_ids = item.get("aig_session_ids", [])
                    result.aig_findings = item.get("findings", [])
                elif "redamon_result" in item:
                    result.redamon_result = item.get("redamon_result")
                elif "skillspector_reports" in item:
                    result.skillspector_findings = item.get("findings", [])
                    result.skillspector_reports = item.get("skillspector_reports", [])

        # 4. 关联与去重
        result.all_findings = dedup_findings(
            result.aig_findings + result.redamon_findings + result.skillspector_findings
        )

        result.success = True
        result.message = (
            f"作业完成: target={profile.target}, "
            f"aig_findings={len(result.aig_findings)}, "
            f"redamon_findings={len(result.redamon_findings)}, "
            f"skillspector_findings={len(result.skillspector_findings)}, "
            f"unified={len(result.all_findings)}"
        )
        return result

    def _build_pipeline_runner(self) -> PipelineRunner:
        """构造默认的 11 阶段 PipelineRunner"""
        stages = [
            CredentialDiscoveryStage(),
            AuthenticationStage(),
            APIProbeStage(),
            NavigationStage(),
            NetworkInterceptionStage(),
            EntryDiscoveryStage(),
            DOMReconStage(),
            ProbeInteractionStage(),
            AnalysisStage(),
            CredentialExtractionStage(),
            ExportStage(),
        ]
        return PipelineRunner(stages=stages)

    async def _run_recon_pipeline(self) -> Optional[TargetProfile]:
        """运行 ai300-recon 流水线"""
        # 合并用户传入的 pipeline_config，并注入 username/password 用于登录页自动填充
        pipeline_config = dict(self.config.pipeline_config)
        if self.config.username:
            pipeline_config["username"] = self.config.username
        if self.config.password:
            pipeline_config["password"] = self.config.password

        context = PipelineContext(
            target_url=self.config.target_url,
            target_type=self.config.target_type,
            headless=self.config.headless,
            config=pipeline_config,
        )
        runner = self._build_pipeline_runner()
        final_context = await runner.run(context)
        return final_context.profile if final_context else None

    async def _run_aig(
        self,
        profile: TargetProfile,
    ) -> Dict[str, Any]:
        """
        向 AI-Infra-Guard 提交任务并轮询结果。

        Returns:
            {"aig_session_ids": [...], "findings": [...]}
        """
        builder = AIGTaskBuilder(profile)
        tasks = builder.build_all()

        session_ids: List[str] = []
        all_findings: List[UnifiedFinding] = []
        normalizer = AIGResultNormalizer()

        async with AIGClient(
            base_url=self.config.aig_base_url,
            poll_interval=self.config.aig_poll_interval,
            max_poll_time=self.config.aig_max_poll_time,
        ) as client:
            # 并发提交所有任务
            create_tasks = [
                asyncio.create_task(self._safe_create_task(client, t))
                for t in tasks
            ]
            created = await asyncio.gather(*create_tasks)

            # 过滤成功创建的任务
            pending: List[tuple[str, str]] = []
            for session_id, task_type in created:
                if session_id:
                    session_ids.append(session_id)
                    pending.append((session_id, task_type))

            # 并发轮询所有任务结果
            poll_tasks = [
                asyncio.create_task(self._safe_wait_task(client, sid, ttype, profile.target, normalizer))
                for sid, ttype in pending
            ]
            polled = await asyncio.gather(*poll_tasks)

            for findings in polled:
                all_findings.extend(findings)

        return {
            "aig_session_ids": session_ids,
            "findings": all_findings,
        }

    async def _safe_create_task(
        self,
        client: AIGClient,
        task: Dict[str, Any],
    ) -> tuple[str, str]:
        """安全地创建 AIG 任务"""
        try:
            session_id = await client.create_task(task["type"], task["content"])
            return session_id, task["type"]
        except Exception as exc:
            logger.warning("AIG 任务创建失败 type=%s: %s", task["type"], exc)
            return "", task["type"]

    async def _safe_wait_task(
        self,
        client: AIGClient,
        session_id: str,
        task_type: str,
        target: str,
        normalizer: AIGResultNormalizer,
    ) -> List[UnifiedFinding]:
        """安全地等待 AIG 任务并规范化结果"""
        try:
            outcome = await client.wait_for_task(session_id)
            result_data = outcome.get("result", {})
            return normalizer.normalize(task_type, session_id, result_data, target)
        except Exception as exc:
            logger.warning("AIG 任务轮询失败 session=%s: %s", session_id, exc)
            return []

    async def _run_redamon(
        self,
        profile: TargetProfile,
    ) -> Dict[str, Any]:
        """
        将 Profile 写入 RedAmon 并触发后续侦察。

        Returns:
            {"redamon_result": {...}}
        """
        project_id = self.config.project_id
        adapter = ProfileToGraphAdapter(project_id=project_id, user_id=self.config.user_id)
        payload = adapter.to_redamon_payload(profile)

        async with RedAmonClient(base_url=self.config.redamon_base_url) as client:
            try:
                ingest_result = await client.ingest_profile(project_id, payload)

                # 可选：触发 RedAmon 外部侦察
                trigger_result = await client.trigger_recon(
                    project_id=project_id,
                    target=profile.target,
                    depth=profile.recon_depth,
                )

                return {
                    "redamon_result": {
                        "success": True,
                        "ingest": ingest_result,
                        "trigger": trigger_result,
                    }
                }
            except Exception as exc:
                logger.warning("RedAmon 调度失败: %s", exc)
                return {
                    "redamon_result": {
                        "success": False,
                        "error": str(exc),
                    }
                }

    async def _run_skillspector(
        self,
        profile: TargetProfile,
    ) -> Dict[str, Any]:
        """
        调用 SkillSpector 扫描 AI agent skills / MCP skills。

        Returns:
            {"findings": [...], "skillspector_reports": [...]}
        """
        inputs = list(self.config.skillspector_inputs)

        # 如果未显式配置输入，尝试从 Profile 中提取 skill 相关路径/URL
        if not inputs:
            inputs = self._extract_skill_inputs_from_profile(profile)

        if not inputs:
            logger.info("未找到 SkillSpector 扫描目标，跳过")
            return {"findings": [], "skillspector_reports": []}

        client = SkillSpectorClient(
            mode=self.config.skillspector_mode,
            docker_image=self.config.skillspector_docker_image,
            timeout=self.config.skillspector_timeout,
            no_llm=self.config.skillspector_no_llm,
        )
        normalizer = SkillSpectorResultNormalizer()

        all_findings: List[UnifiedFinding] = []
        reports: List[Dict[str, Any]] = []

        # 由于 client.scan 是同步阻塞（子进程/Docker），放到线程池执行
        loop = asyncio.get_event_loop()
        for input_path in inputs:
            try:
                report = await loop.run_in_executor(
                    None,
                    client.scan,
                    input_path,
                    "json",
                )
                reports.append({
                    "input": input_path,
                    "report": report,
                })
                findings = normalizer.normalize(
                    report,
                    target=profile.target,
                    session_id=f"skillspector:{input_path}",
                )
                all_findings.extend(findings)
                logger.info(
                    "SkillSpector 扫描完成: input=%s findings=%s",
                    input_path,
                    len(findings),
                )
            except Exception as exc:
                logger.warning("SkillSpector 扫描失败 input=%s: %s", input_path, exc)

        return {
            "findings": all_findings,
            "skillspector_reports": reports,
        }

    def _extract_skill_inputs_from_profile(self, profile: TargetProfile) -> List[str]:
        """从 Profile 中提取可能的 skill 输入路径/URL"""
        inputs: List[str] = []

        # 从 agent_features 中提取 skill 目录或 Git URL
        for feat in profile.fingerprint.agent_features:
            skill_path = feat.get("skill_path") or feat.get("skill_url") or ""
            if skill_path and skill_path not in inputs:
                inputs.append(skill_path)

        # 从 rag_features 中提取知识库文档路径
        for feat in profile.fingerprint.rag_features:
            doc_path = feat.get("doc_path") or feat.get("source_url") or ""
            if doc_path and doc_path not in inputs:
                inputs.append(doc_path)

        return inputs

    def _check_roe(self, target_url: str) -> bool:
        """
        Rules of Engagement 校验。

        简单实现：检查目标 URL 是否为空、是否在黑名单中。
        生产环境应接入 Central Config Service 与 Vault。
        """
        if not target_url:
            return False

        # 简单黑名单示例
        blacklist = ["localhost", "127.0.0.1", "0.0.0.0"]
        for blocked in blacklist:
            if blocked in target_url:
                logger.warning("RoE 黑名单命中: %s", target_url)
                return False

        return True
