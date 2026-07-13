"""统一编排器 — 预固化多阶段攻击流程。

预固化攻击流水线（考试期间一键执行）：
  Phase 1: 变体生成（可选）
  Phase 2: PROBE 快速探测
  Phase 3: 编码攻击（BASE64 + ROT13）
  Phase 4: 语义攻击（ROLEPLAY + STEALTH）
  Phase 5: 前沿漏洞攻击（自动发现活跃漏洞）
  Phase 6: 结果聚合 + 评分

高频策略优先执行，保证考试期间攻击效率。

使用方式：
  orchestrator = PipelineOrchestrator(target_url, auth)
  results = orchestrator.run(objectives, payloads)
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from redteam.attack.core.runner import NativeAttackRunner
from redteam.attack.core.strategy_router import AttackStrategy, StrategyRouter
from redteam.attack.frontier.adapter import FrontierAdapter
from redteam.core.models import AuthContext, Finding, PromptInjectionResult

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """统一编排器 — 预固化多阶段攻击流程。"""

    DEFAULT_PHASES = [
        ("probe", [AttackStrategy.PROBE]),
        ("encoding", [AttackStrategy.BASE64, AttackStrategy.ROT13]),
        ("semantic", [AttackStrategy.ROLEPLAY, AttackStrategy.STEALTH]),
        ("frontier", [AttackStrategy.FRONTIER]),
    ]

    def __init__(
        self,
        target_url: str,
        auth: AuthContext | None = None,
        timeout: float = 30.0,
        enable_frontier: bool = True,
        max_concurrent: int = 5,
    ):
        self._target_url = target_url
        self._auth = auth
        self._timeout = timeout
        self._enable_frontier = enable_frontier
        self._max_concurrent = max_concurrent

        self._router = StrategyRouter(target_url, auth, timeout)
        self._native_runner = NativeAttackRunner(target_url, auth, timeout=timeout)

        if enable_frontier:
            self._frontier_adapter = FrontierAdapter(self._native_runner)
        else:
            self._frontier_adapter = None

        self._results: list[dict] = []
        self._findings: list[Finding] = []

    async def run(
        self,
        objectives: list[str],
        payload_templates: list[str] | None = None,
        phases: list[tuple[str, list[AttackStrategy]]] | None = None,
    ) -> dict:
        """执行完整攻击流水线。

        Args:
            objectives: 攻击目标描述列表
            payload_templates: 载荷模板列表（可选，留空则使用默认载荷）
            phases: 自定义攻击阶段（可选，留空则使用默认阶段）

        Returns:
            攻击结果汇总字典
        """
        start_time = time.time()
        self._results.clear()
        self._findings.clear()

        active_phases = phases or self.DEFAULT_PHASES
        logger.info(f"Starting pipeline orchestration with {len(active_phases)} phases")

        for phase_name, strategies in active_phases:
            if phase_name == "frontier" and not self._frontier_adapter:
                logger.info("Frontier phase skipped (disabled)")
                continue

            logger.info(f"Executing phase: {phase_name}")
            phase_results = await self._execute_phase(objectives, payload_templates, strategies)
            self._results.extend(phase_results)

        elapsed = time.time() - start_time
        success_count = sum(1 for r in self._results if r.get("success"))

        summary = {
            "total_attempts": len(self._results),
            "success_count": success_count,
            "success_rate": round(success_count / max(len(self._results), 1) * 100, 2),
            "elapsed_seconds": round(elapsed, 2),
            "phases": [p[0] for p in active_phases],
            "findings": [f.dict() for f in self._findings],
            "results": self._results,
        }

        logger.info(f"Pipeline completed: {success_count}/{len(self._results)} successes in {elapsed:.1f}s")
        return summary

    async def _execute_phase(
        self,
        objectives: list[str],
        payload_templates: list[str] | None,
        strategies: list[AttackStrategy],
    ) -> list[dict]:
        """执行单个攻击阶段。"""
        phase_results = []

        for strategy in strategies:
            if strategy == AttackStrategy.FRONTIER:
                if self._frontier_adapter:
                    for objective in objectives:
                        findings = self._frontier_adapter.run_all_active(objective)
                        self._findings.extend(findings)
                        for finding in findings:
                            phase_results.append({
                                "strategy": "frontier",
                                "payload": f"Frontier vuln: {finding.title}",
                                "success": True,
                                "response_preview": finding.evidence,
                                "finding": finding.dict(),
                            })
            else:
                runner = self._router.get_runner(strategy)
                for objective in objectives:
                    if payload_templates:
                        for template in payload_templates:
                            payload = template.format(objective=objective) if "{objective}" in template else template
                            result = runner.send_prompt(payload)
                            phase_results.append(self._to_result_dict(strategy, payload, result))
                    else:
                        default_payload = f"Execute the following objective: {objective}"
                        result = runner.send_prompt(default_payload)
                        phase_results.append(self._to_result_dict(strategy, default_payload, result))

        return phase_results

    def _to_result_dict(
        self,
        strategy: AttackStrategy,
        payload: str,
        result: PromptInjectionResult,
    ) -> dict:
        """将 PromptInjectionResult 转换为结果字典。"""
        return {
            "strategy": strategy.value,
            "payload": payload,
            "success": result.success,
            "response_preview": result.response_preview,
            "guardrail_triggered": result.guardrail_triggered,
            "extracted_info": result.extracted_info,
            "score": getattr(result, "score", 0.0),
        }

    def run_sync(
        self,
        objectives: list[str],
        payload_templates: list[str] | None = None,
        phases: list[tuple[str, list[AttackStrategy]]] | None = None,
    ) -> dict:
        """同步执行攻击流水线。"""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return asyncio.create_task(
                    self.run(objectives, payload_templates, phases)
                ).result()
            return loop.run_until_complete(
                self.run(objectives, payload_templates, phases)
            )
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                self.run(objectives, payload_templates, phases)
            )

    def get_findings(self) -> list[Finding]:
        """获取所有发现的漏洞。"""
        return self._findings

    def get_results(self) -> list[dict]:
        """获取所有攻击结果。"""
        return self._results
