"""AI 红队攻击流水线 — 扩展方法 Mixin。

从 runner.py 中拆分，包含阶段快捷方法、单阶段执行 run_phase、
以及场景驱动模式 run_scenario。AIPipeline 通过多重继承获得这些方法。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from redteam.core.models import AIService, AuthContext, Finding, ReconResult
from redteam.core.rate_limiter import RateLimitGovernor
from redteam.core.store import load_json
from redteam.core.terminal_output import print_phase_banner
from redteam.scenario import (
    ScenarioLoader,
    ScenarioOrchestrator,
    AttackTargetType,
)


class PipelineExtensionsMixin:
    """AIPipeline 扩展方法 Mixin。

    提供阶段快捷方法和场景驱动运行模式。
    """

    # 由 AIPipeline 提供
    settings: Any
    resolver: Any

    def _get_auth(
        self,
        api_key: str | None = None,
        header_text: str | None = None,
        header_file: str | None = None,
    ) -> AuthContext | None:
        """获取认证上下文。"""
        if api_key:
            return AuthContext(bearer=api_key)
        from redteam.recon.auth_parse import parse_headers, parse_headers_file
        if header_file:
            return parse_headers_file(header_file)
        elif header_text:
            return parse_headers(header_text)
        return None

    def recon_phase(
        self,
        target: str,
        header_text: str | None = None,
        header_file: str | None = None,
        run_id: str | None = None,
        connectivity=None,
    ) -> tuple:
        """侦察阶段 — 快捷方法。"""
        from .recon_phase import recon_phase
        return recon_phase(target, header_text, header_file, run_id, self.resolver, connectivity=connectivity)

    def injection_phase(
        self,
        run_id: str,
        recon: ReconResult,
        services: list[AIService],
        auth: AuthContext | None = None,
        with_multi_turn: bool = False,
        target_model_name: str = "",
        judge_endpoint: str | None = None,
        judge_api_key: str = "not-needed",
        judge_model_name: str = "",
        governor: "RateLimitGovernor | None" = None,
    ) -> tuple:
        """注入阶段 — 快捷方法。"""
        from .injection_phase import injection_phase as _injection_phase
        return _injection_phase(
            run_id, recon, services, auth,
            with_multi_turn=with_multi_turn,
            target_model_name=target_model_name,
            judge_endpoint=judge_endpoint,
            judge_api_key=judge_api_key,
            judge_model_name=judge_model_name,
            governor=governor,
        )

    def agent_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """Agent 攻击阶段 — 快捷方法。"""
        from .agent_phase import agent_attack_phase as _agent_attack_phase
        return _agent_attack_phase(run_id, services, auth)

    def multi_agent_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """多 Agent/A2A 攻击阶段 — 快捷方法（AI-300 Ch4）。"""
        from .multi_agent_phase import multi_agent_phase as _multi_agent_phase
        return _multi_agent_phase(run_id, services, auth)

    def rag_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """RAG 攻击阶段 — 快捷方法。"""
        from .rag_phase import rag_attack_phase as _rag_attack_phase
        return _rag_attack_phase(run_id, services, auth)

    def embeddings_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """嵌入模型攻击阶段 — 快捷方法。"""
        from .embeddings_phase import embeddings_attack_phase as _embeddings_attack_phase
        return _embeddings_attack_phase(run_id, services, auth)

    def supply_chain_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """供应链攻击阶段 — 快捷方法。"""
        from .supply_chain_phase import supply_chain_phase as _supply_chain_phase
        return _supply_chain_phase(run_id, services, auth)

    def infra_attack_phase(
        self,
        run_id: str,
        recon: ReconResult,
        services: list[AIService],
    ) -> list[Finding]:
        """基础设施攻击阶段 — 快捷方法。"""
        from .infra_phase import infra_attack_phase as _infra_attack_phase
        return _infra_attack_phase(run_id, recon, services)

    def run_phase(
        self,
        phase: str,
        target: str,
        api_key: str | None = None,
        header_text: str | None = None,
        header_file: str | None = None,
        run_id: str | None = None,
        with_multi_turn: bool = False,
        judge_endpoint: str | None = None,
        judge_api_key: str = "not-needed",
    ) -> Any:
        """执行单个阶段。

        Args:
            phase: 阶段名称（recon, injection, agent, rag, embeddings, supply_chain, infra）
            target: 目标 URL
            api_key: API Key（用于认证，优先于请求头）
            header_text: F12 请求头文本（可选）
            header_file: F12 请求头文件路径（可选）
            run_id: 运行 ID（可选）
            with_multi_turn: 启用多轮攻击（仅 injection 阶段有效）
            judge_endpoint: LLM Judge 端点（仅 injection 阶段有效）
            judge_api_key: LLM Judge API Key

        Returns:
            阶段执行结果
        """
        auth = self._get_auth(api_key, header_text, header_file)

        from .recon_phase import recon_phase as _recon_phase
        from .injection_phase import injection_phase as _injection_phase
        from .agent_phase import agent_attack_phase as _agent_attack_phase
        from .multi_agent_phase import multi_agent_phase as _multi_agent_phase
        from .rag_phase import rag_attack_phase as _rag_attack_phase
        from .embeddings_phase import embeddings_attack_phase as _embeddings_attack_phase
        from .supply_chain_phase import supply_chain_phase as _supply_chain_phase
        from .infra_phase import infra_attack_phase as _infra_attack_phase

        phase_map = {
            "recon": _recon_phase,
            "injection": _injection_phase,
            "agent": _agent_attack_phase,
            "multi_agent": _multi_agent_phase,
            "rag": _rag_attack_phase,
            "embeddings": _embeddings_attack_phase,
            "supply_chain": _supply_chain_phase,
            "infra": _infra_attack_phase,
        }

        if phase not in phase_map:
            raise ValueError(f"Unknown phase: {phase}. Available: {list(phase_map.keys())}")

        if phase == "recon":
            run_id, recon, services, gov = _recon_phase(target, header_text, header_file, run_id, self.resolver)
            return run_id, recon, services, gov
        elif phase == "injection":
            if not run_id:
                raise ValueError("run_id is required for injection phase")
            recon_data = load_json(run_id, "recon")
            services_data = load_json(run_id, "services")
            recon = ReconResult(**recon_data) if recon_data else ReconResult(target=target)
            services = [AIService(**s) for s in services_data] if services_data else []
            return _injection_phase(
                run_id, recon, services, auth,
                with_multi_turn=with_multi_turn,
                judge_endpoint=judge_endpoint,
                judge_api_key=judge_api_key,
            )
        elif phase == "agent":
            if not run_id:
                raise ValueError("run_id is required for agent phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return _agent_attack_phase(run_id, services, auth)
        elif phase == "multi_agent":
            if not run_id:
                raise ValueError("run_id is required for multi_agent phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return _multi_agent_phase(run_id, services, auth)
        elif phase == "rag":
            if not run_id:
                raise ValueError("run_id is required for rag phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return _rag_attack_phase(run_id, services, auth)
        elif phase == "embeddings":
            if not run_id:
                raise ValueError("run_id is required for embeddings phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return _embeddings_attack_phase(run_id, services, auth)
        elif phase == "supply_chain":
            if not run_id:
                raise ValueError("run_id is required for supply_chain phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return _supply_chain_phase(run_id, services, auth)
        elif phase == "infra":
            if not run_id:
                raise ValueError("run_id is required for infra phase")
            recon_data = load_json(run_id, "recon")
            services_data = load_json(run_id, "services")
            recon = ReconResult(**recon_data) if recon_data else ReconResult(target=target)
            services = [AIService(**s) for s in services_data] if services_data else []
            return _infra_attack_phase(run_id, recon, services)

        return None

    def run_scenario(
        self,
        scenario_name: str,
        target: str,
        header_text: str | None = None,
        header_file: str | None = None,
        objectives: list[str] | None = None,
        run_id: str | None = None,
        generate_report: bool = True,
    ) -> dict[str, Any]:
        """场景驱动模式 — 模板驱动攻击（考试推荐）。

        考试期间操作流程：
          1. 修改 config/scenarios/agent.yaml 中的载荷内容
          2. 调用此方法或运行: redteam scenario run --scenario agent --target https://xxx
          3. 自动执行所有策略 + 生成报告

        Args:
            scenario_name: 场景名称或目标类型（agent/mcp/rag/generic）
            target: 目标 URL
            header_text: F12 请求头文本（可选）
            header_file: F12 请求头文件路径（可选）
            objectives: 自定义攻击目标列表（可选，覆盖场景默认目标）
            run_id: 运行 ID（可选，自动生成）
            generate_report: 是否生成报告

        Returns:
            场景执行结果字典
        """
        from .report_writer import ReportWriter

        auth = self._get_auth(header_text=header_text, header_file=header_file)
        loader = ScenarioLoader()

        try:
            target_type = AttackTargetType(scenario_name)
            scenario = loader.load_by_target_type(target_type)
        except ValueError:
            scenario = loader.load_by_id(scenario_name)

        if not scenario:
            scenario = loader.load_from_path(scenario_name)

        if not scenario:
            try:
                target_type = AttackTargetType(scenario_name)
                scenario = loader.generate(target_type=target_type, target_url=target)
            except ValueError:
                raise ValueError(f"Unknown scenario: {scenario_name}")

        scenario.attack_config.target_url = target
        if objectives:
            scenario.attack_config.objectives = objectives
        scenario.attack_config.generate_report = generate_report

        orchestrator = ScenarioOrchestrator(
            scenario=scenario,
            auth=auth,
            run_id=run_id,
        )

        result = orchestrator.run_sync()

        # 场景结果写入增量报告
        writer = ReportWriter(result.run_id, target)
        writer.append_recon(components=[], models=[])
        findings_dict = [f.model_dump() for f in result.findings]
        if findings_dict:
            writer.append_phase("Scenario Attack", 0, findings_dict, scenario_name)
        report_path = writer.finalize()

        return {
            "run_id": result.run_id,
            "target": target,
            "scenario": scenario_name,
            "total_attempts": result.total_attempts,
            "success_count": result.success_count,
            "success_rate": result.success_rate,
            "duration": result.elapsed_seconds,
            "findings_count": len(result.findings),
            "findings": [f.model_dump() for f in result.findings],
            "phases": [p.model_dump() for p in result.phases],
        }


__all__ = [
    "PipelineExtensionsMixin",
]
