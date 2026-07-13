"""AI-300 红队攻击流水线主编排器。

统一编排所有攻击阶段，提供三种执行模式：
  - run_all(): 执行全部 8 个阶段（代码驱动模式）
  - run_phase(): 执行单个阶段
  - run_scenario(): 场景驱动模式（模板驱动，考试推荐）
"""
from __future__ import annotations

import time
from typing import Any

from redteam.core.models import AIService, AttackChain, AuthContext, Finding, ReconResult
from redteam.core.tools import ToolResolver
from redteam.core.terminal_output import print_section_header
from redteam.scenario import (
    ScenarioLoader,
    ScenarioOrchestrator,
    ScenarioReporter,
    AttackTargetType,
)

from .recon_phase import recon_phase
from .injection_phase import injection_phase
from .agent_phase import agent_attack_phase
from .multi_agent_phase import multi_agent_phase
from .rag_phase import rag_attack_phase
from .embeddings_phase import embeddings_attack_phase
from .supply_chain_phase import supply_chain_phase
from .infra_phase import infra_attack_phase
from .report_phase import report_phase


class AIPipeline:
    """AI-300 红队攻击流水线。

    提供完整的 AI 红队评估流程编排：
      - run_all(): 执行全部 9 个阶段
      - run_phase(): 执行单个阶段
      - run_from_config(): YAML 配置驱动模式（考试推荐）
    """

    def __init__(self, resolver: ToolResolver | None = None):
        self.resolver = resolver or ToolResolver()
        self.settings = self.resolver.settings

    def run_all(
        self,
        target: str,
        api_key: str | None = None,
        header_text: str | None = None,
        header_file: str | None = None,
        run_id: str | None = None,
        use_pyrit: bool | None = None,
        phases: list[str] | None = None,
        with_multi_turn: bool = False,
        judge_endpoint: str | None = None,
        judge_api_key: str = "not-needed",
    ) -> dict[str, Any]:
        """执行完整红队评估（9个阶段）。

        Args:
            target: 目标 URL
            api_key: API Key（用于认证，优先于请求头）
            header_text: F12 请求头文本（可选）
            header_file: F12 请求头文件路径（可选）
            run_id: 运行 ID（可选，自动生成）
            use_pyrit: 是否强制使用 PyRIT（None=自动检测）
            phases: 指定执行的阶段列表（默认全部执行）
            with_multi_turn: 启用 Crescendo + TAP 多轮攻击（Ch3.2）
            judge_endpoint: LLM Judge API 端点（Native 路径外部评分）
            judge_api_key: LLM Judge API Key

        Returns:
            完整评估结果字典
        """
        started = time.time()

        run_id, recon, services = recon_phase(
            target, header_text, header_file, run_id, self.resolver
        )

        auth = self._get_auth(api_key, header_text, header_file)

        injection_findings, attack_chain = injection_phase(
            run_id, recon, services,
            auth=auth,
            use_pyrit=use_pyrit,
            with_multi_turn=with_multi_turn,
            judge_endpoint=judge_endpoint,
            judge_api_key=judge_api_key,
        )

        agent_findings = agent_attack_phase(
            run_id, services,
            auth=auth,
            use_pyrit=use_pyrit,
        )

        multi_agent_findings = multi_agent_phase(
            run_id, services,
            auth=auth,
        )

        rag_findings = rag_attack_phase(
            run_id, services,
            auth=auth,
        )

        embedding_findings = embeddings_attack_phase(
            run_id, services,
            auth=auth,
        )

        supply_chain_findings = supply_chain_phase(
            run_id, services,
            auth=auth,
        )

        infra_findings = infra_attack_phase(run_id, recon, services)

        all_findings = (
            injection_findings
            + agent_findings
            + multi_agent_findings
            + rag_findings
            + embedding_findings
            + supply_chain_findings
            + infra_findings
        )

        report = report_phase(run_id, recon, all_findings, attack_chain)

        elapsed = time.time() - started

        print_section_header("ASSESSMENT COMPLETE", f"Total Duration: {elapsed:.1f}s")

        print(f"  Total Findings: {len(all_findings)}")
        print(f"  Run ID: {run_id}")
        print(f"  Report: reports/{run_id}/AI300_Report.md")
        print(f"\n  {'═'*66}")

        return {
            "run_id": run_id,
            "target": target,
            "duration": elapsed,
            "total_duration_seconds": elapsed,
            "findings_count": len(all_findings),
            "recon": recon,
            "services": services,
            "findings": all_findings,
            "attack_chain": attack_chain,
            "report": report,
        }

    def run_phase(
        self,
        phase: str,
        target: str,
        api_key: str | None = None,
        header_text: str | None = None,
        header_file: str | None = None,
        run_id: str | None = None,
        use_pyrit: bool | None = None,
        with_multi_turn: bool = False,
        judge_endpoint: str | None = None,
        judge_api_key: str = "not-needed",
    ) -> Any:
        """执行单个阶段。

        Args:
            phase: 阶段名称（recon, injection, agent, rag, embeddings, supply_chain, infra, report）
            target: 目标 URL
            api_key: API Key（用于认证，优先于请求头）
            header_text: F12 请求头文本（可选）
            header_file: F12 请求头文件路径（可选）
            run_id: 运行 ID（可选）
            use_pyrit: 是否强制使用 PyRIT（None=自动检测）
            with_multi_turn: 启用多轮攻击（仅 injection 阶段有效）
            judge_endpoint: LLM Judge 端点（仅 injection 阶段有效）
            judge_api_key: LLM Judge API Key

        Returns:
            阶段执行结果
        """
        auth = self._get_auth(api_key, header_text, header_file)

        phase_map = {
            "recon": recon_phase,
            "injection": injection_phase,
            "agent": agent_attack_phase,
            "multi_agent": multi_agent_phase,
            "rag": rag_attack_phase,
            "embeddings": embeddings_attack_phase,
            "supply_chain": supply_chain_phase,
            "infra": infra_attack_phase,
            "report": report_phase,
        }

        if phase not in phase_map:
            raise ValueError(f"Unknown phase: {phase}. Available: {list(phase_map.keys())}")

        if phase == "recon":
            return recon_phase(target, header_text, header_file, run_id, self.resolver)
        elif phase == "injection":
            from redteam.core.store import load_json
            from redteam.core.models import ReconResult, AIService
            if not run_id:
                raise ValueError("run_id is required for injection phase")
            recon_data = load_json(run_id, "recon")
            services_data = load_json(run_id, "services")
            recon = ReconResult(**recon_data) if recon_data else ReconResult(target=target)
            services = [AIService(**s) for s in services_data] if services_data else []
            return injection_phase(
                run_id, recon, services, auth, use_pyrit,
                with_multi_turn=with_multi_turn,
                judge_endpoint=judge_endpoint,
                judge_api_key=judge_api_key,
            )
        elif phase == "agent":
            from redteam.core.store import load_json
            from redteam.core.models import AIService
            if not run_id:
                raise ValueError("run_id is required for agent phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return agent_attack_phase(run_id, services, auth, use_pyrit)
        elif phase == "multi_agent":
            from redteam.core.store import load_json
            from redteam.core.models import AIService
            if not run_id:
                raise ValueError("run_id is required for multi_agent phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return multi_agent_phase(run_id, services, auth)
        elif phase == "rag":
            from redteam.core.store import load_json
            from redteam.core.models import AIService
            if not run_id:
                raise ValueError("run_id is required for rag phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return rag_attack_phase(run_id, services, auth)
        elif phase == "embeddings":
            from redteam.core.store import load_json
            from redteam.core.models import AIService
            if not run_id:
                raise ValueError("run_id is required for embeddings phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return embeddings_attack_phase(run_id, services, auth)
        elif phase == "supply_chain":
            from redteam.core.store import load_json
            from redteam.core.models import AIService
            if not run_id:
                raise ValueError("run_id is required for supply_chain phase")
            services_data = load_json(run_id, "services")
            services = [AIService(**s) for s in services_data] if services_data else []
            return supply_chain_phase(run_id, services, auth)
        elif phase == "infra":
            from redteam.core.store import load_json
            from redteam.core.models import ReconResult, AIService
            if not run_id:
                raise ValueError("run_id is required for infra phase")
            recon_data = load_json(run_id, "recon")
            services_data = load_json(run_id, "services")
            recon = ReconResult(**recon_data) if recon_data else ReconResult(target=target)
            services = [AIService(**s) for s in services_data] if services_data else []
            return infra_attack_phase(run_id, recon, services)
        elif phase == "report":
            from redteam.core.store import load_json
            from redteam.core.models import ReconResult, Finding
            if not run_id:
                raise ValueError("run_id is required for report phase")
            recon_data = load_json(run_id, "recon")
            findings_data = load_json(run_id, "findings")
            recon = ReconResult(**recon_data) if recon_data else ReconResult(target=target)
            findings = [Finding(**f) for f in findings_data] if findings_data else []
            return report_phase(run_id, recon, findings)

        return None

    def run_from_config(
        self,
        config_path: str,
        target: str | None = None,
        api_key: str | None = None,
        header_text: str | None = None,
        header_file: str | None = None,
    ) -> dict[str, Any]:
        """YAML 配置驱动模式 — 从配置文件加载完整攻击流水线（考试推荐）。

        配置文件格式示例 config/pipeline.yaml：
          target: https://target.example.com
          phases: [recon, injection, agent, multi_agent, rag, embeddings, supply_chain, infra, report]
          auth:
            bearer: sk-xxx
          settings:
            timeout: 30.0
            max_concurrent: 5
            generate_report: true

        Args:
            config_path: YAML 配置文件路径
            target: 覆盖配置文件中的 target URL
            api_key: API Key（覆盖配置）
            header_text: F12 请求头文本（覆盖配置）
            header_file: F12 请求头文件路径（覆盖配置）

        Returns:
            完整评估结果字典
        """
        import yaml
        from pathlib import Path

        config_path_obj = Path(config_path)
        if not config_path_obj.exists():
            raise FileNotFoundError(f"配置文件不存在: {config_path}")

        with open(config_path_obj, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        # 合并参数：CLI 参数优先于配置文件
        final_target = target or config.get("target", "")
        if not final_target:
            raise ValueError("未指定 target URL（配置文件中未找到且未通过参数传入）")

        final_api_key = api_key or (config.get("auth", {}) or {}).get("bearer")
        final_header_text = header_text or (config.get("auth", {}) or {}).get("header_text")
        final_header_file = header_file or (config.get("auth", {}) or {}).get("header_file")

        # 确定执行的阶段
        phase_list = config.get("phases", None)
        run_id_override = config.get("run_id", None)

        settings = config.get("settings", {})
        use_pyrit = settings.get("use_pyrit", None)
        with_multi_turn = settings.get("with_multi_turn", False)
        judge_endpoint = settings.get("judge_endpoint", None)
        judge_api_key = settings.get("judge_api_key", "not-needed")

        return self.run_all(
            target=final_target,
            api_key=final_api_key,
            header_text=final_header_text,
            header_file=final_header_file,
            run_id=run_id_override,
            use_pyrit=use_pyrit,
            phases=phase_list,
            with_multi_turn=with_multi_turn,
            judge_endpoint=judge_endpoint,
            judge_api_key=judge_api_key,
        )

    def _get_auth(
        self,
        api_key: str | None = None,
        header_text: str | None = None,
        header_file: str | None = None,
    ) -> AuthContext | None:
        """获取认证上下文。

        优先级: api_key > header_file > header_text

        Args:
            api_key: API Key（直接传入，优先级最高）
            header_text: F12 请求头文本
            header_file: F12 请求头文件路径

        Returns:
            AuthContext 或 None
        """
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
    ) -> tuple:
        """侦察阶段 — 快捷方法。"""
        return recon_phase(target, header_text, header_file, run_id, self.resolver)

    def injection_phase(
        self,
        run_id: str,
        recon: ReconResult,
        services: list[AIService],
        auth: AuthContext | None = None,
        use_pyrit: bool | None = None,
        with_multi_turn: bool = False,
        judge_endpoint: str | None = None,
        judge_api_key: str = "not-needed",
    ) -> tuple:
        """注入阶段 — 快捷方法（v2.0 多轮 + LLM Judge）。

        Args:
            run_id: 运行 ID
            recon: 侦察结果
            services: AI 服务列表
            auth: 认证上下文
            use_pyrit: 是否使用 PyRIT
            with_multi_turn: 启用 Crescendo + TAP 多轮攻击
            judge_endpoint: LLM Judge 端点
            judge_api_key: LLM Judge API Key
        """
        return injection_phase(
            run_id, recon, services, auth, use_pyrit,
            with_multi_turn=with_multi_turn,
            judge_endpoint=judge_endpoint,
            judge_api_key=judge_api_key,
        )

    def agent_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
        use_pyrit: bool | None = None,
    ) -> list[Finding]:
        """Agent 攻击阶段 — 快捷方法。"""
        return agent_attack_phase(run_id, services, auth, use_pyrit)

    def multi_agent_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """多 Agent/A2A 攻击阶段 — 快捷方法（AI-300 Ch4）。"""
        return multi_agent_phase(run_id, services, auth)

    def rag_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """RAG 攻击阶段 — 快捷方法。"""
        return rag_attack_phase(run_id, services, auth)

    def embeddings_attack_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """嵌入模型攻击阶段 — 快捷方法。"""
        return embeddings_attack_phase(run_id, services, auth)

    def supply_chain_phase(
        self,
        run_id: str,
        services: list[AIService],
        auth: AuthContext | None = None,
    ) -> list[Finding]:
        """供应链攻击阶段 — 快捷方法。"""
        return supply_chain_phase(run_id, services, auth)

    def infra_attack_phase(
        self,
        run_id: str,
        recon: ReconResult,
        services: list[AIService],
    ) -> list[Finding]:
        """基础设施攻击阶段 — 快捷方法。"""
        return infra_attack_phase(run_id, recon, services)

    def report_phase(
        self,
        run_id: str,
        recon: ReconResult,
        findings: list[Finding],
        attack_chain: AttackChain | None = None,
    ) -> str:
        """报告生成阶段 — 快捷方法。"""
        return report_phase(run_id, recon, findings, attack_chain)

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
        auth = self._get_auth(header_text, header_file)
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

        if generate_report:
            reporter = ScenarioReporter(result)
            reporter.generate()

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
    "AIPipeline",
]