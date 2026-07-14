"""AI-300 红队攻击流水线主编排器。

统一编排所有攻击阶段，以 AI 红队专家角色全局统筹全流程攻击。

两种执行模式（代码驱动）：
  - run_all(): 执行全部 9 个阶段（自动模式）
  - run_from_config(): YAML 数据驱动模式（考试推荐）

扩展方法（通过 PipelineExtensionsMixin 继承）：
  - run_phase(): 执行单个阶段（手动模式）
  - 阶段快捷方法（recon_phase ~ infra_attack_phase）
  - run_scenario(): 场景驱动模式

显示工具（拆分至 runner_display.py）：
  - print_rate_limit_advisory: 速率限制建议展示
  - interactive_rpm_override: RPM 覆盖交互

架构设计哲学（五大核心原则）：
  1. YAML 数据驱动 — 载荷、场景、参数均通过 YAML 配置
  2. AI 红队专家风格 — 每阶段以专业安全分析师视角呈现
  3. Native-First — 纯 httpx 执行，零框架依赖
  4. 全局统筹 — 侦察结果自动驱动后续阶段目标选择
  5. 阶段提示 — 统一横幅 + 实时进度 + 结果摘要
"""
from __future__ import annotations

import time
from typing import Any

from redteam.core.models import AIService, AttackChain, AuthContext, Finding, ReconResult
from redteam.core.rate_limiter import RateLimitGovernor, get_governor
from redteam.core.tools import ToolResolver
from redteam.core.terminal_output import (
    print_phase_banner,
    print_findings_display,
    print_global_findings_summary,
)

from .recon_phase import recon_phase
from .injection_phase import injection_phase
from .agent_phase import agent_attack_phase
from .multi_agent_phase import multi_agent_phase
from .rag_phase import rag_attack_phase
from .embeddings_phase import embeddings_attack_phase
from .supply_chain_phase import supply_chain_phase
from .infra_phase import infra_attack_phase
from .report_writer import ReportWriter
from .runner_display import print_rate_limit_advisory, interactive_rpm_override
from .runner_extensions import PipelineExtensionsMixin


def _append_to_report(
    writer: ReportWriter,
    phase_name: str,
    phase_num: int,
    findings: list[Finding],
    subtitle: str = "",
) -> None:
    """将阶段发现追加到增量报告（Finding 模型 → dict 转换）。"""
    if not findings:
        return
    findings_dict = [
        f.model_dump() if hasattr(f, "model_dump") else f
        for f in findings
    ]
    writer.append_phase(phase_name, phase_num, findings_dict, subtitle)


class AIPipeline(PipelineExtensionsMixin):
    """AI-300 红队攻击流水线。

    提供完整的 AI 红队评估流程编排：
      - run_all(): 执行全部 9 个阶段
      - run_phase(): 执行单个阶段
      - run_from_config(): YAML 配置驱动模式（考试推荐）
      - 阶段快捷方法 + run_scenario() 由 PipelineExtensionsMixin 提供
    """

    def __init__(self, resolver: ToolResolver | None = None):
        self.resolver = resolver or ToolResolver()
        self.settings = self.resolver.settings

    # ── Phase-to-subtitle mapping ──────────────────────────────
    _PHASE_CONFIG: dict[str, dict[str, str]] = {
        "recon": {
            "num": "1", "title": "AI 攻击面侦察",
            "subtitle": "Ch2: AI Surface Recon + Service Discovery + Auth Analysis",
        },
        "injection": {
            "num": "2", "title": "提示注入攻击",
            "subtitle": "Ch3: Prompt Injection + Jailbreak + System Prompt Extraction",
        },
        "agent": {
            "num": "3", "title": "Agent 攻击",
            "subtitle": "Ch3/Ch4: Agent Memory Poison + Goal Hijack + Tool Hijack",
        },
        "multi_agent": {
            "num": "4", "title": "多 Agent / A2A 协议攻击",
            "subtitle": "Ch4: Inter-Agent Trust + Cascading Failure + Rogue Agent",
        },
        "rag": {
            "num": "5", "title": "RAG 流水线攻击",
            "subtitle": "Ch5: Vector DB + Knowledge Poisoning + Retrieval Leakage",
        },
        "embeddings": {
            "num": "6", "title": "嵌入模型攻击",
            "subtitle": "Ch6: Embedding Inversion + Membership/Attribute Inference",
        },
        "supply_chain": {
            "num": "7", "title": "AI 供应链攻击",
            "subtitle": "Ch8: HF Model Integrity + Pickle RCE + Dependency Risks",
        },
        "infra": {
            "num": "8", "title": "MCP + 基础设施攻击",
            "subtitle": "Ch7/Ch9: MCP Tool Hijack + K8s Escape + Cloud IAM Escalation",
        },
    }

    @staticmethod
    def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
        """统计 Finding 列表中各严重等级的计数。"""
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = getattr(f, "severity", "info")
            if hasattr(sev, "value"):
                sev = sev.value
            counts[str(sev).lower()] = counts.get(str(sev).lower(), 0) + 1
        return counts

    @staticmethod
    def _print_phase_result(
        phase_name: str,
        findings: list[Finding],
        total_duration: float | None = None,
        phase_num: int = 0,
    ) -> None:
        """打印单个阶段的结果摘要。"""
        if total_duration is not None:
            print(f"  Duration: {total_duration:.1f}s")

        print_findings_display(
            findings,
            phase_name=phase_name,
            phase_num=phase_num,
        )

    def run_all(
        self,
        target: str,
        api_key: str | None = None,
        header_text: str | None = None,
        header_file: str | None = None,
        run_id: str | None = None,
        phases: list[str] | None = None,
        with_multi_turn: bool = False,
        judge_endpoint: str | None = None,
        judge_api_key: str = "not-needed",
    ) -> dict[str, Any]:
        """执行完整红队评估（YAML 数据驱动端到端自动化攻击）。

        遵循五大核心设计原则：
          1. YAML 数据驱动 — 载荷/场景/参数全部从 YAML 加载
          2. AI 红队专家风格 — 每阶段以专业安全分析师视角呈现结果
          3. Native-First — 纯 httpx 执行，零框架依赖
          4. 全局统筹 — 侦察结果驱动后续目标选择，失败不阻断下游
          5. 阶段提示 — 统一横幅 + 实时进度 + 严重等级分解

        Args:
            target: 目标 URL
            api_key: API Key（用于认证，优先于请求头）
            header_text: F12 请求头文本（可选）
            header_file: F12 请求头文件路径（可选）
            run_id: 运行 ID（可选，自动生成）
            phases: 指定执行的阶段列表（默认全部执行）
            with_multi_turn: 启用 Crescendo + TAP 多轮攻击（Ch3.2）
            judge_endpoint: LLM Judge API 端点（Native 路径外部评分）
            judge_api_key: LLM Judge API Key

        Returns:
            完整评估结果字典
        """
        started = time.time()
        all_phase_order = [
            "recon", "injection", "agent", "multi_agent",
            "rag", "embeddings", "supply_chain", "infra",
        ]
        to_run = phases if phases else all_phase_order

        # Phase 1: Reconnaissance
        if "recon" in to_run:
            cfg = self._PHASE_CONFIG["recon"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            run_id, recon, services, governor = recon_phase(
                target, header_text, header_file, run_id, self.resolver
            )
            svc_count = len(services) if services else 0
            print(f"\n  [green]OK[/] Recon complete: {svc_count} AI services, {getattr(recon, 'components', [])} components")
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, status="complete")
        else:
            raise ValueError("Recon phase (recon) is required as first phase")
            governor = get_governor()  # unreachable, for type checker

        auth = self._get_auth(api_key, header_text, header_file)

        # Init incremental report writer
        writer = ReportWriter(run_id, target)
        writer.append_recon(
            components=list(getattr(recon, "components", [])) if recon else [],
            models=list(getattr(recon, "models", [])) if recon else [],
        )

        # Phase 2: Prompt Injection
        injection_findings: list[Finding] = []
        attack_chain = None
        if "injection" in to_run:
            cfg = self._PHASE_CONFIG["injection"]
            print_phase_banner(
                int(cfg["num"]), cfg["title"],
                target=services[0].url if services else target,
                subtitle=cfg["subtitle"],
                status="active",
            )

            high_rpm_targets = print_rate_limit_advisory(governor, services)

            if high_rpm_targets and governor:
                interactive_rpm_override(governor, high_rpm_targets)

            phase_start = time.time()
            injection_findings, attack_chain = injection_phase(
                run_id, recon, services,
                auth=auth,
                with_multi_turn=with_multi_turn,
                judge_endpoint=judge_endpoint,
                judge_api_key=judge_api_key,
                governor=governor,
            )
            self._print_phase_result("Prompt Injection", injection_findings, time.time() - phase_start, phase_num=2)
            _append_to_report(writer, "Prompt Injection", 2, injection_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # Phase 3: Agent Attack
        agent_findings: list[Finding] = []
        if "agent" in to_run:
            cfg = self._PHASE_CONFIG["agent"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            agent_findings = agent_attack_phase(run_id, services, auth=auth)
            self._print_phase_result("Agent Attack", agent_findings, time.time() - phase_start, phase_num=3)
            _append_to_report(writer, "Agent Attack", 3, agent_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # Phase 4: Multi-Agent / A2A
        multi_agent_findings: list[Finding] = []
        if "multi_agent" in to_run:
            cfg = self._PHASE_CONFIG["multi_agent"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            multi_agent_findings = multi_agent_phase(run_id, services, auth=auth)
            self._print_phase_result("Multi-Agent/A2A Attack", multi_agent_findings, time.time() - phase_start, phase_num=4)
            _append_to_report(writer, "Multi-Agent/A2A Attack", 4, multi_agent_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # Phase 5: RAG Attack
        rag_findings: list[Finding] = []
        if "rag" in to_run:
            cfg = self._PHASE_CONFIG["rag"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            rag_findings = rag_attack_phase(run_id, services, auth=auth)
            self._print_phase_result("RAG Pipeline Attack", rag_findings, time.time() - phase_start, phase_num=5)
            _append_to_report(writer, "RAG Pipeline Attack", 5, rag_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # Phase 6: Embedding Attack
        embedding_findings: list[Finding] = []
        if "embeddings" in to_run:
            cfg = self._PHASE_CONFIG["embeddings"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            embedding_findings = embeddings_attack_phase(run_id, services, auth=auth)
            self._print_phase_result("Embedding Attack", embedding_findings, time.time() - phase_start, phase_num=6)
            _append_to_report(writer, "Embedding Attack", 6, embedding_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # Phase 7: Supply Chain Attack
        supply_chain_findings: list[Finding] = []
        if "supply_chain" in to_run:
            cfg = self._PHASE_CONFIG["supply_chain"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            supply_chain_findings = supply_chain_phase(run_id, services, auth=auth)
            self._print_phase_result("AI Supply Chain Attack", supply_chain_findings, time.time() - phase_start, phase_num=7)
            _append_to_report(writer, "AI Supply Chain Attack", 7, supply_chain_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # Phase 8: Infrastructure Attack
        infra_findings: list[Finding] = []
        if "infra" in to_run:
            cfg = self._PHASE_CONFIG["infra"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            infra_findings = infra_attack_phase(run_id, recon, services)
            self._print_phase_result("MCP + Infrastructure Attack", infra_findings, time.time() - phase_start, phase_num=8)
            _append_to_report(writer, "MCP + Infrastructure Attack", 8, infra_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # Aggregate all findings
        all_findings = (
            injection_findings
            + agent_findings
            + multi_agent_findings
            + rag_findings
            + embedding_findings
            + supply_chain_findings
            + infra_findings
        )

        # Finalize incremental report
        report_path = writer.finalize()

        elapsed = time.time() - started

        # Build per-phase findings map for global summary
        phase_findings_map: dict[str, list[Finding]] = {
            "Prompt Injection": injection_findings,
            "Agent Attack": agent_findings,
            "Multi-Agent/A2A Attack": multi_agent_findings,
            "RAG Pipeline Attack": rag_findings,
            "Embedding Attack": embedding_findings,
            "AI Supply Chain Attack": supply_chain_findings,
            "MCP + Infrastructure Attack": infra_findings,
        }
        print_global_findings_summary(phase_findings_map, elapsed)

        total_tests = len(all_findings)
        all_sev = self._count_by_severity(all_findings)
        crit_high = all_sev["critical"] + all_sev["high"]

        print(f"\n{'=' * 66}")
        print(f"  ASSESSMENT COMPLETE - Duration: {elapsed:.1f}s")
        print(f"  Total Findings: {total_tests}  |  High/Critical: {crit_high}")
        print(f"  Run ID: {run_id}")
        print(f"  Report: reports/{run_id}/AI300_Report.md")
        print(f"{'=' * 66}\n")

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
            "report": str(report_path),
        }

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
          phases: [recon, injection, agent, multi_agent, rag, embeddings, supply_chain, infra]
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
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path_obj, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        final_target = target or config.get("target", "")
        if not final_target:
            raise ValueError("No target URL specified (not in config file or CLI args)")

        final_api_key = api_key or (config.get("auth", {}) or {}).get("bearer")
        final_header_text = header_text or (config.get("auth", {}) or {}).get("header_text")
        final_header_file = header_file or (config.get("auth", {}) or {}).get("header_file")

        phase_list = config.get("phases", None)
        run_id_override = config.get("run_id", None)

        settings = config.get("settings", {})
        with_multi_turn = settings.get("with_multi_turn", False)
        judge_endpoint = settings.get("judge_endpoint", None)
        judge_api_key = settings.get("judge_api_key", "not-needed")

        print_phase_banner(
            0, "YAML Data-Driven Attack Pipeline",
            target=final_target,
            subtitle=f"Config: {config_path} | Phases: {', '.join(phase_list or ['all'])}",
            status="active",
        )
        print(f"  [AI Red Team Expert] Config-as-Attack - Declarative Red Team Mode")
        if phase_list:
            print(f"  Phases: {' -> '.join(phase_list)}")
        print()

        return self.run_all(
            target=final_target,
            api_key=final_api_key,
            header_text=final_header_text,
            header_file=final_header_file,
            run_id=run_id_override,
            phases=phase_list,
            with_multi_turn=with_multi_turn,
            judge_endpoint=judge_endpoint,
            judge_api_key=judge_api_key,
        )


__all__ = [
    "AIPipeline",
]
