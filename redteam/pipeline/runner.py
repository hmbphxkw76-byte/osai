"""AI-300 红队攻击流水线主编排器。

统一编排所有攻击阶段，以 AI 红队专家角色全局统筹全流程攻击。

三种执行模式：
  - run_all(): 执行全部 9 个阶段（代码驱动模式，自动模式）
  - run_phase(): 执行单个阶段（手动模式）
  - run_from_config(): YAML 数据驱动模式（考试推荐）

架构设计哲学（五大核心原则）：
  1. YAML 数据驱动 — 载荷、场景、参数均通过 YAML 配置
  2. AI 红队专家风格 — 每阶段以专业安全分析师视角呈现
  3. PyRIT 专家指导 — 自动推荐最优转换器+评分策略
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
    print_result_bar,
    print_findings_display,
    print_global_findings_summary,
)
from redteam.scenario import (
    ScenarioLoader,
    ScenarioOrchestrator,
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
from .report_writer import ReportWriter


def _print_rate_limit_advisory(
    governor: RateLimitGovernor,
    services: list[AIService],
) -> list[dict[str, Any]]:
    """PyRIT 攻击前展示调速策略建议（AI 红队专家风格）。

    基于 Phase 1 速率限制探测结果，为攻击执行器推荐安全的请求速率
    和执行模式（batch/sequential）。

    v2.2: 新增 30 RPM 能力提示和 15 RPM 保守默认值展示。

    Args:
        governor: 自适应调速器实例
        services: AI 服务列表

    Returns:
        具有高 RPM 潜力的端点摘要列表（供后续交互覆写使用）
    """
    summaries = governor.get_all_summaries()
    if not summaries:
        return []

    has_limit = governor.has_any_rate_limit()
    global_delay = governor.get_global_min_delay_ms()
    high_potential_targets: list[dict[str, Any]] = []

    print(f"\n  ╔{' Rate Limit Advisory '.center(64, '═')}╗")
    if has_limit:
        print(f"  ║ {'⚠  Detected Rate Limiting — PyRIT 攻击将自动调速'.ljust(64)}║")
    else:
        print(f"  ║ {'No rate limiting detected — conservative 15 RPM default'.ljust(64)}║")
    print(f"  ╠{'─'*64}╣")

    for s in summaries[:5]:  # 最多显示 5 个端点
        safe_rpm = s["safe_rpm"]
        threshold = s["known_threshold_rpm"]
        url_short = s["url"]
        if len(url_short) > 48:
            from urllib.parse import urlparse
            parsed = urlparse(url_short)
            url_short = f"{parsed.path}" if parsed.path else url_short[:48]

        if s["rate_limit_detected"] and threshold > 0:
            safe_delay = int((60.0 / safe_rpm) * 1000) if safe_rpm > 0 else 0
            print(f"  ║  {url_short.ljust(48)} ║")
            print(f"  ║    Threshold: {threshold:.0f} RPM → Safe: {safe_rpm:.0f} RPM ({safe_delay}ms) ║")
        elif threshold >= 20:
            # 目标在 20+ RPM 档位未触发限速 — 可能支持更高
            print(f"  ║  {url_short.ljust(48)} ║")
            print(f"  ║    Tested: {threshold:.0f} RPM (no limit) → Safe: {safe_rpm:.0f} RPM        ║")
            high_potential_targets.append({
                "url": s["url"],
                "url_short": url_short,
                "tested_rpm": threshold,
                "safe_rpm": safe_rpm,
            })
        else:
            print(f"  ║  {url_short.ljust(48)} → No limit    ║")

    print(f"  ╠{'─'*64}╣")
    if has_limit:
        # PyRIT 执行模式建议
        if global_delay > 1000:
            mode = "sequential"
            batch_size = 1
            est_min = (len(services) * 10 * global_delay / 1000 / 60)
            print(f"  ║  PyRIT Mode:       {mode.ljust(14)} batch_size={batch_size}           ║")
            if est_min > 0:
                print(f"  ║  Est. Duration:    ~{est_min:.1f} min (10 payloads/endpoint)          ║")
        elif global_delay > 500:
            mode = "sequential"
            batch_size = 3
            print(f"  ║  PyRIT Mode:       {mode.ljust(14)} batch_size={batch_size}           ║")
        else:
            mode = "sequential"
            batch_size = 5
            print(f"  ║  PyRIT Mode:       {mode.ljust(14)} batch_size={batch_size}           ║")
    else:
        # 无限制模式下的执行策略
        avg_safe = sum(s["safe_rpm"] for s in summaries) / max(len(summaries), 1)
        if avg_safe < 20:
            print(f"  ║  PyRIT Mode:       sequential     batch_size=3           ║")
        else:
            print(f"  ║  PyRIT Mode:       batch          batch_size=5           ║")

    # ━━━ 30 RPM 能力提示 ━━━
    if high_potential_targets:
        print(f"  ╠{'─'*64}╣")
        print(f"  ║  {'💡 30 RPM Capability Hint'.ljust(62)} ║")
        for t in high_potential_targets:
            short = t["url_short"]
            tested = t["tested_rpm"]
            print(f"  ║    {short[:48].ljust(44)} tested {tested:.0f} RPM OK  ║")
        print(f"  ║  {' '.ljust(62)} ║")
        print(f"  ║  {'Probe Stopped at 15 RPM (OffSec safe default).'.ljust(62)} ║")
        print(f"  ║  {'Target may support 30+ RPM — override via prompt below.'.ljust(62)} ║")

    print(f"  ╚{'═'*64}╝\n")
    return high_potential_targets


def _interactive_rpm_override(
    governor: RateLimitGovernor,
    high_rpm_targets: list[dict[str, Any]],
    default_rpm: int = 15,
    max_rpm: int = 30,
) -> None:
    """Phase 2 预攻击交互：允许用户覆写目标端点的安全 RPM。

    当探测结果显示目标支持 20+ RPM 且未触发限速时，提供交互界面
    让用户选择使用更高速率（最大 30 RPM）或保持保守默认值 15 RPM。

    若侦察阶段已通过高阶探测确认更高安全速率，支持覆写至 300 RPM。
    >30 RPM 时会显示风险提示。

    Args:
        governor: 自适应调速器实例
        high_rpm_targets: _print_rate_limit_advisory 返回的高 RPM 潜力端点
        default_rpm: 保守默认 RPM（OffSec 考试推荐 15）
        max_rpm: 允许手动调整的最大 RPM（默认 30，高阶探测后可达 300）
    """
    if not high_rpm_targets:
        return

    # 检查 governor 中是否已有更高安全速率（来自侦察阶段高阶探测）
    existing_safe, _ = governor.get_safe_rate(high_rpm_targets[0]["url"])
    effective_max = max(max_rpm, int(existing_safe) if existing_safe > 0 else max_rpm)
    # 如果侦察阶段已确认 >30 RPM 安全，扩展覆写范围
    if effective_max < 300 and existing_safe >= 30:
        effective_max = 300

    try:
        override = input(
            f"  🔧  Override RPM? [{default_rpm}-{effective_max}, Enter=default {default_rpm}]: "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  Using default {default_rpm} RPM (conservative)\n")
        return

    if not override:
        print(f"  Using default {default_rpm} RPM (conservative)\n")
        return

    try:
        rpm = int(override)
    except ValueError:
        print(f"  Invalid input — using default {default_rpm} RPM\n")
        return

    if rpm < default_rpm or rpm > effective_max:
        print(f"  Value {rpm} out of range [{default_rpm}-{effective_max}] — using default {default_rpm} RPM\n")
        return

    # >30 RPM 风险提示
    if rpm > 30:
        print(f"\n  ⚠  风险提示：{rpm} RPM 已超出常规安全范围 [10-30]。")
        print(f"     过高频率可能导致 WAF 封禁或目标性能下降。")
        print(f"     调速器将在触发限速时自动退回到安全值。\n")

    # 覆写所有高潜力端点的安全 RPM
    for t in high_rpm_targets:
        governor.override_safe_rpm(t["url"], float(rpm))

    # 重新查询并展示新的有效 RPM
    print()
    for t in high_rpm_targets:
        new_safe, _ = governor.get_safe_rate(t["url"])
        print(f"  [{t['url_short']}] safe rate: {new_safe:.0f} RPM")

    est_phase2_min = 40 / rpm  # 约 40 条有效载荷
    print(f"  Est. Phase 2 duration: ~{est_phase2_min:.1f} min\n")


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
        """打印单个阶段的结果摘要 — 统一 Findings Summary + Attack Path Details + Findings Details。

        Args:
            phase_name: 阶段显示名称
            findings: 该阶段发现的漏洞列表
            total_duration: 阶段耗时（秒）
            phase_num: 阶段编号
        """
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
        use_pyrit: bool | None = None,
        phases: list[str] | None = None,
        with_multi_turn: bool = False,
        judge_endpoint: str | None = None,
        judge_api_key: str = "not-needed",
    ) -> dict[str, Any]:
        """执行完整红队评估（YAML 数据驱动端到端自动化攻击）。

        遵循五大核心设计原则：
          1. YAML 数据驱动 — 载荷/场景/参数全部从 YAML 加载
          2. AI 红队专家风格 — 每阶段以专业安全分析师视角呈现结果
          3. PyRIT 专家指导 — 自动选择最优编码绕过+评分策略
          4. 全局统筹 — 侦察结果驱动后续目标选择，失败不阻断下游
          5. 阶段提示 — 统一横幅 + 实时进度 + 严重等级分解

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
        all_phase_order = [
            "recon", "injection", "agent", "multi_agent",
            "rag", "embeddings", "supply_chain", "infra",
        ]
        to_run = phases if phases else all_phase_order

        # ━━━━━━━━━━━━ Phase 1: 侦察 ━━━━━━━━━━━━
        if "recon" in to_run:
            cfg = self._PHASE_CONFIG["recon"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            run_id, recon, services, governor = recon_phase(
                target, header_text, header_file, run_id, self.resolver
            )
            svc_count = len(services) if services else 0
            print(f"\n  [green]✓[/] 侦察完成 — 发现 {svc_count} 个 AI 服务, {getattr(recon, 'components', [])} 组件")
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, status="complete")
        else:
            raise ValueError("侦察阶段 (recon) 是必需的，必须作为第一阶段执行")
            governor = get_governor()  # unreachable, for type checker

        auth = self._get_auth(api_key, header_text, header_file)

        # 初始化增量报告写入器
        writer = ReportWriter(run_id, target)
        writer.append_recon(
            components=list(getattr(recon, "components", [])) if recon else [],
            models=list(getattr(recon, "models", [])) if recon else [],
        )

        # ━━━━━━━━━━━━ Phase 2: 提示注入 ━━━━━━━━━━━━
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

            # ━━━ PyRIT 调速策略建议 ━━━
            high_rpm_targets = _print_rate_limit_advisory(governor, services)

            # ━━━ RPM 覆写交互 ━━━
            if high_rpm_targets and governor:
                _interactive_rpm_override(governor, high_rpm_targets)

            phase_start = time.time()
            injection_findings, attack_chain = injection_phase(
                run_id, recon, services,
                auth=auth,
                use_pyrit=use_pyrit,
                with_multi_turn=with_multi_turn,
                judge_endpoint=judge_endpoint,
                judge_api_key=judge_api_key,
                governor=governor,
            )
            self._print_phase_result("提示注入攻击", injection_findings, time.time() - phase_start, phase_num=2)
            _append_to_report(writer, "提示注入攻击", 2, injection_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # ━━━━━━━━━━━━ Phase 3: Agent 攻击 ━━━━━━━━━━━━
        agent_findings: list[Finding] = []
        if "agent" in to_run:
            cfg = self._PHASE_CONFIG["agent"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            agent_findings = agent_attack_phase(run_id, services, auth=auth, use_pyrit=use_pyrit)
            self._print_phase_result("Agent 攻击", agent_findings, time.time() - phase_start, phase_num=3)
            _append_to_report(writer, "Agent 攻击", 3, agent_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # ━━━━━━━━━━━━ Phase 4: 多 Agent/A2A ━━━━━━━━━━━━
        multi_agent_findings: list[Finding] = []
        if "multi_agent" in to_run:
            cfg = self._PHASE_CONFIG["multi_agent"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            multi_agent_findings = multi_agent_phase(run_id, services, auth=auth)
            self._print_phase_result("多 Agent/A2A 攻击", multi_agent_findings, time.time() - phase_start, phase_num=4)
            _append_to_report(writer, "多 Agent/A2A 攻击", 4, multi_agent_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # ━━━━━━━━━━━━ Phase 5: RAG 攻击 ━━━━━━━━━━━━
        rag_findings: list[Finding] = []
        if "rag" in to_run:
            cfg = self._PHASE_CONFIG["rag"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            rag_findings = rag_attack_phase(run_id, services, auth=auth)
            self._print_phase_result("RAG 流水线攻击", rag_findings, time.time() - phase_start, phase_num=5)
            _append_to_report(writer, "RAG 流水线攻击", 5, rag_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # ━━━━━━━━━━━━ Phase 6: Embedding 攻击 ━━━━━━━━━━━━
        embedding_findings: list[Finding] = []
        if "embeddings" in to_run:
            cfg = self._PHASE_CONFIG["embeddings"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            embedding_findings = embeddings_attack_phase(run_id, services, auth=auth)
            self._print_phase_result("嵌入模型攻击", embedding_findings, time.time() - phase_start, phase_num=6)
            _append_to_report(writer, "嵌入模型攻击", 6, embedding_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # ━━━━━━━━━━━━ Phase 7: 供应链攻击 ━━━━━━━━━━━━
        supply_chain_findings: list[Finding] = []
        if "supply_chain" in to_run:
            cfg = self._PHASE_CONFIG["supply_chain"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            supply_chain_findings = supply_chain_phase(run_id, services, auth=auth)
            self._print_phase_result("AI 供应链攻击", supply_chain_findings, time.time() - phase_start, phase_num=7)
            _append_to_report(writer, "AI 供应链攻击", 7, supply_chain_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # ━━━━━━━━━━━━ Phase 8: 基础设施攻击 ━━━━━━━━━━━━
        infra_findings: list[Finding] = []
        if "infra" in to_run:
            cfg = self._PHASE_CONFIG["infra"]
            print_phase_banner(int(cfg["num"]), cfg["title"], target=target, subtitle=cfg["subtitle"], status="active")
            phase_start = time.time()
            infra_findings = infra_attack_phase(run_id, recon, services)
            self._print_phase_result("MCP + 基础设施攻击", infra_findings, time.time() - phase_start, phase_num=8)
            _append_to_report(writer, "MCP + 基础设施攻击", 8, infra_findings, cfg["subtitle"])
            print_phase_banner(int(cfg["num"]), cfg["title"], status="complete")

        # 汇总所有 Findings
        all_findings = (
            injection_findings
            + agent_findings
            + multi_agent_findings
            + rag_findings
            + embedding_findings
            + supply_chain_findings
            + infra_findings
        )

        # ━━━━━━━━ 增量报告收尾 ━━━━━━━━
        report_path = writer.finalize()

        elapsed = time.time() - started

        # 构建分阶段 findings 字典供全局汇总
        phase_findings_map: dict[str, list[Finding]] = {
            "提示注入攻击": injection_findings,
            "Agent 攻击": agent_findings,
            "多 Agent/A2A 攻击": multi_agent_findings,
            "RAG 流水线攻击": rag_findings,
            "嵌入模型攻击": embedding_findings,
            "AI 供应链攻击": supply_chain_findings,
            "MCP + 基础设施攻击": infra_findings,
        }
        print_global_findings_summary(phase_findings_map, elapsed)

        total_tests = len(all_findings)
        all_sev = self._count_by_severity(all_findings)
        crit_high = all_sev["critical"] + all_sev["high"]

        print(f"\n{'═' * 66}")
        print(f"  ASSESSMENT COMPLETE — Duration: {elapsed:.1f}s")
        print(f"  Total Findings: {total_tests}  |  High/Critical: {crit_high}")
        print(f"  Run ID: {run_id}")
        print(f"  Report: reports/{run_id}/AI300_Report.md")
        print(f"{'═' * 66}\n")

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
        }

        if phase not in phase_map:
            raise ValueError(f"Unknown phase: {phase}. Available: {list(phase_map.keys())}")

        if phase == "recon":
            run_id, recon, services, gov = recon_phase(target, header_text, header_file, run_id, self.resolver)
            return run_id, recon, services, gov
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

        # YAML 配置驱动模式启动横幅
        print_phase_banner(
            0, "YAML 数据驱动攻击流水线",
            target=final_target,
            subtitle=f"Config: {config_path} | Phases: {', '.join(phase_list or ['all'])}",
            status="active",
        )
        print(f"  [AI Red Team Expert]  配置即攻击 — 声明式红队模式")
        if phase_list:
            print(f"  Phases: {' → '.join(phase_list)}")
        print()

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
        connectivity=None,
    ) -> tuple:
        """侦察阶段 — 快捷方法。"""
        return recon_phase(target, header_text, header_file, run_id, self.resolver, connectivity=connectivity)

    def injection_phase(
        self,
        run_id: str,
        recon: ReconResult,
        services: list[AIService],
        auth: AuthContext | None = None,
        use_pyrit: bool | None = None,
        with_multi_turn: bool = False,
        target_model_name: str = "",
        judge_endpoint: str | None = None,
        judge_api_key: str = "not-needed",
        judge_model_name: str = "",
        governor: "RateLimitGovernor | None" = None,
    ) -> tuple:
        """注入阶段 — 快捷方法（v2.1 调速器集成）。

        Args:
            run_id: 运行 ID
            recon: 侦察结果
            services: AI 服务列表
            auth: 认证上下文
            use_pyrit: 是否使用 PyRIT
            with_multi_turn: 启用 Crescendo + TAP 多轮攻击
            target_model_name: 目标模型名称（用于 Runner 内部 API 调用）
            judge_endpoint: LLM Judge 端点
            judge_api_key: LLM Judge API Key
            judge_model_name: LLM Judge 模型名称（如 glm-4-flash, gpt-4o）
            governor: 自适应调速器（v2.1 新增）
        """
        return injection_phase(
            run_id, recon, services, auth, use_pyrit,
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
    "AIPipeline",
]