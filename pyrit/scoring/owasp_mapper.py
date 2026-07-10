"""
===============================================================================
OWASP 风险映射引擎 — LLM Top 10 + Agentic Top 10 双向映射
===============================================================================
职责:
  - 根据漏洞特征自动映射到 OWASP LLM Top 10 (2025)
  - 根据攻击模式自动映射到 OWASP Agentic Top 10 (NEW)
  - 风险等级计算（critical / high / medium / low）
  - CVSS 风格评分
  - 为攻击面分析提供标准化的漏洞分类

使用方式:
  from scoring.owasp_mapper import OWASPMapper

  mapper = OWASPMapper()
  findings = mapper.classify_vulnerabilities(recon_profile, garak_results)
  filtered = mapper.filter_by_risk(findings, min_risk="high")
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from rich.console import Console
from rich.table import Table

console = Console()


# ═══════════════════════════════════════════════════════════════════════
# 枚举
# ═══════════════════════════════════════════════════════════════════════

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class OwaspLLM(str, Enum):
    """OWASP LLM Top 10 (2025) — 大语言模型应用安全风险"""
    LLM01 = "LLM01: Prompt Injection"
    LLM02 = "LLM02: Insecure Output Handling"
    LLM03 = "LLM03: Training Data Poisoning"
    LLM04 = "LLM04: Model Denial of Service"
    LLM05 = "LLM05: Supply Chain Vulnerabilities"
    LLM06 = "LLM06: Sensitive Information Disclosure"
    LLM07 = "LLM07: Insecure Plugin Design"
    LLM08 = "LLM08: Excessive Agency"
    LLM09 = "LLM09: Overreliance"
    LLM10 = "LLM10: Model Theft"


class OwaspAgentic(str, Enum):
    """OWASP Agentic Top 10 (2025) — 多智能体系统安全风险"""
    AG01 = "AG01: Agent Prompt Injection"
    AG02 = "AG02: Agent-to-Agent Hijacking"
    AG03 = "AG03: Tool/Plugin Abuse"
    AG04 = "AG04: Memory Persistence Poisoning"
    AG05 = "AG05: Cascading Failure"
    AG06 = "AG06: Authorization Bypass"
    AG07 = "AG07: Autonomous Action Override"
    AG08 = "AG08: Multi-Agent Collusion"
    AG09 = "AG09: Goal Divergence"
    AG10 = "AG10: Human-in-the-Loop Trust Exploit"


# ═══════════════════════════════════════════════════════════════════════
# 数据模型
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class VulnerabilityFinding:
    """单个漏洞发现，携带 OWASP 分类和风险评级。"""
    finding_id: str
    title: str
    description: str
    owasp_llm: Optional[OwaspLLM] = None
    owasp_agentic: Optional[OwaspAgentic] = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    cvss_score: float = 0.0
    evidence: str = ""
    affected_component: str = ""
    remediation: str = ""
    attack_ready: bool = False  # 是否已准备好攻击
    prompt_required: bool = False  # 是否需要 Promptfoo 提示词管理
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict = field(default_factory=dict)


@dataclass
class AttackSurfaceReport:
    """攻击面分析报告 — 聚合所有漏洞发现。"""
    target_url: str
    target_type: str  # basic_llm / rag / agent / multi_agent
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ═══════════════════════════════════════════════════════════════════════
# OWASP 映射引擎
# ═══════════════════════════════════════════════════════════════════════

class OWASPMapper:
    """OWASP 风险映射引擎。

    根据侦察结果和行为特征，自动将发现映射到 OWASP LLM Top 10 和
    OWASP Agentic Top 10，并计算综合风险等级。
    """

    # ── 特征→OWASP 签名匹配规则 ──

    _LLM_SIGNATURES: dict[str, tuple[OwaspLLM, RiskLevel, str]] = {
        # 特征关键词 → (OWASP类别, 默认风险等级, 触发条件描述)
        "prompt_injection_vuln": (OwaspLLM.LLM01, RiskLevel.CRITICAL, "直接提示注入漏洞"),
        "jailbreak_possible": (OwaspLLM.LLM01, RiskLevel.HIGH, "越狱攻击可能"),
        "xpia_possible": (OwaspLLM.LLM01, RiskLevel.HIGH, "间接提示注入可能"),
        "output_rendering_unsafe": (OwaspLLM.LLM02, RiskLevel.HIGH, "输出未安全编码"),
        "code_execution_in_output": (OwaspLLM.LLM02, RiskLevel.CRITICAL, "输出中包含可执行代码"),
        "rag_poisoning_possible": (OwaspLLM.LLM03, RiskLevel.HIGH, "RAG 投毒可能"),
        "training_data_leak": (OwaspLLM.LLM03, RiskLevel.HIGH, "训练数据泄露"),
        "rate_limit_none": (OwaspLLM.LLM04, RiskLevel.MEDIUM, "无速率限制"),
        "supply_chain_risk": (OwaspLLM.LLM05, RiskLevel.MEDIUM, "供应链风险"),
        "sensitive_info_leak": (OwaspLLM.LLM06, RiskLevel.CRITICAL, "敏感信息泄露"),
        "pii_in_response": (OwaspLLM.LLM06, RiskLevel.CRITICAL, "PII 出现在响应中"),
        "model_credentials_exposed": (OwaspLLM.LLM06, RiskLevel.CRITICAL, "模型凭证暴露"),
        "insecure_plugin": (OwaspLLM.LLM07, RiskLevel.HIGH, "不安全插件设计"),
        "tool_abuse_possible": (OwaspLLM.LLM07, RiskLevel.HIGH, "工具滥用可能"),
        "excessive_agency": (OwaspLLM.LLM08, RiskLevel.HIGH, "过度自主权"),
        "agent_autonomous_action": (OwaspLLM.LLM08, RiskLevel.HIGH, "Agent 自主行为"),
        "overreliance_risk": (OwaspLLM.LLM09, RiskLevel.MEDIUM, "过度依赖风险"),
        "model_theft_possible": (OwaspLLM.LLM10, RiskLevel.HIGH, "模型窃取可能"),
        "model_extraction_possible": (OwaspLLM.LLM10, RiskLevel.HIGH, "模型提取可能"),
    }

    _AGENTIC_SIGNATURES: dict[str, tuple[OwaspAgentic, RiskLevel, str]] = {
        "agent_prompt_injection": (OwaspAgentic.AG01, RiskLevel.CRITICAL, "Agent 提示注入"),
        "agent_to_agent_hijack": (OwaspAgentic.AG02, RiskLevel.CRITICAL, "Agent 间通信劫持"),
        "tool_plugin_abuse": (OwaspAgentic.AG03, RiskLevel.HIGH, "工具/插件滥用"),
        "memory_poisoning": (OwaspAgentic.AG04, RiskLevel.HIGH, "记忆持久化投毒"),
        "cascading_failure": (OwaspAgentic.AG05, RiskLevel.HIGH, "级联故障触发"),
        "auth_bypass": (OwaspAgentic.AG06, RiskLevel.CRITICAL, "授权绕过"),
        "autonomous_override": (OwaspAgentic.AG07, RiskLevel.HIGH, "自主行为覆盖"),
        "multi_agent_collusion": (OwaspAgentic.AG08, RiskLevel.MEDIUM, "多 Agent 合谋"),
        "goal_divergence": (OwaspAgentic.AG09, RiskLevel.MEDIUM, "目标分歧"),
        "hitl_trust_exploit": (OwaspAgentic.AG10, RiskLevel.HIGH, "人机信任利用"),
    }

    # ── 攻击类型 → 是否需要提示词 ──

    _PROMPT_REQUIRED_CATEGORIES: set[str] = {
        "jailbreak", "injection", "xpia", "prompt_leak", "crescendo",
    }

    # ── 分类方法 ──

    def classify_from_recon_profile(
        self,
        profile: dict,
        target_url: str = "",
    ) -> list[VulnerabilityFinding]:
        """从 ai-recon 的 target_profile.json 中提取漏洞发现。

        基于侦察结果中的行为特征、端点暴露、认证弱点等进行 OWASP 映射。
        """
        findings = []
        target_type = profile.get("target", {}).get("architecture", "unknown")
        idx = 0

        # 1. 认证相关的发现
        auth = profile.get("auth", {})
        if auth.get("api_key_exposed", False):
            findings.append(self._create_finding(
                f"VULN-{idx:04d}", "API Key 暴露在客户端",
                "发现 API Key 在客户端代码/请求中明文传输",
                "model_credentials_exposed", target_url, target_type,
            ))
            idx += 1

        # 2. 端点暴露
        endpoints = profile.get("api_endpoints", [])
        for ep in endpoints:
            if ep.get("category") == "debug":
                findings.append(self._create_finding(
                    f"VULN-{idx:04d}", f"调试端点暴露: {ep.get('path', '')}",
                    "调试端点未受保护，可能泄露内部信息",
                    "sensitive_info_leak", target_url, target_type,
                ))
                idx += 1
            if ep.get("category") == "admin" and ep.get("auth_required", True) is False:
                findings.append(self._create_finding(
                    f"VULN-{idx:04d}", f"管理端点未受保护: {ep.get('path', '')}",
                    "管理端点无需认证即可访问",
                    "sensitive_info_leak", target_url, target_type,
                ))
                idx += 1

        # 3. 安全防护检测
        defense = profile.get("defense", {})
        if not defense.get("waf", False):
            findings.append(self._create_finding(
                f"VULN-{idx:04d}", "未检测到 WAF/防护中间件",
                "目标未部署 Web 应用防火墙，攻击面较广",
                "rate_limit_none", target_url, target_type,
            ))
            idx += 1
        if not defense.get("rate_limiting", False):
            findings.append(self._create_finding(
                f"VULN-{idx:04d}", "未检测到速率限制",
                "目标未实施 API 速率限制，DoS 风险增加",
                "rate_limit_none", target_url, target_type,
            ))
            idx += 1

        # 4. RAG/Agent 特有发现
        rag_info = profile.get("rag", {})
        if rag_info.get("detected"):
            findings.append(self._create_finding(
                f"VULN-{idx:04d}", "RAG 检索增强生成系统检测到",
                "RAG 系统可能面临检索注入、文档投毒等风险",
                "rag_poisoning_possible", target_url, target_type,
            ))
            idx += 1

        agent_info = profile.get("agent", {})
        if agent_info.get("detected"):
            findings.append(self._create_finding(
                f"VULN-{idx:04d}", "Agent 智能体系统检测到",
                "Agent 系统可能面临工具滥用、自主行为等风险",
                "excessive_agency", target_url, target_type,
            ))
            idx += 1
            if agent_info.get("tools_count", 0) > 0:
                findings.append(self._create_finding(
                    f"VULN-{idx:04d}", f"Agent 暴露 {agent_info.get('tools_count')} 个工具",
                    "Agent 工具可能被诱导滥用",
                    "tool_abuse_possible", target_url, target_type,
                ))
                idx += 1

        return findings

    def classify_from_garak_results(
        self,
        garak_profile: dict,
        target_url: str = "",
        target_type: str = "unknown",
    ) -> list[VulnerabilityFinding]:
        """从 Garak 扫描结果中提取漏洞发现。"""
        findings = []
        idx = 0

        probes = garak_profile.get("probe_results", garak_profile.get("results", []))
        for probe in probes:
            if isinstance(probe, dict) and probe.get("status") == "fail":
                probe_name = probe.get("probe_name", "")
                findings.append(self._create_finding(
                    f"VULN-GRK-{idx:04d}",
                    f"Garak 探测失败: {probe_name}",
                    f"Garak 探测 {probe_name} 检测到漏洞",
                    self._garak_to_owasp_signature(probe_name),
                    target_url, target_type,
                ))
                idx += 1

        return findings

    def classify_from_behavior(
        self,
        behavior_map: dict,
        target_url: str = "",
        target_type: str = "unknown",
    ) -> list[VulnerabilityFinding]:
        """从行为测绘结果中提取漏洞发现。"""
        findings = []
        idx = 0

        vulnerabilities = behavior_map.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            if isinstance(vuln, str):
                title = vuln
            elif isinstance(vuln, dict):
                title = vuln.get("name", vuln.get("title", str(vuln)))
            else:
                continue

            findings.append(self._create_finding(
                f"VULN-BHV-{idx:04d}", title, f"行为测绘发现: {title}",
                self._infer_signature_from_title(title), target_url, target_type,
            ))
            idx += 1

        return findings

    def build_attack_surface_report(
        self,
        target_url: str,
        target_type: str,
        recon_profile: dict,
        garak_profile: Optional[dict] = None,
        behavior_map: Optional[dict] = None,
    ) -> AttackSurfaceReport:
        """构建完整的攻击面分析报告。"""
        all_findings: list[VulnerabilityFinding] = []

        # 从侦察结果提取
        all_findings.extend(self.classify_from_recon_profile(recon_profile, target_url))

        # 从 Garak 结果提取
        if garak_profile:
            all_findings.extend(self.classify_from_garak_results(garak_profile, target_url, target_type))

        # 从行为测绘提取
        if behavior_map:
            all_findings.extend(self.classify_from_behavior(behavior_map, target_url, target_type))

        # 统计
        critical = sum(1 for f in all_findings if f.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for f in all_findings if f.risk_level == RiskLevel.HIGH)
        medium = sum(1 for f in all_findings if f.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for f in all_findings if f.risk_level == RiskLevel.LOW)

        # 去重: 相同 OWASP 类别只保留最高风险的
        seen_categories: set[str] = set()
        deduped = []
        for f in sorted(all_findings, key=lambda x: _risk_order(x.risk_level)):
            cat = f.owasp_llm.value if f.owasp_llm else ""
            agent_cat = f.owasp_agentic.value if f.owasp_agentic else ""
            key = cat + agent_cat
            if key and key in seen_categories:
                continue
            if key:
                seen_categories.add(key)
            deduped.append(f)
        all_findings = deduped

        return AttackSurfaceReport(
            target_url=target_url,
            target_type=target_type,
            total_findings=len(all_findings),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            findings=all_findings,
        )

    def filter_by_risk(
        self,
        findings: list[VulnerabilityFinding],
        min_risk: str = "high",
    ) -> list[VulnerabilityFinding]:
        """按最低风险等级筛选漏洞。

        Args:
            findings: 漏洞发现列表
            min_risk: 最低风险等级 ("critical" > "high" > "medium" > "low")

        Returns:
            筛选后的漏洞列表（按风险降序排列）
        """
        risk_levels = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
        min_idx = risk_levels.index(RiskLevel(min_risk)) if min_risk in {r.value for r in RiskLevel} else 1
        filtered = [f for f in findings if _risk_order(f.risk_level) <= min_idx]
        return sorted(filtered, key=lambda f: _risk_order(f.risk_level))

    def filter_attack_ready(
        self,
        findings: list[VulnerabilityFinding],
    ) -> list[VulnerabilityFinding]:
        """筛选已准备好攻击的漏洞。"""
        return [f for f in findings if f.attack_ready]

    def split_by_prompt_requirement(
        self,
        findings: list[VulnerabilityFinding],
    ) -> tuple[list[VulnerabilityFinding], list[VulnerabilityFinding]]:
        """将漏洞分为「需要提示词」和「不需要提示词」两组。

        Returns:
            (需要提示词管理的, 可直接攻击的)
        """
        prompt_needed = []
        direct_attack = []
        for f in findings:
            # 判断是否需要提示词
            if f.prompt_required or self._needs_prompt(f):
                prompt_needed.append(f)
            else:
                direct_attack.append(f)
        return prompt_needed, direct_attack

    # ── 辅助方法 ──

    def _create_finding(
        self,
        finding_id: str,
        title: str,
        description: str,
        signature: str,
        target_url: str,
        target_type: str,
    ) -> VulnerabilityFinding:
        """根据签名创建 VulnerabilityFinding。"""
        llm_info = self._LLM_SIGNATURES.get(signature)
        agentic_info = self._AGENTIC_SIGNATURES.get(signature)

        finding = VulnerabilityFinding(
            finding_id=finding_id,
            title=title,
            description=description,
        )

        if llm_info:
            finding.owasp_llm = llm_info[0]
            finding.risk_level = llm_info[1]

        if agentic_info:
            finding.owasp_agentic = agentic_info[0]
            # agentic 风险可能比 llm 高
            if _risk_order(agentic_info[1]) < _risk_order(finding.risk_level):
                finding.risk_level = agentic_info[1]

        # CVSS 评分
        cvss_map = {
            RiskLevel.CRITICAL: 9.5,
            RiskLevel.HIGH: 7.5,
            RiskLevel.MEDIUM: 5.0,
            RiskLevel.LOW: 2.5,
        }
        finding.cvss_score = cvss_map.get(finding.risk_level, 0.0)
        finding.affected_component = target_type

        return finding

    def _needs_prompt(self, finding: VulnerabilityFinding) -> bool:
        """判断漏洞是否需要对提示词进行管理（Promptfoo）。"""
        # 提示注入类需要精心构造提示词
        if finding.owasp_llm in (OwaspLLM.LLM01,):
            return True
        # Agent 提示注入也需要
        if finding.owasp_agentic in (OwaspAgentic.AG01,):
            return True
        return False

    def _garak_to_owasp_signature(self, probe_name: str) -> str:
        """将 Garak 探测名称映射到 OWASP 签名。"""
        probe_lower = probe_name.lower()
        mapping = {
            "prompt_injection": "prompt_injection_vuln",
            "jailbreak": "jailbreak_possible",
            "encoding": "prompt_injection_vuln",
            "dan": "jailbreak_possible",
            "leak": "sensitive_info_leak",
            "extraction": "model_extraction_possible",
            "toxicity": "output_rendering_unsafe",
            "misinformation": "overreliance_risk",
            "snowball": "rag_poisoning_possible",
            "package": "supply_chain_risk",
        }
        for key, sig in mapping.items():
            if key in probe_lower:
                return sig
        return "prompt_injection_vuln"  # 默认

    def _infer_signature_from_title(self, title: str) -> str:
        """从漏洞标题推断 OWASP 签名。"""
        title_lower = title.lower()
        for keyword, (_, _, _) in self._LLM_SIGNATURES.items():
            if keyword.replace("_", " ") in title_lower or keyword in title_lower:
                return keyword
        return "prompt_injection_vuln"

    # ── 展示方法 ──

    def display_attack_surface(self, report: AttackSurfaceReport):
        """以终端表格展示攻击面分析报告。"""
        console.print()
        console.print(Panel.fit(
            f"目标: {report.target_url}\n类型: {report.target_type}",
            title="[bold cyan]攻击面分析报告[/bold cyan]",
        ))

        # 统计摘要
        summary = Table(title="风险统计")
        summary.add_column("等级", style="bold")
        summary.add_column("数量")
        summary.add_column("占比")
        total = max(report.total_findings, 1)
        summary.add_row("[bold red]CRITICAL[/bold red]", str(report.critical_count), f"{report.critical_count / total:.0%}")
        summary.add_row("[red]HIGH[/red]", str(report.high_count), f"{report.high_count / total:.0%}")
        summary.add_row("[yellow]MEDIUM[/yellow]", str(report.medium_count), f"{report.medium_count / total:.0%}")
        summary.add_row("[dim]LOW[/dim]", str(report.low_count), f"{report.low_count / total:.0%}")
        console.print(summary)

        # 详细列表
        if report.findings:
            detail = Table(title="漏洞详情")
            detail.add_column("ID", style="cyan", no_wrap=True)
            detail.add_column("标题", style="white")
            detail.add_column("OWASP LLM", style="magenta")
            detail.add_column("OWASP Agentic", style="yellow")
            detail.add_column("风险", style="red")
            detail.add_column("CVSS", style="dim")

            for f in report.findings:
                risk_style = {
                    RiskLevel.CRITICAL: "[bold red]",
                    RiskLevel.HIGH: "[red]",
                    RiskLevel.MEDIUM: "[yellow]",
                    RiskLevel.LOW: "[dim]",
                }.get(f.risk_level, "")
                detail.add_row(
                    f.finding_id,
                    f.title[:50],
                    f.owasp_llm.value if f.owasp_llm else "-",
                    f.owasp_agentic.value if f.owasp_agentic else "-",
                    f"{risk_style}{f.risk_level.value}[/]",
                    f"{f.cvss_score:.1f}",
                )
            console.print(detail)


def _risk_order(level: RiskLevel) -> int:
    """风险等级排序索引（越小越严重）。"""
    order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.NONE: 4}
    return order.get(level, 99)
