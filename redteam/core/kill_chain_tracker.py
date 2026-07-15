"""AI Kill Chain 追踪器（AI-300 Ch1+Ch10: Kill Chain Operationalization）。

在管线执行过程中自动追踪当前所处的 Kill Chain 阶段，
为报告生成提供实时战术映射，支持攻击链构建评分（OSAI 20% 权重）。

Kill Chain 阶段（10 阶段，对齐 MITRE ATLAS + AI 特有阶段）：
  Reconnaissance → Initial Access → Execution → Persistence
    → Privilege Escalation → Credential Access → Discovery
    → Collection → Command & Control → Actions on Objective

每个 Finding 在生成时会自动记录当前 Kill Chain 阶段，
支持跨阶段攻击链可视化和覆盖率追踪。

AI-300 章节映射：Ch10: AI Target Threat Modeling
技术点：MITRE ATLAS Tactics, Kill Chain Phase Tracking
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from redteam.core.models import MITREATLASTactic


# Kill Chain 阶段定义（与 MITRE ATLAS 战术一一对应）
_KILL_CHAIN_PHASES = [
    ("reconnaissance", "Reconnaissance", "AI资产发现与侦察"),
    ("initial_access", "Initial Access", "提示注入/目标劫持获取入口"),
    ("execution", "Execution", "工具误用/代码执行"),
    ("persistence", "Persistence", "记忆投毒/后门持久化"),
    ("privilege_escalation", "Privilege Escalation", "权限滥用/代理间提权"),
    ("credential_access", "Credential Access", "系统提示提取/凭据窃取"),
    ("discovery", "Discovery", "配置提取/工具发现"),
    ("collection", "Collection", "RAG泄露/嵌入反演/数据收集"),
    ("command_and_control", "Command & Control", "恶意代理C2/持久化通信"),
    ("actions_on_objective", "Actions on Objective", "数据泄露/级联故障/最终影响"),
]

# 管线阶段 → Kill Chain 阶段映射
_PHASE_TO_KILL_CHAIN: dict[str, str] = {
    "recon": "reconnaissance",
    "injection": "initial_access",
    "agent": "execution",
    "multi_agent": "privilege_escalation",
    "rag": "collection",
    "embeddings": "collection",
    "supply_chain": "execution",
    "infra": "discovery",
}


@dataclass
class KillChainState:
    """Kill Chain 执行状态。"""

    current_phase: str = "reconnaissance"
    completed_phases: set[str] = field(default_factory=set)
    findings_per_phase: dict[str, int] = field(default_factory=dict)
    phase_findings: dict[str, list[str]] = field(default_factory=dict)  # phase -> [finding_category]

    def advance(self, pipeline_phase: str) -> None:
        """推进 Kill Chain 阶段。

        Args:
            pipeline_phase: 管线阶段名称 (recon, injection, agent, ...)
        """
        kc_phase = _PHASE_TO_KILL_CHAIN.get(pipeline_phase, pipeline_phase)
        if kc_phase != self.current_phase and self.current_phase != "reconnaissance":
            self.completed_phases.add(self.current_phase)
        self.current_phase = kc_phase
        if kc_phase not in self.findings_per_phase:
            self.findings_per_phase[kc_phase] = 0
            self.phase_findings[kc_phase] = []

    def record_finding(self, category: str) -> None:
        """在当前阶段记录一个 Finding。

        Args:
            category: Finding.category 值
        """
        phase = self.current_phase
        self.findings_per_phase[phase] = self.findings_per_phase.get(phase, 0) + 1
        if phase not in self.phase_findings:
            self.phase_findings[phase] = []
        self.phase_findings[phase].append(category)

    def finalize(self) -> None:
        """完成追踪，标记当前阶段为已完成。"""
        self.completed_phases.add(self.current_phase)

    def coverage_ratio(self) -> float:
        """计算 Kill Chain 覆盖率（已执行阶段/总阶段数）。"""
        covered = len(self.completed_phases) + 1  # +1 for current
        return min(covered / len(_KILL_CHAIN_PHASES), 1.0)

    def coverage_summary(self) -> dict:
        """生成覆盖率摘要。

        Returns:
            {
                "total_phases": 10,
                "covered": 5,
                "ratio": 0.5,
                "phases": {"reconnaissance": True, ...},
                "findings_per_phase": {"reconnaissance": 3, ...}
            }
        """
        phases_status: dict[str, bool] = {}
        for phase_id, _, _ in _KILL_CHAIN_PHASES:
            phases_status[phase_id] = (
                phase_id in self.completed_phases or phase_id == self.current_phase
            )

        return {
            "total_phases": len(_KILL_CHAIN_PHASES),
            "covered": len(self.completed_phases) + 1,
            "ratio": round(self.coverage_ratio(), 2),
            "phases": phases_status,
            "findings_per_phase": dict(self.findings_per_phase),
        }

    def to_atlas_mapping(self) -> dict[str, list[str]]:
        """生成 Kill Chain → MITRE ATLAS 战术映射。

        Returns:
            {kill_chain_phase: [atlas_tactic_id, ...]}
        """
        # Kill Chain 阶段 → MITRE ATLAS 战术映射
        mapping: dict[str, list[str]] = {
            "reconnaissance": ["Reconnaissance", "ML Model Access"],
            "initial_access": ["Initial Access", "ML Supply Chain Compromise"],
            "execution": ["Execution", "LLM Prompt Injection"],
            "persistence": ["Persistence", "Backdoor ML Model"],
            "privilege_escalation": ["Privilege Escalation", "LLM Plugin Compromise"],
            "credential_access": ["Credential Access", "Unsecured Credentials"],
            "discovery": ["Discovery", "Discover ML Artifacts"],
            "collection": ["Collection", "LLM Data Leakage"],
            "command_and_control": ["Command and Control"],
            "actions_on_objective": ["Impact", "Exfiltration"],
        }
        return mapping


@dataclass
class KillChainTracker:
    """全局 Kill Chain 追踪器（单例模式）。"""

    state: KillChainState = field(default_factory=KillChainState)

    def start_phase(self, pipeline_phase: str) -> None:
        """管线阶段开始时的 hook。

        Args:
            pipeline_phase: 管线阶段名称
        """
        self.state.advance(pipeline_phase)

    def record(self, category: str) -> None:
        """记录 Finding 类别。"""
        self.state.record_finding(category)

    def end_phase(self) -> None:
        """管线阶段结束时的 hook。"""
        pass  # finalized in get_coverage()

    def get_coverage(self) -> dict:
        """获取最终覆盖率摘要。"""
        self.state.finalize()
        return self.state.coverage_summary()

    def get_atlas_map(self) -> dict:
        """获取 Kill Chain → ATLAS 映射。"""
        return self.state.to_atlas_mapping()

    def get_attack_chain_phase(self) -> str:
        """获取当前 Kill Chain 阶段。"""
        return self.state.current_phase


# 全局追踪器实例
_global_tracker: Optional[KillChainTracker] = None


def get_tracker() -> KillChainTracker:
    """获取全局 Kill Chain 追踪器（懒初始化）。"""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = KillChainTracker()
    return _global_tracker


def reset_tracker() -> None:
    """重置全局追踪器（用于测试和多次运行）。"""
    global _global_tracker
    _global_tracker = KillChainTracker()


__all__ = [
    "KillChainTracker",
    "KillChainState",
    "get_tracker",
    "reset_tracker",
    "_KILL_CHAIN_PHASES",
    "_PHASE_TO_KILL_CHAIN",
]
