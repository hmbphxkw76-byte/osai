# -*- coding: utf-8 -*-
"""
AI-300 Framework - Pipeline Stage Protocols
流水线阶段协议：标准化输入输出契约

设计原则：
- StageInput / StageOutput 作为阶段间通信的统一契约
- PipelineStage 协议定义阶段执行接口
- 所有阶段实现统一接口，编排器只需调用 execute()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


# ── 阶段常量 ──
PHASE_CREDENTIAL = "credential"
PHASE_RECON = "recon"
PHASE_ATTACK = "attack"
PHASE_REPORT = "report"

ALL_PHASES = [PHASE_CREDENTIAL, PHASE_RECON, PHASE_ATTACK, PHASE_REPORT]


@dataclass
class StageInput:
    """
    流水线阶段的标准输入

    封装所有阶段可能需要的输入参数，
    各阶段按需读取自己关心的字段。

    Attributes:
        target_url: 目标 URL
        target_file: 目标配置文件路径
        spa_config: SPA 配置文件路径
        depth: 侦察深度
        scope: 攻击范围
        profile_path: 侦察画像路径（攻击阶段使用）
        framework_id: 安全框架 ID
        use_cache: 是否使用缓存
        credential_resolution: 凭据解析结果
        extra: 额外参数（阶段特定配置）
    """
    target_url: str = ""
    target_file: Optional[str] = None
    spa_config: Optional[str] = None
    depth: str = "standard"
    scope: str = "quick"
    profile_path: Optional[str] = None
    framework_id: Optional[str] = None
    use_cache: Optional[bool] = None
    credential_resolution: Optional[Any] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StageOutput:
    """
    流水线阶段的标准输出

    所有阶段执行后返回此数据结构，
    编排器据此决定是否继续执行下一阶段。

    Attributes:
        phase: 阶段名称
        success: 是否成功
        duration_ms: 耗时（毫秒）
        summary: 结果摘要
        data: 原始数据（阶段特定结果）
        errors: 错误列表
    """
    phase: str
    success: bool
    duration_ms: float = 0.0
    summary: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """是否包含错误"""
        return len(self.errors) > 0


@dataclass
class PipelineResult:
    """
    全链路编排结果

    Attributes:
        target: 目标 URL
        phases: 各阶段结果列表
        profile_path: 侦察画像路径
        report_path: 报告路径
        total_duration_ms: 总耗时
        overall_success: 总体是否成功
        credential_resolution: 凭据解析结果
    """
    target: str = ""
    phases: List[StageOutput] = field(default_factory=list)
    profile_path: str = ""
    report_path: str = ""
    total_duration_ms: float = 0.0
    overall_success: bool = False
    credential_resolution: Optional[Any] = None

    @property
    def recon_success(self) -> bool:
        """侦察阶段是否成功"""
        for p in self.phases:
            if p.phase == PHASE_RECON:
                return p.success
        return False

    @property
    def attack_success(self) -> bool:
        """攻击阶段是否成功"""
        for p in self.phases:
            if p.phase == PHASE_ATTACK:
                return p.success
        return False

    @property
    def report_success(self) -> bool:
        """报告阶段是否成功"""
        for p in self.phases:
            if p.phase == PHASE_REPORT:
                return p.success
        return False

    def get_phase(self, phase_name: str) -> Optional[StageOutput]:
        """获取指定阶段的结果"""
        for p in self.phases:
            if p.phase == phase_name:
                return p
        return None

    def summary_table(self) -> str:
        """生成摘要表格文本"""
        lines = []
        lines.append("═" * 60)
        lines.append("  AI Red Team 全链路执行摘要")
        lines.append("═" * 60)
        lines.append(f"  目标:       {self.target}")
        lines.append(f"  总耗时:     {self.total_duration_ms / 1000:.1f}s")
        lines.append(f"  总体状态:   {'✅ 成功' if self.overall_success else '⚠️ 部分完成'}")
        lines.append("")
        for p in self.phases:
            icon = "✅" if p.success else "❌"
            lines.append(f"  {icon} {p.phase:<12} {p.duration_ms / 1000:>8.1f}s  {p.summary}")
        lines.append("")
        if self.profile_path:
            lines.append(f"  侦察画像:   {self.profile_path}")
        if self.report_path:
            lines.append(f"  评估报告:   {self.report_path}")
        lines.append("═" * 60)
        return "\n".join(lines)


@runtime_checkable
class PipelineStage(Protocol):
    """
    流水线阶段协议

    所有阶段必须实现此接口，编排器通过此接口统一调度。
    """

    def execute(self, stage_input: StageInput) -> StageOutput:
        """
        执行阶段

        Args:
            stage_input: 阶段输入

        Returns:
            阶段输出
        """
        ...
