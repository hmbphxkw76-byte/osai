"""
===============================================================================
前沿 AI 漏洞追踪模块 — 基础数据结构
===============================================================================
每个前沿漏洞的核心描述由两个 YAML 文件驱动:
  - manifest.yaml  元数据（CVE/论文/状态/策略映射）
  - payloads.yaml  Payload 数据（纯文本攻击载荷）

设计原则:
  ✅ 零代码扩展 — 新增漏洞只需创建目录 + 2 个 YAML 文件
  ✅ 热插拔      — status 字段控制是否加入攻击管道
  ✅ 生命周期管理 — experimental → active → deprecated → retired
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class FrontierStatus(str, Enum):
    """前沿漏洞生命周期状态"""
    EXPERIMENTAL = "experimental"   # 实验阶段，默认不激活
    ACTIVE = "active"               # 正式追踪，自动加入攻击管道
    DEPRECATED = "deprecated"       # 已过时/被修复，保留 payload 但不执行
    RETIRED = "retired"             # 归档保留，完全不加载


class SeverityLevel(str, Enum):
    """漏洞严重性等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FrontierVuln:
    """前沿漏洞的完整描述 — 从 manifest.yaml 反序列化。

    属性:
        id:              唯一标识（如 FRONTIER-2026-003）
        name:            漏洞名称
        status:          生命周期状态
        severity:        严重性等级
        confidence:      估算成功率 (0.0-1.0)
        discovery_date:  发现日期
        discovered_by:   发现方
        cve:             CVE 编号（可选）
        paper:           论文链接（可选）
        tags:            标签列表（用于筛选）
        attack_strategy: 对应的攻击策略名称（动态注入到管道）
        converter:       使用的转换器名称（复用已有转换器）
        description:     漏洞描述
        known_mitigations: 已知缓解措施
        examples:        攻击示例列表
        source_dir:      漏洞目录路径（注册表自动填充）
        payloads_file:   payloads.yaml 路径（注册表自动填充）
    """
    id: str
    name: str
    status: FrontierStatus = FrontierStatus.EXPERIMENTAL
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = 0.5
    discovery_date: str = ""
    discovered_by: str = ""
    cve: str = ""
    paper: str = ""
    tags: list[str] = field(default_factory=list)
    attack_strategy: str = ""        # 策略名称，用于路由
    converter: str = ""              # 转换器名称
    requires_advanced_pipeline: bool = False
    description: str = ""
    known_mitigations: list[str] = field(default_factory=list)
    examples: list[dict] = field(default_factory=list)
    # 内部字段（注册表自动填充）
    source_dir: str = ""
    payloads_file: str = ""

    @classmethod
    def from_manifest(cls, data: dict, source_dir: str = "") -> "FrontierVuln":
        """从 manifest YAML 字典构建"""
        status = FrontierStatus(data.get("status", "experimental"))
        severity = SeverityLevel(data.get("severity", "medium"))
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            status=status,
            severity=severity,
            confidence=float(data.get("confidence", 0.5)),
            discovery_date=data.get("discovery_date", ""),
            discovered_by=data.get("discovered_by", ""),
            cve=data.get("cve", ""),
            paper=data.get("paper", ""),
            tags=data.get("tags", []),
            attack_strategy=data.get("attack_strategy", ""),
            converter=data.get("converter", ""),
            requires_advanced_pipeline=data.get("requires_advanced_pipeline", False),
            description=data.get("description", ""),
            known_mitigations=data.get("known_mitigations", []),
            examples=data.get("examples", []),
            source_dir=source_dir,
            payloads_file=data.get("payloads_file", f"{source_dir}/payloads.yaml"),
        )

    @property
    def is_active(self) -> bool:
        return self.status == FrontierStatus.ACTIVE

    @property
    def is_loaded(self) -> bool:
        """是否应被加载到系统（active + experimental 均可，但 experimental 需要手动启用）"""
        return self.status in (FrontierStatus.ACTIVE, FrontierStatus.EXPERIMENTAL)

    def to_summary(self) -> dict:
        """轻量摘要（用于报告）"""
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "discovery_date": self.discovery_date,
            "tags": self.tags,
        }


@dataclass
class FrontierPayload:
    """前沿漏洞的单条 Payload。

    从 vuln 的 payloads.yaml 加载，每个 section（basic/advanced/stealth）包含多条 payload 文本。
    """
    text: str
    section_key: str        # basic | advanced | stealth | custom
    vuln_id: str            # 来自哪个漏洞
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "section_key": self.section_key,
            "vuln_id": self.vuln_id,
            "description": self.description,
        }
