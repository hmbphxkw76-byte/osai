"""前沿漏洞 Schema — Pydantic 模型定义。

漏洞目录结构：
  vulns/FRONTIER-2026-XXX_漏洞名/
  ├── manifest.yaml    # 漏洞元数据
  └── payloads.yaml    # 攻击载荷

manifest.yaml 字段说明：
  id: 漏洞唯一标识（如 FRONTIER-2025-001）
  name: 漏洞名称
  description: 漏洞描述
  severity: 严重程度（critical/high/medium/low/info）
  attack_strategy: 攻击策略名称
  converter: 关联的转换器名称（可选）
  tags: 标签列表（用于分类过滤）
  cve: CVE 编号（可选）
  paper_url: 论文链接（可选）
  known_mitigations: 已知缓解措施列表
  status: 生命周期状态（experimental/active/deprecated/retired）

payloads.yaml 字段说明：
  basic: 基础载荷列表（快速验证）
  advanced: 高级载荷列表（深度利用）
  stealth: 隐身载荷列表（规避检测）
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class VulnStatus(str, Enum):
    EXPERIMENTAL = "experimental"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class FrontierPayload(BaseModel):
    text: str = Field(description="攻击载荷文本")
    description: str = Field(default="", description="载荷描述")


class FrontierVuln(BaseModel):
    id: str = Field(description="漏洞唯一标识")
    name: str = Field(description="漏洞名称")
    description: str = Field(default="", description="漏洞描述")
    severity: str = Field(default="high", description="严重程度")
    attack_strategy: str = Field(description="攻击策略名称")
    converter: Optional[str] = Field(default=None, description="关联转换器名称")
    tags: list[str] = Field(default_factory=list, description="标签列表")
    cve: Optional[str] = Field(default=None, description="CVE 编号")
    paper_url: Optional[str] = Field(default=None, description="论文链接")
    known_mitigations: list[str] = Field(default_factory=list, description="已知缓解措施")
    status: VulnStatus = Field(default=VulnStatus.EXPERIMENTAL, description="生命周期状态")

    def is_active(self) -> bool:
        return self.status == VulnStatus.ACTIVE

    def to_finding(self, evidence: str = "") -> dict:
        return {
            "source": "frontier",
            "category": ", ".join(self.tags),
            "severity": self.severity,
            "title": f"{self.id}: {self.name}",
            "description": self.description,
            "evidence": evidence,
            "remediation": "\n".join(self.known_mitigations),
            "cve_refs": [self.cve] if self.cve else [],
        }


class FrontierPayloads(BaseModel):
    basic: list[str] = Field(default_factory=list, description="基础载荷")
    advanced: list[str] = Field(default_factory=list, description="高级载荷")
    stealth: list[str] = Field(default_factory=list, description="隐身载荷")

    def get_all(self) -> list[str]:
        return self.basic + self.advanced + self.stealth

    def get_by_type(self, payload_type: str) -> list[str]:
        return getattr(self, payload_type, [])
