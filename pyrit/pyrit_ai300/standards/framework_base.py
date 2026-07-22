# -*- coding: utf-8 -*-
"""
AI-300 Framework - AISafetyFramework 基类

灵感来源：DeepTeam frameworks/base.py 的 AISafetyFramework 抽象

设计目标：
- 提供统一的安全框架接口（OWASP / NIST / MITRE ATLAS）
- 每个框架定义自己的漏洞类别、攻击方法、风险等级
- 框架可序列化为 dict / JSON，便于跨工具传递
- 支持动态框架选择（YAML 配置 → 框架实例）
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FrameworkVulnerability:
    """框架内单个漏洞定义"""
    vuln_id: str               # 框架内唯一 ID（如 "LLM01"）
    title: str                  # 漏洞标题
    description: str             # 描述
    severity: str = "medium"   # critical / high / medium / low
    risk_category: str = ""   # 风险类别（如 "Security"）
    attacks: List[str] = field(default_factory=list)
    remediation: str = ""     # 修复建议


@dataclass(frozen=True)
class FrameworkAttack:
    """框架内单个攻击方法定义"""
    attack_id: str             # 攻击方法 ID
    title: str                  # 攻击标题
    description: str             # 描述
    vulnerabilities: List[str] = field(default_factory=list)
    severity: str = "medium"


class AISafetyFramework(ABC):
    """
    AI 安全框架抽象基类

    子类必须实现：
    - framework_name: 框架名称
    - framework_version: 框架版本
    - get_vulnerabilities(): 获取所有漏洞定义
    - get_attacks(): 获取所有攻击方法

    可选实现：
    - get_risk_categories(): 获取风险类别
    - to_dict(): 序列化为字典
    """

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """框架名称（如 "OWASP Top 10 for LLMs 2025"）"""
        ...

    @property
    @abstractmethod
    def framework_version(self) -> str:
        """框架版本（如 "2025.1"）"""
        ...

    @property
    @abstractmethod
    def framework_id(self) -> str:
        """框架短标识（如 "owasp_llm_2025"）"""
        ...

    @abstractmethod
    def get_vulnerabilities(self) -> List[FrameworkVulnerability]:
        """获取框架定义的所有漏洞类别"""
        ...

    @abstractmethod
    def get_attacks(self) -> List[FrameworkAttack]:
        """获取框架定义的所有攻击方法"""
        ...

    def get_vulnerability(self, vuln_id: str) -> Optional[FrameworkVulnerability]:
        """根据 ID 获取单个漏洞定义"""
        for v in self.get_vulnerabilities():
            if v.vuln_id == vuln_id:
                return v
        return None

    def get_attack(self, attack_id: str) -> Optional[FrameworkAttack]:
        """根据 ID 获取单个攻击方法"""
        for a in self.get_attacks():
            if a.attack_id == attack_id:
                return a
        return None

    def get_risk_categories(self) -> List[str]:
        """获取所有风险类别（可选，默认返回空列表）"""
        return []

    def get_vulnerability_ids(self) -> List[str]:
        """获取所有漏洞 ID 列表"""
        return [v.vuln_id for v in self.get_vulnerabilities()]

    def get_attack_ids(self) -> List[str]:
        """获取所有攻击方法 ID 列表"""
        return [a.attack_id for a in self.get_attacks()]

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "framework_version": self.framework_version,
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "title": v.title,
                    "description": v.description,
                    "severity": v.severity,
                    "risk_category": v.risk_category,
                    "attacks": v.attacks,
                    "remediation": v.remediation,
                }
                for v in self.get_vulnerabilities()
            ],
            "attacks": [
                {
                    "attack_id": a.attack_id,
                    "title": a.title,
                    "description": a.description,
                    "vulnerabilities": a.vulnerabilities,
                    "severity": a.severity,
                }
                for a in self.get_attacks()
            ],
            "risk_categories": self.get_risk_categories(),
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({self.framework_id} v{self.framework_version})>"

    def __str__(self) -> str:
        return f"{self.framework_name} v{self.framework_version}"
