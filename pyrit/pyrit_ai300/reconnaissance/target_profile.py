# -*- coding: utf-8 -*-
"""
AI-300 Framework - TargetProfile Data Model
目标画像数据模型：侦察引擎与攻击引擎之间的唯一接口契约

设计原则：
- 纯数据模型，无业务逻辑
- 支持 JSON 序列化/反序列化（模块间通信格式）
- 所有字段可选（不同工具产出不同信息）
"""

from __future__ import annotations

import json
import sys
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


@dataclass
class FingerprintData:
    """目标指纹信息"""
    model_name: Optional[str] = None
    model_family: Optional[str] = None
    provider: Optional[str] = None
    context_window: Optional[int] = None
    system_prompt: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    detected_filters: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class VulnerabilityFinding:
    """单个漏洞/弱点发现"""
    tool: str = ""           # 发现工具（garak/deepteam/etc）
    category: str = ""       # 类别（prompt_injection/jailbreak/etc）
    severity: str = "medium"  # low/medium/high/critical
    description: str = ""
    evidence: str = ""
    owasp_mapping: str = ""  # LLM01-LLM10 / ASI01-ASI10
    confidence: float = 0.0


@dataclass
class TargetProfile:
    """
    目标画像：侦察引擎的完整输出

    这是侦察引擎与攻击引擎之间的唯一接口契约。
    侦察引擎写入此文件，攻击引擎读取此文件。
    """

    # ── 元数据 ──
    target: str = ""                        # 目标 URL/endpoint
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    recon_depth: str = "standard"           # quick/standard/deep
    tools_used: List[str] = field(default_factory=list)

    # ── 指纹信息 ──
    fingerprint: FingerprintData = field(default_factory=FingerprintData)

    # ── 攻击面 ──
    surfaces: List[str] = field(default_factory=list)  # prompt/rag/mcp/agent/etc
    entry_points: List[Dict[str, Any]] = field(default_factory=list)

    # ── 漏洞发现 ──
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)

    # ── 原始结果（各工具输出） ──
    raw_results: Dict[str, Any] = field(default_factory=dict)

    # ── 综合评估 ──
    risk_level: str = "unknown"             # low/medium/high/critical
    attack_recommendations: List[str] = field(default_factory=list)

    # ── 序列化 ──

    def to_dict(self) -> dict:
        """转为字典（用于 JSON 序列化）"""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """转为 JSON 字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> TargetProfile:
        """从字典创建实例"""
        fingerprint_data = data.pop("fingerprint", {})
        vulnerabilities_data = data.pop("vulnerabilities", [])

        fingerprint = FingerprintData(**fingerprint_data)
        vulnerabilities = [VulnerabilityFinding(**v) for v in vulnerabilities_data]

        return cls(fingerprint=fingerprint, vulnerabilities=vulnerabilities, **data)

    @classmethod
    def from_json(cls, json_str: str) -> TargetProfile:
        """从 JSON 字符串创建实例"""
        return cls.from_dict(json.loads(json_str))

    def save(self, path: str) -> None:
        """保存为 JSON 文件"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, path: str) -> TargetProfile:
        """从 JSON 文件加载"""
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_json(f.read())

    # ── 便捷方法 ──

    def get_vulnerabilities_by_severity(self, severity: str) -> List[VulnerabilityFinding]:
        """按严重程度筛选漏洞"""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_vulnerabilities_by_category(self, category: str) -> List[VulnerabilityFinding]:
        """按类别筛选漏洞"""
        return [v for v in self.vulnerabilities if v.category == category]

    def get_owasp_mappings(self) -> List[str]:
        """获取所有 OWASP 映射（去重）"""
        return list(set(v.owasp_mapping for v in self.vulnerabilities if v.owasp_mapping))

    @property
    def vulnerability_count(self) -> int:
        """漏洞总数"""
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        """严重漏洞数"""
        return len(self.get_vulnerabilities_by_severity("critical"))

    @property
    def high_count(self) -> int:
        """高危漏洞数"""
        return len(self.get_vulnerabilities_by_severity("high"))
