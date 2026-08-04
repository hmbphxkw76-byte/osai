# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""FrameworkMapper — 三框架映射 (CSA + OWASP Agentic + MITRE ATLAS)。.

提供三个行业标准框架之间的映射关系:

1. CSA Agentic AI Red Teaming Guide — 12 威胁类别
2. OWASP Agentic Top 10 (ASI01-ASI10) — 10 风险分类
3. MITRE ATLAS — AI/ML 对抗技术

三框架链: CSA → OWASP → ATLAS
  CSA 告诉你 "测什么"
  OWASP 分类 "发现了什么"
  ATLAS 链接 "已知对抗技术"

与 mcp-attack-labs 的三框架映射完全对齐。

> **日期**: 2026-8-4
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class OWASPAgenticCode(str, Enum):
    """OWASP Agentic Top 10 (ASI01-ASI10) 风险代码。."""

    ASI01 = "ASI01"  # Agent Goal Hijacking
    ASI02 = "ASI02"  # Tool Misuse & Exploitation
    ASI03 = "ASI03"  # Identity & Authorization Failures
    ASI04 = "ASI04"  # Supply Chain Vulnerabilities
    ASI05 = "ASI05"  # Insecure Output Handling
    ASI06 = "ASI06"  # Knowledge & Memory Poisoning
    ASI07 = "ASI07"  # Insecure Inter-Agent Communication
    ASI08 = "ASI08"  # Cascading Failures
    ASI09 = "ASI09"  # Human Trust Exploitation
    ASI10 = "ASI10"  # Agent Untraceability


class AssessmentPhase(str, Enum):
    """5 阶段评估流程。."""

    SCOPING = "phase1_scoping"
    ENUMERATION = "phase2_enumeration"
    AUTOMATED_SCAN = "phase3_automated_scan"
    DEEP_EXPLOITATION = "phase4_deep_exploitation"
    MANUAL_TESTING = "phase5_manual_testing"


# ── CSA → OWASP 映射 ──
CSA_CATEGORY_OWASP_MAP: dict[str, list[OWASPAgenticCode]] = {
    "Authorization & Control Hijacking": [OWASPAgenticCode.ASI01, OWASPAgenticCode.ASI03],
    "Checker-Out-of-the-Loop": [OWASPAgenticCode.ASI09],
    "Critical System Interaction": [OWASPAgenticCode.ASI02, OWASPAgenticCode.ASI05],
    "Goal & Instruction Manipulation": [OWASPAgenticCode.ASI01],
    "Hallucination Exploitation": [OWASPAgenticCode.ASI08],
    "Impact Chain & Blast Radius": [OWASPAgenticCode.ASI08],
    "Knowledge Base Poisoning": [OWASPAgenticCode.ASI06],
    "Memory & Context Manipulation": [OWASPAgenticCode.ASI06],
    "Multi-Agent Exploitation": [OWASPAgenticCode.ASI07],
    "Resource & Service Exhaustion": [OWASPAgenticCode.ASI08],
    "Supply Chain & Dependency": [OWASPAgenticCode.ASI04],
    "Agent Untraceability": [OWASPAgenticCode.ASI10],
}

# ── OWASP → MITRE ATLAS 映射 ──
OWASP_ATLAS_MAP: dict[OWASPAgenticCode, list[str]] = {
    OWASPAgenticCode.ASI01: ["AML.T0051", "AML.T0054"],
    OWASPAgenticCode.ASI02: ["AML.T0056", "AML.T0048"],
    OWASPAgenticCode.ASI03: ["AML.T0051"],
    OWASPAgenticCode.ASI04: ["AML.T0053"],
    OWASPAgenticCode.ASI05: ["AML.T0048", "AML.T0049"],
    OWASPAgenticCode.ASI06: ["AML.T0043"],
    OWASPAgenticCode.ASI07: ["AML.T0051", "AML.T0056"],
    OWASPAgenticCode.ASI08: ["AML.T0043", "AML.T0048"],
    OWASPAgenticCode.ASI09: ["AML.T0052"],
    OWASPAgenticCode.ASI10: [],
}

# ── OWASP 描述 ──
_OWASP_DESCRIPTIONS: dict[OWASPAgenticCode, str] = {
    OWASPAgenticCode.ASI01: "Agent Goal Hijacking — 代理目标被攻击者替换",
    OWASPAgenticCode.ASI02: "Tool Misuse & Exploitation — 合法工具被恶意参数调用或链式利用",
    OWASPAgenticCode.ASI03: "Identity & Authorization Failures — 代理继承凭证或信任未验证身份",
    OWASPAgenticCode.ASI04: "Supply Chain Vulnerabilities — 恶意 MCP 服务器或依赖包",
    OWASPAgenticCode.ASI05: "Insecure Output Handling — 代理输出未经验证被下游消费",
    OWASPAgenticCode.ASI06: "Knowledge & Memory Poisoning — RAG/向量库/持久记忆被投毒",
    OWASPAgenticCode.ASI07: "Insecure Inter-Agent Communication — 伪造委托消息或编排器投毒",
    OWASPAgenticCode.ASI08: "Cascading Failures — 单一投毒输入通过多代理管道放大",
    OWASPAgenticCode.ASI09: "Human Trust Exploitation — 用户过度依赖代理输出",
    OWASPAgenticCode.ASI10: "Agent Untraceability — 日志不足导致无法取证",
}


@dataclass
class CoverageMatrix:
    """框架覆盖矩阵。.

    Attributes:
        tested_owasp_codes: 已测试的 OWASP 代码集合。
        tested_atlas_techniques: 已测试的 ATLAS 技术集合。
        tested_csa_categories: 已测试的 CSA 类别集合。
        total_owasp: OWASP 总数 (固定 10)。
        total_csa: CSA 总数 (固定 12)。
    """

    tested_owasp_codes: set[OWASPAgenticCode] = field(default_factory=set)
    tested_atlas_techniques: set[str] = field(default_factory=set)
    tested_csa_categories: set[str] = field(default_factory=set)
    total_owasp: int = 10
    total_csa: int = 12

    @property
    def owasp_coverage_pct(self) -> float:
        """OWASP 覆盖率百分比。."""
        return (len(self.tested_owasp_codes) / self.total_owasp) * 100

    @property
    def csa_coverage_pct(self) -> float:
        """CSA 覆盖率百分比。."""
        return (len(self.tested_csa_categories) / self.total_csa) * 100

    @property
    def atlas_coverage_count(self) -> int:
        """ATLAS 技术覆盖数。."""
        return len(self.tested_atlas_techniques)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "tested_owasp_codes": sorted(c.value for c in self.tested_owasp_codes),
            "tested_atlas_techniques": sorted(self.tested_atlas_techniques),
            "tested_csa_categories": sorted(self.tested_csa_categories),
            "owasp_coverage_pct": round(self.owasp_coverage_pct, 1),
            "csa_coverage_pct": round(self.csa_coverage_pct, 1),
            "atlas_coverage_count": self.atlas_coverage_count,
        }


class FrameworkMapper:
    """三框架映射器。.

    提供 CSA ↔ OWASP ↔ ATLAS 之间的双向映射,
    以及覆盖率矩阵生成。

    用法:
        mapper = FrameworkMapper()
        owasp_codes = mapper.csa_to_owasp("Goal & Instruction Manipulation")
        atlas_codes = mapper.owasp_to_atlas(OWASPAgenticCode.ASI01)
        coverage = mapper.build_coverage_matrix(
            tested_owasp={OWASPAgenticCode.ASI01, OWASPAgenticCode.ASI02}
        )
    """

    def csa_to_owasp(self, csa_category: str) -> list[OWASPAgenticCode]:
        """CSA 类别 → OWASP 代码。.

        Args:
            csa_category: CSA 威胁类别名称。

        Returns:
            对应的 OWASP 代码列表 (空列表 if unknown)。
        """
        return CSA_CATEGORY_OWASP_MAP.get(csa_category, [])

    def owasp_to_atlas(self, owasp_code: OWASPAgenticCode) -> list[str]:
        """OWASP 代码 → MITRE ATLAS 技术。.

        Args:
            owasp_code: OWASP Agentic 代码。

        Returns:
            对应的 ATLAS 技术列表。
        """
        return OWASP_ATLAS_MAP.get(owasp_code, [])

    def owasp_description(self, owasp_code: OWASPAgenticCode) -> str:
        """获取 OWASP 代码描述。.

        Args:
            owasp_code: OWASP Agentic 代码。

        Returns:
            描述文本。
        """
        return _OWASP_DESCRIPTIONS.get(owasp_code, "")

    def build_coverage_matrix(
        self,
        *,
        tested_owasp: set[OWASPAgenticCode] | None = None,
        tested_csa: set[str] | None = None,
    ) -> CoverageMatrix:
        """构建覆盖矩阵。.

        Args:
            tested_owasp: 已测试的 OWASP 代码集合。
            tested_csa: 已测试的 CSA 类别集合。

        Returns:
            CoverageMatrix 覆盖矩阵。
        """
        tested_owasp = tested_owasp or set()
        tested_csa = tested_csa or set()

        tested_atlas: set[str] = set()
        for code in tested_owasp:
            tested_atlas.update(self.owasp_to_atlas(code))

        return CoverageMatrix(
            tested_owasp_codes=tested_owasp,
            tested_atlas_techniques=tested_atlas,
            tested_csa_categories=tested_csa,
        )

    def get_all_csa_categories(self) -> list[str]:
        """获取全部 CSA 类别列表。.

        Returns:
            CSA 类别名称列表。
        """
        return list(CSA_CATEGORY_OWASP_MAP.keys())

    def get_all_owasp_codes(self) -> list[OWASPAgenticCode]:
        """获取全部 OWASP Agentic 代码列表。.

        Returns:
            OWASP 代码列表。
        """
        return list(OWASPAgenticCode)

    def map_attack_to_frameworks(
        self,
        *,
        attack_type: str,
        owasp_codes: list[OWASPAgenticCode],
    ) -> dict[str, Any]:
        """将攻击映射到三框架。.

        Args:
            attack_type: 攻击类型名称。
            owasp_codes: 关联的 OWASP 代码列表。

        Returns:
            包含攻击类型和三框架映射的字典。
        """
        atlas_techniques: list[str] = []
        for code in owasp_codes:
            atlas_techniques.extend(self.owasp_to_atlas(code))

        csa_categories = [
            cat
            for cat, codes in CSA_CATEGORY_OWASP_MAP.items()
            if any(code in owasp_codes for code in codes)
        ]

        return {
            "attack_type": attack_type,
            "owasp_codes": [c.value for c in owasp_codes],
            "atlas_techniques": atlas_techniques,
            "csa_categories": csa_categories,
            "owasp_descriptions": [
                self.owasp_description(c) for c in owasp_codes
            ],
        }
