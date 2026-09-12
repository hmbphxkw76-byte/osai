"""core/contracts — 跨阶段共享的 Pydantic v2 契约层（plan Wave 1 / REQ-153）。

本包是「多组件组合体」目标架构的类型心脏。所有跨阶段（recon → arm → strike →
assess → report）传递的结构化数据都在此定义，做到：

* **一处定义、多处消费**（宪法 C3 SSOT）
* **可序列化**（model_dump / model_validate），支撑 checkpoint/resume 与证据落盘
* **带 schema_version**，支撑幂等重放与版本漂移检测

子模块：
    component.py        ComponentSpec / DetectionSpec / AssessSpec / WiringError
    component_graph.py  ComponentNode / ComponentEdge / ComponentGraph
    attack_chain.py     ChainState / AttackStep / StatefulAttackChain / FailedStep
    impact_chain.py     ImpactNode / ImpactLink / ImpactChain / CausalityGap
    evidence.py         EvidenceRecord（含 metadata —— 修 CB-2 断裂）
    verdict.py          JudgeVerdict / VerdictRecord（schema_version + content_hash）
    manifest.py         ScoreRunManifest（seed / judge 模型 / rubric 哈希 / temperature）

Academic basis:
    - PyRIT (arXiv:2407.01232): AttackResult / ScenarioResult 结构化结果模型
    - Greshake et al. (arXiv:2302.12173): 攻击面建模与攻击链抽象
"""

from __future__ import annotations

from core.contracts.attack_chain import (
    AttackStep,
    ChainState,
    FailedStep,
    StatefulAttackChain,
)
from core.contracts.component import (
    AssessSpec,
    ComponentSpec,
    DetectionSpec,
    WiringError,
)
from core.contracts.component_graph import (
    ComponentEdge,
    ComponentGraph,
    ComponentNode,
)
from core.contracts.evidence import EvidenceRecord
from core.contracts.impact_chain import (
    CausalityGap,
    ImpactChain,
    ImpactLink,
    ImpactNode,
)
from core.contracts.manifest import ScoreRunManifest
from core.contracts.verdict import JudgeVerdict, VerdictRecord

SCHEMA_VERSION = "1.0"

__all__ = [
    "SCHEMA_VERSION",
    "AssessSpec",
    "ComponentSpec",
    "DetectionSpec",
    "WiringError",
    "ComponentEdge",
    "ComponentGraph",
    "ComponentNode",
    "AttackStep",
    "ChainState",
    "FailedStep",
    "StatefulAttackChain",
    "CausalityGap",
    "ImpactChain",
    "ImpactLink",
    "ImpactNode",
    "EvidenceRecord",
    "JudgeVerdict",
    "VerdictRecord",
    "ScoreRunManifest",
]
