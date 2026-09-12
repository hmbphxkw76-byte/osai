"""core/contracts/evidence.py — 证据记录契约（EvidenceRecord）。

**修 CB-2 断裂**：`report/component_reports.py:96/109/167` 读取
`getattr(ev, "metadata", {}).get("component_type")`，而 `report/evidence.py` 的
`VulnerabilityEvidence` 无 `metadata` 字段 → 恒 `{}` → `_determine_dominant_component()`
恒 `None` → **组件专属报告永不生成**。

本契约定义 `metadata` 的最小必填形状，并由 `core/phases/_component_bridge.py`
统一写入（规则 CB-1：禁止其他模块直接写 `component_type`）。

Academic basis:
    - PyRIT (arXiv:2407.01232): AttackResult 证据固化
    - REQ-007: 全字段证据（可复现 PoC）
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


class EvidenceRecord(BaseModel):
    """一条可序列化、可哈希、可追溯的证据记录。

    `metadata` 至少应含 `component_type`（CB-1/CB-2），其余键自由扩展
    （category / attack_vector / owasp_id ...）。
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    evidence_id: str = ""
    attack_id: str = ""
    technique_name: str = ""
    objective: str = ""
    converted_value: str = ""
    response: str = ""
    is_success: bool = False
    component_key: str = ""
    owasp_id: str = ""
    cvss_vector: str = ""
    arxiv_reference: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # component_type（CB-2 唯一读取口径）
    # ------------------------------------------------------------------
    @property
    def component_type(self) -> str | None:
        """读取 `metadata["component_type"]`；缺省回落到显式字段（IA-6：不崩溃）。"""
        value = self.metadata.get("component_type")
        if isinstance(value, str) and value:
            return value
        return self.component_key or None

    def stamp_component(self, component_key: str, *, extra: dict[str, Any] | None = None) -> None:
        """写入 component_type（CB-1：仅 `_component_bridge` 应调用）。"""
        self.metadata["component_type"] = component_key
        if component_key:
            self.component_key = component_key
        if extra:
            self.metadata.update(extra)

    # ------------------------------------------------------------------
    # 幂等哈希（重跑不重复追加）
    # ------------------------------------------------------------------
    def content_hash(self) -> str:
        """内容哈希：用于重跑去重与 EVD 文件幂等写入。"""
        payload = json.dumps(
            {
                "technique": self.technique_name,
                "objective": self.objective,
                "converted": self.converted_value,
                "response": self.response,
                "component": self.component_type or "",
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
