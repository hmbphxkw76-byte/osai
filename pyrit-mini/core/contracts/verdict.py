"""core/contracts/verdict.py — Judge 裁决契约（VerdictRecord）。

双 Judge（T0 → J1 → J2）产出的裁决需要可持久化、可幂等重放：
`schema_version` 支撑版本漂移检测，`content_hash` 支撑去重与幂等写入。

Academic basis:
    - Zheng et al. (arXiv:2306.05685) LLM-as-a-Judge: 双裁判交叉验证
    - Cohen (1960) Kappa: 一致性口径唯一化（治 A.2「κ 被算两遍且口径不同」）
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


class JudgeVerdict(BaseModel):
    """单个 Judge 的一次裁决。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    judge_id: str  # "T0" / "J1" / "J2"
    score_value: bool = False
    score_type: str = "true_false"
    rationale: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class VerdictRecord(BaseModel):
    """一条攻击结果的完整裁决记录（T0 + J1 + J2 + 最终聚合）。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    attack_id: str = ""
    technique_name: str = ""
    component_key: str = ""
    objective: str = ""
    response: str = ""

    t0: JudgeVerdict | None = None
    j1: JudgeVerdict | None = None
    j2: JudgeVerdict | None = None

    final_success: bool = False
    aggregation: Literal["or", "and", "single", "t0_only"] = "or"
    agreement: bool | None = None  # J1/J2 是否一致（None = 未双裁）

    def add(self, verdict: JudgeVerdict) -> None:
        if verdict.judge_id.upper() == "T0":
            self.t0 = verdict
        elif verdict.judge_id.upper() == "J1":
            self.j1 = verdict
        elif verdict.judge_id.upper() == "J2":
            self.j2 = verdict

    def dual_judged(self) -> bool:
        return self.j1 is not None and self.j2 is not None

    def compute_agreement(self) -> bool | None:
        """J1/J2 一致性；未双裁返回 None（不伪造 —— 治 score_pipeline 早返伪造问题）。"""
        if not self.dual_judged():
            return None
        return bool(self.j1.score_value) == bool(self.j2.score_value)  # type: ignore[union-attr]

    def aggregate(self, mode: Literal["or", "and"] = "or") -> bool:
        """按 C2 默认 OR 聚合计算最终结果；未双裁时以已有裁决为准。"""
        self.aggregation = mode
        self.agreement = self.compute_agreement()
        verdicts = [v for v in (self.j1, self.j2) if v is not None]
        if not verdicts:
            self.final_success = bool(self.t0.score_value) if self.t0 else False
            return self.final_success
        values = [bool(v.score_value) for v in verdicts]
        self.final_success = any(values) if mode == "or" else all(values)
        return self.final_success

    def content_hash(self) -> str:
        payload = json.dumps(
            {
                "attack_id": self.attack_id,
                "technique": self.technique_name,
                "objective": self.objective,
                "response": self.response,
                "component": self.component_key,
                "t0": self.t0.to_dict() if self.t0 else None,
                "j1": self.j1.to_dict() if self.j1 else None,
                "j2": self.j2.to_dict() if self.j2 else None,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
