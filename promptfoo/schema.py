"""
===============================================================================
Promptfoo 数据模型 — 提示词评估 + Pydantic 用例/Payload Schema (整合 datasets/)
===============================================================================
统一提示词管理、测试用例与 Payload 的数据结构定义。
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ═══════════════════════════════════════════════════════════════════
# 1. 提示词评估 Schema (原 promptfoo)
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PromptEntry:
    """单条提示词条目。"""
    id: str
    objective: str
    criterion: str
    content: str
    category: str = ""           # injection / jailbreak / xpia / rag / agent_abuse
    owasp_mapping: str = ""      # e.g. LLM01
    risk_level: str = "medium"   # critical / high / medium / low
    tags: list[str] = field(default_factory=list)
    source: str = "builtin"


@dataclass
class PromptSet:
    """一组提示词（通常对应一个攻击场景）。"""
    name: str
    description: str = ""
    prompts: list[PromptEntry] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PromptfooEvalResult:
    """Promptfoo 评估结果。"""
    success: bool
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    asr_score: float = 0.0
    output_path: str = ""
    raw_results: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════
# 2. Pydantic 用例模型 (原 datasets/models.py)
# ═══════════════════════════════════════════════════════════════════

class SyllabusMapping(BaseModel):
    """7 维攻击分类：模块/章节/OWASP/技术/难度/Crescendo 标记"""
    module: str = ""
    section: str = ""
    attack_category: str = ""
    owasp_llm_top10: str = ""
    primary_technique: str = ""
    difficulty: str = "Basic"
    crescendo: bool = False

    @field_validator("difficulty", mode="before")
    @classmethod
    def _normalize_difficulty(cls, v: str) -> str:
        if isinstance(v, str) and v.startswith("Probe"):
            return "Probe"
        return v


class AttackCombo(BaseModel):
    """一组攻击组合：名称 + 转换器名称列表。"""
    name: str
    converters: list[str] = Field(default_factory=list)

    def to_pyrit_resolver(self):
        try:
            from converters.registry import resolve_converters
            return resolve_converters(self.converters)
        except ImportError:
            import logging
            logging.getLogger(__name__).debug(
                "PyRIT 未安装，AttackCombo.to_pyrit_resolver() 返回空列表"
            )
            return []


class TestCase(BaseModel):
    """一个红队测试用例。"""
    id: str = Field(..., min_length=1)
    objective: str = ""
    criterion: str
    attack_combos: list[AttackCombo] = Field(default_factory=list)
    multi_turn_objectives: Optional[list[str]] = None
    syllabus_mapping: SyllabusMapping = Field(default_factory=SyllabusMapping)

    @property
    def is_multi_turn(self) -> bool:
        return bool(self.multi_turn_objectives)

    @property
    def is_probe(self) -> bool:
        return self.id.upper().startswith("PROBE_")

    @property
    def phase(self) -> str:
        if self.is_probe:
            return "probe"
        if self.is_multi_turn:
            return "crescendo"
        return "single"

    @model_validator(mode="after")
    def _validate_objective_for_type(self) -> "TestCase":
        if not self.is_multi_turn and not self.objective:
            raise ValueError(f"单轮用例 {self.id} 的 objective 不能为空")
        return self

    def to_legacy_dict(self) -> dict:
        data = self.model_dump(exclude_none=True, exclude={"is_multi_turn", "is_probe", "phase"})
        return data

    def to_seed_prompt(self):
        try:
            from pyrit.models import SeedPrompt
            return SeedPrompt(
                id=self.id,
                value=self.objective,
                data_type="text",
                harm_categories=[
                    self.syllabus_mapping.attack_category,
                    self.syllabus_mapping.owasp_llm_top10,
                    self.syllabus_mapping.primary_technique,
                ],
                parameters={
                    "criterion": self.criterion,
                    "attack_combos": [c.model_dump() for c in self.attack_combos],
                    "phase": self.phase,
                    "difficulty": self.syllabus_mapping.difficulty,
                    "multi_turn_objectives": self.multi_turn_objectives,
                },
                source="PyRIT_RedTeam_TestCase",
            )
        except ImportError:
            import logging
            logging.getLogger(__name__).debug(
                "PyRIT 未安装，TestCase.to_seed_prompt() 返回 None"
            )
            return None


class TestCaseSet(BaseModel):
    """JSON 文件的顶层结构：metadata + test_cases 数组"""
    metadata: dict = Field(default_factory=dict)
    test_cases: list[TestCase] = Field(..., min_length=1)

    @classmethod
    def from_json_file(cls, filepath: str) -> "TestCaseSet":
        import json
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)

    def to_legacy_list(self) -> list[dict]:
        return [tc.to_legacy_dict() for tc in self.test_cases]

    def filter_by_phase(self, phase: str) -> "TestCaseSet":
        filtered = [tc for tc in self.test_cases if tc.phase == phase]
        return TestCaseSet(metadata=self.metadata, test_cases=filtered)


class PayloadRegistry(BaseModel):
    """Payload YAML 文件的 Pydantic 模型。"""
    class Config:
        extra = "allow"

    @classmethod
    def from_yaml_file(cls, filepath: str) -> "PayloadRegistry":
        import yaml
        with open(filepath, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return cls.model_validate(raw)

    def extract_payload_vars(self) -> dict[str, str]:
        data = self.model_dump(exclude_none=True)
        return {k: v for k, v in data.items()
                if not k.startswith("_") and isinstance(v, str)}

    def extract_presets(self) -> dict:
        presets = self.model_dump(exclude_none=True).get("_presets", {})
        if isinstance(presets, dict):
            return {k: v for k, v in presets.items() if not k.startswith("_")}
        return {}


_PRESET_DESCRIPTIONS: dict[str, str] = {
    "stealth": "学术/技术中性语言，避免敏感词汇，混淆检测系统",
    "bruteforce": "最直接的攻击版本，含完整代码/命令/步骤",
    "redteam": "红队授权评估视角，含安全评估上下文包装",
    "academic": "学术教学视角，以教育/研究目的呈现",
    "minimal": "最精简版本，只保留核心攻击载荷",
}


class PayloadRow(BaseModel):
    """单个 payload 的行式定义。"""
    name: str = Field(..., min_length=1)
    base: str = Field(..., min_length=1)
    stealth: str = Field(default="", description=_PRESET_DESCRIPTIONS["stealth"])
    bruteforce: str = Field(default="", description=_PRESET_DESCRIPTIONS["bruteforce"])
    redteam: str = Field(default="", description=_PRESET_DESCRIPTIONS["redteam"])
    academic: str = Field(default="", description=_PRESET_DESCRIPTIONS["academic"])
    minimal: str = Field(default="", description=_PRESET_DESCRIPTIONS["minimal"])
    variants: Optional[dict[str, str]] = Field(default=None)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        import re
        if not re.match(r'^[a-z][a-z0-9_]*$', v):
            raise ValueError(f"Payload 名称 '{v}' 不合法，必须是 snake_case")
        return v

    @model_validator(mode="after")
    def _validate_presets(self) -> "PayloadRow":
        for preset_name in ["stealth", "bruteforce", "redteam", "academic", "minimal"]:
            if not getattr(self, preset_name):
                object.__setattr__(self, preset_name, self.base)
        return self

    def to_python_row(self, indent: int = 4) -> str:
        pad = " " * indent
        pad2 = " " * (indent + 4)
        lines = [f"{pad}'{self.name}': {{"]
        lines.append(f"{pad2}\"base\": {self.base!r},")
        for pn in ["stealth", "bruteforce", "redteam", "academic", "minimal"]:
            val = getattr(self, pn, "")
            if val and val != self.base:
                lines.append(f"{pad2}{pn!r}: {val!r},")
        if self.variants:
            lines.append(f'{pad2}"variants": {{')
            for vk, vv in self.variants.items():
                lines.append(f"{pad2}    {vk!r}: {vv!r},")
            lines.append(f"{pad2}}},")
        if lines[-1].endswith(","):
            lines[-1] = lines[-1][:-1]
        lines.append(f"{pad}}},")
        return "\n".join(lines)


class PayloadBatch(BaseModel):
    """LLM 批量生成 payload 的容器模型。"""
    metadata: dict = Field(default_factory=lambda: {
        "generated_by": "PayloadGenerator",
        "version": "auto",
    })
    payloads: list[PayloadRow] = Field(..., min_length=1, max_length=10)

    def to_python_module(self, module_header: str = "") -> str:
        lines = []
        if module_header:
            lines.append(module_header)
        lines.append("# ── 自动生成的 Payload 块 ──")
        lines.append("")
        for p in self.payloads:
            lines.append(p.to_python_row(indent=4))
        lines.append("")
        return "\n".join(lines)


class CaseBatch(BaseModel):
    """LLM 批量生成用例的容器模型。"""
    metadata: dict = Field(default_factory=lambda: {
        "framework": "PyRIT_RedTeam_AutoGenerated",
        "version": "auto",
        "description": "Auto-generated via LLM Few-shot + Pydantic Validation",
    })
    test_cases: list[TestCase] = Field(..., min_length=1, max_length=50)


# ═══════════════════════════════════════════════════════════════════
# 3. 动态扩展注册表
# ═══════════════════════════════════════════════════════════════════

_DYNAMIC_PAYLOADS: dict[str, dict[str, str]] = {}
_DYNAMIC_CASES: list[TestCase] = []


def register_payload(name: str, payload: dict[str, str]) -> None:
    if not isinstance(payload, dict) or "base" not in payload:
        raise ValueError("payload 必须是包含 'base' 键的字典")
    try:
        PayloadRow.model_validate({"name": name, **payload})
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Payload '%s' Pydantic 校验警告: %s", name, e)
    _DYNAMIC_PAYLOADS[name] = payload


def register_preset(preset_name: str, preset_payloads: dict[str, str]) -> None:
    for name in preset_payloads:
        if name not in _DYNAMIC_PAYLOADS:
            _DYNAMIC_PAYLOADS[name] = {}
        _DYNAMIC_PAYLOADS[name][preset_name] = preset_payloads[name]


def inject_payload(name: str, value: str, preset: str = "base") -> None:
    if name not in _DYNAMIC_PAYLOADS:
        _DYNAMIC_PAYLOADS[name] = {}
    _DYNAMIC_PAYLOADS[name][preset] = value


def register_test_case(
    case_id: str,
    objective: str = "",
    criterion: str = "",
    attack_combos: list[dict] | None = None,
    multi_turn_objectives: list[str] | None = None,
    difficulty: str = "Basic",
) -> TestCase:
    combos = [
        AttackCombo(name=c["name"], converters=c["converters"])
        for c in (attack_combos or [])
    ]
    tc = TestCase(
        id=case_id,
        objective=objective,
        criterion=criterion,
        attack_combos=combos,
        multi_turn_objectives=multi_turn_objectives,
        syllabus_mapping=SyllabusMapping(difficulty=difficulty),
    )
    _DYNAMIC_CASES.append(tc)
    return tc


__all__ = [
    # 提示词评估
    "PromptEntry",
    "PromptSet",
    "PromptfooEvalResult",
    # Pydantic 用例模型
    "SyllabusMapping",
    "AttackCombo",
    "TestCase",
    "TestCaseSet",
    "PayloadRegistry",
    "PayloadRow",
    "PayloadBatch",
    "CaseBatch",
    # 动态注册
    "register_payload",
    "register_preset",
    "inject_payload",
    "register_test_case",
]
