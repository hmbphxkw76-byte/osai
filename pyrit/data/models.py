"""
===============================================================================
OffSec AI-300 — Pydantic 数据模型（用例 & Payload Schema 验证）
===============================================================================
职责:
- 定义 TestCase / AttackCombo / SyllabusMapping / PayloadRegistry 的数据结构
- 提供运行时验证：JSON → Pydantic → 自动校验字段完整性 + 类型正确性
- 支持 LLM Few-shot 生成时的结构化约束（model_json_schema() 输出 JSON Schema）
- 对 engines.py / reporter.py 完全透明：Pydantic 实例仍支持 dict-like 访问

使用方式:
    from data.models import TestCaseSet
    validated = TestCaseSet.model_validate(json_data)       # Pydantic v2 风格
    cases_dict = validated.model_dump()["test_cases"]        # 转回 dict, 零代码改动

新增用例时的 Schema 保障:
    from data.models import TestCase
    new_case = TestCase(id="CAP_xxx", objective="...", criterion="...", ...)
    # 若字段缺失/类型错误 → 立即抛 ValidationError，防止入库坏数据
===============================================================================
"""
from __future__ import annotations

from typing import Optional, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


# ═══════════════════════════════════════════════════════════════════
# 1. SyllabusMapping — 教学大纲映射（每个用例 7 维分类）
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
        """归一化难度标记，兼容 "Probe (Lightweight)" → 统一为 "Probe" """
        if isinstance(v, str) and v.startswith("Probe"):
            return "Probe"
        return v


# ═══════════════════════════════════════════════════════════════════
# 2. AttackCombo — 攻击组合单元
# ═══════════════════════════════════════════════════════════════════

class AttackCombo(BaseModel):
    """一组攻击组合：名称 + 转换器名称列表（与 CONVERTER_MAP 键对应）"""
    name: str
    converters: list[str] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════
# 3. TestCase — 单个测试用例
# ═══════════════════════════════════════════════════════════════════

class TestCase(BaseModel):
    """一个红队测试用例。

    字段说明:
    - id: 唯一标识（如 CAP_001_social_eng_phishing / PROBE_01_roleplay_defense）
    - objective: 攻击目标文本（支持 {key} 模板占位符）
    - criterion: 成功判定标准（Judge 用）
    - attack_combos: 应用的攻击组合列表
    - syllabus_mapping: 7 维分类
    - multi_turn_objectives: 若提供，则为多轮 Crescendo 用例（每轮一个子目标）
    """
    id: str = Field(..., min_length=1, description="Unique case identifier")
    objective: str = ""
    criterion: str
    attack_combos: list[AttackCombo] = Field(default_factory=list)

    # ── 可选字段（单轮用例可省略） ──
    multi_turn_objectives: Optional[list[str]] = None

    # ── 元信息（全部有默认值，向后兼容旧 JSON） ──
    syllabus_mapping: SyllabusMapping = Field(default_factory=SyllabusMapping)

    # ═══════════════════════════════════════════════════
    # 计算属性（替代 engines.classify_case 中的字符串 if-else）
    # ═══════════════════════════════════════════════════

    @property
    def is_multi_turn(self) -> bool:
        """是否为 Crescendo 多轮用例"""
        return bool(self.multi_turn_objectives)

    @property
    def is_probe(self) -> bool:
        """是否为轻量探测用例（ID 以 PROBE_ 开头）"""
        return self.id.upper().startswith("PROBE_")

    @property
    def phase(self) -> str:
        """返回用例的归属阶段: probe | single | crescendo"""
        if self.is_probe:
            return "probe"
        if self.is_multi_turn:
            return "crescendo"
        return "single"

    @model_validator(mode="after")
    def _validate_objective_for_type(self) -> "TestCase":
        """校验: 多轮用例 objective 可为空（用 multi_turn_objectives 替代）；
        单轮用例 objective 不可为空。"""
        if not self.is_multi_turn and not self.objective:
            raise ValueError(f"单轮用例 {self.id} 的 objective 不能为空")
        return self

    def to_legacy_dict(self) -> dict:
        """转为 engines/reporter 兼容的旧格式 dict（零代码改动兼容）"""
        data = self.model_dump(exclude_none=True, exclude={"is_multi_turn", "is_probe", "phase"})
        return data


# ═══════════════════════════════════════════════════════════════════
# 4. TestCaseSet — 完整测试用例集
# ═══════════════════════════════════════════════════════════════════

class TestCaseSet(BaseModel):
    """JSON 文件的顶层结构：metadata + test_cases 数组"""
    metadata: dict = Field(default_factory=dict)
    test_cases: list[TestCase] = Field(..., min_length=1)

    @classmethod
    def from_json_file(cls, filepath: str) -> "TestCaseSet":
        """从 JSON 文件加载并自动校验。"""
        import json
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)

    def to_legacy_list(self) -> list[dict]:
        """将 test_cases 转为旧代码兼容的 dict 列表。"""
        return [tc.to_legacy_dict() for tc in self.test_cases]


# ═══════════════════════════════════════════════════════════════════
# 5. PayloadRegistry — Payload 变量注册表（YAML → Pydantic 校验）
# ═══════════════════════════════════════════════════════════════════

class PayloadRegistry(BaseModel):
    """Payload YAML 文件的 Pydantic 模型。

    自动识别: _description, _presets, _variants 等元数据键。
    所有非 _ 开头键为 payload 变量名 → 字符串值。
    """
    class Config:
        extra = "allow"  # 允许任意动态 payload 键

    @classmethod
    def from_yaml_file(cls, filepath: str) -> "PayloadRegistry":
        """从 YAML 文件加载并校验基本结构。"""
        import yaml
        with open(filepath, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return cls.model_validate(raw)

    def extract_payload_vars(self) -> dict[str, str]:
        """提取所有非元数据 payload 变量（排除 _ 开头的键）。"""
        data = self.model_dump(exclude_none=True)
        return {k: v for k, v in data.items()
                if not k.startswith("_") and isinstance(v, str)}

    def extract_presets(self) -> dict:
        """提取 _presets 节（若存在）。"""
        presets = self.model_dump(exclude_none=True).get("_presets", {})
        if isinstance(presets, dict):
            return {k: v for k, v in presets.items() if not k.startswith("_")}
        return {}


# ═══════════════════════════════════════════════════════════════════
# 6. PayloadRow — 单个 Payload 的行式定义（LLM 生成用）
# ═══════════════════════════════════════════════════════════════════

_PRESET_DESCRIPTIONS: dict[str, str] = {
    "stealth": "学术/技术中性语言，避免敏感词汇，混淆检测系统",
    "bruteforce": "最直接的攻击版本，含完整代码/命令/步骤",
    "redteam": "红队授权评估视角，含安全评估上下文包装",
    "academic": "学术教学视角，以教育/研究目的呈现",
    "minimal": "最精简版本，只保留核心攻击载荷",
}

class PayloadRow(BaseModel):
    """单个 payload 的行式定义，对应 payloads_cn.py 中 PAYLOADS 的一行。

    字段说明:
    - name: payload 变量名（snake_case），如 "sql_injection_bypass"
    - base: 基础载荷文本（原始版本）
    - stealth/bruteforce/redteam/academic/minimal: 5 套预设变体
    - variants: 可选的子变体（A/B/C/D 分类）
    """
    name: str = Field(
        ...,
        min_length=1,
        description="Payload 变量名（snake_case 英文），如 sql_injection_bypass"
    )
    base: str = Field(..., min_length=1, description="基础载荷文本")
    stealth: str = Field(default="", description=_PRESET_DESCRIPTIONS["stealth"])
    bruteforce: str = Field(default="", description=_PRESET_DESCRIPTIONS["bruteforce"])
    redteam: str = Field(default="", description=_PRESET_DESCRIPTIONS["redteam"])
    academic: str = Field(default="", description=_PRESET_DESCRIPTIONS["academic"])
    minimal: str = Field(default="", description=_PRESET_DESCRIPTIONS["minimal"])
    variants: Optional[dict[str, str]] = Field(
        default=None,
        description="可选的子变体（如 {'A_xxx': '...', 'B_xxx': '...'}）"
    )

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        """确保 name 是合法 Python 标识符（snake_case）。"""
        import re
        if not re.match(r'^[a-z][a-z0-9_]*$', v):
            raise ValueError(
                f"Payload 名称 '{v}' 不合法，必须是小写英文字母开头的 snake_case"
            )
        # 保留字检查
        reserved = {"ctx_hm_prompt", "ctx_hm_prompt"}
        if v in reserved:
            raise ValueError(f"'{v}' 是系统保留变量名，不可用于 payload")
        return v

    @model_validator(mode="after")
    def _validate_presets(self) -> "PayloadRow":
        """若 preset 为空，自动回退为 base 值。"""
        for preset_name in ["stealth", "bruteforce", "redteam", "academic", "minimal"]:
            if not getattr(self, preset_name):
                object.__setattr__(self, preset_name, self.base)
        return self

    def to_python_row(self, indent: int = 4) -> str:
        """将 PayloadRow 转换为 payloads_cn.py 中可直接插入的行式代码块。

        Returns:
            可复制到 PAYLOADS 字典中的 Python 代码片段
        """
        pad = " " * indent
        pad2 = " " * (indent + 4)
        lines = [f"{pad}'{self.name}': {{"]
        lines.append(f"{pad2}\"base\": {self.base!r},")

        # 只输出与 base 不同的 preset
        for pn in ["stealth", "bruteforce", "redteam", "academic", "minimal"]:
            val = getattr(self, pn, "")
            if val and val != self.base:
                lines.append(f"{pad2}{pn!r}: {val!r},")

        if self.variants:
            lines.append(f'{pad2}"variants": {{')
            for vk, vv in self.variants.items():
                lines.append(f"{pad2}    {vk!r}: {vv!r},")
            lines.append(f"{pad2}}},")

        # 移除最后一个逗号
        if lines[-1].endswith(","):
            lines[-1] = lines[-1][:-1]
        lines.append(f"{pad}}},")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# 7. PayloadBatch — LLM 批量生成 Payload 的容器
# ═══════════════════════════════════════════════════════════════════

class PayloadBatch(BaseModel):
    """LLM 批量生成 payload 的容器模型。
    调用 LLM 生成 JSON 后直接用此模型校验 → 入库前自动发现格式错误。
    """
    metadata: dict = Field(default_factory=lambda: {
        "generated_by": "PayloadGenerator",
        "version": "auto",
    })
    payloads: list[PayloadRow] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="生成的 payload 行列表"
    )

    def to_python_module(self, module_header: str = "") -> str:
        """将整个 batch 转换为可插入 payloads_*.py 的 Python 代码。

        Args:
            module_header: 可选的顶部注释

        Returns:
            完整的 Python 代码片段
        """
        lines = []
        if module_header:
            lines.append(module_header)
        lines.append("# ── 自动生成的 Payload 块 ──")
        lines.append("")
        for p in self.payloads:
            lines.append(p.to_python_row(indent=4))
        lines.append("")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# 8. CaseBatch — LLM Few-shot 生成的批量用例容器
# ═══════════════════════════════════════════════════════════════════

class CaseBatch(BaseModel):
    """LLM 批量生成用例的容器模型。
    调用 LLM 生成 JSON 后直接用此模型校验 → 入库前自动发现格式错误。
    """
    metadata: dict = Field(default_factory=lambda: {
        "framework": "OffSec_AI300_AutoGenerated",
        "version": "auto",
        "description": "Auto-generated via LLM Few-shot + Pydantic Validation",
    })
    test_cases: list[TestCase] = Field(..., min_length=1, max_length=50)
