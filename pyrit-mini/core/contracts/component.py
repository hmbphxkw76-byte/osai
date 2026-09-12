"""core/contracts/component.py — 组件规格契约（ComponentSpec）。

`ComponentSpec` 是「每种组件都有全套配套」的声明式载体：一个组件键
（如 `mcp_tool_poisoning`）在一处 YAML 中声明它的 recon / seeds / converters /
strike / assess / report / PoC 全链路落点，运行时调度与静态校验共用同一份数据
（治愈宪法 C3 违例与 IA-3「组件类型键四份分散硬编码」）。

契约来源（一处定义两处用）：
    运行时：core/registry.py → ComponentRegistry.spec(key)
    静态  ：tools/architecture_validator.py ← ComponentRegistry.validate_wiring()

Academic basis:
    - NIST SP 800-115 Sec4: Attack surface enumeration（组件面枚举）
    - OWASP ASI Top 10: owasp 字段用于 ASI01-ASI10 映射
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0"

# 组件间关系语义（ComponentEdge.relation 的取值域；与 AttackPathPlanner 共用）
RELATIONS = (
    "calls",
    "retrieves_from",
    "delegates_to",
    "persists_to",
    "gated_by",
    "observes",
)


class DetectionSpec(BaseModel):
    """组件识别信号（多信号融合的输入）。

    `signals` 是 `config/components/README.md` W0 契约的字段名，与 4.3 节的
    `path_patterns`/`body_markers` 等价，二者取并集，保证新旧 YAML 都能加载。
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    path_patterns: list[str] = Field(default_factory=list)
    body_markers: list[str] = Field(default_factory=list)
    active_probes: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    min_confidence: float = 0.60

    @field_validator("min_confidence")
    @classmethod
    def _clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, float(v)))

    def all_signals(self) -> list[str]:
        """返回去重的全部识别信号（路径 + 响应体 + 主动探针 + legacy signals）。"""
        merged = [*self.path_patterns, *self.body_markers, *self.active_probes, *self.signals]
        seen: set[str] = set()
        out: list[str] = []
        for s in merged:
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out


class AssessSpec(BaseModel):
    """组件评分落点：T0 检测函数 + rubric。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    t0_check: str | None = None
    rubric: str | None = None


class ComponentSpec(BaseModel):
    """单个组件的全链路规格（C-NAME-1：component_key 与 strike/<dir>/ 语义一致）。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION

    # ---- 身份 ----
    component_key: str
    id: str = ""  # 短名（mcp / a2a / rag ...），缺省取 YAML 文件名
    display_name: str = ""
    labels: list[str] = Field(default_factory=list)

    # ---- 目录落点（C-NAME-1）----
    recon_dir: str = ""
    strike_dir: str = ""

    # ---- 识别 ----
    detection: DetectionSpec = Field(default_factory=DetectionSpec)
    detect: dict[str, Any] | None = None  # legacy: {signals: [...], min_confidence: float}

    # ---- 侦察 ----
    recon_modules: list[str] = Field(default_factory=list)
    recon: list[str] = Field(default_factory=list)  # legacy alias
    service_profile_keys: list[str] = Field(default_factory=list)

    # ---- 武器化（ARM）----
    seed_sets: list[str] = Field(default_factory=list)
    seeds: list[str] = Field(default_factory=list)  # legacy alias
    seed_suitable_for: list[str] = Field(default_factory=list)  # C-NAME-2
    converter_vectors: list[str] = Field(default_factory=list)
    converters: list[str] = Field(default_factory=list)  # legacy alias

    # ---- 攻击（STRIKE）----
    preferred_attack_class: str = "PromptSendingAttack"  # 宪法 7B
    asr_prior: float = 0.50
    strike_modules: list[str] = Field(default_factory=list)
    playbooks: list[str] = Field(default_factory=list)

    # ---- 评分 / 报告 / PoC ----
    assess: AssessSpec | None = None
    scorer: str | None = None  # rubric 名（legacy）
    report_builder: str | None = None
    report_section: str | None = None  # legacy alias
    poc_template: str | None = None

    # ---- 组合体推断 & 合规 ----
    owasp: list[str] = Field(default_factory=list)
    neighbors: list[str] = Field(default_factory=list)
    cleanup: list[str] = Field(default_factory=list)  # I13：未声明 cleanup 的副作用步禁止执行

    @field_validator("component_key", "id")
    @classmethod
    def _strip(cls, v: str) -> str:
        return (v or "").strip()

    # ------------------------------------------------------------------
    # 归一化：legacy 字段并入新字段，保证"一处定义"对下游唯一可见
    # ------------------------------------------------------------------
    def model_post_init(self, __context: Any) -> None:  # noqa: D105
        if not self.id:
            self.id = self.component_key
        if not self.display_name:
            self.display_name = self.component_key
        if not self.labels:
            self.labels = [self.id or self.component_key]

        # legacy detect: {signals, min_confidence}
        if isinstance(self.detect, dict):
            sigs = [str(s) for s in (self.detect.get("signals") or []) if s]
            if sigs:
                merged = list(self.detection.signals) + [
                    s for s in sigs if s not in self.detection.signals
                ]
                self.detection = self.detection.model_copy(update={"signals": merged})
            mc = self.detect.get("min_confidence")
            if mc is not None and abs(float(self.detection.min_confidence) - 0.60) < 1e-9:
                self.detection = self.detection.model_copy(update={"min_confidence": float(mc)})

        # legacy list aliases
        self.recon_modules = _merge(self.recon_modules, self.recon)
        self.seed_sets = _merge(self.seed_sets, self.seeds)
        self.converter_vectors = _merge(self.converter_vectors, self.converters)

        # legacy scorer / report_section
        if self.scorer and self.assess is None:
            self.assess = AssessSpec(t0_check=None, rubric=self.scorer)
        elif self.scorer and self.assess is not None and not self.assess.rubric:
            self.assess.rubric = self.scorer
        if self.report_section and not self.report_builder:
            self.report_builder = self.report_section

        # seed_suitable_for 缺省 = 组件键自身（C-NAME-2）
        if not self.seed_suitable_for:
            self.seed_suitable_for = [self.component_key]

        if not self.strike_dir and self.id:
            self.strike_dir = self.id
        if not self.recon_dir and self.id:
            self.recon_dir = self.id

    # ------------------------------------------------------------------
    # 便捷查询
    # ------------------------------------------------------------------
    @property
    def min_confidence(self) -> float:
        return self.detection.min_confidence

    @property
    def signals(self) -> list[str]:
        return self.detection.all_signals()

    @property
    def rubric(self) -> str | None:
        return (self.assess.rubric if self.assess else None) or self.scorer

    @property
    def t0_check(self) -> str | None:
        return self.assess.t0_check if self.assess else None

    def recon_module_list(self) -> list[str]:
        return list(self.recon_modules)

    @classmethod
    def from_yaml(cls, data: dict[str, Any], *, fallback_id: str = "") -> "ComponentSpec":
        """从 YAML 字典构造；未知字段忽略，缺字段走缺省（IA-6：未知组件不崩溃）。"""
        if not isinstance(data, dict):
            raise TypeError(f"ComponentSpec expects dict, got {type(data).__name__}")
        payload = dict(data)
        payload.setdefault("id", fallback_id)
        if not payload.get("component_key"):
            payload["component_key"] = str(payload.get("id") or fallback_id)
        return cls.model_validate(payload)


def _merge(primary: list[str], legacy: list[str]) -> list[str]:
    """合并主字段与 legacy 别名字段，保持顺序且去重。"""
    out: list[str] = []
    seen: set[str] = set()
    for item in [*primary, *legacy]:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


class WiringError(BaseModel):
    """组件接线校验错误（供 `ComponentRegistry.validate_wiring()` 与 architecture_validator 使用）。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    component_key: str
    layer: Literal["recon", "strike", "assess", "report", "seeds", "schema"]
    detail: str
    severity: Literal["warning", "blocking"] = "warning"

    def __str__(self) -> str:  # pragma: no cover - 展示用
        return f"[{self.severity.upper()}][{self.layer}] {self.component_key}: {self.detail}"
