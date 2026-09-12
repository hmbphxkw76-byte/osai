"""core/registry.py - ComponentRegistry：组件差异的唯一来源（REQ-153 / plan Wave 1）。

目标架构 v4.0（蓝图第十三章）六个一等公民之一。**组件差异只准声明在这里**，
编排层禁止硬编码组件名（护栏 R-EVENT-1，ADR-007）。

本模块同时是 plan §4.1 要求的**运行时 SSOT**：
    - 供运行时调度消费（recon/arm/strike/assess/report 全部查此表）
    - 反向供静态校验消费（tools/architecture_validator.py ← validate_wiring()）
    —— 「一处定义、两处使用」，治愈宪法 C3 与 IA-3（组件键四份分散硬编码）。

声明式攻击矩阵（`config/components/<name>.yaml`）契约（新版 plan §4.3）：
    component_key:  str                     # C-NAME-1：与 strike/<dir>/ 语义一致
    id/labels:      str / list[str]         # 短名与多标签（IC-1）
    detection:      {path_patterns, body_markers, active_probes, min_confidence}
    recon_modules:  list[str]               # 专项侦察器 dotted path
    seed_sets / seed_suitable_for: list[str]# C-NAME-2
    preferred_attack_class: str             # 宪法 7B
    asr_prior:      float                   # 预算裁剪排序依据
    strike_modules: list[str]
    assess:         {t0_check, rubric}
    report_builder / poc_template: str
    owasp / neighbors: list[str]            # 组合体推断
    cleanup:        list[str]               # I13：未声明 cleanup 的副作用步禁止执行

设计原则:
    1. 零行为变更：注册表为空/缺失时，所有查询返回空结果，调用方按既有逻辑运行
    2. 只读声明：本模块不执行任何攻击逻辑，只做查表
    3. 零依赖：仅标准库 + pyyaml + pydantic（NEG-4）
    4. IA-6：未知组件键一律返回 None，禁止崩溃

Usage:
    from core.registry import get_registry

    reg = get_registry()
    spec = reg.spec("mcp_tool_poisoning")   # 按组件键取
    comp = reg.get("mcp")                   # 按短名取原始 dict（兼容既有调用方）
    if spec:
        seeds = spec.seed_sets

Academic basis:
    - NIST SP 800-115 Sec4: Attack surface enumeration
"""

from __future__ import annotations

import importlib
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from core.contracts.component import ComponentSpec, WiringError

logger = logging.getLogger(__name__)

# 组件声明目录（声明式资产，蓝图 2.1 数据层）
COMPONENTS_DIR = Path(__file__).resolve().parent.parent / "config" / "components"


class ComponentRegistry:
    """组件注册表：加载 `config/components/*.yaml` 并提供查表接口。

    空注册表是合法状态（W0）——所有查询返回空/None，调用方回退到既有逻辑，
    保证 W0 阶段零行为回归。
    """

    def __init__(self, components_dir: Path | None = None) -> None:
        self.dir = Path(components_dir) if components_dir is not None else COMPONENTS_DIR
        self._components: dict[str, dict[str, Any]] = {}
        # component_key（如 mcp_tool_poisoning）→ 原始声明的二级索引
        self._by_key: dict[str, dict[str, Any]] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # 加载
    # ------------------------------------------------------------------
    def load(self, force: bool = False) -> dict[str, dict[str, Any]]:
        """加载全部组件声明；目录缺失或 YAML 空时不抛异常（降级为空注册表）。"""
        if self._loaded and not force:
            return self._components
        self._components = {}
        self._by_key = {}
        if not self.dir.exists():
            logger.debug("[Registry] 组件目录不存在，使用空注册表: %s", self.dir)
            self._loaded = True
            return self._components
        try:
            import yaml
        except ImportError:  # pyyaml 缺失时降级为空注册表（不阻断主链路）
            logger.warning("[Registry] pyyaml 不可用，使用空注册表")
            self._loaded = True
            return self._components
        for path in sorted(self.dir.glob("*.yaml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                if not isinstance(data, dict):
                    continue
                name = str(data.get("id") or path.stem)
                self._components[name] = data
                # 组件键二级索引（plan §4.1：component_key 为运行时调度主键）
                ck = str(data.get("component_key") or "")
                if ck:
                    self._by_key[ck] = data
            except Exception as e:  # 单个组件文件损坏不影响其他组件
                logger.warning("[Registry] 组件声明加载失败 %s: %s", path.name, e)
        self._loaded = True
        logger.debug("[Registry] 已加载 %d 个组件声明", len(self._components))
        return self._components

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def get(self, name: str) -> dict[str, Any] | None:
        """按组件名取声明；不存在返回 None（调用方回退既有逻辑）。"""
        self.load()
        return self._components.get(name)

    def names(self) -> list[str]:
        """已注册组件名列表。"""
        self.load()
        return list(self._components.keys())

    def by_label(self, label: str) -> list[dict[str, Any]]:
        """按标签反查组件（IC-1：一个标签可命中多个组件）。"""
        self.load()
        return [c for c in self._components.values() if label in (c.get("labels") or [])]

    def resolve(self, label: str) -> list[str]:
        """按标签解析组件名列表。"""
        return [str(c.get("id") or "") for c in self.by_label(label)]

    def get_field(self, name: str, field: str, default: Any = None) -> Any:
        """取组件声明的单个字段（安全缺省）。"""
        comp = self.get(name)
        if not comp:
            return default
        return comp.get(field, default)

    @property
    def is_empty(self) -> bool:
        """注册表是否为空（W4 前为 True，调用方据此走既有逻辑）。"""
        self.load()
        return not self._components

    # ------------------------------------------------------------------
    # 强类型视图（plan Wave 1：ComponentSpec 运行时 SSOT）
    # ------------------------------------------------------------------
    def spec(self, key_or_id: str) -> ComponentSpec | None:
        """按组件键（`mcp_tool_poisoning`）或短名（`mcp`）取强类型规格。

        IA-6：未知键返回 None，禁止崩溃。
        """
        self.load()
        raw = self._components.get(key_or_id)
        if raw is None:
            raw = self._by_key.get(key_or_id)
        if raw is None:
            return None
        try:
            return ComponentSpec.from_yaml(raw, fallback_id=str(raw.get("id") or ""))
        except Exception as e:  # 单个组件声明不合法不得拖垮全表
            logger.warning("[Registry] 组件声明不合法 %s: %s", key_or_id, e)
            return None

    def specs(self) -> list[ComponentSpec]:
        """全部组件的强类型规格列表（顺序 = YAML 文件名升序，保证可复现）。"""
        self.load()
        out: list[ComponentSpec] = []
        for raw in self._components.values():
            s = ComponentSpec.from_yaml(raw, fallback_id=str(raw.get("id") or ""))
            out.append(s)
        return out

    def iter_all(self) -> Iterator[ComponentSpec]:
        """迭代器形式，供大批量遍历（返回规格而非原始 dict）。"""
        yield from self.specs()

    def keys(self) -> list[str]:
        """全部**组件键**（plan §2.1 的 10 类），与短名列表 `names()` 区分。"""
        self.load()
        out: list[str] = []
        for raw in self._components.values():
            k = str(raw.get("component_key") or raw.get("id") or "")
            if k and k not in out:
                out.append(k)
        return out

    def by_neighbor(self, component_key: str) -> list[ComponentSpec]:
        """组合体推断：返回与该组件常共存的全部组件规格。"""
        spec = self.spec(component_key)
        if spec is None:
            return []
        out: list[ComponentSpec] = []
        for nb in spec.neighbors:
            s = self.spec(nb)
            if s is not None and s.component_key not in [x.component_key for x in out]:
                out.append(s)
        return out

    def for_seed_component(self, suitable_for: str) -> list[ComponentSpec]:
        """C-NAME-2：按种子 frontmatter 的 `suitable_for` 反查组件规格。"""
        return [s for s in self.specs() if suitable_for in s.seed_suitable_for]

    # ------------------------------------------------------------------
    # 接线校验（一处定义两处用：反向供 tools/architecture_validator.py 消费）
    # ------------------------------------------------------------------
    def validate_wiring(self, *, strict: bool = False) -> list[WiringError]:
        """校验每个组件声明的 recon/strike/assess/report 落点是否真实存在。

        Args:
            strict: True 时把「模块不存在」也升级为 blocking。

        Returns:
            WiringError 列表；空列表 = 接线完整。
        """
        errors: list[WiringError] = []
        for spec in self.specs():
            key = spec.component_key
            if not key:
                errors.append(
                    WiringError(component_key=str(spec.id), layer="schema", detail="缺少 component_key", severity="blocking")
                )
                continue

            # recon 层
            if not spec.recon_module_list():
                errors.append(
                    WiringError(component_key=key, layer="recon", detail="未声明任何 recon_modules", severity="warning")
                )
            for dotted in spec.recon_module_list():
                if not _module_exists(dotted):
                    errors.append(
                        WiringError(
                            component_key=key,
                            layer="recon",
                            detail=f"recon 模块不存在: {dotted}",
                            severity="blocking" if strict else "warning",
                        )
                    )

            # strike 层（侦察级组件 supply_chain 允许为空）
            for dotted in spec.strike_modules:
                if not _module_exists(dotted):
                    errors.append(
                        WiringError(
                            component_key=key,
                            layer="strike",
                            detail=f"strike 模块不存在: {dotted}",
                            severity="blocking" if strict else "warning",
                        )
                    )

            # assess 层：T0 函数可调用性
            if spec.t0_check and not _dotted_attr_exists(spec.t0_check):
                errors.append(
                    WiringError(
                        component_key=key,
                        layer="assess",
                        detail=f"T0 检测函数不可解析: {spec.t0_check}",
                        severity="blocking" if strict else "warning",
                    )
                )
            if spec.rubric and not (Path(_project_root()) / spec.rubric).is_file():
                errors.append(
                    WiringError(
                        component_key=key, layer="assess", detail=f"rubric 文件不存在: {spec.rubric}", severity="warning"
                    )
                )

            # report 层
            if spec.report_builder and not _dotted_attr_exists(spec.report_builder):
                errors.append(
                    WiringError(
                        component_key=key,
                        layer="report",
                        detail=f"report_builder 不可解析: {spec.report_builder}",
                        severity="warning",
                    )
                )

            # 种子集目录存在性（glob 取其目录部分再判存在）
            for seed_dir in spec.seed_sets:
                p = Path(_project_root()) / _seed_dir_of(seed_dir)
                if not p.exists():
                    errors.append(
                        WiringError(
                            component_key=key, layer="seeds", detail=f"种子目录不存在: {seed_dir}", severity="warning"
                        )
                    )
        return errors


# ---------------------------------------------------------------------------
# 内部工具（零攻击逻辑，仅反射查表）
# ---------------------------------------------------------------------------


@lru_cache(maxsize=256)
def _module_exists(dotted: str) -> bool:
    """dotted 模块是否可导入（结果缓存，避免校验阶段重复 IO）。"""
    if not dotted:
        return False
    try:
        importlib.import_module(dotted)
        return True
    except Exception:
        return False


def _seed_dir_of(seed_path: str) -> str:
    """种子声明可能是目录（`data/seeds/mcp/`）或 glob（`data/seeds/mcp/*`），统一取目录部分。"""
    cleaned = seed_path.rstrip("/")
    if cleaned.endswith("*"):
        cleaned = cleaned.rstrip("*").rstrip("/")
    return cleaned or seed_path


@lru_cache(maxsize=256)
def _dotted_attr_exists(dotted: str) -> bool:
    """`pkg.mod:func` 或 `pkg.mod.func` 形式的可调用对象是否存在。"""
    if not dotted:
        return False
    path = dotted.replace(":", ".")
    if "." not in path:
        return False
    mod_name, _, attr = path.rpartition(".")
    try:
        mod = importlib.import_module(mod_name)
        return hasattr(mod, attr)
    except Exception:
        return False


@lru_cache(maxsize=1)
def _project_root() -> str:
    return str(Path(__file__).resolve().parent.parent)


@lru_cache(maxsize=1)
def get_registry(components_dir: Path | None = None) -> ComponentRegistry:
    """获取全局注册表单例（W0：通常为空，不产生任何行为变化）。"""
    return ComponentRegistry(components_dir)
