"""Architecture Compliance Validator - 组件感知流水线架构合规验证器

验证当前代码是否完全遵循 "侦察驱动 → 组件感知 → 自动适配 → 专项攻击 → 专项评分 → 专项报告" 架构。

验证维度:
    1. Phase Boundary Contracts (阶段边界契约) - 阶段间数据传递是否完整
    2. Component Type Propagation (组件类型传播) - component_type 是否全链路一致
    3. Module Routing Integrity (模块路由完整性) - 组件子模块是否被正确调用
    4. Metadata Continuity (元数据连续性) - attack_results metadata 是否在阶段间保持

Usage:
    python -m tools.adapter_validator --mode=static    # 静态分析
    python -m tools.architecture_validator --mode=runtime   # 运行时追踪
    python -m tools.architecture_validator --mode=full      # 全量验证
"""

from __future__ import annotations

import ast
import logging
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# =============================================================================
# Architecture Specification (组件感知流水线架构规范)
# =============================================================================

# 支持的组件类型及其 SSOT 注册名
SUPPORTED_COMPONENT_TYPES: list[str] = [
    "mcp_tool_poisoning",
    "a2a_agent_integrity",
    "model_behavior_shift",
    "rag_pipeline",
    "session_memory",
    "web_api",
]

# 阶段边界契约定义: 每个阶段输出到 ctx 的字段
PHASE_OUTPUT_CONTRACTS: dict[str, dict[str, type | tuple[type, ...]]] = {
    "recon": {
        "service_profile": dict,
        "parsed_request": object,  # ParsedBurpRequest
        "mcpsec_surface": dict,
        "mcpsec_scan_results": dict,
        "a2a_inventory": dict,
        "a2a_topology": dict,
        "a2a_defense_profile": dict,
        "a2a_attack_plan": dict,
    },
    "arm": {
        "seeds": list,
        "techniques": list,
        "converter_map": dict,
        "attack_plan": object,  # AttackSurfaceMapper plan
    },
    "strike": {
        "attack_results": dict,
        "advanced_attack_results": dict,
    },
    "assess": {
        "asr_per_technique": dict,
        "overall_asr": float,
        "wilson_ci": tuple,
        "dual_judge_stats": dict,
    },
    "report": {
        # Report 阶段从 evidence 和 ctx 读取
    },
}

# =============================================================================
# 组件接线映射 —— 唯一来源：core/registry.py → config/components/*.yaml
# =============================================================================
# plan Wave 1.8：本文件此前把「组件键 + recon/strike/assess/report 四层模块映射」
# 硬编码成 4 份常量，与 core/phases/_component_bridge.py、assess/component_router.py、
# report/component_reports.py 各持一份 —— 典型 C3 / IA-3 违例（加一个组件要改 4 处）。
# 现统一从 ComponentRegistry 读取；注册表为空时回落到下面的历史兜底，保证向后兼容。

_FALLBACK_RECON_MODULES: dict[str, list[str]] = {
    "mcp_tool_poisoning": ["recon.mcp.schema_extractor"],
    "a2a_agent_integrity": ["recon.a2a.discoverer", "recon.a2a.topology"],
    "rag_pipeline": ["recon.rag.metadata_parser", "recon.rag.pipeline_probe"],
    "model_behavior_shift": ["recon.model.api_classifier", "recon.model.prompt_injector"],
    "session_memory": [],
    "web_api": ["recon.api.auth_detector", "recon.api.openapi_discoverer"],
}

_FALLBACK_STRIKE_MODULES: dict[str, list[str]] = {
    "mcp_tool_poisoning": ["strike.mcp.malicious_server", "strike.mcp.orchestrator"],
    "a2a_agent_integrity": ["strike.a2a.card_spoofer", "strike.a2a.rogue_registrar", "strike.a2a.workflow_attacker"],
    "rag_pipeline": ["strike.rag.data_poisoning", "strike.rag.kb_injector", "strike.rag.vector_db_poisoner"],
    "model_behavior_shift": ["strike.model.backdoor", "strike.model.filter_bypass", "strike.model.multimodal"],
    "session_memory": ["strike.memory.memory_injector", "strike.memory.memory_reader"],
    "web_api": ["strike.web.attacks", "strike.web.http_engine"],
}


def _registry() -> Any:
    """惰性获取 ComponentRegistry；不可用时返回 None（IA-6：静态校验不得因配置缺失崩溃）。"""
    try:
        from core.registry import get_registry

        return get_registry()
    except Exception as e:
        logger.warning("[ArchValidator] ComponentRegistry 不可用，回落到内置组件清单: %s", e)
        return None


def supported_component_types() -> list[str]:
    """支持的组件键 —— 来自注册表；空表时回落历史清单。"""
    reg = _registry()
    if reg is not None and not reg.is_empty:
        return reg.keys()
    return list(SUPPORTED_COMPONENT_TYPES)


def component_recon_modules(component_type: str) -> list[str]:
    reg = _registry()
    if reg is not None:
        spec = reg.spec(component_type)
        if spec is not None:
            return spec.recon_module_list()
    return _FALLBACK_RECON_MODULES.get(component_type, [])


def component_strike_modules(component_type: str) -> list[str]:
    reg = _registry()
    if reg is not None:
        spec = reg.spec(component_type)
        if spec is not None:
            return list(spec.strike_modules)
    return _FALLBACK_STRIKE_MODULES.get(component_type, [])


def component_assess_modules(component_type: str) -> list[str]:
    reg = _registry()
    if reg is not None:
        spec = reg.spec(component_type)
        if spec is not None and spec.t0_check:
            return [spec.t0_check.replace(":", ".")]
    return [f"assess.component_scorers.t0_{component_type}_check"]


def component_report_modules(component_type: str) -> list[str]:
    reg = _registry()
    if reg is not None:
        spec = reg.spec(component_type)
        if spec is not None and spec.report_builder:
            return [spec.report_builder.replace(":", ".")]
    return [f"report.component_reports._build_{component_type}_sections"]


# =============================================================================
# Validation Result Types
# =============================================================================


class Severity(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    BLOCKING = "BLOCKING"


@dataclass
class ValidationFinding:
    """单个验证发现"""

    severity: Severity
    category: str  # e.g., "phase_boundary", "component_propagation", "module_routing"
    message: str
    location: str = ""
    suggestion: str = ""


@dataclass
class ValidationReport:
    """完整验证报告"""

    findings: list[ValidationFinding] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.PASS)

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def blockers(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.BLOCKING)

    def add(self, severity: Severity, category: str, message: str, location: str = "", suggestion: str = "") -> None:
        self.findings.append(ValidationFinding(severity, category, message, location, suggestion))

    def merge(self, other: ValidationReport) -> None:
        self.findings.extend(other.findings)

    def format_report(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("Architecture Compliance Validation Report")
        lines.append("=" * 70)
        lines.append(f"  PASS: {self.passed} | WARNING: {self.warnings} | BLOCKING: {self.blockers}")
        lines.append("")

        # Group by category
        categories: dict[str, list[ValidationFinding]] = {}
        for f in self.findings:
            categories.setdefault(f.category, []).append(f)

        for cat, items in categories.items():
            lines.append(f"[{cat.upper()}]")
            for item in items:
                icon = (
                    "PASS"
                    if item.severity == Severity.PASS
                    else "WARN"
                    if item.severity == Severity.WARNING
                    else "BLOCK"
                )
                loc = f" @ {item.location}" if item.location else ""
                lines.append(f"  [{icon}] {item.message}{loc}")
                if item.suggestion:
                    lines.append(f"        Suggestion: {item.suggestion}")
            lines.append("")

        return "\n".join(lines)


# =============================================================================
# Validator 1: Static Code Analysis (静态代码分析)
# =============================================================================


class StaticAnalyzer:
    """静态分析器: 验证代码结构是否符合架构规范"""

    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.report = ValidationReport()

    def analyze(self) -> ValidationReport:
        """执行全量静态分析"""
        self._validate_phase_boundary_contracts()
        self._validate_component_type_propagation()
        self._validate_component_wiring()
        self._validate_module_routing()
        self._validate_metadata_continuity()
        self._validate_bridge_integration()
        return self.report

    def _validate_phase_boundary_contracts(self) -> None:
        """验证阶段边界契约: 各阶段是否正确输出到 ctx"""
        phase_files = {
            "recon": self.root_dir / "core" / "phases" / "recon.py",
            "arm": self.root_dir / "core" / "phases" / "arm.py",
            "strike": self.root_dir / "core" / "phases" / "strike.py",
            "assess": self.root_dir / "core" / "phases" / "assess.py",
            "report": self.root_dir / "core" / "phases" / "report.py",
        }

        for phase_name, filepath in phase_files.items():
            if not filepath.exists():
                self.report.add(Severity.BLOCKING, "phase_boundary", f"Phase file missing: {filepath}")
                continue

            source = filepath.read_text(encoding="utf-8")
            ast.parse(source)

            # Check for ctx assignments that match contract
            # Supports: ctx.attr = ..., ctx.attr["key"] = ..., ctx.attr += ...
            expected_outputs = PHASE_OUTPUT_CONTRACTS.get(phase_name, {})
            for attr_name in expected_outputs:
                # Pattern matches:
                #   ctx.attr = ...      (direct assignment)
                #   ctx.attr += ...     (augmented assignment)
                #   ctx.attr["key"] = ... (dict item assignment)
                #   ctx.attr[0] = ...   (list item assignment)
                pattern = rf"\.{attr_name}\s*(?:\[[^\]]*\])?\s*(?:\+|-|\*|/)?="
                if re.search(pattern, source):
                    self.report.add(
                        Severity.PASS,
                        "phase_boundary",
                        f"Phase '{phase_name}' outputs ctx.{attr_name}",
                        location=str(filepath),
                    )
                else:
                    self.report.add(
                        Severity.WARNING,
                        "phase_boundary",
                        f"Phase '{phase_name}' may not output ctx.{attr_name}",
                        location=str(filepath),
                        suggestion=f"Ensure {phase_name} phase writes results to ctx.{attr_name}",
                    )

    def _validate_component_type_propagation(self) -> None:
        """验证组件类型传播: component_type 是否在攻击结果中保持一致"""

        # Check _component_bridge.py exists and has stamp function
        bridge_file = self.root_dir / "core" / "phases" / "_component_bridge.py"
        if bridge_file.exists():
            source = bridge_file.read_text(encoding="utf-8")
            if "stamp_component_metadata" in source or "stamp_results" in source:
                self.report.add(
                    Severity.PASS,
                    "component_propagation",
                    "Component bridge has stamp function",
                    location=str(bridge_file),
                )
            else:
                self.report.add(
                    Severity.BLOCKING,
                    "component_propagation",
                    "Component bridge missing stamp function",
                    location=str(bridge_file),
                )

            # Check inference methods
            if "_infer_component_from_text" in source:
                self.report.add(
                    Severity.PASS,
                    "component_propagation",
                    "Bridge has text-based component inference",
                    location=str(bridge_file),
                )
            if "_infer_component_from_category" in source:
                self.report.add(
                    Severity.PASS,
                    "component_propagation",
                    "Bridge has category-based component inference",
                    location=str(bridge_file),
                )
        else:
            self.report.add(Severity.BLOCKING, "component_propagation", "Component bridge module missing")

        # Check component_router.py exists
        router_file = self.root_dir / "assess" / "component_router.py"
        if router_file.exists():
            source = router_file.read_text(encoding="utf-8")
            if "classify_component_from_result" in source:
                self.report.add(
                    Severity.PASS,
                    "component_propagation",
                    "Component router has classification function",
                    location=str(router_file),
                )
            if "run_component_t0" in source:
                self.report.add(
                    Severity.PASS, "component_propagation", "Component router has T0 routing", location=str(router_file)
                )
        else:
            self.report.add(Severity.BLOCKING, "component_propagation", "Component router module missing")

    def _validate_component_wiring(self) -> None:
        """验证组件接线（plan Wave 1.8）：ComponentRegistry.validate_wiring() 的静态入口。

        这一项是「一处定义两处用」的反向消费者：运行时调度与静态体检共用同一份
        `config/components/*.yaml` 声明，任何一侧的漂移都会在此暴露。
        """
        reg = _registry()
        if reg is None:
            self.report.add(
                Severity.WARNING,
                "component_wiring",
                "ComponentRegistry 不可用，跳过组件接线校验",
            )
            return

        if reg.is_empty:
            self.report.add(
                Severity.WARNING,
                "component_wiring",
                "组件注册表为空（config/components/ 无声明），无法校验接线",
            )
            return

        errors = reg.validate_wiring()
        if not errors:
            self.report.add(
                Severity.PASS,
                "component_wiring",
                f"全部 {len(reg.keys())} 个组件接线完整（recon/strike/assess/report/seeds）",
            )
            return

        for err in errors:
            self.report.add(
                Severity.BLOCKING if err.severity == "blocking" else Severity.WARNING,
                "component_wiring",
                str(err),
                suggestion="修正 config/components/<id>.yaml 中的对应声明",
            )

    def _validate_module_routing(self) -> None:
        """验证模块路由: 各组件类型是否有对应的 recon/strike/assess/report 模块"""

        for component_type in supported_component_types():
            # Check recon modules
            for mod_path in component_recon_modules(component_type):
                mod_file = self.root_dir / (mod_path.replace(".", "/") + ".py")
                if mod_file.exists():
                    self.report.add(
                        Severity.PASS, "module_routing", f"Recon module exists for {component_type}: {mod_path}"
                    )
                else:
                    self.report.add(
                        Severity.WARNING, "module_routing", f"Recon module missing for {component_type}: {mod_path}"
                    )

            # Check strike modules
            for mod_path in component_strike_modules(component_type):
                mod_file = self.root_dir / (mod_path.replace(".", "/") + ".py")
                if mod_file.exists():
                    self.report.add(
                        Severity.PASS, "module_routing", f"Strike module exists for {component_type}: {mod_path}"
                    )
                else:
                    self.report.add(
                        Severity.WARNING, "module_routing", f"Strike module missing for {component_type}: {mod_path}"
                    )

            # Check report builders
            for builder_path in component_report_modules(component_type):
                # Builder is a function in component_reports.py
                builder_file = self.root_dir / "report" / "component_reports.py"
                if builder_file.exists():
                    source = builder_file.read_text(encoding="utf-8")
                    func_name = builder_path.split(".")[-1]
                    if func_name in source:
                        self.report.add(
                            Severity.PASS, "module_routing", f"Report builder exists for {component_type}: {func_name}"
                        )
                    else:
                        self.report.add(
                            Severity.WARNING,
                            "module_routing",
                            f"Report builder missing for {component_type}: {func_name}",
                        )

            # Check scorer T0 functions
            scorer_file = self.root_dir / "assess" / "component_scorers.py"
            if scorer_file.exists():
                source = scorer_file.read_text(encoding="utf-8")
                t0_func = f"t0_{component_type.replace('_poisoning', '').replace('_agent_integrity', '')}"
                if t0_func in source or f"t0_{component_type}" in source:
                    self.report.add(Severity.PASS, "module_routing", f"Scorer T0 function exists for {component_type}")
                else:
                    self.report.add(
                        Severity.WARNING, "module_routing", f"Scorer T0 function may be missing for {component_type}"
                    )

    def _validate_metadata_continuity(self) -> None:
        """验证元数据连续性: attack_results metadata 是否在桥接和评分中保持"""

        # Check that score_pipeline reads metadata from attack_results
        score_file = self.root_dir / "assess" / "score_pipeline.py"
        if score_file.exists():
            source = score_file.read_text(encoding="utf-8")
            if "metadata" in source and "component_type" in source:
                self.report.add(
                    Severity.PASS, "metadata_continuity", "Score pipeline reads component_type from metadata"
                )
            elif "metadata" in source:
                self.report.add(Severity.PASS, "metadata_continuity", "Score pipeline reads metadata from results")
            else:
                self.report.add(
                    Severity.WARNING, "metadata_continuity", "Score pipeline may not preserve component metadata"
                )

        # Check that evidence collector preserves metadata
        evidence_file = self.root_dir / "report" / "evidence.py"
        if evidence_file.exists():
            source = evidence_file.read_text(encoding="utf-8")
            if "metadata" in source:
                self.report.add(Severity.PASS, "metadata_continuity", "Evidence collector preserves metadata")
            else:
                self.report.add(Severity.WARNING, "metadata_continuity", "Evidence collector may not preserve metadata")

    def _validate_bridge_integration(self) -> None:
        """验证桥接集成: 组件桥接是否在正确位置被调用"""

        # Check strike.py calls bridge
        strike_file = self.root_dir / "core" / "phases" / "strike.py"
        if strike_file.exists():
            source = strike_file.read_text(encoding="utf-8")
            if "_component_bridge" in source or "stamp_component_metadata" in source:
                self.report.add(Severity.PASS, "bridge_integration", "Strike phase integrates component bridge")
            else:
                self.report.add(
                    Severity.WARNING,
                    "bridge_integration",
                    "Strike phase may not call component bridge",
                    suggestion="Call stamp_component_metadata in strike phase output",
                )

        # Check score_pipeline uses component_router
        score_file = self.root_dir / "assess" / "score_pipeline.py"
        if score_file.exists():
            source = score_file.read_text(encoding="utf-8")
            if "component_router" in source or "run_component_t0" in source:
                self.report.add(Severity.PASS, "bridge_integration", "Score pipeline uses component router")
            else:
                self.report.add(Severity.WARNING, "bridge_integration", "Score pipeline may not use component router")

        # Check report generator uses component_reports
        report_gen_file = self.root_dir / "report" / "generator.py"
        if report_gen_file.exists():
            source = report_gen_file.read_text(encoding="utf-8")
            if "component_reports" in source or "component_sections" in source:
                self.report.add(Severity.PASS, "bridge_integration", "Report generator uses component reports")
            else:
                self.report.add(
                    Severity.WARNING, "bridge_integration", "Report generator may not use component reports"
                )


# =============================================================================
# Validator 2: Runtime Data Flow Tracer (运行时数据流追踪)
# =============================================================================


class RuntimeTracer:
    """运行时追踪器: 在流水线执行时追踪数据流"""

    def __init__(self):
        self.report = ValidationReport()
        self.phase_snapshots: dict[str, dict[str, Any]] = {}

    def capture_phase_output(self, ctx: Any, phase_name: str) -> None:
        """捕获阶段输出快照"""
        snapshot = {}

        if phase_name == "recon":
            for attr in ["service_profile", "mcpsec_surface", "a2a_inventory"]:
                val = getattr(ctx, attr, None)
                if val:
                    snapshot[attr] = type(val).__name__

        elif phase_name == "arm":
            for attr in ["seeds", "techniques", "converter_map"]:
                val = getattr(ctx, attr, None)
                if val is not None:
                    snapshot[attr] = f"{type(val).__name__}(len={len(val)})"

        elif phase_name == "strike":
            val = getattr(ctx, "attack_results", {})
            if val:
                total = sum(len(v) for v in val.values())
                snapshot["attack_results"] = f"dict({len(val)} techniques, {total} results)"

        elif phase_name == "assess":
            for attr in ["overall_asr", "asr_per_technique", "dual_judge_stats"]:
                val = getattr(ctx, attr, None)
                if val is not None:
                    snapshot[attr] = str(val)[:100]

        self.phase_snapshots[phase_name] = snapshot
        self.report.add(
            Severity.PASS, "runtime_trace", f"Phase '{phase_name}' output captured: {list(snapshot.keys())}"
        )

    def verify_component_propagation(self, ctx: Any) -> None:
        """验证组件类型在攻击结果中的传播"""
        attack_results = getattr(ctx, "attack_results", {})
        if not attack_results:
            return

        stamped_count = 0
        total_count = 0

        for technique, results in attack_results.items():
            for result in results:
                total_count += 1
                meta = getattr(result, "metadata", None)
                if isinstance(meta, dict) and meta.get("component_type"):
                    stamped_count += 1

        if total_count > 0:
            ratio = stamped_count / total_count * 100
            if ratio >= 80:
                self.report.add(
                    Severity.PASS,
                    "runtime_trace",
                    f"Component type propagation: {stamped_count}/{total_count} ({ratio:.0f}%)",
                )
            elif ratio >= 50:
                self.report.add(
                    Severity.WARNING,
                    "runtime_trace",
                    f"Component type propagation incomplete: {stamped_count}/{total_count} ({ratio:.0f}%)",
                )
            else:
                self.report.add(
                    Severity.BLOCKING,
                    "runtime_trace",
                    f"Component type propagation failed: {stamped_count}/{total_count} ({ratio:.0f}%)",
                    suggestion="Ensure _component_bridge.stamp_component_metadata is called",
                )


# =============================================================================
# Validator 3: Contract-Based Boundary Checker (基于契约的边界检查器)
# =============================================================================


class ContractChecker:
    """契约检查器: 验证每个阶段是否满足输入/输出契约"""

    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.report = ValidationReport()

    def check_all(self) -> ValidationReport:
        """执行全量契约检查"""
        self._check_recon_to_arm_contract()
        self._check_arm_to_strike_contract()
        self._check_strike_to_assess_contract()
        self._check_assess_to_report_contract()
        self._check_cross_cutting_concerns()
        return self.report

    def _check_recon_to_arm_contract(self) -> None:
        """Recon → ARM 契约检查: 侦察结果必须正确传递给武器化阶段"""

        arm_file = self.root_dir / "core" / "phases" / "arm.py"
        if not arm_file.exists():
            return

        source = arm_file.read_text(encoding="utf-8")

        # Check: arm reads ctx.service_profile
        if "ctx.service_profile" in source:
            self.report.add(
                Severity.PASS, "phase_contract", "ARM reads ctx.service_profile (RAG KB map, auth type, etc.)"
            )
        else:
            self.report.add(Severity.WARNING, "phase_contract", "ARM may not read ctx.service_profile")

        # Check: arm reads ctx.mcpsec_surface
        if "ctx.mcpsec_surface" in source:
            self.report.add(Severity.PASS, "phase_contract", "ARM reads ctx.mcpsec_surface (MCP tools)")
        else:
            self.report.add(Severity.WARNING, "phase_contract", "ARM may not read ctx.mcpsec_surface")

        # Check: arm reads ctx.adaptive_probe_ctx
        if "ctx.adaptive_probe_ctx" in source or "adaptive_probe_ctx" in source:
            self.report.add(Severity.PASS, "phase_contract", "ARM reads adaptive probe budget")
        else:
            self.report.add(Severity.WARNING, "phase_contract", "ARM may not use adaptive probe budget")

    def _check_arm_to_strike_contract(self) -> None:
        """ARM → Strike 契约检查: 武器化输出必须正确传递给攻击阶段"""

        strike_file = self.root_dir / "core" / "phases" / "strike.py"
        if not strike_file.exists():
            return

        source = strike_file.read_text(encoding="utf-8")

        # Check: strike uses ctx.seeds, ctx.techniques, ctx.converter_map
        contract_attrs = ["ctx.seeds", "ctx.techniques", "ctx.converter_map"]
        for attr in contract_attrs:
            if attr in source:
                self.report.add(Severity.PASS, "phase_contract", f"Strike reads {attr}")
            else:
                self.report.add(Severity.WARNING, "phase_contract", f"Strike may not read {attr}")

    def _check_strike_to_assess_contract(self) -> None:
        """Strike → Assess 契约检查: attack_results 必须正确传递给评分阶段"""

        assess_file = self.root_dir / "core" / "phases" / "assess.py"
        if not assess_file.exists():
            return

        source = assess_file.read_text(encoding="utf-8")

        # Check: assess reads ctx.attack_results
        if "ctx.attack_results" in source:
            self.report.add(Severity.PASS, "phase_contract", "Assess reads ctx.attack_results")
        else:
            self.report.add(Severity.BLOCKING, "phase_contract", "Assess does NOT read ctx.attack_results")

        # Check: assess calls precompute_outcomes_async
        if "precompute_outcomes_async" in source:
            self.report.add(Severity.PASS, "phase_contract", "Assess calls precompute_outcomes_async for scoring")
        else:
            self.report.add(Severity.WARNING, "phase_contract", "Assess may not call precompute_outcomes_async")

    def _check_assess_to_report_contract(self) -> None:
        """Assess → Report 契约检查: 评分结果必须正确传递给报告阶段"""

        report_file = self.root_dir / "core" / "phases" / "report.py"
        if not report_file.exists():
            return

        source = report_file.read_text(encoding="utf-8")

        # Check: report reads ctx.overall_asr, ctx.asr_per_technique
        contract_attrs = ["ctx.overall_asr", "ctx.asr_per_technique", "ctx.dual_judge_stats"]
        for attr in contract_attrs:
            if attr in source:
                self.report.add(Severity.PASS, "phase_contract", f"Report reads {attr}")
            else:
                self.report.add(Severity.WARNING, "phase_contract", f"Report may not read {attr}")

    def _check_cross_cutting_concerns(self) -> None:
        """横切关注点检查: 通用关注点"""

        # Check: orchestration_log exists in all phases
        phase_files = [
            self.root_dir / "core" / "phases" / "recon.py",
            self.root_dir / "core" / "phases" / "arm.py",
            self.root_dir / "core" / "phases" / "strike.py",
            self.root_dir / "core" / "phases" / "assess.py",
            self.root_dir / "core" / "phases" / "report.py",
        ]

        for pf in phase_files:
            if pf.exists():
                source = pf.read_text(encoding="utf-8")
                if "orchestration_log" in source:
                    self.report.add(Severity.PASS, "cross_cutting", f"{pf.stem} logs to orchestration_log")
                else:
                    self.report.add(Severity.WARNING, "cross_cutting", f"{pf.stem} does not log to orchestration_log")

        # Check: dataflow snapshot hooks exist
        for pf in phase_files:
            if pf.exists():
                source = pf.read_text(encoding="utf-8")
                if "snapshot_hook" in source:
                    self.report.add(Severity.PASS, "cross_cutting", f"{pf.stem} has dataflow snapshot hook")
                else:
                    self.report.add(Severity.WARNING, "cross_cutting", f"{pf.stem} missing dataflow snapshot hook")


# =============================================================================
# Main Entry Point
# =============================================================================


def run_validation(mode: str = "full", root_dir: Path | None = None) -> ValidationReport:
    """
    运行架构合规验证

    Args:
        mode: "static", "runtime", or "full"
        root_dir: 项目根目录

    Returns:
        ValidationReport 完整验证报告
    """
    if root_dir is None:
        root_dir = Path(__file__).resolve().parent.parent

    combined = ValidationReport()

    if mode in ("static", "full"):
        logger.info("Running static analysis...")
        static_analyzer = StaticAnalyzer(root_dir)
        static_report = static_analyzer.analyze()
        combined.merge(static_report)

    if mode in ("contract", "full"):
        logger.info("Running contract checks...")
        contract_checker = ContractChecker(root_dir)
        contract_report = contract_checker.check_all()
        combined.merge(contract_report)

    return combined


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    mode = sys.argv[1] if len(sys.argv) > 1 else "full"
    report = run_validation(mode=mode)
    print(report.format_report())

    # Exit with appropriate code
    sys.exit(1 if report.blockers > 0 else 0)
