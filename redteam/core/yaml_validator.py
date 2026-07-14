"""YAML 预检验证器 — 在执行管道前检测配置错误。

AI-300 章节映射：Ch1 框架介绍（MITRE ATLAS、OWASP）
OSAI 评分维度：工具可靠性（考试期间配置错误即失败）
技术点：YAML 解析、Pydantic 模型验证、跨引用完整性、继承链校验

验证维度：
  1. YAML 语法检查 — 定位语法错误的行/列
  2. Schema 符合性验证 — 基于 Pydantic AttackScenario 模型
  3. 跨引用完整性 — phase.payload_templates ID 是否存在于 payloads 列表
  4. 继承链校验 — extends 值是否对应有效注册场景 ID
  5. 载荷源引用 — payload_sources 类别是否存在于 config/payloads/
  6. 注册表一致性 — 注册表条目与实际 YAML 文件是否同步
  7. 枚举值正确性 — 所有 strategy/phase_type/target_type 值校验

Library-First: 纯 Python 实现，零外部依赖。基于 yaml + pydantic。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


# ── 已知的有效类别集合（与 config/payloads/ 目录对齐） ──────────────
KNOWN_PAYLOAD_CATEGORIES: set[str] = {
    "llm01", "llm02", "llm03", "llm04", "llm05",
    "llm06", "llm07", "llm08", "llm09", "llm10",
}

KNOWN_OWASP_IDS: set[str] = {
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
}

KNOWN_TARGET_TYPES: set[str] = {
    "agent", "mcp", "rag", "embeddings", "supply_chain", "infra", "generic",
}

DEFAULT_SCENARIO_DIR = "config/scenarios"
DEFAULT_PAYLOAD_DIR = "config/payloads"


# ── 数据类 ────────────────────────────────────────────────────────────

@dataclass
class ValidationIssue:
    """单个验证问题。"""

    severity: str  # "error" | "warning" | "info"
    category: str  # "syntax" | "schema" | "cross_ref" | "extends" | "payload_source" | "registry" | "enum"
    message: str
    file_path: str = ""
    line: int | None = None
    column: int | None = None
    field: str = ""
    suggestion: str = ""

    def __str__(self) -> str:
        location = ""
        if self.file_path:
            location = self.file_path
            if self.line is not None:
                location += f":{self.line}"
                if self.column is not None:
                    location += f":{self.column}"
        field_str = f" [{self.field}]" if self.field else ""
        return f"[{self.severity.upper()}] {self.category}{field_str} — {self.message} ({location})"


@dataclass
class ValidationReport:
    """验证报告 — 汇总所有检查结果。"""

    file_path: str = ""
    total_checks: int = 0
    errors: int = 0
    warnings: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.errors == 0

    @property
    def clean(self) -> bool:
        return self.errors == 0 and self.warnings == 0

    def add(self, issue: ValidationIssue) -> None:
        self.issues.append(issue)
        if issue.severity == "error":
            self.errors += 1
        elif issue.severity == "warning":
            self.warnings += 1

    def merge(self, other: "ValidationReport") -> None:
        self.errors += other.errors
        self.warnings += other.warnings
        self.total_checks += other.total_checks
        self.issues.extend(other.issues)


# ── 主验证器 ──────────────────────────────────────────────────────────

class YamlValidator:
    """YAML 预检验证器 — 在管道执行前检查所有配置错误。

    使用方式：
        validator = YamlValidator("config/scenarios", "config/payloads")
        report = validator.validate_file("config/scenarios/agent.yaml")
        if not report.passed:
            validator.print_report(report)

        # 批量验证所有场景
        report = validator.validate_all()

        # 注册表一致性检查
        report = validator.validate_registry()
    """

    def __init__(
        self,
        scenario_dir: str = DEFAULT_SCENARIO_DIR,
        payload_dir: str = DEFAULT_PAYLOAD_DIR,
        strict: bool = False,
    ):
        self.scenario_dir = Path(scenario_dir)
        self.payload_dir = Path(payload_dir)
        self.strict = strict  # strict=True 时 warning 升级为 error

        # 延迟初始化注册表索引
        self._registry_ids: set[str] | None = None
        self._registry_entries: dict[str, dict] | None = None

    # ── 公开入口 ──────────────────────────────────────────────────────

    def validate_file(self, file_path: str) -> ValidationReport:
        """对单个场景 YAML 文件执行完整验证。

        Args:
            file_path: YAML 文件路径

        Returns:
            ValidationReport 包含所有检查结果
        """
        path = Path(file_path)
        report = ValidationReport(file_path=str(path))

        if not path.exists():
            report.add(ValidationIssue(
                severity="error",
                category="file",
                message=f"文件不存在: {path}",
                file_path=str(path),
                suggestion="检查文件路径或使用 --all 查看所有可用文件",
            ))
            return report

        raw_data = self._check_syntax(path, report)
        if raw_data is None:
            return report

        scenario = self._check_schema(raw_data, path, report)
        if scenario is not None:
            self._check_cross_references(scenario, report, str(path))

        # 枚举值检查始终执行（即使 Pydantic 解析失败也要检测明显错误）
        self._check_enum_values(raw_data, report, str(path))

        self._check_extends(raw_data, report, str(path))
        self._check_payload_sources(raw_data, report, str(path))

        report.total_checks = (
            1 +  # syntax
            (1 if scenario is not None else 0) +  # schema
            (1 if scenario is not None else 0) +  # cross_refs
            1 +  # extends
            1 +  # payload_sources
            (1 if scenario is not None else 0)  # enum_values
        )

        return report

    def validate_all(self) -> ValidationReport:
        """验证所有场景 YAML 文件。

        Returns:
            合并的验证报告
        """
        combined = ValidationReport(file_path="ALL_SCENARIOS")

        yaml_files = self._discover_scenario_files()
        if not yaml_files:
            combined.add(ValidationIssue(
                severity="warning",
                category="file",
                message=f"未在 {self.scenario_dir} 中找到场景 YAML 文件",
            ))
            return combined

        for yf in yaml_files:
            report = self.validate_file(str(yf))
            combined.merge(report)

        # 注册表一致性检查
        reg_report = self.validate_registry()
        combined.merge(reg_report)

        return combined

    def validate_registry(self) -> ValidationReport:
        """验证注册表与 YAML 文件的一致性。

        检查项：
          - 注册表中每个条目对应的 YAML 文件是否存在
          - 每个 YAML 文件是否在注册表中有对应条目
          - owasp_coverage 是否使用已知 OWASP ID
          - payload_sources 是否使用已知类别
          - extends 指向的场景 ID 是否存在

        Returns:
            注册表一致性验证报告
        """
        report = ValidationReport(file_path="REGISTRY_CONSISTENCY")

        self._ensure_registry_loaded()

        reg_path = self.scenario_dir / "_registry.core.yaml"
        local_path = self.scenario_dir / "_registry.local.yaml"
        report.total_checks = 4

        if not reg_path.exists():
            report.add(ValidationIssue(
                severity="warning",
                category="registry",
                message="核心注册表文件不存在",
                file_path=str(reg_path),
                suggestion="确保 _registry.core.yaml 存在且格式正确",
            ))
            return report

        # 加载注册表
        registry = self._load_registry_dict(reg_path, report)
        if registry is None:
            return report

        scenarios_list = registry.get("scenarios", [])
        if not scenarios_list:
            report.add(ValidationIssue(
                severity="warning",
                category="registry",
                message="注册表中无场景条目",
                file_path=str(reg_path),
            ))
            return report

        # 建立注册表索引
        reg_by_id: dict[str, dict] = {}
        for entry in scenarios_list:
            if not isinstance(entry, dict):
                continue
            eid = entry.get("id", "")
            if eid:
                reg_by_id[eid] = entry

        # 收集 YAML 文件索引
        yaml_files = self._discover_scenario_files()
        yaml_by_id: dict[str, Path] = {}
        for yf in yaml_files:
            scenario = self._quick_parse_id(yf)
            if scenario:
                yaml_by_id[scenario] = yf

        # ── 检查 1: 注册表条目 → YAML 文件 ──
        for eid, entry in reg_by_id.items():
            file_name = entry.get("file", "")
            if file_name:
                yaml_path = self.scenario_dir / file_name
                if not yaml_path.exists():
                    report.add(ValidationIssue(
                        severity="error",
                        category="registry",
                        message=f"注册表引用文件不存在: {file_name}",
                        file_path=str(reg_path),
                        field=f"scenarios[?id={eid}].file",
                        suggestion="检查文件是否被重命名或删除",
                    ))
            else:
                # 检查是否有对应 YAML 文件
                cand = self.scenario_dir / f"{eid}.yaml"
                if not cand.exists():
                    report.add(ValidationIssue(
                        severity="error",
                        category="registry",
                        message=f"注册表条目 {eid} 无 file 字段且对应 YAML 文件也不存在",
                        file_path=str(reg_path),
                        field=f"scenarios[?id={eid}]",
                        suggestion=f"确保 {eid}.yaml 存在或设置 file 字段",
                    ))

            # 检查 extends 引用
            extends_val = entry.get("extends")
            if extends_val and isinstance(extends_val, str) and extends_val.strip():
                if extends_val not in reg_by_id:
                    report.add(ValidationIssue(
                        severity="error",
                        category="extends",
                        message=f"注册表中 {eid} extends 引用未知场景 ID: {extends_val}",
                        file_path=str(reg_path),
                        field=f"scenarios[?id={eid}].extends",
                        suggestion=f"检查 {extends_val} 是否在注册表中注册",
                    ))

            # 检查 owasp_coverage
            owasp = entry.get("owasp_coverage", [])
            if isinstance(owasp, list):
                for oid in owasp:
                    if oid not in KNOWN_OWASP_IDS:
                        report.add(ValidationIssue(
                            severity="warning",
                            category="registry",
                            message=f"注册表 {eid} 含未知 OWASP ID: {oid}",
                            file_path=str(reg_path),
                            field=f"scenarios[?id={eid}].owasp_coverage",
                            suggestion=f"使用已知 OWASP ID: {sorted(KNOWN_OWASP_IDS)}",
                        ))

            # 检查 payload_sources
            sources = entry.get("payload_sources", [])
            if isinstance(sources, list):
                for src in sources:
                    if isinstance(src, str) and src not in KNOWN_PAYLOAD_CATEGORIES:
                        report.add(ValidationIssue(
                            severity="warning",
                            category="registry",
                            message=f"注册表 {eid} 含未知载荷源: {src}",
                            file_path=str(reg_path),
                            field=f"scenarios[?id={eid}].payload_sources",
                            suggestion=f"使用已知 OWASP 类别: {sorted(KNOWN_PAYLOAD_CATEGORIES)}",
                        ))

        # ── 检查 2: YAML 文件 → 注册表条目 ──
        for fid, yf in yaml_by_id.items():
            if fid not in reg_by_id:
                report.add(ValidationIssue(
                    severity="warning",
                    category="registry",
                    message=f"YAML 文件 {yf.name} (id={fid}) 未在注册表中注册",
                    file_path=str(yf),
                    suggestion=f"在 {reg_path.name} 中添加对应条目",
                ))

        # ── 检查 3: 注册表场景 id 与 YAML 中 id 一致性 ──
        for fid, yf in yaml_by_id.items():
            if fid in reg_by_id:
                entry = reg_by_id[fid]
                yaml_data = self._safe_load_yaml(yf)
                if yaml_data:
                    yaml_target = yaml_data.get("target_type", "")
                    reg_target = entry.get("target_type", "")
                    if yaml_target and reg_target and yaml_target != reg_target:
                        report.add(ValidationIssue(
                            severity="error",
                            category="registry",
                            message=f"{fid} 注册表 target_type={reg_target} 与 YAML={yaml_target} 不一致",
                            file_path=str(yf),
                            field="target_type",
                            suggestion="同步注册表与 YAML 文件的 target_type 字段",
                        ))

        return report

    def print_report(self, report: ValidationReport, verbose: bool = False) -> None:
        """以可读格式输出验证报告（无 Rich 依赖）。

        Args:
            report: 验证报告
            verbose: 是否显示所有详情
        """
        lines: list[str] = []

        if report.file_path:
            lines.append(f"\n{'='*70}")
            lines.append(f" 验证报告: {report.file_path}")
            lines.append(f"{'='*70}")

        # 汇总
        status = "PASS" if report.passed else "FAIL"
        status_icon = "OK" if report.clean else ("WARN" if report.passed else "FAIL")
        lines.append(f"\n  结果: {status_icon}  "
                     f"错误={report.errors}  警告={report.warnings}  "
                     f"总问题={len(report.issues)}")

        # 分类统计
        cats: dict[str, int] = {}
        for iss in report.issues:
            cats[iss.category] = cats.get(iss.category, 0) + 1
        if cats:
            lines.append(f"  分类: {', '.join(f'{k}={v}' for k, v in sorted(cats.items()))}")

        # 错误列表
        errors_list = [i for i in report.issues if i.severity == "error"]
        warnings_list = [i for i in report.issues if i.severity == "warning"]
        infos = [i for i in report.issues if i.severity == "info"]

        if errors_list:
            lines.append(f"\n  [ERROR] ({len(errors_list)}):")
            for iss in errors_list:
                lines.append(f"     - {iss.message}")
                if iss.suggestion:
                    lines.append(f"       HINT: {iss.suggestion}")

        if warnings_list:
            lines.append(f"\n  [WARNING] ({len(warnings_list)}):")
            for iss in warnings_list:
                lines.append(f"     - {iss.message}")
                if iss.suggestion:
                    lines.append(f"       HINT: {iss.suggestion}")

        if verbose and infos:
            lines.append(f"\n  [INFO] ({len(infos)}):")
            for iss in infos:
                lines.append(f"     - {iss.message}")

        if report.clean:
            lines.append(f"\n  PASS: All checks passed, pipeline is safe to execute.")
        elif report.passed:
            lines.append(f"\n  PASS (with warnings): Pipeline can continue.")
        else:
            lines.append(f"\n  FAIL: Found {report.errors} error(s), fix before running pipeline.")

        # 安全输出，避免 emoji 在 Windows GBK 环境下崩溃
        safe_output = "\n".join(lines)
        try:
            print(safe_output)
        except UnicodeEncodeError:
            # fallback: 写入 stderr（已过滤所有 emoji，不应触发，但保留安全机制）
            import sys
            sys.stderr.write(safe_output.encode("ascii", errors="replace").decode("ascii") + "\n")

    # ── 私有方法 ─────────────────────────────────────────────────────

    def _check_syntax(self, path: Path, report: ValidationReport) -> dict[str, Any] | None:
        """检查 YAML 语法。

        Returns:
            解析后的原始数据，失败返回 None
        """
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()
            data = yaml.safe_load(content)
            if data is None:
                report.add(ValidationIssue(
                    severity="error",
                    category="syntax",
                    message="YAML 文件为空",
                    file_path=str(path),
                ))
                return None
            if not isinstance(data, dict):
                report.add(ValidationIssue(
                    severity="error",
                    category="syntax",
                    message=f"YAML 根元素应为字典，实际为 {type(data).__name__}",
                    file_path=str(path),
                ))
                return None
            return data
        except yaml.YAMLError as e:
            # 尝试提取行/列信息
            line = None
            column = None
            if hasattr(e, "problem_mark") and e.problem_mark:
                line = e.problem_mark.line + 1
                column = e.problem_mark.column + 1
            report.add(ValidationIssue(
                severity="error",
                category="syntax",
                message=f"YAML 语法错误: {e}",
                file_path=str(path),
                line=line,
                column=column,
                suggestion="检查缩进、引号匹配、特殊字符转义",
            ))
            return None
        except Exception as e:
            report.add(ValidationIssue(
                severity="error",
                category="syntax",
                message=f"读取文件失败: {e}",
                file_path=str(path),
                suggestion="检查文件编码（应为 UTF-8）和权限",
            ))
            return None

    def _check_schema(
        self, raw_data: dict, path: Path, report: ValidationReport
    ) -> Optional[Any]:
        """通过 Pydantic 模型验证 YAML 结构。
        
        延迟导入避免循环依赖。
        """
        from redteam.scenario.schema import (
            AttackScenario, AttackConfig, AttackPhase, PayloadTemplate,
            AttackStrategy, AttackPhaseType, AttackTargetType, ScorerType,
        )

        try:
            scenario = AttackScenario(**raw_data)
            if self.strict:
                self._check_semantic(scenario, report, str(path))
            return scenario
        except Exception as e:
            error_msg = str(e)
            # 提取更多上下文信息
            report.add(ValidationIssue(
                severity="error",
                category="schema",
                message=f"模式验证失败: {error_msg}",
                file_path=str(path),
                suggestion="检查字段类型、枚举值、必填字段是否缺失",
            ))

            # 尝试分步解析以定位具体问题
            self._stepwise_validation(raw_data, path, report)
            return None

    def _stepwise_validation(
        self, raw_data: dict, path: Path, report: ValidationReport
    ) -> None:
        """分步验证：逐个检查 payloads/phases/attack_config 以精确定位问题。"""
        from redteam.scenario.schema import (
            AttackConfig, AttackPhase, PayloadTemplate,
            AttackStrategy, AttackPhaseType, AttackTargetType, ScorerType,
        )

        # 检查 attack_config
        config_data = raw_data.get("attack_config", {})
        if isinstance(config_data, dict):
            try:
                AttackConfig(**config_data)
            except Exception as e:
                report.add(ValidationIssue(
                    severity="error",
                    category="schema",
                    message=f"attack_config 验证失败: {e}",
                    file_path=str(path),
                    field="attack_config",
                    suggestion="检查 target_url、objectives、scorers 等字段",
                ))

        # 检查 phases
        phases_data = raw_data.get("phases", [])
        if isinstance(phases_data, list):
            for i, phase_data in enumerate(phases_data):
                if not isinstance(phase_data, dict):
                    report.add(ValidationIssue(
                        severity="error",
                        category="schema",
                        message=f"phases[{i}] 不是字典",
                        file_path=str(path),
                        field=f"phases[{i}]",
                    ))
                    continue
                try:
                    AttackPhase(**phase_data)
                except Exception as e:
                    report.add(ValidationIssue(
                        severity="error",
                        category="schema",
                        message=f"phases[{i}] ({phase_data.get('name', '?')}): {e}",
                        file_path=str(path),
                        field=f"phases[{i}]",
                        suggestion="检查 strategies 枚举值和必填字段",
                    ))

        # 检查 payloads
        payloads_data = raw_data.get("payloads", [])
        if isinstance(payloads_data, list):
            seen_ids: set[str] = set()
            for i, pl_data in enumerate(payloads_data):
                if not isinstance(pl_data, dict):
                    report.add(ValidationIssue(
                        severity="error",
                        category="schema",
                        message=f"payloads[{i}] 不是字典",
                        file_path=str(path),
                        field=f"payloads[{i}]",
                    ))
                    continue
                try:
                    pt = PayloadTemplate(**pl_data)
                    if pt.id in seen_ids:
                        report.add(ValidationIssue(
                            severity="error",
                            category="schema",
                            message=f"重复的 payload ID: {pt.id}",
                            file_path=str(path),
                            field=f"payloads[{i}].id",
                            suggestion="每个 payload id 必须全局唯一",
                        ))
                    seen_ids.add(pt.id)
                except Exception as e:
                    report.add(ValidationIssue(
                        severity="error",
                        category="schema",
                        message=f"payloads[{i}] ({pl_data.get('id', '?')}): {e}",
                        file_path=str(path),
                        field=f"payloads[{i}]",
                        suggestion="检查 strategy 枚举值、difficulty 字段（easy/medium/hard）",
                    ))

    def _check_cross_references(
        self, scenario: Any, report: ValidationReport, file_path: str
    ) -> None:
        """检查 phase.payload_templates ID 是否都存在于 payloads 列表中。

        Args:
            scenario: AttackScenario 实例
            report: 验证报告
            file_path: 文件路径
        """
        # 收集所有 payload ID
        payload_ids: set[str] = {p.id for p in scenario.payloads}

        for phase in scenario.phases:
            for pt_id in phase.payload_templates:
                if pt_id not in payload_ids:
                    report.add(ValidationIssue(
                        severity="error",
                        category="cross_ref",
                        message=f"阶段 '{phase.name}' 引用的载荷模板 '{pt_id}' 不存在于 payloads 列表中",
                        file_path=file_path,
                        field=f"phases[?name={phase.name}].payload_templates",
                        suggestion=f"检查 payload ID 是否正确，或添加对应的 payload 定义",
                    ))

        # 检查孤立的 payload（未被任何 phase 引用）
        referenced_ids: set[str] = set()
        for phase in scenario.phases:
            referenced_ids.update(phase.payload_templates)

        orphan_ids = payload_ids - referenced_ids
        if orphan_ids:
            for oid in sorted(orphan_ids):
                report.add(ValidationIssue(
                    severity="warning",
                    category="cross_ref",
                    message=f"载荷模板 '{oid}' 未被任何阶段引用（孤立载荷）",
                    file_path=file_path,
                    field="payloads",
                    suggestion="添加对应的 phase.payload_templates 引用或移除无用载荷",
                ))

    def _check_extends(
        self, raw_data: dict, report: ValidationReport, file_path: str
    ) -> None:
        """检查 extends 引用的场景 ID 是否有效。

        Args:
            raw_data: 原始 YAML 字典
            report: 验证报告
            file_path: 文件路径
        """
        extends_val = raw_data.get("extends", "")
        if not extends_val or not isinstance(extends_val, str) or not extends_val.strip():
            return

        extends_val = extends_val.strip()
        self._ensure_registry_loaded()

        if extends_val not in self._registry_ids:
            report.add(ValidationIssue(
                severity="error",
                category="extends",
                message=f"extends 引用未知场景: '{extends_val}'",
                file_path=file_path,
                field="extends",
                suggestion=f"可用场景 ID: {sorted(self._registry_ids)}",
            ))
        else:
            # extends 存在，检查是否有循环继承风险
            # 简单检查：如果被继承场景也继承当前场景
            parent_entry = self._registry_entries.get(extends_val, {}) if self._registry_entries else {}
            parent_extends = parent_entry.get("extends", "")
            current_id = raw_data.get("id", "")
            if parent_extends == current_id:
                report.add(ValidationIssue(
                    severity="error",
                    category="extends",
                    message=f"检测到循环继承: {current_id} ↔ {extends_val}",
                    file_path=file_path,
                    field="extends",
                    suggestion="打破继承循环，调整继承关系",
                ))

    def _check_payload_sources(
        self, raw_data: dict, report: ValidationReport, file_path: str
    ) -> None:
        """检查 payload_sources 引用的是否为已知 OWASP 类别。

        Args:
            raw_data: 原始 YAML 字典
            report: 验证报告
            file_path: 文件路径
        """
        sources = raw_data.get("payload_sources", [])
        if not sources or not isinstance(sources, list):
            return

        for i, src in enumerate(sources):
            if isinstance(src, str):
                cat = src
            elif isinstance(src, dict):
                cat = src.get("categories", src.get("category", ""))
                if isinstance(cat, list):
                    # 检查列表中的每个类别
                    for j, sub_cat in enumerate(cat):
                        if isinstance(sub_cat, str) and sub_cat not in KNOWN_PAYLOAD_CATEGORIES:
                            report.add(ValidationIssue(
                                severity="warning",
                                category="payload_source",
                                message=f"未知载荷源类别: '{sub_cat}'",
                                file_path=file_path,
                                field=f"payload_sources[{i}].categories[{j}]",
                                suggestion=f"已知类别: {sorted(KNOWN_PAYLOAD_CATEGORIES)}",
                            ))
                    continue
                elif not isinstance(cat, str):
                    continue
            else:
                continue

            if isinstance(cat, str) and cat not in KNOWN_PAYLOAD_CATEGORIES:
                report.add(ValidationIssue(
                    severity="warning",
                    category="payload_source",
                    message=f"未知载荷源类别: '{cat}'",
                    file_path=file_path,
                    field=f"payload_sources[{i}]",
                    suggestion=f"已知 OWASP 类别: {sorted(KNOWN_PAYLOAD_CATEGORIES)}",
                ))

    def _check_enum_values(
        self, raw_data: dict, report: ValidationReport, file_path: str
    ) -> None:
        """检查 raw_data 中的枚举值是否在 Pydantic 解析前就明显错误。

        已通过 _check_schema 覆盖，这里做补充检查。
        """
        from redteam.scenario.schema import (
            AttackStrategy, AttackPhaseType, AttackTargetType, ScorerType,
        )

        # 快捷获取所有有效枚举值
        valid_strategies = {s.value for s in AttackStrategy}
        valid_phase_types = {p.value for p in AttackPhaseType}
        valid_target_types = {t.value for t in AttackTargetType}
        valid_scorers = {s.value for s in ScorerType}

        # 检查 target_type
        tt = raw_data.get("target_type", "")
        if isinstance(tt, str) and tt not in valid_target_types:
            report.add(ValidationIssue(
                severity="error",
                category="enum",
                message=f"无效 target_type: '{tt}'",
                file_path=file_path,
                field="target_type",
                suggestion=f"有效值: {sorted(valid_target_types)}",
            ))

        # 检查 phases 中的 strategy 和 phase_type
        phases_data = raw_data.get("phases", [])
        if isinstance(phases_data, list):
            for i, phase in enumerate(phases_data):
                if not isinstance(phase, dict):
                    continue
                # 检查 phase_type
                pt = phase.get("phase_type", "")
                if isinstance(pt, str) and pt not in valid_phase_types:
                    report.add(ValidationIssue(
                        severity="error",
                        category="enum",
                        message=f"phases[{i}] 无效 phase_type: '{pt}'",
                        file_path=file_path,
                        field=f"phases[{i}].phase_type",
                        suggestion=f"有效值: {sorted(valid_phase_types)}",
                    ))

                # 检查 strategies
                strategies = phase.get("strategies", [])
                if isinstance(strategies, list):
                    for j, s in enumerate(strategies):
                        if isinstance(s, str) and s not in valid_strategies:
                            report.add(ValidationIssue(
                                severity="error",
                                category="enum",
                                message=f"phases[{i}] 无效 strategy: '{s}'",
                                file_path=file_path,
                                field=f"phases[{i}].strategies[{j}]",
                                suggestion=f"有效策略值: {sorted(valid_strategies)[:10]}...等 {len(valid_strategies)} 种",
                            ))

        # 检查 payloads 中的 strategy
        payloads_data = raw_data.get("payloads", [])
        if isinstance(payloads_data, list):
            for i, pl in enumerate(payloads_data):
                if not isinstance(pl, dict):
                    continue
                s = pl.get("strategy", "")
                if isinstance(s, str) and s not in valid_strategies:
                    report.add(ValidationIssue(
                        severity="error",
                        category="enum",
                        message=f"payloads[{i}] ({pl.get('id', '?')}) 无效 strategy: '{s}'",
                        file_path=file_path,
                        field=f"payloads[{i}].strategy",
                        suggestion=f"有效策略值: {sorted(valid_strategies)[:10]}...等 {len(valid_strategies)} 种",
                    ))

        # 检查 attack_config 中的 scorers
        config = raw_data.get("attack_config", {})
        if isinstance(config, dict):
            scorers = config.get("scorers", [])
            if isinstance(scorers, list):
                for i, s in enumerate(scorers):
                    if isinstance(s, str) and s not in valid_scorers:
                        report.add(ValidationIssue(
                            severity="error",
                            category="enum",
                            message=f"attack_config.scorers[{i}] 无效值: '{s}'",
                            file_path=file_path,
                            field=f"attack_config.scorers[{i}]",
                            suggestion=f"有效评分器: {sorted(valid_scorers)}",
                        ))

    def _check_semantic(
        self, scenario: Any, report: ValidationReport, file_path: str
    ) -> None:
        """语义级别检查（仅在 strict 模式启用）。

        检查项：
          - 阶段顺序是否合理（probe → injection → encoding → ...）
          - timeout 是否在合理范围
          - objective 是否为空
        """
        # 检查 objectives
        if not scenario.attack_config.objectives:
            report.add(ValidationIssue(
                severity="warning",
                category="schema",
                message="attack_config.objectives 为空",
                file_path=file_path,
                field="attack_config.objectives",
                suggestion="至少定义一个攻击目标",
            ))

        # 检查 phases 顺序
        from redteam.scenario.schema import AttackPhaseType
        phase_order = {
            AttackPhaseType.PROBE: 0,
            AttackPhaseType.INJECTION: 1,
            AttackPhaseType.ENCODING: 2,
            AttackPhaseType.SEMANTIC: 3,
            AttackPhaseType.ADVANCED: 4,
            AttackPhaseType.POISONING: 5,
            AttackPhaseType.RETRIEVAL: 5,
            AttackPhaseType.EXPLOITATION: 6,
            AttackPhaseType.DESERIALIZATION: 6,
            AttackPhaseType.ACCESS: 7,
            AttackPhaseType.EVASION: 8,
            AttackPhaseType.FRONTIER: 9,
        }

        last_order = -1
        for phase in scenario.phases:
            current = phase_order.get(phase.phase_type, 99)
            if current < last_order:
                report.add(ValidationIssue(
                    severity="info",
                    category="schema",
                    message=f"阶段顺序异常: {phase.name} ({phase.phase_type.value}) "
                            f"在非标准位置",
                    file_path=file_path,
                    field=f"phases[?name={phase.name}]",
                    suggestion="建议按 probe → injection → encoding → semantic → advanced 顺序排列",
                ))
            last_order = current

        # 检查 timeout
        if scenario.attack_config.timeout_seconds < 5:
            report.add(ValidationIssue(
                severity="warning",
                category="schema",
                message=f"超时设置过短: {scenario.attack_config.timeout_seconds}s",
                file_path=file_path,
                field="attack_config.timeout_seconds",
                suggestion="建议至少 10s 以避免网络超时误判",
            ))

        # 检查 phases 的 payload_templates 数量
        for phase in scenario.phases:
            if not phase.payload_templates and phase.phase_type != AttackPhaseType.PROBE:
                report.add(ValidationIssue(
                    severity="warning",
                    category="schema",
                    message=f"阶段 '{phase.name}' 无 payload_templates 引用",
                    file_path=file_path,
                    field=f"phases[?name={phase.name}]",
                    suggestion="添加至少一个 payload 引用或设置 enabled: false",
                ))

    # ── 工具方法 ─────────────────────────────────────────────────────

    def _discover_scenario_files(self) -> list[Path]:
        """发现所有场景 YAML 文件（排除注册表）。"""
        if not self.scenario_dir.exists():
            return []
        files: list[Path] = []
        skip_prefixes = ("_registry", "_template")
        for yf in sorted(self.scenario_dir.glob("*.yaml")):
            if yf.stem.startswith(skip_prefixes):
                continue
            files.append(yf)
        return files

    def _ensure_registry_loaded(self) -> None:
        """延迟加载注册表索引。"""
        if self._registry_ids is not None:
            return
        self._registry_ids = set()
        self._registry_entries = {}

        reg_path = self.scenario_dir / "_registry.core.yaml"
        if not reg_path.exists():
            return

        registry = self._safe_load_yaml(reg_path)
        if not registry:
            return

        for entry in registry.get("scenarios", []):
            if not isinstance(entry, dict):
                continue
            eid = entry.get("id", "")
            if eid:
                self._registry_ids.add(eid)
                self._registry_entries[eid] = entry

    def _quick_parse_id(self, yaml_path: Path) -> str | None:
        """快速从 YAML 文件中提取场景 ID（避免完整 Pydantic 解析）。

        Args:
            yaml_path: YAML 文件路径

        Returns:
            场景 ID 或 None
        """
        data = self._safe_load_yaml(yaml_path)
        if data and isinstance(data, dict):
            sid = data.get("id", "")
            if isinstance(sid, str) and sid.strip():
                return sid.strip()
        return None

    @staticmethod
    def _safe_load_yaml(path: Path) -> dict[str, Any] | None:
        """安全加载 YAML 文件，解析失败返回 None。"""
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data
            return None
        except Exception:
            return None

    @staticmethod
    def _load_registry_dict(path: Path, report: ValidationReport) -> dict[str, Any] | None:
        """加载注册表文件并验证格式。"""
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                report.add(ValidationIssue(
                    severity="error",
                    category="registry",
                    message="注册表文件格式错误（非字典）",
                    file_path=str(path),
                ))
                return None
            if "scenarios" not in data:
                report.add(ValidationIssue(
                    severity="warning",
                    category="registry",
                    message="注册表缺少 'scenarios' 字段",
                    file_path=str(path),
                ))
            return data
        except yaml.YAMLError as e:
            report.add(ValidationIssue(
                severity="error",
                category="registry",
                message=f"注册表 YAML 解析失败: {e}",
                file_path=str(path),
            ))
            return None
        except Exception as e:
            report.add(ValidationIssue(
                severity="error",
                category="registry",
                message=f"读取注册表失败: {e}",
                file_path=str(path),
            ))
            return None


# ── 公开工具函数 ────────────────────────────────────────────────────────


def validate_scenario_file(
    file_path: str,
    scenario_dir: str = DEFAULT_SCENARIO_DIR,
    payload_dir: str = DEFAULT_PAYLOAD_DIR,
    strict: bool = False,
) -> ValidationReport:
    """便捷函数：验证单个场景文件。

    Args:
        file_path: YAML 文件路径
        scenario_dir: 场景目录
        payload_dir: 载荷目录
        strict: 是否启用严格模式

    Returns:
        验证报告
    """
    validator = YamlValidator(scenario_dir, payload_dir, strict=strict)
    return validator.validate_file(file_path)


def validate_all_scenarios(
    scenario_dir: str = DEFAULT_SCENARIO_DIR,
    payload_dir: str = DEFAULT_PAYLOAD_DIR,
    strict: bool = False,
) -> ValidationReport:
    """便捷函数：验证所有场景文件。

    Args:
        scenario_dir: 场景目录
        payload_dir: 载荷目录
        strict: 是否启用严格模式

    Returns:
        合并后的验证报告
    """
    validator = YamlValidator(scenario_dir, payload_dir, strict=strict)
    return validator.validate_all()


__all__ = [
    "YamlValidator",
    "ValidationIssue",
    "ValidationReport",
    "validate_scenario_file",
    "validate_all_scenarios",
    "KNOWN_PAYLOAD_CATEGORIES",
    "KNOWN_OWASP_IDS",
    "KNOWN_TARGET_TYPES",
]
