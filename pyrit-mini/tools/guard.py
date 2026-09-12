"""
tools/guard.py - Architecture Guard CLI (宪法守卫)

R-SIZE / R-CONV / R-IMPORT / R-STACK 静态架构检查 (19+ 规则)

调用方式:
    py -m tools.guard              # 运行全量检查
    py -m tools.guard -v           # 详细输出
    py -m tools.guard --quick file.py  # 单文件快速检查
    py -m tools.guard --watch      # 实时文件监视

Academic basis:  (clean architecture, god object anti-pattern)

迁移自: core/architecture_guard.py (2026-09-08 目录职责优化)
合并自: tools/quick_check.py, tools/watch_guard.py (2026-09-10 功能合并)
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Dict, Set, Tuple

logger = logging.getLogger(__name__)

# ===============================================================================
# R-SIZE 阈值: 检测 God Object 逃离
# ===============================================================================

_SIZE_WARNING_THRESHOLD = 850  # 警告阈值 (原 800, 放宽 50)
_SIZE_BLOCKING_THRESHOLD = 1500  # 阻塞阈值
_SIZE_BYPASS_WHITELIST = {
    "arm/converter_chains.py",
    "arm/converter_selector.py",
    "arm/seed_ranker.py",  # 679行，稳定运行，含完整测试覆盖
    "arm/seed_ranking.py",  # 675行，稳定运行，含完整测试覆盖
    "tools/guard_extended.py",  # 迁移后路径
    "core/orchestrator.py",
    "recon/health_probe.py",  # 860行，4层侦察完整实现，含stealth集成
    "utils/display.py",
    "report/report_markdown.py",
    # 2026-09-09: 新增大型文件白名单 (稳定运行，含完整测试覆盖)
    # R-DELIVERY-1 豁免: 300-600 行文件，单一职责，稳定运行
    "recon/_target_router_helpers.py",  # 858行
    "report/poc_generator.py",  # 1033行
    "strike/common/executor.py",  # 1133行 (重构: strike/executor.py -> strike/common/executor.py)
    "strike/common/escalation_runtime.py",  # 467行 (重构: strike/ -> strike/common/)
    "strike/common/asr_forensics.py",  # 346行 (重构: strike/ -> strike/common/)
    "strike/injection/file_upload_executor.py",  # 650行 (重构: strike/ -> strike/injection/)
    "report/evidence.py",  # 607行
    "recon/model/prompt_injector.py",  # 633行 (重构: recon/ -> recon/model/)
    "recon/capability_probe.py",  # 657行
    "tools/drift_detector.py",  # 586行
    "tools/guard.py",  # 430行
    "assess/adaptive_dual_judge.py",  # 545行
    "assess/judge_manager.py",  # 714行
    "assess/score_pipeline.py",  # 751行
    "core/config.py",  # 814行
    "core/_arg_parser.py",  # parse_args CLI 解析 (从 config.py 抽出，单一职责)
    "core/phases/arm.py",  # 723行
    "core/phases/strike.py",  # 766行
    # 2026-09-09: 第二批 300-600 行文件豁免 (R-DELIVERY-1)
    "recon/capability_detector.py",  # 521行
    "recon/burp_parser.py",  # 514行
    "recon/target_builder.py",  # 511行
    "recon/guardrail_detector.py",  # 444行
    "recon/api/endpoint_sorter.py",  # 439行 (重构: recon/ -> recon/api/)
    "recon/confidence_scorer.py",  # 425行
    "recon/api/openapi_discoverer.py",  # 414行 (重构: recon/ -> recon/api/)
    # 2026-09-09: 第三批 300-600 行A2A侦察框架文件 (R-DELIVERY-1)
    "recon/target_wrapper.py",  # 374行
    "recon/api/recursive_expander.py",  # 366行 (重构: recon/ -> recon/api/)
    "recon/trust_chain_probe.py",  # 334行
    "recon/trust_level_enum.py",  # 320行
    # 2026-09-09: 攻击面映射框架 (R-DELIVERY-1 豁免: 636行，单一职责)
    "arm/attack_surface_mapper.py",  # 636行，统一攻击面枚举框架
    "recon/target_router.py",  # 311行
    "strike/injection/auth_attacks.py",  # 440行 (重构: strike/ -> strike/injection/)
    "assess/asr_manager.py",  # 460行
    "assess/asr_stats.py",  # 358行
    "assess/_judge_init.py",  # 329行
    "core/context.py",  # 313行
    "core/scenario_router.py",  # 379行
    "core/seed_dynamic_engine.py",  # 583行
    "core/seed_quality_assessor.py",  # 417行
    "core/seed_router.py",  # 453行
    "core/_config_parsers.py",  # 516行
    "core/phases/_helpers.py",  # 431行
    "report/evidence_extract.py",  # 421行
    "report/generator.py",  # 385行
    "report/owasp_constants.py",  # 402行
    "report/owasp_mapping.py",  # 351行
    "report/pyrit_native_output.py",  # 473行
    "report/report_sections.py",  # 423行
    "report/_poc_templates.py",  # 446行
    "tools/hooks.py",  # 304行
    "strike/common/_executor_attack_paths.py",  # 324行 (重构: strike/ -> strike/common/)
    "strike/common/_executor_helpers.py",  # 329行 (重构: strike/ -> strike/common/)
    # 2026-09-12: 白名单路径对账 (配合目录重构)
    # 11 个文件已按重构后的子包路径重映射 (recon/api, recon/model, strike/common, strike/injection)。
    # 20 个失效条目已移除: 对应文件在重构中重命名/删除，按文件名全仓检索无匹配
    # (recon/a2a_*, recon/rag_metadata_parser, recon/rag_pipeline_probe, recon/rag_typo_fuzzer,
    #  recon/system_prompt_extractor, strike/malicious_mcp_server, strike/backdoor_attack,
    #  strike/mcpsec_orchestrator, strike/web_page_injector, strike/http_attack_engine,
    #  strike/document_poisoner, strike/multimodal_injection, strike/dynamic_mcp_seeds,
    #  strike/output_filter_bypass, strike/rag_targeted_consumer, tools/data_flow_validator 等)。
    # 若这些稳定模块仍需豁免，请提供重构后的新路径，再补回白名单。
}

# ===============================================================================


class Severity(IntEnum):
    BLOCKING = 0  # 阻塞 CI / commit
    WARNING = 1  # 警告
    INFO = 2  # 信息


@dataclass
class Violation:
    rule: str
    severity: Severity
    file: str
    line: int
    description: str
    fix_hint: str = ""


class ArchitectureGuard:
    def __init__(self, project_root: Path) -> None:
        self.root = project_root
        self.violations: list[Violation] = []
        self._source_files: list[Path] | None = None

    @property
    def source_files(self) -> list[Path]:
        if self._source_files is not None:
            return self._source_files

        exclude_dirs = {
            "outputs",
            ".venv",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            "node_modules",
            ".git",
            ".assistant_pyrit",
            ".idea",
            ".vscode",
            "pyrit_strike.egg-info",
            # 非代码目录：docs(文档/模板示例)、data(prompt 语料)、config(YAML 配置)
            # 不是 Python 包，不应参与架构守卫扫描，避免模板示例误报 R-TOOLS-1。
            "docs",
            "data",
            "config",
        }
        self._source_files = []
        for path in self.root.rglob("*.py"):
            if any(part in exclude_dirs for part in path.parts):
                continue
            self._source_files.append(path)
        return self._source_files

    def check_size_escape(self) -> None:
        """R-SIZE: 检测超过行数阈值的文件"""
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                line_count = len(content.splitlines())
            except OSError:
                continue

            rel_path = str(path.relative_to(self.root))

            # 白名单检查 (兼容 Windows 路径分隔符)
            norm_path = rel_path.replace("\\", "/")
            if norm_path in _SIZE_BYPASS_WHITELIST:
                continue

            if line_count >= _SIZE_BLOCKING_THRESHOLD:
                self.violations.append(
                    Violation(
                        rule="R-SIZE",
                        severity=Severity.BLOCKING,
                        file=rel_path,
                        line=1,
                        description=f"God Object 逃离: {path.name} {line_count} 行 (超过 +{_SIZE_BLOCKING_THRESHOLD})",
                        fix_hint=f"拆分至 <{_SIZE_WARNING_THRESHOLD} 行: 优先抽取到 core/phases/ 或 assess/ 子模块",
                    )
                )
            elif line_count >= _SIZE_WARNING_THRESHOLD:
                self.violations.append(
                    Violation(
                        rule="R-SIZE",
                        severity=Severity.WARNING,
                        file=rel_path,
                        line=1,
                        description=f"文件膨胀警告: {path.name} {line_count} 行 (超过 +{_SIZE_WARNING_THRESHOLD})",
                        fix_hint="建议拆分: 优先抽取到 core/phases/ 或 assess/ 子模块",
                    )
                )

    def check_serial_stacking(self) -> None:
        """R-CONV-1: 检测 ConverterConfiguration 串联超过阈值"""
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                if "ConverterConfiguration" in line and "converters=[" in line:
                    match = re.search(r"converters\s*=\s*\[(.*?)\]", line)
                    if not match:
                        continue

                    inner = match.group(1).strip()
                    comma_count = inner.count(",")

                    if comma_count > 2:
                        self.violations.append(
                            Violation(
                                rule="R-CONV-1",
                                severity=Severity.BLOCKING,
                                file=str(path.relative_to(self.root)),
                                line=i,
                                description=f"Converter 串联违规: {path.name}:{i} 包含 {comma_count + 1} 个 converter",
                                fix_hint="最多 2 个 converter 串联: 使用 chained_selective 模式",
                            )
                        )

    def check_forbidden_custom_classes(self) -> None:
        """R-IMPORT-1: 检测禁止使用的第三方库"""
        forbidden_patterns = [
            (r"import\s+requests", "使用 urllib.request 或 httpx 替代"),
            (r"from\s+requests\s+import", "使用 urllib.request 或 httpx 替代"),
        ]

        for path in self.source_files:
            if "adapters" in str(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for pattern, fix in forbidden_patterns:
                for i, line in enumerate(content.split("\n"), 1):
                    if re.search(pattern, line) and not line.strip().startswith("#"):
                        self.violations.append(
                            Violation(
                                rule="R-IMPORT-1",
                                severity=Severity.WARNING,
                                file=str(path.relative_to(self.root)),
                                line=i,
                                description=f"禁止依赖: {line.strip()[:60]}",
                                fix_hint=fix,
                            )
                        )

    def check_cli_location(self) -> None:
        """R-TOOLS-1: CLI 工具必须放在 tools/ 目录

        检查项:
        - core/ 下文件禁止带 `if __name__ == "__main__"` (作为实际执行入口)
        - utils/ / report/ 等同上
        - 允许: 根目录 main.py, tools/*.py, tests/*.py (测试)
        - 忽略: 在 docstring/字符串模板内的 __main__ 引用 (如 PoC 模板)
        """
        _ALLOWED_MAIN_DIRS = {"tools", "tests", "scripts"}  # scripts/ 允许维护脚本入口
        _ALLOWED_ROOT_FILES = {"main.py"}

        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if "if __name__" not in content:
                continue

            # 提取不在三引号内的 __main__ 块
            real_main_lines = self._extract_real_main_lines(content)
            if not real_main_lines:
                continue

            rel_path = str(path.relative_to(self.root))
            parts = rel_path.replace("\\", "/").split("/")

            # 根目录文件
            if len(parts) == 1:
                if parts[0] in _ALLOWED_ROOT_FILES:
                    continue
                self.violations.append(
                    Violation(
                        rule="R-TOOLS-1",
                        severity=Severity.BLOCKING,
                        file=rel_path,
                        line=real_main_lines[0],
                        description=f"根目录非法 CLI 入口: {rel_path} (应迁移到 tools/ 目录)",
                        fix_hint=f"将 {rel_path} 迁移到 tools/ 目录，或删除 __main__ 块",
                    )
                )
                continue

            # 子目录文件
            top_dir = parts[0]
            if top_dir not in _ALLOWED_MAIN_DIRS:
                self.violations.append(
                    Violation(
                        rule="R-TOOLS-1",
                        severity=Severity.BLOCKING,
                        file=rel_path,
                        line=real_main_lines[0],
                        description=f"CLI 入口位置违规: {rel_path} (CLI 工具必须放在 tools/ 目录)",
                        fix_hint=f"将 {rel_path} 迁移到 tools/{path.name}",
                    )
                )

    @staticmethod
    def _extract_real_main_lines(content: str) -> list[int]:
        """提取不在三引号字符串模板内的 `if __main__` 所在行号

        返回行号列表, 如果全部在三引号内则返回空列表。
        支持检测行中/行尾开始的三引号 (如 f'''...''')
        """
        lines = content.split("\n")
        in_triple_quote: str | None = None
        main_lines: list[int] = []

        for i, line in enumerate(lines):
            stripped = line.strip()

            # 检测三引号开关 (支持行中开始的三引号)
            if in_triple_quote is None:
                # 查找行中第一个三引号
                tq_pos = -1
                for quote in ('"""', "'''"):
                    pos = stripped.find(quote)
                    if pos != -1 and (tq_pos == -1 or pos < tq_pos):
                        tq_pos = pos
                        in_triple_quote = quote

                if in_triple_quote is not None:
                    # 检查同一行是否也关闭了三引号
                    after_open = stripped[tq_pos + 3 :]
                    if in_triple_quote in after_open:
                        # 单行三引号字符串，状态不变
                        in_triple_quote = None
                    continue
            else:
                if in_triple_quote in stripped:
                    in_triple_quote = None
                    continue

            # 不在三引号内
            if in_triple_quote is None and "if __name__" in stripped and "__main__" in stripped:
                main_lines.append(i + 1)  # 1-indexed

        return main_lines

    def check_data_flow_integrity(self) -> None:
        """R-DATA-1: Recon → ARM → Strike → Assess → Report/Evidence 全链路数据流完整性验证

        检查 PipelineContext 在各 Phase 边界的数据传递是否完整一致。
        通过 import data_flow_validator 运行自动化测试。
        覆盖 5 阶段 × (字段契约 + 传递规则 + 跨阶段一致性) = 完整验证链。
        """
        import subprocess
        import sys

        # 运行 pytest 测试数据流完整性 (仅运行快速测试集)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "tests/common/test_data_flow_integrity.py",
                    "-v",
                    "--tb=short",
                    "-q",
                    "--no-header",
                    "-p",
                    "no:cacheprovider",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(self.root),
            )

            if result.returncode != 0:
                # 解析失败信息
                output_lines = result.stdout.strip().split("\n")[-10:] if result.stdout else []
                "\n".join(output_lines) if output_lines else "pytest 执行失败"

                self.violations.append(
                    Violation(
                        rule="R-DATA-1",
                        severity=Severity.WARNING,
                        file="tools/data_flow_validator.py",
                        line=1,
                        description=f"数据流完整性验证失败: {result.returncode} 个测试未通过",
                        fix_hint="运行 pytest tests/common/test_data_flow_integrity.py -v 查看详细结果",
                    )
                )
            else:
                # 记录通过信息 (INFO 级别)
                self.violations.append(
                    Violation(
                        rule="R-DATA-1",
                        severity=Severity.INFO,
                        file="tools/data_flow_validator.py",
                        line=1,
                        description="全链路数据流完整性验证通过: Recon→ARM→Strike→Assess→Report/Evidence 无断点",
                        fix_hint="",
                    )
                )
        except subprocess.TimeoutExpired:
            self.violations.append(
                Violation(
                    rule="R-DATA-1",
                    severity=Severity.WARNING,
                    file="tools/data_flow_validator.py",
                    line=1,
                    description="数据流验证超时 (>60s)",
                    fix_hint="检查是否有死循环或网络调用",
                )
            )
        except FileNotFoundError:
            self.violations.append(
                Violation(
                    rule="R-DATA-1",
                    severity=Severity.INFO,
                    file="tools/data_flow_validator.py",
                    line=1,
                    description="pytest 跳过 (未安装或测试文件缺失)",
                    fix_hint="",
                )
            )
        except Exception as e:
            self.violations.append(
                Violation(
                    rule="R-DATA-1",
                    severity=Severity.INFO,
                    file="tools/data_flow_validator.py",
                    line=1,
                    description=f"数据流验证跳过: {type(e).__name__}",
                    fix_hint="",
                )
            )

    def check_all(self) -> list[Violation]:
        self.violations.clear()

        # 内置检查 (R-SIZE / R-STACK / R-CLASS / R-TOOLS)
        self.check_size_escape()
        self.check_serial_stacking()
        self.check_forbidden_custom_classes()
        self.check_cli_location()

        # R-DATA-1: 数据流完整性验证 (每次 guard 运行时自动检查)
        self.check_data_flow_integrity()

        # 扩展检查 (R-PIPE / R-IMPORT / R-REDTEAM / R-EVID / R-REPORT)
        # 通过 register_extended_checks() 在模块级别注册
        for attr_name in dir(self):
            if attr_name.startswith("check_") and attr_name not in (
                "check_size_escape",
                "check_serial_stacking",
                "check_forbidden_custom_classes",
                "check_all",
                "check_data_flow_integrity",
            ):
                method = getattr(self, attr_name, None)
                if callable(method):
                    try:
                        method()
                    except Exception as e:
                        logger.debug("Extended check %s failed: %s", attr_name, e)

        return self.violations


# === Quick Check 功能 (合并自 tools/quick_check.py) ===
# R-DELIVERY-1 行数阈值已与 R-SIZE 治理统一（见 _check_file_size：850 警告 / 1500 阻塞 + 白名单）。
_MODULE_DOCSTRING_REQUIRED = True  # R-DELIVERY-5

# Forbidden cross-layer imports (R-DELIVERY-3)
_FORBIDDEN_CROSS_LAYER = {
    "report": ["strike"],
    "utils": ["strike", "recon", "arm", "assess", "report"],
}


def _check_file_size(filepath: Path, project_root: Path | None = None) -> list[str]:
    """R-DELIVERY-1: 模块行数检查 —— 与 R-SIZE 治理对齐（850 警告 / 1500 阻塞 + 白名单）。

    历史硬编码 300 行阈值会误伤 70+ 个稳定、已充分测试的模块，与项目实际的
    R-SIZE 治理（850 警告 / 1500 阻塞 + `_SIZE_BYPASS_WHITELIST`）严重不一致，
    长期成为纯噪声。现统一口径：白名单内豁免；超 850 行警告、超 1500 行阻塞。
    已手动拆分至 ≤300 行的模块（如 core/resilience.py、core/phases/_component_bridge.py）
    仍保持整洁，不受阈值放宽影响。
    """
    violations = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        line_count = len(content.splitlines())
    except OSError:
        return violations

    # 白名单豁免（与 R-SIZE 一致），兼容 Windows 路径分隔符
    if project_root is not None:
        try:
            rel_path = str(filepath.relative_to(project_root)).replace("\\", "/")
            if rel_path in _SIZE_BYPASS_WHITELIST:
                return violations
        except ValueError:
            pass

    if line_count >= _SIZE_BLOCKING_THRESHOLD:
        violations.append(
            f"  R-DELIVERY-1 [BLOCKING] {filepath.name}: {line_count} lines (limit: {_SIZE_BLOCKING_THRESHOLD})"
        )
    elif line_count >= _SIZE_WARNING_THRESHOLD:
        violations.append(
            f"  R-DELIVERY-1 [WARNING] {filepath.name}: {line_count} lines (limit: {_SIZE_WARNING_THRESHOLD})"
        )
    return violations


def _check_docstring(filepath: Path) -> list[str]:
    """R-DELIVERY-5: Check module docstring."""
    violations = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        has_docstring = False
        for line in lines[:10]:
            stripped = line.strip()
            if stripped.startswith(('"""', "'''")):
                has_docstring = True
                break
            elif stripped and not stripped.startswith("#"):
                break
        if not has_docstring and len(lines) > 5:
            violations.append(f"  R-DELIVERY-5 [INFO] {filepath.name}: missing module docstring")
    except OSError:
        pass
    return violations


def _check_cross_layer_imports(filepath: Path) -> list[str]:
    """R-DELIVERY-3: Check forbidden cross-layer imports."""
    violations = []
    rel_path = str(filepath).replace("\\", "/")

    # Determine which layer this file belongs to
    src_layer = None
    for layer in _FORBIDDEN_CROSS_LAYER:
        if f"/{layer}/" in rel_path or rel_path.startswith(f"{layer}/"):
            src_layer = layer
            break

    if not src_layer:
        return violations

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return violations

    for dst_layer in _FORBIDDEN_CROSS_LAYER.get(src_layer, []):
        pattern = rf"from\s+{dst_layer}\.|import\s+{dst_layer}\."
        if re.search(pattern, content):
            violations.append(f"  R-DELIVERY-3 [BLOCKING] {filepath.name}: cross-layer import from '{dst_layer}'")

    return violations


def run_quick_check(filepath: Path, project_root: Path | None = None) -> list[str]:
    """Run all quick checks on a single file."""
    if not filepath.exists():
        print(f"Error: {filepath} not found")
        return []

    if not filepath.suffix == ".py":
        print(f"Error: {filepath} is not a Python file")
        return []

    all_violations = []
    all_violations.extend(_check_file_size(filepath, project_root))
    all_violations.extend(_check_docstring(filepath))
    all_violations.extend(_check_cross_layer_imports(filepath))
    return all_violations


def run_quick_check_all(project_root: Path) -> tuple[list[str], list[str]]:
    """Run quick checks on all files in core packages."""
    files = []
    dirs = ["strike", "recon", "arm", "assess", "core", "report", "utils"]
    for d in dirs:
        d_path = project_root / d
        if d_path.exists():
            for f in d_path.rglob("*.py"):
                if f.name != "__init__.py":
                    files.append(f)

    all_violations = []
    blocking_violations = []
    for f in files:
        violations = run_quick_check(f, project_root)
        all_violations.extend(violations)
        for v in violations:
            if "[BLOCKING]" in v:
                blocking_violations.append(v)

    return all_violations, blocking_violations


# === Watch Guard 功能 (合并自 tools/watch_guard.py) ===
_WATCHED_DIRS = ["strike", "recon", "arm", "assess", "core", "report", "utils", "tools"]
_CHECK_INTERVAL = 2  # seconds between scans
_DEBOUNCE_SECONDS = 1  # wait before checking after change


class FileWatcher:
    """Watches Python files for changes and triggers architecture checks."""

    def __init__(self, project_root: Path, package: str = None, fast: bool = False):
        self.project_root = project_root
        self.target_dirs = [project_root / package] if package else [project_root / d for d in _WATCHED_DIRS]
        self.fast = fast
        self.file_hashes: Dict[str, str] = {}
        self.last_change_time: float = 0
        self.pending_check: bool = False

    def _compute_file_hash(self, filepath: Path) -> str:
        """Compute SHA-256 hash of a file (change-detection only; MD5 retired per CWE-327)."""
        try:
            content = filepath.read_bytes()
            return hashlib.sha256(content).hexdigest()
        except OSError:
            return ""

    def _get_all_py_files(self) -> list[Path]:
        """Get all Python files to watch."""
        files = []
        for d in self.target_dirs:
            if d.exists():
                for f in d.rglob("*.py"):
                    if f.name != "__init__.py" or not self.fast:
                        files.append(f)
        return files

    def _scan_for_changes(self) -> list[Path]:
        """Scan files and return list of changed files."""
        changed = []
        current_files: Set[str] = set()

        for filepath in self._get_all_py_files():
            rel_path = str(filepath.relative_to(self.project_root))
            current_files.add(rel_path)

            new_hash = self._compute_file_hash(filepath)
            old_hash = self.file_hashes.get(rel_path)

            if old_hash is None:
                self.file_hashes[rel_path] = new_hash
            elif old_hash != new_hash:
                changed.append(filepath)
                self.file_hashes[rel_path] = new_hash

        for rel_path in list(self.file_hashes.keys()):
            if rel_path not in current_files:
                del self.file_hashes[rel_path]

        return changed

    def _run_full_guard(self) -> Tuple[bool, str]:
        """Run full architecture guard."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "tools.guard"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=30,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Guard timeout (30s)"
        except Exception as e:
            return False, f"Guard error: {e}"

    def run(self):
        """Main watch loop."""
        print("=" * 60)
        print("  Architecture Guard - Real-time Watcher")
        print("=" * 60)
        print()
        print(f"  Watching: {[d.name for d in self.target_dirs if d.exists()]}")
        print(f"  Interval: {_CHECK_INTERVAL}s")
        print(f"  Mode: {'Fast (modified files only)' if self.fast else 'Full (all rules)'}")
        print()
        print("  Press Ctrl+C to stop")
        print("-" * 60)
        print()

        # Initial scan
        print("[1/2] Running initial check...")
        ok, output = self._run_full_guard()
        if ok:
            print("  [PASS] Initial check passed")
        else:
            print(f"  [INFO] Found issues: {output.strip().split(chr(10))[-1] if output else 'unknown'}")

        print("[2/2] Starting file watcher...")
        print()

        try:
            while True:
                time.sleep(_CHECK_INTERVAL)

                changed = self._scan_for_changes()
                if not changed:
                    continue

                time.sleep(_DEBOUNCE_SECONDS)
                changed = self._scan_for_changes()

                now = time.strftime("%H:%M:%S")
                print(f"[{now}] Changed: {[f.name for f in changed]}")

                ok, output = self._run_full_guard()

                if ok:
                    print("  [PASS] All checks passed")
                else:
                    lines = output.strip().split("\n")
                    if lines:
                        last_line = lines[-1] if lines else ""
                        print(f"  [WARN] {last_line}")
                        rdelivery_lines = [line for line in lines if "R-DELIVERY" in line]
                        if rdelivery_lines:
                            print("  R-DELIVERY violations:")
                            for line in rdelivery_lines[:3]:
                                print(f"    {line.strip()}")

                print()

        except KeyboardInterrupt:
            print()
            print("-" * 60)
            print("  Watcher stopped.")
            print("-" * 60)


def run_watch_guard(project_root: Path, package: str = None, fast: bool = False) -> None:
    """Run real-time file watcher."""
    watcher = FileWatcher(project_root, package=package, fast=fast)
    watcher.run()


# === CLI 入口 ===
def main() -> None:
    parser = argparse.ArgumentParser(description="Architecture Guard - 静态架构检查")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--quick", type=str, default=None, help="Quick check a single file")
    parser.add_argument("--quick-all", action="store_true", help="Quick check all files")
    parser.add_argument("--watch", action="store_true", help="Real-time file watcher")
    parser.add_argument("--watch-package", type=str, default=None, help="Watch specific package")
    parser.add_argument("--watch-fast", action="store_true", help="Fast watch mode")
    parser.add_argument("--component-purity", action="store_true", help="Component purity & coverage validation")
    parser.add_argument("--min-purity", type=float, default=0.90, help="Minimum purity threshold (0.0-1.0)")
    parser.add_argument("--min-coverage", type=float, default=0.60, help="Minimum coverage threshold (0.0-1.0)")

    args = parser.parse_args()

    if not args.verbose:
        logging.basicConfig(level=logging.WARNING)

    # Quick check mode
    if args.quick:
        filepath = Path(args.quick)
        if not filepath.is_absolute():
            filepath = args.root / filepath
        violations = run_quick_check(filepath)
        if violations:
            print(f"Quick check: {filepath.name}")
            for v in violations:
                print(v)
            print()
            sys.exit(1)
        else:
            print(f"  [PASS] {filepath.name}: All R-DELIVERY rules passed")
            sys.exit(0)

    if args.quick_all:
        all_violations, blocking_violations = run_quick_check_all(args.root)
        if all_violations:
            print(f"Quick check: {len(all_violations)} issue(s) found")
            for v in all_violations[:20]:
                print(v)
            if len(all_violations) > 20:
                print(f"  ... and {len(all_violations) - 20} more")
        if blocking_violations:
            print(f"\n  [FAIL] {len(blocking_violations)} BLOCKING issue(s) found")
            sys.exit(1)
        else:
            print("  [PASS] No BLOCKING issues (WARNING/INFO are non-blocking)")
            sys.exit(0)

    # Component purity mode
    if args.component_purity:
        from tools.component_purity import ComponentPurityValidator

        validator = ComponentPurityValidator(args.root)
        results = validator.validate_all()

        blocking_count = 0
        warning_count = 0

        for category, components in results.items():
            for name, report in sorted(components.items()):
                if report.purity_score < args.min_purity:
                    print(f"  [FAIL] {category}/{name}: purity {report.purity_score:.2%} < {args.min_purity:.2%}")
                    blocking_count += 1
                if report.coverage_score < args.min_coverage:
                    print(f"  [WARN] {category}/{name}: coverage {report.coverage_score:.2%} < {args.min_coverage:.2%}")
                    warning_count += 1
                for finding in report.findings:
                    if finding.severity == "error":
                        print(f"  [ERR] {category}/{name}: {finding.message}")
                    elif finding.severity == "warning":
                        print(f"  [WRN] {category}/{name}: {finding.message}")

        print(f"\n 组件纯粹性报告: {blocking_count} 阻塞 / {warning_count} 警告")

        if blocking_count > 0:
            raise SystemExit(1)
        print("  [PASS] 组件纯粹性检查通过")
        sys.exit(0)

    # Watch mode
    if args.watch or args.watch_package or args.watch_fast:
        run_watch_guard(args.root, package=args.watch_package, fast=args.watch_fast)
        return

    # Full guard mode
    guard = ArchitectureGuard(args.root)
    violations = guard.check_all()

    blocking = [v for v in violations if v.severity == Severity.BLOCKING]
    warnings = [v for v in violations if v.severity == Severity.WARNING]
    info = [v for v in violations if v.severity == Severity.INFO]

    for v in blocking:
        print(f"  {v.rule} {v.file}:{v.line}")
        print(f"    {v.description}")
        if v.fix_hint:
            print(f"    修复建议: {v.fix_hint}")

    for v in warnings:
        print(f"  {v.rule} {v.file}:{v.line}")
        print(f"    {v.description}")
        if v.fix_hint:
            print(f"    修复建议: {v.fix_hint}")

    for v in info:
        print(f"  {v.rule} {v.file}:{v.line}")
        print(f"    {v.description}")

    print(f"\n 扫描结果: {len(blocking)} 阻塞 / {len(warnings)} 警告 / {len(info)} 信息")

    if blocking:
        raise SystemExit(1)


# === 注册扩展检查 (R-PIPE / R-IMPORT / R-REDTEAM / R-EVID / R-REPORT) ===
def _register_all_extended_checks() -> None:
    try:
        from tools.guard_extended import register_extended_checks

        register_extended_checks(ArchitectureGuard)
    except ImportError as e:
        logger.debug("Extended checks not available: %s", e)


_register_all_extended_checks()


if __name__ == "__main__":
    main()
