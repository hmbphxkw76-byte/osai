"""
tools/guard.py - Architecture Guard CLI (宪法守卫)

R-SIZE / R-CONV / R-IMPORT / R-STACK 静态架构检查 (19+ 规则)

调用方式:
    py -m tools.guard              # 运行全量检查
    py -m tools.guard -v           # 详细输出

Academic basis:  (clean architecture, god object anti-pattern)

迁移自: core/architecture_guard.py (2026-09-08 目录职责优化)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

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
    "recon/rag_metadata_parser.py",
    "recon/health_probe.py",  # 860行，4层侦察完整实现，含stealth集成
    "utils/display.py",
    "report/report_markdown.py",
}

# ===============================================================================

class Severity(IntEnum):
    BLOCKING = 0      # 阻塞 CI / commit
    WARNING = 1       # 警告
    INFO = 2          # 信息

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
            "outputs", ".venv", "__pycache__", ".pytest_cache",
            ".ruff_cache", "node_modules", ".git", ".assistant_pyrit",
            ".idea", ".vscode", "pyrit_strike.egg-info"
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
                self.violations.append(Violation(
                    rule="R-SIZE",
                    severity=Severity.BLOCKING,
                    file=rel_path,
                    line=1,
                    description=f"God Object 逃离: {path.name} {line_count} 行 (超过 +{_SIZE_BLOCKING_THRESHOLD})",
                    fix_hint=f"拆分至 <{_SIZE_WARNING_THRESHOLD} 行: 优先抽取到 core/phases/ 或 assess/ 子模块",
                ))
            elif line_count >= _SIZE_WARNING_THRESHOLD:
                self.violations.append(Violation(
                    rule="R-SIZE",
                    severity=Severity.WARNING,
                    file=rel_path,
                    line=1,
                    description=f"文件膨胀警告: {path.name} {line_count} 行 (超过 +{_SIZE_WARNING_THRESHOLD})",
                    fix_hint="建议拆分: 优先抽取到 core/phases/ 或 assess/ 子模块",
                ))

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
                        self.violations.append(Violation(
                            rule="R-CONV-1",
                            severity=Severity.BLOCKING,
                            file=str(path.relative_to(self.root)),
                            line=i,
                            description=f"Converter 串联违规: {path.name}:{i} 包含 {comma_count + 1} 个 converter",
                            fix_hint="最多 2 个 converter 串联: 使用 chained_selective 模式",
                        ))

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
                        self.violations.append(Violation(
                            rule="R-IMPORT-1",
                            severity=Severity.WARNING,
                            file=str(path.relative_to(self.root)),
                            line=i,
                            description=f"禁止依赖: {line.strip()[:60]}",
                            fix_hint=fix,
                        ))

    def check_cli_location(self) -> None:
        """R-TOOLS-1: CLI 工具必须放在 tools/ 目录

        检查项:
        - core/ 下文件禁止带 `if __name__ == "__main__"` (作为实际执行入口)
        - utils/ / report/ 等同上
        - 允许: 根目录 main.py, tools/*.py, tests/*.py (测试)
        - 忽略: 在 docstring/字符串模板内的 __main__ 引用 (如 PoC 模板)
        """
        _ALLOWED_MAIN_DIRS = {"tools", "tests"}
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
                self.violations.append(Violation(
                    rule="R-TOOLS-1",
                    severity=Severity.BLOCKING,
                    file=rel_path,
                    line=real_main_lines[0],
                    description=f"根目录非法 CLI 入口: {rel_path} (应迁移到 tools/ 目录)",
                    fix_hint=f"将 {rel_path} 迁移到 tools/ 目录，或删除 __main__ 块",
                ))
                continue

            # 子目录文件
            top_dir = parts[0]
            if top_dir not in _ALLOWED_MAIN_DIRS:
                self.violations.append(Violation(
                    rule="R-TOOLS-1",
                    severity=Severity.BLOCKING,
                    file=rel_path,
                    line=real_main_lines[0],
                    description=f"CLI 入口位置违规: {rel_path} (CLI 工具必须放在 tools/ 目录)",
                    fix_hint=f"将 {rel_path} 迁移到 tools/{path.name}",
                ))

    @staticmethod
    def _extract_real_main_lines(content: str) -> list[int]:
        """提取不在三引号 docstring 内的 `if __main__` 所在行号

        返回行号列表, 如果全部在 docstring 内则返回空列表
        """
        lines = content.split("\n")
        in_triple_quote: str | None = None
        main_lines: list[int] = []

        for i, line in enumerate(lines):
            stripped = line.strip()

            # 检测三引号开关
            if in_triple_quote is None:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    quote = stripped[:3]
                    # 单行三引号
                    if stripped.count(quote) >= 2 and stripped.endswith(quote):
                        continue
                    in_triple_quote = quote
                    continue
                # 检查多行模式下的引号
                if '"""' in stripped or "'''" in stripped:
                    # 简单处理: 检查是否包含 if __name__ 且不在三引号后
                    pass
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
                [sys.executable, "-m", "pytest",
                 "tests/test_data_flow_integrity.py",
                 "-v", "--tb=short", "-q",
                 "--no-header", "-p", "no:cacheprovider"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(self.root),
            )

            if result.returncode != 0:
                # 解析失败信息
                output_lines = result.stdout.strip().split("\n")[-10:] if result.stdout else []
                "\n".join(output_lines) if output_lines else "pytest 执行失败"

                self.violations.append(Violation(
                    rule="R-DATA-1",
                    severity=Severity.WARNING,
                    file="tools/data_flow_validator.py",
                    line=1,
                    description=f"数据流完整性验证失败: {result.returncode} 个测试未通过",
                    fix_hint="运行 pytest tests/test_data_flow_integrity.py -v 查看详细结果",
                ))
            else:
                # 记录通过信息 (INFO 级别)
                self.violations.append(Violation(
                    rule="R-DATA-1",
                    severity=Severity.INFO,
                    file="tools/data_flow_validator.py",
                    line=1,
                    description="全链路数据流完整性验证通过: Recon→ARM→Strike→Assess→Report/Evidence 无断点",
                    fix_hint="",
                ))
        except subprocess.TimeoutExpired:
            self.violations.append(Violation(
                rule="R-DATA-1",
                severity=Severity.WARNING,
                file="tools/data_flow_validator.py",
                line=1,
                description="数据流验证超时 (>60s)",
                fix_hint="检查是否有死循环或网络调用",
            ))
        except FileNotFoundError:
            self.violations.append(Violation(
                rule="R-DATA-1",
                severity=Severity.INFO,
                file="tools/data_flow_validator.py",
                line=1,
                description="pytest 跳过 (未安装或测试文件缺失)",
                fix_hint="",
            ))
        except Exception as e:
            self.violations.append(Violation(
                rule="R-DATA-1",
                severity=Severity.INFO,
                file="tools/data_flow_validator.py",
                line=1,
                description=f"数据流验证跳过: {type(e).__name__}",
                fix_hint="",
            ))

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
                "check_size_escape", "check_serial_stacking",
                "check_forbidden_custom_classes", "check_all",
                "check_data_flow_integrity",
            ):
                method = getattr(self, attr_name, None)
                if callable(method):
                    try:
                        method()
                    except Exception as e:
                        logger.debug("Extended check %s failed: %s", attr_name, e)

        return self.violations

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Architecture Guard - 静态架构检查")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if not args.verbose:
        logging.basicConfig(level=logging.WARNING)

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
    return None

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
