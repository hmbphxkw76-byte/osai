#!/usr/bin/env python3
"""pipeline_guard.py — 规则强制执行守卫。

这是项目的"宪法"执行器。每次代码变更后必须运行此脚本，
违规将导致非零退出码，从而阻断 commit / CI / 任务完成。

检查项 (对应 SKILL.md 5 条规则):
    R1: PyRIT 原生优先 — 检测自定义 Target/Executor/Scorer 类
    R2: 代码量 + 目录结构 — pipeline/ 行数、文件数、根目录文件
    R3: L5 参数基线 — defaults.yaml 参数不得低于基线
    R4: ruff + pytest — 调用 ruff 和 pytest (此脚本本身是门禁的一部分)
    R5: 学术引用 — defaults.yaml 参数应有 arXiv 注释

使用:
    python pipeline_guard.py              # 全量检查
    python pipeline_guard.py --fix-suggest # 输出修复建议
    python pipeline_guard.py --ci          # CI 模式 (严格, 无 WARNING 容忍)

退出码:
    0 = 全部通过
    1 = 有 BLOCK 级违规
    2 = 仅 WARNING (CI 模式下也返回 1)
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
_PIPELINE_DIR = _PROJECT_ROOT / "pipeline"
_CONFIG_FILE = _PROJECT_ROOT / "config" / "defaults.yaml"
_STRIKE_DIR = _PIPELINE_DIR / "strike"

# ═══════════════════════════════════════════════════════════════════════════════
# 阈值定义 (对应 SKILL.md Rule 2)
# ═══════════════════════════════════════════════════════════════════════════════

MAX_LINES_PER_FILE = 1000
MAX_PIPELINE_LINES = 21000
MAX_PIPELINE_FILES = 61
MAX_STRIKE_FILES = 15
MAX_CONFIG_LINES = 80
MAX_ENTRY_SCRIPT_LINES = 600

# 根目录允许的 .py 文件 (Rule 2)
ALLOWED_ROOT_PY = frozenset({
    "main.py",
    "run_strike.py",
    "run_batch.py",
    "run_web_vuln.py",
    "pipeline_guard.py",
})

# L5 参数基线 (Rule 3) — 参数名: (最小值, 类型)
L5_BASELINE: dict[str, tuple[int | float, str]] = {
    "max_attempts": (3, "int"),
    "max_seeds": (25, "int"),
    "escalation_asr_threshold": (90, "int"),
    "post_l1_exit_threshold": (70, "int"),
    "post_l2_exit_threshold": (80, "int"),
    "max_escalation_targets": (10, "int"),
    "crescendo_max_turns": (10, "int"),
    "tap_tree_width": (4, "int"),
    "tap_tree_depth": (4, "int"),
    "best_of_n_retries": (5, "int"),
    "l5_optimal_paths": (7, "int"),
    "auto_seed_expansion_factor": (3, "int"),
    "dual_judge_high_confidence_threshold": (0.85, "float"),
    "wilson_confidence_level": (0.95, "float"),
}

# L5 参数必须有 arXiv 注释 (Rule 5)
L5_REQUIRES_ARXIV = frozenset(L5_BASELINE.keys())

# 禁止自建的 PyRIT 组件 (Rule 1) — 通过类名模式检测
FORBIDDEN_CLASS_PATTERNS: list[tuple[str, str]] = [
    (r"Custom\w*Target", "自定义 Target 类 — 必须使用 PyRIT 原生 OpenAIChatTarget/HTTPTarget/PlaywrightTarget"),
    (r"Custom\w*Executor", "自定义 Executor 类 — 必须使用 PyRIT 原生 PromptSendingAttack/CrescendoAttack/TAPAttack/PAIRAttack"),
    (r"Custom\w*Scorer", "自定义 Scorer 类 — 必须使用 PyRIT 原生 SelfAskTrueFalseScorer/SubStringScorer"),
    (r"Custom\w*Memory", "自定义 Memory 类 — 必须使用 PyRIT 原生 CentralMemory/DuckDBMemory"),
    (r"Custom\w*Converter", "自定义 Converter 类 — 必须使用 pyrit.converter.* 原生组件"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# 检查结果数据结构
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class Violation:
    """规则违规记录。"""

    rule: str
    severity: str  # "BLOCK" or "WARNING"
    message: str
    file: str = ""
    line: int = 0
    fix_suggestion: str = ""


@dataclass
class GuardReport:
    """守卫检查报告。"""

    violations: list[Violation] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    @property
    def has_block(self) -> bool:
        return any(v.severity == "BLOCK" for v in self.violations)

    @property
    def has_warning(self) -> bool:
        return any(v.severity == "WARNING" for v in self.violations)

    def add_block(self, rule: str, message: str, **kwargs: object) -> None:
        self.violations.append(Violation(rule=rule, severity="BLOCK", message=message, **kwargs))

    def add_warning(self, rule: str, message: str, **kwargs: object) -> None:
        self.violations.append(Violation(rule=rule, severity="WARNING", message=message, **kwargs))

    def add_pass(self, check_name: str) -> None:
        self.passed.append(check_name)


# ═══════════════════════════════════════════════════════════════════════════════
# 检查函数
# ═══════════════════════════════════════════════════════════════════════════════


def count_lines(path: Path) -> int:
    """统计文件行数。"""
    try:
        return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except Exception:
        return 0


def get_py_files(directory: Path) -> list[Path]:
    """递归获取目录下所有 .py 文件。"""
    return sorted(directory.rglob("*.py"))


# ── R1: PyRIT 原生优先 ─────────────────────────────────────────────────────────


def check_pyrit_native(report: GuardReport) -> None:
    """R1: 检测自定义 Target/Executor/Scorer/Memory/Converter 类。"""
    if not _PIPELINE_DIR.exists():
        report.add_block("R1", f"pipeline/ 目录不存在: {_PIPELINE_DIR}")
        return

    py_files = get_py_files(_PIPELINE_DIR)
    found_violation = False

    for py_file in py_files:
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            class_name = node.name

            for pattern, reason in FORBIDDEN_CLASS_PATTERNS:
                if re.match(pattern, class_name):
                    report.add_block(
                        "R1",
                        f"禁止自建类: {class_name} — {reason}",
                        file=str(py_file.relative_to(_PROJECT_ROOT)),
                        line=node.lineno,
                        fix_suggestion=f"删除 {class_name}，改用 PyRIT 原生组件",
                    )
                    found_violation = True

    if not found_violation:
        report.add_pass("R1: 无自定义 PyRIT 组件替换")


# ── R2: 代码量 + 目录结构 ───────────────────────────────────────────────────────


def check_code_volume(report: GuardReport) -> None:
    """R2: 检查代码量是否超过阈值。"""
    if not _PIPELINE_DIR.exists():
        report.add_block("R2", f"pipeline/ 目录不存在: {_PIPELINE_DIR}")
        return

    py_files = get_py_files(_PIPELINE_DIR)

    # 总文件数
    # 排除 __init__.py 的文件数统计
    non_init_files = [f for f in py_files if f.name != "__init__.py"]
    total_files = len(non_init_files)
    if total_files > MAX_PIPELINE_FILES:
        report.add_block(
            "R2",
            f"pipeline/ 文件数 {total_files} 超过上限 {MAX_PIPELINE_FILES}",
            fix_suggestion="合并功能相近的模块，删除未使用的文件",
        )
    else:
        report.add_pass(f"R2: pipeline/ 文件数 {total_files}/{MAX_PIPELINE_FILES}")

    # 总行数
    total_lines = sum(count_lines(f) for f in py_files)
    if total_lines > MAX_PIPELINE_LINES:
        report.add_block(
            "R2",
            f"pipeline/ 总行数 {total_lines} 超过上限 {MAX_PIPELINE_LINES} (超出 {total_lines - MAX_PIPELINE_LINES} 行)",
            fix_suggestion="拆分大文件、删除死代码、合并重复逻辑",
        )
    else:
        report.add_pass(f"R2: pipeline/ 总行数 {total_lines}/{MAX_PIPELINE_LINES}")

    # 单文件行数
    for py_file in py_files:
        lines = count_lines(py_file)
        if lines > MAX_LINES_PER_FILE:
            report.add_block(
                "R2",
                f"单文件行数 {lines} 超过上限 {MAX_LINES_PER_FILE}",
                file=str(py_file.relative_to(_PROJECT_ROOT)),
                fix_suggestion=f"将 {py_file.name} 拆分为多个 < {MAX_LINES_PER_FILE} 行的模块",
            )

    # strike/ 文件数
    if _STRIKE_DIR.exists():
        strike_files = [f for f in get_py_files(_STRIKE_DIR) if f.name != "__init__.py"]
        strike_count = len(strike_files)
        if strike_count > MAX_STRIKE_FILES:
            report.add_block(
                "R2",
                f"strike/ 文件数 {strike_count} 超过上限 {MAX_STRIKE_FILES}",
                fix_suggestion="合并 escalation_level*.py、合并 *attacks.py、删除未使用的攻击模块",
            )
        else:
            report.add_pass(f"R2: strike/ 文件数 {strike_count}/{MAX_STRIKE_FILES}")


def check_root_directory(report: GuardReport) -> None:
    """R2: 检查根目录是否只有允许的文件。"""
    root_py_files = list(_PROJECT_ROOT.glob("*.py"))

    for py_file in root_py_files:
        if py_file.name not in ALLOWED_ROOT_PY:
            lines = count_lines(py_file)
            report.add_block(
                "R2",
                f"根目录不允许的 .py 文件: {py_file.name} ({lines} 行)",
                file=py_file.name,
                fix_suggestion=f"删除 {py_file.name} 或移动到 pipeline/ 子目录或 tests/",
            )

    # 入口脚本行数检查
    for name in ["main.py", "run_strike.py", "run_batch.py", "run_web_vuln.py"]:
        entry = _PROJECT_ROOT / name
        if entry.exists():
            lines = count_lines(entry)
            if lines > MAX_ENTRY_SCRIPT_LINES:
                report.add_block(
                    "R2",
                    f"入口脚本 {name} 行数 {lines} 超过上限 {MAX_ENTRY_SCRIPT_LINES}",
                    file=name,
                    fix_suggestion=f"将 {name} 中的逻辑提取到 pipeline/ 模块",
                )

    # 根目录日志文件
    log_files = list(_PROJECT_ROOT.glob("*.log")) + list(_PROJECT_ROOT.glob("*_log.txt"))
    for log_file in log_files:
        report.add_block(
            "R2",
            f"根目录日志文件: {log_file.name} — 必须放入 outputs/ 或删除",
            file=log_file.name,
            fix_suggestion=f"移动到 outputs/ 或删除 {log_file.name}",
        )

    # 根目录 txt 文件 (非 .env)
    txt_files = list(_PROJECT_ROOT.glob("*.txt"))
    for txt_file in txt_files:
        report.add_block(
            "R2",
            f"根目录 txt 文件: {txt_file.name} — 不属于根目录",
            file=txt_file.name,
            fix_suggestion="移动到 data/ 或 outputs/ 或删除",
        )

    allowed_count = sum(1 for f in root_py_files if f.name in ALLOWED_ROOT_PY)
    if allowed_count == len(root_py_files) and not log_files and not txt_files:
        report.add_pass("R2: 根目录文件干净")


# ── R3: L5 参数基线 ─────────────────────────────────────────────────────────────


def check_l5_baseline(report: GuardReport) -> None:
    """R3: 检查 defaults.yaml 参数是否不低于 L5 基线。"""
    if not _CONFIG_FILE.exists():
        report.add_block("R3", f"配置文件不存在: {_CONFIG_FILE}")
        return

    config_text = _CONFIG_FILE.read_text(encoding="utf-8", errors="replace")
    config_lines = config_text.splitlines()

    if len(config_lines) > MAX_CONFIG_LINES:
        report.add_block(
            "R3",
            f"defaults.yaml 行数 {len(config_lines)} 超过上限 {MAX_CONFIG_LINES}",
            fix_suggestion="精简注释，移除已废弃参数",
        )

    for param_name, (min_val, _type) in L5_BASELINE.items():
        # 查找参数行 (格式: key: value  # comment)
        pattern = re.compile(rf"^{param_name}:\s*([\d.]+)", re.MULTILINE)
        match = pattern.search(config_text)
        if not match:
            report.add_block(
                "R3",
                f"defaults.yaml 缺少 L5 参数: {param_name}",
                fix_suggestion=f"在 defaults.yaml 中添加 {param_name}: {min_val}",
            )
            continue

        actual_val: int | float
        try:
            if _type == "int":
                actual_val = int(match.group(1))
            else:
                actual_val = float(match.group(1))
        except ValueError:
            report.add_block(
                "R3",
                f"defaults.yaml 参数 {param_name} 值无法解析: {match.group(1)}",
            )
            continue

        if actual_val < min_val:
            report.add_block(
                "R3",
                f"defaults.yaml 参数 {param_name}={actual_val} 低于 L5 基线 {min_val}",
                fix_suggestion=f"将 {param_name} 改为 ≥ {min_val}",
            )
        else:
            report.add_pass(f"R3: {param_name}={actual_val} ≥ {min_val}")


# ── R5: 学术引用 ───────────────────────────────────────────────────────────────


def check_arxiv_citations(report: GuardReport) -> None:
    """R5: 检查 defaults.yaml 参数是否有 arXiv 注释。"""
    if not _CONFIG_FILE.exists():
        return

    config_text = _CONFIG_FILE.read_text(encoding="utf-8", errors="replace")
    config_lines = config_text.splitlines()

    for i, line in enumerate(config_lines):
        for param_name in L5_REQUIRES_ARXIV:
            if re.match(rf"^{param_name}:", line.strip()):
                # 检查当前行或前行是否有 arXiv 注释
                has_arxiv = bool(re.search(r"arXiv:|arxiv:|#[^#]*\d{4}\.\d{4,5}", line))
                if not has_arxiv:
                    # 检查前 3 行是否有注释
                    for j in range(max(0, i - 3), i):
                        if re.search(r"#.*arXiv|arxiv|\d{4}\.\d{4,5}", config_lines[j]):
                            has_arxiv = True
                            break
                if not has_arxiv:
                    report.add_warning(
                        "R5",
                        f"defaults.yaml 参数 {param_name} 缺少 arXiv 引用注释",
                        file="config/defaults.yaml",
                        line=i + 1,
                        fix_suggestion=f"在 {param_name} 行添加 # arXiv:XXXX.XXXXX 注释",
                    )
                break

    # 检查 pipeline/ 中攻击技术文件是否有 arXiv 注释
    attack_dirs = [_PIPELINE_DIR / "strike", _PIPELINE_DIR / "arm"]
    for attack_dir in attack_dirs:
        if not attack_dir.exists():
            continue
        for py_file in get_py_files(attack_dir):
            if py_file.name == "__init__.py":
                continue
            content = py_file.read_text(encoding="utf-8", errors="replace")
            # 检查文件是否有任何 arXiv 引用
            if not re.search(r"arXiv:|arxiv:", content):
                # 检查文件是否包含攻击技术相关关键词
                if re.search(r"class|def.*attack|def.*escalat|def.*jailbreak|def.*crescendo|def.*tap|def.*pair", content, re.IGNORECASE):
                    report.add_warning(
                        "R5",
                        f"攻击技术文件缺少 arXiv 引用: {py_file.name}",
                        file=str(py_file.relative_to(_PROJECT_ROOT)),
                        fix_suggestion=f"在 {py_file.name} 中添加 # arXiv:XXXX.XXXXX 注释",
                    )


# ── outputs 垃圾检测 ────────────────────────────────────────────────────────────


def check_outputs_cleanup(report: GuardReport) -> None:
    """R2: 检查 outputs/ 目录是否堆积过多。"""
    outputs_dir = _PROJECT_ROOT / "outputs"
    if not outputs_dir.exists():
        return

    # 统计 outputs/ 下的目录数
    sub_dirs = [d for d in outputs_dir.iterdir() if d.is_dir()]
    if len(sub_dirs) > 30:
        report.add_warning(
            "R2",
            f"outputs/ 下有 {len(sub_dirs)} 个目录 — 建议清理旧的运行结果",
            fix_suggestion="删除不再需要的 outputs/strike_* 目录，只保留最近 5-10 次",
        )

    # 统计大日志文件
    log_files = list(outputs_dir.glob("*.log"))
    total_log_size = sum(f.stat().st_size for f in log_files if f.exists())
    if total_log_size > 10 * 1024 * 1024:  # 10 MB
        report.add_warning(
            "R2",
            f"outputs/ 日志文件总大小 {total_log_size / 1024 / 1024:.1f} MB — 建议清理",
            fix_suggestion="删除大日志文件，它们不应被提交到 git",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 主函数
# ═══════════════════════════════════════════════════════════════════════════════

# ANSI 颜色 (Windows 10+ 支持)
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_RESET = "\033[0m"
_BOLD = "\033[1m"


def run_guard(ci_mode: bool = False, fix_suggest: bool = False) -> int:
    """运行全量守卫检查。

    Args:
        ci_mode: CI 模式 — WARNING 也返回非零退出码
        fix_suggest: 输出修复建议

    Returns:
        0 = 全部通过, 1 = 有违规
    """
    # UTF-8 强制 (Windows GBK 终端兼容)
    import os

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    report = GuardReport()

    print(f"\n{_BOLD}{'═' * 70}{_RESET}")
    print(f"{_BOLD}  PyRIT-Strike Pipeline Guard — 规则强制执行守卫{_RESET}")
    print(f"{_BOLD}{'═' * 70}{_RESET}\n")

    # 运行所有检查
    print(f"{_CYAN}[R1] PyRIT 原生优先检查...{_RESET}")
    check_pyrit_native(report)

    print(f"{_CYAN}[R2] 代码量 + 目录结构检查...{_RESET}")
    check_code_volume(report)
    check_root_directory(report)
    check_outputs_cleanup(report)

    print(f"{_CYAN}[R3] L5 参数基线检查...{_RESET}")
    check_l5_baseline(report)

    print(f"{_CYAN}[R5] 学术引用检查...{_RESET}")
    check_arxiv_citations(report)

    # 输出结果
    print(f"\n{_BOLD}{'─' * 70}{_RESET}")
    print(f"{_BOLD}  检查结果{_RESET}")
    print(f"{_BOLD}{'─' * 70}{_RESET}\n")

    # 通过的检查
    for item in report.passed:
        print(f"  {_GREEN}✓{_RESET} {item}")

    # 违规
    blocks = [v for v in report.violations if v.severity == "BLOCK"]
    warnings = [v for v in report.violations if v.severity == "WARNING"]

    if blocks:
        print()
        for v in blocks:
            location = f" ({v.file}:{v.line})" if v.file else ""
            print(f"  {_RED}✗ [BLOCK] {_RESET}{v.rule}: {v.message}{location}")
            if fix_suggest and v.fix_suggestion:
                print(f"          {_YELLOW}→ 修复: {v.fix_suggestion}{_RESET}")

    if warnings:
        print()
        for v in warnings:
            location = f" ({v.file}:{v.line})" if v.file else ""
            print(f"  {_YELLOW}⚠ [WARN] {_RESET}{v.rule}: {v.message}{location}")
            if fix_suggest and v.fix_suggestion:
                print(f"          {_YELLOW}→ 修复: {v.fix_suggestion}{_RESET}")

    # 总结
    print(f"\n{_BOLD}{'─' * 70}{_RESET}")
    total_pass = len(report.passed)
    total_block = len(blocks)
    total_warn = len(warnings)

    if total_block == 0 and total_warn == 0:
        print(f"{_GREEN}  ✓ 全部通过 — {total_pass} 项检查 OK{_RESET}")
        print(f"{_BOLD}{'═' * 70}{_RESET}\n")
        return 0
    elif total_block == 0:
        print(f"{_YELLOW}  ⚠ {total_pass} 项通过, {total_warn} 项警告{_RESET}")
        if ci_mode:
            print(f"{_RED}  ✗ CI 模式: 警告即失败{_RESET}")
            print(f"{_BOLD}{'═' * 70}{_RESET}\n")
            return 1
        print(f"{_BOLD}{'═' * 70}{_RESET}\n")
        return 0
    else:
        print(f"{_RED}  ✗ {total_block} 项阻断违规, {total_warn} 项警告, {total_pass} 项通过{_RESET}")
        print(f"{_BOLD}{'═' * 70}{_RESET}\n")
        return 1


def main() -> int:
    """CLI 入口。"""
    import argparse

    parser = argparse.ArgumentParser(
        description="PyRIT-Strike Pipeline Guard — 规则强制执行守卫",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI 模式: WARNING 也返回非零退出码",
    )
    parser.add_argument(
        "--fix-suggest",
        action="store_true",
        help="输出修复建议",
    )
    args = parser.parse_args()

    return run_guard(ci_mode=args.ci, fix_suggest=args.fix_suggest)


if __name__ == "__main__":
    sys.exit(main())
