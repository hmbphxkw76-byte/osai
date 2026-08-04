# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""R-022 PyRIT 原生优先合规检查器 — 防偏离机制.

本脚本实现 R-022 原生优先原则的自动化合规检查:

机制 1: 原生优先决策树 — 检查自研模块是否至少依赖一个原生组件
机制 2: 自研代码分类标注 — 检查模块文档字符串是否标注 R-022 分类
机制 3: 禁止直接调用 send_prompt_async — 扫描攻击执行路径中的违规调用
机制 4: 原生 API 一致性检查 — 验证 PyRIT 版本一致性和 import 合规性

用法::

    python scripts/check_r022_compliance.py
    python scripts/check_r022_compliance.py --verbose

退出码:
    0 = 全部合规
    1 = 发现违规

> **日期**: 2026-8-5
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NamedTuple

# ── 配置 ──
PROJECT_ROOT = Path(__file__).parent.parent
PIPELINE_DIR = PROJECT_ROOT / "pipeline"

# 允许直接调用/定义 send_prompt_async 的白名单 (文件路径片段)
_SEND_PROMPT_ASYNC_WHITELIST = [
    "stage_init.py",       # 预检探针 (Stage 1 连通性检查)
    "stage_auth",          # 认证探测 (非攻击执行)
    "auth_probe",          # 认证探测
    "preflight",           # 预检工具
    "web_redteam/",        # Web Red Team 交互层 (非 PyRIT 攻击执行)
    "tests/",              # 测试文件
    "output_manager.py",   # ProgressPoller (查询 Memory, 不调用 send_prompt_async)
    "dynamic_chain_creator",  # Converter 配置工具 (LLM 分析查询, 非攻击执行)
]

# 实现原生 Target 接口的模块 (必须定义 send_prompt_async 方法, 非违规)
_TARGET_INTERFACE_MODULES = [
    "rate_limited_target.py",   # 包装原生 PromptTarget, 必须实现接口
    "rich_metadata_loader.py",  # 元数据加载, 非攻击模块
    "targets/",                 # targets 目录下的模块实现原生接口
]


class Violation(NamedTuple):
    """R-022 违规记录."""

    file: str
    line: int
    rule: str
    message: str
    severity: str  # ERROR / WARNING


def _is_in_docstring(lines: list[str], line_idx: int) -> bool:
    """检查指定行是否在文档字符串内."""
    in_docstring = False
    for i in range(line_idx + 1):
        line = lines[i].strip()
        if line.startswith(('"""', "'''")):
            if in_docstring and line.endswith('"""') and len(line) > 3:
                in_docstring = False
            elif not in_docstring:
                in_docstring = True
            elif line == '"""' or line == "'''":
                in_docstring = False
    return in_docstring


def _is_def_or_override(line: str) -> bool:
    """检查是否是方法定义 (def send_prompt_async) 而非调用."""
    return bool(re.match(r"\s*(async\s+)?def\s+send_prompt_async", line))


def check_send_prompt_async_violations(verbose: bool = False) -> list[Violation]:
    """机制 3: 扫描攻击执行路径中直接调用 send_prompt_async 的违规.

    规则:
      - ERROR: 攻击执行模块中直接调用 target.send_prompt_async()
      - ALLOWED: Target 接口实现 (def send_prompt_async) — 原生接口要求
      - ALLOWED: _fallback_send 方法内 — PyRIT import 失败回退
      - ALLOWED: _probe 方法内 — 预检探针
      - ALLOWED: 文档字符串中的引用
      - ALLOWED: 注释中的引用
    """
    violations: list[Violation] = []

    py_files = list(PIPELINE_DIR.rglob("*.py"))

    for py_file in py_files:
        rel_path = str(py_file.relative_to(PROJECT_ROOT)).replace("\\", "/")

        # 检查白名单
        if any(wl in rel_path for wl in _SEND_PROMPT_ASYNC_WHITELIST):
            if verbose:
                print(f"  [SKIP] {rel_path} (whitelist)")
            continue

        # 检查是否是 Target 接口实现模块
        is_target_impl = any(tl in rel_path for tl in _TARGET_INTERFACE_MODULES)

        try:
            content = py_file.read_text(encoding="utf-8")
        except Exception:
            continue

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if "send_prompt_async" not in line:
                continue

            # 跳过方法定义 (Target 接口实现)
            if _is_def_or_override(line):
                if verbose:
                    print(f"  [OK] {rel_path}:{i} (method definition)")
                continue

            # 跳过文档字符串
            if _is_in_docstring(lines, i - 1):
                if verbose:
                    print(f"  [OK] {rel_path}:{i} (in docstring)")
                continue

            # 跳过注释
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Target 接口实现模块中的调用 (super().send_prompt_async) 允许
            if is_target_impl:
                if verbose:
                    print(f"  [OK] {rel_path}:{i} (target interface)")
                continue

            # 检查上下文: _fallback_send 方法内
            context_start = max(0, i - 30)
            context = "\n".join(lines[context_start:i])
            if "_fallback_send" in context:
                if verbose:
                    print(f"  [OK] {rel_path}:{i} (in _fallback_send)")
                continue

            # 检查上下文: _query_llm / _llm_analysis 方法内 (LLM 分析查询, 非攻击执行)
            if ("_query_llm" in context or "_llm_analysis" in context) and "def " in context:
                if verbose:
                    print(f"  [OK] {rel_path}:{i} (in LLM analysis method)")
                continue

            # 检查上下文: _probe 方法内
            if "_probe" in context and "def " in context:
                if verbose:
                    print(f"  [OK] {rel_path}:{i} (in _probe method)")
                continue

            violations.append(Violation(
                file=rel_path,
                line=i,
                rule="R-022-M3",
                message="直接调用 send_prompt_async — 应使用原生 PromptSendingAttack/CrescendoAttack 等执行器",
                severity="ERROR",
            ))

    return violations


def _is_in_string_literal(line: str, pattern: str) -> bool:
    """检查 pattern 在该行中是否仅出现在字符串字面量内 (引号包裹).

    如果 pattern 出现在引号内 (如 ``"PromptSendingAttack"``),
    则认为是字符串引用而非实际代码使用。
    """
    # 查找 pattern 在行中的所有位置
    start = 0
    while True:
        idx = line.find(pattern, start)
        if idx == -1:
            break
        # 检查该位置前后的字符是否是引号
        # 向前查找最近的引号
        before = line[:idx]
        # 统计引号数量 (单引号和双引号)
        dq_count = before.count('"')
        sq_count = before.count("'")
        # 如果引号数量为奇数, 说明在字符串内
        in_double = dq_count % 2 == 1
        in_single = sq_count % 2 == 1
        if in_double or in_single:
            # 检查 pattern 后面是否也是引号 (字符串值的结尾)
            after = line[idx + len(pattern):]
            # 如果后面紧跟引号或冒号/逗号, 确认是字符串值
            if after and after[0] in "\"':, )":
                return True
        start = idx + 1
    return False


def check_native_import_compliance(verbose: bool = False) -> list[Violation]:
    """机制 4: 验证使用原生 PyRIT 组件的模块是否正确 import.

    支持检测:
      - 顶层 import: from pyrit.executor.attack import PromptSendingAttack
      - 函数内 lazy import: def run_async(): from pyrit.executor.attack import ...
      - try/except import: try: from pyrit.executor.attack import ... except ImportError

    误报消除:
      - 跳过字符串字面量中的引用 (如 ``"PromptSendingAttack"`` 字典键)
      - 全文件搜索 import 语句 (不限于文件头部)
      - 跳过文档字符串中的引用
    """
    violations: list[Violation] = []

    # 原生组件 → 必须的 import 模块
    native_patterns = [
        ("PromptSendingAttack", "pyrit.executor.attack"),
        ("CrescendoAttack", "pyrit.executor.attack"),
        ("TAPAttack", "pyrit.executor.attack"),
        ("SequentialAttack", "pyrit.executor.attack"),
        ("XPIAWorkflow", "pyrit.executor.attack"),
        ("RedTeamingAttack", "pyrit.executor.attack"),
        ("SelfAskTrueFalseScorer", "pyrit.score"),
        ("AttackAdversarialConfig", "pyrit.executor.attack"),
        ("AttackScoringConfig", "pyrit.executor.attack"),
    ]

    all_py_files = list(PIPELINE_DIR.rglob("*.py"))

    for py_file in all_py_files:
        rel_path = str(py_file.relative_to(PROJECT_ROOT)).replace("\\", "/")

        try:
            content = py_file.read_text(encoding="utf-8")
        except Exception:
            continue

        lines = content.split("\n")

        for pattern, expected_module in native_patterns:
            # 检查文件中是否实际使用了该组件 (排除注释/文档字符串/字符串字面量)
            uses_pattern = False
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if _is_in_docstring(lines, i - 1):
                    continue
                if pattern not in line:
                    continue
                # 关键: 跳过字符串字面量中的引用
                if _is_in_string_literal(line, pattern):
                    if verbose:
                        print(f"  [SKIP] {rel_path}:{i} — {pattern} in string literal")
                    continue
                uses_pattern = True
                break

            if not uses_pattern:
                continue

            # 全文件搜索 import 语句 (不限于文件头部)
            import_found = False
            for idx, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                # 检查 from pyrit.executor.attack import ... PatternSendingAttack ...
                if re.search(
                    rf"from\s+{re.escape(expected_module)}\s+import.*{pattern}",
                    line,
                ):
                    import_found = True
                    break
                # 检查 from pyrit.executor.workflow import XPIAWorkflow (替代路径)
                if (
                    expected_module == "pyrit.executor.attack"
                    and pattern == "XPIAWorkflow"
                    and re.search(r"from\s+pyrit\.executor\.workflow\s+import.*XPIAWorkflow", line)
                ):
                    import_found = True
                    break
                # 检查多行 import: from pyrit.executor.attack import (
                if f"from {expected_module} import" in line and "(" in line:
                    for next_line in lines[idx:idx + 15]:
                        if pattern in next_line and not next_line.strip().startswith("#"):
                            import_found = True
                            break
                    if import_found:
                        break
                # 检查 from pyrit.executor.attack import (无括号, 单行多名称)
                if f"from {expected_module} import" in line:
                    for next_line in lines[idx:idx + 5]:
                        if pattern in next_line and not next_line.strip().startswith("#"):
                            import_found = True
                            break
                    if import_found:
                        break
                # 检查替代模块路径: from pyrit.executor.workflow import XPIAWorkflow
                if pattern == "XPIAWorkflow" and re.search(r"from\s+pyrit\.executor\.workflow\s+import", line):
                    for next_line in lines[idx:idx + 5]:
                        if "XPIAWorkflow" in next_line:
                            import_found = True
                            break
                    if import_found:
                        break

            if not import_found:
                violations.append(Violation(
                    file=rel_path,
                    line=1,
                    rule="R-022-M4",
                    message=f"使用 {pattern} 但未从 {expected_module} import (或使用 lazy import)",
                    severity="WARNING",
                ))

    return violations


def check_r022_classification_labels(verbose: bool = False) -> list[Violation]:
    """机制 2: 检查自研模块是否标注 R-022 分类标签."""
    violations: list[Violation] = []

    module_dirs = [
        PIPELINE_DIR / "orchestrators",
        PIPELINE_DIR / "scenarios",
        PIPELINE_DIR / "scoring",
        PIPELINE_DIR / "asr",
        PIPELINE_DIR / "converters",
        PIPELINE_DIR / "targets",
        PIPELINE_DIR / "integrations",
        PIPELINE_DIR / "assessment",
        PIPELINE_DIR / "analysis",
    ]

    r022_labels = [
        "R-022",
        "原生优先",
        "配置层增强",
        "数据层增强",
        "选择层增强",
        "分析层增强",
        "PyRIT 原生",
        "native",
        "PromptSendingAttack",
        "CrescendoAttack",
        "Scenario",
        "PyRIT",
    ]

    for module_dir in module_dirs:
        if not module_dir.exists():
            continue

        for py_file in module_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue

            rel_path = str(py_file.relative_to(PROJECT_ROOT)).replace("\\", "/")

            try:
                content = py_file.read_text(encoding="utf-8")
            except Exception:
                continue

            header = content[:500]
            has_label = any(label in header for label in r022_labels)

            if not has_label:
                violations.append(Violation(
                    file=rel_path,
                    line=1,
                    rule="R-022-M2",
                    message="缺少 R-022 分类标签 (应在文档字符串中标注: 配置层/数据层/选择层/分析层增强)",
                    severity="WARNING",
                ))

    return violations


def check_pyrit_version_consistency(verbose: bool = False) -> list[Violation]:
    """机制 4: PyRIT 版本一致性检查."""
    violations: list[Violation] = []

    pyproject = PROJECT_ROOT / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        version_matches = re.findall(r"PyRIT.*?(\d+\.\d+\.\d+)", content, re.IGNORECASE)
        if version_matches:
            versions = set(version_matches)
            if len(versions) > 1:
                violations.append(Violation(
                    file="pyproject.toml",
                    line=0,
                    rule="R-022-M4",
                    message=f"PyRIT 版本不一致: {versions}",
                    severity="ERROR",
                ))

    code_files = list(PIPELINE_DIR.rglob("*.py"))
    version_refs: dict[str, list[str]] = {}

    for py_file in code_files:
        try:
            content = py_file.read_text(encoding="utf-8")
        except Exception:
            continue

        matches = re.findall(r"PyRIT[^\d]*(\d+\.\d+\.\d+)", content)
        for ver in matches:
            if ver not in version_refs:
                version_refs[ver] = []
            rel_path = str(py_file.relative_to(PROJECT_ROOT)).replace("\\", "/")
            version_refs[ver].append(rel_path)

    if len(version_refs) > 1:
        for ver, files in version_refs.items():
            for f in files[:3]:
                violations.append(Violation(
                    file=f,
                    line=0,
                    rule="R-022-M4",
                    message=f"PyRIT 版本引用 {ver} (与其他不一致)",
                    severity="WARNING",
                ))

    return violations


def print_report(violations: list[Violation], verbose: bool = False) -> int:
    """打印检查报告."""
    errors = [v for v in violations if v.severity == "ERROR"]
    warnings = [v for v in violations if v.severity == "WARNING"]

    print("\n" + "=" * 70)
    print("R-022 PyRIT 原生优先合规检查报告")
    print("=" * 70)

    if not violations:
        print("\n  ✅ 全部合规 — 无 R-022 违规")
        return 0

    if errors:
        print(f"\n  ❌ ERROR ({len(errors)} 项):")
        for v in errors:
            print(f"    [{v.rule}] {v.file}:{v.line} — {v.message}")

    if warnings:
        print(f"\n  ⚠ WARNING ({len(warnings)} 项):")
        for v in warnings[:20]:
            print(f"    [{v.rule}] {v.file}:{v.line} — {v.message}")
        if len(warnings) > 20:
            print(f"    ... 及其余 {len(warnings) - 20} 项")

    print(f"\n  总计: {len(errors)} ERROR + {len(warnings)} WARNING")
    return len(errors)


def main() -> int:
    """主入口."""
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print("R-022 PyRIT 原生优先合规检查开始...")
    print(f"  扫描目录: {PIPELINE_DIR}")

    all_violations: list[Violation] = []

    print("\n  [机制 3] 检查 send_prompt_async 直接调用...")
    v3 = check_send_prompt_async_violations(verbose=verbose)
    all_violations.extend(v3)
    print(f"    发现 {len(v3)} 项违规")

    print("\n  [机制 4] 检查原生 PyRIT import 合规性...")
    v4 = check_native_import_compliance(verbose=verbose)
    all_violations.extend(v4)
    print(f"    发现 {len(v4)} 项违规")

    print("\n  [机制 2] 检查 R-022 分类标签...")
    v2 = check_r022_classification_labels(verbose=verbose)
    all_violations.extend(v2)
    print(f"    发现 {len(v2)} 项违规")

    print("\n  [机制 4] 检查 PyRIT 版本一致性...")
    v_ver = check_pyrit_version_consistency(verbose=verbose)
    all_violations.extend(v_ver)
    print(f"    发现 {len(v_ver)} 项违规")

    error_count = print_report(all_violations, verbose=verbose)

    return 1 if error_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
