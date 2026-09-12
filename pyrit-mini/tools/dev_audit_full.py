#!/usr/bin/env python3
"""
tools/dev_audit_full.py — 一键开发全审脚本 (A→L)

串联开发全审完整流程：
    A. Spec Impact      — 规格影响分析 (检查 specs/ 文档)
    B. Architecture Guard — py -m tools.guard (R-SIZE/CONV/IMPORT/TOOLS/DATA)
    B2. ArchCheck       — 组件感知流水线架构合规验证 (阶段边界/组件传播/模块路由)
    C. Lint              — py -m ruff check .
    D. Unit Test         — py -m pytest tests/ -v --tb=short
    E. Runtime Dry-Run   — py main.py --dry-run --max-seeds 1
    F. Data Flow         — py -m pytest tests/common/test_data_flow_integrity.py -v
    G. Drift Detection   — py -m tools.drift_detector --full
    H. Final Check       — py -m tools.guard (R-DELIVERY 规则快速扫描)
    (Phases I-L implemented: security/test/dependency/release audit)
    J. Test Audit        — py -m tools.test_audit (覆盖率/质量/边界/隔离/变异)
    K. Dependency Audit  — py -m tools.dependency_audit (版本/许可证/漏洞/树健康/源)
    L. Release Audit     — py -m tools.release_audit (版本/变更日志/生产就绪/回滚/文档)

特性:
    - 任一步失败立即停止 (fail-fast)
    - 彩色终端输出 (PASS/FAIL 标记)
    - 最终汇总报告
    - 可跳过指定步骤 (--skip e,f,i,j,k,l)
    - 支持 verbose 模式 (-v)

调用方式:
    py -m tools.dev_audit_full              # 执行全审 A→L
    py -m tools.dev_audit_full --skip e,f   # 跳过步骤 E 和 F
    py -m tools.dev_audit_full -v           # 详细输出
    py -m tools.dev_audit_full --phase b    # 仅执行 Phase B

Academic basis:
    - NIST SP 800-115: Technical Guide to Information Security Testing
    - OWASP Testing Guide v4.2: Continuous Compliance Verification
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# UTF-8 强制 (兼容 Windows GBK 终端)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ============================================================================
# 配置
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# 定义每个阶段
@dataclass
class Phase:
    """单阶段配置"""

    id: str  # a, b, c, ...
    name: str  # 显示名称
    description: str  # 说明
    command: list[str]  # 执行命令
    required: bool = True  # 是否必须通过
    timeout: int = 300  # 超时秒数


# 全审流程定义
AUDIT_PHASES: list[Phase] = [
    Phase(
        id="b",
        name="Architecture Guard",
        description="R-SIZE / R-CONV / R-IMPORT / R-TOOLS / R-DATA 静态架构检查",
        command=[sys.executable, "-m", "tools.guard"],
        timeout=120,
    ),
    Phase(
        id="b2",
        name="ArchCheck",
        description="组件感知流水线架构合规验证 (阶段边界/组件传播/模块路由/元数据连续性)",
        command=[sys.executable, "tools/architecture_validator.py", "full"],
        timeout=60,
    ),
    Phase(
        id="c",
        name="Lint (Ruff)",
        description="代码风格检查 (E/F/W/I 规则集)",
        command=[sys.executable, "-m", "ruff", "check", "."],
        timeout=60,
    ),
    Phase(
        id="d",
        name="Unit Test",
        description="pytest tests/ 全量单元测试",
        command=[sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        timeout=300,
    ),
    Phase(
        id="e",
        name="Runtime Dry-Run",
        description="main.py 6 阶段流水线运行时验证 (跳过 API 调用)",
        command=[sys.executable, "main.py", "--dry-run", "--max-seeds", "1"],
        timeout=120,
    ),
    Phase(
        id="f",
        name="Data Flow Integrity",
        description="Recon→ARM→Strike→Assess→Report/Evidence 全链路数据流验证",
        command=[sys.executable, "-m", "pytest", "tests/common/test_data_flow_integrity.py", "-v"],
        timeout=120,
    ),
    Phase(
        id="g",
        name="Drift Detection",
        description="规约-代码漂移检测 (R-DRIFT-1~4)",
        command=[sys.executable, "-m", "tools.drift_detector", "--full"],
        timeout=120,
    ),
    Phase(
        id="h",
        name="Final Guard Check",
        description="R-DELIVERY 规则快速扫描 (文件大小/文档字符串/跨层导入)",
        command=[sys.executable, "-m", "tools.guard"],
        timeout=60,
    ),
    Phase(
        id="i",
        name="Security Audit",
        description="密钥扫描 + 漏洞检测 + 注入检测 + 输入验证 + 权限检查",
        command=[sys.executable, "-m", "tools.security_audit"],
        timeout=180,
    ),
    Phase(
        id="j",
        name="Test Audit",
        description="覆盖率分析 + 测试质量 + 边界条件 + 测试隔离 + 变异测试",
        command=[sys.executable, "-m", "tools.test_audit"],
        timeout=300,
    ),
    Phase(
        id="k",
        name="Dependency Audit",
        description="版本一致性 + 许可证合规 + 已知漏洞 + 依赖树健康 + 源验证",
        command=[sys.executable, "-m", "tools.dependency_audit"],
        timeout=180,
    ),
    Phase(
        id="l",
        name="Release Audit",
        description="版本号规范 + 变更日志 + 生产就绪 + 回滚验证 + 文档同步",
        command=[sys.executable, "-m", "tools.release_audit"],
        timeout=120,
    ),
]

# ============================================================================
# 终端输出
# ============================================================================


class Colors:
    """终端颜色码"""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"

    @classmethod
    def disable(cls) -> None:
        """禁用颜色 (Windows 兼容)"""
        if sys.platform == "win32":
            cls.RESET = cls.BOLD = cls.RED = cls.GREEN = ""
            cls.YELLOW = cls.BLUE = cls.MAGENTA = cls.CYAN = ""


# Windows 检测: 如果不支持 ANSI 则禁用颜色
if sys.platform == "win32":
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        Colors.disable()


def print_header(title: str) -> None:
    """打印分阶段头部"""
    width = 70
    print()
    print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}{title:^{width}}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}")
    print()


def print_phase_start(phase: Phase) -> None:
    """打印阶段开始"""
    print(f"{Colors.BOLD}[Phase {phase.id.upper()}] {phase.name}{Colors.RESET}")
    print(f"  {phase.description}")
    if phase.command is not None:
        print(f"  Command: {' '.join(phase.command)}")
    else:
        print("  Command: MANUAL (module pending implementation)")
    print()


def print_phase_result(phase: Phase, passed: bool, duration: float, output: str = "") -> None:
    """打印阶段结果"""
    status = f"{Colors.GREEN}PASS{Colors.RESET}" if passed else f"{Colors.RED}FAIL{Colors.RESET}"
    print(f"  Result: {status} ({duration:.1f}s)")
    if output and not passed:
        # 显示失败输出的最后几行
        lines = output.strip().split("\n")
        tail = lines[-10:] if len(lines) > 10 else lines
        print(f"  Output (last {len(lines)} lines):")
        for line in tail:
            print(f"    {line}")
    print()


def print_summary(results: list[tuple[Phase, bool, float]]) -> None:
    """打印最终汇总"""
    print_header(" Development Audit Summary ")
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed
    total_time = sum(t for _, _, t in results)

    print(f"  Total Phases: {total}")
    print(f"  Passed:       {Colors.GREEN}{passed}{Colors.RESET}")
    print(f"  Failed:       {Colors.RED}{failed}{Colors.RESET}")
    print(f"  Total Time:   {total_time:.1f}s")
    print()
    print(f"  {'Phase':<8} {'Name':<25} {'Result':<10} {'Time':<10}")
    print(f"  {'-' * 8} {'-' * 25} {'-' * 10} {'-' * 10}")

    for phase, ok, dur in results:
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if ok else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {phase.id.upper():<8} {phase.name:<25} {status:<10} {dur:.1f}s")

    print()
    if failed == 0:
        print(f"{Colors.GREEN}{Colors.BOLD}  ALL PHASES PASSED — Ready for commit{Colors.RESET}")
    else:
        print(f"{Colors.RED}{Colors.BOLD}  {failed} PHASE(S) FAILED — Fix before commit{Colors.RESET}")
    print()


# ============================================================================
# 执行引擎
# ============================================================================


def run_phase(phase: Phase, verbose: bool = False) -> tuple[bool, str, float]:
    """
    执行单个阶段

    Returns:
        (是否通过, 输出文本, 耗时秒数)
    """
    print_phase_start(phase)
    start = time.monotonic()

    # 处理手动/无命令阶段
    if phase.command is None:
        duration = time.monotonic() - start
        output = "SKIPPED (Module pending implementation)"
        print_phase_result(phase, True, duration, output)
        return True, output, duration

    try:
        result = subprocess.run(
            phase.command,
            capture_output=True,
            text=True,
            timeout=phase.timeout,
            cwd=str(PROJECT_ROOT),
            encoding="utf-8",
            errors="replace",
        )
        duration = time.monotonic() - start
        output = result.stdout + result.stderr
        passed = result.returncode == 0

        if verbose:
            print(output)

        print_phase_result(phase, passed, duration, output if not passed else "")
        return passed, output, duration

    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        output = f"TIMEOUT after {phase.timeout}s"
        print_phase_result(phase, False, duration, output)
        return False, output, duration

    except FileNotFoundError as e:
        duration = time.monotonic() - start
        output = f"COMMAND NOT FOUND: {e}"
        print_phase_result(phase, False, duration, output)
        return False, output, duration

    except Exception as e:
        duration = time.monotonic() - start
        output = f"ERROR: {type(e).__name__}: {e}"
        print_phase_result(phase, False, duration, output)
        return False, output, duration


def run_audit(
    skip: set[str] | None = None,
    only: str | None = None,
    verbose: bool = False,
    fail_fast: bool = True,
) -> int:
    """
    运行完整开发全审流程

    Args:
        skip: 跳过的阶段 ID 集合
        only: 仅执行指定阶段
        verbose: 详细输出
        fail_fast: 失败即停

    Returns:
        0=全部通过, 1=有失败
    """
    print_header(" Development Audit Pipeline (A→H) ")
    print(f"  Project: {PROJECT_ROOT}")
    print(f"  Python:  {sys.version.split()[0]}")
    print(f"  Time:    {time.strftime('%Y-%m-%d %H:%M:%S')}")
    if skip:
        print(f"  Skip:    {', '.join(sorted(skip)).upper()}")

    # Phase A: Spec Impact (提示用户手动阅读)
    if "a" not in (skip or set()):
        print(f"{Colors.BOLD}[Phase A] Spec Impact (Manual){Colors.RESET}")
        print("  开发前必读: 00-CONSTITUTION / 10-ARCHITECTURE / 20-REQUIREMENTS / 40-GUARDRAILS")
        print("  请确认已阅读相关 specs/ 文档并理解涉及的宪法条款和红线")
        print(f"  Result: {Colors.YELLOW}MANUAL{Colors.RESET}")
        print()

    # 筛选要执行的阶段
    phases_to_run = AUDIT_PHASES
    if only:
        phases_to_run = [p for p in phases_to_run if p.id == only]
    if skip:
        phases_to_run = [p for p in phases_to_run if p.id not in skip]

    # 执行各阶段
    results: list[tuple[Phase, bool, float]] = []
    for phase in phases_to_run:
        passed, output, duration = run_phase(phase, verbose=verbose)
        results.append((phase, passed, duration))

        if not passed and fail_fast and phase.required:
            print(f"{Colors.RED}[FAIL-FAST] Phase {phase.id.upper()} failed, stopping pipeline{Colors.RESET}")
            break

    # 打印汇总
    print_summary(results)

    failed = sum(1 for _, ok, _ in results if not ok)
    return 1 if failed > 0 else 0


# ============================================================================
# CLI 入口
# ============================================================================


def main() -> int:
    """CLI 入口"""
    parser = argparse.ArgumentParser(
        description="Development Audit Pipeline — A→H 全审流程一键执行",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  py -m tools.dev_audit_full                # 执行全审 B→L (A 为手动)
  py -m tools.dev_audit_full --skip e,f     # 跳过 Dry-Run 和 Data Flow
  py -m tools.dev_audit_full --phase b      # 仅执行 Architecture Guard
  py -m tools.dev_audit_full --phase b2     # 仅执行 ArchCheck 架构合规验证
  py -m tools.dev_audit_full --phase i      # 仅执行 Security Audit
  py -m tools.dev_audit_full --skip i,j,k,l # 跳过新增审计 (兼容旧流程)
  py -m tools.dev_audit_full -v             # 详细输出 (显示完整命令输出)
  py -m tools.dev_audit_full --no-fail-fast # 失败继续执行后续阶段
        """,
    )
    parser.add_argument(
        "--skip",
        type=str,
        default=None,
        help="跳过的阶段 (逗号分隔, 如: e,f,g)",
    )
    parser.add_argument(
        "--phase",
        type=str,
        default=None,
        choices=["a", "b", "b2", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"],
        help="仅执行指定阶段",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="详细输出 (显示完整命令输出)",
    )
    parser.add_argument(
        "--no-fail-fast",
        action="store_true",
        help="失败不停止, 继续执行后续阶段",
    )

    args = parser.parse_args()

    skip_set = set(args.skip.split(",")) if args.skip else None

    return run_audit(
        skip=skip_set,
        only=args.phase,
        verbose=args.verbose,
        fail_fast=not args.no_fail_fast,
    )


if __name__ == "__main__":
    sys.exit(main())
