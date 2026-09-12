#!/usr/bin/env python3
"""
tools/component_audit_config.py — 组件审计配置和终端输出

包含:
    - Phase 数据类定义
    - 组件审计流程阶段配置
    - 终端颜色和输出格式化
"""

from __future__ import annotations

import os
import sys
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

# 支持的组件类型 (全 6 种核心组件)
ALL_COMPONENTS: list[str] = [
    "mcp",
    "a2a",
    "model",
    "rag",
    "session",
    "web",
]

# 扩展组件 (非核心但包含在审计中)
EXTENDED_COMPONENTS: list[str] = [
    "memory",
    "evasion",
    "injection",
]


# 定义每个阶段
@dataclass
class Phase:
    """单阶段配置"""

    id: str  # 1, 2, 3, ...
    name: str  # 显示名称
    description: str  # 说明
    command: list[str]  # 执行命令
    required: bool = True  # 是否必须通过
    timeout: int = 300  # 超时秒数


# 组件审计流程定义
COMPONENT_AUDIT_PHASES: list[Phase] = [
    Phase(
        id="1",
        name="Baseline Scan",
        description="扫描所有模块组件目录清单 (strike/recon/assess/report/tools + seeds)",
        command=[
            sys.executable,
            "-c",
            "from tools.component_audit_core import ComponentAuditor; ComponentAuditor().phase1_baseline_scan()",
        ],
        timeout=60,
    ),
    Phase(
        id="2",
        name="Purity Validation",
        description="AST+正则验证组件纯净度 (component_purity.py 全模块基线验证)",
        command=[
            sys.executable,
            "-m",
            "pytest",
            "tests/common/test_component_purity.py",
            "-v",
            "--tb=short",
        ],
        timeout=120,
    ),
    Phase(
        id="3",
        name="T0 Coverage",
        description="assess/component_router.py 分类模式 + T0 检查器覆盖",
        command=[
            sys.executable,
            "-c",
            "from tools.component_audit_core import ComponentAuditor; ComponentAuditor().phase3_t0_coverage()",
        ],
        timeout=60,
    ),
    Phase(
        id="4",
        name="Scorer/Report Coverage",
        description="scorers/ + report 组件感知章节覆盖验证",
        command=[
            sys.executable,
            "-c",
            "from tools.component_audit_core import ComponentAuditor; "
            "ComponentAuditor().phase4_scorer_report_coverage()",
        ],
        timeout=60,
    ),
    Phase(
        id="5",
        name="Seed Inventory",
        description="data/seeds/ 种子文件数量与组件类型匹配分析",
        command=[
            sys.executable,
            "-c",
            "from tools.component_audit_core import ComponentAuditor; ComponentAuditor().phase5_seed_inventory()",
        ],
        timeout=60,
    ),
    Phase(
        id="6",
        name="Validation Gate",
        description="pytest + guard + architecture_validator 三重验证",
        command=[
            sys.executable,
            "-c",
            "from tools.component_audit_core import ComponentAuditor; ComponentAuditor().phase6_validation_gate()",
        ],
        timeout=300,
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
    width = 72
    print()
    print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}{title:^{width}}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}")
    print()


def print_phase_start(phase: Phase) -> None:
    """打印阶段开始"""
    print(f"{Colors.BOLD}[Phase {phase.id}] {phase.name}{Colors.RESET}")
    print(f"  {phase.description}")
    print(f"  Command: {' '.join(phase.command)}")
    print()


def print_phase_result(phase: Phase, passed: bool, duration: float, output: str = "") -> None:
    """打印阶段结果"""
    status = f"{Colors.GREEN}PASS{Colors.RESET}" if passed else f"{Colors.RED}FAIL{Colors.RESET}"
    print(f"  Result: {status} ({duration:.1f}s)")
    if output and not passed:
        lines = output.strip().split("\n")
        tail = lines[-10:] if len(lines) > 10 else lines
        print(f"  Output (last {len(tail)} lines):")
        for line in tail:
            print(f"    {line}")
    print()


def print_summary(results: list[tuple[Phase, bool, float]]) -> None:
    """打印最终汇总"""
    print_header(" Component Audit Summary ")
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed
    total_time = sum(t for _, _, t in results)

    print(f"  Total Phases: {total}")
    print(f"  Passed:       {Colors.GREEN}{passed}{Colors.RESET}")
    print(f"  Failed:       {Colors.RED}{failed}{Colors.RESET}")
    print(f"  Total Time:   {total_time:.1f}s")
    print()
    print(f"  {'Phase':<8} {'Name':<28} {'Result':<10} {'Time':<10}")
    print(f"  {'-' * 8} {'-' * 28} {'-' * 10} {'-' * 10}")

    for phase, ok, dur in results:
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if ok else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {phase.id:<8} {phase.name:<28} {status:<10} {dur:.1f}s")

    print()
    if failed == 0:
        print(f"{Colors.GREEN}{Colors.BOLD}  ALL PHASES PASSED — 组件审计全绿{Colors.RESET}")
    else:
        print(f"{Colors.RED}{Colors.BOLD}  {failed} PHASE(S) FAILED — 修复后再提交{Colors.RESET}")
    print()
