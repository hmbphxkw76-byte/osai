#!/usr/bin/env python3
"""
tools/component_audit_core.py — 组件审计核心逻辑

包含:
    - ComponentAuditor 类 (Phase 1-6 分析逻辑)
    - 执行引擎 (run_phase 函数)
    - 主审计流程 (run_component_audit 函数)
"""

from __future__ import annotations

import subprocess
import sys
import time

from tools.component_audit_config import (
    ALL_COMPONENTS,
    COMPONENT_AUDIT_PHASES,
    EXTENDED_COMPONENTS,
    PROJECT_ROOT,
    Colors,
    Phase,
    print_header,
    print_phase_result,
    print_phase_start,
    print_summary,
)


class ComponentAuditor:
    """
    组件审计器 - 执行 6 阶段组件审计流程的各个阶段
    """

    def __init__(self) -> None:
        self.project_root = PROJECT_ROOT
        self.components = ALL_COMPONENTS
        self.extended_components = EXTENDED_COMPONENTS
        self.all_component_dirs = ALL_COMPONENTS + EXTENDED_COMPONENTS

    # ──────────────────────────────────────────────────────────────────────
    # Phase 1: 基线扫描
    # ──────────────────────────────────────────────────────────────────────

    def phase1_baseline_scan(self) -> int:
        """
        基线扫描: 列出所有模块的组件目录结构和文件清单
        """
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}  Phase 1: Baseline Scan{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

        modules = {
            "strike": self.project_root / "strike",
            "recon": self.project_root / "recon",
            "assess": self.project_root / "assess",
            "report": self.project_root / "report",
            "tools": self.project_root / "tools",
            "data/seeds": self.project_root / "data" / "seeds",
            "data/scorers": self.project_root / "data" / "scorers",
        }

        total_issues = 0

        for module_name, module_path in modules.items():
            print(f"{Colors.CYAN}Module: {module_name}{Colors.RESET}")
            if not module_path.exists():
                print(f"  {Colors.YELLOW}[WARN] Directory not found{Colors.RESET}")
                continue

            # 查找组件子目录
            found_components: list[str] = []
            for comp in self.all_component_dirs:
                comp_dir = module_path / comp
                if comp_dir.is_dir():
                    py_files = list(comp_dir.glob("*.py"))
                    found_components.append(comp)
                    status = f"{Colors.GREEN}OK{Colors.RESET}"
                    print(f"  [{status}] {comp}/ ({len(py_files)} files)")
                elif comp in self.components:
                    # 核心组件目录缺失
                    print(f"  {Colors.RED}[MISS]{Colors.RESET} {comp}/ (required)")
                    total_issues += 1

            if not found_components:
                print("  (no component subdirectories)")

            print()

        # assess/report 特殊检查 (模块级文件)
        print(f"{Colors.CYAN}Module-level Components:{Colors.RESET}")
        for module_name, expected_files in [
            ("assess", ["component_router.py", "component_scorers.py"]),
            ("report", ["component_reports.py", "component_poc.py"]),
        ]:
            module_path = self.project_root / module_name
            for fname in expected_files:
                fpath = module_path / fname
                if fpath.exists():
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] {module_name}/{fname}")
                else:
                    print(f"  {Colors.RED}[MISS]{Colors.RESET} {module_name}/{fname} (required)")
                    total_issues += 1

        print()
        if total_issues == 0:
            print(f"{Colors.GREEN}[PASS] 基线扫描完成，所有核心组件目录存在{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[WARN] 发现 {total_issues} 个缺失项 (非阻塞，可能为可选组件){Colors.RESET}")

        return 0  # 非阻塞，始终返回成功

    # ──────────────────────────────────────────────────────────────────────
    # Phase 3: T0 Coverage
    # ──────────────────────────────────────────────────────────────────────

    def phase3_t0_coverage(self) -> int:
        """
        T0 Coverage: 检查 assess/component_router.py 的
        分类模式 + T0 检查器是否覆盖所有 6 种核心组件类型
        """
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}  Phase 3: T0 Coverage{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

        total_issues = 0

        # 检查 1: component_router.py 是否存在
        router_path = self.project_root / "assess" / "component_router.py"
        if not router_path.exists():
            print(f"{Colors.RED}[FAIL] assess/component_router.py 不存在{Colors.RESET}")
            return 1

        # 读取文件内容
        router_content = router_path.read_text(encoding="utf-8")

        # 检查 2: _OBJECTIVE_COMPONENT_PATTERNS 是否覆盖所有核心组件
        print(f"{Colors.CYAN}Checking _OBJECTIVE_COMPONENT_PATTERNS coverage:{Colors.RESET}")
        all_pattern_keys = {
            "mcp": "mcp_tool_poisoning",
            "a2a": "a2a_agent_integrity",
            "model": "model_behavior_shift",
            "rag": "rag_pipeline",
            "session": "session_memory",
            "web": "web_api",
        }
        for comp, full_type_name in all_pattern_keys.items():
            if f'"{full_type_name}"' in router_content or f"'{full_type_name}'" in router_content:
                print(f"  [{Colors.GREEN}OK{Colors.RESET}] {comp} ({full_type_name})")
            else:
                # 也检查短名形式
                if f'"{comp}"' in router_content or f"'{comp}'" in router_content:
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] {comp} (short name)")
                else:
                    print(f"  {Colors.RED}[MISS]{Colors.RESET} {comp} ({full_type_name} not found)")
                    total_issues += 1

        print()

        # 检查 3: T0 检查器函数覆盖
        print(f"{Colors.CYAN}Checking T0 checker functions:{Colors.RESET}")
        expected_t0_checkers = {
            "mcp": "t0_mcp_tool_poisoning_check",
            "a2a": "t0_a2a_agent_integrity_check",
            "model": "t0_model_behavior_shift_check",
            "rag": "t0_rag_pipeline_check",
            "session": "t0_session_memory_check",
            "web": "t0_web_api_check",
        }
        scorers_path = self.project_root / "assess" / "component_scorers.py"
        scorers_content = scorers_path.read_text(encoding="utf-8") if scorers_path.exists() else ""
        combined_content = router_content + scorers_content
        for comp, checker_name in expected_t0_checkers.items():
            if checker_name in combined_content:
                print(f"  [{Colors.GREEN}OK{Colors.RESET}] {comp} -> {checker_name}")
            else:
                print(f"  {Colors.RED}[MISS]{Colors.RESET} {comp} -> {checker_name}")
                total_issues += 1

        print()

        # 检查 4: assess/__init__.py 是否导出所有 T0 检查器
        init_path = self.project_root / "assess" / "__init__.py"
        if init_path.exists():
            init_content = init_path.read_text(encoding="utf-8")
            print(f"{Colors.CYAN}Checking assess/__init__.py exports:{Colors.RESET}")
            for _, checker_name in expected_t0_checkers.items():
                if checker_name in init_content:
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] {checker_name} exported")
                else:
                    print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} {checker_name} not in __init__.py")
        else:
            print(f"{Colors.RED}[FAIL] assess/__init__.py 不存在{Colors.RESET}")
            total_issues += 1

        print()

        # 检查 5: 单指标强信号分类覆盖
        print(f"{Colors.CYAN}Checking single-indicator strong-signal classification:{Colors.RESET}")
        if (
            "single-indicator" in router_content.lower()
            or "强信号" in router_content
            or "special case" in router_content.lower()
        ):
            strong_signal_count = 0
            for comp in self.components:
                if comp in router_content.lower():
                    strong_signal_count += 1
            if strong_signal_count >= len(self.components):
                print(f"  [{Colors.GREEN}OK{Colors.RESET}] 强信号分类覆盖全部 {len(self.components)} 种组件")
            else:
                print(
                    f"  {Colors.YELLOW}[WARN]{Colors.RESET} 强信号分类覆盖 {strong_signal_count}/{len(self.components)} 种组件"
                )
        else:
            print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} 未找到明确的强信号分类逻辑")

        print()

        # 检查 6: 元数据推断覆盖
        print(f"{Colors.CYAN}Checking _infer_component_from_metadata coverage:{Colors.RESET}")
        if "_infer_component_from_metadata" in router_content:
            for comp in ["rag_pipeline", "session_memory", "web_api"]:
                if comp in router_content:
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] metadata inference for {comp}")
                else:
                    print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} metadata inference missing for {comp}")
        else:
            print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} _infer_component_from_metadata not found")

        print()

        if total_issues == 0:
            print(f"{Colors.GREEN}[PASS] T0 Coverage 检查完成，所有核心组件路由正常{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[WARN] 发现 {total_issues} 个 T0 覆盖问题{Colors.RESET}")

        return 1 if total_issues > 3 else 0

    # ──────────────────────────────────────────────────────────────────────
    # Phase 4: Scorer/Report Coverage
    # ──────────────────────────────────────────────────────────────────────

    def phase4_scorer_report_coverage(self) -> int:
        """
        Scorer/Report Coverage: 检查 data/scorers/ 和 report/ 的
        组件感知章节覆盖
        """
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}  Phase 4: Scorer/Report Coverage{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

        total_issues = 0

        # 检查 1: data/scorers/component_scorers/ 目录
        scorers_dir = self.project_root / "data" / "scorers" / "component_scorers"
        print(f"{Colors.CYAN}Checking data/scorers/component_scorers/:{Colors.RESET}")
        if scorers_dir.exists():
            for comp in self.components:
                comp_scorers = (
                    list(scorers_dir.glob(f"*{comp}*.yaml"))
                    + list(scorers_dir.glob(f"*{comp}*.yml"))
                    + list(scorers_dir.glob(f"*{comp}*.json"))
                )
                if comp_scorers:
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] {comp} ({len(comp_scorers)} scorer file(s))")
                else:
                    print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} {comp} (no scorer files)")
        else:
            print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} component_scorers/ directory not found")

        print()

        # 检查 2: report/component_reports.py
        comp_reports_path = self.project_root / "report" / "component_reports.py"
        print(f"{Colors.CYAN}Checking report/component_reports.py:{Colors.RESET}")
        if comp_reports_path.exists():
            content = comp_reports_path.read_text(encoding="utf-8")
            for comp in self.components:
                if comp in content:
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] {comp} chapter builder found")
                else:
                    print(f"  {Colors.RED}[MISS]{Colors.RESET} {comp} chapter builder missing")
                    total_issues += 1
        else:
            print(f"  {Colors.RED}[FAIL]{Colors.RESET} component_reports.py not found")
            total_issues += 1

        print()

        # 检查 3: report/component_poc.py
        comp_poc_path = self.project_root / "report" / "component_poc.py"
        print(f"{Colors.CYAN}Checking report/component_poc.py:{Colors.RESET}")
        if comp_poc_path.exists():
            content = comp_poc_path.read_text(encoding="utf-8")
            for comp in self.components:
                if comp in content:
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] {comp} PoC generator found")
                else:
                    print(f"  {Colors.RED}[MISS]{Colors.RESET} {comp} PoC generator missing")
                    total_issues += 1
        else:
            print(f"  {Colors.RED}[FAIL]{Colors.RESET} component_poc.py not found")
            total_issues += 1

        print()

        # 检查 4: core/phases/_component_bridge.py
        bridge_path = self.project_root / "core" / "phases" / "_component_bridge.py"
        print(f"{Colors.CYAN}Checking core/phases/_component_bridge.py:{Colors.RESET}")
        if bridge_path.exists():
            print(f"  [{Colors.GREEN}OK{Colors.RESET}] component bridge exists")
        else:
            print(f"  {Colors.YELLOW}[WARN]{Colors.RESET} component bridge not found")

        print()

        if total_issues == 0:
            print(f"{Colors.GREEN}[PASS] Scorer/Report Coverage 检查完成，所有组件报告和 PoC 覆盖{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[WARN] 发现 {total_issues} 个覆盖问题{Colors.RESET}")

        return 1 if total_issues > 5 else 0

    # ──────────────────────────────────────────────────────────────────────
    # Phase 5: Seed Inventory
    # ──────────────────────────────────────────────────────────────────────

    def phase5_seed_inventory(self) -> int:
        """
        Seed Inventory: data/seeds/ 种子文件数量与组件类型匹配分析
        """
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}  Phase 5: Seed Inventory{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

        seeds_dir = self.project_root / "data" / "seeds"
        if not seeds_dir.exists():
            print(f"{Colors.RED}[FAIL] data/seeds/ not found{Colors.RESET}")
            return 1

        print(f"{Colors.CYAN}Component seed counts:{Colors.RESET}")
        min_seeds_per_component = 3
        total_issues = 0

        for comp in self.components:
            comp_dir = seeds_dir / comp
            if comp_dir.exists():
                seed_files = list(comp_dir.glob("*.prompt"))
                count = len(seed_files)
                if count >= min_seeds_per_component:
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] {comp}: {count} seeds")
                elif count > 0:
                    print(
                        f"  {Colors.YELLOW}[WARN]{Colors.RESET} {comp}: {count} seeds (建议 >= {min_seeds_per_component})"
                    )
                else:
                    print(f"  {Colors.RED}[MISS]{Colors.RESET} {comp}: 0 seeds")
                    total_issues += 1
            else:
                print(f"  {Colors.RED}[MISS]{Colors.RESET} {comp}/ directory not found")
                total_issues += 1

        # 扩展组件 (非阻塞)
        print(f"\n{Colors.CYAN}Extended component seed counts (optional):{Colors.RESET}")
        for comp in self.extended_components:
            comp_dir = seeds_dir / comp
            if comp_dir.exists():
                seed_files = list(comp_dir.glob("*.prompt"))
                print(f"  [INFO] {comp}: {len(seed_files)} seeds")

        print()

        # _attack_surface 种子统计
        attack_surface_dir = seeds_dir / "_attack_surface"
        if attack_surface_dir.exists():
            surface_count = len(list(attack_surface_dir.rglob("*.prompt")))
            print(f"  [INFO] _attack_surface/: {surface_count} seeds")

        print()

        if total_issues == 0:
            print(f"{Colors.GREEN}[PASS] Seed Inventory 检查完成，所有核心组件种子充足{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[WARN] 发现 {total_issues} 个种子不足问题{Colors.RESET}")

        return 1 if total_issues > 2 else 0

    # ──────────────────────────────────────────────────────────────────────
    # Phase 6: Validation Gate
    # ──────────────────────────────────────────────────────────────────────

    def phase6_validation_gate(self) -> int:
        """
        Validation Gate: pytest + guard + architecture_validator 三重验证
        """
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}  Phase 6: Validation Gate{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

        total_issues = 0

        # 6a: pytest component_purity
        print(f"{Colors.CYAN}6a. pytest tests/common/test_component_purity.py{Colors.RESET}")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/common/test_component_purity.py", "-v", "--tb=short"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.project_root),
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode == 0:
                passed_count = result.stdout.count(" PASSED")
                print(f"  [{Colors.GREEN}OK{Colors.RESET}] {passed_count} purity tests passed")
            else:
                failed_count = result.stdout.count(" FAILED")
                print(f"  {Colors.RED}[FAIL]{Colors.RESET} {failed_count} purity tests failed")
                total_issues += failed_count
        except Exception as e:
            print(f"  {Colors.RED}[ERROR]{Colors.RESET} {e}")
            total_issues += 1

        print()

        # 6b: guard
        print(f"{Colors.CYAN}6b. tools/guard.py Architecture Guard{Colors.RESET}")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "tools.guard"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.project_root),
                encoding="utf-8",
                errors="replace",
            )
            blocking_count = result.stdout.count("BLOCKING")
            warning_count = result.stdout.count("WARNING")
            print(f"  [INFO] Guard: BLOCKING={blocking_count}, WARNING={warning_count}")
            if blocking_count > 0:
                print(f"  {Colors.RED}[FAIL]{Colors.RESET} {blocking_count} BLOCKING issues found")
                total_issues += blocking_count
            elif warning_count > 0:
                print(f"  [{Colors.YELLOW}WARN{Colors.RESET}] {warning_count} WARNING (non-blocking)")
        except Exception as e:
            print(f"  {Colors.RED}[ERROR]{Colors.RESET} {e}")
            total_issues += 1

        print()

        # 6c: architecture_validator
        print(f"{Colors.CYAN}6c. tools/architecture_validator.py Architecture Compliance{Colors.RESET}")
        try:
            result = subprocess.run(
                [sys.executable, "tools/architecture_validator.py", "full"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(self.project_root),
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode == 0:
                pass_count = result.stdout.count("PASS")
                warn_count = result.stdout.count("WARNING")
                blocking_count = result.stdout.count("BLOCKING")
                print(f"  [INFO] ArchCheck: PASS={pass_count}, WARNING={warn_count}, BLOCKING={blocking_count}")
                if blocking_count > 0:
                    print(f"  {Colors.RED}[FAIL]{Colors.RESET} {blocking_count} BLOCKING issues")
                    total_issues += blocking_count
                else:
                    print(f"  [{Colors.GREEN}OK{Colors.RESET}] No blocking issues")
            else:
                print(f"  {Colors.RED}[FAIL]{Colors.RESET} architecture_validator exited with code {result.returncode}")
                total_issues += 1
        except FileNotFoundError:
            print(f"  {Colors.YELLOW}[SKIP]{Colors.RESET} architecture_validator.py not found (optional)")
        except Exception as e:
            print(f"  {Colors.RED}[ERROR]{Colors.RESET} {e}")
            total_issues += 1

        print()

        if total_issues == 0:
            print(f"{Colors.GREEN}[PASS] Validation Gate 通过 — 三重验证全绿{Colors.RESET}")
        else:
            print(f"{Colors.RED}[FAIL] Validation Gate 发现 {total_issues} 个问题{Colors.RESET}")

        return 1 if total_issues > 0 else 0


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


# ============================================================================
# 主审计流程
# ============================================================================


def run_component_audit(
    skip: set[str] | None = None,
    only: str | None = None,
    verbose: bool = False,
    fail_fast: bool = True,
) -> int:
    """
    运行完整组件审计流程

    Args:
        skip: 跳过的阶段 ID 集合
        only: 仅执行指定阶段
        verbose: 详细输出
        fail_fast: 失败即停

    Returns:
        0=全部通过, 1=有失败
    """
    print_header(" Component Audit Pipeline (Phase 1→6) ")
    print(f"  Project:      {PROJECT_ROOT}")
    print(f"  Python:       {sys.version.split()[0]}")
    print(f"  Time:         {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Components:   {', '.join(ALL_COMPONENTS)}")
    if skip:
        print(f"  Skip:         {', '.join(sorted(skip))}")

    # 筛选要执行的阶段
    phases_to_run = COMPONENT_AUDIT_PHASES
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
            print(f"{Colors.RED}[FAIL-FAST] Phase {phase.id} failed, stopping pipeline{Colors.RESET}")
            break

    # 打印汇总
    print_summary(results)

    failed = sum(1 for _, ok, _ in results if not ok)
    return 1 if failed > 0 else 0
