"""门禁本体护栏（R-GATE-1~3）——校验 `tools/gate.py` 自身是否合规。

为什么需要：门禁一旦"默默地少跑几步"，C10 的"全部执行、全部通过"就形同虚设，
而这类失效没有任何其他检查器能发现（E-01 即由此长期存在）。本模块把门禁本体
纳入被守护范围。

    R-GATE-1 门禁等价（BLOCKING）：`tools/gate.py` 的阶段步骤必须覆盖规约六步
    R-GATE-2 门禁不得静默跳过（BLOCKING）：不得出现 [SKIP] / 非阻塞 降级分支
    R-GATE-3 hooks 在线性（WARNING）：pre-commit / pre-push 必须已安装

裁决依据：CP-004 §8.7 D-6；NFR-20 / NEG-8~10。
"""

from __future__ import annotations

import re
from pathlib import Path

# 规约六步（README §2）在 gate.py 中的步骤标识
_REQUIRED_STEPS = ("guard", "architecture", "ruff", "pytest", "dry-run", "drift", "dataflow")

# 静默降级的特征串（出现即视为违规）
_SILENT_SKIP_MARKERS = ("非阻塞", "[SKIP]")


def register_gate_checks(guard_cls) -> None:
    """把门禁本体检查器注册到 ArchitectureGuard 类。"""

    from tools.guard_extended import _get_violation_classes

    Severity, Violation = _get_violation_classes()

    def check_gate_stage_parity(self) -> None:
        """R-GATE-1: 门禁阶段步骤必须覆盖规约六步（NFR-20）。"""
        gate_file: Path = self.root / "tools" / "gate.py"
        if not gate_file.exists():
            self.violations.append(
                Violation(
                    rule="R-GATE-1",
                    severity=Severity.BLOCKING,
                    file="tools/gate.py",
                    line=0,
                    description="门禁本体 tools/gate.py 不存在",
                    fix_hint="恢复 tools/gate.py",
                )
            )
            return

        content = gate_file.read_text(encoding="utf-8", errors="replace")
        covered = set(re.findall(r'"(guard|architecture|ruff|pytest|dry-run|drift|dataflow|e2e)"', content))
        missing = [s for s in _REQUIRED_STEPS if s not in covered]
        if missing:
            self.violations.append(
                Violation(
                    rule="R-GATE-1",
                    severity=Severity.BLOCKING,
                    file="tools/gate.py",
                    line=0,
                    description=f"门禁未覆盖规约步骤: {missing}（违反 NFR-20 / C10）",
                    fix_hint="在 COMMIT_STEPS / PUSH_STEPS 中补齐缺失步骤",
                )
            )

    def check_gate_no_silent_skip(self) -> None:
        """R-GATE-2: 门禁内禁止把失败/缺依赖降级为非阻塞（NEG-9 / R-H1）。"""
        gate_file: Path = self.root / "tools" / "gate.py"
        if not gate_file.exists():
            return
        for lineno, line in enumerate(
            gate_file.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for marker in _SILENT_SKIP_MARKERS:
                if marker in stripped:
                    self.violations.append(
                        Violation(
                            rule="R-GATE-2",
                            severity=Severity.BLOCKING,
                            file="tools/gate.py",
                            line=lineno,
                            description=f"门禁存在静默降级分支（含 {marker!r}）",
                            fix_hint="依赖缺失/命令不存在必须阻塞，不得降级为跳过",
                        )
                    )
                    break

    def check_hooks_installed(self) -> None:
        """R-GATE-3: Git 钩子必须已安装（README §2.1 三层防线的 L3）。"""
        hooks_dir = self.root / ".git" / "hooks"
        missing = [name for name in ("pre-commit", "pre-push") if not (hooks_dir / name).exists()]
        if missing:
            self.violations.append(
                Violation(
                    rule="R-GATE-3",
                    severity=Severity.WARNING,
                    file=".git/hooks",
                    line=0,
                    description=f"Git 钩子未安装: {missing}（三层防线实际只有两层）",
                    fix_hint="运行 python -m tools.hooks 安装；无法安装时须在任务汇报声明",
                )
            )

    guard_cls.check_gate_stage_parity = check_gate_stage_parity
    guard_cls.check_gate_no_silent_skip = check_gate_no_silent_skip
    guard_cls.check_hooks_installed = check_hooks_installed
