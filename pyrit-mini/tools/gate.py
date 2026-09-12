"""PyRIT-mini 统一开发门禁 (Unified Dev Gate) —— 门禁本体（ADR-009 / NFR-20 / NEG-9）。

本文件是 `docs/specs/README.md §2` 六步门禁的**唯一代码实现**，也是命令清单的
**唯一权威**：规约文档只描述"阶段 → 责任"，命令由 `python -m tools.gate --describe`
生成，禁止在文档/hooks/CI 中手抄（C3 / D1，杜绝"文档表 vs 代码实现"孪生漂移）。

阶段划分（裁决：CP-004 §8.7 D-6）：
  commit : 1 guard · 1.5 架构体检 · 2 ruff · 4 dry-run
           （dry-run 是唯一 0-token 的运行时证据，能在秒级发现 ImportError/
             AttributeError/KeyError/TypeError —— 静态 guard 抓不到这一类）
  push   : 上述 + 3 pytest 全量 · 5 drift · 6 dataflow · 7 e2e（存在时）

**禁止静默跳过**（NEG-9 / R-GATE-2）：依赖缺失 = 环境不合格 = 阻塞，不降级为 SKIP。
理由：`--no-verify` 绕过比"晚一点发现"危险得多（40-GUARDRAILS 第三章）。

退出码: 0 = 通过, 1 = 存在阻塞项（commit/push 会被钩子中止）。
"""
from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
_FAILED: list[str] = []

# --- 步骤注册表（唯一权威；--describe 与规约文档均以本表为准） -----------------
STEP_DESCRIPTIONS: dict[str, str] = {
    "guard": "1   静态守卫        python -m tools.guard",
    "architecture": "1.5 架构体检        python tools/architecture_validator.py full",
    "ruff": "2   代码风格        python -m ruff check .",
    "pytest": "3   回归测试        python -m pytest tests/ -q",
    "dry-run": "4   0-token 运行时   python main.py --dry-run --max-seeds 1",
    "drift": "5   规范漂移        python -m tools.drift_detector --full",
    "dataflow": "6   数据流契约      python -m pytest tests/common/test_data_flow_integrity.py -q",
    "e2e": "7   靶场端到端      python -m pytest tests/e2e -q",
}

COMMIT_STEPS: tuple[str, ...] = ("guard", "architecture", "ruff", "dry-run")
PUSH_STEPS: tuple[str, ...] = COMMIT_STEPS + ("pytest", "drift", "dataflow", "e2e")


def _run(name: str, cmd: list[str]) -> None:
    """执行一步门禁。命令不存在 / 返回非零 → 一律阻塞（禁止静默跳过，NEG-9）。"""
    print(f"\n=== {name} ===")
    try:
        rc = subprocess.run(cmd, cwd=str(ROOT), check=False).returncode
    except FileNotFoundError:
        print(f"  [阻塞] 命令不存在: {' '.join(cmd)}（环境不合格，禁止降级为跳过）")
        _FAILED.append(name)
        return
    if rc != 0:
        print(f"  [阻塞] {name} 返回退出码 {rc}")
        _FAILED.append(name)
    else:
        print(f"  [PASS] {name}")


def _guard() -> None:
    _run("guard", [PY, "-m", "tools.guard"])


def _architecture() -> None:
    _run("architecture", [PY, "tools/architecture_validator.py", "full"])


def _ruff() -> None:
    if importlib.util.find_spec("ruff") is None:
        print("\n=== ruff ===")
        print("  [阻塞] ruff 未安装（dev 依赖 ruff>=0.4）→ 环境不合格，禁止降级为跳过")
        _FAILED.append("ruff")
        return
    _run("ruff", [PY, "-m", "ruff", "check", "."])


def _pytest() -> None:
    _run("pytest", [PY, "-m", "pytest", "tests/", "-q"])


def _dry_run() -> None:
    _run("dry-run", [PY, "main.py", "--dry-run", "--max-seeds", "1"])


def _drift() -> None:
    _run("drift", [PY, "-m", "tools.drift_detector", "--full"])


def _dataflow() -> None:
    _run("dataflow", [PY, "-m", "pytest", "tests/common/test_data_flow_integrity.py", "-q"])


def _e2e() -> None:
    """靶场 e2e：目录不存在时显式 INFO 并登记（BL-056），**不静默**也不阻塞。"""
    print("\n=== e2e ===")
    if not (ROOT / "tests" / "e2e").exists():
        print("  [INFO] tests/e2e/ 不存在 → 跳过（已登记 BL-056，REQ-156⑤ 待达成）")
        return
    _run("e2e", [PY, "-m", "pytest", "tests/e2e", "-q"])


def _registry_wiring() -> None:
    print("\n=== registry 接线 ===")
    try:
        sys.path.insert(0, str(ROOT))
        from core.registry import get_registry

        reg = get_registry()
        errors = reg.validate_wiring() or []
        blocking_errors = [
            e for e in errors if str(getattr(e, "severity", "warning")).lower() in ("blocking", "error")
        ]
        if blocking_errors:
            print(f"  [阻塞] registry 接线失败: {blocking_errors}")
            _FAILED.append("registry")
        else:
            warn = len(errors) - len(blocking_errors)
            print(
                f"  [PASS] registry 接线正常（{len(reg.keys())} 个组件键"
                + (f"，{warn} 条 warning 不阻塞" if warn else "")
                + "）"
            )
    except Exception as exc:  # pragma: no cover - 防御性
        print(f"  [阻塞] registry 导入/校验异常: {exc}")
        _FAILED.append("registry")


STEP_RUNNERS = {
    "guard": _guard,
    "architecture": _architecture,
    "ruff": _ruff,
    "pytest": _pytest,
    "dry-run": _dry_run,
    "drift": _drift,
    "dataflow": _dataflow,
    "e2e": _e2e,
}


def _describe() -> None:
    """输出阶段 → 步骤清单（ADR-009：规约文档引用本输出，不手抄命令）。"""
    print("PyRIT-mini 门禁阶段清单（唯一权威 = 本文件 STEP_DESCRIPTIONS）\n")
    for stage, steps in (("commit", COMMIT_STEPS), ("push", PUSH_STEPS)):
        print(f"[{stage}]")
        for step in steps:
            print(f"  {STEP_DESCRIPTIONS.get(step, step)}")
        print()


def main() -> int:
    ap = argparse.ArgumentParser(description="PyRIT-mini 统一开发门禁")
    ap.add_argument(
        "--stage",
        choices=["commit", "push", "all"],
        default="all",
        help="commit=快检(pre-commit) / push=全量(pre-push,CI) / all=全部",
    )
    ap.add_argument(
        "--describe",
        action="store_true",
        help="打印阶段→步骤清单后退出（供规约文档引用，ADR-009）",
    )
    args = ap.parse_args()

    if args.describe:
        _describe()
        return 0

    steps: tuple[str, ...] = COMMIT_STEPS if args.stage == "commit" else PUSH_STEPS
    print(f"=== 门禁阶段: {args.stage}（{len(steps)} 步）===")

    for step in steps:
        STEP_RUNNERS[step]()
    _registry_wiring()

    print("\n" + "=" * 48)
    if _FAILED:
        print(f"[GATE FAIL] 阻塞项: {', '.join(_FAILED)}")
        return 1
    print(f"[GATE PASS] 所有门禁通过（{len(steps)} 步 + registry 接线）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
