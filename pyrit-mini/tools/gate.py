"""PyRIT-mini 统一开发门禁 (Unified Dev Gate).

本文件是 docs/specs/README.md §2 门禁的**唯一代码入口 (SSOT)**。
所有门禁都通过它执行，避免命令在文档/钩子/CI 间抄写漂移。

阶段 (stage):
  commit : ruff + guard + registry 接线   —— pre-commit 钩子执行（快）
  push   : + drift --full + 数据流契约测试 —— pre-push 钩子 / CI 执行
  all    : 以上全部（默认；CI 使用）

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


def _run(name: str, cmd: list[str], *, blocking: bool = True) -> None:
    print(f"\n=== {name} ===")
    try:
        rc = subprocess.run(cmd, cwd=str(ROOT), check=False).returncode
    except FileNotFoundError:
        print(f"  [SKIP] 命令不存在: {cmd[0]}（视为非阻塞）")
        return
    if rc != 0:
        tag = "阻塞" if blocking else "警告(非阻塞)"
        print(f"  [{tag}] {name} 返回退出码 {rc}")
        if blocking:
            _FAILED.append(name)
    else:
        print(f"  [PASS] {name}")


def _ruff(*, blocking: bool = True) -> None:
    if importlib.util.find_spec("ruff") is None:
        print("\n=== ruff ===\n  [SKIP] ruff 未安装（dev 依赖 ruff>=0.4），跳过（非阻塞）")
        return
    _run("ruff", [PY, "-m", "ruff", "check", "."], blocking=blocking)


def _registry_wiring(*, blocking: bool = True) -> None:
    print("\n=== registry 接线 ===")
    try:
        sys.path.insert(0, str(ROOT))
        from core.registry import get_registry

        reg = get_registry()
        errors = reg.validate_wiring()
        # validate_wiring() 返回 list[WiringError]；空列表 = 接线完整。
        # 仅 blocking/error 级别阻塞提交；warning 级别（规划中模块尚未落地）不阻塞。
        if errors is None:
            errors = []
        blocking_errors = [
            e
            for e in errors
            if str(getattr(e, "severity", "warning")).lower() in ("blocking", "error")
        ]
        if blocking_errors:
            print(f"  [阻塞] registry 接线失败: {blocking_errors}")
            if blocking:
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
        if blocking:
            _FAILED.append("registry")


def main() -> int:
    ap = argparse.ArgumentParser(description="PyRIT-mini 统一开发门禁")
    ap.add_argument(
        "--stage",
        choices=["commit", "push", "all"],
        default="all",
        help="commit=快检(pre-commit) / push=全量(pre-push,CI) / all=全部",
    )
    args = ap.parse_args()
    stage = args.stage
    do_push = stage in ("push", "all")

    if stage in ("commit", "all"):
        _ruff(blocking=True)
        _run("guard", [PY, "-m", "tools.guard"], blocking=True)
        _registry_wiring(blocking=True)
    if do_push:
        _run("drift", [PY, "-m", "tools.drift_detector", "--full"], blocking=True)
        _run(
            "data-flow",
            [PY, "-m", "pytest", "tests/common/test_data_flow_integrity.py", "-q"],
            blocking=True,
        )

    print("\n" + "=" * 48)
    if _FAILED:
        print(f"[GATE FAIL] 阻塞项: {', '.join(_FAILED)}")
        return 1
    print("[GATE PASS] 所有门禁通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
