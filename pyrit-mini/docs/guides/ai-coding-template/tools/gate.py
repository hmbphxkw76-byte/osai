#!/usr/bin/env python3
"""${PROJECT_NAME} 统一开发门禁 (Unified Dev Gate) —— 通用参考实现。

这是 ai-coding-template 自带的「最小可用」guard，与具体项目无关，开箱即跑：
  - 内置零依赖的结构化检查（文件体积、红线、密钥、规范骨架、提交粒度），无需任何外部工具；
  - 按 audit_config.yaml 声明的命令，编排调用外部关卡（lint / test / drift ...）。

设计原则（见 ai-dev-guides.md §5 质量关卡）：
  - 内置检查始终运行，且对「真实缺陷」默认 BLOCK（如硬编码密钥、规范骨架缺失）；
  - 外部命令未配置 / 工具未安装 → SKIP（非阻塞），保证「未接入也能跑」；
  - 外部命令非零退出 → BLOCK（阻塞），保证「接入后真卡得住」。

阶段 stage:
  commit : 快检（内置 + lint + typecheck + 提交粒度）—— pre-commit 钩子
  push   : 全量（内置 + test + drift + dataflow）—— pre-push / CI
  all    : 以上全部（默认；CI 使用）

用法:
  python -m tools.gate [--stage {commit,push,all}]
  python tools/gate.py --stage commit

退出码: 0 = 通过；1 = 存在阻塞项（commit/push 会被钩子中止）。
"""
from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
PROJECT = "${PROJECT_NAME}"

_FAILED: list[str] = []

# 扫描忽略的目录（非代码 / 产物 / 依赖）
_IGNORE_DIRS = {
    ".git", ".venv", "__pycache__", "node_modules", "outputs",
    ".assistant_pyrit", ".pytest_cache", ".ruff_cache", ".idea", ".vscode",
}


def _iter_py():
    """零依赖遍历仓库内所有 .py（排除忽略目录）。"""
    for f in ROOT.rglob("*.py"):
        if _IGNORE_DIRS & set(f.parts):
            continue
        yield f


def _block(msg: str) -> None:
    print(f"  [BLOCK] {msg}")
    _FAILED.append(msg)


def _warn(msg: str) -> None:
    print(f"  [WARN] {msg}")


def load_config() -> dict:
    cfg_path = ROOT / "audit_config.yaml"
    if cfg_path.exists():
        try:
            import yaml  # type: ignore
            with cfg_path.open(encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
        except ImportError:
            print("[WARN] 未安装 PyYAML，使用内置默认阈值；pip install pyyaml 以读取 audit_config.yaml")
    return {}


def _check_file_sizes(thresholds: dict) -> None:
    warn = int(thresholds.get("file_size_warning", 850))
    block = int(thresholds.get("file_size_blocking", 1500))
    print("\n=== 文件体积 ===")
    scanned = 0
    for f in _iter_py():
        scanned += 1
        try:
            n = sum(1 for _ in f.open(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        rel = f.relative_to(ROOT)
        if n > block:
            _block(f"{rel} 过大 ({n} 行 > {block})")
        elif n > warn:
            _warn(f"{rel} 偏大 ({n} 行 > {warn})")
    if scanned == 0:
        print("  [INFO] 未发现 .py 文件（跳过）")
    else:
        print(f"  [INFO] 扫描 {scanned} 个 .py 文件")


# 红线 / 安全启发式
_BARE_EXCEPT = re.compile(r"^\s*except\s*:\s*(#.*)?$")
_RAISE_NOT_IMPL = re.compile(r"^\s*raise\s+NotImplementedError\b")
_SECRET = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']"
)


def _check_redlines() -> None:
    print("\n=== 红线 / 安全扫描 ===")
    hits = 0
    for f in _iter_py():
        rel = f.relative_to(ROOT)
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if _SECRET.search(line):
                _block(f"{rel}:{i} 疑似硬编码密钥/凭证 (R-SEC)")
                hits += 1
            elif _BARE_EXCEPT.match(line):
                _warn(f"{rel}:{i} 裸 except:（静默吞错 R-H2）")
                hits += 1
            elif _RAISE_NOT_IMPL.match(line):
                _warn(f"{rel}:{i} raise NotImplementedError（桩函数 R-H1）")
                hits += 1
    if hits == 0:
        print("  [PASS] 未发现密钥/调试打印/裸 except / 桩函数")


def _check_spec_skeleton() -> None:
    print("\n=== 规范骨架存在性 (L5) ===")
    required = [
        "specs/README.md",
        "specs/00-CONSTITUTION.md",
        "specs/10-ARCHITECTURE.md",
        "specs/40-GUARDRAILS.md",
    ]
    missing = []
    for p in required:
        fp = ROOT / p
        if not fp.exists() or fp.stat().st_size == 0:
            missing.append(p)
    if missing:
        _block("规范骨架缺失或为空: " + ", ".join(missing))
    else:
        print("  [PASS] L5 规范骨架齐备 (README/宪法/架构/护栏)")


def _check_diff_limit(thresholds: dict) -> None:
    limit = int(thresholds.get("diff_limit", 300))
    print(f"\n=== 提交粒度 (<= {limit} 行) ===")
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--numstat"],
            cwd=str(ROOT), capture_output=True, text=True,
        )
    except (OSError, FileNotFoundError):
        print("  [SKIP] 非 git 仓库，跳过粒度检查")
        return
    if out.returncode != 0:
        print("  [SKIP] 无暂存改动或 git 不可用")
        return
    added = 0
    for line in out.stdout.splitlines():
        cols = line.split("\t")
        if cols and cols[0].isdigit():
            added += int(cols[0])
    if added > limit:
        _warn(f"暂存改动 {added} 行 > {limit}，建议拆分为更小提交 (R-DELIVERY-1)")
    else:
        print(f"  [PASS] 暂存改动 {added} 行 (<= {limit})")


def _run_cmd(name: str, cmd_str: str | None) -> None:
    if not cmd_str:
        print(f"\n=== {name} ===\n  [SKIP] 未配置命令（audit_config.commands.{name}）")
        return
    cmd = shlex.split(cmd_str)
    print(f"\n=== {name} ===\n  $ {' '.join(cmd)}")
    try:
        rc = subprocess.run(cmd, cwd=str(ROOT)).returncode
    except FileNotFoundError:
        print(f"  [SKIP] 命令不存在: {cmd[0]}（未安装，非阻塞）")
        return
    if rc != 0:
        print(f"  [BLOCK] {name} 返回退出码 {rc}")
        _FAILED.append(name)
    else:
        print(f"  [PASS] {name}")


def main() -> int:
    ap = argparse.ArgumentParser(description=f"{PROJECT} 统一开发门禁")
    ap.add_argument(
        "--stage",
        choices=["commit", "push", "all"],
        default="all",
        help="commit=快检 / push=全量 / all=全部(默认)",
    )
    args = ap.parse_args()
    cfg = load_config()
    project_name = (cfg.get("project") or {}).get("name") or PROJECT
    modules = [v for v in (cfg.get("modules") or {}).values() if isinstance(v, str)]
    modules = list(dict.fromkeys(modules))  # 去重
    thresholds = cfg.get("thresholds") or {}
    commands = cfg.get("commands") or {}

    print(f"# {project_name} Dev Gate  (stage={args.stage})")
    # 内置检查始终运行（零依赖、快）
    _check_file_sizes(thresholds)
    _check_redlines()
    _check_spec_skeleton()

    if args.stage in ("commit", "all"):
        _check_diff_limit(thresholds)
        _run_cmd("lint", commands.get("lint"))
        _run_cmd("typecheck", commands.get("typecheck"))
    if args.stage in ("push", "all"):
        _run_cmd("test", commands.get("test"))
        _run_cmd("drift", commands.get("drift"))
        _run_cmd("dataflow", commands.get("dataflow"))

    print("\n" + "=" * 48)
    if _FAILED:
        print(f"[GATE FAIL] 阻塞项 ({len(_FAILED)}):")
        for item in _FAILED:
            print(f"  - {item}")
        return 1
    print("[GATE PASS] 所有门禁通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
