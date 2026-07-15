"""结果 JSON 持久化（checkpoint 续跑）。

阶段间以 JSON 落盘，单阶段失败不影响其余阶段。

目录结构（v2.0+）：
    results/{run_id}/                    ← 原始攻击数据（中间产物）
    ├── recon/          # 侦察产物（recon.json, services.json, attack_chain_*.json, ...）
    ├── detect/         # 检测阶段 Findings（线索型，含 JudgeVerdict 评分）
    ├── exploit/        # 利用证明 Findings（升级后含 exploitation_proof + verified）
    └── AI300_Report.md # 自动生成的中间报告

    reports/{run_id}/                    ← 正式提交报告（从 results/ 加工产出）
    └── AI300_Report.md # 精加工后的最终报告

向后兼容：load_json/load_findings 自动扫描根目录 + recon/detect/exploit 子目录。
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .models import ReconResult, Finding

DEFAULT_STORE_DIR = Path("results")

# 自动扫描子目录优先级（recon → detect → exploit）
_AUTO_SCAN_SUBDIRS = ("recon", "detect", "exploit")


def make_run_id(target: str, short_id: str, timestamp: str | None = None) -> str:
    """生成可追踪的 run_id：{sanitized_target}_{timestamp}_{short_id}。

    Example:
        make_run_id("http://192.168.0.25:11434", "a1b2c3d4")
        # -> "192.168.0.25_11434_20260712_143052_a1b2c3d4"
    """
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target.replace("://", "_"))
    if timestamp is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
    return f"{safe}_{timestamp}_{short_id}"


def _default(o: Any) -> Any:
    if hasattr(o, "model_dump"):
        return o.model_dump()
    if isinstance(o, (set,)):
        return list(o)
    return str(o)


def _run_dir(store_dir: Path, run_id: str, subdir: str | None = None) -> Path:
    """创建 run 目录（含可选子目录）。

    Args:
        store_dir: 结果根目录（默认 results/）
        run_id: 运行 ID（含目标 + 时间戳）
        subdir: 可选子目录（"recon" / "detect" / "exploit"），None 时为根目录
    """
    d = store_dir / run_id
    if subdir:
        d = d / subdir
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_json(
    run_id: str,
    name: str,
    data: Any,
    store_dir: Path = DEFAULT_STORE_DIR,
    subdir: str | None = None,
) -> Path:
    """将数据序列化为 JSON 文件。

    Args:
        run_id: 运行 ID
        name: 文件名（不含 .json 后缀）
        data: 可序列化数据
        store_dir: 报告根目录
        subdir: 可选子目录（"recon" / "detect" / "exploit"）
    """
    d = _run_dir(store_dir, run_id, subdir)
    p = d / f"{name}.json"
    p.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, default=_default),
        encoding="utf-8",
    )
    return p


def load_json(
    run_id: str,
    name: str,
    store_dir: Path = DEFAULT_STORE_DIR,
    subdir: str | None = None,
) -> Any:
    """从 JSON 文件加载数据。

    读取策略（三级回退）：
    1. 若明确指定 subdir → 先读取 subdir/name.json，找不到则回退根目录
    2. 未指定 subdir → 先读取根目录（向后兼容旧 run），
       再自动扫描 recon → detect → exploit 子目录

    Args:
        run_id: 运行 ID
        name: 文件名（不含 .json 后缀）
        store_dir: 报告根目录
        subdir: 可选子目录，None 时自动扫描
    """
    # 策略 1：明确指定 subdir
    if subdir:
        p = store_dir / run_id / subdir / f"{name}.json"
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
        # 回退到根目录（向后兼容）
        fallback = store_dir / run_id / f"{name}.json"
        if fallback.exists():
            return json.loads(fallback.read_text(encoding="utf-8"))
        return None

    # 策略 2：自动扫描（根目录 → 子目录）
    root_p = store_dir / run_id / f"{name}.json"
    if root_p.exists():
        return json.loads(root_p.read_text(encoding="utf-8"))

    for sd in _AUTO_SCAN_SUBDIRS:
        sp = store_dir / run_id / sd / f"{name}.json"
        if sp.exists():
            return json.loads(sp.read_text(encoding="utf-8"))
    return None


def save_recon(
    run_id: str,
    result: ReconResult,
    store_dir: Path = DEFAULT_STORE_DIR,
    subdir: str = "recon",
) -> Path:
    """保存侦察结果到 recon/ 子目录。"""
    return save_json(run_id, "recon", result.model_dump(), store_dir, subdir=subdir)


def load_recon(
    run_id: str,
    store_dir: Path = DEFAULT_STORE_DIR,
    subdir: str | None = None,
) -> ReconResult | None:
    """加载侦察结果（自动扫描根目录 + recon/ 子目录）。"""
    data = load_json(run_id, "recon", store_dir, subdir=subdir)
    return ReconResult(**data) if data else None


def save_findings(
    run_id: str,
    findings: list[Finding],
    store_dir: Path = DEFAULT_STORE_DIR,
    subdir: str | None = None,
) -> Path:
    """保存 Findings 列表。

    Args:
        run_id: 运行 ID
        findings: Finding 列表
        store_dir: 报告根目录
        subdir: 子目录 — "detect"（检测阶段线索型）或 "exploit"（利用证明升级后）
    """
    return save_json(
        run_id, "findings",
        [f.model_dump() for f in findings],
        store_dir, subdir=subdir,
    )


def load_findings(
    run_id: str,
    store_dir: Path = DEFAULT_STORE_DIR,
    subdir: str | None = None,
) -> list[Finding]:
    """加载 Findings 列表（自动扫描根目录 + detect/exploit 子目录）。

    Args:
        run_id: 运行 ID
        store_dir: 报告根目录
        subdir: 指定子目录，None 时自动扫描（根 → detect → exploit）
    """
    data = load_json(run_id, "findings", store_dir, subdir=subdir) or []
    return [Finding(**d) for d in data]
