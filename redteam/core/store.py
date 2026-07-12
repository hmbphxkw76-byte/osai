"""结果 JSON 持久化（checkpoint 续跑）。

阶段间以 JSON 落盘，单阶段失败不影响其余阶段。
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .models import ReconResult, Finding

DEFAULT_STORE_DIR = Path("reports")


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


def _run_dir(store_dir: Path, run_id: str) -> Path:
    d = store_dir / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_json(run_id: str, name: str, data: Any, store_dir: Path = DEFAULT_STORE_DIR) -> Path:
    d = _run_dir(store_dir, run_id)
    p = d / f"{name}.json"
    p.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, default=_default),
        encoding="utf-8",
    )
    return p


def load_json(run_id: str, name: str, store_dir: Path = DEFAULT_STORE_DIR) -> Any:
    p = store_dir / run_id / f"{name}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def save_recon(run_id: str, result: ReconResult, store_dir: Path = DEFAULT_STORE_DIR) -> Path:
    return save_json(run_id, "recon", result.model_dump(), store_dir)


def load_recon(run_id: str, store_dir: Path = DEFAULT_STORE_DIR) -> ReconResult | None:
    data = load_json(run_id, "recon", store_dir)
    return ReconResult(**data) if data else None


def save_findings(run_id: str, findings: list[Finding], store_dir: Path = DEFAULT_STORE_DIR) -> Path:
    return save_json(run_id, "findings", [f.model_dump() for f in findings], store_dir)


def load_findings(run_id: str, store_dir: Path = DEFAULT_STORE_DIR) -> list[Finding]:
    data = load_json(run_id, "findings", store_dir) or []
    return [Finding(**d) for d in data]
