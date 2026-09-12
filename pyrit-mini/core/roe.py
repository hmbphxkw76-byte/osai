"""core/roe.py — Rules of Engagement（授权文件）加载与校验（REQ-163 / R-ROE-1）。

OffSec 行业标准（PTES Pre-engagement / OWASP AI Testing Guide）要求红队工具在架构层
内置授权控制。本模块提供**授权文件**形态的 RoE：

    authorization_ref: "ROE-2026-042"      # 授权编号（审计追溯）
    targets: ["example.com", "*.example.com"]
    valid_from: "2026-09-01"               # 授权开始（含）
    valid_until: "2026-09-30"              # 授权结束（含）

设计约束：
    - 纯标准库（NEG-4）；YAML 走既有 PyYAML 依赖。
    - **默认行为不变**：只有显式提供 `--roe-file` 才加载；只有 `--require-roe`
      才在缺失/失效时拒绝启动。既有运行路径零回归。
    - 校验失败一律返回**问题清单**（不抛异常），由调用方决定拒绝或降级留痕。

学术/标准依据：
    - PTES Pre-engagement Interactions
    - OWASP AI Testing Guide（authorization / scope 前置）
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ROEPolicy:
    """Parsed Rules-of-Engagement document."""

    authorization_ref: str = ""
    targets: list[str] = field(default_factory=list)
    valid_from: str = ""
    valid_until: str = ""
    notes: str = ""
    source_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_ref": self.authorization_ref,
            "targets": list(self.targets),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "notes": self.notes,
            "source_path": self.source_path,
        }


def _as_date(value: Any) -> date | None:
    """Parse ISO date or datetime (with/without timezone) into a date."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def load_roe_file(path: str | Path) -> ROEPolicy:
    """Load a RoE document (YAML or JSON). Raises FileNotFoundError/ValueError."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    data: Any
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        data = json.loads(stripped)
    else:
        import yaml

        data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"RoE 文件必须是映射结构（dict）：{p}")
    if isinstance(data.get("roe"), dict):
        data = data["roe"]

    targets = data.get("targets") or data.get("authorized_targets") or []
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split(",") if t.strip()]

    return ROEPolicy(
        authorization_ref=str(data.get("authorization_ref") or data.get("ref") or ""),
        targets=[str(t) for t in targets],
        valid_from=str(data.get("valid_from") or data.get("not_before") or ""),
        valid_until=str(data.get("valid_until") or data.get("not_after") or ""),
        notes=str(data.get("notes") or ""),
        source_path=str(p),
    )


def validate_roe(policy: ROEPolicy, *, now: datetime | None = None) -> list[str]:
    """Return a list of problems (empty = valid). Never raises.

    Checks: authorization ref present; at least one target; validity window
    (missing bounds are tolerated but reported as warnings).
    """
    problems: list[str] = []
    if not policy.authorization_ref:
        problems.append("缺少 authorization_ref（授权编号），无法审计追溯")
    if not policy.targets:
        problems.append("缺少 targets（授权目标清单），无法进行范围锁定")

    today = (now or datetime.now(timezone.utc)).date()
    start = _as_date(policy.valid_from)
    end = _as_date(policy.valid_until)

    if start is None and policy.valid_from:
        problems.append(f"valid_from 无法解析：{policy.valid_from!r}")
    if end is None and policy.valid_until:
        problems.append(f"valid_until 无法解析：{policy.valid_until!r}")

    if start is not None and today < start:
        problems.append(f"授权尚未生效（valid_from={start.isoformat()}，今日 {today.isoformat()}）")
    if end is not None and today > end:
        problems.append(f"授权已过期（valid_until={end.isoformat()}，今日 {today.isoformat()}）")
    return problems


def merge_authorized_targets(existing: Any, policy: ROEPolicy) -> list[str]:
    """Union the existing authorized list with the RoE targets (order-preserving)."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in list(existing or []) + list(policy.targets or []):
        host = str(raw).strip().lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out
