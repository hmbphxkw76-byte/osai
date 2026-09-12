"""REQ-151 PlaybookEngine — 以"步骤选 adapter"为本质的攻击编排层。

设计要点（对齐 REQ-151 / BL-031 / BL-037）：
- 每个 playbook 由有序 `steps` 组成；每步声明 `adapter`（TargetAdapter 种类）与
  `action`（对 adapter 的语义动作）。编排层**不含**任何攻击技巧实现 —— 技巧全部在
  `recon/adapters` / `strike/targets` 内（REQ-149），符合"单一职责、无第二套链机制"。
- adapter 经 `recon.adapters.build_adapter` 解析（IC-2）：http/sse/jsonrpc/multipart 走通用
  适配层；mcp/rag/a2a 走 `strike.targets` 的 Target 实现。
- playbook 以 YAML 声明，统一置于 `config/playbooks/`；`depends_on` 支持简单 DAG 排序。
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from recon import adapters

logger = logging.getLogger(__name__)


@dataclass
class PlaybookStep:
    name: str
    adapter: str
    action: str = "send"
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)


@dataclass
class Playbook:
    name: str
    description: str
    steps: list[PlaybookStep]


@dataclass
class StepResult:
    name: str
    adapter: str
    action: str
    status: str
    text: str = ""
    data: dict[str, Any] = field(default_factory=dict)


def load_playbook(path: str | Path) -> Playbook:
    """Load a single playbook YAML."""
    path = Path(path)
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    steps = [
        PlaybookStep(
            name=s.get("name", f"step{i}"),
            adapter=s["adapter"],
            action=s.get("action", "send"),
            params=s.get("params", {}) or {},
            depends_on=s.get("depends_on", []) or [],
        )
        for i, s in enumerate(doc.get("steps", []))
    ]
    return Playbook(name=doc.get("name", path.stem), description=doc.get("description", ""), steps=steps)


def load_playbooks(directory: str | Path) -> dict[str, Playbook]:
    """Load all `*.yaml` playbooks in a directory keyed by name."""
    directory = Path(directory)
    out: dict[str, Playbook] = {}
    if directory.is_dir():
        for p in sorted(directory.glob("*.yaml")):
            pb = load_playbook(p)
            out[pb.name] = pb
    return out


def _order_steps(steps: list[PlaybookStep]) -> list[PlaybookStep]:
    """Topological order by `depends_on` (Kahn); cycles fall back to declaration order."""
    names = {s.name for s in steps}
    indeg = {s.name: 0 for s in steps}
    adj: dict[str, list[str]] = {s.name: [] for s in steps}
    index = {s.name: s for s in steps}
    for s in steps:
        for dep in s.depends_on:
            if dep in names and dep != s.name:
                adj[dep].append(s.name)
                indeg[s.name] += 1
    ordered: list[PlaybookStep] = []
    ready = [n for n in indeg if indeg[n] == 0]
    while ready:
        n = ready.pop(0)
        ordered.append(index[n])
        for m in adj[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                ready.append(m)
    if len(ordered) < len(steps):  # cycle guard
        seen = {s.name for s in ordered}
        ordered.extend(s for s in steps if s.name not in seen)
    return ordered


def _first_tool(by_name: dict[str, StepResult]) -> str:
    for r in by_name.values():
        tools = r.data.get("tools") if isinstance(r.data, dict) else None
        if isinstance(tools, list) and tools:
            first = tools[0]
            return first.get("name", "") if isinstance(first, dict) else str(first)
    return ""


def _resp_data(resp: Any) -> dict[str, Any]:
    data = getattr(resp, "data", None)
    if not isinstance(data, dict):  # BaseAdapter 归一响应用 `.payload` 承载结构化结果
        data = getattr(resp, "payload", None)
    return data if isinstance(data, dict) else {}


class PlaybookEngine:
    """Execute a playbook: build the per-step TargetAdapter and dispatch its action."""

    def __init__(self, verify: bool = False) -> None:
        self._verify = verify

    async def run(
        self,
        playbook: Playbook,
        base_url: str,
        prompt: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> list[StepResult]:
        results: list[StepResult] = []
        by_name: dict[str, StepResult] = {}
        for step in _order_steps(playbook.steps):
            adapter = adapters.build_adapter(
                url=base_url,
                kind=step.adapter,
                headers=headers,
                timeout=timeout,
                verify=self._verify,
            )
            try:
                text, data = await self._dispatch(adapter, step, prompt, by_name)
                status = "ok"
            except Exception as e:  # 单步失败不阻断整条 playbook（优雅降级）
                logger.warning("Playbook step '%s' failed: %s", step.name, e)
                text, data, status = "", {"error": str(e)}, "error"
            results.append(
                StepResult(
                    name=step.name, adapter=step.adapter, action=step.action,
                    status=status, text=text, data=data,
                )
            )
            by_name[step.name] = results[-1]
            try:
                closer = adapter.close
                if inspect.iscoroutinefunction(closer):
                    await closer()
                else:
                    closer()
            except Exception:
                pass
        return results

    @staticmethod
    async def _dispatch(
        adapter: Any, step: PlaybookStep, prompt: str, by_name: dict[str, StepResult]
    ) -> tuple[str, dict[str, Any]]:
        action = step.action
        if action == "send":
            resp = await adapter.send(prompt)
            return (resp.text or "", _resp_data(resp))
        method = getattr(adapter, action, None)
        if not callable(method):  # 未知动作回退到 send
            resp = await adapter.send(prompt)
            return (resp.text or "", _resp_data(resp))
        # 语义动作派发（REQ-149 Target 提供同名方法）
        if action == "call_tool":
            tool = step.params.get("tool") or _first_tool(by_name)
            out = await method(tool, step.params.get("arguments", {}))
        elif action in ("handshake", "list_tools", "fetch_agent_card"):
            out = await method()
        elif action in ("query", "send_task"):
            out = await method(prompt)
        else:
            out = await method(prompt)
        if isinstance(out, dict):
            return (str(out.get("status") or out.get("text") or ""), out)
        if action == "list_tools" and isinstance(out, list):  # 工具清单归一，供后续 call_tool 动态解析
            return (str(out), {"tools": out})
        return (str(out), {})
