"""Julius-style declarative probe-pack engine (Python port of Praetorian's Go matcher).

P0-2: Reproduces the RedAmon probe_pack_engine.py semantics:
  - Probes are declared as YAML packs (data/probe_packs/*.yaml)
  - Each Probe has requests + match rules (status_code / body_contains / header / json_path)
  - MatchRule matching is AND-combined
  - models.extract performs jq-style JSON path extraction (.field / .field[] / .a.b)

This is a thin, dependency-free reimplementation of the Go matcher logic.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml


@dataclass
class MatchRule:
    """A single matcher rule. All rules within a probe are AND-combined."""
    status_code: int | None = None
    body_contains: list[str] = field(default_factory=list)
    header: dict[str, str] = field(default_factory=dict)
    json_path: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MatchRule":
        return cls(
            status_code=d.get("status_code"),
            body_contains=d.get("body_contains", []) or [],
            header=d.get("header", {}) or {},
            json_path=d.get("json_path", {}) or {},
        )


@dataclass
class ProbeRequest:
    path: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProbeRequest":
        return cls(
            path=d["path"],
            method=d.get("method", "GET").upper(),
            headers=d.get("headers", {}) or {},
            body=d.get("body"),
        )


@dataclass
class Probe:
    name: str
    requests: list[ProbeRequest]
    match: MatchRule
    interface: str | None = None
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Probe":
        reqs = [ProbeRequest.from_dict(r) for r in d.get("requests", [])]
        if not reqs:
            # Allow a single top-level path/method for brevity
            reqs = [ProbeRequest.from_dict(d)]
        return cls(
            name=d["name"],
            requests=reqs,
            match=MatchRule.from_dict(d.get("match", {})),
            interface=d.get("interface"),
            description=d.get("description", ""),
        )


@dataclass
class ProbeResult:
    name: str
    matched: bool
    url: str
    status_code: int | None = None
    interface: str | None = None
    extracted: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "matched": self.matched,
            "url": self.url,
            "status_code": self.status_code,
            "interface": self.interface,
            "extracted": self.extracted,
            "error": self.error,
        }


def load_probe_packs(packs_dir: str | Path) -> list[Probe]:
    """Recursively load all YAML probe packs under packs_dir.

    P0-2-B: Returns a flat list of Probe objects across all YAML files.
    """
    packs_dir = Path(packs_dir)
    probes: list[Probe] = []
    if not packs_dir.exists():
        return probes
    for yaml_file in sorted(packs_dir.rglob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:  # pragma: no cover - defensive
            print(f"[probe_pack] skipped {yaml_file}: {exc}")
            continue
        if not data:
            continue
        for entry in data.get("probes", []):
            probes.append(Probe.from_dict(entry))
    return probes


def _extract(path: str, obj: Any) -> Any:
    """jq-style extraction: '.a.b' or '.a.b[]' (P0-2-D)."""
    if not path.startswith("."):
        path = "." + path
    cur: Any = obj
    parts = [p for p in path.split(".") if p and p != "[]"]
    for part in parts:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_rule(rule: MatchRule, status_code: int | None, body: str,
                headers: dict[str, str], parsed: Any) -> bool:
    if rule.status_code is not None:
        if status_code != rule.status_code:
            return False
    for needle in rule.body_contains:
        if needle not in body:
            return False
    for h_key, h_val in rule.header.items():
        if headers.get(h_key, "").lower() != h_val.lower():
            return False
    for jp, expected in rule.json_path.items():
        got = _extract(jp, parsed)
        if got is None:
            return False
        if isinstance(expected, str) and expected.startswith("~"):
            # regex match
            import re
            if not re.search(expected[1:], str(got)):
                return False
        elif got != expected:
            return False
    return True


def run_probe_packs(
    probes: list[Probe],
    requester: Callable[[ProbeRequest], dict[str, Any]],
) -> list[ProbeResult]:
    """Run each probe against the target via a requester callback. P0-2-C.

    Args:
        probes: Loaded probe definitions.
        requester: Callable taking a ProbeRequest and returning a response dict
            with keys: body (str), status_code (int), headers (dict[str, str]).
            The requester performs the actual network I/O (e.g. via httpx),
            so this engine stays synchronous and unit-testable.

    Returns:
        List of ProbeResult across all probes/requests.
    """
    results: list[ProbeResult] = []
    for probe in probes:
        for req in probe.requests:
            try:
                resp = requester(req)
            except Exception as exc:  # noqa: BLE001 - network failures are non-fatal
                results.append(ProbeResult(probe.name, False, req.path, error=str(exc)))
                continue
            body = resp.get("body", "") or ""
            status_code = resp.get("status_code")
            headers = {k.lower(): str(v) for k, v in (resp.get("headers", {}) or {}).items()}
            parsed: Any = None
            try:
                parsed = json.loads(body) if body else None
            except (json.JSONDecodeError, ValueError):
                parsed = None
            matched = _match_rule(probe.match, status_code, body, headers, parsed)
            extracted: dict[str, Any] = {}
            if parsed and isinstance(parsed, dict):
                for jp in probe.match.json_path.keys():
                    extracted[jp] = _extract(jp, parsed)
            results.append(ProbeResult(
                name=probe.name, matched=matched, url=req.path,
                status_code=status_code, interface=probe.interface, extracted=extracted,
            ))
    return results
