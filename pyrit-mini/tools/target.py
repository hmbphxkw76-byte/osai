"""tools/target — object-first CLI entry (`python -m tools.target <object>`).

This is the single object-selector front door for the pipeline. It normalizes an
attack-object key and resolves it across every layer that follows the
object-axis convention (strike / converters / data / assess / report), then
either prints the resolved routing or forwards a ready-to-run `main.py` command.

It performs NO attacks — it is a routing/validation façade over `core.object_taxonomy`
and the existing layer modules. The actual execution still goes through `main.py`.

(R-TOOLS-1 compliant: CLI tools live under tools/.)

Examples (all equivalent object routing):
    python -m tools.target mcp
    python -m tools.target mcp --strike mcp --converters mcp --data mcp
    python -m tools.target a2a --strike a2a --data a2a

Flags:
    --strike <obj>      resolve strike strategy for <obj>   (-> strike/_strategies.yaml)
    --converters <obj>  resolve converter preset for <obj>  (-> arm/<obj>/)
    --data <obj>        resolve seed set for <obj>          (-> data/seeds/<obj>/)
    --assess <obj>      resolve T0 scorer for <obj>         (-> assess/<obj>/)
    --report <obj>      resolve report section for <obj>    (-> report/<obj>/)
    --build             emit a `python main.py` command line for the resolved routing
    --list              list canonical objects and aliases
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.object_taxonomy import (  # noqa: E402
    OBJECT_ALIASES,
    OBJECTS,
    component_for_object,
    normalize_object,
)


def _resolve_strike(obj: str) -> str:
    """Resolve the strike strategy file presence for an object."""
    strategies = Path("strike", "_strategies.yaml")
    if not strategies.exists():
        return "n/a (strike/_strategies.yaml missing)"
    try:
        import yaml

        data = yaml.safe_load(strategies.read_text(encoding="utf-8")) or {}
        targets = (data.get("targets") or {}).get(obj)
        if targets:
            phases = targets.get("phases") or []
            return f"{obj} ({len(phases)} phases: " + ", ".join(
                p.get("strategy", "?") for p in phases
            ) + ")"
    except Exception:
        pass
    return f"{obj} (declared)"


def _resolve_converters(obj: str) -> str:
    """Resolve the converter module path for an object."""
    mod = Path("arm", obj, "preset.py")
    if mod.exists():
        return f"arm/{obj}/preset.py"
    return f"arm/converter_presets.py (target_type -> {obj})"


def _resolve_data(obj: str) -> str:
    """Resolve the seed directory for an object."""
    seed_dir = Path("data", "seeds", obj)
    if seed_dir.is_dir():
        n = len(list(seed_dir.glob("*.prompt")))
        return f"data/seeds/{obj}/ ({n} seeds)"
    return f"data/seeds/{obj}/ (empty/not-created)"


def _resolve_assess(obj: str) -> str:
    """Resolve the T0 scorer module for an object."""
    component = component_for_object(obj)
    mod = Path("assess", obj, "t0.py")
    if mod.exists():
        return f"assess/{obj}/t0.py -> component '{component}'"
    return f"assess/component_scorers.py -> component '{component}'"


def _resolve_report(obj: str) -> str:
    """Resolve the report section module for an object."""
    component = component_for_object(obj)
    mod = Path("report", obj, "sections.py")
    if mod.exists():
        return f"report/{obj}/sections.py -> component '{component}'"
    return f"report/component_reports.py -> component '{component}'"


def _build_command(obj: str, layers: dict[str, str]) -> str:
    """Emit a `python main.py` command for the resolved routing."""
    parts = ["python main.py", f"--target {obj}"]
    if layers.get("strike"):
        parts.append(f"--strike {layers['strike']}")
    if layers.get("converters"):
        parts.append(f"--converters {layers['converters']}")
    if layers.get("data"):
        parts.append(f"--seeds {layers['data']}")
    return " ".join(parts)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m tools.target",
        description="Object-first routing façade for the attack pipeline.",
    )
    ap.add_argument("object", nargs="?", help="attack-object key (mcp/a2a/rag/model/web/...)")
    ap.add_argument("--strike", metavar="OBJ", help="resolve strike strategy for OBJ")
    ap.add_argument("--converters", metavar="OBJ", help="resolve converter preset for OBJ")
    ap.add_argument("--data", metavar="OBJ", help="resolve seed set for OBJ")
    ap.add_argument("--assess", metavar="OBJ", help="resolve T0 scorer for OBJ")
    ap.add_argument("--report", metavar="OBJ", help="resolve report section for OBJ")
    ap.add_argument("--build", action="store_true", help="emit a python main.py command line")
    ap.add_argument("--list", action="store_true", help="list canonical objects + aliases")
    args = ap.parse_args(argv)

    if args.list or not args.object:
        if args.list or args.object is None:
            print("Canonical objects:")
            for o in OBJECTS:
                print(f"  - {o}")
            print("\nAliases:")
            for alias, target in OBJECT_ALIASES.items():
                print(f"  - {alias} -> {target}")
            if not args.object:
                return 0 if args.list else 1
            if args.object is None:
                return 0

    obj = normalize_object(args.object or "")
    if obj is None:
        print(f"[target] unknown object: {args.object!r} (use --list to see valid keys)")
        return 2

    print(f"=== object routing: {args.object} -> {obj} ===")

    layers: dict[str, str] = {}
    strike_obj = args.strike or args.object
    conv_obj = args.converters or args.object
    data_obj = args.data or args.object
    assess_obj = args.assess or args.object
    report_obj = args.report or args.object

    s = normalize_object(strike_obj)
    if s:
        layers["strike"] = s
        print(f"  strike   : {_resolve_strike(s)}")
    c = normalize_object(conv_obj)
    if c:
        layers["converters"] = c
        print(f"  converters: {_resolve_converters(c)}")
    d = normalize_object(data_obj)
    if d:
        layers["data"] = d
        print(f"  data     : {_resolve_data(d)}")
    a = normalize_object(assess_obj)
    if a:
        print(f"  assess   : {_resolve_assess(a)}")
    r = normalize_object(report_obj)
    if r:
        print(f"  report   : {_resolve_report(r)}")

    if args.build:
        print("\n# resolved main.py command:")
        print("  " + _build_command(obj, layers))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
