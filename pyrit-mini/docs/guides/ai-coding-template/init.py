#!/usr/bin/env python3
"""AI-Coding Template initializer.

Reads ``template.config.yaml``, replaces ``${KEY}`` tokens in every file listed
under ``targets`` (relative to this template directory), and writes the result
into ``--output`` preserving the relative directory structure. Files listed
under ``assets`` are copied verbatim (no substitution) -- handy for shipping
the methodology docs alongside the skeleton.

Illustrative ``${...}`` tokens that are NOT present in ``substitutions`` are
left intact (they are meant to be filled per real architecture) and reported at
the end for awareness.

Usage:
    python init.py --config template.config.yaml --output .
"""
from __future__ import annotations

import argparse
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required to run init.py:  pip install pyyaml")

PLACEHOLDER = re.compile(r"\$\{([A-Z0-9_]+)\}")


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def substitute(text: str, subs: dict) -> tuple[str, set[str]]:
    unresolved: set[str] = set()

    def repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key in subs:
            return str(subs[key])
        unresolved.add(key)
        return match.group(0)

    return PLACEHOLDER.sub(repl, text), unresolved


def copy_asset(src: str, dst: str) -> None:
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(fin.read())


def main() -> None:
    ap = argparse.ArgumentParser(description="AI-Coding template initializer")
    ap.add_argument("--config", default="template.config.yaml",
                    help="path to template.config.yaml")
    ap.add_argument("--output", default=".",
                    help="project root to write generated files into")
    ap.add_argument("--template-dir", default=None,
                    help="template root (default: directory of --config)")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be written without writing")
    args = ap.parse_args()

    cfg = load_config(args.config)
    template_dir = args.template_dir or os.path.dirname(os.path.abspath(args.config))
    subs = cfg.get("substitutions", {}) or {}
    targets = cfg.get("targets", []) or []
    assets = cfg.get("assets", []) or []

    total_unresolved: dict[str, set[str]] = {}
    written = 0

    for rel in targets:
        src = os.path.join(template_dir, rel)
        dst = os.path.join(args.output, rel)
        if not os.path.exists(src):
            print(f"[WARN] target not found, skip: {src}")
            continue
        with open(src, "r", encoding="utf-8") as fh:
            text = fh.read()
        new_text, unresolved = substitute(text, subs)
        for key in unresolved:
            total_unresolved.setdefault(key, set()).add(rel)
        if args.dry_run:
            print(f"[DRY] would write {dst} ({len(new_text)} bytes)")
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(new_text)
        print(f"[OK]  {dst}")
        written += 1

    for rel in assets:
        src = os.path.join(template_dir, rel)
        if not os.path.exists(src):
            print(f"[WARN] asset not found, skip: {src}")
            continue
        # 资源文件落到目标项目的 docs/ 下（剥离可能的 ../ 前缀，用文件名）
        dst = os.path.join(args.output, "docs", os.path.basename(rel))
        if args.dry_run:
            print(f"[DRY] would copy  {dst}")
            continue
        copy_asset(src, dst)
        print(f"[CP]  {dst}")
        written += 1

    print(f"\n[SUMMARY] wrote {written} file(s) into '{args.output}'.")

    if total_unresolved:
        print("\n[INFO] Unresolved illustrative placeholders (fill per-architecture):")
        for key in sorted(total_unresolved):
            files = total_unresolved[key]
            print(f"  ${{{key}}}  (in {len(files)} file(s))")

    if not subs:
        print("\n[ERROR] 'substitutions' 为空 —— 未做任何替换，生成的骨架不可用。")
        print("         请先在 template.config.yaml 的 substitutions: 下填写 PROJECT_NAME 等真实值，再运行 init.py。")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
