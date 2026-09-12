"""tests/unit/test_import_graph.py - AST-level import connectivity guard.

Purpose
-------
Wave 0 acceptance gate. This project suffered a systematic class of failure: after
`strike/` and `recon/` were refactored into sub-packages, callers kept importing the
old *flat* module paths (e.g. `from strike.dispatcher import ...`, which now lives at
`strike/common/dispatcher.py`). Because every one of those imports sits inside
`try: ... except Exception: logger.debug(...)`, the breakage was completely silent:
whole features disappeared while the pipeline still exited 0.

This test statically resolves every first-party absolute/relative import in the repo
(AST, no execution) and asserts two things per import:

  1. the target module exists on disk
  2. the imported symbol is actually exported by that module

Modules that implement PEP 562 lazy dispatch (a module-level `__getattr__`, used by
`strike/__init__.py` and `arm/__init__.py`) are exempted from check 2, because their
public surface is computed at runtime by design.

Deliberately excluded from the scan:
  * third-party imports (only first-party tops are resolved)
  * dotted names that are attributes rather than modules (e.g. `import os.path`)
  * the `tests/` tree is scanned but reported separately (see VALIDATION note)
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]

#: First-party top-level packages/modules whose imports we own and must keep coherent.
FIRST_PARTY_TOPS: frozenset[str] = frozenset(
    {"core", "recon", "arm", "strike", "assess", "report", "utils", "tools", "main"}
)

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {
        "__pycache__",
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "outputs",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".assistant_pyrit",
    }
)


def _iter_python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in SKIP_DIR_NAMES for part in path.relative_to(root).parts):
            continue
        files.append(path)
    return sorted(files)


def _module_name_for(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    if rel.name == "__init__":
        rel = rel.parent
    return ".".join(rel.parts)


def _build_module_index(root: Path) -> dict[str, Path]:
    """Map every importable dotted module name to its defining file."""
    index: dict[str, Path] = {}
    for path in _iter_python_files(root):
        index[_module_name_for(path, root)] = path
    return index


def _package_dirs(root: Path) -> set[str]:
    """Dotted names that are packages (have __init__.py) - safe `from pkg import name` targets."""
    return {
        _module_name_for(p.parent, root)
        for p in _iter_python_files(root)
        if p.name == "__init__.py"
    }


def _toplevel_exports(path: Path) -> tuple[set[str], bool]:
    """Return (statically known top-level names, has_lazy___getattr__)."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set(), False
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return set(), False

    names: set[str] = set()
    has_lazy_getattr = False

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            if node.name == "__getattr__":
                has_lazy_getattr = True
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)

    # When __all__ is declared it is the authoritative public surface.
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    try:
                        declared = set(ast.literal_eval(node.value))  # type: ignore[arg-type]
                    except (ValueError, SyntaxError):
                        continue
                    names = names | set(declared)

    return names, has_lazy_getattr


def _resolve_relative(base_module: str, level: int, module: str | None) -> str:
    parts = base_module.split(".") if base_module else []
    if module is None:
        # `from . import X` —— X 是 base_module 自身的符号，锚点即模块本身。
        anchor = parts
    else:
        # `from .sibling import X` —— 锚点是「第 level 级父包」：
        #   level=1 (.sibling)  → 当前包 (去掉模块自身这一级)
        #   level=2 (..sibling) → 父包的父包，依此类推。
        # 历史实现误将 level=1 的锚点取为模块本身，导致 `from .sibling` 被解析成
        # `pkg.module.sibling`（不存在），使合法的同级相对导入被误判为断链。
        anchor = parts[: len(parts) - level] if len(parts) >= level else []
    tail = module.split(".") if module else []
    return ".".join([*anchor, *tail])


def collect_import_breakages(root: Path = PROJECT_ROOT) -> list[str]:
    """Return a human-readable list of broken first-party imports."""
    module_index = _build_module_index(root)
    packages = _package_dirs(root)
    breakages: list[str] = []

    for path in _iter_python_files(root):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue

        base_module = _module_name_for(path, root)
        if path.name == "__init__.py":
            base_module = ".".join(base_module.split("."))

        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue

            if node.level > 0:
                target = _resolve_relative(base_module, node.level, node.module)
            else:
                if node.module is None:
                    continue
                top = node.module.split(".")[0]
                if top not in FIRST_PARTY_TOPS:
                    continue
                target = node.module

            if not target:
                continue

            # module-level resolution
            if target in module_index:
                target_path: Path | None = module_index[target]
            elif target in packages:
                target_path = None  # namespace-ish package without tracked module file
            else:
                # `from pkg import submodule` - the submodule may be a package dir
                candidate: Path | None = None
                for mod_name, mod_path in module_index.items():
                    if mod_name.startswith(target + "."):
                        candidate = mod_path
                        break
                if candidate is None:
                    breakages.append(
                        f"{path.relative_to(root)}:{node.lineno}: "
                        f"module not found -> `from {'.' * node.level}{node.module or ''} import ...` (resolved: {target!r})"
                    )
                    continue
                target_path = candidate

            if target_path is None or target_path == path:
                continue

            exports, has_lazy_getattr = _toplevel_exports(target_path)
            # PEP 562 lazy dispatch resolves names at runtime; do not second-guess it.
            if has_lazy_getattr:
                continue

            for alias in node.names:
                if alias.name == "*":
                    continue
                if alias.name not in exports:
                    # `from pkg import submodule` is legitimate even if not re-exported
                    if any(mod_name == f"{target}.{alias.name}" for mod_name in module_index):
                        continue
                    if f"{target}.{alias.name}" in packages:
                        continue
                    breakages.append(
                        f"{path.relative_to(root)}:{node.lineno}: "
                        f"symbol not found -> `{alias.name}` not exported by {target} "
                        f"({target_path.relative_to(root)})"
                    )

    return sorted(set(breakages))


def test_first_party_import_graph_is_connected() -> None:
    """Every first-party import must resolve to a real module AND a real symbol.

    A failure here means a feature silently disappeared at runtime (see module docstring).
    Fix by correcting the module path or the symbol name - do NOT silence this test.
    """
    breakages = collect_import_breakages()

    if breakages:
        preview = "\n  - ".join(breakages[:40])
        omitted = "" if len(breakages) <= 40 else f"\n  ... and {len(breakages) - 40} more"
        pytest.fail(
            f"{len(breakages)} broken first-party import(s):\n  - {preview}{omitted}",
            pytrace=False,
        )


def test_import_graph_scanner_is_functional() -> None:
    """Guard against the scanner itself silently returning nothing (false green)."""
    module_index = _build_module_index(PROJECT_ROOT)
    assert len(module_index) > 50, "module index suspiciously small - scanner is broken"
    assert "core/phases/recon.py".replace("/", ".")[:-3] in module_index or any(
        name.startswith("core") for name in module_index
    )
