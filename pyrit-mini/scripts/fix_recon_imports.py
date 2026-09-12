# -*- coding: utf-8 -*-
"""
Internal helper: rewrite stale top-level recon imports after component-based
refactoring. Idempotent - safe to run multiple times.

Usage:
    python scripts/fix_recon_imports.py

Constitution compliance:
    - C4: Internal tooling (no PyRIT API fallback)
    - R-H3: Single responsibility - only rewrites imports
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "recon"

# Migration map: old_module_name -> new_dotted_path
# e.g. "a2a_discoverer" -> "a2a.discoverer"
MIGRATION_MAP: dict[str, str] = {
    # A2A
    "a2a_discoverer": "a2a.discoverer",
    "a2a_agent_card": "a2a.agent_card",
    "a2a_attack_planner": "a2a.attack_planner",
    "a2a_defense_awareness": "a2a.defense_awareness",
    "multi_agent_topology": "a2a.topology",
    # RAG
    "rag_pipeline_probe": "rag.pipeline_probe",
    "rag_metadata_parser": "rag.metadata_parser",
    "rag_typo_fuzzer": "rag.typo_fuzzer",
    # Model
    "model_seed_mapper": "model.seed_mapper",
    "api_classifier": "model.api_classifier",
    "system_prompt_extract": "model.system_prompt_extract",
    "prompt_injector": "model.prompt_injector",
    # API
    "auth_detector": "api.auth_detector",
    "endpoint_sorter": "api.endpoint_sorter",
    "openapi_discoverer": "api.openapi_discoverer",
    "adaptive_probe_config": "api.adaptive_config",
    "sse_parser": "api.sse_parser",
    "recursive_expander": "api.recursive_expander",
    # MCP
    "schema_extractor": "mcp.schema_extractor",
    # Embedding
    "vector_probe": "embedding.vector_probe",
    # Core
    "fingerprint": "core.fingerprint",
    "stealth_config": "core.stealth_config",
    "stealth_timing": "core.stealth_timing",
    "burp_parser": "core.burp_parser",
    "confidence_scorer": "core.confidence_scorer",
    "guardrail_detector": "core.guardrail_detector",
    "health_probe": "core.health_probe",
    "target_builder": "core.target_builder",
    "target_router": "core.target_router",
    "target_wrapper": "core.target_wrapper",
    "config_loader": "core.config_loader",
    "capability_detector": "core.capability_detector",
    "capability_probe": "core.capability_probe",
    "trust_chain_probe": "core.trust_chain_probe",
    "trust_level_enum": "core.trust_level_enum",
    "_target_router_helpers": "core._target_router_helpers",
}

# Precompile regex patterns for performance
FROM_PATTERN = re.compile(
    r"^(\s*from\s+)recon\.(" + "|".join(re.escape(k) for k in MIGRATION_MAP) + r")(\s+import\s+)",
    re.MULTILINE,
)
IMPORT_PATTERN = re.compile(
    r"^(\s*import\s+)recon\.(" + "|".join(re.escape(k) for k in MIGRATION_MAP) + r")(\s*)$",
    re.MULTILINE,
)


def _replace_from_match(match: re.Match[str]) -> str:
    prefix = match.group(1)
    old_name = match.group(2)
    suffix = match.group(3)
    new_path = MIGRATION_MAP[old_name]
    return f"{prefix}recon.{new_path}{suffix}"


def _replace_import_match(match: re.Match[str]) -> str:
    prefix = match.group(1)
    old_name = match.group(2)
    suffix = match.group(3)
    new_path = MIGRATION_MAP[old_name]
    return f"{prefix}recon.{new_path}{suffix}"


def fix_file(path: Path) -> bool:
    """Fix imports in a single file. Returns True if modified."""
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False

    new_content = FROM_PATTERN.sub(_replace_from_match, content)
    new_content = IMPORT_PATTERN.sub(_replace_import_match, new_content)

    if new_content != content:
        path.write_text(new_content, encoding="utf-8")
        return True
    return False


def main() -> None:
    """Fix all .py files under recon/."""
    fixed = 0
    for py_file in ROOT.rglob("*.py"):
        if fix_file(py_file):
            fixed += 1
            print(f"  Fixed: {py_file.relative_to(ROOT.parent)}")
    print(f"\nTotal files modified: {fixed}")


if __name__ == "__main__":
    main()
