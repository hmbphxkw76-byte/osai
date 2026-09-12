"""arm — Weapon preparation phase: Seed selection + Converter configuration.

Attack pipeline steps 2-3:
    Seed selection: Load attack seeds from YAML seed files, rank by historical ASR
    Converter configuration: Build L5 optimal converter candidate list
        - Persuasion: Zeng et al. (arXiv:2402.19181) - Authority endorsement ASR 38.4%
        - Decomposition: DrAttack (arXiv:2402.14266) - Decompose & reconstruct ASR 40-60%
        - Selective encoding: Wei et al. (arXiv:2307.15043) - Partial obfuscation ASR 25-35%

Module hierarchy (3 tiers):
    ┌─────────────────────────────────────────────────────────────────┐
    │ TIER 1 — Public Facade (SSOT entry points)                      │
    │   seed_ranker    : load_seeds() — single entry for all seed ops │
    │   converter_presets: build_converter_map() — converter config   │
    │   technique_picker : select_techniques() — technique selection  │
    ├─────────────────────────────────────────────────────────────────┤
    │ TIER 2 — Internal Implementation (consumed by Tier 1 only)      │
    │   seed_ranking   : ASR ranking algo + UCB + MTOS scoring        │
    │   converter_selector: OWASP priority + ASR pruning logic        │
    │   converter_chains : PyRIT native converter chain definitions   │
    ├─────────────────────────────────────────────────────────────────┤
    │ TIER 3 — Utility / Enhancement (optional, lazy-loaded)          │
    │   seed_auto_expander: VariationConverter-based seed expansion   │
    │   attack_surface_mapper: Multi-agent attack surface enumeration │
    │   steganography_encoder: LSB/Unicode steganographic encoding    │
    │   unicode_code_obfuscator: Programming language ID obfuscation  │
    └─────────────────────────────────────────────────────────────────┘

SSOT boundary (IMPORTANT):
    seed_ranker.py is the ONLY public interface for seed operations.
    seed_ranking.py must NOT be imported directly outside arm/.
    If you need seed ranking, use: from arm import load_seeds

Design principles:
    - Arm phase is side-effect-free: no file I/O, no network calls, no temp files
    - All deferred execution (PDF/Word generation) handled in strike phase
    - SSOT pattern: Tier 1 modules are the public facade, Tier 2/3 are internal
    - File size monitoring: converter_chains.py approaching 900-line threshold
"""

from arm.attack_surface_mapper import (
    AttackPlan,
    AttackSurfaceMapper,
    AttackVector,
    RiskLevel,
    VectorCategory,
    create_attack_surface_mapper,
)
from arm.converter_presets import build_converter_map
from arm.seed_ranker import load_seeds
from arm.technique_picker import select_techniques

__all__ = [
    "load_seeds",
    "build_converter_map",
    "select_techniques",
    "AttackSurfaceMapper",
    "AttackVector",
    "AttackPlan",
    "VectorCategory",
    "RiskLevel",
    "create_attack_surface_mapper",
    # Steganography & Obfuscation utilities (arm/ side-effect-free)
    "create_steganographic_payload",
    "create_obfuscated_code",
]


# Lazy imports for new modules (C1: Glue/Enhancement only)
def __getattr__(name: str):
    """Lazy import for steganography and obfuscation modules."""
    if name == "create_steganographic_payload":
        from arm.steganography_encoder import create_steganographic_payload

        return create_steganographic_payload
    if name == "create_obfuscated_code":
        from arm.unicode_code_obfuscator import create_obfuscated_code

        return create_obfuscated_code
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
