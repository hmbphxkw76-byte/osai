"""arm — Weapon preparation phase: Seed selection + Converter configuration.

Attack pipeline steps 2-3:
    Seed selection: Load attack seeds from YAML seed files, rank by historical ASR
    Converter configuration: Build L5 optimal converter candidate list
        - Persuasion: Zeng et al. (arXiv:2402.19181) - Authority endorsement ASR 38.4%
        - Decomposition: DrAttack (arXiv:2402.14266) - Decompose & reconstruct ASR 40-60%
        - Selective encoding: Wei et al. (arXiv:2307.15043) - Partial obfuscation ASR 25-35%

Core modules:
    - seed_ranker: Seed loading + ASR sorting + language adaptation (SSOT facade)
    - seed_ranking: ASR ranking implementation + UCB + MTOS multi-turn scoring
    - seed_auto_expander: VariationConverter-based seed expansion
    - converter_chains: PyRIT native converter chain definitions
    - converter_presets: l5_optimal preset + build_converter_map
    - technique_picker: Attack technique selection (single/multi-turn/adaptive)
    - converter_selector: Converter candidate selection + OWASP priority + ASR pruning
    - steganography_encoder: LSB/Unicode steganographic payload encoding
    - unicode_code_obfuscator: Programming language identifier obfuscation

Design principles:
    - Arm phase is side-effect-free: no file I/O, no network calls, no temp files
    - All deferred execution (PDF/Word generation) handled in strike phase
    - SSOT pattern: seed_ranker is the public facade, others are internal
"""

from arm.converter_presets import build_converter_map
from arm.seed_ranker import load_seeds
from arm.technique_picker import select_techniques

__all__ = [
    "load_seeds",
    "build_converter_map",
    "select_techniques",
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
