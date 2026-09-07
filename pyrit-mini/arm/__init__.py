"""arm — Seed selection + Converter transformation phase.

Attack pipeline steps 2-3:
    Seed selection: Load attack seeds from YAML seed files, sort by historical ASR
    Converter transformation: Build L5 optimal Converter chain (encoding/persuasion/decomposition/obfuscation)

Core modules:
    - seed_ranker: Seed loading + ASR sorting + language adaptation
    - converter_chains: L5 expert-level Converter chain definitions
    - converter_presets: l5_optimal preset + build_converter_map
    - technique_picker: Attack technique selection (single-turn/multi-turn/adaptive)
    - converter_selector: Converter candidate selection + OWASP priority + ASR pruning
"""

from arm.converter_presets import build_converter_map
from arm.seed_ranker import load_seeds
from arm.technique_picker import filter_by_adversarial, select_techniques

__all__ = [
    "load_seeds",
    "build_converter_map",
    "select_techniques",
    "filter_by_adversarial",
]
