"""recon/_burp_models — Re-export of the dependency-free Burp data contracts.

The `TargetFingerprint` / `ParsedBurpRequest` dataclasses were moved to
`core._burp_models` (CP-012 S5) so that `core` can reference them without
importing `recon` (the matrix forbids `core → recon`). They live in `core` now;
this module re-exports them so every historical import path
(`recon._burp_models`, `recon.burp_parser`, `recon`) keeps working unchanged.
"""

from core._burp_models import ParsedBurpRequest, TargetFingerprint

__all__ = ["ParsedBurpRequest", "TargetFingerprint"]
