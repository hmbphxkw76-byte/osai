"""core/asset_mapper.py - (v2).

 MITRE ATLAS .

:
    v61 imports data/asset_mapper.py ,  D-13 :
    data/ Layer,  core/ Layer.

:
  - NIST SP 800-115: 
  - MITRE ATLAS v4.2: ->TTP
  - HarmBench (arXiv:2402.04249): 

:
  1. , 
  2. : Layer
  3. : converter(s)
  4. :  YAML 

Usage:
    from core.asset_mapper import AssetMapper, load_asset_index
    mapper = AssetMapper()

 # Burp -> 
    seeds = mapper.get_seeds_for_burp_profile("mcp05")

 # -> 
    scorer = mapper.get_scorer_for_attack_surface("mcp_server")

 # 
    index = load_asset_index()
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AssetMapper:
 """ - Burp->Seed, Seed->Scorer ."""

    def __init__(self, asset_index: dict[str, Any] | None = None):
 """
        .

        Args:
            asset_index: . imports config/asset_index.yaml Load (v61).
 """
        if asset_index is not None:
            self._index = asset_index
        else:
            self._index = self._load_default_index()

        self._seeds_cfg = self._index.get("assets", {}).get("seeds", {})
        self._scorers_cfg = self._index.get("assets", {}).get("scorers", {})
        self._surface_mapping = self._index.get("attack_surface_seed_mapping", {})
        self._burp_rules = self._index.get("burp_profile_rules", {}).get("patterns", [])

    @staticmethod
    def _load_default_index() -> dict[str, Any]:
 """Load asset_index.yaml."""
 # v63: asset_index config/profiles/ ()
        import yaml
        from pathlib import Path
        index_path = Path(__file__).resolve().parent.parent / "config" / "profiles" / "asset_index.yaml"
        if not index_path.exists():
            logger.warning("config/asset_index.yaml not found at %s", index_path)
            return {}
        with open(index_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

 # ==============================================
 # Burp Profile -> 
 # ==============================================
    def classify_attack_surface(self, burp_profile_name: str) -> str:
 """ Burp .

         ():
          1.  ()
          2.  ()
          3. : standard_llm_api

        Args:
            burp_profile_name: Burp  ( "mcp05", "mocka")

        Returns:
             ( "mcp_server", "standard_llm_api")
 """
        profile_lower = burp_profile_name.lower()

 # 
        for rule in self._burp_rules:
            patterns = rule.get("patterns", [])
            match_type = rule.get("match_type", "filename_contains")
            attack_surface = rule.get("attack_surface", "standard_llm_api")

            if match_type == "filename_contains":
                for pattern in patterns:
                    if pattern.lower() in profile_lower:
                        logger.debug(
                            "Burp profile '%s' matched rule '%s' via pattern '%s' -> %s",
                            burp_profile_name, rule.get("name"), pattern, attack_surface,
                        )
                        return attack_surface

 # 
        logger.debug(
            "Burp profile '%s' did not match any rule, defaulting to standard_llm_api",
            burp_profile_name,
        )
        return "standard_llm_api"

 # ==============================================
 # -> 
 # ==============================================
    def get_seeds_for_attack_surface(self, attack_surface: str) -> list[str]:
 """.

        Args:
            attack_surface:  ( "mcp_server", "rag_system")

        Returns:
             ( ["mcp_tool_enum", "mcp_server_injection"])
 """
        mapping = self._surface_mapping.get(attack_surface)
        if not mapping:
            logger.warning(
                "No seed mapping for attack_surface='%s', falling back to standard_llm_api",
                attack_surface,
            )
            mapping = self._surface_mapping.get("standard_llm_api")

        if not mapping:
            logger.error("No fallback seed mapping found!")
            return []

        seeds = mapping.get("seeds", [])
        logger.debug(
            "Attack surface '%s' mapped to %d seeds (priority=%s)",
            attack_surface, len(seeds), mapping.get("priority"),
        )
        return seeds

    def get_seeds_for_burp_profile(self, burp_profile_name: str) -> list[str]:
 """Burp -> ().

        Args:
            burp_profile_name: Burp  ( "mcp05")

        Returns:
            
 """
        attack_surface = self.classify_attack_surface(burp_profile_name)
        return self.get_seeds_for_attack_surface(attack_surface)

 # ==============================================
 # -> 
 # ==============================================
    def get_scorer_for_attack_surface(self, attack_surface: str) -> str | None:
 """.

        Args:
            attack_surface: 

        Returns:
             ( "web_vuln_detected")
 """
        mapping = self._surface_mapping.get(attack_surface)
        if not mapping:
            return None
        return mapping.get("scorer")

    def get_scorer_path(self, scorer_name: str) -> str | None:
 """.

        Args:
            scorer_name:  ( "web_vuln_detected")

        Returns:
             ( "scorers/web_vuln_detected.yaml")
 """
        scorer_cfg = self._scorers_cfg.get(scorer_name)
        if not scorer_cfg:
            logger.warning("Scorer '%s' not found in asset_index", scorer_name)
            return None
        return scorer_cfg.get("path")

 # ==============================================
 # -> 
 # ==============================================
    def get_seed_file_path(self, seed_name: str) -> str | None:
 """.

        Args:
            seed_name:  ( "mcp_tool_enum")

        Returns:
             ( "_attack_surface/T1_ASI02_mcp_full_surface/mcp_tool_enum")
 """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            logger.warning("Seed '%s' not found in asset_index", seed_name)
            return None
        return seed_cfg.get("path")

    def get_seed_tier(self, seed_name: str) -> int | None:
 """ tier .

        Args:
            seed_name: 

        Returns:
            tier  (1/2/3)  None
 """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            return None
        return seed_cfg.get("tier")

    def get_seed_category(self, seed_name: str) -> str | None:
 """.

        Args:
            seed_name: 

        Returns:
            
 """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            return None
        return seed_cfg.get("category")

 # ==============================================
 # 
 # ==============================================
    def get_full_synergy_config(self, burp_profile_name: str) -> dict[str, Any]:
 """Burp -> ().

        Args:
            burp_profile_name: Burp 

        Returns:
            :
            {
                "burp_profile": str,
                "attack_surface": str,
                "seeds": list[str],       # 
                "scorer": str,            # 
                "scorer_path": str,       # 
            }
 """
        attack_surface = self.classify_attack_surface(burp_profile_name)
        seeds = self.get_seeds_for_attack_surface(attack_surface)
        scorer = self.get_scorer_for_attack_surface(attack_surface)
        scorer_path = self.get_scorer_path(scorer) if scorer else None

        return {
            "burp_profile": burp_profile_name,
            "attack_surface": attack_surface,
            "seeds": seeds,
            "scorer": scorer,
            "scorer_path": scorer_path,
        }


# ==============================================
# ()
# ==============================================
_default_mapper: AssetMapper | None = None


def get_default_mapper() -> AssetMapper:
 """ AssetMapper ."""
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = AssetMapper()
    return _default_mapper


# ==============================================
# 
# ==============================================
import yaml as _yaml

# 
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
# v63: asset_index config/profiles/ ()
ASSET_INDEX_PATH = _PROJECT_ROOT / "config" / "profiles" / "asset_index.yaml"


def load_asset_index() -> dict[str, Any]:
 """Load asset_index.yaml .

    v61: imports data/__init__.py  core/asset_mapper.py.
    data/ Layer,  Python .

    Returns:
        , Load
 """
    if not ASSET_INDEX_PATH.exists():
        return {}
    try:
        with open(ASSET_INDEX_PATH, encoding="utf-8") as f:
            return _yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Failed to load asset_index.yaml: %s", e)
        return {}


# ()
def get_seeds_for_burp(burp_profile_name: str) -> list[str]:
 """: Burp -> ."""
    return get_default_mapper().get_seeds_for_burp_profile(burp_profile_name)


def get_scorer_for_burp(burp_profile_name: str) -> str | None:
 """: Burp -> ."""
    mapper = get_default_mapper()
    surface = mapper.classify_attack_surface(burp_profile_name)
    return mapper.get_scorer_for_attack_surface(surface)


def get_synergy_config(burp_profile_name: str) -> dict[str, Any]:
 """: ."""
    return get_default_mapper().get_full_synergy_config(burp_profile_name)
