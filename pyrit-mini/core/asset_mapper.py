"""core/asset_mapper.py - Asset mapping layer (v2).

Maps attack surface types to seed categories and scorers.

Academic basis:
  - NIST SP 800-115: Technical Guide to Information Security Testing
  - MITRE ATLAS v4.2: Maps LLM attack patterns to TTPs
  - HarmBench (arXiv:2402.04249): Cross-model harm evaluation

Architecture:
  1. Load asset_index.yaml configuration
  2. Classify attack surface from Burp profile names
  3. Map attack surface to seed categories
  4. Load scorer definitions from YAML

Usage:
    from core.asset_mapper import AssetMapper, load_asset_index
    mapper = AssetMapper()

    # Burp profile to seeds mapping
    seeds = mapper.get_seeds_for_burp_profile("mcp05")

    # Attack surface to scorer mapping
    scorer = mapper.get_scorer_for_attack_surface("mcp_server")

    # Load asset index
    index = load_asset_index()
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Re-export yaml for safe_load usage in load_asset_index
try:
    import yaml as _yaml
except ImportError:
    _yaml = None  # type: ignore[assignment]


class AssetMapper:
    """Maps attack surface types to seed categories and scorers.

    Loads asset_index.yaml and provides methods to:
    - Classify attack surface from Burp profile names
    - Map attack surface to seed file paths
    - Map attack surface to scorer file paths
    """

    def __init__(self, asset_index: dict[str, Any] | None = None) -> None:
        """Initialize AssetMapper.

        Args:
            asset_index: Optional pre-loaded asset index dict.
                If None, loads from config/profiles/asset_index.yaml.
        """
        self._index = asset_index if asset_index is not None else self._load_default_index()
        self._seeds_cfg = self._index.get("assets", {}).get("seeds", {})
        self._scorers_cfg = self._index.get("assets", {}).get("scorers", {})
        self._surface_mapping = self._index.get("attack_surface_seed_mapping", {})
        self._burp_rules = self._index.get("burp_profile_rules", {}).get("patterns", [])
        # D-08 fix: Load target_profiles.yaml for path-based profile matching
        self._target_profiles = self._load_target_profiles()

    @staticmethod
    def _load_default_index() -> dict[str, Any]:
        """Load asset_index.yaml from config/profiles/.

        Returns:
            Dict containing asset index configuration.
        """
        index_path = Path(__file__).resolve().parent.parent / "config" / "profiles" / "asset_index.yaml"
        if not index_path.exists():
            return {}
        try:
            if _yaml is not None:
                with open(index_path, encoding="utf-8") as f:
                    return _yaml.safe_load(f) or {}
        except Exception as e:
            logger.debug("Failed to load asset_index.yaml: %s", e)
        return {}

    @staticmethod
    def _load_target_profiles() -> list[dict[str, Any]]:
        """Load target_profiles.yaml from config/.

        Returns:
            List of profile dicts with id, name, category, path_pattern, seeds, etc.
        """
        profiles_path = Path(__file__).resolve().parent.parent / "config" / "target_profiles.yaml"
        if not profiles_path.exists():
            return []
        try:
            if _yaml is not None:
                with open(profiles_path, encoding="utf-8") as f:
                    data = _yaml.safe_load(f) or {}
                    return data.get("profiles", [])
        except Exception as e:
            logger.debug("Failed to load target_profiles.yaml: %s", e)
        return []

    def match_profile_by_path(self, url_path: str) -> dict[str, Any] | None:
        """Match a URL path against target_profiles.yaml patterns.

        D-08 fix: Enables path-based profile matching for dynamic seed selection.

        Args:
            url_path: URL path to match (e.g., "/v1/chat/completions")

        Returns:
            Matched profile dict with seeds, category, etc., or None if no match.
        """
        if not url_path or not self._target_profiles:
            return None

        for profile in self._target_profiles:
            pattern = profile.get("path_pattern", "")
            if not pattern:
                continue
            try:
                if re.search(pattern, url_path, re.IGNORECASE):
                    logger.debug(
                        "URL path '%s' matched profile '%s' (pattern: %s)",
                        url_path, profile.get("id"), pattern,
                    )
                    return profile
            except re.error as e:
                logger.debug("Invalid regex pattern '%s' in profile '%s': %s",
                             pattern, profile.get("id"), e)
        return None

    def get_seeds_for_path(self, url_path: str) -> list[str]:
        """Get seed names for a URL path using target_profiles.yaml.

        D-08 fix: Path-based seed selection from target_profiles.yaml.

        Args:
            url_path: URL path to match

        Returns:
            List of seed names from the matched profile, or empty list.
        """
        profile = self.match_profile_by_path(url_path)
        if profile:
            return profile.get("seeds", [])
        return []

    @property
    def target_profile_count(self) -> int:
        """Return number of loaded target profiles."""
        return len(self._target_profiles)

    # ==============================================
    # Burp Profile -> Attack Surface Classification
    # ==============================================
    def classify_attack_surface(self, burp_profile_name: str) -> str:
        """Classify attack surface type from Burp profile name.

        Classification priority:
        1. Explicit burp_profile_rules.patterns match
        2. Attack surface seed mapping lookup
        3. Default: standard_llm_api

        Args:
            burp_profile_name: Burp profile filename (e.g., "mcp05", "mocka")

        Returns:
            Attack surface type string ("mcp_server", "standard_llm_api", etc.)
        """
        profile_lower = burp_profile_name.lower()

        # Check explicit rules first
        for rule in self._burp_rules:
            match_type = rule.get("match_type", "filename_contains")
            attack_surface = rule.get("attack_surface", "standard_llm_api")

            if match_type == "filename_contains":
                patterns = rule.get("patterns", [])
                for pattern in patterns:
                    if pattern.lower() in profile_lower:
                        logger.debug(
                            "Burp profile '%s' matched rule '%s' via pattern '%s' -> %s",
                            burp_profile_name, rule.get("name"), pattern, attack_surface,
                        )
                        return attack_surface

        # Default fallback
        logger.debug(
            "Burp profile '%s' did not match any rule, defaulting to standard_llm_api",
            burp_profile_name,
        )
        return "standard_llm_api"

    # ==============================================
    # Attack Surface -> Seeds Mapping
    # ==============================================
    def get_seeds_for_attack_surface(self, attack_surface: str) -> list[str]:
        """Get seed names for a given attack surface type.

        Args:
            attack_surface: Attack surface type (e.g., "mcp_server", "rag_system")

        Returns:
            List of seed names (e.g., ["mcp_tool_enum", "mcp_server_injection"])
        """
        mapping = self._surface_mapping.get(attack_surface)
        if not mapping:
            logger.debug(
                "No seed mapping for attack_surface='%s', falling back to standard_llm_api",
                attack_surface,
            )
            mapping = self._surface_mapping.get("standard_llm_api")

        if not mapping:
            return []

        seeds = mapping.get("seeds", [])
        logger.debug(
            "Attack surface '%s' mapped to %d seeds (priority=%s)",
            attack_surface, len(seeds), mapping.get("priority"),
        )
        return seeds

    def get_seeds_for_burp_profile(self, burp_profile_name: str) -> list[str]:
        """Get seed names for a Burp profile (with default mapper).

        Args:
            burp_profile_name: Burp profile filename (e.g., "mcp05")

        Returns:
            List of seed names for this profile's attack surface.
        """
        attack_surface = self.classify_attack_surface(burp_profile_name)
        return self.get_seeds_for_attack_surface(attack_surface)

    # ==============================================
    # Attack Surface -> Scorer Mapping
    # ==============================================
    def get_scorer_for_attack_surface(self, attack_surface: str) -> str | None:
        """Get scorer name for a given attack surface type.

        Args:
            attack_surface: Attack surface type

        Returns:
            Scorer name (e.g., "web_vuln_detected") or None
        """
        mapping = self._surface_mapping.get(attack_surface)
        if not mapping:
            return None
        return mapping.get("scorer")

    def get_scorer_path(self, scorer_name: str) -> str | None:
        """Get file path for a scorer.

        Args:
            scorer_name: Scorer name (e.g., "web_vuln_detected")

        Returns:
            Path string (e.g., "scorers/web_vuln_detected.yaml") or None
        """
        scorer_cfg = self._scorers_cfg.get(scorer_name)
        if not scorer_cfg:
            return None
        return scorer_cfg.get("path")

    # ==============================================
    # Seed Metadata Access
    # ==============================================
    def get_seed_file_path(self, seed_name: str) -> str | None:
        """Get file path for a seed.

        Args:
            seed_name: Seed name (e.g., "mcp_tool_enum")

        Returns:
            Path string (e.g., "_attack_surface/T1_ASI02_mcp_full_surface/mcp_tool_enum")
        """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            return None
        return seed_cfg.get("path")

    def get_seed_tier(self, seed_name: str) -> int | None:
        """Get tier level for a seed.

        Args:
            seed_name: Seed name

        Returns:
            Tier integer (1/2/3) or None if not found
        """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            return None
        return seed_cfg.get("tier")

    def get_seed_category(self, seed_name: str) -> str | None:
        """Get category for a seed.

        Args:
            seed_name: Seed name

        Returns:
            Category string or None
        """
        seed_cfg = self._seeds_cfg.get(seed_name)
        if not seed_cfg:
            return None
        return seed_cfg.get("category")

    # ==============================================
    # Synergy Config
    # ==============================================
    def get_full_synergy_config(self, burp_profile_name: str) -> dict[str, Any]:
        """Get complete synergy config for a Burp profile.

        Args:
            burp_profile_name: Burp profile name

        Returns:
            Dict with keys:
                burp_profile: str,
                attack_surface: str,
                seeds: list[str],
                scorer: str,
                scorer_path: str,
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
# Module-level defaults and convenience functions
# ==============================================
_default_mapper: AssetMapper | None = None


def get_default_mapper() -> AssetMapper:
    """Get or create the default AssetMapper singleton.

    Returns:
        Default AssetMapper instance.
    """
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = AssetMapper()
    return _default_mapper


# Asset index path (cached at module load)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSET_INDEX_PATH = _PROJECT_ROOT / "config" / "profiles" / "asset_index.yaml"


def load_asset_index() -> dict[str, Any]:
    """Load asset_index.yaml from config/profiles/.

    Returns:
        Dict containing asset index configuration.
    """
    if not ASSET_INDEX_PATH.exists():
        return {}
    try:
        if _yaml is not None:
            with open(ASSET_INDEX_PATH, encoding="utf-8") as f:
                return _yaml.safe_load(f) or {}
    except Exception as e:
        logger.debug("Failed to load asset_index.yaml: %s", e)
    return {}


# Convenience functions
def get_seeds_for_burp(burp_profile_name: str) -> list[str]:
    """Get seeds for a Burp profile using default mapper.

    Args:
        burp_profile_name: Burp profile filename

    Returns:
        List of seed names.
    """
    return get_default_mapper().get_seeds_for_burp_profile(burp_profile_name)


def get_scorer_for_burp(burp_profile_name: str) -> str | None:
    """Get scorer for a Burp profile using default mapper.

    Args:
        burp_profile_name: Burp profile filename

    Returns:
        Scorer name or None.
    """
    mapper = get_default_mapper()
    surface = mapper.classify_attack_surface(burp_profile_name)
    return mapper.get_scorer_for_attack_surface(surface)


def get_synergy_config(burp_profile_name: str) -> dict[str, Any]:
    """Get synergy config for a Burp profile using default mapper.

    Args:
        burp_profile_name: Burp profile filename

    Returns:
        Complete synergy configuration dict.
    """
    return get_default_mapper().get_full_synergy_config(burp_profile_name)
