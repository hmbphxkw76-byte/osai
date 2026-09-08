"""Model Seed Mapper - Load model-to-seed mappings from YAML.

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - Compromising LLMs via data poisoning
    - Mazeika et al. (arXiv:2406.18510) - WILDTEAMING
    - RedAmon Julius probe pack - API seed selection heuristics

Usage:
    >>> from recon.model_seed_mapper import get_seeds_for_model, detect_model_family
    >>> prefs = get_seeds_for_model("gpt-4o")
    >>> family = detect_model_family("gpt-4o-2024-08-06")
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml as _yaml

logger = logging.getLogger(__name__)

# SSOT: path to model seed mapping YAML
_MAPPING_PATH = Path(__file__).resolve().parent.parent / "config" / "model_seed_mapping.yaml"

class ModelSeedMapper:
    """Load and query model-to-seed mappings from YAML config.

    Supports:
        - Exact model name matching
        - Version stripping (full_version -> base_family)
        - Prefix/substring match
        - Default fallback (__default__)
    """

    def __init__(self, mapping_path: Path | None = None) -> None:
        """Initialize ModelSeedMapper.

        Args:
            mapping_path: Path to YAML mapping file (None = use default)
        """
        self._mapping_path = mapping_path or _MAPPING_PATH
        self._config: dict[str, Any] | None = None
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def _raw(self) -> dict[str, Any]:
        """Load YAML config from file (cached)."""
        if self._config is None:
            self._config = self._load_config()
        return self._config

    def _load_config(self) -> dict[str, Any]:
        """Load YAML configuration from mapping file."""
        try:
            if self._mapping_path.exists():
                with open(self._mapping_path, encoding="utf-8") as f:
                    config = _yaml.safe_load(f)
                if isinstance(config, dict):
                    return config
        except Exception as e:
            logger.warning("Failed to load model seed mapping: %s", e)
        return {}

    def get_seeds_for_model(self, model_name: str) -> dict[str, Any]:
        """Get seed mapping for a model name.

        Matching order:
            1. Exact match (model_name in config)
            2. Version stripping (full_version -> base_family)
            3. Prefix match (substring in model_name)
            4. Default fallback (__default__)

        Args:
            model_name: Model ID or display name

        Returns:
            Dict with keys: preferred_templates, avoid_templates,
            optimal_converters, notes, source
        """
        if not model_name:
            return self._get_default(seed_source="empty_name")

        model_lower = model_name.lower().strip()

        # Check cache
        if model_lower in self._cache:
            return self._cache[model_lower]

        model_families = self._raw.get("model_families", {})

        # 1. Exact match
        if model_lower in model_families:
            result = model_families[model_lower]
            result["source"] = "exact"
            self._cache[model_lower] = result
            return result

        # 2. Fuzzy match via family detection
        family = self.detect_family(model_lower)
        if family and family != "__default__":
            result = model_families[family]
            result["source"] = "fuzzy"
            self._cache[model_lower] = result
            return result

        # 3. Substring match (e.g., "my-gpt-4o-api" -> "gpt-4o")
        for key in model_families:
            if key in model_lower or model_lower in key:
                result = model_families[key]
                result["source"] = "substring"
                self._cache[model_lower] = result
                return result

        # 4. Default fallback
        default_result = self._get_default(source="fallback")
        self._cache[model_lower] = default_result
        return default_result

    def detect_family(self, model_name: str) -> str:
        """Strip version suffix to detect model family.

        Args:
            model_name: Full model name with version

        Returns:
            Base family name or "__default__"
        """
        if not model_name:
            return "__default__"

        # Regex patterns for version stripping (generic, not model-specific)
        version_patterns = [
            r"(gpt-(?:4|3\.5)(?:\w+(?:\-\w+)?)?)(?:\-\d{4})",
            r"(claude(?:\-\d+\.\d+|\-\d+)\-\w+)(?:\-\d+)",
            r"(qwen\d*\.?\d*\-\d+b)(?:\-\w+)?",
            r"(llama\-\d+\-\d+b)(?:\-\w+)?",
            r"(mistral\-\w+)(?:\-\d+b)?",
            r"(gemini\-\d+\.\d+\-\w+)(?:\-\d+)?",
            r"(deepseek\-\w+)(?:\-\w+)?",
            r"(ernie(?:\-\d+\.\d+|\-\d+))",
            r"(glm(?:\-\d+\.\d+|\-\d+))",
            r"(baichuan\d+\-\d+b)",
            r"(yi\-\w+)(?:\-\d+b)?",
            r"(internlm\d+\-\d+b)",
            r"(falcon\-\d+b)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, model_name, re.I)
            if match:
                family = match.group(1).lower()
                logger.debug("Model '%s' mapped to family '%s'", model_name, family)
                return family

        logger.debug("Model '%s' could not be stripped to a known family", model_name)
        return "__default__"

    def get_template_characteristics(self, template_name: str) -> dict[str, Any]:
        """Get stealth/evasion characteristics for a template.

        Args:
            template_name: Template identifier

        Returns:
            Dict with keys: stealth_level, guardrail_evasion, notes
        """
        template_chars = self._raw.get("template_characteristics", {})
        return template_chars.get(template_name, {})

    def get_all_model_names(self) -> list[str]:
        """Get all model names in config."""
        return list(self._raw.get("model_families", {}).keys())

    def get_all_template_names(self) -> list[str]:
        """Get all template names in config."""
        return list(self._raw.get("template_characteristics", {}).keys())

    def get_optimal_converter_chain(
        self,
        model_name: str,
        guardrail_report: dict[str, Any] | None = None,
    ) -> list[str]:
        """Get optimal converter chain for a model.

        Filters converters based on guardrail severity.
        For strict guardrails, only high-stealth converters are used.

        Args:
            model_name: Target model name
            guardrail_report: Guardrail detection report (optional)

        Returns:
            List of converter names (ordered by priority)
        """
        seeds_config = self.get_seeds_for_model(model_name)

        # Determine stealth requirement from guardrail report
        stealth_required = "low"
        if guardrail_report and guardrail_report.get("has_guardrail"):
            severity = guardrail_report.get("severity", "moderate")
            if severity == "strict":
                stealth_required = "high"
            elif severity == "moderate":
                stealth_required = "moderate"
            else:
                stealth_required = "low"

        # Filter converters by stealth level
        # CONVERTER_STEALTH_MAP defines each converter's evasion capability
        CONVERTER_STEALTH_MAP = {
            "base64": "high",
            "rot13": "paranoid",  # Known weak against detection
            "leet_speak": "low",
            "humanizer": "high",
            "unicode_smuggling": "high",
            "accent_obfuscation": "high",
            "homoglyph_chinese": "high",
        }

        converters = seeds_config.get("optimal_converters", ["base64"])

        # Filter: keep converters with stealth >= required
        stealth_order = {"paranoid": 0, "low": 1, "moderate": 2, "high": 3}
        filtered = []
        for conv in converters:
            conv_stealth = CONVERTER_STEALTH_MAP.get(conv, "moderate")
            if stealth_order.get(conv_stealth, 0) >= stealth_order.get(stealth_required, 0):
                filtered.append(conv)

        return filtered or ["base64"]  # fallback: base64

    def _get_default(self, source: str = "fallback") -> dict[str, Any]:
        """Get default mapping (from config __default__ or empty fallback).

        Args:
            source: Source identifier for tracking

        Returns:
            Default seed mapping dict
        """
        default = self._raw.get("model_families", {}).get("__default__", {})
        if default:
            default["source"] = source
            return default
        # Fallback when YAML unavailable: return empty defaults
        return {
            "preferred_templates": [],
            "avoid_templates": [],
            "optimal_converters": [],
            "notes": "No mapping available - YAML loading failed",
            "source": "fallback_empty",
        }

# ====================================================================
# Module-level convenience functions (singleton pattern)
# ====================================================================

_default_mapper: ModelSeedMapper | None = None

def get_mapper() -> ModelSeedMapper:
    """Get or create singleton ModelSeedMapper instance."""
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = ModelSeedMapper()
    return _default_mapper

def get_seeds_for_model(model_name: str) -> dict[str, Any]:
    """Module-level convenience: get seeds for model (auto-loads YAML)."""
    return get_mapper().get_seeds_for_model(model_name)

def detect_model_family(model_name: str) -> str:
    """Module-level convenience: detect model family from name."""
    return get_mapper().detect_family(model_name)
