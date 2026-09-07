"""Model Seed Mapper - Load -> 

Academic basis:
    - Greshake et al. (arXiv:2302.12173) -  -> 
    - Mazeika et al. (arXiv:2406.18510) - WILDTEAMING: 
    - RedAmon Julius probe pack - API  -> 

Usage:
    >>> from recon.model_seed_mapper import ModelSeedMapper
    >>> mapper = ModelSeedMapper()
    >>> prefs = mapper.get_seeds_for_model("gpt-4o")
    >>> # prefs = {"preferred_templates": [...], "avoid_templates": [...], ...}
    >>>
    >>> # 
    >>> family = mapper.detect_family("gpt-4o-2024-08-06")
    >>> # family = "gpt-4o"
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml as _yaml

logger = logging.getLogger(__name__)

# SSOT 
_MAPPING_PATH = Path(__file__).resolve().parent.parent / "config" / "model_seed_mapping.yaml"


class ModelSeedMapper:
 """Load

    imports config/model_seed_mapping.yaml Load 90+ ,
     ->  -> 

    :
        -  (/gpt-4o-2024-08-06 -> gpt-4o)
        - cache ()
        -  ( -> __default__)
 """

    def __init__(self, mapping_path: Path | None = None) -> None:
 """

        Args:
            mapping_path: YAML  ()
 """
        self._mapping_path = mapping_path or _MAPPING_PATH
        self._config: dict[str, Any] | None = None
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def _raw(self) -> dict[str, Any]:
 """Load YAML """
        if self._config is None:
            self._config = self._load_config()
        return self._config

    def _load_config(self) -> dict[str, Any]:
 """imports YAML Load"""
        try:
            if self._mapping_path.exists():
                with open(self._mapping_path, encoding="utf-8") as f:
                    config = _yaml.safe_load(f)
                if isinstance(config, dict):
                    return config
        except Exception as e:
            logger.warning("Failed to load model seed mapping: %s", e)
        return {}

 # ============================================================
 # 
 # ============================================================

    def get_seeds_for_model(self, model_name: str) -> dict[str, Any]:
 """

        :
            1.  (gpt-4o)
            2.  (gpt-4o-2024-08-06 -> gpt-4o)
            3.  (my-gpt-4o-custom -> gpt-4o)
            4.  (__default__)

        Args:
            model_name:  ID /  ( "gpt-4o", "claude-3-opus-20240229")

        Returns:
            :
            {
                "preferred_templates": list[str],
                "avoid_templates": list[str],
                "optimal_converters": list[str],
                "notes": str,
                "source": str,  # : "exact" / "fuzzy" / "prefix" / "default"
            }
 """
        if not model_name:
            return self._get_default(seed_source="empty_name")

        model_lower = model_name.lower().strip()

 # 
        if model_lower in self._cache:
            return self._cache[model_lower]

        model_families = self._raw.get("model_families", {})

 # 1. 
        if model_lower in model_families:
            result = model_families[model_lower]
            result["source"] = "exact"
            self._cache[model_lower] = result
            return result

 # 2. + 
        family = self.detect_family(model_lower)
        if family and family != "__default__":
            if family in model_families:
                result = model_families[family]
                result["source"] = "fuzzy"
                self._cache[model_lower] = result
                return result

 # 3. (e.g., "my-gpt-4o-api")
        for key in model_families:
            if key in model_lower:
                result = model_families[key]
                result["source"] = "substring"
                self._cache[model_lower] = result
                return result

 # 4. 
        default_result = self._get_default(source="fallback")
        self._cache[model_lower] = default_result
        return default_result

    def detect_family(self, model_name: str) -> str:
 """imports

        :
            "gpt-4o-2024-08-06" -> "gpt-4o"
            "claude-3-opus-20240229" -> "claude-3-opus"
            "qwen2.5-72b-instruct" -> "qwen2.5-72b"
            "deepseek-v2-chat" -> "deepseek-v2"

        Args:
            model_name: 

        Returns:
            
 """
        if not model_name:
            return "__default__"

 # 
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
 """

        Args:
            template_name:  ( "authority_inference_key_given")

        Returns:
            :
            {
                "stealth_level": str,  # paranoid / low / moderate / high
                "guardrail_evasion": float,
                "notes": str,
            }
 """
        template_chars = self._raw.get("template_characteristics", {})
        return template_chars.get(template_name, {})

    def get_all_model_names(self) -> list[str]:
 """all"""
        return list(self._raw.get("model_families", {}).keys())

    def get_all_template_names(self) -> list[str]:
 """all"""
        return list(self._raw.get("template_characteristics", {}).keys())

    def get_optimal_converter_chain(
        self,
        model_name: str,
        guardrail_report: dict[str, Any] | None = None,
    ) -> list[str]:
 """ ()

        ,  converter ( rot13).
        /,  converter .

        Args:
            model_name: 
            guardrail_report:  ()

        Returns:
            Converter  ()
 """
        seeds_config = self.get_seeds_for_model(model_name)

        if guardrail_report and guardrail_report.get("has_guardrail"):
            severity = guardrail_report.get("severity", "moderate")
            if severity == "strict":
 # : converter
                stealth_required = "high"
            elif severity == "moderate":
                stealth_required = "moderate"
            else:
                stealth_required = "low"
        else:
            stealth_required = "low"

        converters = seeds_config.get("optimal_converters", ["base64"])

 # 
        CONVERTER_STEALTH_MAP = {
            "base64": "high",
            "rot13": "paranoid",  # , 
            "leet_speak": "low",
            "humanizer": "high",
            "unicode_smuggling": "high",
            "accent_obfuscation": "high",
            "homoglyph_chinese": "high",
        }

        filtered = []
        for conv in converters:
            conv_stealth = CONVERTER_STEALTH_MAP.get(conv, "low")
 # paranoid < low < moderate < high
            stealth_order = {"paranoid": 0, "low": 1, "moderate": 2, "high": 3}
            if stealth_order.get(conv_stealth, 0) >= stealth_order.get(stealth_required, 0):
                filtered.append(conv)

        return filtered or ["base64"]  # fallback: base64

 # ============================================================
 # 
 # ============================================================

    def _get_default(self, source: str = "fallback") -> dict[str, Any]:
 """"""
        default = self._raw.get("model_families", {}).get("__default__", {})
        if default:
            default["source"] = source
            return default
 # Hardcoded fallback ()
        return {
            "preferred_templates": [
                "authority_inference_key_given",
                "step_by_step_analysis",
                "direct_instruction",
            ],
            "avoid_templates": [],
            "optimal_converters": ["base64", "humanizer"],
            "notes": "Hardcoded fallback - YAML loading failed",
            "source": "hardcoded",
        }


# ====================================================================
# ()
# ====================================================================

_default_mapper: ModelSeedMapper | None = None


def get_mapper() -> ModelSeedMapper:
 """ ModelSeedMapper """
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = ModelSeedMapper()
    return _default_mapper


def get_seeds_for_model(model_name: str) -> dict[str, Any]:
 """: 

    , Load YAML
 """
    return get_mapper().get_seeds_for_model(model_name)


def detect_model_family(model_name: str) -> str:
 """: """
    return get_mapper().detect_family(model_name)
