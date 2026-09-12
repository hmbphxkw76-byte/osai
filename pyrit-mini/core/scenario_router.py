"""core/scenario_router.py - Scenario routing and technique tag filtering (v62 cleanup).

Provides:
  - ScenarioRouter: Selects attack scenario based on classification
  - SynergyConfig dataclass: Lightweight config for technique tag filtering
  - apply_scenario_overrides: Apply scenario-specific technique filters

Data flow:
    classification -> router.select_scenario()
                   -> (name, {technique_tags, description, ...})
                   -> main.py: scenario_config.technique_tags = config["technique_tags"]

Academic basis:
    - NIST SP 800-115: Technical Guide to Information Security Testing
    - PyRIT (arXiv:2407.01232): TextAdaptive + technique_tags
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "defaults.yaml"


@dataclass
class ClassificationResult:
    """Classification result for attack surface detection.

    Attributes:
        attack_surface: Detected attack surface type
        confidence: Classification confidence [0.0, 1.0]
        evidence: List of evidence indicators
    """

    attack_surface: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


class ScenarioRouter:
    """
       - imports config/defaults.yaml Load scenario_technique_filters
       -  ClassificationResult
       -  (--scenario)

    v59 :
       - Load scenarios.yaml
       -  seeds/converters/scorer
       - ->technique_tags
    """

    def __init__(self, config_path: Path | None = None):
        """

        Args:
            config_path: defaults.yaml path (default: config/defaults.yaml)
        """
        self._config_path = config_path or CONFIG_PATH
        self._scenario_filters: dict[str, Any] = {}
        self._default_scenario = "model_scenario"
        self._load_config()

    def _load_config(self) -> None:
        """Load scenario_technique_filters from defaults.yaml.

        Falls back to hardcoded defaults if yaml unavailable.
        """
        # v60: Use hardcoded defaults
        default_filters: dict[str, Any] = {
            "mcp_scenario": {
                "description": "MCP Server  (Tag: mcp_targeted)",
                "triggers": {"attack_surface": "mcp_server", "min_confidence": 0.6},
                "technique_tags": ["mcp_targeted"],
            },
            "agent_scenario": {
                "description": " (Tag: agent_targeted)",
                "triggers": {"attack_surface": "multi_agent_system", "min_confidence": 0.6},
                "technique_tags": ["agent_targeted"],
            },
            "rag_scenario": {
                "description": "RAG  (Tag: rag_targeted)",
                "triggers": {"attack_surface": "rag_system", "min_confidence": 0.6},
                "technique_tags": ["rag_targeted"],
            },
            "model_scenario": {
                "description": " LLM  (, )",
                "triggers": {"attack_surface": "standard_llm_api", "min_confidence": 0.0},
                "technique_tags": None,  # None =
            },
        }

        try:
            if self._config_path.exists():
                import yaml

                with open(self._config_path, encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                if isinstance(config, dict):
                    scenario_filters = config.get("scenario_technique_filters", {})
                    # scenario_technique_filters scenario
                    surface_to_name = {
                        "mcp_server": "mcp_scenario",
                        "multi_agent_system": "agent_scenario",
                        "rag_system": "rag_scenario",
                        "standard_llm_api": "model_scenario",
                    }
                    for surface_name, surface_cfg in scenario_filters.items():
                        if isinstance(surface_cfg, dict):
                            self._scenario_filters[surface_to_name.get(surface_name, surface_name)] = {
                                "description": surface_cfg.get("description", f"{surface_name} scenario"),
                                "triggers": {
                                    "attack_surface": surface_name,
                                    "min_confidence": 0.6,
                                },
                                "technique_tags": surface_cfg.get("technique_tags"),
                            }
                    logger.debug(
                        "Loaded scenario_technique_filters from defaults.yaml: %d scenarios",
                        len(scenario_filters),
                    )
        except Exception as e:
            logger.debug("Failed to load scenario config: %s", e)

        self._scenario_filters = default_filters

    def select_scenario(
        self,
        classification: Any,
        user_override: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Select scenario based on classification (->)

        Args:
            classification: ClassificationResult (attack_surface, confidence)
            user_override: User-specified scenario (--scenario)

        Returns:
            (scenario_name, scenario_config)
        """
        # 1. User override takes priority
        if user_override:
            if user_override in self._scenario_filters:
                logger.info("Scenario forced by user: %s", user_override)
                return user_override, self._get_scenario_config(user_override)
            else:
                logger.warning("Unknown scenario '%s', falling back to auto", user_override)

        # 2. Auto-select based on scenario triggers
        for name, config in self._scenario_filters.items():
            if self._matches_trigger(classification, config):
                logger.info(
                    "Auto-selected scenario: %s (attack_surface=%s, confidence=%.2f, technique_tags=%s)",
                    name,
                    classification.attack_surface,
                    classification.confidence,
                    config.get("technique_tags"),
                )
                return name, config

        # 3. Fallback: default scenario
        default_name = self._default_scenario
        logger.info("No scenario matched, using default: %s", default_name)
        return default_name, self._get_scenario_config(default_name)

    def _matches_trigger(
        self,
        classification: Any,
        scenario_config: dict[str, Any],
    ) -> bool:
        """Check if classification matches scenario triggers.

        Args:
            classification: ClassificationResult
            scenario_config: Scenario configuration

        Returns:
            True if matches
        """
        triggers = scenario_config.get("triggers", {})

        # Attack surface must match
        if triggers.get("attack_surface") != classification.attack_surface:
            return False

        # Confidence must meet minimum
        min_conf = triggers.get("min_confidence", 0.0)
        if classification.confidence < min_conf:
            return False

        return True

    def list_scenarios(self) -> list[dict[str, Any]]:
        """List all available scenarios.

        Returns:
            List of scenario configs
        """
        result = []
        for name, config in self._scenario_filters.items():
            result.append(
                {
                    "name": name,
                    "description": config.get("description", ""),
                    "triggers": config.get("triggers", {}),
                    "technique_tags": config.get("technique_tags"),
                }
            )
        return result

    def _validate_scenario(self, name: str) -> bool:
        """Validate if scenario exists.

        Args:
            name: Scenario name

        Returns:
            True if valid
        """
        return name in self._scenario_filters

    def _get_scenario_config(self, name: str) -> dict[str, Any]:
        """Get scenario config by name.

        Args:
            name: Scenario name

        Returns:
            Scenario config or default
        """
        return self._scenario_filters.get(name, self._scenario_filters.get(self._default_scenario, {}))

    def format_scenarios_display(self) -> str:
        """Format all scenarios for display (--list-scenarios).

        Returns:
            Formatted string
        """
        scenarios = self.list_scenarios()
        if not scenarios:
            return "No scenarios available."

        lines = [
            "+==============================================================================+",
            "||                    Available Scenarios (v60 Tag-Based)                       ||",
            "+==============================================================================+",
        ]

        for i, sc in enumerate(scenarios, 1):
            triggers = sc.get("triggers", {})
            surface = triggers.get("attack_surface", "any")
            min_conf = triggers.get("min_confidence", 0.0)
            tags = sc.get("technique_tags")
            tags_str = ", ".join(tags) if tags else "all (no filter)"

            lines.extend(
                [
                    "||                                                                              ||",
                    f"||  {i}. {sc['name']:<68}||",
                    f"||     Description: {sc['description'][:50]:<52}||",
                    f"||     Triggers: surface={surface}, min_conf={min_conf:<36}||",
                    f"||     Technique Tags: {tags_str[:48]:<50}||",
                ]
            )

        lines.extend(
            [
                "||                                                                              ||",
                "+==============================================================================+",
            ]
        )

        return "\n".join(lines)


def apply_scenario_overrides(ctx: Any, scenario_config: dict[str, Any], args: Any) -> None:
    """Apply scenario-specific overrides to context.

    v60 implementation:
        - Apply scenario-specific seeds/scorer/converters filters
        - Use adaptive_technique_filter for technique selection

    Priority chain:
        - CLI --technique-filter > Scenario > defaults.yaml > defaults

    Args:
        ctx: PipelineContext to modify
        scenario_config: Selected scenario config (may contain technique_tags)
        args: CLI arguments
    """
    technique_tags = scenario_config.get("technique_tags")

    # v60: Apply technique_filter if not already set by CLI
    if not hasattr(args, "adaptive_technique_filter") or args.adaptive_technique_filter is None:
        if technique_tags is not None:
            ctx.args.adaptive_technique_filter = technique_tags
            logger.info("Applied scenario technique filter: %s", technique_tags)
    # technique_tags is None means no filtering (use all techniques)

    logger.info(
        "Applied scenario overrides (v60): technique_filter=%s",
        getattr(ctx.args, "adaptive_technique_filter", "not set (use all)"),
    )


# ==============================================================================
# Singleton
# ==============================================================================
_default_router: ScenarioRouter | None = None


def get_router() -> ScenarioRouter:
    """Get or create default ScenarioRouter singleton.

    Returns:
        Default ScenarioRouter instance
    """
    global _default_router
    if _default_router is None:
        _default_router = ScenarioRouter()
    return _default_router


def reset_router() -> None:
    """Reset the default router singleton.

    Useful for testing.
    """
    global _default_router
    _default_router = None


# ==============================================================================
# Synergy (v61 data/synergy_orchestrator.py )
# ==============================================================================


@dataclass
class SynergyConfig:
    """Synergy configuration for target-aware attack chain.

    Combines burp_profile, attack_surface, confidence, and technique_tags
    to enable scenario-based attack chain selection.

    v61: imports data/synergy_orchestrator.py  core/scenario_router.py.
    """

    burp_profile: str
    attack_surface: str
    confidence: float

    # v60: ( config/defaults.yaml -> scenario_technique_filters )
    technique_tags: list[str] | None = None  # None =

    evidence: list[str] = field(default_factory=list)
    synergy_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "burp_profile": self.burp_profile,
            "attack_surface": self.attack_surface,
            "confidence": self.confidence,
            "technique_tags": self.technique_tags,
            "evidence": self.evidence,
            "synergy_enabled": self.synergy_enabled,
        }

    def summary(self) -> str:
        """Human-readable summary."""
        return (
            f"SynergyConfig(\n"
            f"  burp_profile={self.burp_profile},\n"
            f"  attack_surface={self.attack_surface},\n"
            f"  confidence={self.confidence:.2f},\n"
            f"  technique_tags={self.technique_tags},\n"
            f"  synergy_enabled={self.synergy_enabled}\n"
            f")"
        )


# CLI : --list-scenarios
# ==============================================================================
def main() -> None:
    """CLI entry point for --list-scenarios."""
    router = get_router()
    print(router.format_scenarios_display())
