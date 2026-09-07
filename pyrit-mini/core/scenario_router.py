"""core/scenario_router.py - -> (v61 synergy_orchestrator)

v61 :
  -  data/synergy_orchestrator.py  SynergyOrchestrator + SynergyConfig
  - data/ Layer,  Python 
  - ""  "":  -> technique_tags -> TextAdaptive
  -  API  (select_scenario  (name, config) )

:
     (ClassificationResult)
           v
    config/defaults.yaml -> scenario_technique_filters 
           v
    (scenario_name, {technique_tags, description, ...})

Data flow:
    classification -> router.select_scenario()
                   -> (name, {technique_tags, description, ...})
                   -> main.py: synergy_config.technique_tags = config["technique_tags"]

:
    SynergyOrchestrator  SynergyConfig ,  main.py 

Academic basis:
    - NIST SP 800-115: 
    - PyRIT (arXiv:2407.01232): TextAdaptive + technique_tags 
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "defaults.yaml"


class ScenarioRouter:
 """-> (v60)

    :
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
            config_path: defaults.yaml  (: config/defaults.yaml)
 """
        self._config_path = config_path or CONFIG_PATH
        self._scenario_filters: dict[str, Any] = {}
        self._default_scenario = "model_scenario"
        self._load_config()

    def _load_config(self) -> None:
 """imports defaults.yaml Load scenario_technique_filters .

        : .
 """
 # v60: ()
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
            import yaml

            if self._config_path.exists():
                with open(self._config_path, "r", encoding="utf-8") as f:
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
                        scenario_name = surface_to_name.get(surface_name, f"{surface_name}_scenario")
                        if isinstance(surface_cfg, dict):
                            default_filters[scenario_name] = {
                                "description": surface_cfg.get(
                                    "description",
                                    f"{surface_name} "
                                ),
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
            logger.warning("Failed to load scenario config: %s, using defaults", e)

        self._scenario_filters = default_filters

    def select_scenario(
        self,
        classification: Any,
        user_override: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
 """ Scenario (->)

        Args:
            classification:  ( attack_surface, confidence )
            user_override:  Scenario  (--scenario)

        Returns:
            (scenario_name, scenario_config) 
 """
 # 1. 
        if user_override:
            if self._validate_scenario(user_override):
                logger.info("Scenario forced by user: %s", user_override)
                return user_override, self._get_scenario_config(user_override)
            else:
                logger.warning("Invalid scenario '%s', falling back to auto", user_override)

 # 2. : Scenario triggers
        for name, config in self._scenario_filters.items():
            if self._matches_trigger(classification, config):
                logger.info(
                    "Auto-selected scenario: %s (attack_surface=%s, confidence=%.2f, technique_tags=%s)",
                    name, classification.attack_surface, classification.confidence,
                    config.get("technique_tags"),
                )
                return name, config

 # 3. Fallback: Scenario
        default_name = self._default_scenario
        logger.info("No scenario matched, using default: %s", default_name)
        return default_name, self._get_scenario_config(default_name)

    def _matches_trigger(
        self,
        classification: Any,
        scenario_config: dict[str, Any],
    ) -> bool:
 """ Scenario triggers .

        Args:
            classification: 
            scenario_config: Scenario 

        Returns:
            
 """
        triggers = scenario_config.get("triggers", {})

 # 
        if triggers.get("attack_surface") != classification.attack_surface:
            return False

 # 
        min_conf = triggers.get("min_confidence", 0.0)
        if classification.confidence < min_conf:
            return False

        return True

    def list_scenarios(self) -> list[dict[str, Any]]:
 """all Scenario

        Returns:
            Scenario 
 """
        result = []
        for name, config in self._scenario_filters.items():
            result.append({
                "name": name,
                "description": config.get("description", ""),
                "triggers": config.get("triggers", {}),
                "technique_tags": config.get("technique_tags"),
            })
        return result

    def _validate_scenario(self, name: str) -> bool:
 """ Scenario 

        Args:
            name: Scenario 

        Returns:
            
 """
        return name in self._scenario_filters

    def _get_scenario_config(self, name: str) -> dict[str, Any]:
 """ Scenario 

        Args:
            name: Scenario 

        Returns:
            Scenario  model_scenario
 """
        return self._scenario_filters.get(name, self._scenario_filters.get(self._default_scenario, {}))

    def format_scenarios_display(self) -> str:
 """all Scenario ( --list-scenarios )

        Returns:
             Scenario 
 """
        scenarios = self.list_scenarios()
        if not scenarios:
            return "No scenarios configured."

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

            lines.extend([
                "||                                                                              ||",
                f"||  {i}. {sc['name']:<68}||",
                f"||     Description: {sc['description'][:50]:<52}||",
                f"||     Triggers: surface={surface}, min_conf={min_conf:<36}||",
                f"||     Technique Tags: {tags_str[:48]:<50}||",
            ])

        lines.extend([
            "||                                                                              ||",
            "+==============================================================================+",
        ])

        return "\n".join(lines)


def apply_scenario_overrides(ctx: Any, scenario_config: dict[str, Any], args: Any) -> None:
 """ Scenario ctx.args (v60 ).

    v60 :
        -  seeds/scorer/converters 
        -  adaptive_technique_filter ()

    :
        -  CLI 
        - : CLI --technique-filter > Scenario > defaults.yaml > 

    Args:
        ctx:  (PipelineContext)
        scenario_config:  Scenario  ( technique_tags)
        args: CLI 
 """
 # v60: technique_filter ()
    if not hasattr(args, "adaptive_technique_filter") or args.adaptive_technique_filter is None:
        technique_tags = scenario_config.get("technique_tags")
        if technique_tags is not None:
 # scenario's technique_tags adaptive_technique_filter
            ctx.args.adaptive_technique_filter = technique_tags
            logger.info(
                "Applied scenario technique filter: %s", technique_tags
            )
 # technique_tags None, ()

    logger.info(
        "Applied scenario overrides (v60): technique_filter=%s",
        getattr(ctx.args, "adaptive_technique_filter", "not set (use all)"),
    )


# ==============================================================================
# 
# ==============================================================================
_default_router: ScenarioRouter | None = None


def get_router() -> ScenarioRouter:
 """ Scenario router

    Returns:
         ScenarioRouter 
 """
    global _default_router
    if _default_router is None:
        _default_router = ScenarioRouter()
    return _default_router


def reset_router() -> None:
 """router ()"""
    global _default_router
    _default_router = None


# ==============================================================================
# Synergy (v61 data/synergy_orchestrator.py )
# ==============================================================================
from dataclasses import dataclass, field


@dataclass
class SynergyConfig:
 """ (v60 ).

    :  + .
    v61: imports data/synergy_orchestrator.py  core/scenario_router.py.
 """

 # 
    burp_profile: str
    attack_surface: str
    confidence: float

 # v60: ( config/defaults.yaml -> scenario_technique_filters )
    technique_tags: list[str] | None = None  # None = 

 # 
    evidence: list[str] = field(default_factory=list)
    synergy_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
 """."""
        return {
            "burp_profile": self.burp_profile,
            "attack_surface": self.attack_surface,
            "confidence": self.confidence,
            "technique_tags": self.technique_tags,
            "evidence": self.evidence,
            "synergy_enabled": self.synergy_enabled,
        }

    def summary(self) -> str:
 """."""
        return (
            f"SynergyConfig(\n"
            f"  burp_profile={self.burp_profile},\n"
            f"  attack_surface={self.attack_surface},\n"
            f"  confidence={self.confidence:.2f},\n"
            f"  technique_tags={self.technique_tags},\n"
            f"  synergy_enabled={self.synergy_enabled}\n"
            f")"
        )


def _split_burp_content(burp_content: str) -> tuple[str, str]:
 """imports Burp HTTP .

    Burp :
        HTTP  (headers + body)
        ()
        HTTP/1.1 200 OK
        ... ( headers + body)

    Args:
        burp_content: Burp 

    Returns:
        (http_request, http_response) 
 """
    lines = burp_content.split("\n")
    response_start = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("HTTP/1."):
            response_start = i
            break

    if response_start == -1:
        return burp_content, ""

    http_request = "\n".join(lines[:response_start]).strip()
    http_response = "\n".join(lines[response_start:]).strip()
    return http_request, http_response


class SynergyOrchestrator:
 """-> (v61 core/).

    :
      1.  ( + HTTP )
      2.  -> technique_tags  ( config/defaults.yaml)

    v61: imports data/synergy_orchestrator.py  core/scenario_router.py.
 """

    def __init__(
        self,
        data_root: Path | None = None,
        burp_dir: Path | None = None,
    ):
 """
        .

        Args:
            data_root:  (: project/data)
            burp_dir: Burp  (: config/burp)
 """
        self._data_root = data_root or PROJECT_ROOT / "data"
 # v63: burp config/burp (, )
        self._burp_dir = burp_dir or (PROJECT_ROOT / "config" / "burp")

 # 
        self._mapper = None
        self._tag_mapping: dict[str, list[str] | None] | None = None

    @property
    def mapper(self):
 """Load AssetMapper."""
        if self._mapper is None:
            from core.asset_mapper import AssetMapper
            self._mapper = AssetMapper()
        return self._mapper

    def _load_tag_mapping(self) -> dict[str, list[str] | None]:
 """imports config/defaults.yaml Load->technique_tags .

        v60: ,  scenarios.yaml .

        Returns:
             -> technique_tags 
 """
        if self._tag_mapping is not None:
            return self._tag_mapping

        default_mapping: dict[str, list[str] | None] = {
            "mcp_server": ["mcp_targeted"],
            "multi_agent_system": ["agent_targeted"],
            "rag_system": ["rag_targeted"],
            "standard_llm_api": None,  # None = 
        }

        try:
            import yaml

            config_path = PROJECT_ROOT / "config" / "defaults.yaml"
            if config_path.exists():
                with open(config_path, encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                scenario_filters = config.get("scenario_technique_filters", {})
                if scenario_filters:
                    for surface, cfg in scenario_filters.items():
                        if isinstance(cfg, dict) and "technique_tags" in cfg:
                            default_mapping[surface] = cfg["technique_tags"]
                    logger.debug(
                        "Loaded scenario_technique_filters from defaults.yaml: %d surfaces",
                        len(scenario_filters),
                    )
        except Exception as e:
            logger.warning("Failed to load scenario_technique_filters: %s, using defaults", e)

        self._tag_mapping = default_mapping
        return default_mapping

    def build_synergy_config(
        self,
        burp_profile_name: str,
        burp_content: str | None = None,
        force_surface: str | None = None,
    ) -> SynergyConfig:
 """ ( + ).

        :  Burp  + .

        Args:
            burp_profile_name: Burp  ( "mcp05")
            burp_content: Burp  ()
            force_surface:  ()

        Returns:
            SynergyConfig:  attack_surface + technique_tags
 """
        logger.info("Building synergy config for burp profile: %s", burp_profile_name)

 # == Step 1: ==
        if force_surface:
            attack_surface = force_surface
            confidence = 1.0
            evidence = [f"Forced surface type: {force_surface}"]
        elif burp_content:
 # 
            from recon.attack_surface_classifier import classify_http_content

            url = self._extract_url(burp_content)
            http_request, http_response = _split_burp_content(burp_content)
            result = classify_http_content(
                http_request=http_request,
                http_response=http_response,
                url=url,
            )
            attack_surface = result.attack_surface
            confidence = result.confidence
            evidence = result.evidence
        else:
 # 
            attack_surface = self.mapper.classify_attack_surface(burp_profile_name)
            confidence = 0.6
            evidence = ["File-name based classification"]

 # == Step 2: -> technique_tags ==
        tag_mapping = self._load_tag_mapping()
        technique_tags = tag_mapping.get(attack_surface)

        logger.info(
            "Synergy config ready: surface=%s, technique_tags=%s, confidence=%.2f",
            attack_surface, technique_tags, confidence,
        )

        return SynergyConfig(
            burp_profile=burp_profile_name,
            attack_surface=attack_surface,
            confidence=confidence,
            technique_tags=technique_tags,
            evidence=evidence,
            synergy_enabled=True,
        )

    def build_from_burp_file(self, burp_filename: str) -> SynergyConfig:
 """imports Burp .

        :  Burp .

        Args:
            burp_filename: Burp  ( "mcp05.txt")

        Returns:
            SynergyConfig
 """
        profile_name = burp_filename.replace(".txt", "")

        burp_content = None
        burp_file = self._burp_dir / burp_filename
        if burp_file.exists():
            try:
                burp_content = burp_file.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                logger.warning("Failed to read burp file %s: %s", burp_file, e)
        else:
            logger.debug("Burp file not found: %s", burp_file)

        return self.build_synergy_config(profile_name, burp_content)

    @staticmethod
    def _extract_url(http_content: str) -> str | None:
 """imports HTTP URL."""
        first_line = http_content.split("\n", 1)[0].strip()
        parts = first_line.split()
        if len(parts) >= 2:
            return parts[1]
        return None


# ==============================================
# (Synergy Layer)
# ==============================================
_default_orchestrator: SynergyOrchestrator | None = None


def get_orchestrator() -> SynergyOrchestrator:
 """."""
    global _default_orchestrator
    if _default_orchestrator is None:
        _default_orchestrator = SynergyOrchestrator()
    return _default_orchestrator


def quick_build(burp_profile_name: str) -> SynergyConfig:
 """.

    Args:
        burp_profile_name: Burp 

    Returns:
        SynergyConfig
 """
    return get_orchestrator().build_synergy_config(burp_profile_name)


def build_from_burp_file(burp_filename: str) -> SynergyConfig:
 """imports Burp .

    Args:
        burp_filename: Burp 

    Returns:
        SynergyConfig
 """
    return get_orchestrator().build_from_burp_file(burp_filename)


def get_cli_overrides(burp_profile_name: str) -> dict[str, Any]:
 """ CLI ( main.py ).

    v60:  attack_surface + technique_tags,  seeds/scorer.

    Args:
        burp_profile_name: Burp 

    Returns:
        
 """
    config = quick_build(burp_profile_name)

    return {
        "attack_surface": config.attack_surface,
        "technique_filter": config.technique_tags,
        "synergy_enabled": config.synergy_enabled,
    }


# ==============================================================================
# CLI : --list-scenarios
# ==============================================================================
def main() -> None:
 """CLI : all Scenario"""
    router = get_router()
    print(router.format_scenarios_display())


if __name__ == "__main__":
 # : python -m core.scenario_router
    logging.basicConfig(level=logging.INFO)
    main()
