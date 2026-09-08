"""Config Parser Helpers - argument parsing utilities.

Extracted from core/config.py: defaults, config file loading,
CSV/normalization helpers, and individual field parsers.
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Path constants
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULTS_YAML = _PROJECT_ROOT / "config" / "defaults.yaml"


def _load_defaults() -> dict[str, Any]:
    """imports config/defaults.yaml Load (SSOT)."""
    if not _DEFAULTS_YAML.exists():
        return {}
    try:
        with open(_DEFAULTS_YAML, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("Failed to load defaults.yaml: %s", e)
        return {}

def _apply_defaults(args: argparse.Namespace, defaults: dict[str, Any]) -> None:
    """ YAML args None ."""
    key_map = {"scenario_timeout": "timeout"}
    for yaml_key, default_val in defaults.items():
        arg_key = key_map.get(yaml_key, yaml_key)
        current = getattr(args, arg_key, None)
        if current is None:
            setattr(args, arg_key, default_val)

def _load_config_file(path: str) -> dict[str, Any]:
    """Load --config-file YAML

     YAML  ( Campaign Schema v2.0):
        name: string           # Campaign
        description: string    # Campaign
        version: string        #
        targets: [string]      # Burp ( config/burp/burp/)
        strategy:              #
            mode: string       # single_turn | multi_turn | adaptive
            intensity: string  # minimal | standard | maximum
        attack_surface: string # ( asset_index.yaml)
        orchestration:         #
            seeds: [string]    #
            converters: [string] #
            techniques: [string] #
            scorers: [string]  #
        execution:             #
            max_seeds: int
            max_attempts: int
            max_concurrency: int
            timeout: int
            escalation: bool
            html_report: bool
        memory_labels: dict    # ( CentralMemory)
        seed_filters: dict     # (KEY=VALUE)

     ():
        seeds: string          # ()
        converters: string     # Converter (auto, l5_optimal, none, technique:converter.xxx )
        techniques: string     # (auto, single, crescendo, ...)
        burp: [string]         # Burp
        max_seeds: int
        max_attempts: int
        max_concurrency: int
        timeout: int
        add_initializer: [string]  # Initializer
        offensive: bool
        escalation: bool
        html_report: bool
        rate_limit: int
        target_api_endpoint: string
        target_api_key: string
        target_api_model: string
        target_api_type: string  # chat | responses
        litellm_model: string
        browser_url: string
    """
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = _PROJECT_ROOT / config_path
    if not config_path.exists():
        logger.warning("Config file not found: %s", config_path)
        return {}
    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            logger.warning("Config file %s is not a dict, ignoring", config_path)
            return {}
        logger.info("Loaded config file: %s (%d keys)", config_path, len(data))
        return data
    except Exception as e:
        logger.warning("Failed to load config file %s: %s", config_path, e)
        return {}

def _normalize_list_to_csv(value: Any, key: str = "") -> Any:
    """ YAML list ()

    :
        seeds: [core/, encoding/]  ->  "core/,encoding/"
        converters: [l5_optimal]    ->  "l5_optimal"
        techniques: [auto]          ->  "auto"

     (//None )
    """
    if isinstance(value, list):
        return ",".join(str(v).strip() for v in value if str(v).strip())
    return value

def _apply_config_file(args: argparse.Namespace, config: dict[str, Any]) -> None:
    """ --config-file YAML args None

    : CLI --flag > --config-file > config/defaults.yaml >
    Therefore, args  None

     YAML  section (all section  key  args Layer,  defaults.yaml key ):
        scoring:       # - T0/J1/J2/J3
            dual_judge_enabled: bool
            dual_judge_high_confidence_threshold: float
            wilson_confidence_level: float
            scorer_timeout: int
            best_of_n_retries: int
        escalation:    # - Crescendo/TAP/PAIR
            escalation_asr_threshold: float
            post_l1_exit_threshold: float
            post_l2_exit_threshold: float
            max_escalation_targets: int
            crescendo_max_turns: int
            tap_tree_width: int
            tap_tree_depth: int
            tap_branching: int
            tap_success_threshold: int
            pair_tree_width: int
            pair_tree_depth: int
            escalation_levels: string  # ( "L2,L4"),
        probe:         #
            probe_timeout: int
            probe_retries: int
            deep_probe_timeout: int
            parallel_probe_timeout: int
            max_concurrent_probes: int
        adaptive:      # PyRIT TextAdaptive
            adaptive_epsilon: float
            adaptive_random_seed: int
            adaptive_max_attempts: int
            adaptive_technique_filter: list | null
        execution:     #
            max_concurrency: int
            max_attempts: int
            max_seeds: int
            scenario_timeout: int
            api_timeout: int
            rate_limit: int
            l5_optimal_paths: int
            auto_seed_expansion_factor: int
        strategy:      #
            mode: string
            intensity: string
        orchestration: #
            seeds: list
            converters: list
            techniques: list
            scorers: list
    """
 # == : seeds/converters/techniques/scorers list CSV ==
 # seeds: [core/, encoding/] seeds: "core/,encoding/"
    _list_to_csv_keys = ("seeds", "converters", "techniques", "scorers")
    for _key in _list_to_csv_keys:
        if _key in config:
            config[_key] = _normalize_list_to_csv(config[_key], _key)

 # /: None
    _str_keys = [
        "seeds", "converters", "techniques", "max_seeds", "max_attempts",
        "max_concurrency", "timeout", "rate_limit",
        "litellm_model", "target_api_endpoint", "target_api_key",
        "target_api_model", "target_api_type", "browser_url",
    ]
    for key in _str_keys:
        yaml_val = config.get(key)
        if yaml_val is not None and getattr(args, key, None) is None:
            setattr(args, key, yaml_val)

 # burp: - config_file burp , args.burp None
    burp_cfg = config.get("burp")
    if burp_cfg is not None and args.burp is None:
        if isinstance(burp_cfg, list):
            args.burp = burp_cfg[0] if len(burp_cfg) == 1 else burp_cfg
        else:
            args.burp = burp_cfg

 # bool : None/
    if config.get("offensive") is not None and not args.offensive:
        args.offensive = bool(config["offensive"])
    if config.get("html_report") is not None and not args.html_report:
        args.html_report = bool(config["html_report"])
    if config.get("escalation") is not None and args.escalation is None:
        args.escalation = bool(config["escalation"])

 # escalation_levels: config_file ( "L2,L4"), CLI
 # CLI --escalation-levels (None), config_file
 # parse_args _parse_escalation_levels
    el_cfg = config.get("escalation_levels")
    if el_cfg is not None and getattr(args, "escalation_levels", None) is None:
        if isinstance(el_cfg, (str, list)):
            args.escalation_levels = ",".join(el_cfg) if isinstance(el_cfg, list) else el_cfg

 # memory_labels: config_file dict, CLI JSON
 # CLI --memory-labels (None), config_file
    ml_cfg = config.get("memory_labels")
    if ml_cfg is not None and args.memory_labels is None:
        if isinstance(ml_cfg, dict):
            args.memory_labels = ml_cfg  # _parse_memory_labels dict

 # seed_filters: config_file dict, CLI KEY=VALUE
    sf_cfg = config.get("seed_filters")
    if sf_cfg is not None and args.seed_filters is None:
        if isinstance(sf_cfg, dict):
         # KEY=VALUE , _parse_seed_filters
            args.seed_filters = ",".join(f"{k}={v}" for k, v in sf_cfg.items())

 # add_initializer: config_file
    ai_cfg = config.get("add_initializer")
    if ai_cfg is not None and args.add_initializer is None:
        if isinstance(ai_cfg, list):
            args.add_initializer = [str(x) for x in ai_cfg]

 # == Campaign Schema v2.0: targets -> burp ==
 # targets: [mocka, mockb] args.burp (CLI )
    targets_cfg = config.get("targets")
    if targets_cfg is not None and args.burp is None:
        if isinstance(targets_cfg, list):
         # : , parse_args burp
            args.burp = [str(t) for t in targets_cfg]
            logger.info("campaign schema v2.0: targets -> burp = %s", args.burp)
        elif isinstance(targets_cfg, str):
            args.burp = [targets_cfg]

    # == Campaign Schema v2.0: attack_surface args ==
    attack_surface_cfg = config.get("attack_surface")
    if attack_surface_cfg is not None:
        args.attack_surface = str(attack_surface_cfg)
        logger.info("campaign schema v2.0: attack_surface = %s", args.attack_surface)

 # == Campaign Schema v2.0: strategy adaptive_technique_filter ==
    strategy_cfg = config.get("strategy")
    if isinstance(strategy_cfg, dict):
     # mode: single_turn / multi_turn / adaptive -> adaptive_technique_filter
        strategy_mode = strategy_cfg.get("mode")
        if strategy_mode and getattr(args, "adaptive_technique_filter", None) is None:
            if strategy_mode == "single_turn":
                args.adaptive_technique_filter = ["single_turn"]
            elif strategy_mode == "multi_turn":
                args.adaptive_technique_filter = ["multi_turn"]
            elif strategy_mode == "adaptive":
                args.adaptive_technique_filter = None  # None =
            logger.info("campaign schema v2: strategy.mode -> adaptive_technique_filter = %s",
                        args.adaptive_technique_filter)

 # == section: scoring / escalation / probe / adaptive / execution ==
 # section key args Layer ( defaults.yaml key )
 # _apply_config_file _apply_defaults ,
 # defaults.yaml ( None)
    _section_keys = [
        # scoring section -
        ("scoring", ["dual_judge_enabled", "dual_judge_high_confidence_threshold",
                     "wilson_confidence_level", "scorer_timeout", "best_of_n_retries"]),
        # escalation section -
        ("escalation", ["escalation_asr_threshold", "post_l1_exit_threshold",
                        "post_l2_exit_threshold", "max_escalation_targets",
                        "crescendo_max_turns", "tap_tree_width", "tap_tree_depth",
                        "tap_branching", "tap_success_threshold",
                        "pair_tree_width", "pair_tree_depth", "escalation_levels",
                        "priority_scheduler_enabled", "priority_scheduler_high_threshold",
                        "priority_scheduler_low_threshold", "priority_scheduler_epsilon"]),
        # probe section -
        ("probe", ["probe_timeout", "probe_retries", "deep_probe_timeout",
                   "parallel_probe_timeout", "max_concurrent_probes"]),
        # adaptive section - PyRIT TextAdaptive
        ("adaptive", ["adaptive_epsilon", "adaptive_random_seed",
                      "adaptive_max_attempts", "adaptive_technique_filter"]),
        # execution section - ( _str_keys )
        ("execution", ["scenario_timeout", "api_timeout", "rate_limit_retries",
                       "timeout_max_retries", "timeout_max_delay",
                       "l5_optimal_paths", "auto_seed_expansion_factor",
                       "rate_limit", "max_concurrency", "max_attempts", "max_seeds"]),
    ]

    for section_name, keys in _section_keys:
        section_data = config.get(section_name)
        if not isinstance(section_data, dict):
            continue
        for key in keys:
            if key not in section_data:
                continue
            val = section_data[key]
 # args None (CLI )
            if getattr(args, key, None) is None:
                setattr(args, key, val)
                logger.debug("config-file section '%s': %s = %s", section_name, key, val)

 # == Campaign Schema v2.0: orchestration section ==
 # orchestration.seeds/converters/techniques/scorers list -> CSV
    orch_cfg = config.get("orchestration")
    if isinstance(orch_cfg, dict):
        _orch_key_map = {
            "seeds": "seeds",
            "converters": "converters",
            "techniques": "techniques",
            "scorers": "scorers",
        }
        for _yaml_key, _arg_key in _orch_key_map.items():
            if _yaml_key not in orch_cfg:
                continue
            _val = orch_cfg[_yaml_key]
            if _val is not None and getattr(args, _arg_key, None) is None:
                if isinstance(_val, list):
                    setattr(args, _arg_key, ",".join(str(v).strip() for v in _val if str(v).strip()))
                else:
                    setattr(args, _arg_key, str(_val))
                logger.info("campaign schema v2: orchestration.%s -> args.%s = %s",
                            _yaml_key, _arg_key, getattr(args, _arg_key))

def _parse_memory_labels(raw: Any) -> dict[str, str]:
    """ --memory-labels dict

    :
        - JSON : '{"run_id":"r001","target":"deepseek"}'
        - dict ( config_file):
        - None/:  {}
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
            logger.warning("--memory-labels JSON is not a dict: %s", type(parsed).__name__)
        except json.JSONDecodeError as e:
            logger.warning("--memory-labels is not valid JSON: %s (value=%s)", e, raw[:100])
    return {}

def _parse_seed_filters(raw: Any) -> dict[str, str]:
    """ --seed-filters dict

    :
        -  KEY=VALUE: "owasp_id=LLM01,difficulty=high"
        - dict ( config_file):
        - None/:  {}
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str):
        result: dict[str, str] = {}
        for pair in raw.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                logger.warning("Invalid seed-filter (expected KEY=VALUE): %s", pair)
                continue
            k, v = pair.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                result[k] = v
        return result
    return {}

def _parse_converter_overrides(converters_str: str | None) -> dict[str, list[str]]:
    """ --converters technique:converter.xxx

    : --converters "auto;tap:persuasion;pair:decomposition,base64"
    - :  converter ,  per-technique
    -  technique ,  converter chain
    -  {technique: [chain_name, ...]}

    ,  {} ()
    """
    if not converters_str or ";" not in converters_str:
        return {}

    overrides: dict[str, list[str]] = {}
    parts = converters_str.split(";")
    for part in parts[1:]:  # Skipconverter(s) ()
        part = part.strip()
        if not part or ":" not in part:
            continue
        tech, chains = part.split(":", 1)
        tech = tech.strip()
        chain_list = [c.strip() for c in chains.split(",") if c.strip()]
        if tech and chain_list:
            overrides[tech] = chain_list
    return overrides

def _parse_converter_global(converters_str: str | None) -> str:
    """ --converters converter ()

    "auto;tap:persuasion" -> "auto"
    "l5_optimal" -> "l5_optimal"
    "none;pair:base64" -> "none"
    """
    if not converters_str:
        return "auto"
    if ";" in converters_str:
        return converters_str.split(";")[0].strip()
    return converters_str.strip()

def _parse_initializer_specs(raw: list[str] | None) -> list[dict[str, Any]]:
    """ --add-initializer spec

    : ["ClassName,arg1=val1,arg2=val2", "OtherInit"]
    : [
        {"class": "ClassName", "args": {"arg1": "val1", "arg2": "val2"}},
        {"class": "OtherInit", "args": {}},
    ]
    """
    if not raw:
        return []
    specs: list[dict[str, Any]] = []
    for item in raw:
        parts = item.split(",")
        class_name = parts[0].strip()
        if not class_name:
            continue
        kwargs: dict[str, str] = {}
        for part in parts[1:]:
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                kwargs[k] = v
        specs.append({"class": class_name, "args": kwargs})
    return specs

def _parse_escalation_levels(raw: str) -> set[int] | None:
    """ --escalation-levels

    :
        - : "L1,L2,L4" -> {1, 2, 4}
        - : "L1-L4" -> {1, 2, 3, 4}
        - : "L1,L3-L4" -> {1, 3, 4}
        - : "l1,l2" -> {1, 2}
        - "all" -> {1, 2, 3, 4}
        - "none"/"" -> None ()

    Args:
        raw:

    Returns:
         ( {1, 2, 4}), None
    """
    if not raw or not raw.strip():
        return None
    raw = raw.strip().lower()
    if raw == "all":
        return {1, 2, 3, 4}
    if raw in ("none", "default"):
        return None

    levels: set[int] = set()
    parts = raw.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
 # : L1-L4
        if "-" in part:
            range_parts = part.split("-")
            if len(range_parts) == 2:
                try:
                    start = int(range_parts[0].strip().lstrip("lL"))
                    end = int(range_parts[1].strip().lstrip("lL"))
                    for i in range(start, end + 1):
                        if 1 <= i <= 4:
                            levels.add(i)
                except ValueError:
                    logger.warning("Invalid escalation level range: %s", part)
            continue
 # : L1
        try:
            num = int(part.lstrip("lL"))
            if 1 <= num <= 4:
                levels.add(num)
            else:
                logger.warning("Escalation level out of range (1-4): %s", part)
        except ValueError:
            logger.warning("Invalid escalation level: %s", part)

    if not levels:
        logger.warning("No valid escalation levels parsed from '%s', using full chain", raw)
        return None
    return levels

