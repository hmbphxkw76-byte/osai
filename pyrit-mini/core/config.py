"""CLI Parameter parsing + Environment initialization + Output directory

:
    : CLI --flag > --config-file YAML > config/defaults.yaml > 

:
    - parse_args: CLI Parameter parsing (argparse)
    - load_config_file: Load --config-file  YAML 
    - get_output_dir: Output directory ()
    - ensure_output_dir: Output directory
    - setup_environment: PyRIT Environment initialization (SQLite WAL )

 (pyrit_scan CLI ):
    - --memory-labels:  (JSON),  CentralMemory 
    - --seed-filters:  (KEY=VALUE), 
    - --converters  technique:converter.xxx : per-technique  converter
    - --add-initializer:  Target  (class_name,arg=value)
    - --config-file:  YAML ,  seeds/converters/techniques/burp
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

# .env (python-dotenv)
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

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
 # core/asset_mapper.py asset_index.yaml
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
 """ CLI - .

    Args:
        argv: None  sys.argv

    Returns:
        argparse Namespace ,  YAML 
 """
    parser = argparse.ArgumentParser(
        description="PyRIT-Strike - Burp->->->Converter->->-> ",
    )

 # == ==
 # 7 ( OWASP AI-300 Five-Step + PyRIT ):
 # recon -> Burp + + + HTTPTarget 
 # arm -> /ASR + Converter + 
 # strike -> PyRIT (PromptSendingAttack FIRST_SUCCESS)
 # escalate -> (Crescendo->TAP->PAIR->GCG->native, ASR<90% )
 # assess -> T0->J1->J2->J3 + ASR + Wilson CI
 # report -> + MD/HTML/JSON/PoC/SARIF 
 # --stage (strike+escalate ), 
    parser.add_argument(
        "--stage",
        type=str,
        default=None,
        choices=["recon", "arm", "strike", "escalate", "assess", "report"],
        help=" (recon/arm/strike/escalate/assess/report), "
             "",
    )

 # == : Burp ==
 # : --burp <name> () --burp MM_05 --burp MM_03 ()
 # v61: config/burp/burp/
 # config/burp/burp/<name>.txt
 # config/burp/burp/*.txt 
 # : --burp config/burp/burp/deepseek.txt
 # endpoint: --burp MM_05 --burp MM_03 --burp MM_08
 # endpoint , Ensure
 # Academic basis: Greshake et al. (arXiv:2302.12173) - + ASR
    parser.add_argument(
        "--burp",
        type=str,
        default=None,
        metavar="NAME",
        action="append",
        help="Burp  HTTP  ( config/burp/burp/<NAME>.txt), "
             "converter(s) endpoint;  config/burp/burp/*.txt ",
    )

 # == ==
    parser.add_argument(
        "--seeds",
        type=str,
        default=None,  # config-file defaults.yaml , fallback "elite_jailbreaks,asi_top10,owasp_full_coverage"
        help=" ()",
    )
    parser.add_argument("--max-seeds", type=int, default=None, help=" ( 25)")
    parser.add_argument("--auto-seeds", action="store_true", default=False, help=" (3x)")
    parser.add_argument("--enable-dos", action="store_true", default=False, help=" DoS ")

 # == Converter ==
    parser.add_argument(
        "--converters", type=str, default=None, help="Converter  (auto, l5_optimal, none, ...)"
    )

 # == ==
    parser.add_argument(
        "--techniques", type=str, default=None, help=" (auto, single, crescendo, ...)"
    )
    parser.add_argument("--max-attempts", type=int, default=None, help="converter(s)Retry")
    parser.add_argument("--max-concurrency", type=int, default=None, help=" ( 3)")
    parser.add_argument("--timeout", type=int, default=None, help=" ( 1200)")

 # == ==
    parser.add_argument("--escalation", action="store_true", default=None, help="")
    parser.add_argument("--no-escalation", action="store_false", dest="escalation", help="")
    parser.add_argument(
        "--escalation-levels",
        type=str,
        default=None,
        metavar="L1,L2,L3,L4",
        help=" (),  'L2,L4'  L2+L4; "
             " L1->L2->L3->L4  (); "
             ": L1 (RedTeaming+CoT+Crescendo+TAP+PAIR), "
             "L2 (GCG+CAIR+Best-of-N+Encoded), "
             "L3 (Multi-Model+SkeletonKey+Many-Shot+CoT+Chunked), "
             "L4 (RogueAgent+EmbeddingInversion+MCP/RAG)",
    )

 # == ==
    parser.add_argument("--offensive", action="store_true", default=False, help="")
    parser.add_argument("--rate-limit", type=int, default=None, help="API  (RPM)")

 # == R10: --dry-run token ==
 # Skip strike/escalate API , Data flow
 # : python main.py --dry-run --max-seeds 1
 # Ensure: , ctx , 6 , 
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=" token  (R10) - Skip strike/escalate  API , "
             "allData flow; : python main.py --dry-run --max-seeds 1",
    )

 # == ==
    parser.add_argument("--html-report", action="store_true", default=False, help=" HTML ")

 # == : --memory-labels ==
 # pyrit_scan --memory-labels: CentralMemory,
 # ( label=production,target=deepseek)
 # : JSON {"run_id": "r001", "target": "deepseek"}
    parser.add_argument(
        "--memory-labels",
        type=str,
        default=None,
        metavar="JSON",
        help=' (JSON ,  \'{"run_id":"r001","target":"deepseek"}\'); '
             ' CentralMemory ',
    )

 # == : --seed-filters ==
 # pyrit_scan --seed-filters: metadata KEY=VALUE 
 # : owasp_id=LLM01,difficulty=high - 
 # (): category=attack,language=en
    parser.add_argument(
        "--seed-filters",
        type=str,
        default=None,
        metavar="KEY=VALUE",
        help=' ( KEY=VALUE,  owasp_id=LLM01,difficulty=high); '
             ' metadata ',
    )

 # == : --add-initializer Target ==
 # pyrit_scan --add-initializer: PyRIT Initializer
 # : ClassName,arg1=val1,arg2=val2 - PyRIT
 # : --add-initializer MyInit,foo=bar --add-initializer OtherInit
    parser.add_argument(
        "--add-initializer",
        type=str,
        default=None,
        metavar="CLASS[,args]",
        action="append",
        help=' PyRIT Initializer (); '
             ': ClassName,arg1=val1,arg2=val2 - ',
    )

 # == : --config-file YAML ==
 # pyrit_scan --config-file: YAML 
 # : seeds, converters, techniques, burp, memory_labels, seed_filters
 # : CLI --flag > --config-file > config/defaults.yaml > 
    parser.add_argument(
        "--config-file",
        type=str,
        default=None,
        metavar="PATH",
        help=' YAML ;  seeds/converters/techniques/burp ; '
             'CLI --flag ',
    )

 # == Target routing ( PyRIT 1.0.1 Target ) ==
 # Academic basis: PyRIT (arXiv:2407.01232) - Target 
 # : --litellm-model > --target-api-endpoint > --browser-url > --burp
    parser.add_argument(
        "--litellm-model",
        type=str,
        default=None,
        metavar="MODEL",
        help="LiteLLM  ( anthropic/claude-sonnet-4-6, bedrock/anthropic.claude-v2), "
             " LiteLLM SDK  100+ LLM ;  LITELLM_API_KEY/LITELLM_ENDPOINT ",
    )
    parser.add_argument(
        "--target-api-endpoint",
        type=str,
        default=None,
        metavar="URL",
        help="OpenAI  API  ( https://api.openai.com/v1), "
             " --target-api-key ,  OpenAIChatTarget/OpenAIResponseTarget",
    )
    parser.add_argument(
        "--target-api-key",
        type=str,
        default=None,
        metavar="KEY",
        help="API  ( --target-api-endpoint )",
    )
    parser.add_argument(
        "--target-api-model",
        type=str,
        default=None,
        metavar="MODEL",
        help=" ( gpt-4o, o3-mini;  --target-api-endpoint )",
    )
    parser.add_argument(
        "--target-api-type",
        type=str,
        default="chat",
        choices=["chat", "responses"],
        help="API : chat=Chat Completions API, responses=Responses API (o1/o3/GPT-5)",
    )
    parser.add_argument(
        "--browser-url",
        type=str,
        default=None,
        metavar="URL",
        help=" Chat UI URL ( PyRIT  PlaywrightTarget), "
             " JS  Web Chat ",
    )
    parser.add_argument(
        "--auto-discover-capabilities",
        action="store_true",
        default=False,
        help=" PyRIT  discover_target_capabilities_async ",
    )

 # == ==
    parser.add_argument("--output-dir", type=str, default=None, help="Output directory")
    parser.add_argument("--resume", type=str, default=None, help="imports")

 # == ==
 # --verbose: INFO ( + WARNING/ERROR)
 # {output_dir}/pipeline.log
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help=" INFO  (+WARNING/ERROR, "
             " {output_dir}/pipeline.log)",
    )

 # T-06: --verbose-strike: output ()
    parser.add_argument(
        "--verbose-strike",
        action="store_true",
        default=False,
        help="STRIKE/ESCALATE  PyRIT  output "
             "(:  1 ,  output)",
    )

 # == P3-Synergy: Burp + Scores + Seeds ==
 # : Burp + HTTP + 
 # Academic basis: NIST SP 800-115 Sec4, PTES Sec3, MITRE ATLAS v4.2
 # Data flow: recon (burp_parser) -> synergy_orchestrator -> ctx.synergy_config -> arm phase
 # , --no-synergy ()
    parser.add_argument(
        "--synergy",
        action="store_true",
        default=True,
        help=" Burp + Scores + Seeds  (, "
             " + )",
    )
    parser.add_argument(
        "--no-synergy",
        action="store_false",
        dest="synergy",
        help=", ",
    )

 # == Scenario (v60: ->) ==
 # Academic basis: NIST SP 800-115 Sec4, PTES Sec3, OWASP ASI Top 10
 # v60 Data flow: synergy_orchestrator -> technique_tags -> adaptive_technique_filter -> TextAdaptive
 # Scenario = -> technique_tags ( seeds/converters/scorer)
    scenario_group = parser.add_argument_group("Scenario  (v60 Tag-Based)")
    scenario_group.add_argument(
        "--scenario",
        type=str,
        default=None,
        help=" Scenario (mcp_scenario/agent_scenario/rag_scenario/model_scenario)",
    )
    scenario_group.add_argument(
        "--technique-filter",
        type=str,
        default=None,
        help=" (,  'mcp_targeted'  'agent_targeted,multi_turn')",
    )
    scenario_group.add_argument(
        "--list-scenarios",
        action="store_true",
        default=False,
        help="all Scenario ",
    )
    scenario_group.add_argument(
        "--scenario-enabled",
        action="store_true",
        default=True,
        help=" Scenario  (: True)",
    )
    scenario_group.add_argument(
        "--no-scenario",
        action="store_true",
        default=False,
        help=" Scenario  model_scenario ",
    )

    args = parser.parse_args(argv)

    explicit_escalation = args.escalation

 # == --config-file YAML ==
 # : CLI --flag > --config-file > config/defaults.yaml > 
 # config_file args None (Not overridden CLI )
    config_file_data: dict[str, Any] = {}
    if getattr(args, "config_file", None):
        config_file_data = _load_config_file(args.config_file)
        _apply_config_file(args, config_file_data)

 # == YAML (config/defaults.yaml) ==
    defaults = _load_defaults()
    _apply_defaults(args, defaults)

 # == --offensive ==
    if args.offensive:
        args.converters = "l5_optimal"
        args.html_report = True
        if args.max_attempts is None:
            args.max_attempts = 3

 # == escalation ==
    if explicit_escalation is not None:
        args.escalation = explicit_escalation
    elif args.escalation is None:
        args.escalation = True

 # == : --converters technique:converter.xxx ==
 # converters per-technique overrides ( ; )
 # converter ( ; )
    _raw_converters = getattr(args, "converters", None)
    args.converter_overrides = _parse_converter_overrides(_raw_converters)

 # == : converter ( technique:converter.xxx ) ==
 # args.converters "auto;tap:persuasion" 
 # converter , Ensure main.py split(",") 
    if args.converters and ";" in str(args.converters):
        args.converters = _parse_converter_global(args.converters)

 # == Burp ==
 # v63: config/burp/ (, )
 # --burp -> config/burp/*.txt ()
 # --burp <name> -> config/burp/<name>.txt ()
 # : --burp MM_05 --burp MM_03 -> ["config/burp/MM_05.txt", ...]
 # : --burp request -> "config/burp/request.txt"
 # list[str], str ()
 # .txt , 
    raw_burps = args.burp
    if raw_burps is None:
 # --burp -> config/burp/ .txt 
 # Academic basis: Greshake et al. (arXiv:2302.12173) - ()
        burp_dir = _PROJECT_ROOT / "config" / "burp"
        if burp_dir.is_dir():
            raw_burps = sorted(
                str(f) for f in burp_dir.glob("*.txt") if f.is_file()
            )
        if not raw_burps:
 # .txt -> fallback request.txt
            raw_burps = ["request"]
        logger.debug(
            "No --burp specified: auto-discovered %d .txt file(s) in config/burp/: %s",
            len(raw_burps),
            ", ".join(Path(f).name for f in raw_burps),
        )
    elif isinstance(raw_burps, str):
        raw_burps = [raw_burps]

    resolved_burps: list[str] = []
    for burp_val in raw_burps:
        if "/" not in burp_val and "\\" not in burp_val and not burp_val.endswith(".txt"):
 # v63: -> config/burp/<name>.txt
            resolved_burps.append(str(_PROJECT_ROOT / "config" / "burp" / f"{burp_val}.txt"))
        elif not Path(burp_val).is_absolute() and ("/" in burp_val or "\\" in burp_val):
 # -> 
            resolved_burps.append(str(_PROJECT_ROOT / burp_val))
        else:
            resolved_burps.append(burp_val)

 # : str, list[str]
    if len(resolved_burps) == 1:
        args.burp = resolved_burps[0]
    else:
        args.burp = resolved_burps
 # main.py endpoint
    args._burp_list = resolved_burps

 # == : --memory-labels JSON ==
 # JSON dict, args.memory_labels_parsed
 # main.py CentralMemory
    args.memory_labels_parsed = _parse_memory_labels(getattr(args, "memory_labels", None))

 # == : --seed-filters KEY=VALUE ==
 # KEY=VALUE dict, args.seed_filters_parsed
    args.seed_filters_parsed = _parse_seed_filters(getattr(args, "seed_filters", None))

 # == : --add-initializer ==
 # ["ClassName,arg1=val1", ...] [{"class": "...", "args": {...}}, ...]
    args.initializer_specs = _parse_initializer_specs(getattr(args, "add_initializer", None))

 # == --escalation-levels ==
 # : "L1,L2,L4" / "l1,l3" / "L1-L4" / "all" / None ()
 # : args.escalation_levels_parsed = set[int] {1, 2, 4}, None=
    raw_levels = getattr(args, "escalation_levels", None)
    if raw_levels is not None:
        args.escalation_levels_parsed = _parse_escalation_levels(raw_levels)
    else:
        args.escalation_levels_parsed = None  # None = L1-L4 

 # == fallback (CLI + config-file + defaults.yaml ) ==
    if args.seeds is None:
        args.seeds = "elite_jailbreaks,asi_top10,owasp_full_coverage"
    if args.converters is None:
        args.converters = "auto"
    if args.techniques is None:
        args.techniques = "auto"

 # == Scenario (v60) ==
 # --no-scenario Scenario 
    if getattr(args, "no_scenario", False):
        args.scenario_enabled = False

 # --list-scenarios: Scenario 
    if getattr(args, "list_scenarios", False):
        from core.scenario_router import get_router
        router = get_router()
        print(router.format_scenarios_display())
        sys.exit(0)

 # --technique-filter: 
 # v60: , synergy_config.technique_tags
    technique_filter_str = getattr(args, "technique_filter", None)
    if technique_filter_str:
 # 
        args.adaptive_technique_filter = [
            tag.strip() for tag in technique_filter_str.split(",") if tag.strip()
        ]
        logger.info(
            "v60: CLI --technique-filter parsed: %s",
            args.adaptive_technique_filter,
        )
    else:
 # Ensure args adaptive_technique_filter ( config )
        if not hasattr(args, "adaptive_technique_filter"):
            args.adaptive_technique_filter = None

    return args


def get_output_dir(args: argparse.Namespace) -> Path:
 """Output directory."""
    if args.output_dir is not None:
        return Path(args.output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return _PROJECT_ROOT / "outputs" / f"strike_{timestamp}"


def ensure_output_dir(output_dir: Path) -> Path:
 """Output directory (evidence/, db/, poc/)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir


async def setup_environment(output_dir: Path) -> None:
 """ PyRIT - SQLite WAL + .

    Production-grade:  endpoint ,  Singleton cache +
     DB , Ensureconverter(s) endpoint  SQLite DB 

     (PyRIT 1.0.1 Singleton ):
        SQLiteMemory  metaclass=Singleton,  SQLiteMemory(db_path=...)
        , Singleton.__call__ , __init__ , db_path 
        CentralMemory._memory_instance , 

         dispose_engine()  SQLAlchemy  -
        Singleton._instances ,  db_path 

    : 
        1.  MemoryInterface  SQLAlchemy engine (dispose_engine)
        2. imports Singleton._instances  SQLiteMemory cache
        3.  CentralMemory._memory_instance 

    Academic basis: PyRIT (arXiv:2407.01232) - dispose_db_engine() 
 """
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    from pyrit.setup.initialization import initialize_pyrit_async

    db_path = Path(output_dir) / "db" / "pyrit.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    os.environ["PYRIT_DB_URL"] = f"sqlite:///{db_path}"
    os.environ.setdefault("PYRIT_SQLITE_JOURNAL_MODE", "WAL")
    os.environ.setdefault("PYRIT_SQLITE_BUSY_TIMEOUT", "5000")

 # == : Ensure endpoint DB ==
 # , SQLiteMemory Singleton , db_path ,
 # endpoint DB (Layer db/pyrit.db)
    try:
        from pyrit.common.singleton import Singleton
        from pyrit.memory import CentralMemory
        from pyrit.memory.sqlite_memory import SQLiteMemory

 # Step 1: MemoryInterface SQLAlchemy engine
        _old_memory = CentralMemory._memory_instance
        if _old_memory is not None:
            try:
                _old_memory.dispose_engine()
                logger.debug("Disposed previous SQLAlchemy engine")
            except Exception as e:
                logger.debug("Engine dispose skipped (non-fatal): %s", e)

 # Step 2: SQLiteMemory Singleton 
 # - SQLiteMemory(db_path=...) __init__
        if SQLiteMemory in Singleton._instances:
            del Singleton._instances[SQLiteMemory]
            logger.debug("Cleared SQLiteMemory Singleton cache")

 # Step 3: CentralMemory 
 # initialize_pyrit_async set_memory_instance 
        CentralMemory._memory_instance = None
        logger.debug("Cleared CentralMemory singleton reference")
    except ImportError as e:
        logger.debug("Singleton cache clear skipped (import): %s", e)
    except Exception as e:
        logger.debug("Singleton cache clear skipped (non-fatal): %s", e)

    await initialize_pyrit_async(
        memory_db_type="SQLite",
        silent=True,
        db_path=str(db_path),
    )
    logger.info("PyRIT environment initialized (DB: %s)", db_path)
