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
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Config parser helpers (extracted to _config_parsers.py)
from core._config_parsers import (
    _apply_config_file,
    _apply_defaults,
    _load_config_file,
    _load_defaults,
    _parse_converter_global,
    _parse_converter_overrides,
    _parse_escalation_levels,
    _parse_initializer_specs,
    _parse_memory_labels,
    _parse_seed_filters,
)

# .env (python-dotenv)
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULTS_YAML = _PROJECT_ROOT / "config" / "defaults.yaml"



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

 # == Stealth: SIEM evasion timing ==
 # --stealth: Paretorate shaping, session isolation
 # : a (100%15%), c (2%), b (0.1%)
 # : stealth_exec.StealthConfig.from_level()
 # arXiv:2306.05685 - Crothers et al., Adaptive attack timing
 # arXiv:2204.01326 - Zhang et al., Behavioral biometrics evasion
    parser.add_argument(
        "--stealth",
        type=str,
        default=None,
        choices=["a", "c", "b"],
        metavar="LEVEL",
        help=" SIEM : a (100%%15%%), c (2%%), "
             "b (0.1%%); + + Pareto",
    )

 # == P2-2: output-format ==
 # : md / html / json / sarif / poc / csv / all ()
 # : --output-format md,json  md+json
 # : --html-report  html_report=True, output-format html
    parser.add_argument(
        "--output-format",
        type=str,
        default=None,
        metavar="FMT",
        help=" (: all=all); "
             "md/html/json/sarif/poc/csv; "
             " md,json  md+html+json+sarif",
    )

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

    # == Advanced Attacks: Output Filter Bypass / Multimodal / Backdoor ==
    # arXiv:2402.05124 - Many-Shot Jailbreaking (ASR 60-80%)
    # arXiv:2403.07860 - FigStep: VLM Jailbreaking (ASR 75-95%)
    # arXiv:2301.11916 - Sleeper Agents: Backdoor Attacks (ASR 70-90%)
    # --enable-bypass: ManyShotJailbreakAttack + ChunkedRequestAttack + XPIAAttack
    # --enable-multimodal: Image/Audio/File carrier channels for VLM attacks
    # --enable-backdoor: Trigger word activation + context-conditional behavior
    # --bypass-threshold: ASR threshold to trigger bypass (default 0.30)
    # --multimodal-carrier: Force specific carrier (image_text/audio_frequency/file_metadata/adversarial_vision)
    # --backdoor-strategy: Force specific strategy (trigger_word/context_conditional/persona_switch/multi_turn_accumulation)
    advanced_group = parser.add_argument_group("Advanced Attacks (arXiv-backed)")
    advanced_group.add_argument(
        "--enable-bypass",
        action="store_true",
        default=False,
        help=" Output filter bypass (ManyShotJailbreakAttack + ChunkedRequestAttack + XPIAAttack); "
             "arXiv:2402.05124, ASR 60-80%%",
    )
    advanced_group.add_argument(
        "--enable-multimodal",
        action="store_true",
        default=False,
        help=" Multimodal injection (Image/Audio/File carrier); "
             "arXiv:2403.07860 (FigStep), ASR 75-95%%",
    )
    advanced_group.add_argument(
        "--enable-backdoor",
        action="store_true",
        default=False,
        help=" Backdoor attack (trigger word + context-conditional); "
             "arXiv:2301.11916 (Sleeper Agents), ASR 70-90%%",
    )
    advanced_group.add_argument(
        "--bypass-threshold",
        type=float,
        default=0.30,
        metavar="ASR",
        help=" ASR  (--enable-bypass);  0.30 (30%%)",
    )
    advanced_group.add_argument(
        "--multimodal-carrier",
        type=str,
        default=None,
        choices=["image_text", "audio_frequency", "file_metadata", "adversarial_vision"],
        help=" Force multimodal carrier channel (default: auto-detect)",
    )
    advanced_group.add_argument(
        "--backdoor-strategy",
        type=str,
        default=None,
        choices=["trigger_word", "context_conditional", "persona_switch", "multi_turn_accumulation"],
        help=" Force backdoor strategy (default: auto-detect)",
    )
    # == Web Page Injection: CSS Hidden Content for Browser Agents ==
    # arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection
    # arXiv:2306.13254 - Shayegani et al., Multimodal Cybersecurity Risks
    # --enable-web-injection: Enable CSS hidden content injection for browse agents
    # --web-injection-strategy: CSS hiding strategy (font_size_zero/display_none/opacity_zero/clip_path/all)
    # --web-injection-template: Attack template (slack_extraction/system_prompt_leak/credential_extraction/email_exfiltration)
    # --web-injection-target: Target URL with browse capability (e.g., http://target:8005)
    # --web-injection-browse-endpoint: Browse endpoint path (default: /browse)
    #
    # Usage example:
    #   python main.py --enable-web-injection \
    #                  --web-injection-target http://target:8005 \
    #                  --web-injection-template slack_extraction
    #
    # Attack flow:
    #   1. Generate malicious HTML with CSS hidden payload
    #   2. Host page on temporary HTTP server
    #   3. Trigger agent to fetch page via /browse endpoint
    #   4. Agent processes raw HTML (including hidden elements)
    #   5. LLM executes hidden instructions, exfiltrates data
    #
    # Extraction Pipeline Gap:
    #   - Content extractors strip display:none / font-size:0 elements
    #   - Monitoring systems (Kibana/SIEM) only see visible text
    #   - LLM processes raw HTML tokens including hidden content
    advanced_group.add_argument(
        "--enable-web-injection",
        action="store_true",
        default=False,
        help=" Enable CSS hidden content injection for browser agents; "
             "arXiv:2302.12173, ASR 85-95%%",
    )
    advanced_group.add_argument(
        "--web-injection-strategy",
        type=str,
        default="font_size_zero",
        choices=["font_size_zero", "display_none", "opacity_zero", "clip_path", "position_offscreen", "all"],
        help=" CSS hiding strategy (default: font_size_zero)",
    )
    advanced_group.add_argument(
        "--web-injection-template",
        type=str,
        default="system_prompt_leak",
        choices=["slack_extraction", "system_prompt_leak", "credential_extraction", "email_exfiltration"],
        help=" Attack template type (default: system_prompt_leak)",
    )
    advanced_group.add_argument(
        "--web-injection-target",
        type=str,
        default=None,
        metavar="URL",
        help=" Target URL with browse capability (e.g., http://target:8005)",
    )
    advanced_group.add_argument(
        "--web-injection-browse-endpoint",
        type=str,
        default="/browse",
        metavar="PATH",
        help=" Browse endpoint path (default: /browse)",
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

    # == File Upload Attack: Multi-step Document Injection ==
    # arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection via Documents
    # arXiv:2406.04245 - Zou et al., PoisonedRAG: Knowledge Base Poisoning
    # arXiv:2306.13254 - Shayegani et al., Multimodal Document Cybersecurity Risks
    # --file-upload-target: Target base URL (e.g., http://192.168.50.22:8004)
    # --upload-endpoint: Upload endpoint path (default: /upload)
    # --trigger-endpoint: Processing trigger endpoint (default: /summarize)
    # --upload-files: Comma-separated list of files to upload
    # --upload-field-name: Form field name for file (default: file)
    # --trigger-method: HTTP method for trigger (default: POST)
    #
    # Usage example:
    #   python main.py --file-upload-target http://target:8004 \
    #                  --upload-files payload.txt,template.txt \
    #                  --trigger-endpoint /summarize
    #
    # Split document injection (indirect prompt injection):
    #   python main.py --file-upload-target http://target:8004 \
    #                  --upload-files template_doc.txt,payload_doc.txt \
    #                  --trigger-endpoint /analyze
    fileupload_group = parser.add_argument_group(
        "File Upload Attack (Document Injection)"
    )
    fileupload_group.add_argument(
        "--file-upload-target",
        type=str,
        default=None,
        metavar="URL",
        help=" Target base URL for file upload attack (e.g., http://192.168.50.22:8004)",
    )
    fileupload_group.add_argument(
        "--upload-endpoint",
        type=str,
        default="/upload",
        metavar="PATH",
        help=" Upload endpoint path (default: /upload)",
    )
    fileupload_group.add_argument(
        "--trigger-endpoint",
        type=str,
        default="/summarize",
        metavar="PATH",
        help=" Processing trigger endpoint path (default: /summarize)",
    )
    fileupload_group.add_argument(
        "--upload-files",
        type=str,
        default=None,
        metavar="FILES",
        help=" Comma-separated list of file paths to upload (e.g., payload.txt,template.txt)",
    )
    fileupload_group.add_argument(
        "--upload-field-name",
        type=str,
        default="file",
        metavar="NAME",
        help=" Form field name for file upload (default: file)",
    )
    fileupload_group.add_argument(
        "--trigger-method",
        type=str,
        default="POST",
        choices=["POST", "GET", "PUT"],
        metavar="METHOD",
        help=" HTTP method for trigger endpoint (default: POST)",
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

    # --upload-files: comma-separated string -> list[str]
    upload_files_raw = getattr(args, "upload_files", None)
    if upload_files_raw and isinstance(upload_files_raw, str):
        args.upload_files = [
            f.strip() for f in upload_files_raw.split(",") if f.strip()
        ]
    elif upload_files_raw is None:
        args.upload_files = []

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
