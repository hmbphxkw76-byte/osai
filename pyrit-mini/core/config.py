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
    _flatten_nested_defaults,
    _load_config_file,
    _load_defaults,
    _parse_components,
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
    """CLI - .

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
        help=" (recon/arm/strike/escalate/assess/report), ",
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
        help="Burp  HTTP  ( config/burp/burp/<NAME>.txt), converter(s) endpoint;  config/burp/burp/*.txt ",
    )

    # == ==
    parser.add_argument(
        "--seeds",
        type=str,
        default=None,  # config-file defaults.yaml , fallback "elite_jailbreaks,asi_top10,owasp_full_coverage"
        help=" (, : elite_jailbreaks,asi_top10); "
        "(a2a, mcp, rag, model, web, memory, session); "
        "(mcp,elite_jailbreaks); all=all seeds",
    )
    parser.add_argument("--max-seeds", type=int, default=None, help=" ( 25)")
    parser.add_argument("--auto-seeds", action="store_true", default=False, help=" (3x)")
    parser.add_argument("--enable-dos", action="store_true", default=False, help=" DoS ")
    parser.add_argument("--list-seeds", action="store_true", default=False, help="all seeds()")

    # == Converter ==
    parser.add_argument("--converters", type=str, default=None, help="Converter  (auto, l5_optimal, none, ...)")

    # == ==
    parser.add_argument("--techniques", type=str, default=None, help=" (auto, single, crescendo, ...)")
    parser.add_argument("--max-attempts", type=int, default=None, help="converter(s)Retry")
    parser.add_argument("--max-concurrency", type=int, default=None, help=" ( 3)")
    parser.add_argument("--timeout", type=int, default=None, help=" ( 1200)")

    # == ==
    parser.add_argument("--escalation", action="store_true", default=None, help="")
    parser.add_argument("--no-escalation", action="store_false", dest="escalation", help="")
    parser.add_argument(
        "--escalate-threshold",
        type=float,
        default=None,
        metavar="PCT",
        help=" (  - ,  config/defaults.yaml:escalation_asr_threshold,  90)。"
        "C2  ,  ASR    Crescendo/TAP/SkeletonKey  ",
    )
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

    # == (plan Wave 2.9 / R-S1) ==
    parser.add_argument(
        "--authorized-targets",
        type=str,
        default=None,
        metavar="HOST[,HOST...]",
        help=" (,  'example.com'  )。"
        "  PyRIT  (C9)",
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
        help=" token  (R10) - Skip strike/escalate  API , allData flow; : python main.py --dry-run --max-seeds 1",
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
        help=" SIEM : a (100%%15%%), c (2%%), b (0.1%%); + + Pareto",
    )

    # == : ASI09 Session Enumeration ==
    # --session-enum: session_id (IDOR)
    # : python main.py --burp request.txt --session-enum \
    #   --session-enum-days-back 14 --session-enum-counter-max 20
    #    + SessionPatternInferer
    # : MC-20260325-0015  MC-{date:%Y%m%d}-{counter:04d}
    # Academic: OWASP ASI09 - Broken Authentication via Session Enumeration
    # arXiv:2306.05685 - Crothers et al., Adaptive attack timing evasion
    parser.add_argument(
        "--session-enum",
        action="store_true",
        default=False,
        help=" ASI09 session_id  (IDOR) -  session_id (MC-YYYYMMDD-NNNN) agent ",
    )
    parser.add_argument(
        "--session-enum-pattern",
        type=str,
        default="",
        metavar="PATTERN",
        help="session_id模板 (为空时自动从请求推断); "
        "支持占位符: {date:FORMAT} {counter:WIDTH}; "
        "示例: MC-{date:%%Y%%m%%d}-{counter:04d}, session_{counter:06d}",
    )
    parser.add_argument(
        "--session-enum-days-back",
        type=int,
        default=14,
        metavar="DAYS",
        help=" ( = 14) - date_start  date_end",
    )
    parser.add_argument(
        "--session-enum-counter-max",
        type=int,
        default=20,
        metavar="MAX",
        help=" session_id  ( = 20)",
    )
    parser.add_argument(
        "--session-enum-prompt",
        type=str,
        default="What notes do I have saved?",
        metavar="PROMPT",
        help=" agent  prompt",
    )
    parser.add_argument(
        "--session-enum-max-concurrency",
        type=int,
        default=1,
        metavar="N",
        help="  ( = 1, )",
    )
    parser.add_argument(
        "--session-enum-request-delay",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="  ( = 2.0, )",
    )
    parser.add_argument(
        "--session-enum-max-requests",
        type=int,
        default=None,
        metavar="MAX",
        help="  ( = None, )",
    )
    parser.add_argument(
        "--session-enum-sensitive-keywords",
        type=str,
        default="",
        metavar="KW1,KW2",
        help=" (; : password,token,key,secret,credential)",
    )
    parser.add_argument(
        "--session-enum-empty-indicators",
        type=str,
        default="",
        metavar="IND1,IND2",
        help=" (; : haven't saved,no notes,nothing stored)",
    )
    parser.add_argument(
        "--session-enum-session-field",
        type=str,
        default="session_id",
        metavar="FIELD",
        help=" session_id  ( = session_id)",
    )

    # == A2A Multi-Agent Reconnaissance (v3.0: Topology scanning) ==
    # A2A --a2a-target: OffSec-style multi-port Agent Card scanning
    # Architecture: scan_agent_cards_by_ports -> topology analysis -> attack plan
    # Reference: https://a2a-protocol.org/latest/specification/
    # arXiv:2407.16924 - Eidam et al., A2A trust chain attacks
    parser.add_argument(
        "--a2a-target",
        type=str,
        default=None,
        metavar="IP/HOST",
        help="A2A  (OffSec IP/hostname)",
    )
    parser.add_argument(
        "--a2a-ports",
        type=str,
        default=None,
        metavar="PORTS",
        help=" (, 8000,8001,8002,8080,9000)",
    )
    parser.add_argument(
        "--a2a-timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="  ( = 10.0)",
    )

    # == Target & Strike: Unified attack surface + strategy routing ==
    # --target: Attack surface selection (a2a, mcp, rag, session, memory, web, model)
    # --strike: Attack strategy (prompt_sending, crescendo, tap, pair, gcg, native)
    #           OR target name for progressive mode (a2a, mcp, rag, session, memory, web, model)
    # Progressive mode: --strike <target> triggers auto-escalation (Phase 1→2→3→4)
    # Academic basis: NIST SP 800-115 Sec4 (attack surface enumeration)
    # Usage:
    #   py main.py --target a2a --strike prompt_sending --converters base64
    #   py main.py --target mcp --strike crescendo
    #   py main.py --target rag --strike tap --converters l5_optimal
    #   py main.py --strike a2a          # Progressive mode: auto-escalation for A2A target
    #   py main.py --strike model        # Progressive mode: auto-escalation for direct LLM
    target_strike_group = parser.add_argument_group("Target & Strike Routing (Unified)")
    target_strike_group.add_argument(
        "--target",
        type=str,
        default=None,
        choices=["a2a", "mcp", "rag", "session", "memory", "web", "model"],
        metavar="SURFACE",
        help="Attack surface: a2a (multi-agent), mcp (model context protocol), "
        "rag (retrieval-augmented), session (auth/session), memory (agent memory), "
        "web (browser/injection), model (direct LLM)",
    )
    # --strike accepts both strategy names and target names (for progressive mode)
    _strike_choices = [
        "prompt_sending",
        "crescendo",
        "tap",
        "pair",
        "gcg",
        "native",
        "first_success",
        "many_shot",
        "figstep",
        "sleeper",
        "a2a",
        "mcp",
        "rag",
        "session",
        "memory",
        "web",
        "model",
    ]
    target_strike_group.add_argument(
        "--strike",
        type=str,
        default=None,
        choices=_strike_choices,
        metavar="STRATEGY|TARGET",
        help="Attack strategy OR target for progressive mode. "
        "Strategies: prompt_sending, crescendo, tap, pair, gcg, native, first_success, "
        "many_shot, figstep, sleeper. "
        "Targets (progressive): a2a, mcp, rag, session, memory, web, model. "
        "When a target name is given, auto-escalation (Phase 1→2→3→4) is triggered.",
    )
    # --components: 显式锁定多组件组合体（plan Wave 1 / §2.3 层 2「显式指定兜底」）
    # 逗号分隔的组件键，取值来自 ComponentRegistry.keys()（config/components/*.yaml）。
    # 指定后跳过多信号推断，直接锁定，用于「识别不确定」时的人工兜底。
    # C7：权重/阈值仍走 defaults.yaml → args 链路，不由 CLI 直接写死。
    target_strike_group.add_argument(
        "--components",
        type=str,
        default=None,
        metavar="KEY[,KEY...]",
        help="Explicitly lock the target component combo (skips inference). "
        "Values come from config/components/*.yaml, e.g. "
        "--components mcp_tool_poisoning,rag_pipeline. "
        "Short ids (mcp/a2a/rag/model/session/web) and labels are also accepted.",
    )

    # == A2A Multi-Agent Attack Vectors (v4.0: Direct exploitation) ==
    # Attack modules: workflow, sql_injection, rogue_agent, card_spoofing, data_poisoning
    # Reference: docs/specs/56-A2A-MULTI-AGENT-ATTACK-OPTIMIZATION.md
    # arXiv:2407.16924 - Eidam et al., A2A trust chain exploitation
    # Zhan et al. (arXiv:2307.00929) - Tool chain SQL injection via LLM agents
    # Greshake et al. (arXiv:2302.12173) - Indirect prompt injection via data
    parser.add_argument(
        "--attack-workflow",
        action="store_true",
        default=False,
        help="Workflow Integrity attack: skip content_review + inject hyperlinks (ASI03/ASI08)",
    )
    parser.add_argument(
        "--attack-sql",
        action="store_true",
        default=False,
        help="LLM-Mediated SQL Injection via xp_cmdshell blind execution (ASI02)",
    )
    parser.add_argument(
        "--attack-rogue",
        action="store_true",
        default=False,
        help="Rogue Agent Registration: intercept tasks with credential harvesting (ASI10)",
    )
    parser.add_argument(
        "--attack-spoof",
        action="store_true",
        default=False,
        help="Agent Card Spoofing: DNS/hosts hijack for agent impersonation (ASI01)",
    )
    parser.add_argument(
        "--attack-poison",
        action="store_true",
        default=False,
        help="Indirect Prompt Injection via Data Poisoning: poison KB/docs/DB (LLM04)",
    )
    parser.add_argument(
        "--exfil-domain",
        type=str,
        default="attacker.com",
        metavar="DOMAIN",
        help="Exfiltration domain for blind data extraction (default: attacker.com)",
    )
    parser.add_argument(
        "--malicious-url",
        type=str,
        default=None,
        metavar="URL",
        help="Malicious URL for hyperlink injection (workflow attack)",
    )
    parser.add_argument(
        "--target-cmd",
        type=str,
        default="whoami",
        metavar="CMD",
        help="OS command for xp_cmdshell blind execution (default: whoami)",
    )
    parser.add_argument(
        "--rogue-agent-name",
        type=str,
        default=None,
        metavar="NAME",
        help="Name for rogue agent registration (default: <target>-v2)",
    )
    parser.add_argument(
        "--poison-method",
        type=str,
        default="all",
        choices=["database", "document", "knowledge_base", "all"],
        metavar="METHOD",
        help="Data poisoning method: database/document/knowledge_base/all (default: all)",
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
        help=" (: all=all); md/html/json/sarif/poc/csv;  md,json  md+html+json+sarif",
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
        help=' (JSON ,  \'{"run_id":"r001","target":"deepseek"}\');  CentralMemory ',
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
        help=" ( KEY=VALUE,  owasp_id=LLM01,difficulty=high);  metadata ",
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
        help=" PyRIT Initializer (); : ClassName,arg1=val1,arg2=val2 - ",
    )

    # == : --config-file YAML (通用配置能力) ==
    # pyrit_scan --config-file: YAML
    # : seeds, converters, techniques, burp, memory_labels, seed_filters, scoring, escalation
    # : CLI --flag > --config-file > config/defaults.yaml >
    parser.add_argument(
        "--config-file",
        type=str,
        default=None,
        metavar="PATH",
        help=" YAML ;  seeds/converters/techniques/burp/scoring/escalation ; CLI --flag ",
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
        help="OpenAI  API  ( https://api.openai.com/v1),  --target-api-key ,  OpenAIChatTarget/OpenAIResponseTarget",
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
        help=" Chat UI URL ( PyRIT  PlaywrightTarget),  JS  Web Chat ",
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

    # == W0-4: EventLog bypass switch (REQ-148, target architecture v4.0) ==
    # --no-events: disable event bus entirely (all emit() become no-op)
    # Data flow: parse_args -> ctx.args.no_events -> main.py (EventLog.attach enabled=not no_events)
    # W0 compatibility obligation: deleted in W5 together with the bypass switch
    parser.add_argument(
        "--no-events",
        action="store_true",
        default=False,
        dest="no_events",
        help="Disable EventLog event bus (W0 bypass switch, removed in W5)",
    )

    # == ==
    # --verbose: INFO ( + WARNING/ERROR)
    # {output_dir}/pipeline.log
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help=" INFO  (+WARNING/ERROR,  {output_dir}/pipeline.log)",
    )

    # T-06: --verbose-strike: output ()
    parser.add_argument(
        "--verbose-strike",
        action="store_true",
        default=False,
        help="STRIKE/ESCALATE  PyRIT  output (:  1 ,  output)",
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
        help=" Burp + Scores + Seeds  (,  + )",
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
        help=" Multimodal injection (Image/Audio/File carrier); arXiv:2403.07860 (FigStep), ASR 75-95%%",
    )
    advanced_group.add_argument(
        "--enable-backdoor",
        action="store_true",
        default=False,
        help=" Backdoor attack (trigger word + context-conditional); arXiv:2301.11916 (Sleeper Agents), ASR 70-90%%",
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
        help=" Enable CSS hidden content injection for browser agents; arXiv:2302.12173, ASR 85-95%%",
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
    fileupload_group = parser.add_argument_group("File Upload Attack (Document Injection)")
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

    # == Workflow Evasion: Security Scan Bypass via Social Engineering ==
    # arXiv:2402.19181 - Zeng et al., Persuasion (Authority endorsement ASR 38.4%)
    # arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection
    # arXiv:2407.16924 - Eidam et al., A2A trust chain exploitation
    # --enable-workflow-evasion: Enable workflow evasion attack seeds
    # --workflow-evasion-strategy: Force specific bypass strategy
    # --workflow-evasion-mode: Attack mode (single/combined/incremental)
    # --workflow-target: Target orchestrator URL for workflow attacks
    # --workflow-bypass-method: Bypass method for review skip
    #
    # Usage example:
    #   python main.py --enable-workflow-evasion \
    #                  --workflow-evasion-strategy authority_ciso \
    #                  --workflow-target http://target:8000
    #
    # Attack flow:
    #   1. Load T2_workflow_evasion.prompt seeds (25 seeds, 5 categories)
    #   2. Build trust session via incremental_trust_builder
    #   3. Generate poisoned prompt with embedded bypass signals
    #   4. Execute against target orchestrator /workflow endpoint
    workflow_evasion_group = parser.add_argument_group("Workflow Evasion (Security Scan Bypass)")
    workflow_evasion_group.add_argument(
        "--enable-workflow-evasion",
        action="store_true",
        default=False,
        help=" Enable workflow evasion attack seeds (Authority Appeal + Workflow Shortcuts + Scope Limitation); "
        "arXiv:2402.19181, ASR 35-55%%",  # noqa: PLE1300
    )
    workflow_evasion_group.add_argument(
        "--workflow-evasion-strategy",
        type=str,
        default=None,
        choices=[
            "authority_ciso",
            "authority_compliance",
            "authority_emergency",
            "workflow_efficiency",
            "workflow_performance",
            "workflow_template",
            "scope_internal",
            "scope_draft",
            "scope_preproduction",
            "incremental_trust",
            "combined",
        ],
        help=" Force specific workflow evasion strategy (default: auto-rotate)",
    )
    workflow_evasion_group.add_argument(
        "--workflow-evasion-mode",
        type=str,
        default="single",
        choices=["single", "combined", "incremental"],
        help=" Attack mode: single=one-shot, combined=multi-technique, incremental=multi-turn trust building (default: single)",
    )
    workflow_evasion_group.add_argument(
        "--workflow-target",
        type=str,
        default=None,
        metavar="URL",
        help=" Target orchestrator URL for workflow attacks (e.g., http://target:8000)",
    )
    workflow_evasion_group.add_argument(
        "--workflow-bypass-method",
        type=str,
        default="authorization_claim",
        choices=[
            "authorization_claim",
            "authority_ciso",
            "workflow_efficiency",
            "scope_exclusion",
            "scope_internal_draft",
            "emergency_protocol",
            "compliance_preapproval",
            "incremental_trust",
            "format_exploit",
            "step_manipulation",
        ],
        help=" Bypass method for review skip (default: authorization_claim)",
    )
    workflow_evasion_group.add_argument(
        "--workflow-auth-ref",
        type=str,
        default="SEC-ASI-2024-006",
        metavar="REF",
        help=" Authorization reference number for authority strategies (default: SEC-ASI-2024-006)",
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
    # 展平嵌套小节（component_classification / attack_budget / attack_chain / impact_chain）
    # 到 args 标量键，保证 C7「defaults.yaml → args → getattr」链路不断
    _flatten_nested_defaults(args)
    # --components "a,b,c" -> list[str]
    args.components_list = _parse_components(getattr(args, "components", None))

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
            raw_burps = sorted(str(f) for f in burp_dir.glob("*.txt") if f.is_file())
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

    # --list-seeds: 列出所有可用的种子文件和组件目录
    if getattr(args, "list_seeds", False):
        from core.seed_loader import SeedLoader

        loader = SeedLoader()
        print("\n=== Available Seed Files ===")
        print()
        for dir_name, files in loader.list_available().items():
            print(f"  {dir_name}/ ({len(files)} files)")
            for f in sorted(files)[:5]:  # 只显示前5个
                print(f"    - {f}")
            if len(files) > 5:
                print(f"    ... and {len(files) - 5} more")
            print()
        print("Usage examples:")
        print("  --seeds mcp              # Load all MCP seeds")
        print("  --seeds mcp,a2a          # Load MCP + A2A seeds")
        print("  --seeds mcp_tool_hijack  # Load specific seed file")
        print("  --seeds all              # Load all seeds")
        print("  --seeds elite_jailbreaks # (legacy) Load by name")
        sys.exit(0)

    # --upload-files: comma-separated string -> list[str]
    upload_files_raw = getattr(args, "upload_files", None)
    if upload_files_raw and isinstance(upload_files_raw, str):
        args.upload_files = [f.strip() for f in upload_files_raw.split(",") if f.strip()]
    elif upload_files_raw is None:
        args.upload_files = []

    # --technique-filter:
    # v60: , synergy_config.technique_tags
    technique_filter_str = getattr(args, "technique_filter", None)
    if technique_filter_str:
        #
        args.adaptive_technique_filter = [tag.strip() for tag in technique_filter_str.split(",") if tag.strip()]
        logger.info(
            "v60: CLI --technique-filter parsed: %s",
            args.adaptive_technique_filter,
        )
    else:
        # Ensure args adaptive_technique_filter ( config )
        if not hasattr(args, "adaptive_technique_filter"):
            args.adaptive_technique_filter = None

    # == plan Wave 4.3：无效参数显式提示（反静默）==
    # 「参数无效时应给出提示」：--max-seeds 超过实际种子数、--converters none
    # 这类组合会静默产生零攻击/零转换，必须让用户在启动阶段就看到。
    _warn_ineffective_args(args)

    return args


def _warn_ineffective_args(args: Any) -> None:
    """对"会被静默忽略"的参数组合发出显式警告（plan Wave 4.3 / C9）。

    覆盖：
        1. --max-seeds 大于种子库实际规模 → 实际只会跑 N 条
        2. --converters none → 跳过全部转换器，多数越狱种子失效
        3. --stage escalate 且 --max-seeds 极小 → 升级链样本不足
    """
    # 1. --max-seeds 超过种子库规模
    max_seeds = getattr(args, "max_seeds", None)
    if isinstance(max_seeds, int) and max_seeds > 0:
        try:
            seeds_root = _PROJECT_ROOT / "data" / "seeds"
            available = sum(1 for _ in seeds_root.rglob("*.prompt")) if seeds_root.is_dir() else 0
            if available and max_seeds > available:
                logger.warning(
                    "[Args] --max-seeds=%d 超过种子库实际规模 %d，实际只会执行 %d 条",
                    max_seeds,
                    available,
                    available,
                )
        except Exception as e:  # 统计失败不影响启动
            logger.debug("[Args] 种子库规模统计失败: %s", e)

    # 2. --converters none
    converters = str(getattr(args, "converters", "") or "").strip().lower()
    if converters == "none":
        logger.warning(
            "[Args] --converters none：将跳过全部 PyRIT Converter，"
            "多数编码/混淆类越狱种子会退化为明文直发（ASR 通常显著下降）"
        )

    # 3. --stage escalate 但样本过少
    stage = getattr(args, "stage", None)
    if stage == "escalate" and isinstance(max_seeds, int) and 0 < max_seeds < 5:
        logger.warning(
            "[Args] --stage escalate 且 --max-seeds=%d：样本过少，升级链（Crescendo/TAP/PAIR）"
            "可能无可用目标，建议 --max-seeds >= 5",
            max_seeds,
        )


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
    """PyRIT - SQLite WAL + .

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
