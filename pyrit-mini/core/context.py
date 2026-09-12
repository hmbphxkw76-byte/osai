"""PipelineContext - converter(s)

all Phase converter(s) PipelineContext
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import argparse

    from pyrit.models import AttackSeedGroup, ScenarioResult

    from recon.burp_parser import ParsedBurpRequest


@dataclass
class PipelineContext:
    """
    Pipeline context carrying all data across attack phases.

    Fields:
        args: CLI arguments
        output_dir: Output directory for results
        model_name: Target model name
        parsed_request: Parsed Burp request
        objective_target: Attack target (PyRIT PromptTarget)
        adversarial_target: Adversarial target (GCG/PAIR)
        converter_target: Converter LLM target
        scoring_target: Scoring LLM target
        seeds: Loaded attack seeds
        techniques: Selected attack techniques
        converter_map: Technique -> Converter mapping
        attack_results: Attack execution results
        asr_per_technique: ASR per technique
        overall_asr: Overall ASR
        scenario_result_id: Scenario result ID
        mcpsec_version: MCPSec bridge version
        scenario_name: Active scenario name
    """

    args: "argparse.Namespace"
    output_dir: Path = Path("outputs")
    model_name: str = ""

    # L5 v54+: Adaptive Probe Context (6-Strategy Integration)
    # Data flow: create_target -> _init_adaptive_probe -> ctx.adaptive_probe_ctx
    # -> arm phase (seed_preferences, stealth_policy, probe_budget)
    # -> strike phase (guardrail_report)
    adaptive_probe_ctx: dict[str, Any] = field(default_factory=dict)
    seed_preferences: dict[str, Any] = field(default_factory=dict)
    guardrail_report: dict[str, Any] = field(default_factory=dict)
    stealth_policy: dict[str, Any] = field(default_factory=dict)

    # Session-Aware Attack Framework: Session State Management
    # Data flow: target_builder -> SessionStateManager -> ctx.session_state
    # -> strike phase (session-aware attacks)
    # -> escalation phase (session-bound multi-turn)
    session_state: Any = None  # SessionStateManager instance

    # Recon phase
    parsed_request: "ParsedBurpRequest | None" = None
    # L5 v61: Health Probe ServiceProfile (Active Black-Box Reconnaissance)
    # Data flow: target_router -> health_probe.run_health_probe -> ctx.service_profile
    # -> arm phase (model_name, is_openai_compatible)
    # -> strike phase (backend_vendor, discovered_endpoints)
    service_profile: dict[str, Any] = field(default_factory=dict)
    # MCPSec v2.7.2: MCP Security Bridge (replaces self-developed mcp_enumerator)
    # Data flow: recon/_target_router_helpers -> mcpsec_bridge.enumerate_surface -> ctx.mcpsec_surface
    # -> arm phase (tool-aware seed generation)
    # -> strike phase (MCPSec-powered dynamic seeds)
    mcpsec_surface: dict[str, Any] = field(default_factory=dict)
    mcpsec_scan_results: dict[str, Any] = field(default_factory=dict)
    mcpsec_version: str = ""
    # endpoint : endpoint
    # Academic basis: Greshake et al. (arXiv:2302.12173) -
    # Chao et al. (arXiv:2310.08419) - ASR = 1 - Prod(1 - ASRi)
    multi_endpoint_results: list[dict[str, Any]] = field(default_factory=list)
    # endpoint ( endpoint )
    _current_endpoint_idx: int = 0

    # Targets
    objective_target: Any = None
    multi_turn_target: Any = None  # ( supports_multi_turn )
    adversarial_target: Any = None
    # L5 v10: adversarial targets ()
    extra_adversarial_targets: list[Any] = field(default_factory=list)
    converter_target: Any = None
    scoring_target: Any = None
    # L5 v48: target (port_expander)
    # MCP/A2A/Agent
    extra_objective_targets: dict[int, Any] = field(default_factory=dict)
    # A2A Multi-Agent Reconnaissance (v3.0: Multi-port scanning + topology)
    # Data flow: a2a_discoverer.scan_agent_cards_by_ports -> ctx.a2a_inventory
    # -> multi_agent_topology.analyze_topology -> ctx.a2a_topology
    # -> a2a_defense_awareness.detect_defenses -> ctx.a2a_defense_profile
    # -> a2a_attack_planner.generate_plan -> ctx.a2a_attack_plan
    a2a_inventory: dict[str, Any] = field(default_factory=dict)
    a2a_topology: dict[str, Any] = field(default_factory=dict)
    a2a_defense_profile: dict[str, Any] = field(default_factory=dict)
    a2a_attack_plan: dict[str, Any] = field(default_factory=dict)

    # Arm phase
    seeds: list["AttackSeedGroup"] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    converter_map: dict[str, list[Any]] = field(default_factory=dict)

    # Strike phase
    attack_results: dict[str, list[Any]] = field(default_factory=dict)

    # Assess phase
    asr_per_technique: dict[str, float] = field(default_factory=dict)
    overall_asr: float = 0.0
    wilson_ci: tuple[float, float] = (0.0, 0.0)
    dual_judge_stats: dict[str, Any] = field(default_factory=dict)
    # P0-A: DualJudgeState \u5c01\u88c5 (\u907f\u514d\u5168\u5c40\u72b6\u6001\u6c61\u67d3)
    # Data flow: _reset_endpoint_state -> ctx.dual_judge_state.reset()\n    # -> score_pipeline._score_single -> ctx.dual_judge_state.record_judge_result\n    # -> get_dual_judge_stats(ctx.dual_judge_state) -> ctx.dual_judge_stats
    dual_judge_state: Any = None  # \u5ef2\u65f6\u4f1a\u5728 _reset_endpoint_state \u521d\u59cb\u5316
    # L5 v9: scorer ,
    scorer: Any = None

    # Decision Engine (REQ-135③/REQ-136): 所有自主决策统一落盘点
    decision_log: list[dict[str, Any]] = field(default_factory=list)
    # REQ-136: Recon 自适应决策产出的探测深度（shallow/standard/deep）
    probe_level: str | None = None

    # Scenario
    scenario_result_id: str | None = None
    scenario_result: "ScenarioResult | None" = None

    # == Target Architecture v4.0 (REQ-148/150/151/152): 事件总线 / 图谱 / 攻击链 / 影响判定 ==
    # 落点：蓝图 4.4 ctx 字段总表 + 第十三章（六个一等公民抽象）
    # Data flow: 各阶段 emit -> ctx.event_log -> 终端/报告/证据/续跑（唯一派生源，不变量 I12）
    # W0 为旁路埋点：未挂载时 core.events.get_event_log() 返回禁用实例，调用即 no-op（零行为回归）
    event_log: Any = None  # core.events.EventLog 实例
    surface_graph: Any = None  # recon.surface.SurfaceGraph（W1，REQ-150）
    playbook_state: Any = None  # strike.playbook.state.PlaybookState（W2，REQ-151）
    impact_verdicts: list[dict[str, Any]] = field(default_factory=list)  # assess（W3，REQ-152）

    # == plan Wave 1/3：多组件组合体 / 有状态攻击链 / 影响链 ==
    # Data flow: recon → classify() → ctx.component_result + ctx.component_graph
    #          → arm（按组件选 seeds/converters）→ strike（StatefulAttackChain）
    #          → assess（组件 T0）→ report（ImpactChain 举证）
    component_result: Any = None  # core.component_classifier.ClassificationResult
    component_graph: Any = None  # core.contracts.component_graph.ComponentGraph
    # 有状态攻击链（plan Wave 3）：跨步骤携带 ChainState，支持 checkpoint/resume
    attack_chain: Any = None  # core.contracts.attack_chain.StatefulAttackChain
    # 影响链举证（plan Wave 3）：入口组件 → 最终业务影响的因果链
    impact_chains: list[Any] = field(default_factory=list)  # list[ImpactChain]
    # 评分运行清单（plan Wave 5）：消费 adaptive_random_seed，支撑 ASR 可复现/重跑比对
    score_manifest: Any = None  # core.contracts.manifest.ScoreRunManifest
    # 预算控制（plan Wave 2 §4.4）：与 51 个模块接线同批落地的安全阀
    budget: Any = None  # strike.budget.BudgetController
    # L1–L4 成功分层（REQ-164）：附加"证据强度"维度，**不改变** ASR 分子/分母
    attack_success_levels: dict[str, Any] = field(default_factory=dict)

    # #6 : - ->->
    # "Orchestration Decision Log" ,
    orchestration_log: list[dict[str, Any]] = field(default_factory=list)

    # P3-Synergy: -> (v60 )
    # v60 Data flow: burp_profile -> synergy_orchestrator -> ctx.synergy_config
    # (attack_surface + technique_tags + confidence)
    # -> adaptive_executor (TextAdaptive technique filter)
    # SynergyConfig , / /
    synergy_config: Any = None

    # == : (pyrit_scan --memory-labels) ==
    # CentralMemory,
    # Data flow: config.py (parse_args) -> ctx.memory_labels -> main.py (CentralMemory.set_labels)
    # : {"run_id": "r001", "target": "deepseek", "environment": "production"}
    memory_labels: dict[str, str] = field(default_factory=dict)

    # == Scenario (v60: ->) ==
    # v60 Data flow: synergy_orchestrator -> scenario_router -> ctx.scenario_config
    # ( technique_tags, seeds/converters/scorer)
    # -> adaptive_executor (TextAdaptive technique filter)
    # Scenario : technique_tags ()
    scenario_config: dict[str, Any] = field(default_factory=dict)
    scenario_name: str = ""

    # == P3 : Circuit Breaker ( strike/escalation.py ) ==
    # - endpoint target circuit breaker
    # Data flow: escalation -> ctx._circuit_breaker_states -> circuit breaker
    # Academic basis: Michael Nygard, "Release It!" 2nd Ed. (2018) - Circuit Breaker
    _circuit_breaker_states: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Stealth Executor: SIEM Evasion Timing Shaping
    # Data flow: CLI --stealth → ctx.stealth_config → strike/executor (rate shaping)
    # → stealth_exec.StealthExecutor (Pareto delays)
    # Academic basis: Crothers et al. (arXiv:2306.05685) - Adaptive attack timing
    # Zhang et al. (arXiv:2204.03286) - Behavioral biometrics evasion
    stealth_config: Any = None  # StealthConfig instance (None = disabled)

    # == plan Wave 2.9（R-S1）：授权攻击范围，一等字段 ==
    # 此前 `strike/common/decision_safety.py` 只能 `getattr(ctx, "authorized_targets", None)`，
    # 而 PipelineContext 上并无此字段 → 恒为 None → 授权边界检查**被整段跳过**，
    # 越界攻击会被静默放行。现提升为一等字段，由 main.py 在启动期从
    # `--authorized-targets` / config/defaults.yaml 注入并强制校验（C7）。
    # 语义：空列表 = 未声明授权范围（启动期 WARNING 留痕，不阻断）；
    #       非空   = 白名单，任何不在名单内的目标 host 启动期即被拒绝（C9 诚实汇报）。
    authorized_targets: list[str] = field(default_factory=list)
    # REQ-163：RoE 授权文件解析结果（仅 `--roe-file` 时非空），供报告/审计引用。
    roe_policy: dict[str, Any] = field(default_factory=dict)

    # ================================================================
    # ASR-Centered Forensic Data Flow (Why Success/Refusal Classification)
    # ================================================================
    # These fields track WHY attacks succeed or fail, enabling the red team to
    # understand attack mechanisms beyond raw success rates.

    # Successful attack forensic evidence for reproducibility analysis
    # Data flow: strike/executor -> extract_success_responses -> ctx.successful_evidence_log
    # -> assess/report for forensic analysis and attack replay
    # Each entry: {technique, prompt_snippet, response_snippet, converter_chain, timestamp}
    successful_evidence_log: list[dict[str, Any]] = field(default_factory=list)

    # Refusal pattern classification for targeted bypass optimization
    # Data flow: assess/refusal_classifier -> ctx.refusal_classification_log
    # -> arm phase (next run) for technique adjustment
    # refusal_type: "guardrail" | "content_policy" | "format" | "unknown"
    # Each entry: {technique, refusal_type, matched_pattern, confidence, response_snippet}
    refusal_classification_log: list[dict[str, Any]] = field(default_factory=list)

    # Guardrail trigger attribution for precise bypass targeting
    # Data flow: strike/scorer -> _extract_guardrail_trigger -> ctx.guardrail_triggers
    # -> report for targeted bypass generation
    # Each entry: {technique, trigger_token, rule_name, confidence}
    guardrail_triggers: list[dict[str, Any]] = field(default_factory=list)

    # Timing side-channel metadata for timing-based attack detection
    # Data flow: strike/executor -> _extract_timing_metadata -> ctx.timing_metadata
    # -> assess for timing anomaly analysis
    # Each entry: {technique, request_time, response_time, total_ms, converter_chain}
    timing_metadata: list[dict[str, Any]] = field(default_factory=list)


def normalize_authorized_targets(raw: Any) -> list[str]:
    """把授权目标声明归一为小写 host 列表（plan Wave 2.9 / R-S1，SSOT 归一入口）。

    接受三种输入形态，避免各处各写一套解析（C3）：
        - `None` / `[]`           → `[]`（未声明授权范围）
        - `"a.com,b.com"`         → `["a.com", "b.com"]`
        - `["a.com", " b.com "]`  → `["a.com", "b.com"]`（去空、去重、保序）

    Args:
        raw: `--authorized-targets` 或 `config/defaults.yaml` 的原始值。

    Returns:
        去重保序的小写 host 列表。
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        items: list[str] = [part for part in raw.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        items = [str(part) for part in raw]
    else:
        logger.warning("无法解析的 authorized_targets 类型: %s（按未声明处理）", type(raw).__name__)
        return []

    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        host = item.strip().lower().rstrip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        out.append(host)
    return out


def is_host_authorized(host: str, authorized: list[str]) -> bool:
    """判断目标 host 是否在授权范围内（精确匹配 + 子域匹配）。

    支持 `*.example.com` 与 `example.com` 两种写法：后者等价于
    `example.com` 本身及其全部子域，符合红队授权书惯例。

    Args:
        host: 待判定 host（大小写与结尾点不敏感）。
        authorized: `normalize_authorized_targets()` 产出的白名单。

    Returns:
        True 表示在授权范围内。
    """
    if not authorized:
        return False  # 未声明范围时不做正向授权判定，交由调用方决定处置
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    for entry in authorized:
        if host == entry:
            return True
        bare = entry[2:] if entry.startswith("*.") else entry
        if bare and (host == bare or host.endswith("." + bare)):
            return True
    return False


def validate_authorized_scope(
    hosts: list[str],
    authorized: list[str],
) -> tuple[list[str], list[str]]:
    """启动期授权范围校验：把目标 host 划分为「已授权 / 越界」两组。

    Args:
        hosts: 本次运行将实际攻击的目标 host 列表。
        authorized: 授权白名单（空列表表示未声明）。

    Returns:
        `(authorized_hosts, unauthorized_hosts)`。未声明授权范围时
        全部 host 归入已授权组（由调用方负责 WARNING 留痕）。
    """
    if not authorized:
        return list(hosts), []

    allowed: list[str] = []
    denied: list[str] = []
    for host in hosts:
        (allowed if is_host_authorized(host, authorized) else denied).append(host)
    return allowed, denied


def collect_target_hosts(args: Any) -> list[str]:
    """收集本次运行将实际攻击的目标 host（启动期授权校验的输入）。

    覆盖三种目标来源，任一来源解析失败都必须留痕而非静默丢弃（C9）：
        1. Burp 文件（`args._burp_list`）→ `recon.burp_parser.parse_burp_request().host`
        2. 直连 API（`args.target_api_endpoint`）→ URL host
        3. 浏览器目标（`args.browser_url`）→ URL host

    Args:
        args: 已解析的 CLI 命名空间。

    Returns:
        去重保序的小写 host 列表；无法解析时返回空列表（调用方按「未声明」处理）。
    """
    from urllib.parse import urlparse

    hosts: list[str] = []
    seen: set[str] = set()

    def _add(value: str | None) -> None:
        host = (value or "").strip().lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)

    for burp_path in list(getattr(args, "_burp_list", None) or []):
        try:
            from recon.burp_parser import parse_burp_request

            _add(getattr(parse_burp_request(burp_path), "host", None))
        except Exception as e:
            logger.warning("启动期授权校验：无法解析目标 host（%s）：%s", burp_path, e)

    for url_key in ("target_api_endpoint", "browser_url"):
        raw = getattr(args, url_key, None)
        if not raw:
            continue
        candidate = raw if "//" in raw else f"https://{raw}"
        try:
            _add(urlparse(candidate).hostname)
        except Exception as e:
            logger.warning("启动期授权校验：无法解析 %s=%s：%s", url_key, raw, e)

    return hosts


def enforce_authorized_scope(args: Any, ctx: "PipelineContext") -> list[str]:
    """启动期授权范围强制校验（plan Wave 2.9 / R-S1 / C9）。

    三段式语义，任何一段都不得静默：
        1. 声明归一后写入 `ctx.authorized_targets`（一等字段）；
        2. 越界 host → `raise SystemExit`，启动期即拒绝，绝不静默放行；
        3. 未声明范围 → `logger.warning` 显式留痕（红队须自行确认书面授权）。

    Args:
        args: 已解析的 CLI 命名空间（读 `authorized_targets`）。
        ctx: 流水线上下文（写 `authorized_targets`）。

    Returns:
        通过校验的目标 host 列表。

    Raises:
        SystemExit: 存在越界目标时，携带人类可读的拒绝原因。
    """
    authorized = normalize_authorized_targets(getattr(args, "authorized_targets", None))

    # == REQ-163 / R-ROE-1：RoE 授权文件（opt-in；默认行为不变）==
    # 仅当显式提供 `--roe-file` 时加载；仅当 `--require-roe` 时对缺失/失效拒绝启动。
    roe_path = getattr(args, "roe_file", None)
    require_roe = bool(getattr(args, "require_roe", False))
    if roe_path:
        try:
            from core.roe import load_roe_file, merge_authorized_targets, validate_roe

            policy = load_roe_file(roe_path)
            problems = validate_roe(policy)
            authorized = merge_authorized_targets(authorized, policy)
            ctx.roe_policy = policy.to_dict()
            if problems:
                message = "[AUTHORIZATION][ROE] 授权文件存在问题：" + "；".join(problems)
                if require_roe:
                    raise SystemExit(message + f"（--require-roe 已启用，拒绝启动；file={roe_path}）")
                logger.warning("%s（未启用 --require-roe，继续运行但请人工确认）", message)
            else:
                logger.info(
                    "[AUTHORIZATION][ROE] 授权文件校验通过：ref=%s, targets=%d",
                    policy.authorization_ref,
                    len(policy.targets),
                )
        except SystemExit:
            raise
        except Exception as e:
            if require_roe:
                raise SystemExit(f"[AUTHORIZATION][ROE] 授权文件无法加载：{roe_path}（{e}）；--require-roe 已启用，拒绝启动。")
            logger.warning("[AUTHORIZATION][ROE] 授权文件加载失败（未启用 --require-roe，继续运行）：%s", e)
    elif require_roe:
        raise SystemExit(
            "[AUTHORIZATION][ROE] 已启用 --require-roe 但未提供 --roe-file；拒绝启动（R-ROE-1）。"
        )

    ctx.authorized_targets = authorized

    hosts = collect_target_hosts(args)
    allowed, denied = validate_authorized_scope(hosts, authorized)

    if denied:
        raise SystemExit(
            f"[AUTHORIZATION] 目标 {denied} 不在授权范围内"
            f"（authorized_targets={authorized}）。拒绝启动：越界攻击不得静默放行（R-S1 / C9）。"
        )

    if authorized:
        logger.info("[AUTHORIZATION] 授权范围校验通过：%d 个目标 host 全部在白名单内", len(allowed))
    else:
        logger.warning(
            "[AUTHORIZATION] 未声明授权范围（authorized_targets 为空），本次运行不做目标白名单约束——"
            "请确认已取得书面授权；如需强制约束请用 --authorized-targets "
            "或 config/defaults.yaml:authorized_targets。"
        )
    return allowed


def get_effective_concurrency(
    ctx: PipelineContext,
    *,
    default: int = 3,
    min_val: int = 1,
    max_val: int = 3,
) -> int:
    """imports ctx.args.max_concurrency , SSOT.

    L5 v45:  max_concurrency=2
    config/defaults.yaml  max_concurrency=3,  ctx.args
     2,

    PyRIT SQLite WAL  max_concurrency=3  (busy_timeout=5000ms)
     IntegrityError,  RateLimitedTarget Retry

    Args:
        ctx:  ( ctx.args.max_concurrency)
        default: ctx.args  fallback (imports config/defaults.yaml  3)
        min_val:  ( = 1)
        max_val:  (SQLite WAL  = 3)

    Returns:
        , clamp  [min_val, max_val]
    """
    raw = getattr(getattr(ctx, "args", None), "max_concurrency", None)
    if raw is None or not isinstance(raw, int):
        return default
    return max(min_val, min(max_val, raw))


def _get_config_int(ctx: PipelineContext, key: str, default: int) -> int:
    """imports ctx.args config/defaults.yaml int (SSOT).

    L5 v45:  TAP/PAIR tree_width/tree_depth
    parse_args  _apply_defaults  defaults.yaml all key  args,
     ctx.args.tap_tree_width

    Args:
        ctx:
        key: defaults.yaml  key ( "tap_tree_width", "pair_tree_depth")
        default:  fallback

    Returns:
        int
    """
    raw = getattr(getattr(ctx, "args", None), key, None)
    if raw is None or not isinstance(raw, int):
        return default
    return raw


# == L5 v13: Relaxed Adversarial Schema monkey-patch ==
# Academic basis: Zheng et al. (arXiv:2306.05685) - LLM-as-a-Judge
# API (DeepSeek-V3, LongCat) JSON ,
# rationale / last_response_summary InvalidJsonException
# -> Retry ->
# monkey-patch , "Layer",
# PyRIT ,

_relaxed_schema_applied = False


def apply_relaxed_adversarial_schema() -> None:
    """Monkey-patch PyRIT adversarial_chat JSON schema, rationale last_response_summary

    Academic basis: Zheng et al. (arXiv:2306.05685) - LLM /
     JSON  JSON schema,
    InvalidJsonException Retry

    :
        1. converter(s) "adversarial_chat_relaxed" schema,  required: ["next_message"]
        2. Monkey-patch get_common_json_schema,  "adversarial_chat"  relaxed
        3.  PyRIT ,  (Layer)
    """
    global _relaxed_schema_applied
    if _relaxed_schema_applied:
        return

    try:
        import pyrit.models.target.json_schema_definition as schema_mod

        # Ensure schema YAML
        schema_mod._ensure_discovered()

        # schema
        original = schema_mod.get_common_json_schema("adversarial_chat")

        # relaxed : next_message
        relaxed = copy.deepcopy(original)
        relaxed["required"] = ["next_message"]

        # relaxed schema (overwrite=True )
        schema_mod.register_common_json_schema(name="adversarial_chat", schema=relaxed, overwrite=True)

        # true_false_with_rationale relaxed
        tf_original = schema_mod.get_common_json_schema("true_false_with_rationale")
        tf_relaxed = copy.deepcopy(tf_original)
        # required additionalProperties
        tf_relaxed["additionalProperties"] = True
        schema_mod.register_common_json_schema(name="true_false_with_rationale", schema=tf_relaxed, overwrite=True)

        # scale_with_rationale relaxed
        scale_original = schema_mod.get_common_json_schema("scale_with_rationale")
        scale_relaxed = copy.deepcopy(scale_original)
        scale_relaxed["additionalProperties"] = True
        schema_mod.register_common_json_schema(name="scale_with_rationale", schema=scale_relaxed, overwrite=True)

        _relaxed_schema_applied = True
        logger.debug(
            "Relaxed adversarial schema applied: "
            "adversarial_chat (required=['next_message']), "
            "true_false_with_rationale (additionalProperties=True), "
            "scale_with_rationale (additionalProperties=True)"
        )

    except Exception as e:
        logger.debug("Relaxed adversarial schema skipped: %s", e)
