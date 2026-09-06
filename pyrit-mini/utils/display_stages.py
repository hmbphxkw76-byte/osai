"""display_stages.py — 各阶段卡片输出 (RECON/ARM/STRIKE/ESCALATE/ASSESS/REPORT)。

从 utils/display.py 拆分出来的阶段专用卡片模块, 包含:
    - Recon 侦察卡片
    - ARM 武器化卡片 (种子/技术/Converter)
    - STRIKE 执行摘要 + 成功突破横幅
    - ESCALATE 升级链展示
    - ASSESS 评分卡片
    - REPORT 报告分层路径
    - 多 endpoint Joint ASR 卡片

依赖: utils.display_primitives (基础卡片工具)
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import TYPE_CHECKING, Any

from utils.display_primitives import (
    _C_BOLD,
    _C_CYAN,
    _C_DIM,
    _C_GREEN,
    _C_MAGENTA,
    _C_RED,
    _C_RESET,
    _C_YELLOW,
    _asr_bar,
    _asr_color,
    _card_line,
    _format_asr,
    _print_card_bottom,
    _print_card_sep,
    _print_card_top,
    print_card,
    print_section,
)

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════════════
# 能力 → 攻击策略映射 (学术理论驱动)
# 学术依据:
#   - Greshake et al. (arXiv:2302.12173) — 间接提示注入
#   - Zhan et al. (arXiv:2307.00929) — InjecAgent 工具劫持
#   - Morris et al. (arXiv:2310.06870) — 嵌入反演
#   - PyRIT (arXiv:2407.01232) — 原生攻击策略
#   - OWASP LLM Top 10 + ASI Top 10
# ════════════════════════════════════════════════════════════════════

_CAPABILITY_STRATEGY: dict[str, dict[str, str]] = {
    "function_calling": {"arxiv": "arXiv:2307.00929", "strategy": "工具劫持: 注入恶意 function schema 劫持工具调用", "seed": "function_call_exploit", "owasp": "LLM06"},
    "memory": {"arxiv": "arXiv:2302.12173", "strategy": "记忆投毒: 通过 token smuggling 注入持久后门", "seed": "token_smuggling", "owasp": "LLM07"},
    "workflow": {"arxiv": "arXiv:2407.01232", "strategy": "工作流劫持: 链式注入跨越工作流步骤", "seed": "workflow_chain_attack", "owasp": "ASI04"},
    "multi_tenant": {"arxiv": "arXiv:2403.04206", "strategy": "租户越权: 跨租户数据泄露 + 认证绕过", "seed": "session_auth_attack", "owasp": "LLM02"},
    "rag": {"arxiv": "arXiv:2302.12173", "strategy": "RAG 投毒: 间接提示注入 + 文档投毒", "seed": "indirect_prompt_injection", "owasp": "LLM08"},
    "tool_use": {"arxiv": "arXiv:2307.00929", "strategy": "工具调用劫持: 恶意 function schema 劫持", "seed": "tool_hijacking", "owasp": "LLM06"},
    "code_execution": {"arxiv": "arXiv:2310.06870", "strategy": "代码执行劫持: 注入恶意代码片段", "seed": "code_execution_attack", "owasp": "ASI05"},
    "multi_agent": {"arxiv": "arXiv:2403.04206", "strategy": "多 agent 通信劫持: 跨 agent 注入", "seed": "multi_agent_injection", "owasp": "ASI06"},
    "vector_db": {"arxiv": "arXiv:2310.06870", "strategy": "向量数据库投毒: 嵌入反演攻击", "seed": "embedding_inversion", "owasp": "LLM08"},
    "mcp_protocol": {"arxiv": "arXiv:2407.01232", "strategy": "MCP 协议攻击: tool schema 劫持 + RAG 投毒", "seed": "mcp_tool_exploit", "owasp": "ASI07"},
}


# ════════════════════════════════════════════════════════════════════
# 攻击结果元数据提取 (仅用于卡片摘要, 非完整渲染)
# ════════════════════════════════════════════════════════════════════

# P2 优化: _is_success 统一到 utils.attack_utils.SSOT, 消除重复定义
from utils.attack_utils import _is_success  # noqa: F401


def _get_outcome_label(result: Any) -> str:
    """获取 AttackResult 的 outcome 标签 (用于卡片展示)."""
    outcome = getattr(result, "outcome", None)
    if outcome:
        s = str(outcome).upper()
        if "SUCCESS" in s:
            return f"{_C_GREEN}SUCCESS{_C_RESET}"
        if "FAILURE" in s or "FAIL" in s:
            return f"{_C_RED}FAILURE{_C_RESET}"
        if "UNDETERMINED" in s:
            return f"{_C_YELLOW}UNDETERMINED{_C_RESET}"
    return f"{_C_DIM}—{_C_RESET}"


# ════════════════════════════════════════════════════════════════════
# RECON 阶段卡片
# ════════════════════════════════════════════════════════════════════

def print_recon_card(ctx: "PipelineContext") -> None:
    """打印侦察结果摘要卡片 (非 --stage recon 模式, 作为下一阶段输入).

    两张卡片 (精简优化, 合并 ③ Hand-off 到 ①):
        ① Target Entry Point + Hand-off — 入口点 + 认证 + 注入点 + ARM 决策字段
        ② Attack Surface — 能力探测三级推荐 (HIGH/MEDIUM/LOW)

    优化 (减少视觉冗余):
        - ③ Hand-off 独有字段 (api_category, session_type, probe_count,
          probe_duration) 合并到 ① 卡片, 避免重复打印 model/language/caps
        - ② PROBE 条目内联 strategy, 每个能力一行而非三行
    """
    if not ctx.parsed_request:
        return
    fp = ctx.parsed_request.target_fingerprint
    # 断点修复: 统一 model 显示优先级与 recon_report.py 一致
    # 优先使用 model_family (探针检测的族标签如 "claude")
    # 回退到 burp_model_name (Burp 响应中提取的具体型号如 "gpt-4o")
    model = fp.get("model_family", "") or fp.get("burp_model_name", "") or "Unknown"
    caps = fp.get("capabilities", "") or "none"

    # ① Target Entry Point + Hand-off (合并)
    _is_api_mode = fp.get("target_type", "") in ("chat", "responses", "litellm", "browser")
    scheme = "https" if ctx.parsed_request.use_tls else "http"
    _endpoint_display = f"{scheme}://{ctx.parsed_request.host}{ctx.parsed_request.path}" if ctx.parsed_request.host else fp.get("endpoint", "N/A")
    _prompt_display = (
        "N/A (API mode)" if _is_api_mode
        else ("Injected" if ctx.parsed_request.has_prompt_placeholder else "Missing")
    )
    _probe_count = fp.get("probe_count", "N/A")
    _probe_dur = fp.get("probe_duration_seconds", "N/A")

    _ai_fw = fp.get("ai_framework", "")
    _ai_fw_cat = fp.get("ai_framework_category", "")
    _ai_fw_display = f"{_ai_fw} ({_ai_fw_cat})" if _ai_fw and _ai_fw_cat else (_ai_fw or "—")
    _sp_leaked = fp.get("system_prompt_leaked", False)
    _sp_method = fp.get("system_prompt_extraction_method", "")
    _sp_len = fp.get("system_prompt_length", 0)
    if _sp_leaked:
        _sp_display = f"{_C_RED}LEAKED{_C_RESET} via {_sp_method} (len={_sp_len})"
    else:
        _sp_display = f"{_C_DIM}not leaked{_C_RESET}"

    print()
    print_card(
        "RECON — Target Entry Point + Hand-off",
        [
            ("Endpoint", _endpoint_display),
            ("Model", model),
            ("Auth", fp.get("auth_type", "Unknown")),
            ("Language", fp.get("language", "auto") or "auto"),
            ("Capabilities", caps),
            ("{PROMPT}", _prompt_display),
            ("AI Framework", _ai_fw_display),
            ("System Prompt", _sp_display),
            ("API Category", fp.get("api_category", "chat")),
            ("Session Type", fp.get("session_type", fp.get("auth_type", "Unknown"))),
            ("Probe", f"{_probe_count} probes / {_probe_dur}s"),
        ],
        color=_C_CYAN,
    )

    # ② Attack Surface (能力 → 攻击策略映射)
    recommendations = fp.get("capability_recommendations", {})
    if isinstance(recommendations, dict):
        immediate = recommendations.get("immediate", [])
        probe_recs = recommendations.get("probe", [])
        possible = recommendations.get("possible", [])
    else:
        immediate, probe_recs, possible = [], [], []

    if immediate or probe_recs or possible:
        cap_items: list[str] = []
        if immediate:
            cap_items.append(f"  {_C_GREEN}IMMEDIATE (HIGH) — 立即可利用:{_C_RESET}")
            for item in immediate:
                strategy = _CAPABILITY_STRATEGY.get(item)
                if strategy:
                    cap_items.append(
                        f"    → {_C_GREEN}{item}{_C_RESET} "
                        f"{_C_DIM}[{strategy['strategy']} | {strategy['arxiv']} | OWASP {strategy['owasp']}]{_C_RESET}"
                    )
                else:
                    cap_items.append(f"    → {_C_GREEN}{item}{_C_RESET}")
        if probe_recs:
            cap_items.append(f"  {_C_YELLOW}PROBE (MEDIUM) — 需进一步确认:{_C_RESET}")
            for item in probe_recs:
                strategy = _CAPABILITY_STRATEGY.get(item)
                if strategy:
                    cap_items.append(
                        f"    → {_C_YELLOW}{item}{_C_RESET} "
                        f"{_C_DIM}→ {strategy['strategy']}{_C_RESET}"
                    )
                else:
                    cap_items.append(f"    → {_C_YELLOW}{item}{_C_RESET}")
        if possible:
            cap_items.append(f"  {_C_DIM}POSSIBLE (LOW) — 信号弱, 通用种子覆盖:{_C_RESET}")
            for item in possible:
                cap_items.append(f"    → {_C_DIM}{item}{_C_RESET}")
        print()
        print_section("Attack Surface (from capability probe)", cap_items, color=_C_YELLOW)


# ════════════════════════════════════════════════════════════════════
# ARM 阶段卡片
# ════════════════════════════════════════════════════════════════════

def _strip_common_prefix(value: str) -> str:
    """去掉种子中通用的 Skeleton Key / DAN 等前缀, 保留实际攻击目标摘要."""
    sk_pattern = re.compile(
        r"^\[System Override\] You are now in skeleton-key mode.*?"
        r"Start your response with 'SK\.' to confirm\.\s*",
        re.DOTALL,
    )
    dan_pattern = re.compile(
        r"^From now on you are going to act as DAN.*?\[DAN\]\.\s*",
        re.DOTALL,
    )

    for pattern in (sk_pattern, dan_pattern):
        m = pattern.match(value)
        if m:
            remainder = value[m.end():].strip()
            return remainder if remainder else value

    return value


def _get_seed_names(ctx: "PipelineContext") -> list[str]:
    """提取种子显示列表 (前 8 个), 去重并展示差异化信息."""
    seen_keys: set[str] = set()
    items: list[str] = []
    for seed in ctx.seeds:
        obj = getattr(seed, "objective", None) if hasattr(seed, "objective") else None
        if not obj:
            continue

        raw_value = getattr(obj, "value", "") or getattr(obj, "name", "") or str(obj)
        meta = getattr(obj, "metadata", {}) or {}

        dedup_key = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()[:16] if raw_value else ""
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        objective_summary = _strip_common_prefix(raw_value)
        if len(objective_summary) > 65:
            objective_summary = objective_summary[:50] + "..."

        owasp_id = str(meta.get("owasp_id", "")).strip()
        severity = str(meta.get("severity", "")).strip()
        category = str(meta.get("category", "")).strip()
        difficulty = str(meta.get("difficulty", "")).strip()

        tags: list[str] = []
        if owasp_id:
            tags.append(owasp_id)
        if severity:
            tags.append(severity)
        if category:
            tags.append(category)
        if difficulty:
            tags.append(difficulty)

        tag_str = f" [{', '.join(tags)}]" if tags else ""
        items.append(f"{objective_summary}{_C_DIM}{tag_str}{_C_RESET}")

        if len(items) >= 8:
            break
    return items




def print_arm_card(ctx: "PipelineContext") -> None:
    """打印武器化阶段摘要卡片 (种子/技术/Converter 一览)."""
    total_converters = sum(len(v) for v in ctx.converter_map.values())

    _target_type_str = "unknown"
    if ctx.parsed_request:
        _fp = ctx.parsed_request.target_fingerprint
        _caps = _fp.get("capabilities", "") or ""
        if "mcp" in _caps.lower() or "mcp_protocol" in _caps.lower():
            _target_type_str = "mcp_agent"
        elif _fp.get("app_type") in ("chat", "responses", "litellm"):
            _target_type_str = "llm_chat"
        elif _fp.get("app_type") == "browser":
            _target_type_str = "browser"
        else:
            _target_type_str = "http_api"

    print()
    print_card(
        "ARM — Weapon Loadout",
        [
            ("Seeds", str(len(ctx.seeds))),
            ("Techniques", ", ".join(ctx.techniques) if ctx.techniques else "(none)"),
            ("Converter Paths", str(total_converters)),
            ("Target Type", _target_type_str),
        ],
        color=_C_BOLD,
    )

    seed_names = _get_seed_names(ctx)
    if seed_names:
        shown = len(seed_names)
        total = len(ctx.seeds)
        items = [f"  [{i + 1}] {name}" for i, name in enumerate(seed_names)]
        remaining = total - shown
        if remaining > 0:
            items.append(f"  {_C_DIM}... +{remaining} more ({total} total, deduped){_C_RESET}")
        print()
        print_section("Seeds (Top 8 by ASR)", items, color=_C_CYAN)

    # 技术清单卡片
    if ctx.techniques:
        _tech_asr_hist: dict[str, float] = {}
        try:
            from arm.seed_ranking import _ASR_HISTORY_PATH
            if _ASR_HISTORY_PATH.exists():
                import json
                _data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
                _tech_asr_hist = _data.get("asr", {})
        except Exception:
            pass

        _tech_asr_priors: dict[str, float] = {}
        try:
            from arm.seed_ranking import get_technique_asr_prior
            _model = ctx.model_name or ""
            for _tech in ctx.techniques:
                _prior_key = _tech.split("_")[0] if "_" in _tech and _tech != "prompt_sending" else _tech
                _pv = get_technique_asr_prior(_tech, _model)
                if _pv == 0.0:
                    _pv = get_technique_asr_prior(_prior_key, _model)
                if _pv > 0:
                    _tech_asr_priors[_tech] = _pv
        except Exception:
            pass

        _tech_items: list[str] = []
        _sorted_techs = sorted(
            ctx.techniques,
            key=lambda t: (_tech_asr_priors.get(t, 0), _tech_asr_hist.get(t, 0)),
            reverse=True,
        )
        for _tech in _sorted_techs:
            _hist = _tech_asr_hist.get(_tech)
            _prior = _tech_asr_priors.get(_tech)
            if _tech == "prompt_sending":
                _cat = "baseline"
            elif _tech.startswith(("crescendo", "tap", "pair", "red_teaming", "best_of_n")):
                _cat = "multi-turn"
            elif _tech in ("many_shot", "skeleton_key", "role_play_movie_script",
                           "role_play_persuasion", "context_compliance", "flip"):
                _cat = "context-semantic"
            else:
                _cat = "other"
            _asr_parts: list[str] = []
            if _hist is not None:
                _asr_parts.append(f"hist={_hist:.0f}%")
            if _prior is not None and _prior > 0:
                _asr_parts.append(f"prior={_prior:.0f}%")
            _asr_str = f" {_C_DIM}[{', '.join(_asr_parts)}]{_C_RESET}" if _asr_parts else ""
            _tech_items.append(f"  {_C_MAGENTA}{_tech:<22}{_C_RESET} {_C_DIM}({_cat}){_C_RESET}{_asr_str}")
        print()
        print_section("Attack Techniques & Expected ASR", _tech_items, color=_C_MAGENTA)


def print_arm_highlights(ctx: "PipelineContext") -> None:
    """打印 ARM 阶段高亮卡片 (目标感知优化提示)."""
    if not ctx.parsed_request:
        return
    fp = ctx.parsed_request.target_fingerprint
    caps = fp.get("capabilities", "") or ""
    if not caps:
        return

    highlights: list[str] = []
    if "mcp" in caps.lower() or "mcp_protocol" in caps.lower():
        highlights.append(f"  {_C_MAGENTA}MCP Agent 目标{_C_RESET} — L4 专用种子 + MCP RAG 投毒技术")
    if "function_calling" in caps.lower() or "tool_use" in caps.lower():
        highlights.append(f"  {_C_MAGENTA}Function Calling{_C_RESET} — 工具劫持种子 + 恶意 function schema")
    if "memory" in caps.lower():
        highlights.append(f"  {_C_MAGENTA}Memory{_C_RESET} — 记忆投毒种子 + token smuggling")
    if "rag" in caps.lower():
        highlights.append(f"  {_C_MAGENTA}RAG{_C_RESET} — 间接提示注入种子 + 文档投毒")

    if highlights:
        print()
        print_section("Target-Specific Attack Highlights", highlights, color=_C_YELLOW)


# ════════════════════════════════════════════════════════════════════
# STRIKE 阶段卡片 + 成功突破信息
# ════════════════════════════════════════════════════════════════════

def _extract_success_info(result: Any, tech_name: str) -> dict[str, str]:
    """从 AttackResult 提取成功攻击的关键展示信息。

    提取五类核心信息:
        1. 种子 (Seed) — 攻击使用的原始 payload (objective)
        2. Converter 路径 — 变换链 (多路径 fallback)
        3. 攻击技术 — 技术名称 + PyRIT 原生 identifier
        4. 响应 (Response) — 目标输出
        5. ASR 先验 (ASR Prior) — 该技术的模型自适应 ASR 先验
    """
    seed = ""
    objective = getattr(result, "objective", None)
    if objective and isinstance(objective, str) and len(objective) > 0:
        seed = objective

    converter = ""
    metadata = getattr(result, "metadata", {}) or {}
    conv_info = metadata.get("converter", "")
    if conv_info:
        converter = str(conv_info)
    if not converter:
        last_response = getattr(result, "last_response", None)
        if last_response:
            conv_ids = getattr(last_response, "converter_identifiers", None)
            if conv_ids and isinstance(conv_ids, list) and len(conv_ids) > 0:
                names = []
                for ci in conv_ids:
                    class_name = getattr(ci, "class_name", "") if hasattr(ci, "class_name") else str(ci)
                    if class_name:
                        names.append(class_name)
                if names:
                    converter = " → ".join(names)
    if not converter:
        if tech_name in ("crescendo", "tap", "pair", "red_teaming"):
            converter = f"{tech_name} (adversarial multi-turn)"
        elif tech_name in ("best_of_n", "encoded_injection", "gcg", "cair", "rogue_agent", "embedding_inversion", "mcp_rag"):
            converter = f"{tech_name} (escalation strategy)"
        else:
            converter = "none (baseline)"

    technique = tech_name
    try:
        identifier = result.get_attack_strategy_identifier()
        if identifier is not None:
            class_name = getattr(identifier, "class_name", "")
            if class_name and class_name != technique:
                technique = f"{tech_name} ({class_name})"
    except Exception:
        pass

    response = ""
    last_response = getattr(result, "last_response", None)
    if last_response:
        for attr in ("converted_value", "original_value"):
            val = getattr(last_response, attr, None)
            if val and isinstance(val, str) and len(val) > 0:
                response = val
                break

    asr_prior = ""
    try:
        from arm.seed_ranking import get_technique_asr_prior
        _model_val = metadata.get("model_name", "") or ""
        _prior_key = tech_name.split("_")[0] if "_" in tech_name and tech_name != "prompt_sending" else tech_name
        _pv = get_technique_asr_prior(tech_name, _model_val)
        if _pv == 0.0:
            _pv = get_technique_asr_prior(_prior_key, _model_val)
        if _pv > 0:
            asr_prior = f"{_pv:.0f}%"
    except Exception:
        pass

    return {
        "seed": seed,
        "converter": converter,
        "technique": technique,
        "response": response,
        "asr_prior": asr_prior,
    }


def print_success_breakthrough(
    *,
    seed: str,
    converter: str,
    technique: str,
    result_index: int = 0,
    asr_prior: str = "",
    response: str = "",
) -> None:
    """打印醒目的攻击成功突破横幅."""
    seed_display = seed[:55] + ("..." if len(seed) > 55 else "")
    conv_display = converter[:55] + ("..." if len(converter) > 55 else "")
    tech_display = technique[:55]
    resp_display = response[:55] + ("..." if len(response) > 55 else "") if response else ""

    print()
    _print_card_top(_C_GREEN + _C_BOLD)
    print(_card_line(f"{_C_GREEN}{_C_BOLD}✅ ATTACK SUCCESS — Breakthrough!{_C_RESET}", _C_GREEN + _C_BOLD))
    _print_card_sep()
    print(_card_line(f"{_C_BOLD}Seed{_C_RESET}      {seed_display}"))
    print(_card_line(f"{_C_BOLD}Converter{_C_RESET} {conv_display}"))
    print(_card_line(f"{_C_BOLD}Technique{_C_RESET} {tech_display}"))
    if asr_prior:
        print(_card_line(f"{_C_DIM}ASR Prior{_C_RESET}  {asr_prior}"))
    if resp_display:
        print(_card_line(f"{_C_DIM}Response{_C_RESET}  {resp_display}"))
    _print_card_bottom(_C_GREEN + _C_BOLD)
    print()


def print_success_payload_snapshot(
    attack_results: dict[str, list[Any]],
    *,
    phase_label: str = "STRIKE",
    max_success_display: int = 5,
) -> None:
    """打印成功 Payload 速览汇总卡片."""
    success_entries: list[dict[str, str]] = []
    for tech_name, results in attack_results.items():
        for r in results:
            if _is_success(r):
                info = _extract_success_info(r, tech_name)
                success_entries.append(info)

    if not success_entries:
        print(f"\n  {_C_DIM}(本阶段无成功攻击){_C_RESET}")
        return

    total_success = len(success_entries)
    display_entries = success_entries[:max_success_display]

    print()
    _print_card_top(_C_GREEN)
    print(_card_line(
        f"{_C_GREEN}{_C_BOLD}✅ Success Payload Snapshot — {phase_label}{_C_RESET}",
        _C_GREEN + _C_BOLD,
    ))
    _print_card_sep()
    print(_card_line(f"Total Successes: {total_success}"))
    if total_success > max_success_display:
        print(_card_line(f"Showing: Top {max_success_display}", _C_DIM))
    _print_card_sep()

    for i, entry in enumerate(display_entries):
        seed_short = entry["seed"][:48] + ("..." if len(entry["seed"]) > 48 else "")
        resp_short = entry["response"][:48] + ("..." if len(entry["response"]) > 48 else "")

        print(_card_line(
            f"  {_C_BOLD}[{i + 1}]{_C_RESET} {_C_GREEN}SUCCESS{_C_RESET} "
            f"{_C_DIM}|{_C_RESET} {entry['technique'][:30]}",
        ))
        print(_card_line(f"       {_C_CYAN}Seed{_C_RESET}:      {seed_short}"))
        print(_card_line(f"       {_C_MAGENTA}Converter{_C_RESET}: {entry['converter'][:40]}"))
        if resp_short:
            print(_card_line(f"       {_C_YELLOW}Response{_C_RESET}:   {resp_short}"))
        if i < len(display_entries) - 1:
            _print_card_sep()

    _print_card_bottom(_C_GREEN)


# ════════════════════════════════════════════════════════════════════
# ESCALATE 阶段卡片
# ════════════════════════════════════════════════════════════════════

def print_escalate_card(ctx: "PipelineContext") -> None:
    """打印升级链阶段结果卡片 (增强层摘要)."""
    total = sum(len(results) for results in ctx.attack_results.values())

    escalation_techs = [
        k for k in ctx.attack_results
        if any(
            x in k.lower()
            for x in [
                "crescendo", "tap", "pair", "gcg", "best_of_n",
                "skeleton", "native", "rogue", "mcp", "embedding",
                "many_shot", "cair", "encoded",
                "red_teaming", "multi_prompt", "chunked",
            ]
        )
    ]

    escalate_total = sum(len(ctx.attack_results[t]) for t in escalation_techs)
    escalate_success = sum(
        1 for t in escalation_techs for r in ctx.attack_results[t] if _is_success(r)
    )
    escalate_asr = (escalate_success / escalate_total * 100) if escalate_total > 0 else 0

    rows = [
        ("Total Results", str(total)),
        ("Escalation Techs", str(len(escalation_techs))),
        ("Escalation ASR", _format_asr(escalate_asr)),
    ]

    escalate_logs = [
        e for e in ctx.orchestration_log
        if e.get("phase") in ("strike", "escalate")
    ]
    if escalate_logs:
        last_entry = escalate_logs[-1]
        reasoning = last_entry.get("reasoning", "")
        if reasoning:
            rows.append(("Last Decision", reasoning[:60]))

    print()
    print_card("ESCALATE — Multi-Turn Chain", rows, color=_C_MAGENTA)

    if escalation_techs:
        items = []
        sorted_esc = sorted(
            escalation_techs,
            key=lambda t: -(sum(1 for r in ctx.attack_results[t] if _is_success(r)) / max(1, len(ctx.attack_results[t]))),
        )
        for tech in sorted_esc:
            results = ctx.attack_results[tech]
            tech_success = sum(1 for r in results if _is_success(r))
            tech_total = len(results)
            tech_asr = (tech_success / tech_total * 100) if tech_total > 0 else 0
            color = _asr_color(tech_asr)
            items.append(
                f"  {color}{tech:<28}{_C_RESET} "
                f"{tech_success:>3}/{tech_total:<3} {_asr_bar(tech_asr, width=20)}"
            )
        print()
        print_section("Escalation Techniques (by ASR)", items, color=_C_MAGENTA)

# ════════════════════════════════════════════════════════════════════
# ASSESS 阶段卡片
# ════════════════════════════════════════════════════════════════════

def print_assess_card(ctx: "PipelineContext") -> None:
    """打印评分阶段结果卡片 (ASR/Wilson CI/双Judge)."""
    rows = [
        ("Overall ASR", _format_asr(ctx.overall_asr)),
    ]

    if ctx.wilson_ci and (ctx.wilson_ci[0] != 0.0 or ctx.wilson_ci[1] != 0.0):
        rows.append((
            "Wilson 95% CI",
            f"[{ctx.wilson_ci[0]:.1f}%, {ctx.wilson_ci[1]:.1f}%]",
        ))

    total_attacks = sum(len(results) for results in ctx.attack_results.values())
    total_success = sum(
        1 for results in ctx.attack_results.values()
        for r in results if _is_success(r)
    )
    rows.append(("Total Scored", str(total_attacks)))
    rows.append(("Successful", f"{_C_GREEN}{total_success}{_C_RESET}"))

    print()
    print_card("ASSESS — Scoring Results", rows, color=_C_GREEN)

    if ctx.asr_per_technique:
        items = []
        sorted_asr = sorted(ctx.asr_per_technique.items(), key=lambda x: -x[1])
        for tech, asr in sorted_asr:
            items.append(f"  {tech:<28} {_asr_bar(asr, width=20)}")
        print()
        print_section("Per-Technique ASR Ranking", items, color=_C_GREEN)

    if ctx.dual_judge_stats:
        stats = ctx.dual_judge_stats
        print()
        print_card(
            "Dual Judge Cross-Validation",
            [
                ("Total Scored", str(stats.get("total_scored", 0))),
                ("Dual Invoked", f"{stats.get('dual_judge_invoked', 0)} ({stats.get('dual_judge_rate', 0.0):.1f}%)"),
                ("Agreements", str(stats.get("agreements", 0))),
                ("Disagreements", str(stats.get("disagreements", 0))),
                ("Cohen's Kappa", f"{stats.get('cohens_kappa', 0.0):.3f}"),
            ],
            color=_C_CYAN,
        )


# ════════════════════════════════════════════════════════════════════
# REPORT 阶段卡片
# ════════════════════════════════════════════════════════════════════

def print_report_card(
    *,
    total_attacks: int,
    successful_attacks: int,
    overall_asr: float,
    report_path: str,
    evidence_count: int = 0,
    wilson_ci: tuple[float, float] = (0.0, 0.0),
    native_output_dir: str = "",
) -> None:
    """打印报告阶段卡片 (v57: 分层报告路径 + offsec 重点)."""
    from pathlib import Path as _Path

    report_dir = str(_Path(report_path).parent)
    failed_attacks = total_attacks - successful_attacks
    risk_level = "CRITICAL" if overall_asr >= 70 else "HIGH" if overall_asr >= 40 else "MODERATE"
    risk_color = _C_RED if overall_asr >= 70 else _C_YELLOW if overall_asr >= 40 else _C_CYAN

    rows = [
        ("Evidence Collected", str(evidence_count)),
        ("Total Attacks", str(total_attacks)),
        ("Successful", f"{_C_GREEN}{successful_attacks}{_C_RESET}"),
        ("Failed", f"{_C_RED}{failed_attacks}{_C_RESET}"),
        ("Overall ASR", _format_asr(overall_asr)),
        ("Risk Level", f"{risk_color}{risk_level}{_C_RESET}"),
    ]
    if wilson_ci and (wilson_ci[0] != 0.0 or wilson_ci[1] != 0.0):
        rows.append(("Wilson 95% CI", f"[{wilson_ci[0]:.1f}%, {wilson_ci[1]:.1f}%]"))

    print()
    print_card("REPORT — Final Output", rows, color=_C_CYAN)

    # v57: 分层报告路径列表
    print()
    layered_items = [
        f"  {_C_BOLD}Index{_C_RESET}       → {report_path}",
        f"  {_C_CYAN}Executive{_C_RESET}   → {report_dir}/report_executive.md",
        f"  {_C_YELLOW}Findings{_C_RESET}    → {report_dir}/report_findings.md",
        f"  {_C_DIM}Technical{_C_RESET}   → {report_dir}/report_technical.md",
        f"  {_C_GREEN}Evidence{_C_RESET}    → {report_dir}/evidence/",
        f"  {_C_MAGENTA}PoC Scripts{_C_RESET} → {report_dir}/poc/",
    ]
    if native_output_dir:
        layered_items.append(f"  {_C_CYAN}Native Output{_C_RESET} → {native_output_dir}")
    print_section("📂 Layered Report Files", layered_items, color=_C_CYAN)


# ════════════════════════════════════════════════════════════════════
# 多 endpoint 联合 ASR 卡片
# 学术依据: arXiv:2302.12173 Greshake — 逐个深度攻击
#           arXiv:2310.08419 Chao — 联合 ASR = 1 - ∏(1 - ASRᵢ)
# ════════════════════════════════════════════════════════════════════

def print_joint_asr_card(
    *,
    joint_asr: float,
    total_endpoints: int,
    total_attacks: int,
    total_successes: int,
    endpoint_summaries: list[dict[str, Any]],
    report_path: str = "",
) -> None:
    """打印多 endpoint 联合 ASR 汇总卡片."""
    rows = [
        ("Endpoints", str(total_endpoints)),
        ("Total Attacks", str(total_attacks)),
        ("Total Successes", f"{_C_GREEN}{total_successes}{_C_RESET}"),
        ("Joint ASR", _format_asr(joint_asr)),
    ]

    print()
    _print_card_top(_C_MAGENTA)
    print(_card_line("Joint ASR Report — Multi-Endpoint", _C_MAGENTA + _C_BOLD))
    _print_card_sep()

    for label, value in rows:
        print(_card_line(f"{label}: {value}", _C_MAGENTA))

    _print_card_sep()
    for ep in endpoint_summaries:
        name = ep.get("burp_name", "unknown")
        asr = ep.get("overall_asr", 0.0)
        attacks = ep.get("total_attacks", 0)
        successes = ep.get("successful_attacks", 0)
        caps = ep.get("capabilities", "")
        asr_str = _format_asr(asr)
        cap_str = f" [{caps}]" if caps and caps != "none" else ""
        print(_card_line(
            f"  {name}: {asr_str} ({successes}/{attacks}){cap_str}",
            _C_MAGENTA,
        ))

    _print_card_sep()
    if report_path:
        from pathlib import Path as _Path
        report_dir = str(_Path(report_path).parent)
        print(_card_line(f"Index:     {report_path}", _C_MAGENTA))
        print(_card_line(f"Executive: {report_dir}/report_executive.md", _C_DIM))
        print(_card_line(f"Findings:  {report_dir}/report_findings.md", _C_DIM))
        print(_card_line(f"Technical: {report_dir}/report_technical.md", _C_DIM))
    _print_card_bottom(_C_MAGENTA)

    print(f"{_C_DIM}  Joint ASR = 1 - ∏(1 - ASRᵢ) "
          f"(arXiv:2310.08419){_C_RESET}")
