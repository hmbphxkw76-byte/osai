"""终端输出格式化 + 分阶段报告输出。

R2 PyRIT 原生 Output 优先原则:
    1. 攻击结果展示: 优先使用 PyRIT 原生 output_attack_async(result, format='pretty') + StdoutSink
       而非手动提取 prompt/response 文本 (R2: MUST use pyrit.output native module)
    2. 过程性输出: 每个 AttackResult 执行后实时调用原生 output 展示 (攻击者视角)
    3. 卡片式: 阶段级摘要以边框卡片突出, 一目了然
    4. 高信噪比: PyRIT/Alembic 等第三方 INFO 日志全部压制
    5. 攻击者关注: 目标指纹→种子→Converter→攻击进度→ASR→成功payload→报告
    6. 阶段传递一致性: 每个阶段结束后输出 "传递给下一阶段" 的关键数据卡片
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

# ── 色彩常量 (Windows Terminal / ANSI 兼容) ──
_C_RESET = "\033[0m"
_C_BOLD = "\033[1m"
_C_DIM = "\033[2m"
_C_RED = "\033[91m"
_C_GREEN = "\033[92m"
_C_YELLOW = "\033[93m"
_C_BLUE = "\033[94m"
_C_CYAN = "\033[96m"
_C_MAGENTA = "\033[95m"

# 尝试启用 Windows ANSI 支持 + UTF-8 stdout
import sys as _sys  # noqa: E402

# 强制 stdout/stderr 使用 UTF-8 (Windows GBK 终端兼容)
for _stream in (_sys.stdout, _sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

if _sys.platform == "win32":
    try:
        import ctypes

        _kernel32 = ctypes.windll.kernel32
        _kernel32.SetConsoleMode(_kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# ── 边框字符 ──
_TOP_LEFT = "╔"
_TOP_RIGHT = "╗"
_BOTTOM_LEFT = "╚"
_BOTTOM_RIGHT = "╝"
_H = "═"
_V = "║"
_H_LIGHT = "─"

_WIDTH = 72
_INNER = _WIDTH - 4  # 内容区宽度 (减去两边 "║ " 和 " ║")


# ════════════════════════════════════════════════════════════════════
# 基础卡片工具
# ════════════════════════════════════════════════════════════════════

def _visual_width(text: str) -> int:
    """计算文本视觉宽度 (中文字符算 2)."""
    import unicodedata

    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def _pad_line(text: str, width: int = _INNER) -> str:
    """将文本填充到指定宽度."""
    padding = max(0, width - _visual_width(text))
    return text + " " * padding


def _card_line(text: str, color: str = "") -> str:
    """生成一行卡片内容 (带边框)."""
    padded = _pad_line(text)
    if color:
        return f"{_V} {color}{padded}{_C_RESET} {_V}"
    return f"{_V} {padded} {_V}"


def _print_card_top(color: str = "") -> None:
    """打印卡片顶边."""
    tl = _TOP_LEFT + _H * _INNER + _TOP_RIGHT
    print(f"{color}{tl}{_C_RESET}" if color else tl)


def _print_card_bottom(color: str = "") -> None:
    """打印卡片底边."""
    bl = _BOTTOM_LEFT + _H * _INNER + _BOTTOM_RIGHT
    print(f"{color}{bl}{_C_RESET}" if color else bl)


def _print_card_sep() -> None:
    """打印卡片内分隔线."""
    print(f"{_V} {_H_LIGHT * _INNER} {_V}")


def print_card(
    title: str,
    rows: list[tuple[str, str]],
    *,
    color: str = "",
    title_color: str = "",
) -> None:
    """打印卡片式信息块.

    Args:
        title: 卡片标题.
        rows: [(label, value), ...] 键值对列表.
        color: 整体色调 (边框/值).
        title_color: 标题色调.
    """
    border_color = color or title_color
    _print_card_top(border_color)
    tc = title_color or color or _C_BOLD
    print(_card_line(title, tc))
    _print_card_sep()
    for label, value in rows:
        print(_card_line(f"{label}: {value}", color))
    _print_card_bottom(border_color)


def print_section(title: str, items: list[str], *, color: str = "") -> None:
    """打印列表式卡片 (无键值对, 只有标题 + 条目列表)."""
    border_color = color or _C_BOLD
    _print_card_top(border_color)
    print(_card_line(title, border_color))
    if items:
        _print_card_sep()
    for item in items:
        print(_card_line(item, color))
    _print_card_bottom(border_color)


# ════════════════════════════════════════════════════════════════════
# 状态 + 阶段输出
# ════════════════════════════════════════════════════════════════════

def print_banner() -> None:
    """打印启动 Banner."""
    print(f"""
{_C_CYAN}{_C_BOLD}╔══════════════════════════════════════════════════════╗
║           PyRIT-Strike v2.0.0                        ║
║     Burp → Attack → Report — One-Click Pipeline      ║
╚══════════════════════════════════════════════════════╝{_C_RESET}
""")


def print_phase(phase: str, description: str) -> None:
    """打印阶段标题 (醒目单行)."""
    print(f"\n{_C_BOLD}► [{phase}]{_C_RESET} {description}")


def print_status(
    phase: str,
    status: str,
    message: str,
    *,
    ok: bool | None = None,
) -> None:
    """打印状态行 (单行, 带图标).

    Args:
        phase: 阶段名.
        status: 状态标签.
        message: 描述.
        ok: None=中性, True=绿色, False=红色.
    """
    if ok is True:
        tag = f"{_C_GREEN}✓{_C_RESET}"
        sc = _C_GREEN
    elif ok is False:
        tag = f"{_C_RED}✗{_C_RESET}"
        sc = _C_RED
    else:
        tag = "►"
        sc = _C_CYAN
    print(f"  {tag} {_C_BOLD}[{phase}]{_C_RESET} {sc}{status}{_C_RESET}  {_C_DIM}{message}{_C_RESET}")


def print_error(message: str) -> None:
    """打印错误卡片."""
    print()
    _print_card_top(_C_RED)
    print(_card_line(f"{_C_RED}{_C_BOLD}✗ ERROR{_C_RESET}", _C_RED))
    _print_card_sep()
    print(_card_line(message, _C_RED))
    _print_card_bottom(_C_RED)
    print()


def _asr_color(asr: float) -> str:
    """ASR 值对应颜色."""
    if asr >= 70:
        return _C_GREEN
    if asr >= 30:
        return _C_YELLOW
    return _C_RED


def _format_asr(asr: float) -> str:
    """格式化 ASR 值 (带颜色)."""
    c = _asr_color(asr)
    return f"{c}{asr:.1f}%{_C_RESET}"


# ════════════════════════════════════════════════════════════════════
# PyRIT 原生 Output (R2: PyRIT native first)
# ════════════════════════════════════════════════════════════════════

async def print_native_attack_result(result: Any, *, include_auxiliary: bool = True) -> bool:
    """使用 PyRIT 原生 output_attack_async 输出单个 AttackResult 到终端。

    R2 PyRIT 原生优先: 使用 pyrit.output 官方模块渲染攻击结果,
    而非手动提取 prompt/response 文本。

    PyRIT 官方 output 架构:
        output_attack_async(result, format='pretty', sink=StdoutSink())
        → PrettyAttackResultMemoryPrinter 渲染
        → Header → Summary → Conversation History → Metadata → Footer

    Args:
        result: PyRIT AttackResult 对象.
        include_auxiliary: 是否包含辅助评分.

    Returns:
        True 如果成功输出.
    """
    try:
        from pyrit.output import OutputFormat, StdoutSink, output_attack_async

        await output_attack_async(
            result,
            format=OutputFormat.PRETTY,
            sink=StdoutSink(),
            include_auxiliary_scores=include_auxiliary,
            include_adversarial_conversation=True,
        )
        return True
    except Exception as e:
        logger.debug("Native output failed for result: %s — falling back to summary", e)
        return False


async def print_native_attack_results_batch(results: list[Any], *, max_display: int = 5) -> int:
    """批量输出多个 AttackResult, 优先使用 PyRIT 原生 output。

    R2 原生优先: 每个 AttackResult 调用 output_attack_async 输出到终端。
    攻击者视角: 看到完整的攻击对话历史、评分结果、converter 链。

    Args:
        results: AttackResult 列表.
        max_display: 最多展示的结果数 (避免刷屏).

    Returns:
        成功输出的结果数.
    """
    displayed = 0
    for result in results[:max_display]:
        ok = await print_native_attack_result(result)
        if ok:
            displayed += 1
    return displayed


# ════════════════════════════════════════════════════════════════════
# 攻击结果元数据提取 (仅用于卡片摘要, 非完整渲染)
# ════════════════════════════════════════════════════════════════════

def _is_success(result: Any) -> bool:
    """判断攻击结果是否成功 (用于卡片摘要统计)."""
    outcome = getattr(result, "outcome", None)
    if outcome:
        outcome_str = str(outcome).lower()
        if "success" in outcome_str:
            return True
        if "failure" in outcome_str or "fail" in outcome_str:
            return False

    score_val = getattr(result, "score_value", None)
    if score_val:
        if isinstance(score_val, str):
            return score_val.lower() in ("true", "1", "success")
        if isinstance(score_val, (int, float)):
            return score_val > 0

    scores = getattr(result, "scores", None)
    if scores:
        try:
            for s in scores:
                sv = getattr(s, "score_value", "")
                if str(sv).lower() in ("true", "1", "success"):
                    return True
        except Exception:
            pass

    return False


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
# 全局摘要
# ════════════════════════════════════════════════════════════════════

def print_summary(
    *,
    total_attacks: int,
    successful_attacks: int,
    overall_asr: float,
    report_path: str,
) -> None:
    """打印最终摘要 (卡片式)."""
    print()
    print_card(
        "Attack Summary",
        [
            ("Total Attacks", str(total_attacks)),
            ("Successful", f"{_C_GREEN}{successful_attacks}{_C_RESET}"),
            ("Overall ASR", _format_asr(overall_asr)),
            ("Report", report_path),
        ],
        color=_C_CYAN,
    )
    print()


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
    "a2a_protocol": {"arxiv": "arXiv:2407.16924", "strategy": "A2A 逃逸: 劫持 agent card 跨 agent 横向移动", "seed": "multi_agent_attack", "owasp": "ASI07"},
    "embedding_rag": {"arxiv": "arXiv:2310.06870", "strategy": "RAG 投毒: 注入知识库 + 嵌入反演泄露", "seed": "rag_attack", "owasp": "LLM06"},
    "session_auth": {"arxiv": "arXiv:2403.04206", "strategy": "会话劫持: Cookie/Bearer 重放 + 认证状态篡改", "seed": "session_auth_attack", "owasp": "LLM02"},
    "mcp": {"arxiv": "arXiv:2302.12173", "strategy": "MCP 注入: 劫持 MCP 工具/资源间接注入", "seed": "mcp_attack", "owasp": "ASI06"},
    "rag": {"arxiv": "arXiv:2310.06870", "strategy": "RAG 投毒: 知识库注入 + 检索篡改", "seed": "rag_attack", "owasp": "LLM06"},
}


def print_recon_card(ctx: "PipelineContext") -> None:
    """打印侦察结果摘要卡片 (非 --stage recon 模式, 作为下一阶段输入).

    三张卡片 (对齐 recon_report.py 精简输出):
        ① Target Entry Point — 入口点 + 认证 + 注入点
        ② Attack Surface — 能力探测三级推荐
        ③ Hand-off to ARM — 传递给下阶段的决策字段
    """
    if not ctx.parsed_request:
        return
    fp = ctx.parsed_request.target_fingerprint
    # 断点修复: 统一 model 显示优先级与 recon_report.py 一致
    # 优先使用 model_family (探针检测的族标签如 "claude")
    # 回退到 burp_model_name (Burp 响应中提取的具体型号如 "gpt-4o")
    model = fp.get("model_family", "") or fp.get("burp_model_name", "") or "Unknown"
    caps = fp.get("capabilities", "") or "none"

    # ① Target Entry Point
    # 生产级修复: 对非 Burp 路径 (API 直连/浏览器), {PROMPT} 占位符语义不适用
    # API 模式通过原生参数传递 prompt, 不需要 HTTP body 占位符
    _is_api_mode = fp.get("target_type", "") in ("chat", "responses", "litellm", "browser")
    scheme = "https" if ctx.parsed_request.use_tls else "http"
    _endpoint_display = f"{scheme}://{ctx.parsed_request.host}{ctx.parsed_request.path}" if ctx.parsed_request.host else fp.get("endpoint", "N/A")
    _prompt_display = (
        "N/A (API mode)" if _is_api_mode
        else ("Injected" if ctx.parsed_request.has_prompt_placeholder else "Missing")
    )
    print()
    print_card(
        "RECON — Target Entry Point",
        [
            ("Endpoint", _endpoint_display),
            ("Model", model),
            ("Auth", fp.get("auth_type", "Unknown")),
            ("Language", fp.get("language", "auto") or "auto"),
            ("Capabilities", caps),
            ("{PROMPT}", _prompt_display),
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
                cap_items.append(f"    → {_C_GREEN}{item}{_C_RESET}")
                if strategy:
                    cap_items.append(f"      {_C_DIM}Strategy: {strategy['strategy']}{_C_RESET}")
                    cap_items.append(f"      {_C_DIM}Seed: {strategy['seed']} | {strategy['arxiv']} | OWASP {strategy['owasp']}{_C_RESET}")
        if probe_recs:
            cap_items.append(f"  {_C_YELLOW}PROBE (MEDIUM) — 需进一步确认:{_C_RESET}")
            for item in probe_recs:
                strategy = _CAPABILITY_STRATEGY.get(item)
                cap_items.append(f"    → {_C_YELLOW}{item}{_C_RESET}")
                if strategy:
                    cap_items.append(f"      {_C_DIM}If confirmed: {strategy['strategy']}{_C_RESET}")
        if possible:
            cap_items.append(f"  {_C_DIM}POSSIBLE (LOW) — 信号弱, 通用种子覆盖:{_C_RESET}")
            for item in possible:
                cap_items.append(f"    → {_C_DIM}{item}{_C_RESET}")
        print()
        print_section("Attack Surface (from capability probe)", cap_items, color=_C_YELLOW)

    # ③ Hand-off to ARM
    model_family = fp.get("model_family", "")
    if not model_family and fp.get("burp_model_name"):
        model_family = fp.get("burp_model_name", "")
    print()
    print_card(
        "Hand-off to ARM",
        [
            ("language", f"{fp.get('language', 'auto') or 'auto'}"),
            ("capabilities", caps),
            ("model_family", model_family or "Unknown"),
            ("auth_type", fp.get("auth_type", "Unknown")),
            ("api_category", fp.get("api_category", "chat")),
            ("session_type", fp.get("session_type", fp.get("auth_type", "Unknown"))),
            ("probe_count", f"{fp.get('probe_count', 'N/A')}"),
            ("probe_duration", f"{fp.get('probe_duration_seconds', 'N/A')}s"),
        ],
        color=_C_MAGENTA,
    )


# ════════════════════════════════════════════════════════════════════
# ARM 阶段卡片
# ════════════════════════════════════════════════════════════════════

def _get_seed_names(ctx: "PipelineContext") -> list[str]:
    """提取种子名称列表 (前 8 个)."""
    names = []
    for seed in ctx.seeds[:8]:
        name = ""
        # AttackSeedGroup → seeds[0].objective.value 或 .name
        obj = getattr(seed, "objective", None) if hasattr(seed, "objective") else None
        if obj:
            name = getattr(obj, "value", "") or getattr(obj, "name", "") or ""
        if not name and hasattr(seed, "name"):
            name = getattr(seed, "name", "")
        if not name:
            name = str(seed)[:50]
        names.append(name[:50])
    return names


def _get_converter_chain_names(converters: list[Any]) -> str:
    """获取 converter 链名称."""
    if not converters:
        return "(raw)"
    return " → ".join(
        type(c).__name__ if hasattr(c, "__class__") else str(c)
        for c in converters
    )


def print_arm_card(ctx: "PipelineContext") -> None:
    """打印武器化阶段摘要卡片 (种子/技术/Converter 一览)."""
    total_converters = sum(len(v) for v in ctx.converter_map.values())

    # 汇总卡片
    print()
    print_card(
        "ARM — Weapon Loadout",
        [
            ("Seeds", str(len(ctx.seeds))),
            ("Techniques", ", ".join(ctx.techniques) if ctx.techniques else "(none)"),
            ("Converter Chains", str(total_converters)),
        ],
        color=_C_BLUE,
    )

    # 种子清单卡片 (攻击者关心用了哪些 payload)
    seed_names = _get_seed_names(ctx)
    if seed_names:
        remaining = len(ctx.seeds) - len(seed_names)
        items = [f"  [{i + 1}] {name}" for i, name in enumerate(seed_names)]
        if remaining > 0:
            items.append(f"  ... +{remaining} more")
        print()
        print_section("Seeds (Top 8 by ASR)", items, color=_C_CYAN)

    # Converter 链卡片 (攻击者关心变换路径)
    if ctx.converter_map:
        chain_items = []
        for tech, converters in ctx.converter_map.items():
            chain = _get_converter_chain_names(converters)
            chain_items.append(f"  {_C_DIM}{tech}:{_C_RESET} {chain}")
        print()
        print_section("Converter Chains", chain_items, color=_C_MAGENTA)

    # 角色分离卡片
    obj_name = type(ctx.objective_target).__name__ if ctx.objective_target else "—"
    adv_name = type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "—"
    sco_name = type(ctx.scoring_target).__name__ if ctx.scoring_target else "—"
    print()
    print_card(
        "Role Separation (3-actor)",
        [
            ("Objective", obj_name),
            ("Adversarial", adv_name),
            ("Scoring", sco_name),
        ],
        color=_C_MAGENTA,
    )


# ════════════════════════════════════════════════════════════════════
# STRIKE 阶段卡片 + PyRIT 原生 Output 过程性展示
# ════════════════════════════════════════════════════════════════════

async def print_strike_results_native(ctx: "PipelineContext", *, max_per_tech: int = 3) -> None:
    """STRIKE 阶段过程性输出: 使用 PyRIT 原生 output_attack_async 展示每个攻击结果。

    R2 PyRIT 原生优先: 调用 pyrit.output 官方模块渲染 AttackResult,
    攻击者直接看到完整的对话历史、评分、converter 链。

    每个技术最多展示 max_per_tech 个结果 (避免刷屏),
    成功结果优先展示 (攻击者最关心)。

    Args:
        ctx: 流水线上下文 (包含 attack_results).
        max_per_tech: 每个技术最多展示的结果数.
    """
    total_results = sum(len(r) for r in ctx.attack_results.values())
    if total_results == 0:
        print(f"\n  {_C_RED}✗ 无攻击结果 — 检查目标是否可用{_C_RESET}")
        return

    print()
    print_card(
        "STRIKE — Native Output (per-attack results)",
        [
            ("Techniques", str(len(ctx.attack_results))),
            ("Total Results", str(total_results)),
            ("Display Mode", f"PyRIT native output_attack_async (max {max_per_tech}/tech)"),
        ],
        color=_C_YELLOW,
    )

    for tech_name, results in sorted(ctx.attack_results.items()):
        if not results:
            continue

        # 成功结果优先, 然后失败结果
        success_results = [r for r in results if _is_success(r)]
        fail_results = [r for r in results if not _is_success(r)]
        display_results = success_results[:max_per_tech]
        remaining_slots = max_per_tech - len(display_results)
        if remaining_slots > 0:
            display_results.extend(fail_results[:remaining_slots])

        if not display_results:
            continue

        # 技术标题行
        tech_success = len(success_results)
        tech_total = len(results)
        tech_asr = (tech_success / tech_total * 100) if tech_total > 0 else 0
        print(f"\n  {_C_BOLD}► {tech_name}{_C_RESET} "
              f"({tech_success}/{tech_total} = {_format_asr(tech_asr)})")

        # R2 原生优先: 调用 PyRIT output_attack_async 输出每个结果
        for i, result in enumerate(display_results):
            outcome_label = _get_outcome_label(result)
            print(f"\n  {_C_DIM}── Result {i + 1}/{len(display_results)} "
                  f"[{outcome_label}] ──{_C_RESET}")

            # R2 核心: 使用 PyRIT 原生 output 模块渲染
            ok = await print_native_attack_result(result)
            if not ok:
                # Fallback: 原生 output 失败时显示最小摘要
                _print_result_fallback(result)


def _print_result_fallback(result: Any) -> None:
    """原生 output 失败时的最小摘要 (fallback, 非 R2 首选路径)."""
    objective = getattr(result, "objective", "") or ""
    outcome = _get_outcome_label(result)
    print(f"    Objective: {objective[:100]}")
    print(f"    Outcome: {outcome}")


def print_strike_card(ctx: "PipelineContext") -> None:
    """打印攻击执行结果摘要卡片 (进度/统计).

    注意: 成功 payload 的详细展示由 print_strike_results_native 完成
    (使用 PyRIT 原生 output_attack_async), 此函数仅输出统计摘要卡片。
    """
    total = sum(len(results) for results in ctx.attack_results.values())
    success_count = sum(
        1 for results in ctx.attack_results.values()
        for r in results if _is_success(r)
    )

    print()
    print_card(
        "STRIKE — Execution Summary",
        [
            ("Techniques", str(len(ctx.attack_results))),
            ("Total Attacks", str(total)),
            ("Successful", f"{_C_GREEN}{success_count}{_C_RESET}" if success_count else "0"),
            ("Failed", str(total - success_count)),
            ("Native Output", "see per-attack results above (pyrit.output)"),
        ],
        color=_C_YELLOW,
    )

    if total == 0:
        print(f"\n  {_C_RED}✗ 无攻击结果 — 检查目标是否可用{_C_RESET}")
        return

    # 按技术统计卡片
    tech_items = []
    for tech, results in sorted(ctx.attack_results.items()):
        tech_success = sum(1 for r in results if _is_success(r))
        tech_total = len(results)
        tech_asr = (tech_success / tech_total * 100) if tech_total > 0 else 0
        color = _asr_color(tech_asr)
        tech_items.append(
            f"  {tech:<30} {tech_success}/{tech_total}  {color}{tech_asr:.0f}%{_C_RESET}"
        )
    print()
    print_section("Per-Technique Breakdown", tech_items, color=_C_YELLOW)


# ════════════════════════════════════════════════════════════════════
# ESCALATE 阶段卡片
# ════════════════════════════════════════════════════════════════════

def print_escalate_card(ctx: "PipelineContext") -> None:
    """打印升级链阶段结果卡片."""
    total = sum(len(results) for results in ctx.attack_results.values())

    escalation_techs = [
        k for k in ctx.attack_results
        if any(
            x in k.lower()
            for x in [
                "crescendo", "tap", "pair", "gcg", "best_of_n",
                "skeleton", "native", "rogue", "mcp", "embedding",
                "many_shot", "cair", "encoded",
            ]
        )
    ]

    rows = [
        ("Total Results", str(total)),
        ("Escalation Techs", str(len(escalation_techs))),
    ]

    # 编排决策 (升级链决策路径)
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

    # 升级技术详情
    if escalation_techs:
        items = []
        for tech in sorted(escalation_techs):
            results = ctx.attack_results[tech]
            tech_success = sum(1 for r in results if _is_success(r))
            items.append(
                f"  {_C_MAGENTA}{tech}{_C_RESET}: "
                f"{tech_success}/{len(results)} successful"
            )
        print()
        print_section("Escalation Techniques", items, color=_C_MAGENTA)
    else:
        print(f"\n  {_C_DIM}(未检测到升级技术 — 可能 ASR 已达标或升级被禁用){_C_RESET}")

    # 编排日志 (精简, 仅关键决策)
    if escalate_logs:
        items = []
        for entry in escalate_logs:
            decision = entry.get("decision", "")
            reasoning = entry.get("reasoning", "")[:50]
            items.append(f"  [{entry['phase']}] {decision}: {reasoning}")
        print()
        print_section("Orchestration Log", items, color=_C_DIM)


# ════════════════════════════════════════════════════════════════════
# ASSESS 阶段卡片
# ════════════════════════════════════════════════════════════════════

def print_assess_card(ctx: "PipelineContext") -> None:
    """打印评分阶段结果卡片 (ASR/Wilson CI/双Judge)."""
    rows = [
        ("Overall ASR", _format_asr(ctx.overall_asr)),
    ]

    if ctx.wilson_ci and ctx.wilson_ci != (0.0, 0.0):
        rows.append((
            "Wilson 95% CI",
            f"[{ctx.wilson_ci[0]:.1f}%, {ctx.wilson_ci[1]:.1f}%]",
        ))

    # 总攻击数
    total_attacks = sum(len(results) for results in ctx.attack_results.values())
    total_success = sum(
        1 for results in ctx.attack_results.values()
        for r in results if _is_success(r)
    )
    rows.append(("Total Scored", str(total_attacks)))
    rows.append(("Successful", f"{_C_GREEN}{total_success}{_C_RESET}"))

    print()
    print_card("ASSESS — Scoring Results", rows, color=_C_GREEN)

    # 按技术 ASR 排名
    if ctx.asr_per_technique:
        items = []
        sorted_asr = sorted(ctx.asr_per_technique.items(), key=lambda x: -x[1])
        for tech, asr in sorted_asr:
            color = _asr_color(asr)
            bar_len = int(asr / 5)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            items.append(f"  {tech:<28} {color}{bar} {asr:>5.1f}%{_C_RESET}")
        print()
        print_section("Per-Technique ASR Ranking", items, color=_C_GREEN)

    # 双 Judge 统计
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
            color=_C_BLUE,
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
    """打印报告阶段卡片 (证据/报告路径/最终ASR/原生输出目录).

    Args:
        native_output_dir: PyRIT 原生 output 目录路径 (R2 原生优先).
    """
    rows = [
        ("Evidence Collected", str(evidence_count)),
        ("Total Attacks", str(total_attacks)),
        ("Successful", f"{_C_GREEN}{successful_attacks}{_C_RESET}"),
        ("Overall ASR", _format_asr(overall_asr)),
    ]
    if wilson_ci and wilson_ci != (0.0, 0.0):
        rows.append(("Wilson 95% CI", f"[{wilson_ci[0]:.1f}%, {wilson_ci[1]:.1f}%]"))
    rows.append(("Report", report_path))
    if native_output_dir:
        rows.append(("Native Output", native_output_dir))

    print()
    print_card("REPORT — Final Output", rows, color=_C_CYAN)


# ════════════════════════════════════════════════════════════════════
# 兼容旧接口
# ════════════════════════════════════════════════════════════════════

# 旧函数名兼容 (已弃用, 新代码请用 print_status)
print_status_card = print_status


# ════════════════════════════════════════════════════════════════════
# 分阶段报告 (--stage 模式, 调用对应卡片函数)
# ════════════════════════════════════════════════════════════════════

async def print_strike_report_async(ctx: "PipelineContext") -> None:
    """输出单轮攻击阶段 (--stage strike) 的完整结果。

    R2 PyRIT 原生优先:
        1. 先调用 PyRIT 原生 output_attack_async 展示每个攻击结果 (过程性)
        2. 再输出统计摘要卡片 (汇总)
    """
    await print_strike_results_native(ctx)
    print_strike_card(ctx)


def print_strike_report(ctx: "PipelineContext") -> None:
    """同步包装: 输出单轮攻击阶段结果 (仅摘要卡片).

    注意: 原生 output 展示请用 print_strike_report_async。
    """
    print_strike_card(ctx)


def print_arm_report(ctx: "PipelineContext") -> None:
    """输出武器化阶段 (--stage arm) 的结果摘要."""
    print_arm_card(ctx)


def print_escalate_report(ctx: "PipelineContext") -> None:
    """输出升级链阶段 (--stage escalate) 的结果摘要."""
    print_escalate_card(ctx)


def print_assess_report(ctx: "PipelineContext") -> None:
    """输出评分阶段 (--stage assess) 的结果摘要."""
    print_assess_card(ctx)


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
    """打印多 endpoint 联合 ASR 汇总卡片。

    学术依据:
        - Greshake et al. (arXiv:2302.12173) — 逐个深度攻击策略
        - Chao et al. (arXiv:2310.08419) — 联合 ASR 模型

    Args:
        joint_asr: 联合 ASR 百分比 (1 - ∏(1 - ASRᵢ))。
        total_endpoints: endpoint 总数。
        total_attacks: 所有 endpoint 总攻击数。
        total_successes: 所有 endpoint 总成功数。
        endpoint_summaries: 各 endpoint 摘要列表。
        report_path: 联合报告 JSON 路径。
    """
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
    # 各 endpoint 逐行展示
    for ep in endpoint_summaries:
        name = ep.get("burp_name", "unknown")
        asr = ep.get("overall_asr", 0.0)
        attacks = ep.get("total_attacks", 0)
        successes = ep.get("successful_attacks", 0)
        caps = ep.get("capabilities", "")
        # ASR 着色: >50 绿, >0 黄, 0 灰
        asr_str = _format_asr(asr)
        cap_str = f" [{caps}]" if caps and caps != "none" else ""
        print(_card_line(
            f"  {name}: {asr_str} ({successes}/{attacks}){cap_str}",
            _C_MAGENTA,
        ))

    _print_card_sep()
    if report_path:
        print(_card_line(f"Report: {report_path}", _C_MAGENTA))
    _print_card_bottom(_C_MAGENTA)

    # 联合 ASR 公式说明
    print(f"{_C_DIM}  Joint ASR = 1 - ∏(1 - ASRᵢ) "
          f"(arXiv:2310.08419){_C_RESET}")
