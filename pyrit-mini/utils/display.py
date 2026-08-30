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
    """ASR 值对应颜色 — 攻击者视角 (高 ASR = 红色危险).

    红队最佳实践: 攻击者视角中高 ASR 是 "好结果" (攻击成功),
    但从安全角度看是 "危险" (目标被攻破), 统一用红色突出。
    低 ASR = 绿色 (目标防御有效), 中间 = 黄色/青色。
    """
    if asr >= 70:
        return _C_RED
    if asr >= 40:
        return _C_YELLOW
    if asr >= 15:
        return _C_CYAN
    return _C_GREEN


def _format_asr(asr: float) -> str:
    """格式化 ASR 值 (带颜色, 攻击者视角)."""
    c = _asr_color(asr)
    return f"{c}{asr:.1f}%{_C_RESET}"


def _asr_bar(asr: float, width: int = 20) -> str:
    """ASR 可视化进度条 (攻击者视角).

    格式: ████████░░░░░░░░░░░░ 40.0%
    颜色随 ASR 值变化 (高=红, 低=绿)。
    """
    c = _asr_color(asr)
    filled = int(asr / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"{c}{bar} {asr:>5.1f}%{_C_RESET}"


# ════════════════════════════════════════════════════════════════════
# PyRIT 原生 Output (R2: PyRIT native first)
# ════════════════════════════════════════════════════════════════════

async def print_native_attack_result(
    result: Any,
    *,
    include_auxiliary: bool = True,
    include_adversarial: bool = True,
    include_pruned: bool = True,
) -> bool:
    """使用 PyRIT 原生 output_attack_async 输出单个 AttackResult 到终端。

    R2 PyRIT 原生优先: 使用 pyrit.output 官方模块渲染攻击结果,
    而非手动提取 prompt/response 文本。

    PyRIT 官方 output 架构 (arXiv:2407.01232):
        output_attack_async(result, format='pretty', sink=StdoutSink())
        → PrettyAttackResultMemoryPrinter 渲染
        → Header: ✅ ATTACK RESULT: SUCCESS / ❌ FAILURE / ❓ UNDETERMINED
        → Attack Summary: 📋 Basic Information / ⚡ Execution Metrics / 🎯 Outcome / Final Score
        → Conversation History with Objective Target: 🔹 Turn N - USER / 🔸 ASSISTANT
        → Adversarial Conversation (Red Team LLM): 多轮攻击推理
        → Pruned Conversations: 分支对话摘要
        → Additional Metadata: 攻击特定元数据
        → Footer: Report generated at: timestamp UTC

    Args:
        result: PyRIT AttackResult 对象.
        include_auxiliary: 是否包含辅助评分 (对齐原生 include_auxiliary_scores).
        include_adversarial: 是否包含对抗对话 (对齐原生 include_adversarial_conversation).
        include_pruned: 是否包含裁剪对话 (对齐原生 include_pruned_conversations).

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
            include_adversarial_conversation=include_adversarial,
            include_pruned_conversations=include_pruned,
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
# PyRIT 原生 ScenarioResult 终端输出 (R2: PyRIT native first)
# ════════════════════════════════════════════════════════════════════

async def print_native_scenario_result(scenario_result: Any) -> bool:
    """使用 PyRIT 原生 output_scenario_async 输出 ScenarioResult 到终端。

    R2 PyRIT 原生优先: 使用 pyrit.output 官方模块渲染 ScenarioResult,
    输出完整的 📊 SCENARIO RESULTS 格式:
        Header → Scenario Info → Target Info → Scorer Info
        → Overall Statistics → Per-Group Breakdown → Footer

    PyRIT 官方 output 架构:
        output_scenario_async(result, format='pretty', sink=StdoutSink())
        → PrettyScenarioResultMemoryPrinter 渲染

    Args:
        scenario_result: PyRIT ScenarioResult 对象.

    Returns:
        True 如果成功输出.
    """
    if scenario_result is None:
        logger.debug("No ScenarioResult to display (scenario_result is None)")
        return False

    try:
        from pyrit.output import OutputFormat, StdoutSink, output_scenario_async

        await output_scenario_async(
            scenario_result,
            format=OutputFormat.PRETTY,
            sink=StdoutSink(),
            sort_groups_by_success_rate=True,
        )
        return True
    except Exception as e:
        logger.debug("Native scenario output failed: %s — falling back to summary", e)
        return False


async def print_technique_trail(scenario_result: Any) -> None:
    """输出 per-objective per-attempt 技术链路详情。

    PyRIT 文档: "Inspecting which techniques were tried"
    遍历 ScenarioResult.get_display_groups() 中每个 group 的 AttackResult,
    对每个 objective 展示其 per-attempt 技术链路:
        ContextComplianceAttack(failure) → RolePlayAttack(success)

    然后输出 per-group 和 overall 的技术 wins/picks 统计表。

    数据源:
        - scenario_result.get_display_groups() → {group_name: [AttackResult, ...]}
        - 每组中按 objective 分组, 每个 objective 的结果按顺序排列
        - 每个 AttackResult.get_attack_strategy_identifier() → ComponentIdentifier
        - ComponentIdentifier.class_name → 技术名称 (如 "RolePlayAttack")

    Args:
        scenario_result: PyRIT ScenarioResult 对象.
    """
    if scenario_result is None:
        return

    try:
        from pyrit.models import AttackOutcome
    except ImportError:
        return

    display_groups = scenario_result.get_display_groups()
    if not display_groups:
        return

    # ── Per-Group + Per-Objective 技术链路 ──
    overall_tech_stats: dict[str, dict[str, int]] = {}  # {tech: {"wins": N, "picks": N}}

    for group_name, group_results in display_groups.items():
        if not group_results:
            continue

        print(f"\n{_C_BOLD}=== Group: {group_name} ==={_C_RESET}")

        # 按 objective 分组, 保持出现顺序
        objectives_order: list[str] = []
        objectives_map: dict[str, list[Any]] = {}
        for r in group_results:
            obj = getattr(r, "objective", "") or ""
            if obj not in objectives_map:
                objectives_map[obj] = []
                objectives_order.append(obj)
            objectives_map[obj].append(r)

        group_tech_stats: dict[str, dict[str, int]] = {}

        for objective in objectives_order:
            attempts = objectives_map[objective]
            # 判断整体 outcome (最后一个 attempt 的 outcome)
            final_outcome = getattr(attempts[-1], "outcome", None) if attempts else None
            is_success = final_outcome == AttackOutcome.SUCCESS if final_outcome else False

            outcome_str = (
                f"{_C_GREEN}success{_C_RESET}" if is_success
                else f"{_C_RED}failure{_C_RESET}"
            )
            # 截断 objective 显示
            obj_display = objective[:100] if len(objective) > 100 else objective
            print(f"  [{outcome_str}] '{obj_display}': ", end="")

            # 构建 per-attempt 技术链路
            trail_parts: list[str] = []
            for attempt in attempts:
                tech_name = _get_technique_class_name(attempt)
                attempt_outcome = getattr(attempt, "outcome", None)
                attempt_ok = attempt_outcome == AttackOutcome.SUCCESS if attempt_outcome else False
                outcome_tag = "success" if attempt_ok else "failure"
                trail_parts.append(f"{tech_name}({outcome_tag})")

                # 统计 wins/picks
                if tech_name:
                    if tech_name not in group_tech_stats:
                        group_tech_stats[tech_name] = {"wins": 0, "picks": 0}
                    if tech_name not in overall_tech_stats:
                        overall_tech_stats[tech_name] = {"wins": 0, "picks": 0}
                    group_tech_stats[tech_name]["picks"] += 1
                    overall_tech_stats[tech_name]["picks"] += 1
                    if attempt_ok:
                        group_tech_stats[tech_name]["wins"] += 1
                        overall_tech_stats[tech_name]["wins"] += 1

            if trail_parts:
                print(" → ".join(trail_parts))
            else:
                print("(no technique identifiers found)")

        # Per-Group 技术统计表
        if group_tech_stats:
            _print_tech_stats_table(group_tech_stats)

    # ── Overall 技术统计表 ──
    if overall_tech_stats:
        print(f"\n{_C_BOLD}=== Overall ==={_C_RESET}")
        _print_tech_stats_table(overall_tech_stats)


def _get_technique_class_name(result: Any) -> str:
    """从 AttackResult 提取技术类名。

    通过 result.get_attack_strategy_identifier() 获取 ComponentIdentifier,
    返回其 class_name (如 "RolePlayAttack")。

    Fallback: 如果 identifier 不存在, 尝试从 attack_technique / technique 属性获取。

    Args:
        result: PyRIT AttackResult 对象.

    Returns:
        技术类名字符串, 如果无法提取则返回空字符串.
    """
    try:
        identifier = result.get_attack_strategy_identifier()
        if identifier is not None:
            class_name = getattr(identifier, "class_name", "")
            if class_name:
                return class_name
    except Exception:
        pass

    # Fallback: 从属性获取
    tech = getattr(result, "attack_technique", None) or getattr(result, "technique", None)
    if tech:
        if isinstance(tech, str):
            return tech
        return type(tech).__name__

    return ""


def _print_tech_stats_table(tech_stats: dict[str, dict[str, int]]) -> None:
    """打印技术 wins/picks 统计表。

    格式:
        Technique                                wins / picks   rate
        ContextComplianceAttack                      1 / 4      25%
        RolePlayAttack                               2 / 4      50%

    Args:
        tech_stats: {tech_name: {"wins": int, "picks": int}} 字典.
    """
    if not tech_stats:
        return

    # 表头
    print(f"\n  {_C_BOLD}{'Technique':<40} {'wins / picks':>14}   {'rate':>5}{_C_RESET}")

    # 按 win rate 降序排 (攻击者最关心哪些技术最有效)
    sorted_techs = sorted(
        tech_stats.keys(),
        key=lambda t: (-(tech_stats[t]["wins"] / max(1, tech_stats[t]["picks"]))),
    )
    for tech_name in sorted_techs:
        stats = tech_stats[tech_name]
        wins = stats["wins"]
        picks = stats["picks"]
        rate = int((wins / picks) * 100) if picks > 0 else 0
        color = _asr_color(float(rate))
        print(f"  {color}{tech_name:<40} {wins:>4} / {picks:<5}  {rate:>4}%{_C_RESET}")


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
    # 生产级修复: 对非 Burp 路径 (API 直连/浏览器), {PROMPT} 占位符语义不适用
    # API 模式通过原生参数传递 prompt, 不需要 HTTP body 占位符
    _is_api_mode = fp.get("target_type", "") in ("chat", "responses", "litellm", "browser")
    scheme = "https" if ctx.parsed_request.use_tls else "http"
    _endpoint_display = f"{scheme}://{ctx.parsed_request.host}{ctx.parsed_request.path}" if ctx.parsed_request.host else fp.get("endpoint", "N/A")
    _prompt_display = (
        "N/A (API mode)" if _is_api_mode
        else ("Injected" if ctx.parsed_request.has_prompt_placeholder else "Missing")
    )
    # Hand-off 独有字段 (不与 ① 已有字段重复)
    _probe_count = fp.get("probe_count", "N/A")
    _probe_dur = fp.get("probe_duration_seconds", "N/A")
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
            ("API Category", fp.get("api_category", "chat")),
            ("Session Type", fp.get("session_type", fp.get("auth_type", "Unknown"))),
            ("Probe", f"{_probe_count} probes / {_probe_dur}s"),
        ],
        color=_C_CYAN,
    )

    # ② Attack Surface (能力 → 攻击策略映射)
    # 优化: PROBE 条目内联 strategy, 每个能力一行
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
    """获取 converter 链名称.

    L5 v39: 显示为独立路径编号而非 → 串联, 消除串联误解.
    arXiv:2307.15043 — 每个 converter 是 SequentialAttack 的独立路径,
    非串联堆叠 (串联 >2 层 ASR 12%→4%).
    """
    if not converters:
        return "(raw, no converters)"
    # 单个 converter: 直接显示名称
    if len(converters) == 1:
        c = converters[0]
        return type(c).__name__ if hasattr(c, "__class__") else str(c)
    # 多个 converter: 显示为独立路径编号 [1] X | [2] Y | [3] Z
    parts = []
    for i, c in enumerate(converters):
        name = type(c).__name__ if hasattr(c, "__class__") else str(c)
        parts.append(f"[{i + 1}] {name}")
    return " | ".join(parts)


def print_arm_card(ctx: "PipelineContext") -> None:
    """打印武器化阶段摘要卡片 (种子/技术/Converter 一览)."""
    total_converters = sum(len(v) for v in ctx.converter_map.values())

    # L5 v39: 获取目标类型用于显示
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

    # 汇总卡片
    print()
    print_card(
        "ARM — Weapon Loadout",
        [
            ("Seeds", str(len(ctx.seeds))),
            ("Techniques", ", ".join(ctx.techniques) if ctx.techniques else "(none)"),
            ("Converter Paths", str(total_converters)),
            ("Target Type", _target_type_str),
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

    # L5 v40: 种子 category/suitable_for 覆盖标注
    # 学术依据: Greshake et al. (arXiv:2302.12173) —
    #   显示 converter 路径时标注种子类型覆盖情况
    seed_categories: list[str] = []
    seed_suitable_for: list[str] = []
    for group in ctx.seeds[:20]:
        for seed in getattr(group, "seeds", []):
            meta = getattr(seed, "metadata", {}) or {}
            cat = str(meta.get("category", "")).strip()
            sf = str(meta.get("suitable_for", "")).strip()
            if cat and cat not in seed_categories:
                seed_categories.append(cat)
            if sf and sf not in seed_suitable_for:
                seed_suitable_for.append(sf)

    # 种子类型覆盖标注
    coverage_label = ""
    if seed_categories:
        if len(seed_categories) <= 3:
            coverage_label = f" {_C_DIM}[seeds: {', '.join(seed_categories)}]{_C_RESET}"
        else:
            coverage_label = f" {_C_DIM}[seeds: {len(seed_categories)} categories]{_C_RESET}"

    # Converter 路径卡片 (攻击者关心变换路径)
    # L5 v39: 显示独立路径编号, 标注技术类型 (baseline/context/escalation)
    # L5 v40: 标注种子 category 覆盖 (category-adaptive converter selection)
    if ctx.converter_map:
        chain_items = []
        for tech, converters in ctx.converter_map.items():
            chain = _get_converter_chain_names(converters)
            # 标注技术类型
            if tech in ("prompt_sending",):
                tech_label = f"{_C_DIM}(baseline){_C_RESET}"
            elif tech in ("many_shot", "skeleton_key", "role_play_movie_script",
                          "role_play_persuasion", "context_compliance", "flip"):
                tech_label = f"{_C_DIM}(context-semantic){_C_RESET}"
            else:
                tech_label = f"{_C_DIM}(escalation-full){_C_RESET}"
            chain_items.append(f"  {_C_DIM}{tech}{_C_RESET} {tech_label}: {chain}")
        print()
        print_section(f"Converter Paths (independent, FIRST_SUCCESS){coverage_label}", chain_items, color=_C_MAGENTA)
    else:
        print()
        print_section(
            "Converter Paths",
            [f"  {_C_DIM}(no converters — baseline mode){_C_RESET}"],
            color=_C_MAGENTA,
        )

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

async def print_attack_results_native(
    attack_results: dict[str, list[Any]],
    *,
    phase_label: str = "STRIKE",
    max_per_tech: int = 3,
) -> None:
    """通用过程性输出: 使用 PyRIT 原生 output_attack_async 展示攻击结果。

    R2 §2.1 原生优先: 先调用 pyrit.output 官方模块渲染 AttackResult
    (Header → Summary → Conversation History → Metadata → Footer),
    再输出增强层卡片 (技术 ASR 统计)。

    PyRIT 原生 output 格式标准 (arXiv:2407.01232):
        1. Header — ✅ ATTACK RESULT: SUCCESS / ❌ FAILURE / ❓ UNDETERMINED
        2. Attack Summary — 📋 Basic Information / ⚡ Execution Metrics / 🎯 Outcome / Final Score
        3. Conversation History with Objective Target — 🔹 Turn N - USER / 🔸 ASSISTANT
        4. Adversarial Conversation (Red Team LLM) — 多轮攻击推理 (如启用)
        5. Pruned Conversations — 分支对话摘要 (如有)
        6. Additional Metadata — 攻击特定元数据
        7. Footer — Report generated at: timestamp UTC

    每个技术最多展示 max_per_tech 个结果 (避免刷屏),
    成功结果优先展示 (攻击者最关心)。

    Args:
        attack_results: {technique_name: [AttackResult, ...]} 字典.
        phase_label: 阶段标签 (STRIKE / ESCALATE), 用于增强层卡片标题.
        max_per_tech: 每个技术最多展示的结果数.
    """
    total_results = sum(len(r) for r in attack_results.values())
    if total_results == 0:
        print(f"\n  {_C_RED}✗ 无攻击结果 — 检查目标是否可用{_C_RESET}")
        return

    # 按 ASR 降序排 (攻击者最关心哪些技术最有效)
    sorted_techs = sorted(
        attack_results.items(),
        key=lambda kv: -(sum(1 for r in kv[1] if _is_success(r)) / max(1, len(kv[1]))),
    )

    # ── R2 §2.1: 原生 output 先输出 — 不插入自定义卡片/标题行 ──
    # PyRIT 原生 output_attack_async 渲染完整的 ✅ ATTACK RESULT 格式,
    # 不在原生 output 之前/之间插入任何自定义格式, 保持原生格式完整性。
    for tech_name, results in sorted_techs:
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

        # R2 §2.1 核心: 使用 PyRIT 原生 output 模块渲染每个结果
        # 原生 output 包含 Header → Summary → Conversation History → Footer
        # 不在原生 output 之前插入技术标题行或 Result N/N 分隔行
        for result in display_results:
            ok = await print_native_attack_result(result)
            if not ok:
                # Fallback: 原生 output 失败时显示最小摘要
                _print_result_fallback(result)

    # ── R2 §2.1: 增强层卡片在原生 output 之后输出 ──
    # 技术级 ASR 统计卡片 (原生 output 不提供此信息, 属于补充增强)
    print()
    print_card(
        f"{phase_label} — Per-Technique Summary (enhancement)",
        [
            ("Techniques", str(len(attack_results))),
            ("Total Results", str(total_results)),
            ("Native Output", f"output_attack_async (max {max_per_tech}/tech) shown above"),
        ],
        color=_C_YELLOW,
    )

    for tech_name, results in sorted_techs:
        if not results:
            continue
        tech_success = sum(1 for r in results if _is_success(r))
        tech_total = len(results)
        tech_asr = (tech_success / tech_total * 100) if tech_total > 0 else 0
        color = _asr_color(tech_asr)
        print(f"  {color}{tech_name:<28}{_C_RESET} "
              f"{tech_success:>3}/{tech_total:<3} {_asr_bar(tech_asr, width=20)}")


async def print_strike_results_native(ctx: "PipelineContext", *, max_per_tech: int = 3) -> None:
    """STRIKE 阶段过程性输出的向后兼容包装。

    等价于 print_attack_results_native(ctx.attack_results, phase_label="STRIKE", ...)
    """
    await print_attack_results_native(ctx.attack_results, phase_label="STRIKE", max_per_tech=max_per_tech)


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

    overall_asr = (success_count / total * 100) if total > 0 else 0

    print()
    print_card(
        "STRIKE — Execution Summary",
        [
            ("Techniques", str(len(ctx.attack_results))),
            ("Total Attacks", str(total)),
            ("Successful", f"{_C_GREEN if success_count == 0 else _asr_color(overall_asr)}{success_count}{_C_RESET}"),
            ("Failed", str(total - success_count)),
            ("Overall ASR", _format_asr(overall_asr)),
            ("Native Output", "see per-attack results above (pyrit.output)"),
        ],
        color=_C_YELLOW,
    )

    if total == 0:
        print(f"\n  {_C_RED}✗ 无攻击结果 — 检查目标是否可用{_C_RESET}")
        return

    # 按技术 ASR 降序排 (攻击者最关心哪些技术最有效)
    tech_items = []
    sorted_results = sorted(
        ctx.attack_results.items(),
        key=lambda kv: -(sum(1 for r in kv[1] if _is_success(r)) / max(1, len(kv[1]))),
    )
    for tech, results in sorted_results:
        tech_success = sum(1 for r in results if _is_success(r))
        tech_total = len(results)
        tech_asr = (tech_success / tech_total * 100) if tech_total > 0 else 0
        color = _asr_color(tech_asr)
        tech_items.append(
            f"  {color}{tech:<28}{_C_RESET} "
            f"{tech_success:>3}/{tech_total:<3} {_asr_bar(tech_asr, width=20)}"
        )
    print()
    print_section("Per-Technique ASR Breakdown", tech_items, color=_C_YELLOW)


# ════════════════════════════════════════════════════════════════════
# ESCALATE 阶段卡片 + PyRIT 原生 Output 过程性展示
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

    # 计算升级链 ASR
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

    # 升级技术详情 (按 ASR 降序)
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


async def print_escalate_report_async(ctx: "PipelineContext") -> None:
    """输出升级链阶段的完整结果 (R2 §2.1 原生优先)。

    R2 §2.1 优先级:
        1. 使用 PyRIT 原生 output_attack_async 展示升级链 AttackResult (过程性)
        2. 输出统计摘要卡片 (汇总, 增强层)
    """
    # ── 1. 筛选升级链技术产生的 AttackResult ──
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

    # ── 2. R2 §2.1 原生优先: PyRIT output_attack_async 展示升级链结果 ──
    if escalation_techs:
        escalate_results = {k: ctx.attack_results[k] for k in escalation_techs}
        await print_attack_results_native(
            escalate_results,
            phase_label="ESCALATE",
            max_per_tech=3,
        )

    # ── 3. 增强层: 统计摘要卡片 ──
    print_escalate_card(ctx)


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

    # 按技术 ASR 排名 (降序, 攻击者最关心)
    if ctx.asr_per_technique:
        items = []
        sorted_asr = sorted(ctx.asr_per_technique.items(), key=lambda x: -x[1])
        for tech, asr in sorted_asr:
            items.append(f"  {tech:<28} {_asr_bar(asr, width=20)}")
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
    if wilson_ci and (wilson_ci[0] != 0.0 or wilson_ci[1] != 0.0):
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

    R2 §2.1 终端展示优先级 (PyRIT 原生优先, 卡片增强在后):
        1. 如果存在 ScenarioResult (adaptive 模式), 先调用 PyRIT 原生
           output_scenario_async 输出 📊 SCENARIO RESULTS 汇总到终端
        2. 调用 PyRIT 原生 output_attack_async 展示每个攻击结果 (过程性)
        3. 输出 per-objective per-attempt 技术链路详情 (增强层, 原生 output 之后)
        4. 输出统计摘要卡片 (汇总, 增强层)
    """
    scenario_result = getattr(ctx, "scenario_result", None)

    # ── 1. R2 §2.1 原生优先: PyRIT 原生 ScenarioResult 终端输出 ──
    if scenario_result is not None:
        await print_native_scenario_result(scenario_result)

    # ── 2. R2 §2.1 原生优先: PyRIT 原生 AttackResult 过程性输出 ──
    await print_strike_results_native(ctx)

    # ── 3. 增强层: Per-objective per-attempt 技术链路 (原生 output 之后) ──
    if scenario_result is not None:
        await print_technique_trail(scenario_result)

    # ── 4. 增强层: 统计摘要卡片 ──
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
    """同步包装: 输出升级链阶段结果 (仅摘要卡片).

    注意: 原生 output 展示请用 print_escalate_report_async。
    """
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
