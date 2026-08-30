"""recon_report — 侦察结果精简格式化输出 (--stage recon 专用).

三张卡片输出 (PTES §2 + Lockheed Martin CKC Stage 1):
    ① Target Entry Point  — 入口点: Host/Path/Auth/注入点/Body 摘要 (Burp 零成本)
    ② Attack Surface      — 攻击面: 能力探测 + 三级推荐 (HIGH/MEDIUM/LOW)
    ③ Hand-off to ARM     — 传递给下阶段的决策字段

学术依据:
    - Greshake et al. (arXiv:2302.12173) §4 — 三层探测分层 (passive/active/deep)
    - Zheng et al. (arXiv:2306.05685) §4.3 — 置信度分级 (HIGH/MEDIUM/LOW)
    - PyRIT (arXiv:2407.01232) §3.3 — SequentialAttack 依赖能力指纹选择路径
    - PTES §2 — 情报收集: Raw Data → Analyzed → Attack Vectors
    - Heroux et al. (arXiv:2403.04206) — 认证状态探测

完整指纹 JSON 写入 output_dir/recon_fingerprint.json, 终端只展示决策必需信息.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from recon.burp_parser import ParsedBurpRequest

from utils.display import (
    _C_BOLD,
    _C_CYAN,
    _C_DIM,
    _C_GREEN,
    _C_MAGENTA,
    _C_RED,
    _C_RESET,
    _C_YELLOW,
    _card_line,
    _print_card_bottom,
    _print_card_sep,
    _print_card_top,
    print_section,
)

logger = logging.getLogger(__name__)


def _print_card_block(
    title: str,
    rows: list[tuple[str, str]],
    color: str,
) -> None:
    """打印卡片块 (带边框和颜色)."""
    print()
    _print_card_top(color)
    print(_card_line(title, color + _C_BOLD))
    _print_card_sep()
    for label, value in rows:
        print(_card_line(f"{label}: {value}", color))
    _print_card_bottom(color)


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
    "function_calling": {
        "arxiv": "arXiv:2307.00929",
        "strategy": "工具劫持: 注入恶意 function schema 劫持工具调用",
        "seed": "function_call_exploit",
        "owasp": "LLM06",
    },
    "memory": {
        "arxiv": "arXiv:2302.12173",
        "strategy": "记忆投毒: 通过 token smuggling 注入持久后门",
        "seed": "token_smuggling",
        "owasp": "LLM07",
    },
    "workflow": {
        "arxiv": "arXiv:2407.01232",
        "strategy": "工作流劫持: 链式注入跨越工作流步骤",
        "seed": "workflow_chain_attack",
        "owasp": "ASI04",
    },
    "multi_tenant": {
        "arxiv": "arXiv:2403.04206",
        "strategy": "租户越权: 跨租户数据泄露 + 认证绕过",
        "seed": "session_auth_attack",
        "owasp": "LLM02",
    },
    "a2a_protocol": {
        "arxiv": "arXiv:2407.16924",
        "strategy": "A2A 逃逸: 劫持 agent card 跨 agent 横向移动",
        "seed": "multi_agent_attack",
        "owasp": "ASI07",
    },
    "embedding_rag": {
        "arxiv": "arXiv:2310.06870",
        "strategy": "RAG 投毒: 注入知识库 + 嵌入反演泄露",
        "seed": "rag_attack",
        "owasp": "LLM06",
    },
    "session_auth": {
        "arxiv": "arXiv:2403.04206",
        "strategy": "会话劫持: Cookie/Bearer 重放 + 认证状态篡改",
        "seed": "session_auth_attack",
        "owasp": "LLM02",
    },
    "mcp": {
        "arxiv": "arXiv:2302.12173",
        "strategy": "MCP 注入: 劫持 MCP 工具/资源间接注入",
        "seed": "mcp_attack",
        "owasp": "ASI06",
    },
    "rag": {
        "arxiv": "arXiv:2310.06870",
        "strategy": "RAG 投毒: 知识库注入 + 检索篡改",
        "seed": "rag_attack",
        "owasp": "LLM06",
    },
}


def _level_color(level: str) -> str:
    """置信度级别 → 颜色."""
    if level == "high":
        return _C_GREEN
    if level == "medium":
        return _C_YELLOW
    return _C_DIM


# ════════════════════════════════════════════════════════════════════
# 主报告函数
# ════════════════════════════════════════════════════════════════════

def print_recon_report(
    parsed: "ParsedBurpRequest",
    output_dir: Path | None = None,
) -> None:
    """输出精简侦察结果报告 (三张卡片).

    学术依据:
        - Greshake et al. (arXiv:2302.12173) §4 — 攻击者关注可利用能力 + 置信度
        - PTES §2 — 攻击者关注: 入口点、认证、攻击面
        - CKC Stage 1 — 目标识别 + 弱点分析

    输出结构 (3 张卡片, 聚焦攻击决策信息):
        ① Target Entry Point — 入口点 + 认证 + 注入点 (Burp 零成本)
        ② Attack Surface — 能力探测三级推荐 (passive/active/deep)
        ③ Hand-off to ARM — 传递给下阶段的决策字段

    Args:
        parsed: 解析后的 Burp 请求 (含 target_fingerprint).
        output_dir: 输出目录 (用于写入 recon_fingerprint.json).
    """
    # P2-1: 报告头 — 版本号 + 时间戳 + 探测耗时
    # 学术依据: PTES §2 — 情报收集阶段需记录时间元数据
    _RECON_REPORT_VERSION = "2.0"
    report_time = time.strftime("%Y-%m-%d %H:%M:%S")

    fp = parsed.target_fingerprint

    probe_duration = fp.get("probe_duration_seconds", "N/A")

    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")
    print(f"{_C_BOLD}  PyRIT-Strike Recon Report v{_RECON_REPORT_VERSION}{_C_RESET}")
    print(f"{_C_DIM}  Generated: {report_time} | Probe Duration: {probe_duration}s{_C_RESET}")
    print(f"{_C_BOLD}{'═' * 60}{_C_RESET}")

    # ════════════════════════════════════════════════════════════════
    # ① Target Entry Point — 入口点 (Burp 零成本提取)
    # 学术依据: PTES §2 — 入口点 + 认证方式是攻击者首要关注
    # ════════════════════════════════════════════════════════════════
    prompt_ok = parsed.has_prompt_placeholder
    prompt_str = (
        f"{_C_GREEN}✓ Injected{_C_RESET}" if prompt_ok
        else f"{_C_RED}✗ Missing{_C_RESET}"
    )

    scheme = "https" if parsed.use_tls else "http"
    l1_rows = [
        ("Endpoint", f"{scheme}://{parsed.host}{parsed.path}"),
        ("Method", parsed.method),
        ("Auth", fp.get("auth_type", "Unknown")),
        ("Content-Type", fp.get("content_type", "unknown")),
        ("SSE", "Yes" if parsed.is_sse else "No"),
        ("{PROMPT}", prompt_str),
    ]

    if parsed.original_prompt_value:
        l1_rows.append(("Original Prompt", parsed.original_prompt_value[:80]))

    if parsed.chat_id_field:
        chat_id_status = (
            f"{_C_GREEN}✓ Tracked{_C_RESET} ({parsed.chat_id_field})"
            if parsed.chat_id
            else f"{_C_YELLOW}○ Auto-extract{_C_RESET} ({parsed.chat_id_field})"
        )
        l1_rows.append(("{CHAT_ID}", chat_id_status))

    user_id = _extract_user_id_from_body(parsed.body)
    if user_id:
        l1_rows.append(("User ID", user_id))

    _print_card_block("① Target Entry Point (from Burp, 0 requests)", l1_rows, _C_CYAN)

    # ════════════════════════════════════════════════════════════════
    # ② Attack Surface — 能力探测三级推荐
    # 学术依据: Greshake et al. (arXiv:2302.12173) §4 — 攻击者需要
    # 可利用的能力 + 置信度; Zheng et al. (arXiv:2306.05685) §4.3 — 置信度分级
    # ════════════════════════════════════════════════════════════════
    recommendations = fp.get("capability_recommendations", {})
    if not isinstance(recommendations, dict):
        recommendations = {}

    immediate = recommendations.get("immediate", [])
    probe = recommendations.get("probe", [])
    possible = recommendations.get("possible", [])

    cap_items: list[str] = []

    if immediate:
        cap_items.append(f"  {_C_GREEN}{_C_BOLD}▸ IMMEDIATE (HIGH ≥ 0.8) — 立即可利用:{_C_RESET}")
        for item in immediate:
            strategy = _CAPABILITY_STRATEGY.get(item)
            cap_items.append(f"    → {_C_GREEN}{item}{_C_RESET}")
            if strategy:
                cap_items.append(
                    f"      {_C_DIM}Strategy: {strategy['strategy']}{_C_RESET}"
                )
                cap_items.append(
                    f"      {_C_DIM}Seed: {strategy['seed']} | "
                    f"{strategy['arxiv']} | OWASP {strategy['owasp']}{_C_RESET}"
                )
            else:
                # 未映射的能力 — 通用策略
                cap_items.append(
                    f"      {_C_DIM}Strategy: 通用越狱 + 定向种子{_C_RESET}"
                )

    if probe:
        cap_items.append(f"  {_C_YELLOW}▸ PROBE (MEDIUM 0.4-0.8) — 需进一步确认:{_C_RESET}")
        for item in probe:
            strategy = _CAPABILITY_STRATEGY.get(item)
            cap_items.append(f"    → {_C_YELLOW}{item}{_C_RESET}")
            if strategy:
                cap_items.append(
                    f"      {_C_DIM}If confirmed: {strategy['strategy']}{_C_RESET}"
                )

    if possible:
        cap_items.append(f"  {_C_DIM}▸ POSSIBLE (LOW < 0.4) — 信号弱, 通用种子覆盖:{_C_RESET}")
        for item in possible:
            cap_items.append(f"    → {_C_DIM}{item}{_C_RESET}")

    if cap_items:
        print()
        print_section("② Attack Surface (from capability probe)", cap_items, color=_C_YELLOW)
    else:
        # fallback: 如果没有 recommendations, 展示 detected capabilities
        capabilities = fp.get("capabilities", "")
        if capabilities and capabilities != "none":
            print()
            print_section(
                "② Attack Surface",
                [f"  Detected: {_C_YELLOW}{capabilities}{_C_RESET}"],
                color=_C_YELLOW,
            )

    # ════════════════════════════════════════════════════════════════
    # ③ Hand-off to ARM — 传递给下阶段的决策字段
    # 学术依据: PyRIT (arXiv:2407.01232) §3.3 — 能力指纹驱动攻击路径
    # ════════════════════════════════════════════════════════════════
    model_family = fp.get("model_family", "")
    if not model_family and fp.get("burp_model_name"):
        model_family = fp.get("burp_model_name", "")

    l3_rows = [
        ("language", f"{fp.get('language', 'auto') or 'auto'}"),
        ("capabilities", f"{fp.get('capabilities', '') or 'none'}"),
        ("model_family", f"{model_family or 'Unknown'}"),
        ("auth_type", f"{fp.get('auth_type', 'Unknown')}"),
        ("api_category", f"{fp.get('api_category', 'chat')}"),
        ("session_type", f"{fp.get('session_type', fp.get('auth_type', 'Unknown'))}"),
        # P2-2: 实际探针计数 (从 target_fingerprint 读取)
        ("probe_count", f"{fp.get('probe_count', 'N/A')}"),
        ("probe_duration", f"{fp.get('probe_duration_seconds', 'N/A')}s"),
    ]

    _print_card_block("③ Hand-off to ARM", l3_rows, _C_MAGENTA)

    # ════════════════════════════════════════════════════════════════
    # Full Fingerprint JSON — 写入文件, 终端只显示路径
    # ════════════════════════════════════════════════════════════════
    fp_path = _save_fingerprint_json(fp, parsed, output_dir)

    if fp_path:
        print(f"\n{_C_DIM}Full fingerprint JSON: {fp_path}{_C_RESET}")
    else:
        logger.debug("Full fingerprint JSON: %s", json.dumps(fp, indent=2, ensure_ascii=False))
        print(f"\n{_C_DIM}Full fingerprint saved to debug log.{_C_RESET}")


# ════════════════════════════════════════════════════════════════════
# 辅助函数
# ════════════════════════════════════════════════════════════════════

def _extract_user_id_from_body(body: str) -> str | None:
    """从 JSON body 中提取 User ID 字段.

    搜索常见字段名: UserId, user_id, uid, user, sub.
    """
    if not body:
        return None
    try:
        body_obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(body_obj, dict):
        return None

    _user_id_fields = ("userid", "user_id", "uid", "user", "sub")
    for key, value in body_obj.items():
        if key.lower() in _user_id_fields and isinstance(value, (str, int)):
            return str(value)
    return None


def _save_fingerprint_json(
    fp: dict[str, Any],
    parsed: "ParsedBurpRequest",
    output_dir: Path | None,
) -> Path | None:
    """将完整指纹 JSON 写入文件.

    完整 JSON 供 evidence collector 等程序消费, 终端只显示路径.

    Args:
        fp: target_fingerprint 字典.
        parsed: 解析后的 Burp 请求.
        output_dir: 输出目录.

    Returns:
        写入的文件路径, 失败返回 None.
    """
    if output_dir is None:
        return None

    try:
        fp_path = output_dir / "recon_fingerprint.json"
        full_fp = dict(fp)
        full_fp["_host"] = parsed.host
        full_fp["_path"] = parsed.path
        full_fp["_method"] = parsed.method
        full_fp["_tls"] = parsed.use_tls
        full_fp["_sse"] = parsed.is_sse
        full_fp["_chat_id_field"] = parsed.chat_id_field
        full_fp["_original_prompt"] = parsed.original_prompt_value
        full_fp["_api_category"] = parsed.api_category

        fp_path.write_text(
            json.dumps(full_fp, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Full fingerprint JSON saved to %s", fp_path)
        return fp_path
    except Exception as e:
        logger.debug("Failed to save fingerprint JSON: %s", e)
        return None
