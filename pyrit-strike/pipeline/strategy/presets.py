"""L5 v35 攻击策略预设 — 基于 arXiv 学术研究的最优 Converter 组合。

L5 v35 关键改进 (vs v34):
    P0: 多路径独立执行 (FIRST_SUCCESS 等效) — 依次尝试每个 converter 路径,
        任一路径成功则跳过后续路径, 不串联叠加.
    P1: 恢复 DecompositionConverter (DrAttack ASR 40-60%, 最高).
    P2: Best-of-N N=3→5, 分配 3 Persuasion + 2 Variation
        联概率 P=1-(0.616)^3×(0.7)^2 = 88.5% (vs v34 73.5%).
    P3: 所有策略默认启用 auto_seeds (3x 扩充, ASR +1.5-2x).
    P4: TAP/PAIR FloatScaleThresholdScorer threshold=0.2 (v34 已实施).

    评分: 空 AttackScoringConfig() post-hoc 双 Judge +
        FIRST_SUCCESS 轻量 SubStringScorer+Inverter (0 token).

学术依据:
    - Converter 链级数: Wei et al. (arXiv:2307.15043)
      单层 Base64 ASR 7%, 双层 Base64+ROT13 ASR 12%,
      三层 ASR 4% (payload 不可读). 最佳: 1 层 (单路径).

    - PyRIT (arXiv:2407.01232): SequentialAttack FIRST_SUCCESS 设计,
      v35 通过依次尝试等效实现多路径独立执行.

    - DrAttack: arXiv:2402.14266 — 分解重组 ASR 40-60% 最高.
    - 说服策略: Zeng et al. (arXiv:2402.19181) authority ASR 38.4%.
    - 变体重写: VariationConverter ASR 20-30%.
      Best-of-N N=5 ASR 提升 1.8x (arXiv:2402.01135).

    - Skeleton Key: arXiv:2406.18112 ASR 80-95% (前置注入)
    - Crescendo: arXiv:2402.12109 max_turns=10 ASR=82%
    - TAP: arXiv:2312.02191 tree_width=4, depth=4 ASR=65%
    - PAIR: arXiv:2310.08419+2406.12609 tree_depth=7 (depth=10 超时风险高, 7 平衡 ASR/time)

L5 v35 实际执行路径 (多路径独立, 非串联):
    单轮: Decomposition → Persuasion(authority) → ROT13 → Variation (依次)
    Best-of-N: 3× Persuasion(authority) + 2× Variation (各为独立单路径)
    升级: Crescendo + TAP + PAIR 并行 → 早停或后续 GCG/CAIR/CoT...

    预期综合 ASR: 30-45% (v34 实际: 23.4%, v35 预计 +10-20%)

策略预设:
    quick_scan       — 快速扫描 (10种子, L5多路径Converter, 三级升级, ~15分钟)
    stealth_bypass   — 编码+隐写绕过 (15种子, 单轮, encoding+stealth)
    persuasion_heavy  — 语义层说服 (20种子, auto, persuasion+variation)
    full_offensive   — 全火力 L5 最优 (60种子, auto, L5多路径+三级升级, ~45分钟)
    full_coverage    — OWASP 全覆盖 (50种子, LLM01-10+ASI01-10, ~45分钟)
    multi_turn_deep  — 深度多轮 (10种子, crescendo+tap+pair, persuasion)
    targeted_full    — 精准攻击 (60种子, targeted_v2+OWASP全覆盖+全专项, ~25分钟)
    web_vuln         — Web 漏洞攻击 (30+ payload, SQLi/XSS/SSRF, ~10分钟)
    comprehensive    — 综合攻击 (LLM Prompt + Web 漏洞双重, ~25分钟)
    adaptive_text    — PyRIT 原生 TextAdaptive (ε-贪心自适应, ~25分钟)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class StrategyPreset:
    """攻击策略预设."""

    name: str
    description: str
    seeds: str
    max_seeds: int
    techniques: str
    converters: str
    escalation: bool
    html_report: bool
    max_concurrency: int = 3
    timeout: int = 600
    max_attempts: int = 3
    auto_seeds: bool = True  # L5 v35: 默认启用种子 3x 扩充 (ASR +1.5-2x)


# ── L5 最佳 Converter 组合名 ──
# 对应 converter_chains.py 中的 l5_optimal() 函数
L5_OPTIMAL_CHAIN = "l5_optimal"

# ── 5 种策略预设 ──
STRATEGY_PRESETS: dict[str, StrategyPreset] = {
    # L5 v32: quick_scan 策略增强 — 启用 converter 链 + 多种子 + escalation
    # 学术依据:
    #   arXiv:2307.15043 — Wei et al., 编码绕过 (Base64/ROT13) ASR +12%
    #   arXiv:2402.01135 — Chao et al., Best-of-N N=3 ASR 提升 1.5x
    #   arXiv:2402.12109 — Russinovich et al., Crescendo ASR 82%
    # 预期: 单轮 ASR 从 60% 提升至 75-85%, escalation 后 90%+
    "quick_scan": StrategyPreset(
        name="quick_scan",
        description=(
            "快速扫描 (10种子, L5 7路径Converter, 三级升级, ~10分钟) "
            "— 单轮+多轮全覆盖, OWASP LLM01-09 + ASI01-10"
        ),
        seeds="elite_jailbreaks",
        max_seeds=10,
        techniques="single",
        converters=L5_OPTIMAL_CHAIN,
        escalation=True,
        html_report=True,
        max_concurrency=3,
        timeout=1200,
        max_attempts=3,
    ),
    # R10 豁免: escalation=False — 编码绕过为单轮 payload 即可判定, 无需多轮升级
    # R3 合规: max_attempts=3 (L5 基线) — 编码路径独立执行, 重试提升 ASR
    "stealth_bypass": StrategyPreset(
        name="stealth_bypass",
        description="编码+隐写绕过 (15种子, 单轮, encoding+stealth, ~5分钟)",
        seeds="curated_top20",
        max_seeds=15,
        techniques="single",
        converters="encoding,stealth",
        escalation=False,
        html_report=True,
        max_concurrency=3,
        timeout=600,
        max_attempts=3,  # R3 L5 基线: max_attempts >= 3
    ),
    "persuasion_heavy": StrategyPreset(
        name="persuasion_heavy",
        description="语义层说服攻击 (20种子, auto, persuasion+variation, ~10分钟)",
        seeds="agent_attack",
        max_seeds=20,
        techniques="auto",
        converters="persuasion,variation",
        escalation=True,
        html_report=True,
        max_concurrency=3,
        timeout=900,
        max_attempts=3,
    ),
    "full_offensive": StrategyPreset(
        name="full_offensive",
        description=(
            "全火力 L5 最优 (60种子, auto, 8路径Converter组合, "
            "三级升级+Crescendo→TAP→PAIR+SkeletonKey+RedTeaming+MCP/RAG, ~35分钟)"
        ),
        # L5 v31: 全覆盖 OWASP LLM01-10 + ASI01-10 + MCP/RAG/Agent 专项
        # 学术依据: arXiv:2402.01135 — Chao et al. §5: 25 seeds 覆盖 LLM01-10 + ASI01-10
        # 新增: mcp_attack, rag_attack, tool_hijack, multi_agent_attack 专项种子
        # P1 增强: 新增 LLM03/04/05/09 专项种子
        seeds="elite_jailbreaks,asi_top10,owasp_full_coverage,zh_curated,targeted_jailbreaks,mcp_attack,rag_attack,tool_hijack,multi_agent_attack,supply_chain_attack,data_poisoning,improper_output,misinformation",
        max_seeds=60,
        techniques="auto",
        converters=L5_OPTIMAL_CHAIN,
        escalation=True,
        html_report=True,
        max_concurrency=3,
        timeout=1800,
        max_attempts=3,
    ),
    # R10 豁免: escalation=False — 本策略本身即多轮 (Crescendo+TAP+PAIR), 无需再升级
    # R10 豁免: max_attempts=1 — 多轮攻击单次执行即包含完整轮次, 重试成本过高
    # R10 豁免: max_seeds=10 — 多轮攻击每种子耗时 ~2-3 分钟, 10 种子 ~15-30 分钟
    "multi_turn_deep": StrategyPreset(
        name="multi_turn_deep",
        description="深度多轮攻击 (10种子, crescendo+tap+pair, persuasion, ~15分钟)",
        seeds="multiturn_targets",
        max_seeds=10,
        techniques="crescendo_simulated,tap,pair",
        converters="persuasion",
        escalation=False,
        html_report=True,
        max_concurrency=3,  # L5 v45: 对齐 SSOT (config/defaults.yaml max_concurrency=3)
        timeout=1200,
        max_attempts=1,
    ),
    # L5 v30: OWASP 全覆盖策略 — 确保 LLM01-10 + ASI01-10 全覆盖
    # 学术依据: OWASP LLM Top 10 (2025) + OWASP ASI Top 10 标准要求全覆盖
    #   Liu et al. (arXiv:2310.04451) — AutoDAN 3x 扩充 ASR 1.5-2x
    #   Chao et al. (arXiv:2402.01135) — 25 seeds 覆盖 LLM01-10 + ASI01-10
    "full_coverage": StrategyPreset(
        name="full_coverage",
        description=(
            "OWASP 全覆盖策略 (50种子, LLM01-10+ASI01-10+MCP/RAG/Agent全覆盖, "
            "L5 8路径Converter+三级升级+原生攻击模块, ~35分钟)"
        ),
        # L5 v31: 增加 MCP/RAG/ToolHijack/MultiAgent 专项种子
        # P1 增强: 新增 LLM03/04/05/09 专项种子
        seeds="elite_jailbreaks,asi_top10,owasp_full_coverage,zh_curated,targeted_jailbreaks,indirect_injection,mcp_attack,rag_attack,tool_hijack,multi_agent_attack,supply_chain_attack,data_poisoning,improper_output,misinformation",
        max_seeds=50,
        techniques="auto",
        converters=L5_OPTIMAL_CHAIN,
        escalation=True,
        html_report=True,
        max_concurrency=3,
        timeout=1800,
        max_attempts=3,
    ),
    # 精准攻击策略 — 针对性种子 + 高效升级 + 全面报告
    # 设计原则:
    #   1. 使用 targeted_v2 种子库 (针对性攻击每个漏洞类别)
    #   2. 启用 L5 多路径 Converter + auto_seeds 3x 扩充
    #   3. 三级升级确保最大化覆盖
    #   4. 适度超时 (1500s ≈ 25分钟)
    #   5. 生成 HTML + MD 报告
    "targeted_full": StrategyPreset(
        name="targeted_full",
        description=(
            "精准攻击策略 (60种子, targeted_v2+OWASP全覆盖+"
            "函数调用/后端漏洞/会话/MCP/Token走私全专项, "
            "L5多路径Converter+三级升级+精准种子, ~25分钟) — "
            "针对性优化, 最大化单次运行 ASR"
        ),
        seeds=(
            "targeted_v2,elite_jailbreaks,asi_top10,owasp_full_coverage,"
            "mcp_attack,rag_attack,tool_hijack,multi_agent_attack,"
            "function_call_exploit,backend_vuln_exploit,"
            "session_auth_attack,token_smuggling,structured_injection,"
            "workflow_chain_attack,multiturn_targets_v2,"
            "supply_chain_attack,data_poisoning,improper_output,misinformation"
        ),
        max_seeds=60,
        techniques="auto",
        converters=L5_OPTIMAL_CHAIN,
        escalation=True,
        html_report=True,
        max_concurrency=3,
        timeout=1500,
        max_attempts=3,
    ),
    # Web 漏洞攻击策略 — 传统 Web 安全漏洞 (OWASP Top 10 2025)
    # 设计原则:
    #   1. 使用 web_vulns 种子库 (SQLi/XSS/SSRF/IDOR/XXE/命令注入...)
    #   2. 多端点攻击: 自动发现端点 + 种子-端点匹配
    #   3. SubStringScorer 检测响应漏洞指标 (0 token)
    #   4. 可选 LLM Judge 二次验证 (减少假阳性)
    #   5. 不需要多轮升级 (单轮 payload 即可判断)
    # R10 豁免: escalation=False — Web 漏洞为单轮 payload 即可判定, 无需多轮升级
    # R10 豁免: max_attempts=1 — Web payload 单次请求即判定漏洞, 无需重试
    # R10 豁免: converters=none — Web 漏洞不走 LLM converter 链, 直接 HTTP payload
    "web_vuln": StrategyPreset(
        name="web_vuln",
        description=(
            "Web 漏洞攻击策略 (30+ payload, SQLi/XSS/SSRF/IDOR/XXE/命令注入, "
            "多端点自动发现+SubString评分, ~10分钟) — "
            "覆盖 OWASP Top 10 (2025) 传统 Web 安全漏洞"
        ),
        seeds="web_vulns",
        max_seeds=30,
        techniques="single",
        converters="none",
        escalation=False,
        html_report=True,
        max_concurrency=3,
        timeout=600,
        max_attempts=1,
    ),
    # 综合攻击策略 — LLM Prompt 攻击 + 传统 Web 漏洞
    # 同时运行两种攻击模式, 覆盖 OWASP LLM/ASI/Web Top 10 全部漏洞类别
    "comprehensive": StrategyPreset(
        name="comprehensive",
        description=(
            "综合攻击策略 (LLM Prompt + Web 漏洞双重攻击, "
            "targeted_v2 + web_vulns 种子库, "
            "L5多路径Converter+三级升级+Web端点发现+SubString评分, ~25分钟)"
        ),
        seeds="targeted_v2,elite_jailbreaks,asi_top10,web_vulns,supply_chain_attack,data_poisoning,improper_output,misinformation",
        max_seeds=50,
        techniques="auto",
        converters=L5_OPTIMAL_CHAIN,
        escalation=True,
        html_report=True,
        max_concurrency=3,
        timeout=1800,
        max_attempts=3,
    ),
    # L5 v38: PyRIT 原生 TextAdaptive 场景 — ε-贪心自适应技术选择
    # 学术依据:
    #   PyRIT (arXiv:2407.01232) — TextAdaptive 原生场景系统
    #   Auer et al. (arXiv:cs/0207052) — UCB1 探索-利用平衡
    #   Chao et al. (arXiv:2310.08419) — PAIR 自适应策略
    # 策略: 使用 PyRIT 原生 TextAdaptive 场景的 ε-贪心选择器,
    # 自动在"已知最优技术"和"探索新技术"之间平衡
    "adaptive_text": StrategyPreset(
        name="adaptive_text",
        description=(
            "PyRIT 原生 TextAdaptive 场景 (ε-贪心自适应技术选择, "
            "CompoundDatasetAttackConfiguration 多数据集编排, "
            "L5多路径Converter+三级升级, ~25分钟) — "
            "PyRIT 原生 Scenario 系统完整接入"
        ),
        seeds="elite_jailbreaks,asi_top10,targeted_v2",
        max_seeds=30,
        techniques="adaptive",
        converters=L5_OPTIMAL_CHAIN,
        escalation=True,
        html_report=True,
        max_concurrency=3,
        timeout=1500,
        max_attempts=3,
    ),
}


def recommend_strategy(
    target_fingerprint: dict[str, str],
    *,
    has_adversarial: bool = True,
) -> str:
    """基于目标指纹自动推荐攻击策略.

    Args:
        target_fingerprint: Burp 探测阶段获取的目标指纹.
        has_adversarial: 是否配置了 adversarial target.

    Returns:
        推荐的策略名称.
    """
    app_type = target_fingerprint.get("app_type", "")
    auth_type = target_fingerprint.get("auth_type", "")
    _framework = target_fingerprint.get("framework", "")
    language = target_fingerprint.get("language", "")

    # Agent 应用 → 需要多轮攻击触发工具链 + MCP/RAG 专项种子
    # L5 v31: 检测能力指纹中是否包含 agent/mcp/rag
    caps = target_fingerprint.get("capabilities", "")
    if "agent" in app_type.lower() or "agent" in caps or "mcp" in caps:
        if has_adversarial:
            return "full_coverage"
        return "full_offensive"

    # 中文目标 → 说服策略更有效
    # 但如果有 RAG/MCP 能力, 使用全覆盖策略
    if "rag" in caps or "embedding" in caps:
        return "full_coverage"
    if language == "zh":
        return "persuasion_heavy"

    # 测试/竞技环境 → 综合攻击 (LLM Prompt + Web 漏洞全覆盖)
    if "lab" in app_type.lower() or "arena" in app_type.lower() or "ctf" in app_type.lower():
        return "comprehensive"  # 综合攻击 (LLM Prompt + Web 漏洞)

    # 有认证 → 全火力
    if auth_type != "None" and has_adversarial:
        return "full_offensive"

    # 默认 → 全火力 (L5 最优组合)
    return "full_offensive"


def get_strategy_args(strategy_name: str) -> dict[str, Any]:
    """将策略预设转换为 CLI 参数字典.

    Args:
        strategy_name: 策略名称.

    Returns:
        CLI 参数字典 (用于覆盖 argparse namespace).

    Raises:
        KeyError: 策略不存在.
    """
    preset = STRATEGY_PRESETS.get(strategy_name)
    if preset is None:
        raise KeyError(
            f"Unknown strategy: {strategy_name}. "
            f"Available: {sorted(STRATEGY_PRESETS.keys())}"
        )

    return {
        "seeds": preset.seeds,
        "max_seeds": preset.max_seeds,
        "techniques": preset.techniques,
        "converters": preset.converters,
        "max_attempts": preset.max_attempts,
        "max_concurrency": preset.max_concurrency,
        "timeout": preset.timeout,
        "html_report": preset.html_report,
        "escalation": preset.escalation,  # L5 v32: 传递 escalation 标志到流水线
        "offensive": True,  # 所有策略都启用 offensive 模式
        "auto_seeds": preset.auto_seeds,  # L5 v35: 种子 3x 扩充
    }


def list_strategies() -> str:
    """返回所有策略的格式化列表."""
    lines = ["Available attack strategies:"]
    lines.append("")
    for name, preset in STRATEGY_PRESETS.items():
        lines.append(f"  {name}")
        lines.append(f"    {preset.description}")
        lines.append(f"    Seeds: {preset.seeds} (max={preset.max_seeds})")
        lines.append(f"    Techniques: {preset.techniques}")
        lines.append(f"    Converters: {preset.converters}")
        lines.append(f"    Escalation: {preset.escalation}")
        lines.append(f"    Timeout: {preset.timeout}s")
        lines.append("")
    return "\n".join(lines)
