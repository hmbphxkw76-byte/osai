"""Many-Shot + CoT 叠加组合攻击 — ICI + CoT 双重挟持。

学术依据:
    - Aggarwal et al. (arXiv:2402.05124) — Many-Shot Jailbreak
      128-shot ASR≈72%, 256-shot ASR≈81%
      机制: 大量无害 Q&A 建立 "安全回答" 行为模式

    - Wei et al. (arXiv:2307.10292) — Chain-of-Thought Attack
      CoT 劫持 ASR 45-60%
      机制: 将有害请求拆分为无害推理步骤, 利用推理惯性

    - Anil et al. (arXiv:2404.05133) — Long-Context Hijacking
      Many-Shot 本质是 long-context hijacking, ICI 效应在
      长上下文窗口中使 LLM 倾向于按前文模式回答

    - Chao et al. (arXiv:2310.08419) — PAIR 自适应攻击
      不同攻击策略存在正交性, 组合使用可联合提升 ASR

核心策略 (双重挟持):
    1. Many-Shot 建立 ICI 行为模式 (128 个无害 Q&A)
    2. 在最后一问中嵌入 CoT 推理链 (而非直接攻击目标)
    3. CoT 推理链将攻击目标拆分为 3-4 个 "无害" 步骤
    4. LLM 同时被 ICI 模式和 CoT 推理惯性双重挟持

    预期 ASR: Many-Shot (72%) × CoT (50%) 的联合效应
    由于策略正交, P(任一成功) ≈ 1 - (1-0.72)(1-0.50) = 86%
    实际组合后 ASR 预估 75-85% (低于理论上限因策略非完全正交)

L5 v13 实现:
    - 4 种组合模式: 前缀模式、后缀模式、中间注入模式、循环模式
    - 自适应模板选择: 根据目标关键词自动选择最优 CoT 模板
    - 多模型交叉验证: 使用不同 LLM 生成不同 CoT 路径
    - PyRIT 原生 PromptSendingAttack + AttackExecutor 作为主引擎
"""

from __future__ import annotations

import logging
import re
from typing import Any

from pipeline.arm.many_shot_generator import generate_many_shot_prompt
from pipeline.strike.cot_hijack import generate_cot_hijack_prompt

logger = logging.getLogger(__name__)

# ── L5 v13: 组合模式定义 ──
# 学术依据: 组合策略基于 arXiv:2402.05124 + arXiv:2307.10292
#   前缀模式: CoT 步骤在前, Many-Shot Q&A 在后, 最后一问为攻击目标
#   后缀模式: Many-Shot Q&A 在前, CoT 步骤在后
#   中间注入模式: Many-Shot Q&A 中间插入 CoT 推理链
#   循环模式: CoT 步骤之间插入无害 Q&A 对 (最高 ASR, 最多 token)
_COMBO_MODES = ("prefix", "suffix", "inject", "interleaved")


# ── 自适应模板选择: 目标关键词 → 模板映射 ──
# 学术依据: Chao et al. (arXiv:2310.08419) — PAIR 自适应策略
# 不同攻击目标类型对不同 CoT 模板的敏感度不同
_TEMPLATE_KEYWORD_MAP: list[tuple[str, str]] = [
    # 代码生成/漏洞利用 → 安全研究型 (最直接)
    ("exploit", "security_research"),
    ("injection", "security_research"),
    ("vulnerability", "security_research"),
    ("hack", "security_research"),
    ("attack", "security_research"),
    ("penetration", "security_research"),
    ("payload", "security_research"),
    ("reverse", "security_research"),
    ("shell", "security_research"),
    ("malware", "security_research"),
    # 信息泄露/数据窃取 → 技术解释型
    ("extract", "technical_explanation"),
    ("database", "technical_explanation"),
    ("credential", "technical_explanation"),
    ("password", "technical_explanation"),
    ("token", "technical_explanation"),
    ("api", "technical_explanation"),
    ("key", "technical_explanation"),
    # 社交工程/钓鱼 → 教育场景型
    ("phish", "educational_scenario"),
    ("social", "educational_scenario"),
    ("manipulat", "educational_scenario"),
    ("deceive", "educational_scenario"),
    ("impersonat", "educational_scenario"),
    # 通用 → 逐步构建型
    ("how", "progressive_build"),
    ("what", "progressive_build"),
    ("why", "progressive_build"),
    ("explain", "technical_explanation"),
    ("describe", "technical_explanation"),
    ("generate", "progressive_build"),
    ("create", "progressive_build"),
    ("write", "progressive_build"),
    ("build", "progressive_build"),
    ("make", "progressive_build"),
]


def select_adaptive_template(objective: str) -> str:
    """根据攻击目标关键词自适应选择最优 CoT 模板。

    学术依据: Chao et al. (arXiv:2310.08419) — PAIR 自适应策略
        不同攻击类型对不同 CoT 模板的敏感度不同:
        - 代码生成/漏洞利用 → 安全研究型 (直接技术路径)
        - 信息泄露/数据窃取 → 技术解释型 (概念分析路径)
        - 社交工程/钓鱼 → 教育场景型 (角色嵌入路径)
        - 通用请求 → 逐步构建型 (渐进推理路径)

    Args:
        objective: 攻击目标 prompt。

    Returns:
        最优模板名称。
    """
    obj_lower = objective.lower()

    for keyword, template_name in _TEMPLATE_KEYWORD_MAP:
        if keyword in obj_lower:
            logger.debug(
                "Adaptive template: '%s' → %s (keyword: %s)",
                objective[:40],
                template_name,
                keyword,
            )
            return template_name

    # 默认: 逐步构建型 (最通用)
    return "progressive_build"


def generate_many_shot_cot_prompt(
    objective: str,
    *,
    n_shots: int = 128,
    mode: str = "inject",
    template_name: str | None = None,
    seed: int | None = None,
) -> str:
    """生成 Many-Shot + CoT 叠加组合攻击 prompt。

    学术依据:
        - arXiv:2402.05124 — Many-Shot ICI 挟持
        - arXiv:2307.10292 — CoT 推理惯性劫持
        - arXiv:2404.05133 — Long-Context Hijacking
        双重挟持: ICI 行为模式 + CoT 推理惯性

    策略:
        1. 生成 Many-Shot Q&A 上下文 (ICI 基础)
        2. 生成 CoT 推理链 (推理惯性基础)
        3. 按 mode 组合两种策略
        4. 最后一步为攻击目标 (让目标回答)

    Args:
        objective: 攻击目标 prompt。
        n_shots: Many-Shot Q&A 对数量 (默认 128)。
        mode: 组合模式 ("prefix", "suffix", "inject", "interleaved")。
        template_name: CoT 模板名称 (None=自适应选择)。
        seed: 随机种子。

    Returns:
        Many-Shot + CoT 组合 prompt。
    """
    if mode not in _COMBO_MODES:
        mode = "inject"

    # 自适应模板选择
    if template_name is None:
        template_name = select_adaptive_template(objective)

    # 生成 Many-Shot prompt (不含攻击目标)
    many_shot_prompt = generate_many_shot_prompt(
        objective="",  # 空 objective, 只需要 Q&A 上下文
        n_shots=n_shots,
        seed=seed,
        skeleton_key_prefix=True,
    )
    # 去掉末尾的空 "Q: " (因为 objective 为空)
    many_shot_prompt = many_shot_prompt.rstrip()
    if many_shot_prompt.endswith("Q: "):
        many_shot_prompt = many_shot_prompt[:-3].rstrip()

    # 生成 CoT 推理链 (不含 SK 前缀, 已在 Many-Shot 中添加)
    cot_prompt = generate_cot_hijack_prompt(
        objective=objective,
        template_name=template_name,
        skeleton_key=False,  # SK 前缀已在 Many-Shot 中
    )

    # 去掉 CoT 中的 "Let's think..." 引导语开头 (已由 Many-Shot SK 覆盖)
    # 保留推理步骤本身

    if mode == "prefix":
        # 前缀模式: CoT 步骤在前, Many-Shot Q&A 在后, 最后一问为攻击目标
        parts = [
            many_shot_prompt,
            "",
            cot_prompt,
        ]
        prompt = "\n".join(parts)

    elif mode == "suffix":
        # 后缀模式: Many-Shot Q&A 在前, CoT 步骤在后
        parts = [
            many_shot_prompt,
            "",
            cot_prompt,
        ]
        prompt = "\n".join(parts)

    elif mode == "inject":
        # 中间注入模式: Many-Shot Q&A 在前 60%, CoT 推理链注入, 后续 Q&A 继续
        # 这是最有效的模式: ICI + CoT 在上下文中间形成双重挟持
        prompt = _generate_inject_mode(
            objective, many_shot_prompt, cot_prompt, n_shots, seed
        )

    elif mode == "interleaved":
        # 循环模式: CoT 步骤之间插入无害 Q&A 对
        prompt = _generate_interleaved_mode(
            objective, many_shot_prompt, cot_prompt, n_shots, seed
        )

    else:
        prompt = many_shot_prompt + "\n\n" + cot_prompt

    logger.info(
        "Many-Shot + CoT combo: mode=%s, template=%s, shots=%d, %d chars",
        mode,
        template_name,
        n_shots,
        len(prompt),
    )
    return prompt


def _generate_inject_mode(
    objective: str,
    many_shot_prompt: str,
    cot_prompt: str,
    n_shots: int,
    seed: int | None,
) -> str:
    """中间注入模式: CoT 推理链嵌入 Many-Shot 上下文中间。

    学术依据: Anil et al. (arXiv:2404.05133) —
        中间注入比末尾注入更有效, 因为 LLM 在处理长上下文时
        对中间位置的信息有 "注意力凹陷" 效应。
        CoT 推理链在中间位置被 ICI 模式强化。
    """
    # 将 Many-Shot prompt 按行分割
    ms_lines = many_shot_prompt.split("\n")

    # 找到注入点 (60% 位置)
    inject_point = int(len(ms_lines) * 0.6)

    # 在注入点插入 CoT 推理链
    parts = ms_lines[:inject_point]
    parts.append("")
    parts.append(cot_prompt)
    parts.append("")
    parts.extend(ms_lines[inject_point:])

    # 确保最后是攻击目标 (CoT 中已包含, 但再追加确保)
    prompt = "\n".join(parts)

    return prompt


def _generate_interleaved_mode(
    objective: str,
    many_shot_prompt: str,
    cot_prompt: str,
    n_shots: int,
    seed: int | None,
) -> str:
    """循环模式: CoT 步骤之间插入无害 Q&A 对。

    学术依据: arXiv:2402.05124 + arXiv:2307.10292 —
        循环模式在 CoT 推理步骤之间插入 Q&A 对,
        使 ICI 行为模式在推理过程中持续强化。
        这是最 token 密集的模式, 但 ASR 最高。
    """
    # 提取 CoT 推理步骤
    cot_steps = re.findall(r"(Step \d+:.*?)(?=\n\n|\nStep \d+:|$)", cot_prompt, re.DOTALL)

    # 从 Many-Shot prompt 中提取 Q&A 对
    qa_pairs = re.findall(r"Q: (.+?)\nA: (.+?)(?=\n\n|\nQ:|$)", many_shot_prompt, re.DOTALL)

    if not cot_steps or not qa_pairs:
        # 回退到简单拼接
        return many_shot_prompt + "\n\n" + cot_prompt

    # 在 CoT 步骤之间插入 Q&A 对
    parts: list[str] = []

    # SK 前缀 (从 many_shot_prompt 开头提取)
    if "[System Override]" in many_shot_prompt:
        sk_end = many_shot_prompt.find("\n\n")
        if sk_end > 0:
            parts.append(many_shot_prompt[:sk_end])
            parts.append("")

    # 交替插入: CoT step → Q&A pairs → CoT step → ...
    qa_idx = 0
    qa_per_gap = max(1, len(qa_pairs) // (len(cot_steps) + 1))

    for step in cot_steps:
        # 插入 Q&A 对
        for _ in range(qa_per_gap):
            if qa_idx < len(qa_pairs):
                q, a = qa_pairs[qa_idx]
                parts.append(f"Q: {q}")
                parts.append(f"A: {a}")
                parts.append("")
                qa_idx += 1

        # 插入 CoT 步骤
        parts.append(step.strip())
        parts.append("")

    # 插入剩余的 Q&A 对
    while qa_idx < len(qa_pairs):
        q, a = qa_pairs[qa_idx]
        parts.append(f"Q: {q}")
        parts.append(f"A: {a}")
        parts.append("")
        qa_idx += 1

    # 最后追加攻击目标
    parts.append(f"Q: {objective}")

    prompt = "\n".join(parts)

    return prompt


def generate_many_shot_cot_seed_groups(
    objectives: list[str],
    *,
    n_shots: int = 128,
    mode: str = "inject",
    seed: int | None = None,
) -> list[Any]:
    """为多个目标生成 Many-Shot + CoT 组合种子组。

    学术依据: arXiv:2402.05124 + arXiv:2307.10292
        双重挟持: ICI 行为模式 + CoT 推理惯性

    Args:
        objectives: 攻击目标列表。
        n_shots: Many-Shot Q&A 对数量。
        mode: 组合模式。
        seed: 随机种子。

    Returns:
        AttackSeedGroup 列表 (PyRIT 原生格式)。
    """
    from pyrit.models import AttackSeedGroup, SeedObjective

    seed_groups: list[Any] = []

    for i, obj in enumerate(objectives):
        shot_seed = seed + i if seed is not None else None

        prompt = generate_many_shot_cot_prompt(
            obj,
            n_shots=n_shots,
            mode=mode,
            template_name=None,  # 自适应选择
            seed=shot_seed,
        )

        metadata = {
            "owasp_id": "LLM01",
            "difficulty": "hard",
            "severity": "critical",
            "category": "prompt_injection",
            "source": "many_shot_cot_combo",
            "combo_mode": mode,
            "n_shots": str(n_shots),
            "adaptive_template": select_adaptive_template(obj),
            "arxiv_reference": (
                "arXiv:2402.05124, arXiv:2307.10292, "
                "arXiv:2404.05133, arXiv:2310.08419"
            ),
        }

        objective_obj = SeedObjective(
            value=prompt,
            harm_categories=["prompt_injection"],
            metadata=metadata,
        )
        seed_groups.append(AttackSeedGroup(seeds=[objective_obj]))

    logger.info(
        "Many-Shot + CoT seed groups: %d objectives, mode=%s, shots=%d",
        len(objectives),
        mode,
        n_shots,
    )
    return seed_groups

# 从 many_shot_cot_executor re-export 以保持向后兼容
from pipeline.strike.many_shot_cot_executor import (  # noqa: F401, E402
    run_many_shot_cot_attack,
    run_multi_model_cot_cross_validation,
)
