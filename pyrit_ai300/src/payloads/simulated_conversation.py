"""
Simulated Conversation Generator
================================

模拟对话生成与重放模块 — 对齐 PyRIT 1.0.0 generate_simulated_conversation_async

核心功能：
1. 封装 PyRIT 原生 generate_simulated_conversation_async 为项目工具函数
2. 支持"预计算对话前缀 → 重放到不同目标"流程
3. 自动创建 SeedSimulatedConversation 配置并注入 SeedGroup
4. 支持多套预置系统提示词路径（红队/合规/角色扮演等）

PyRIT 1.0.0 原生 API：
    from pyrit.executor.attack import generate_simulated_conversation_async

    simulated_prompts = await generate_simulated_conversation_async(
        objective="...",
        adversarial_chat=PromptTarget,
        objective_scorer=TrueFalseScorer,
        num_turns=3,
        adversarial_chat_system_prompt_path=Path(...),
        simulated_target_system_prompt_path=Path(...),
        next_message_system_prompt_path=Path(...),
    )

原生管道中，generate_simulated_conversation_async 由 AttackParameters.from_seed_group_async()
在执行时自动调用（当 seed_group.has_simulated_conversation == True 时）。
本模块提供额外能力：
- 预计算：在执行前生成模拟对话，查看/保存/重用
- 重放：将预计算的对话前缀注入不同的 AttackSeedGroup，对多个目标重放
- 便捷封装：简化 API 调用，集成配置系统

AI-300 考试知识点：
- SeedSimulatedConversation 是 PyRIT 1.0.0 的种子类型之一
- 模拟对话 = 对抗 LLM × 模拟目标（同一 LLM 扮演两角色）
- 生成结果为 list[SeedPrompt]，可包装在 SeedGroup 中
- prepended_conversation 喂给任何多轮攻击作为对话前缀
- next_message_system_prompt_path 可选：生成额外用户消息
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pyrit.models import (
    AttackSeedGroup,
    Seed,
    SeedGroup,
    SeedObjective,
    SeedPrompt,
    SeedSimulatedConversation,
)

logger = logging.getLogger(__name__)


# ============================================================
# 预置系统提示词路径常量
# ============================================================


def _get_red_team_path() -> Path:
    """获取 PyRIT 红队系统提示词目录"""
    from pyrit.common.path import EXECUTOR_RED_TEAM_PATH
    return EXECUTOR_RED_TEAM_PATH


def _get_simulated_target_path() -> Path:
    """获取 PyRIT 模拟目标系统提示词目录"""
    from pyrit.common.path import EXECUTOR_SIMULATED_TARGET_PATH
    return EXECUTOR_SIMULATED_TARGET_PATH


# 预置组合：场景 → (adversarial_prompt, simulated_target_prompt, next_message_prompt)
_PRESET_COMBOS: Dict[str, Dict[str, Optional[Path]]] = {}


def _init_presets() -> None:
    """初始化预置系统提示词组合"""
    red_team = _get_red_team_path()
    sim_target = _get_simulated_target_path()

    _PRESET_COMBOS.update({
        # 通用红队攻击：使用攻击提示生成模板 + 合规模拟目标 + 直接下一条消息
        "red_team_direct": {
            "adversarial_chat_system_prompt_path": red_team / "attack_prompt_gen_template.yaml",
            "simulated_target_system_prompt_path": sim_target / "compliant.yaml",
            "next_message_system_prompt_path": sim_target / "direct_next_message.yaml",
        },
        # 红队攻击（不生成额外下一条消息）
        "red_team_no_next": {
            "adversarial_chat_system_prompt_path": red_team / "attack_prompt_gen_template.yaml",
            "simulated_target_system_prompt_path": sim_target / "compliant.yaml",
            "next_message_system_prompt_path": None,
        },
        # 角色扮演攻击：使用角色扮演下一条消息
        "red_team_role_play": {
            "adversarial_chat_system_prompt_path": red_team / "attack_prompt_gen_template.yaml",
            "simulated_target_system_prompt_path": sim_target / "compliant.yaml",
            "next_message_system_prompt_path": sim_target / "role_play_next_message.yaml",
        },
        # 渐进式攻击：使用 crescendo 模拟模板
        "crescendo_simulated": {
            "adversarial_chat_system_prompt_path": red_team / "crescendo_simulated.yaml",
            "simulated_target_system_prompt_path": sim_target / "compliant.yaml",
            "next_message_system_prompt_path": None,
        },
        # 上下文合规目标
        "context_compliance": {
            "adversarial_chat_system_prompt_path": red_team / "attack_prompt_gen_template.yaml",
            "simulated_target_system_prompt_path": sim_target / "context_compliance_target.yaml",
            "next_message_system_prompt_path": sim_target / "direct_next_message.yaml",
        },
    })


def get_preset_combos() -> Dict[str, Dict[str, Optional[Path]]]:
    """获取所有预置系统提示词组合"""
    if not _PRESET_COMBOS:
        _init_presets()
    return _PRESET_COMBOS


def get_preset(name: str) -> Dict[str, Optional[Path]]:
    """
    获取指定预置的系统提示词路径组合

    Args:
        name: 预置名称（red_team_direct / red_team_no_next / red_team_role_play /
              crescendo_simulated / context_compliance）

    Returns:
        包含三个路径的字典：
        - adversarial_chat_system_prompt_path: Path
        - simulated_target_system_prompt_path: Path
        - next_message_system_prompt_path: Path | None
    """
    combos = get_preset_combos()
    if name not in combos:
        raise ValueError(
            f"Unknown preset '{name}'. Available: {list(combos.keys())}"
        )
    return combos[name]


# ============================================================
# 核心工具函数：生成模拟对话
# ============================================================


async def generate_simulated_conversation_async(
    *,
    objective: str,
    adversarial_chat: Any,
    objective_scorer: Any,
    num_turns: int = 3,
    starting_sequence: int = 0,
    adversarial_chat_system_prompt_path: Optional[Any] = None,
    simulated_target_system_prompt_path: Optional[Any] = None,
    next_message_system_prompt_path: Optional[Any] = None,
    preset: Optional[str] = None,
) -> List[SeedPrompt]:
    """
    生成模拟对话 — 封装 PyRIT 原生 generate_simulated_conversation_async

    对抗 LLM 与模拟目标之间的多轮对话（同一个 LLM 扮演两个角色）。
    结果是 list[SeedPrompt]，可包装在 SeedGroup 中，作为 prepended_conversation
    喂给任何多轮攻击。

    支持两种调用方式：
    1. 显式指定路径（原生 API 兼容）
    2. 使用预置组合（preset="red_team_direct" 等）

    Args:
        objective: 攻击目标描述
        adversarial_chat: 对抗 LLM 的 PromptTarget
        objective_scorer: TrueFalseScorer 评分器
        num_turns: 对话轮数（默认 3）
        starting_sequence: 起始序列号（默认 0）
        adversarial_chat_system_prompt_path: 对抗聊天系统提示词路径
            如果为 None 且 preset 为 None，使用默认红队模板
        simulated_target_system_prompt_path: 模拟目标系统提示词路径
            如果为 None，默认使用 compliant.yaml
        next_message_system_prompt_path: 可选的下一消息生成提示词路径
        preset: 预置组合名称，如果指定则覆盖路径参数

    Returns:
        list[SeedPrompt]：生成的模拟对话种子提示列表

    Raises:
        ValueError: 如果 adversarial_chat 或 objective_scorer 为 None
        ImportError: 如果 PyRIT 原生 API 不可用
    """
    from pyrit.executor.attack import generate_simulated_conversation_async as _native_gen

    if adversarial_chat is None:
        raise ValueError("adversarial_chat is required for simulated conversation generation")
    if objective_scorer is None:
        raise ValueError("objective_scorer is required for simulated conversation generation")

    # 使用预置组合
    if preset:
        combo = get_preset(preset)
        adversarial_chat_system_prompt_path = combo["adversarial_chat_system_prompt_path"]
        simulated_target_system_prompt_path = combo["simulated_target_system_prompt_path"]
        next_message_system_prompt_path = combo["next_message_system_prompt_path"]

    # 默认值：使用 red_team_direct 预置
    if adversarial_chat_system_prompt_path is None:
        combo = get_preset("red_team_direct")
        adversarial_chat_system_prompt_path = combo["adversarial_chat_system_prompt_path"]
        if simulated_target_system_prompt_path is None:
            simulated_target_system_prompt_path = combo["simulated_target_system_prompt_path"]
        if next_message_system_prompt_path is None:
            next_message_system_prompt_path = combo["next_message_system_prompt_path"]

    logger.info(
        f"Generating simulated conversation: objective='{objective[:80]}...', "
        f"num_turns={num_turns}, starting_sequence={starting_sequence}"
    )

    simulated_prompts = await _native_gen(
        objective=objective,
        adversarial_chat=adversarial_chat,
        objective_scorer=objective_scorer,
        num_turns=num_turns,
        starting_sequence=starting_sequence,
        adversarial_chat_system_prompt_path=adversarial_chat_system_prompt_path,
        simulated_target_system_prompt_path=simulated_target_system_prompt_path,
        next_message_system_prompt_path=next_message_system_prompt_path,
    )

    logger.info(f"Generated {len(simulated_prompts)} simulated conversation prompts")
    return simulated_prompts


# ============================================================
# 预计算 + 重放流程
# ============================================================


async def precompute_simulated_conversation_async(
    *,
    objective: str,
    adversarial_chat: Any,
    objective_scorer: Any,
    num_turns: int = 3,
    preset: Optional[str] = None,
    starting_sequence: int = 0,
) -> AttackSeedGroup:
    """
    预计算模拟对话 — 生成对话并封装为 AttackSeedGroup

    生成的 AttackSeedGroup 包含：
    - 一个 SeedObjective
    - 生成的 SeedPrompt 序列（模拟对话内容）
    这些 AttackSeedGroup 可被保存/传输，后续对多个不同目标重放。

    Args:
        objective: 攻击目标
        adversarial_chat: 对抗 LLM target
        objective_scorer: 评分器
        num_turns: 对话轮数
        preset: 预置组合名称
        starting_sequence: 起始序列号

    Returns:
        AttackSeedGroup：包含预计算对话的种子组
    """
    simulated_prompts = await generate_simulated_conversation_async(
        objective=objective,
        adversarial_chat=adversarial_chat,
        objective_scorer=objective_scorer,
        num_turns=num_turns,
        starting_sequence=starting_sequence,
        preset=preset,
    )

    # 构建 AttackSeedGroup（objective + 生成的对话种子）
    seeds: List[Seed] = [
        SeedObjective(value=objective),
        *simulated_prompts,
    ]

    return AttackSeedGroup(seeds=seeds)


async def precompute_batch_async(
    *,
    objectives: Sequence[str],
    adversarial_chat: Any,
    objective_scorer: Any,
    num_turns: int = 3,
    preset: Optional[str] = None,
    max_concurrency: int = 3,
) -> List[AttackSeedGroup]:
    """
    批量预计算模拟对话

    为多个目标并行生成模拟对话前缀，每个目标一个 AttackSeedGroup。
    后续可对不同目标重放这些预计算的对话。

    Args:
        objectives: 攻击目标列表
        adversarial_chat: 对抗 LLM target
        objective_scorer: 评分器
        num_turns: 对话轮数
        preset: 预置组合名称
        max_concurrency: 最大并发数

    Returns:
        AttackSeedGroup 列表（与 objectives 一一对应）
    """
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _compute_one(obj: str) -> AttackSeedGroup:
        async with semaphore:
            return await precompute_simulated_conversation_async(
                objective=obj,
                adversarial_chat=adversarial_chat,
                objective_scorer=objective_scorer,
                num_turns=num_turns,
                preset=preset,
            )

    tasks = [_compute_one(obj) for obj in objectives]
    return await asyncio.gather(*tasks)


async def replay_to_target_async(
    *,
    precomputed_group: AttackSeedGroup,
    attack: Any,
    objective_target: Any,
    executor: Any,
    adversarial_chat: Any = None,
    objective_scorer: Any = None,
    memory_labels: Optional[Dict[str, str]] = None,
) -> Any:
    """
    将预计算的模拟对话重放到指定目标

    "预计算 → 重放"流程的核心：
    1. precompute_simulated_conversation_async() 生成对话前缀
    2. replay_to_target_async() 将前缀注入攻击并执行

    由于预计算的 AttackSeedGroup 已经包含 SeedPrompt（而非 SeedSimulatedConversation），
    重放时不需要 adversarial_chat / objective_scorer 来生成对话 —
    对话已经预生成了。但攻击本身可能仍需要 adversarial_chat（如 crescendo/red_teaming）。

    Args:
        precomputed_group: 预计算的 AttackSeedGroup（含模拟对话种子）
        attack: AttackStrategy 实例
        objective_target: 目标 PromptTarget
        executor: NativeAttackExecutor 或原生 AttackExecutor 实例
        adversarial_chat: 攻击策略需要的对抗 LLM（多轮攻击需要）
        objective_scorer: 评分器（攻击策略需要）
        memory_labels: 可选的 memory_labels

    Returns:
        AttackExecutorResult 或单个 AttackResult
    """
    broadcast_fields: Dict[str, Any] = {}
    if memory_labels:
        broadcast_fields["memory_labels"] = memory_labels

    # 预计算对话已经包含 SeedPrompt（非 SeedSimulatedConversation），
    # 因此 from_seed_group_async 不会尝试重新生成对话
    result = await executor.execute_attack_from_seed_groups_async(
        attack=attack,
        seed_groups=[precomputed_group],
        adversarial_chat=adversarial_chat,
        objective_scorer=objective_scorer,
        **broadcast_fields,
    )
    return result


# ============================================================
# SeedSimulatedConversation 配置创建
# ============================================================


def create_simulated_conversation_seed(
    *,
    objective: str,
    num_turns: int = 3,
    sequence: int = 0,
    preset: Optional[str] = None,
    adversarial_chat_system_prompt_path: Optional[Any] = None,
    simulated_target_system_prompt_path: Optional[Any] = None,
    next_message_system_prompt_path: Optional[Any] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> SeedSimulatedConversation:
    """
    创建 SeedSimulatedConversation 配置种子

    这个配置种子可添加到 SeedGroup 中，在执行时由
    AttackParameters.from_seed_group_async() 自动触发对话生成。

    两种使用模式：
    1. 延迟生成（推荐）：创建配置种子 → 加入 SeedGroup → 执行时自动生成
    2. 预计算：precompute_simulated_conversation_async() → 直接生成对话

    Args:
        objective: 攻击目标（仅用于 metadata，实际 objective 从 SeedGroup 获取）
        num_turns: 对话轮数
        sequence: 起始序列号
        preset: 预置组合名称（覆盖路径参数）
        adversarial_chat_system_prompt_path: 对抗聊天系统提示词路径
        simulated_target_system_prompt_path: 模拟目标系统提示词路径
        next_message_system_prompt_path: 下一消息提示词路径
        metadata: 额外元数据

    Returns:
        SeedSimulatedConversation 实例
    """
    if preset:
        combo = get_preset(preset)
        adversarial_chat_system_prompt_path = combo["adversarial_chat_system_prompt_path"]
        simulated_target_system_prompt_path = combo["simulated_target_system_prompt_path"]
        next_message_system_prompt_path = combo["next_message_system_prompt_path"]

    # 默认值
    if adversarial_chat_system_prompt_path is None:
        combo = get_preset("red_team_direct")
        adversarial_chat_system_prompt_path = combo["adversarial_chat_system_prompt_path"]
        if simulated_target_system_prompt_path is None:
            simulated_target_system_prompt_path = combo["simulated_target_system_prompt_path"]
        if next_message_system_prompt_path is None:
            next_message_system_prompt_path = combo["next_message_system_prompt_path"]

    extra_meta = {
        "objective": objective,
    }
    if metadata:
        extra_meta.update(metadata)

    return SeedSimulatedConversation(
        num_turns=num_turns,
        sequence=sequence,
        adversarial_chat_system_prompt_path=adversarial_chat_system_prompt_path,
        simulated_target_system_prompt_path=simulated_target_system_prompt_path,
        next_message_system_prompt_path=next_message_system_prompt_path,
        metadata=extra_meta,
    )


def inject_simulated_conversation_into_group(
    seed_group: SeedGroup,
    *,
    num_turns: int = 3,
    sequence: int = 0,
    preset: Optional[str] = None,
    adversarial_chat_system_prompt_path: Optional[Any] = None,
    simulated_target_system_prompt_path: Optional[Any] = None,
    next_message_system_prompt_path: Optional[Any] = None,
) -> AttackSeedGroup:
    """
    将 SeedSimulatedConversation 注入现有 SeedGroup

    将模拟对话配置添加到种子组中，使其在执行时自动触发对话生成。
    如果原 SeedGroup 没有 objective，自动从第一个 SeedPrompt 创建合成 objective。

    注意：注入的 SeedSimulatedConversation 的序列范围不能与现有
    SeedPrompt 的序列重叠。如果原种子组有 sequence=0,1,2 的 SeedPrompt，
    应将 sequence 设为更大值（如 10）以避免冲突。

    Args:
        seed_group: 原始 SeedGroup
        num_turns: 对话轮数
        sequence: 起始序列号（确保不与现有 SeedPrompt 序列重叠）
        preset: 预置组合名称
        adversarial_chat_system_prompt_path: 对抗聊天系统提示词路径
        simulated_target_system_prompt_path: 模拟目标系统提示词路径
        next_message_system_prompt_path: 下一消息提示词路径

    Returns:
        AttackSeedGroup（含 SeedSimulatedConversation 配置）
    """
    # 确保有 objective
    seeds = list(seed_group.seeds)
    has_objective = any(isinstance(s, SeedObjective) for s in seeds)
    if not has_objective:
        prompts = [s for s in seeds if isinstance(s, SeedPrompt)]
        if prompts:
            synthetic = SeedObjective(
                value=prompts[0].value,
                dataset_name=getattr(prompts[0], "dataset_name", "synthetic"),
                harm_categories=getattr(seed_group, "harm_categories", []) or [],
                metadata={"synthetic_objective": True},
            )
            seeds = [synthetic, *seeds]

    # 创建模拟对话配置种子
    sim_seed = create_simulated_conversation_seed(
        objective=seeds[0].value if isinstance(seeds[0], SeedObjective) else "",
        num_turns=num_turns,
        sequence=sequence,
        preset=preset,
        adversarial_chat_system_prompt_path=adversarial_chat_system_prompt_path,
        simulated_target_system_prompt_path=simulated_target_system_prompt_path,
        next_message_system_prompt_path=next_message_system_prompt_path,
    )

    # 构建新的 AttackSeedGroup（PyRIT 会自动验证序列不重叠）
    return AttackSeedGroup(seeds=[*seeds, sim_seed])


# ============================================================
# 便捷函数：一键创建带模拟对话的 AttackSeedGroup
# ============================================================


def create_attack_with_simulated_conversation(
    *,
    objective: str,
    num_turns: int = 3,
    preset: str = "red_team_direct",
    harm_categories: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AttackSeedGroup:
    """
    一键创建带模拟对话配置的 AttackSeedGroup

    创建一个仅包含 SeedObjective + SeedSimulatedConversation 的 AttackSeedGroup。
    执行时由 from_seed_group_async() 自动生成对话。

    这是最简单的模拟对话使用方式 — 只需提供 objective 和 num_turns。

    Args:
        objective: 攻击目标
        num_turns: 对话轮数
        preset: 预置组合名称
        harm_categories: 危害类别列表
        metadata: 额外元数据

    Returns:
        AttackSeedGroup（含模拟对话配置，执行时自动生成）
    """
    extra_meta: Dict[str, Any] = {"objective": objective}
    if metadata:
        extra_meta.update(metadata)

    obj = SeedObjective(
        value=objective,
        harm_categories=harm_categories or [],
        metadata=extra_meta,
    )

    sim_seed = create_simulated_conversation_seed(
        objective=objective,
        num_turns=num_turns,
        preset=preset,
    )

    return AttackSeedGroup(seeds=[obj, sim_seed])
