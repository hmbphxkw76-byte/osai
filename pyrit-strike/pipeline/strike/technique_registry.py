"""AttackTechniqueFactory 注册 — 将项目攻击技术注册到 PyRIT 原生 registry。

利用 PyRIT 1.0.1 原生 AttackTechniqueFactory + AttackTechniqueRegistry，
将项目的攻击技术（PromptSending + Crescendo + TAP + PAIR + Best-of-N）
注册为可被 TextAdaptive 场景自动发现和选择的技术。

学术依据:
    - PyRIT (arXiv:2407.01232) — AttackTechniqueFactory + Registry 设计,
      scenarios 通过 tag 查询自动发现技术
    - Chao et al. (arXiv:2310.08419) — PAIR 自适应策略选择
    - Mehrotra et al. (arXiv:2312.02191) — TAP 树搜索
    - Russinovich et al. (arXiv:2402.12109) — Crescendo 渐进升级
    - Chao et al. (arXiv:2402.01135) — Best-of-N ASR 提升 1.8x

PyRIT 原生优先 (Rule 2):
    本模块是胶水层 — 将项目配置参数注入 PyRIT 原生 AttackTechniqueFactory,
    不替换任何原生组件。Factory.create() 调用时使用原生 PromptSendingAttack /
    CrescendoAttack / TAPAttack / PAIRAttack 作为 attack_class。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def register_project_techniques(
    *,
    adversarial_target: Any | None = None,
    converter_target: Any | None = None,
) -> dict[str, Any]:
    """将项目攻击技术注册到 PyRIT 原生 AttackTechniqueRegistry。

    构建 AttackTechniqueFactory 实例并注册到全局 registry，
    使 TextAdaptive 场景能自动发现和选择这些技术。

    技术列表 (按 L5 优先级):
        1. PromptSending (baseline, single_turn tag)
        2. Crescendo (multi_turn tag)
        3. TAP (multi_turn tag, tree search)
        4. PAIR (multi_turn tag, iterative)
        5. Best-of-N (single_turn tag, variation retry)

    学术依据:
        - PyRIT (arXiv:2407.01232) — AttackTechniqueRegistry + tag 查询
        - Wei et al. (arXiv:2307.15043) — 单轮多路径独立执行
        - Russinovich et al. (arXiv:2402.12109) — Crescendo ASR=82%
        - Mehrotra et al. (arXiv:2312.02191) — TAP 树搜索
        - Chao et al. (arXiv:2310.08419) — PAIR 迭代优化
        - Chao et al. (arXiv:2402.01135) — Best-of-N N=5 ASR 1.8x

    Args:
        adversarial_target: 多轮攻击的 adversarial chat target (可选)。
        converter_target: Converter 使用的 LLM target (可选, 用于 Best-of-N)。

    Returns:
        注册的 factory 名称→factory 映射字典。空字典表示注册失败。
    """
    try:
        from pyrit.executor.attack import (
            PAIRAttack,
            PromptSendingAttack,
            RedTeamingAttack,
            RTASystemPromptPaths,
            TAPAttack,
        )
        from pyrit.scenario.core.attack_technique_factory import (
            AttackTechniqueFactory,
        )
        try:
            from pyrit.executor.attack import CrescendoAttack
        except ImportError:
            CrescendoAttack = None  # type: ignore[assignment,misc]
    except ImportError as e:
        logger.warning("PyRIT attack classes not available: %s — technique registration skipped", e)
        return {}

    factories: list[AttackTechniqueFactory] = []

    # ── 1. PromptSending (baseline) ──
    # arXiv:2307.15043 — 单轮基线, 多路径独立执行的基础
    # v51: 对齐官方 — SkeletonKey 的 prepended_conversation 通过 execute_async 传入
    try:
        ps_factory = AttackTechniqueFactory(
            name="PromptSending",
            attack_class=PromptSendingAttack,
            description="Single-turn baseline attack with SkeletonKey prepended conversation (arXiv:2307.15043, arXiv:2406.18112)",
            technique_tags=["single_turn", "default", "baseline"],
        )
        factories.append(ps_factory)
        logger.info("Registered AttackTechniqueFactory: PromptSending (single_turn, baseline)")
    except Exception as e:
        logger.warning("Failed to create PromptSending factory: %s", e)

    # ── 2. Crescendo (multi-turn) ──
    # arXiv:2402.12109 — Russinovich et al., 10 turns ASR=82%
    # v51: 对齐官方 — 添加 Crescendo 专用 system_prompt
    if CrescendoAttack is not None and adversarial_target is not None:
        try:
            # v51: 尝试加载官方 Crescendo system_prompt
            crescendo_system_prompt = None
            try:
                from pyrit.common.path import EXECUTOR_SEED_PROMPT_PATH
                crescendo_prompt_path = EXECUTOR_SEED_PROMPT_PATH / "crescendo" / "text_generation.yaml"
                if crescendo_prompt_path.exists():
                    from pyrit.models import SeedPrompt
                    crescendo_system_prompt = SeedPrompt.from_yaml_file(str(crescendo_prompt_path))
                    logger.info("v51: Crescendo technique using official system_prompt")
            except Exception as e:
                logger.debug("v51: Crescendo system_prompt not available: %s", e)

            crescendo_kwargs: dict[str, Any] = {
                "name": "Crescendo",
                "attack_class": CrescendoAttack,
                "description": "Multi-turn progressive escalation with official system_prompt (arXiv:2402.12109)",
                "technique_tags": ["multi_turn", "escalation"],
                "attack_kwargs": {
                    "max_turns": 10,
                    "max_backtracks": 10,
                },
                "adversarial_chat": adversarial_target,
            }
            if crescendo_system_prompt is not None:
                crescendo_kwargs["adversarial_system_prompt"] = crescendo_system_prompt
            crescendo_factory = AttackTechniqueFactory(**crescendo_kwargs)
            factories.append(crescendo_factory)
            logger.info("Registered AttackTechniqueFactory: Crescendo (multi_turn, max_turns=10)")
        except Exception as e:
            logger.warning("Failed to create Crescendo factory: %s", e)

    # ── 3. TAP (multi-turn, tree search) ──
    # arXiv:2312.02191 — Mehrotra et al., tree-of-attacks with pruning
    if adversarial_target is not None:
        try:
            tap_factory = AttackTechniqueFactory(
                name="TAP",
                attack_class=TAPAttack,
                description="Tree-of-attacks with pruning (arXiv:2312.02191)",
                technique_tags=["multi_turn", "escalation", "tree_search"],
                attack_kwargs={
                    "tree_width": 4,
                    "tree_depth": 4,
                    "branching_factor": 2,
                },
                adversarial_chat=adversarial_target,
            )
            factories.append(tap_factory)
            logger.info("Registered AttackTechniqueFactory: TAP (multi_turn, width=4, depth=4)")
        except Exception as e:
            logger.warning("Failed to create TAP factory: %s", e)

    # ── 4. PAIR (multi-turn, iterative) ──
    # arXiv:2310.08419 — Chao et al., iterative adversarial prompting
    if adversarial_target is not None:
        try:
            pair_factory = AttackTechniqueFactory(
                name="PAIR",
                attack_class=PAIRAttack,
                description="Iterative adversarial prompting (arXiv:2310.08419)",
                technique_tags=["multi_turn", "escalation", "iterative"],
                adversarial_chat=adversarial_target,
            )
            factories.append(pair_factory)
            logger.info("Registered AttackTechniqueFactory: PAIR (multi_turn, iterative)")
        except Exception as e:
            logger.warning("Failed to create PAIR factory: %s", e)

    # ── 5. Best-of-N (single-turn, variation retry) ──
    # arXiv:2402.01135 — Chao et al., N=5 ASR 1.8x
    # 使用 PromptSendingAttack 作为 attack_class, converter 配置注入 VariationConverter
    if converter_target is not None:
        try:
            from pyrit.executor.attack import AttackConverterConfig
            from pyrit.prompt_normalizer import ConverterConfiguration

            from pipeline.arm.converter_chains import _conv

            VariationConverter = _conv("VariationConverter")
            variation_conv = VariationConverter(converter_target=converter_target)

            bon_factory = AttackTechniqueFactory(
                name="BestOfN",
                attack_class=PromptSendingAttack,
                description="Best-of-N variation retry, N=5 (arXiv:2402.01135)",
                technique_tags=["single_turn", "variation", "best_of_n"],
                attack_kwargs={
                    "attack_converter_config": AttackConverterConfig(
                        request_converters=[
                            ConverterConfiguration(converters=[variation_conv]),
                        ],
                    ),
                },
            )
            factories.append(bon_factory)
            logger.info("Registered AttackTechniqueFactory: BestOfN (single_turn, variation)")
        except Exception as e:
            logger.warning("Failed to create BestOfN factory: %s", e)

    # ── 6. RedTeaming (multi-turn baseline) ──
    # v51: PyRIT 原生对齐 — 注册 RedTeamingAttack
    # arXiv:2407.01232 — RedTeamingAttack 是官方最通用的 multi-turn baseline
    # 使用 RTASystemPromptPaths.TEXT_GENERATION 作为 system_prompt
    if adversarial_target is not None:
        try:
            # 尝试加载官方 RTA system prompt
            rta_system_prompt = None
            try:
                from pyrit.models import SeedPrompt
                rta_system_prompt = SeedPrompt.from_yaml_file(
                    RTASystemPromptPaths.TEXT_GENERATION.value
                )
                logger.info("v51: RedTeaming technique using RTASystemPromptPaths.TEXT_GENERATION")
            except Exception as e:
                logger.debug("v51: RTA system_prompt not available: %s", e)

            rt_kwargs: dict[str, Any] = {
                "name": "RedTeaming",
                "attack_class": RedTeamingAttack,
                "description": "Multi-turn Red Teaming with RTA system prompt (arXiv:2407.01232)",
                "technique_tags": ["multi_turn", "baseline"],
                "attack_kwargs": {
                    "max_turns": 5,
                },
                "adversarial_chat": adversarial_target,
            }
            if rta_system_prompt is not None:
                rt_kwargs["adversarial_system_prompt"] = rta_system_prompt
            rt_factory = AttackTechniqueFactory(**rt_kwargs)
            factories.append(rt_factory)
            logger.info("Registered AttackTechniqueFactory: RedTeaming (multi_turn, baseline)")
        except Exception as e:
            logger.warning("Failed to create RedTeaming factory: %s", e)

    # ── 注册到全局 AttackTechniqueRegistry ──
    if not factories:
        logger.warning("No AttackTechniqueFactories created — technique registration skipped")
        return {}

    try:
        from pyrit.registry import AttackTechniqueRegistry

        registry = AttackTechniqueRegistry.get_registry_singleton()
        registry.register_from_factories(factories)

        registered = {f.name: f for f in factories}
        logger.info(
            "Registered %d AttackTechniqueFactories to PyRIT registry: %s",
            len(registered),
            ", ".join(registered.keys()),
        )
        return registered
    except Exception as e:
        logger.warning("Failed to register techniques to PyRIT registry: %s", e)
        return {f.name: f for f in factories}


def build_sequential_child_attacks(
    *,
    objective_target: Any,
    scoring_config: Any,
    candidate_converters: list[Any],
    seed_group: Any,
) -> list[Any]:
    """构建 SequentialAttack 的 child attacks 列表 — 原生 FIRST_SUCCESS 多路径。

    使用 PyRIT 原生 SequentialAttack + SequentialChildAttack 替代
    executor.py 中的手动多路径循环。

    每个 converter 对应一个独立的 PromptSendingAttack (1 converter per path),
    任一路径成功 (FIRST_SUCCESS) 则跳过后续路径。

    学术依据:
        - PyRIT SequentialAttack (arXiv:2407.01232) — FIRST_SUCCESS 策略
        - Wei et al. (arXiv:2307.15043) — 串联 >2 层 ASR 从 12% 降至 4%
        - Zeng et al. (arXiv:2402.19181) — authority ASR 38.4% 最高
        - DrAttack (arXiv:2402.14266) — 分解重组 ASR 40-60% 最高

    Args:
        objective_target: 被攻击的 PyRIT PromptTarget。
        scoring_config: AttackScoringConfig (FIRST_SUCCESS 轻量评分)。
        candidate_converters: 候选 converter 列表 (按 ASR 降序)。
        seed_group: AttackSeedGroup (包含攻击 objective)。

    Returns:
        SequentialChildAttack 列表 (每个 converter 一条路径)。
        空列表表示无 converter 或构建失败。
    """
    try:
        from pyrit.executor.attack import (
            AttackConverterConfig,
            PromptSendingAttack,
        )
        from pyrit.executor.attack.compound.sequential_attack import (
            SequentialChildAttack,
        )
        from pyrit.prompt_normalizer import ConverterConfiguration
    except ImportError as e:
        logger.warning("PyRIT SequentialAttack modules not available: %s", e)
        return []

    child_attacks: list[SequentialChildAttack] = []

    for conv in candidate_converters:
        conv_name = type(conv).__name__
        try:
            conv_config = AttackConverterConfig(
                request_converters=[ConverterConfiguration(converters=[conv])],
            )
            attack = PromptSendingAttack(
                objective_target=objective_target,
                attack_scoring_config=scoring_config,
                attack_converter_config=conv_config,
            )
            child = SequentialChildAttack(
                strategy=attack,
                seed_group=seed_group,
            )
            child_attacks.append(child)
            logger.info("SequentialAttack child: %s (path %d)", conv_name, len(child_attacks))
        except Exception as e:
            logger.warning("Failed to build SequentialChildAttack for %s: %s", conv_name, e)

    return child_attacks


def get_technique_class_for_adaptive(
    *,
    adversarial_target: Any | None = None,
    converter_target: Any | None = None,
) -> type | None:
    """构建用于 TextAdaptive 场景的动态 ScenarioTechnique 类。

    将项目注册的 AttackTechniqueFactory 列表转换为
    ScenarioTechnique 子类, 供 TextAdaptive 的
    EpsilonGreedyTechniqueSelector 使用。

    学术依据:
        - PyRIT (arXiv:2407.01232) — AttackTechniqueRegistry.build_technique_class_from_factories
        - Chao et al. (arXiv:2310.08419) — ε-贪心自适应技术选择

    Args:
        adversarial_target: 多轮攻击的 adversarial chat target (可选)。
        converter_target: Converter 使用的 LLM target (可选)。

    Returns:
        动态生成的 ScenarioTechnique 子类, 或 None (构建失败时)。
    """
    factories_dict = register_project_techniques(
        adversarial_target=adversarial_target,
        converter_target=converter_target,
    )
    if not factories_dict:
        return None

    try:
        from pyrit.registry import AttackTechniqueRegistry

        registry = AttackTechniqueRegistry.get_registry_singleton()
        all_factories = list(registry.get_factories().values())
        if not all_factories:
            all_factories = list(factories_dict.values())

        technique_cls = AttackTechniqueRegistry.build_technique_class_from_factories(
            class_name="PyritStrikeTechnique",
            factories=all_factories,
            default_tags={"single_turn"},
        )
        logger.info(
            "Built ScenarioTechnique class '%s' with %d techniques for TextAdaptive",
            technique_cls.__name__,
            len([t for t in technique_cls if t.value not in technique_cls.get_aggregate_tags()]),
        )
        return technique_cls
    except Exception as e:
        logger.warning("Failed to build technique class for adaptive: %s", e)
        return None
