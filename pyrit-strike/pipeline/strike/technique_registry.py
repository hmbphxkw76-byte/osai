"""AttackTechniqueFactory 注册 — 将项目攻击技术注册到 PyRIT 原生 registry。
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

    # v51: PyRIT 原生对齐 — 注册 RedTeamingAttack
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
