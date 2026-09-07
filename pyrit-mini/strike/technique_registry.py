# arXiv:2302.12173 - Greshake et al., PromptSendingAttack
# arXiv:2404.01833 - Russinovich et al., CrescendoAttack
# arXiv:2405.17350 - Mehrabi et al., TAPAttack
# arXiv:2404.02151 - Hughes et al., BestOfN
# arXiv:2402.14266 - SKELETONKEY, SkeletonKey
"""AttackTechniqueFactory ㄥ ? PyRIT  registry?

╃ PyRIT 1.0.1  AttackTechniqueFactory + AttackTechniqueRegistry?
€PromptSending + Crescendo + TAP + PAIR + Best-of-N?
ㄥ?TextAdaptive €€?

︽:
    - PyRIT (arXiv:2407.01232) ?AttackTechniqueFactory + Registry ,
      scenarios  tag ヨ€?
    - Chao et al. (arXiv:2310.08419) ?PAIR €
    - Mehrotra et al. (arXiv:2312.02191) ?TAP ?
    - Russinovich et al. (arXiv:2402.12109) ?Crescendo 
    - Chao et al. (arXiv:2402.01135) ?Best-of-N ASR  1.8x

PyRIT  (Rule 2):
    ā???PyRIT  AttackTechniqueFactory,
    €actory.create() ㄥ?PromptSendingAttack /
    CrescendoAttack / TAPAttack / PAIRAttack  attack_class?
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def register_project_techniques(
    *,
    adversarial_target: Any | None = None,
    converter_target: Any | None = None,
    config_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """ PyRIT  AttackTechniqueRegistry?

     AttackTechniqueFactory ㄥ registry?
    ?TextAdaptive ㄥ€€?

    €?(?L5 ?:
        1. PromptSending (baseline, single_turn tag)
        2. Crescendo (multi_turn tag)
        3. TAP (multi_turn tag, tree search)
        4. PAIR (multi_turn tag, iterative)
        5. Best-of-N (single_turn tag, variation retry)
        6. RedTeaming (multi_turn tag, baseline)
        7. SkeletonKey (single_turn tag, prefix injection)

    ︽:
        - PyRIT (arXiv:2407.01232) ?AttackTechniqueRegistry + tag ヨ
        - Wei et al. (arXiv:2307.15043) ??
        - Russinovich et al. (arXiv:2402.12109) ?Crescendo ASR=82%
        - Mehrotra et al. (arXiv:2312.02191) ?TAP ?
        - Chao et al. (arXiv:2310.08419) ?PAIR 
        - Chao et al. (arXiv:2402.01135) ?Best-of-N N=5 ASR 1.8x

    Args:
        adversarial_target: ?adversarial chat target (€??
        converter_target: Converter ?LLM target (€? ㄤ Best-of-N)?

    Returns:
        ㄥ?factory Оactory ┖ㄧずㄥ?
    """
    try:
        from pyrit.executor.attack import (
            PAIRAttack,
            PromptSendingAttack,
            RedTeamingAttack,
            RTASystemPromptPaths,
            SkeletonKeyAttack,
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
        logger.warning("PyRIT attack classes not available: %s ?technique registration skipped", e)
        return {}

    factories: list[AttackTechniqueFactory] = []

    # €€ 1. PromptSending (baseline) €€
    # arXiv:2307.15043 ?, 
    # v51:  ?SkeletonKey ?prepended_conversation  execute_async 
    try:
        ps_factory = AttackTechniqueFactory(
            name="PromptSending",
            attack_class=PromptSendingAttack,
            description="Single-turn baseline attack with SkeletonKey prepended conversation (arXiv:2307.15043, arXiv:2406.18112)",
            technique_tags=[
                "single_turn", "baseline", "default", "light",
                # v60:  tag — 
                "mcp_targeted", "agent_targeted", "rag_targeted", "general",
            ],
        )
        factories.append(ps_factory)
        logger.info("Registered AttackTechniqueFactory: PromptSending (single_turn, baseline, universal)")
    except Exception as e:
        logger.warning("Failed to create PromptSending factory: %s", e)

    # €€ 2. Crescendo (multi-turn) €€
    # arXiv:2402.12109 ?Russinovich et al., 10 turns ASR=82%
    # v51:  ? Crescendo  system_prompt
    if CrescendoAttack is not None and adversarial_target is not None:
        try:
            # v51:  Crescendo system_prompt
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
                "technique_tags": [
                    "multi_turn", "escalation", "light",
                    "agent_targeted",  # v60: Agent 
                ],
                "attack_kwargs": {
                    "max_turns": (config_overrides or {}).get("crescendo_max_turns", 10),
                    "max_backtracks": (config_overrides or {}).get("crescendo_max_backtracks", 5),
                },
                "adversarial_chat": adversarial_target,
            }
            if crescendo_system_prompt is not None:
                crescendo_kwargs["adversarial_system_prompt"] = crescendo_system_prompt
            crescendo_factory = AttackTechniqueFactory(**crescendo_kwargs)
            factories.append(crescendo_factory)
            logger.info("Registered AttackTechniqueFactory: Crescendo (multi_turn, max_turns from config)")
        except Exception as e:
            logger.warning("Failed to create Crescendo factory: %s", e)

    # €€ 3. TAP (multi-turn, tree search) €€
    # arXiv:2312.02191 ?Mehrotra et al., tree-of-attacks with pruning
    if adversarial_target is not None:
        try:
            _cfg = config_overrides or {}
            tap_factory = AttackTechniqueFactory(
                name="TAP",
                attack_class=TAPAttack,
                description="Tree-of-attacks with pruning (arXiv:2312.02191)",
                technique_tags=[
                    "multi_turn", "escalation", "tree_search",
                    "agent_targeted",  # v60: Agent 
                ],
                attack_kwargs={
                    "tree_width": _cfg.get("tap_tree_width", 4),
                    "tree_depth": _cfg.get("tap_tree_depth", 4),
                    "branching_factor": _cfg.get("tap_branching_factor", 2),
                },
                adversarial_chat=adversarial_target,
            )
            factories.append(tap_factory)
            logger.info(
                "Registered AttackTechniqueFactory: TAP (multi_turn, width=%d, depth=%d)",
                _cfg.get("tap_tree_width", 4), _cfg.get("tap_tree_depth", 4),
            )
        except Exception as e:
            logger.warning("Failed to create TAP factory: %s", e)

    # €€ 4. PAIR (multi-turn, iterative) €€
    # arXiv:2310.08419 ?Chao et al., iterative adversarial prompting
    if adversarial_target is not None:
        try:
            pair_factory = AttackTechniqueFactory(
                name="PAIR",
                attack_class=PAIRAttack,
                description="Iterative adversarial prompting (arXiv:2310.08419)",
                technique_tags=[
                    "multi_turn", "escalation", "iterative",
                    "agent_targeted",  # v60: Agent 
                ],
                adversarial_chat=adversarial_target,
            )
            factories.append(pair_factory)
            logger.info("Registered AttackTechniqueFactory: PAIR (multi_turn, iterative, agent_targeted)")
        except Exception as e:
            logger.warning("Failed to create PAIR factory: %s", e)

    # €€ 5. Best-of-N (single-turn, variation retry) €€
    # arXiv:2402.01135 ?Chao et al., N=5 ASR 1.8x
    #  PromptSendingAttack  attack_class, converter ㄥ VariationConverter
    if converter_target is not None:
        try:
            from pyrit.executor.attack import AttackConverterConfig
            from pyrit.prompt_normalizer import ConverterConfiguration

            from arm.converter_chains import _conv

            VariationConverter = _conv("VariationConverter")
            variation_conv = VariationConverter(converter_target=converter_target)

            bon_factory = AttackTechniqueFactory(
                name="BestOfN",
                attack_class=PromptSendingAttack,
                description="Best-of-N variation retry, N=5 (arXiv:2402.01135)",
                technique_tags=[
                    "single_turn", "variation", "best_of_n",
                    "mcp_targeted", "rag_targeted", "general",  # v60: MCP/RAG/
                ],
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

    # €€ 6. RedTeaming (multi-turn baseline) €€
    # v51: PyRIT  ?ㄥ RedTeamingAttack
    # arXiv:2407.01232 ?RedTeamingAttack ?multi-turn baseline
    #  RTASystemPromptPaths.TEXT_GENERATION  system_prompt
    if adversarial_target is not None:
        try:
            #  RTA system prompt
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
                "technique_tags": [
                    "multi_turn", "baseline", "light",
                    "agent_targeted",  # v60: Agent 
                ],
                "attack_kwargs": {
                    "max_turns": (config_overrides or {}).get("red_teaming_max_turns", 3),
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

    # €? 7. SkeletonKey (single-turn, prefix injection) €€
    # arXiv:2406.18112 ?Hanna et al., SkeletonKey ASR 80-95%
    # PyRIT  SkeletonKeyAttack:  skeleton key prompt + ℃ュ
    #  prepended_conversation ㄥ (, )
    try:
        sk_factory = AttackTechniqueFactory(
            name="SkeletonKey",
            attack_class=SkeletonKeyAttack,
            description="Single-turn SkeletonKey prefix injection (arXiv:2406.18112)",
            technique_tags=[
                "single_turn", "prefix_injection",
                "general",  # v60: 
            ],
        )
        factories.append(sk_factory)
        logger.info("Registered AttackTechniqueFactory: SkeletonKey (single_turn, prefix_injection, general)")
    except Exception as e:
        logger.warning("Failed to create SkeletonKey factory: %s", e)

    # == 8. ManyShotJailbreak (single-turn, many-shot) ==
    # arXiv:2402.05124 — Anthropic, Many-Shot Jailbreaking
    # PyRIT  ManyShotJailbreakAttack: 100 shots ASR 
    #  in-context learning 
    try:
        from pyrit.executor.attack import ManyShotJailbreakAttack

        _cfg = config_overrides or {}
        _ms_count = _cfg.get("many_shot_example_count", 100)
        ms_factory = AttackTechniqueFactory(
            name="ManyShotJailbreak",
            attack_class=ManyShotJailbreakAttack,
            description="Many-shot jailbreak with faux Q/A examples (arXiv:2402.05124)",
            technique_tags=["single_turn", "many_shot"],
            attack_kwargs={
                "example_count": _ms_count,
            },
        )
        factories.append(ms_factory)
        logger.info(
            "Registered AttackTechniqueFactory: ManyShotJailbreak (single_turn, many_shot, count=%d)",
            _ms_count,
        )
    except Exception as e:
        logger.warning("Failed to create ManyShotJailbreak factory: %s", e)

    # == 9. MultiPromptSending (multi-turn, fixed sequence) ==
    # arXiv:2407.01232 — PyRIT, 
    # "", 3
    try:
        from pyrit.executor.attack import MultiPromptSendingAttack

        mps_factory = AttackTechniqueFactory(
            name="MultiPromptSending",
            attack_class=MultiPromptSendingAttack,
            description="Multi-turn fixed sequence attack, step-by-step guidance (arXiv:2407.01232)",
            technique_tags=["multi_turn", "fixed_sequence"],
        )
        factories.append(mps_factory)
        logger.info("Registered AttackTechniqueFactory: MultiPromptSending (multi_turn, fixed_sequence)")
    except Exception as e:
        logger.warning("Failed to create MultiPromptSending factory: %s", e)

    # == 10. ChunkedRequest (multi-turn, chunked extraction) ==
    # arXiv:2407.01232 — PyRIT, 
    # , /
    try:
        from pyrit.executor.attack import ChunkedRequestAttack

        _cfg = config_overrides or {}
        cr_factory = AttackTechniqueFactory(
            name="ChunkedRequest",
            attack_class=ChunkedRequestAttack,
            description="Chunked extraction attack, bypass length filters (arXiv:2407.01232)",
            technique_tags=["multi_turn", "chunked_extraction"],
            attack_kwargs={
                "chunk_size": _cfg.get("chunked_request_chunk_size", 50),
                "total_length": _cfg.get("chunked_request_total_length", 200),
                "chunk_type": "characters",
            },
        )
        factories.append(cr_factory)
        logger.info("Registered AttackTechniqueFactory: ChunkedRequest (multi_turn, chunked_extraction)")
    except Exception as e:
        logger.warning("Failed to create ChunkedRequest factory: %s", e)

    # €€ ㄥ€ AttackTechniqueRegistry €€
    if not factories:
        logger.warning("No AttackTechniqueFactories created ?technique registration skipped")
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


def build_scenario_techniques(
    *,
    technique_filter: list[str] | None = None,
    adversarial_target: Any | None = None,
    converter_target: Any | None = None,
) -> list[Any] | None:
    """v53: Build scenario_techniques list for TextAdaptive.

    Aligns with PyRIT official Adaptive Scenarios doc.
    Builds a list of ScenarioTechnique enum members for TextAdaptive's
    epsilon-greedy selector to choose from.

    PyRIT official API:
        technique_class = TextAdaptive.get_technique_class()
        scenario_techniques = [technique_class("single_turn")]
    When no filter is configured, returns None (TextAdaptive uses all registered techniques).

    Args:
        technique_filter: tag filter list (e.g. ["single_turn"]).
        adversarial_target: adversarial chat target for multi-turn attacks.
        converter_target: LLM target for converters.

    Returns:
        ScenarioTechnique enum member list, or None (use default).
    """
    if not technique_filter:
        return None

    technique_cls = get_technique_class_for_adaptive(
        adversarial_target=adversarial_target,
        converter_target=converter_target,
    )
    if technique_cls is None:
        logger.warning("v53: technique class build failed, using default techniques")
        return None

    try:
        techniques: list[Any] = []
        for tag_or_name in technique_filter:
            try:
                technique = technique_cls(tag_or_name)
                techniques.append(technique)
                logger.info("v53: Added scenario technique: %s", tag_or_name)
            except Exception as e:
                logger.debug("v53: technique '%s' not found in class: %s", tag_or_name, e)
        if techniques:
            return techniques
        logger.warning("v53: no matching techniques for filter %s", technique_filter)
        return None
    except Exception as e:
        logger.warning("v53: build_scenario_techniques failed: %s", e)
        return None


def build_sequential_child_attacks(
    *,
    objective_target: Any,
    scoring_config: Any,
    candidate_converters: list[Any],
    seed_group: Any,
) -> list[Any]:
    """ SequentialAttack ?child attacks  ? FIRST_SUCCESS €?

     PyRIT  SequentialAttack + SequentialChildAttack 
    executor.py €?

     converter € PromptSendingAttack (1 converter per path),
     (FIRST_SUCCESS) €?

    ︽:
        - PyRIT SequentialAttack (arXiv:2407.01232) ?FIRST_SUCCESS 
        - Wei et al. (arXiv:2307.15043) ? >2 ?ASR ?12%  4%
        - Zeng et al. (arXiv:2402.19181) ?authority ASR 38.4% €?
        - DrAttack (arXiv:2402.14266) ?В ASR 40-60% €?

    Args:
        objective_target:  PyRIT PromptTarget?
        scoring_config: AttackScoringConfig (FIRST_SUCCESS )?
        candidate_converters: €?converter  (?ASR )?
        seed_group: AttackSeedGroup ( objective)?

    Returns:
        SequentialChildAttack  ( converter €¤??
        ㄨ converter けャ€?
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
    """ㄤ TextAdaptive ?ScenarioTechnique €?

     AttackTechniqueFactory ?
    ScenarioTechnique , ?TextAdaptive ?
    EpsilonGreedyTechniqueSelector ?

    ︽:
        - PyRIT (arXiv:2407.01232) ?AttackTechniqueRegistry.build_technique_class_from_factories
        - Chao et al. (arXiv:2310.08419) ?-€€€

    Args:
        adversarial_target: ?adversarial chat target (€??
        converter_target: Converter ?LLM target (€??

    Returns:
        ㄦ€ ScenarioTechnique , ?None (??
    """
    # R6 §6.4b:  defaults.yaml  SSOT 
    _tech_cfg: dict[str, Any] = {}
    try:
        import yaml as _yaml
        _cfg_path = _PROJECT_ROOT / "config" / "defaults.yaml"
        if _cfg_path.exists():
            with open(_cfg_path, encoding="utf-8") as _f:
                _tech_cfg = _yaml.safe_load(_f) or {}
    except Exception:
        pass

    factories_dict = register_project_techniques(
        adversarial_target=adversarial_target,
        converter_target=converter_target,
        config_overrides=_tech_cfg,
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

