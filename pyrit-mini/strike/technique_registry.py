"""AttackTechniqueFactory 娉ㄥ唽 鈥?灏嗛」鐩敾鍑绘妧鏈敞鍐屽埌 PyRIT 鍘熺敓 registry銆?

鍒╃敤 PyRIT 1.0.1 鍘熺敓 AttackTechniqueFactory + AttackTechniqueRegistry锛?
灏嗛」鐩殑鏀诲嚮鎶€鏈紙PromptSending + Crescendo + TAP + PAIR + Best-of-N锛?
娉ㄥ唽涓哄彲琚?TextAdaptive 鍦烘櫙鑷姩鍙戠幇鍜岄€夋嫨鐨勬妧鏈€?

瀛︽湳渚濇嵁:
    - PyRIT (arXiv:2407.01232) 鈥?AttackTechniqueFactory + Registry 璁捐,
      scenarios 閫氳繃 tag 鏌ヨ鑷姩鍙戠幇鎶€鏈?
    - Chao et al. (arXiv:2310.08419) 鈥?PAIR 鑷€傚簲绛栫暐閫夋嫨
    - Mehrotra et al. (arXiv:2312.02191) 鈥?TAP 鏍戞悳绱?
    - Russinovich et al. (arXiv:2402.12109) 鈥?Crescendo 娓愯繘鍗囩骇
    - Chao et al. (arXiv:2402.01135) 鈥?Best-of-N ASR 鎻愬崌 1.8x

PyRIT 鍘熺敓浼樺厛 (Rule 2):
    鏈ā鍧楁槸鑳舵按灞?鈥?灏嗛」鐩厤缃弬鏁版敞鍏?PyRIT 鍘熺敓 AttackTechniqueFactory,
    涓嶆浛鎹换浣曞師鐢熺粍浠躲€侳actory.create() 璋冪敤鏃朵娇鐢ㄥ師鐢?PromptSendingAttack /
    CrescendoAttack / TAPAttack / PAIRAttack 浣滀负 attack_class銆?
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
    """灏嗛」鐩敾鍑绘妧鏈敞鍐屽埌 PyRIT 鍘熺敓 AttackTechniqueRegistry銆?

    鏋勫缓 AttackTechniqueFactory 瀹炰緥骞舵敞鍐屽埌鍏ㄥ眬 registry锛?
    浣?TextAdaptive 鍦烘櫙鑳借嚜鍔ㄥ彂鐜板拰閫夋嫨杩欎簺鎶€鏈€?

    鎶€鏈垪琛?(鎸?L5 浼樺厛绾?:
        1. PromptSending (baseline, single_turn tag)
        2. Crescendo (multi_turn tag)
        3. TAP (multi_turn tag, tree search)
        4. PAIR (multi_turn tag, iterative)
        5. Best-of-N (single_turn tag, variation retry)
        6. RedTeaming (multi_turn tag, baseline)
        7. SkeletonKey (single_turn tag, prefix injection)

    瀛︽湳渚濇嵁:
        - PyRIT (arXiv:2407.01232) 鈥?AttackTechniqueRegistry + tag 鏌ヨ
        - Wei et al. (arXiv:2307.15043) 鈥?鍗曡疆澶氳矾寰勭嫭绔嬫墽琛?
        - Russinovich et al. (arXiv:2402.12109) 鈥?Crescendo ASR=82%
        - Mehrotra et al. (arXiv:2312.02191) 鈥?TAP 鏍戞悳绱?
        - Chao et al. (arXiv:2310.08419) 鈥?PAIR 杩唬浼樺寲
        - Chao et al. (arXiv:2402.01135) 鈥?Best-of-N N=5 ASR 1.8x

    Args:
        adversarial_target: 澶氳疆鏀诲嚮鐨?adversarial chat target (鍙€?銆?
        converter_target: Converter 浣跨敤鐨?LLM target (鍙€? 鐢ㄤ簬 Best-of-N)銆?

    Returns:
        娉ㄥ唽鐨?factory 鍚嶇О鈫抐actory 鏄犲皠瀛楀吀銆傜┖瀛楀吀琛ㄧず娉ㄥ唽澶辫触銆?
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
        logger.warning("PyRIT attack classes not available: %s 鈥?technique registration skipped", e)
        return {}

    factories: list[AttackTechniqueFactory] = []

    # 鈹€鈹€ 1. PromptSending (baseline) 鈹€鈹€
    # arXiv:2307.15043 鈥?鍗曡疆鍩虹嚎, 澶氳矾寰勭嫭绔嬫墽琛岀殑鍩虹
    # v51: 瀵归綈瀹樻柟 鈥?SkeletonKey 鐨?prepended_conversation 閫氳繃 execute_async 浼犲叆
    try:
        ps_factory = AttackTechniqueFactory(
            name="PromptSending",
            attack_class=PromptSendingAttack,
            description="Single-turn baseline attack with SkeletonKey prepended conversation (arXiv:2307.15043, arXiv:2406.18112)",
            technique_tags=["single_turn", "default", "baseline", "light"],
        )
        factories.append(ps_factory)
        logger.info("Registered AttackTechniqueFactory: PromptSending (single_turn, baseline)")
    except Exception as e:
        logger.warning("Failed to create PromptSending factory: %s", e)

    # 鈹€鈹€ 2. Crescendo (multi-turn) 鈹€鈹€
    # arXiv:2402.12109 鈥?Russinovich et al., 10 turns ASR=82%
    # v51: 瀵归綈瀹樻柟 鈥?娣诲姞 Crescendo 涓撶敤 system_prompt
    if CrescendoAttack is not None and adversarial_target is not None:
        try:
            # v51: 灏濊瘯鍔犺浇瀹樻柟 Crescendo system_prompt
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
                "technique_tags": ["multi_turn", "escalation", "light"],
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

    # 鈹€鈹€ 3. TAP (multi-turn, tree search) 鈹€鈹€
    # arXiv:2312.02191 鈥?Mehrotra et al., tree-of-attacks with pruning
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

    # 鈹€鈹€ 4. PAIR (multi-turn, iterative) 鈹€鈹€
    # arXiv:2310.08419 鈥?Chao et al., iterative adversarial prompting
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

    # 鈹€鈹€ 5. Best-of-N (single-turn, variation retry) 鈹€鈹€
    # arXiv:2402.01135 鈥?Chao et al., N=5 ASR 1.8x
    # 浣跨敤 PromptSendingAttack 浣滀负 attack_class, converter 閰嶇疆娉ㄥ叆 VariationConverter
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

    # 鈹€鈹€ 6. RedTeaming (multi-turn baseline) 鈹€鈹€
    # v51: PyRIT 鍘熺敓瀵归綈 鈥?娉ㄥ唽 RedTeamingAttack
    # arXiv:2407.01232 鈥?RedTeamingAttack 鏄畼鏂规渶閫氱敤鐨?multi-turn baseline
    # 浣跨敤 RTASystemPromptPaths.TEXT_GENERATION 浣滀负 system_prompt
    if adversarial_target is not None:
        try:
            # 灏濊瘯鍔犺浇瀹樻柟 RTA system prompt
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
                "technique_tags": ["multi_turn", "baseline", "light"],
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

    # 鈹€鈹? 7. SkeletonKey (single-turn, prefix injection) 鈹€鈹€
    # arXiv:2406.18112 鈥?Hanna et al., SkeletonKey ASR 80-95%
    # PyRIT 原生 SkeletonKeyAttack: 鑷姩鏋勯 skeleton key prompt + 妯℃嫙鎺ュ彈
    # 浣滀负 prepended_conversation 娉ㄥ叆 (鍘熺敓鏀寔, 鏃犻渶鎵嬪姩鏋勫缓)
    try:
        sk_factory = AttackTechniqueFactory(
            name="SkeletonKey",
            attack_class=SkeletonKeyAttack,
            description="Single-turn SkeletonKey prefix injection (arXiv:2406.18112)",
            technique_tags=["single_turn", "prefix_injection"],
        )
        factories.append(sk_factory)
        logger.info("Registered AttackTechniqueFactory: SkeletonKey (single_turn, prefix_injection)")
    except Exception as e:
        logger.warning("Failed to create SkeletonKey factory: %s", e)

    # ── 8. ManyShotJailbreak (single-turn, many-shot) ──
    # arXiv:2402.05124 — Anthropic, Many-Shot Jailbreaking
    # PyRIT 原生 ManyShotJailbreakAttack: 100 shots ASR 显著提升
    # 利用模型的 in-context learning 能力绕过安全过滤
    try:
        from pyrit.executor.attack import ManyShotJailbreakAttack

        ms_factory = AttackTechniqueFactory(
            name="ManyShotJailbreak",
            attack_class=ManyShotJailbreakAttack,
            description="Many-shot jailbreak with 100 faux Q/A examples (arXiv:2402.05124)",
            technique_tags=["single_turn", "many_shot"],
            attack_kwargs={
                "example_count": 100,
            },
        )
        factories.append(ms_factory)
        logger.info("Registered AttackTechniqueFactory: ManyShotJailbreak (single_turn, many_shot)")
    except Exception as e:
        logger.warning("Failed to create ManyShotJailbreak factory: %s", e)

    # ── 9. MultiPromptSending (multi-turn, fixed sequence) ──
    # arXiv:2407.01232 — PyRIT, 原生多轮固定序列攻击
    # 适合"分步引导"式越狱场景, 3步引导降低目标安全防御
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

    # ── 10. ChunkedRequest (multi-turn, chunked extraction) ──
    # arXiv:2407.01232 — PyRIT, 原生分块提取攻击
    # 通过请求特定字符范围的信息片段, 绕过长度过滤/输出截断
    try:
        from pyrit.executor.attack import ChunkedRequestAttack

        cr_factory = AttackTechniqueFactory(
            name="ChunkedRequest",
            attack_class=ChunkedRequestAttack,
            description="Chunked extraction attack, bypass length filters (arXiv:2407.01232)",
            technique_tags=["multi_turn", "chunked_extraction"],
            attack_kwargs={
                "chunk_size": 50,
                "total_length": 200,
                "chunk_type": "characters",
            },
        )
        factories.append(cr_factory)
        logger.info("Registered AttackTechniqueFactory: ChunkedRequest (multi_turn, chunked_extraction)")
    except Exception as e:
        logger.warning("Failed to create ChunkedRequest factory: %s", e)

    # 鈹€鈹€ 娉ㄥ唽鍒板叏灞€ AttackTechniqueRegistry 鈹€鈹€
    if not factories:
        logger.warning("No AttackTechniqueFactories created 鈥?technique registration skipped")
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
    """鏋勫缓 SequentialAttack 鐨?child attacks 鍒楄〃 鈥?鍘熺敓 FIRST_SUCCESS 澶氳矾寰勩€?

    浣跨敤 PyRIT 鍘熺敓 SequentialAttack + SequentialChildAttack 鏇夸唬
    executor.py 涓殑鎵嬪姩澶氳矾寰勫惊鐜€?

    姣忎釜 converter 瀵瑰簲涓€涓嫭绔嬬殑 PromptSendingAttack (1 converter per path),
    浠讳竴璺緞鎴愬姛 (FIRST_SUCCESS) 鍒欒烦杩囧悗缁矾寰勩€?

    瀛︽湳渚濇嵁:
        - PyRIT SequentialAttack (arXiv:2407.01232) 鈥?FIRST_SUCCESS 绛栫暐
        - Wei et al. (arXiv:2307.15043) 鈥?涓茶仈 >2 灞?ASR 浠?12% 闄嶈嚦 4%
        - Zeng et al. (arXiv:2402.19181) 鈥?authority ASR 38.4% 鏈€楂?
        - DrAttack (arXiv:2402.14266) 鈥?鍒嗚В閲嶇粍 ASR 40-60% 鏈€楂?

    Args:
        objective_target: 琚敾鍑荤殑 PyRIT PromptTarget銆?
        scoring_config: AttackScoringConfig (FIRST_SUCCESS 杞婚噺璇勫垎)銆?
        candidate_converters: 鍊欓€?converter 鍒楄〃 (鎸?ASR 闄嶅簭)銆?
        seed_group: AttackSeedGroup (鍖呭惈鏀诲嚮 objective)銆?

    Returns:
        SequentialChildAttack 鍒楄〃 (姣忎釜 converter 涓€鏉¤矾寰?銆?
        绌哄垪琛ㄨ〃绀烘棤 converter 鎴栨瀯寤哄け璐ャ€?
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
    """鏋勫缓鐢ㄤ簬 TextAdaptive 鍦烘櫙鐨勫姩鎬?ScenarioTechnique 绫汇€?

    灏嗛」鐩敞鍐岀殑 AttackTechniqueFactory 鍒楄〃杞崲涓?
    ScenarioTechnique 瀛愮被, 渚?TextAdaptive 鐨?
    EpsilonGreedyTechniqueSelector 浣跨敤銆?

    瀛︽湳渚濇嵁:
        - PyRIT (arXiv:2407.01232) 鈥?AttackTechniqueRegistry.build_technique_class_from_factories
        - Chao et al. (arXiv:2310.08419) 鈥?蔚-璐績鑷€傚簲鎶€鏈€夋嫨

    Args:
        adversarial_target: 澶氳疆鏀诲嚮鐨?adversarial chat target (鍙€?銆?
        converter_target: Converter 浣跨敤鐨?LLM target (鍙€?銆?

    Returns:
        鍔ㄦ€佺敓鎴愮殑 ScenarioTechnique 瀛愮被, 鎴?None (鏋勫缓澶辫触鏃?銆?
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

