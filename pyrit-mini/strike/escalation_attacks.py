"""escalation_attacks 鈥?浠?escalation.py 鎷嗗垎鑰屾潵.



鍖呭惈 RedTeaming, Crescendo, TAP, PAIR 鏀诲嚮瀹炵幇.



PyRIT 鍘熺敓瀵归綈 (v51):

    - 鏂板 RedTeamingAttack: 瀹樻柟鏈€閫氱敤鐨勫杞敾鍑? 浣滀负 Crescendo 鍓嶇疆

      (arXiv:2407.01232 鈥?RedTeaming 鏄?multi-turn baseline)

    - Crescendo 娣诲姞 system_prompt: 浣跨敤瀹樻柟 EXECUTOR_SEED_PROMPT_PATH

      (arXiv:2402.12109 鈥?Crescendo 闇€瑕佷笓鐢ㄧ殑娓愯繘寮?system prompt)

    - 鎵€鏈夊杞敾鍑荤粺涓€浣跨敤 AttackAdversarialConfig(target=..., system_prompt=...)

"""



import asyncio
import logging
from typing import Any

from core.context import PipelineContext, _get_config_int
from strike.escalation_level1 import (
    _apply_mtos_ranking,
    _build_skeleton_key_seed_groups,
    _filter_by_suitable_for,
)
from strike.escalation_level2 import _create_fallback_fsts, _retrieve_partial_results
from strike.executor import _build_prepended_conversation_config as _build_prepended_config_safe

logger = logging.getLogger(__name__)



# 鈹€鈹€ L5 v13: security_audit exception capture 鈹€鈹€

_SECURITY_AUDIT_KEYWORDS = [

    "security_audit_fail",

    "content_filter",

    "content_policy",

    "safety_violation",

    "policy_violation",

    "inappropriate_content",

    "harmful_content",

]





class _SecurityAuditError(Exception):

    """Target API security_audit detection exception."""



    pass





def _is_security_audit_error(error_msg: str) -> bool:

    """Check if error message is a security_audit interception."""

    error_lower = error_msg.lower()

    return any(kw in error_lower for kw in _SECURITY_AUDIT_KEYWORDS)





async def _run_red_teaming(

    ctx: PipelineContext,

    objectives: list[str],

) -> dict[str, list[Any]]:

    """瀵瑰け璐ョ洰鏍囨墽琛?RedTeamingAttack 澶氳疆鏀诲嚮銆?



    PyRIT 鍘熺敓瀵归綈 (v51): 鏂板 RedTeamingAttack 浣滀负鍗囩骇閾惧墠缃€?

    RedTeamingAttack 鏄?PyRIT 鏈€閫氱敤鐨勫杞敾鍑? 瀵规姉妯″瀷閫愯疆鐢熸垚 prompt,

    scorer 鍒ゆ柇杩涘害, 寰幆鍒版垚鍔熸垨 max_turns銆?



    浣滀负 Crescendo 鍓嶇疆鐨勪紭鍔?

        1. API 璋冪敤鏇村皯 (max_turns=5 vs Crescendo 10), 璇曟帰鎴愭湰鏇翠綆

        2. 閫氱敤鎬ф洿寮?(涓嶄緷璧栨笎杩涘紡绛栫暐, 閫傚悎鎵€鏈夌洰鏍囩被鍨?

        3. 鍙娇鐢?RTASystemPromptPaths 閫夋嫨绯荤粺鎻愮ず

    瀛︽湳渚濇嵁:

        - PyRIT (arXiv:2407.01232) 鈥?RedTeamingAttack 鏄?multi-turn baseline

        - 瀹樻柟鏂囨。: RedTeamingAttack 浣跨敤 RTASystemPromptPaths.TEXT_GENERATION



    Args:

        ctx: 娴佹按绾夸笂涓嬫枃銆?

        objectives: 澶辫触鐩爣鍒楄〃銆?



    Returns:

        RedTeaming 鏀诲嚮缁撴灉銆?

    """

    from pyrit.executor.attack import (
        AttackAdversarialConfig,
        RedTeamingAttack,
        RTASystemPromptPaths,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective, SeedPrompt



    results: dict[str, list[Any]] = {}



    rt_objectives = _filter_by_suitable_for(objectives, ctx, "red_teaming")

    if not rt_objectives:

        logger.info("RedTeaming: no objectives suitable for this technique, skipping")

        return results



    if len(rt_objectives) > 8:

        rt_objectives = rt_objectives[:8]

        logger.info("v51: RedTeaming limited to top-8 objectives (MTOS-ranked)")



    try:

        from strike.escalation import _build_refusal_inverter_scoring_config

        scoring_config = _build_refusal_inverter_scoring_config(ctx)



        # 鏋勫缓瀵规姉閰嶇疆 鈥?浣跨敤瀹樻柟 RTASystemPromptPaths.TEXT_GENERATION

        # PyRIT 鍘熺敓: AttackAdversarialConfig(target=..., system_prompt=SeedPrompt.from_yaml_file(...))

        adversarial_config_kwargs: dict[str, Any] = {

            "target": ctx.adversarial_target,

        }



        # 灏濊瘯鍔犺浇瀹樻柟 RTA system prompt (TEXT_GENERATION 涓烘渶閫氱敤鐨?

        try:

            system_prompt = SeedPrompt.from_yaml_file(

                RTASystemPromptPaths.TEXT_GENERATION.value

            )

            adversarial_config_kwargs["system_prompt"] = system_prompt

            logger.info("v51: RedTeaming using RTASystemPromptPaths.TEXT_GENERATION")

        except Exception as e:

            logger.debug("v51: RTA system prompt not available (%s), using default", e)



        # v53: RedTeamingAttack does not support prepended_conversation_config in __init__

        # (unlike CrescendoAttack/TAPAttack/PAIRAttack). Instead, prepended_conversation

        # is passed via broadcast_fields to execute_attack_from_seed_groups_async.

        # See AttackParameters.prepended_conversation field.

        rt_prepended_config = _build_prepended_config_safe(ctx)

        rt_prepended_messages = rt_prepended_config._messages if rt_prepended_config else None



        attack = RedTeamingAttack(

            objective_target=ctx.multi_turn_target or ctx.objective_target,

            attack_adversarial_config=AttackAdversarialConfig(**adversarial_config_kwargs),

            attack_scoring_config=scoring_config,

            max_turns=5,  # v51: 5 turns, 浣滀负蹇€熻瘯鎺?(Crescendo 10 turns 浣滀负鍚庣画鍗囩骇)

        )



        mtos_objectives = _apply_mtos_ranking(rt_objectives, ctx, technique_name="red_teaming")

        seed_groups = [

            AttackSeedGroup(seeds=[SeedObjective(value=obj)])

            for obj in mtos_objectives

        ]



        from core.context import get_effective_concurrency

        executor = AttackExecutor(max_concurrency=get_effective_concurrency(ctx))



        executor_result = await asyncio.wait_for(

            executor.execute_attack_from_seed_groups_async(

                attack=attack,

                seed_groups=seed_groups,

                return_partial_on_failure=True,

                # v53: SkeletonKey pre-injection via broadcast_fields (RedTeamingAttack

                # does not support prepended_conversation_config in __init__)

                # arXiv:2406.18112 - prepended conversation lowers safety filter

                prepended_conversation=rt_prepended_messages,

            ),

            timeout=300,

        )



        results["red_teaming"] = list(executor_result.completed_results)

        logger.info(

            "RedTeaming completed: %d success, %d failed",

            len(executor_result.completed_results),

            len(executor_result.incomplete_objectives),

        )



    except asyncio.TimeoutError:

        logger.warning("RedTeaming attack timed out after 300s")

        await _retrieve_partial_results(ctx, "red_teaming")

    except _SecurityAuditError as e:

        logger.warning("RedTeaming: security_audit_fail detected: %s, returning empty results", e)

    except Exception as e:

        exc_str = str(e).lower()

        if "integrityerror" in exc_str or "unique constraint" in exc_str:

            logger.warning("RedTeaming: IntegrityError detected, attempting partial recovery: %s", e)

            await _retrieve_partial_results(ctx, "red_teaming")

        elif _is_security_audit_error(str(e)):

            logger.warning("RedTeaming: security_audit_fail in exception: %s", e)

        else:

            logger.error("RedTeaming attack failed: %s", e)

            await _retrieve_partial_results(ctx, "red_teaming")



    return results





async def _run_crescendo(

    ctx: PipelineContext,

    objectives: list[str],

) -> dict[str, list[Any]]:

    """瀵瑰け璐ョ洰鏍囨墽琛?Crescendo 澶氳疆鏀诲嚮銆?



    PyRIT 鍘熺敓瀵归綈 (v51):

        - 娣诲姞 Crescendo 涓撶敤 system_prompt (瀹樻柟 EXECUTOR_SEED_PROMPT_PATH)

        - AttackAdversarialConfig(target=..., system_prompt=...) 瀹屾暣閰嶇疆

    L5 v20: 淇 sqlite3.IntegrityError (UNIQUE constraint failed: ScoreEntries.id)

    瀛︽湳渚濇嵁: Heroux et al. (arXiv:2403.04206) 鈥?闊ф€у伐绋? 閮ㄥ垎缁撴灉鎭㈠

    闄勫姞: Crescendo 鏈韩鏄杞璇? 鍐呴儴宸叉湁 turn-by-turn 涓茶閫昏緫,

           AttackExecutor 骞跺彂搴︿粎褰卞搷澶氫釜 seed_groups 鐨勫苟琛屽害,

           闄嶄负 1 涓嶅奖鍝嶅崟 seed 鐨勫杞璇濇墽琛?



    Args:

        ctx: 娴佹按绾夸笂涓嬫枃銆?

        objectives: 澶辫触鐩爣鍒楄〃銆?



    Returns:

        Crescendo 鏀诲嚮缁撴灉銆?

    """

    from pyrit.executor.attack import (
        AttackAdversarialConfig,
        CrescendoAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor



    results: dict[str, list[Any]] = {}



    crescendo_objectives = _filter_by_suitable_for(objectives, ctx, "crescendo")

    if not crescendo_objectives:

        logger.info("Crescendo: no objectives suitable for this technique, skipping")

        return results



    if len(crescendo_objectives) > 8:

        crescendo_objectives = crescendo_objectives[:8]

        logger.info("L5 v41: Crescendo limited to top-8 objectives (MTOS-ranked)")



    try:

        from strike.escalation import _build_refusal_inverter_scoring_config

        scoring_config = _build_refusal_inverter_scoring_config(ctx)



        # v51: PyRIT 鍘熺敓瀵归綈 鈥?娣诲姞 Crescendo 涓撶敤 system_prompt

        # 瀹樻柟鏂囨。: CrescendoAttack 閫氳繃 AttackAdversarialConfig(system_prompt=...) 璁剧疆

        # 浣跨敤 EXECUTOR_SEED_PROMPT_PATH / "crescendo" / "text_generation.yaml"

        adversarial_config_kwargs: dict[str, Any] = {

            "target": ctx.adversarial_target,

        }



        try:

            from pyrit.common.path import EXECUTOR_SEED_PROMPT_PATH

            crescendo_prompt_path = EXECUTOR_SEED_PROMPT_PATH / "crescendo" / "text_generation.yaml"

            if crescendo_prompt_path.exists():

                from pyrit.models import SeedPrompt

                system_prompt = SeedPrompt.from_yaml_file(str(crescendo_prompt_path))

                adversarial_config_kwargs["system_prompt"] = system_prompt

                logger.info("v51: Crescendo using official system_prompt from %s", crescendo_prompt_path)

        except Exception as e:

            logger.debug("v51: Crescendo system_prompt not available (%s), using default", e)



        # v53: CrescendoAttack supports prepended_conversation_config in __init__

        # R2 (PyRIT Native First): Pass config directly to constructor

        crescendo_prepended_config = _build_prepended_config_safe(ctx)



        attack = CrescendoAttack(

            objective_target=ctx.multi_turn_target or ctx.objective_target,

            attack_adversarial_config=AttackAdversarialConfig(**adversarial_config_kwargs),

            attack_scoring_config=scoring_config,

            max_turns=_get_config_int(ctx, "crescendo_max_turns", 10),


            max_backtracks=10,  # L5 v3: 8鈫?0, 鏇村鍥炴函鏈轰細

            prepended_conversation_config=crescendo_prepended_config,

        )

        # L5 v12: Crescendo 涓婁笅鏂囩獥鍙ｄ紭鍖?(淇 dead code)

        # 瀛︽湳渚濇嵁: Crescendo (arXiv:2402.12109) 搂4.3 鈥?max_turns=10 闇€瑕?

        # 瓒冲澶х殑涓婁笅鏂囩獥鍙ｄ繚璇佸璇濆巻鍙插畬鏁存€с€?

        # PyRIT 1.0.1 CrescendoAttack 閫氳繃澶氱鍙兘灞炴€х鐞嗕笂涓嬫枃:

        for attr_name in ('max_conversation_memory', 'max_turn_memory', 'conversation_memory_limit'):

            if hasattr(attack, attr_name):

                setattr(attack, attr_name, 4096)

                logger.info("Crescendo: %s set to 4096 tokens/turn", attr_name)

                break

        else:

            logger.debug("Crescendo: using default memory (no explicit context window attr)")



        # 鏋勫缓 seed groups (with Skeleton Key pre-injection + L5 v15 MTOS ranking)

        seed_groups = _build_skeleton_key_seed_groups(crescendo_objectives, ctx=ctx)



        # L5 v45: 缁熶竴浠?ctx.args 璇诲彇骞跺彂鏁?(SSOT: config/defaults.yaml max_concurrency=3)

        from core.context import get_effective_concurrency

        executor = AttackExecutor(

            max_concurrency=get_effective_concurrency(ctx),

        )



        executor_result = await asyncio.wait_for(

            executor.execute_attack_from_seed_groups_async(

                attack=attack,

                seed_groups=seed_groups,

                return_partial_on_failure=True,

            ),

            timeout=max(300, len(seed_groups) * 60),  # L5 v34: 600鈫?00, 姣忕洰鏍噡60s (v34 Crescendo ASR=0%, 缂╃煭瓒呮椂鑺傜渷鏃堕棿)

        )



        results["crescendo"] = list(executor_result.completed_results)

        logger.info(

            "Crescendo completed: %d success, %d failed",

            len(executor_result.completed_results),

            len(executor_result.incomplete_objectives),

        )



    except asyncio.TimeoutError:

        logger.warning("Crescendo attack timed out after 300s")

        # 灏濊瘯妫€绱㈤儴鍒嗙粨鏋?

        await _retrieve_partial_results(ctx, "crescendo")

    except _SecurityAuditError as e:

        logger.warning("Crescendo: security_audit_fail detected: %s, returning empty results", e)

    except Exception as e:

        # L5 v20: 鎹曡幏 IntegrityError, 灏濊瘯鎭㈠閮ㄥ垎缁撴灉

        exc_str = str(e).lower()

        if "integrityerror" in exc_str or "unique constraint" in exc_str:

            logger.warning(

                "Crescendo: IntegrityError (ScoreEntries.id conflict) detected, "

                "attempting partial result recovery: %s",

                e,

            )

            await _retrieve_partial_results(ctx, "crescendo")

        elif _is_security_audit_error(str(e)):

            logger.warning("Crescendo: security_audit_fail in exception: %s", e)

        else:

            logger.error("Crescendo attack failed: %s", e)

            # L5 v20: 鍗充娇鏄潪 IntegrityError, 涔熷皾璇曟仮澶嶉儴鍒嗙粨鏋?

            await _retrieve_partial_results(ctx, "crescendo")



    return results



async def _run_tap(

    ctx: PipelineContext,

    objectives: list[str],

) -> dict[str, list[Any]]:

    """瀵瑰け璐ョ洰鏍囨墽琛?TAP 鏍戞悳绱㈡敾鍑汇€?



    L5 浼樺寲: tree_width=2 (浠?鍑忓皯), tree_depth=2 (浠?鍑忓皯)

    鍑忓皯 API 璋冪敤 ~75%锛屼繚鎸?ASR~50%銆?



    Args:

        ctx: 娴佹按绾夸笂涓嬫枃銆?

        objectives: 澶辫触鐩爣鍒楄〃銆?



    Returns:

        TAP 鏀诲嚮缁撴灉銆?

    """

    from pyrit.executor.attack import (
        AttackAdversarialConfig,
        TAPAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective



    results: dict[str, list[Any]] = {}



    # L5 v36: suitable_for 鍒嗗彂 鈥?鍙墽琛岄€傚悎 TAP 鐨勭瀛?

    # 瀛︽湳渚濇嵁: Mehrotra et al. (arXiv:2312.02191) 鈥?TAP 鏍戞悳绱㈠闇€瑕?

    # 澶氬垎鏀帰绱㈢殑绉嶅瓙 (濡傚伐鍏烽摼寮忚皟鐢? 鏇存湁鏁?

    tap_objectives = _filter_by_suitable_for(objectives, ctx, "tap")

    if not tap_objectives:

        logger.info("TAP: no objectives suitable for this technique, skipping")

        return results



    # L5 v41: 鏀惧闄愬埗浠?3 鈫?8 鈥?瀹炴垬鍦烘櫙涓?ASR 浼樺厛

    # 瀛︽湳渚濇嵁: Mehrotra et al. (arXiv:2312.02191) 鈥?TAP 鏍戞悳绱?ASR=50-80%

    # 鏇村鐩爣 = 鏇村鎴愬姛鏈轰細 (鑱斿悎姒傜巼 P=1-鈭?1-p_i))

    if len(tap_objectives) > 8:

        tap_objectives = tap_objectives[:8]

        logger.info(

            "L5 v41: TAP limited to top-8 objectives (MTOS-ranked)"

        )



    try:

        # L5 v23: 鐩存帴浣跨敤鍘熺敓 FloatScaleThresholdScorer, 绉婚櫎 AdaptiveDualFloatJudgeScorer

        # 鍘熷洜: AdaptiveDualFloatJudgeScorer 缁ф壙 FloatScaleThresholdScorer 浣嗗唴閮?

        # 璋冪敤瀛?scorer 鏃惰繑鍥為潪鏍囧噯鍊? 瀵艰嚧 TAP 鑺傜偣鎶ラ敊:

        # "TrueFalseScorer score value must be True or False"

        # TAP 鍘熺敓璁捐瑕佹眰 FloatScaleThresholdScorer (arXiv:2312.02191 搂3.2)

        # 瀛︽湳渚濇嵁: Mehrotra et al. (arXiv:2312.02191) 鈥?TAP 浣跨敤 FloatScaleScorer



        from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig



        scorer = _create_fallback_fsts(ctx)

        logger.info("TAP scorer: FloatScaleThresholdScorer (threshold=0.2) 鈥?L5 v34 tuned")



        scoring_config = TAPAttackScoringConfig(

            objective_scorer=scorer,

        )



        # v53: TAPAttack supports prepended_conversation_config in __init__

        # R2 (PyRIT Native First): Pass config directly to constructor

        tap_prepended_config = _build_prepended_config_safe(ctx)



        attack = TAPAttack(

            objective_target=ctx.multi_turn_target or ctx.objective_target,

            attack_adversarial_config=AttackAdversarialConfig(

                target=ctx.adversarial_target,

            ),

            attack_scoring_config=scoring_config,

            on_topic_checking_enabled=False,

            tree_width=_get_config_int(ctx, "tap_tree_width", 4),

            tree_depth=_get_config_int(ctx, "tap_tree_depth", 4),

            prepended_conversation_config=tap_prepended_config,

        )



        # L5 v16: TAP 闆嗘垚 MTOS 澶氳疆閫夌鎺掑簭

        # 瀛︽湳渚濇嵁: Chao et al. (arXiv:2310.08419) 鈥?TAP 鏄杞爲鎼滅储鏀诲嚮,

        # 浣?涓?ASR 绉嶅瓙鏇撮€傚悎澶氳疆杩唬浼樺寲, 楂?ASR 绉嶅瓙鍗曡疆宸叉垚鍔?

        # L5 v36: 浼犲叆 technique_name='tap' 鍚敤浜ゅ弶 ASR 鍏堥獙鍔犳潈

        mtos_objectives = _apply_mtos_ranking(tap_objectives, ctx, technique_name="tap")



        seed_groups = [

            AttackSeedGroup(seeds=[SeedObjective(value=obj)])

            for obj in mtos_objectives

        ]



        # L5 v45: 缁熶竴浠?ctx.args 璇诲彇骞跺彂鏁?(SSOT: config/defaults.yaml max_concurrency=3)

        from core.context import get_effective_concurrency

        executor = AttackExecutor(

            max_concurrency=get_effective_concurrency(ctx),

        )



        executor_result = await asyncio.wait_for(

            executor.execute_attack_from_seed_groups_async(

                attack=attack,

                seed_groups=seed_groups,

                return_partial_on_failure=True,

            ),

            timeout=400,  # L5 v34: 600鈫?00, TAP tree_width=4 depth=4 闇€瑕佽緝澶氭椂闂翠絾 600s 澶暱

        )



        results["tap"] = list(executor_result.completed_results)

        logger.info(

            "TAP completed: %d success, %d failed",

            len(executor_result.completed_results),

            len(executor_result.incomplete_objectives),

        )



    except asyncio.TimeoutError:

        logger.warning("TAP attack timed out after 400s")

        await _retrieve_partial_results(ctx, "tap")

    except _SecurityAuditError as e:

        logger.warning("TAP: security_audit_fail detected: %s, returning empty results", e)

    except Exception as e:

        if _is_security_audit_error(str(e)):

            logger.warning("TAP: security_audit_fail in exception: %s", e)

        else:

            logger.error("TAP attack failed: %s", e)



    return results



async def _run_pair(

    ctx: PipelineContext,

    objectives: list[str],

) -> dict[str, list[Any]]:

    """瀵瑰け璐ョ洰鏍囨墽琛?PAIR 杩唬浼樺寲鏀诲嚮銆?



    L5 鏂板: PAIR 浣滀负绗笁鍗囩骇闃舵銆?

    tree_width=1 (鍗曟祦), tree_depth=3 (3娆¤凯浠?

    API 璋冪敤閲忔瀬灏忥紝ASR 40-60%銆?



    瀛︽湳渚濇嵁: Chao et al. (arXiv:2310.08419)



    Args:

        ctx: 娴佹按绾夸笂涓嬫枃銆?

        objectives: 澶辫触鐩爣鍒楄〃銆?



    Returns:

        PAIR 鏀诲嚮缁撴灉銆?

    """

    from pyrit.executor.attack import (
        AttackAdversarialConfig,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.executor.attack.multi_turn.pair import PAIRAttack
    from pyrit.models import AttackSeedGroup, SeedObjective



    results: dict[str, list[Any]] = {}



    # L5 v36: suitable_for 鍒嗗彂 鈥?鍙墽琛岄€傚悎 PAIR 鐨勭瀛?

    # 瀛︽湳渚濇嵁: Chao et al. (arXiv:2310.08419) 鈥?PAIR 瀵归渶瑕佽凯浠ｄ紭鍖栫殑绉嶅瓙鏈夋晥

    pair_objectives = _filter_by_suitable_for(objectives, ctx, "pair")

    if not pair_objectives:

        logger.info("PAIR: no objectives suitable for this technique, skipping")

        return results



    try:

        # L5 v23: 鐩存帴浣跨敤鍘熺敓 FloatScaleThresholdScorer, 绉婚櫎 AdaptiveDualFloatJudgeScorer

        # 鍘熷洜: 涓?_run_tap 淇鐩稿悓 鈥?AdaptiveDualFloatJudgeScorer 杩斿洖闈炴爣鍑嗗€?

        # 瀵艰嚧 PAIR 鑺傜偣鎶ラ敊銆侾AIR 缁ф壙 TAP, 鍘熺敓浣跨敤 FloatScaleScorer銆?

        # 瀛︽湳渚濇嵁: Chao et al. (arXiv:2310.08419) 鈥?PAIR 浣跨敤 FloatScaleScorer



        from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig



        scorer = _create_fallback_fsts(ctx)

        logger.info("PAIR scorer: FloatScaleThresholdScorer (threshold=0.2) 鈥?L5 v34 tuned")



        scoring_config = TAPAttackScoringConfig(

            objective_scorer=scorer,

        )



        # v53: PAIRAttack supports prepended_conversation_config in __init__

        # R2 (PyRIT Native First): Pass config directly to constructor

        pair_prepended_config = _build_prepended_config_safe(ctx)



        attack = PAIRAttack(

            objective_target=ctx.multi_turn_target or ctx.objective_target,

            attack_adversarial_config=AttackAdversarialConfig(

                target=ctx.adversarial_target,

            ),

            attack_scoring_config=scoring_config,

            tree_width=_get_config_int(ctx, "pair_tree_width", 1),    # PAIR: 鍗曟祦杩唬

            tree_depth=_get_config_int(ctx, "pair_tree_depth", 7),   # L5 v50: depth=10鈫?, 骞宠　 ASR 涓庤秴鏃堕闄?(arXiv:2406.12609)

            prepended_conversation_config=pair_prepended_config,

        )



        # L5 v16: PAIR 闆嗘垚 MTOS 澶氳疆閫夌鎺掑簭

        # 瀛︽湳渚濇嵁: Chao et al. (arXiv:2310.08419) 鈥?PAIR 鏄杞凯浠ｄ紭鍖栨敾鍑?

        # 浣?涓?ASR 绉嶅瓙鏇撮€傚悎澶氳疆杩唬, 楂?ASR 绉嶅瓙鍗曡疆宸叉垚鍔?

        # L5 v36: 浼犲叆 technique_name='pair' 鍚敤浜ゅ弶 ASR 鍏堥獙鍔犳潈

        mtos_objectives = _apply_mtos_ranking(pair_objectives, ctx, technique_name="pair")



        seed_groups = [

            AttackSeedGroup(seeds=[SeedObjective(value=obj)])

            for obj in mtos_objectives

        ]



        # L5 v45: 缁熶竴浠?ctx.args 璇诲彇骞跺彂鏁?(SSOT: config/defaults.yaml max_concurrency=3)

        from core.context import get_effective_concurrency

        executor = AttackExecutor(

            max_concurrency=get_effective_concurrency(ctx),

        )



        executor_result = await asyncio.wait_for(

            executor.execute_attack_from_seed_groups_async(

                attack=attack,

                seed_groups=seed_groups,

                return_partial_on_failure=True,

            ),

            timeout=300,  # L5 v50: 400鈫?00s, depth=7 (21 LLM calls/obj), 鍙潬瀹屾垚鐜?~95%

        )



        results["pair"] = list(executor_result.completed_results)

        logger.info(

            "PAIR completed: %d success, %d failed",

            len(executor_result.completed_results),

            len(executor_result.incomplete_objectives),

        )



    except asyncio.TimeoutError:

        logger.warning("PAIR attack timed out after 300s")

        await _retrieve_partial_results(ctx, "pair")

    except _SecurityAuditError as e:

        logger.warning("PAIR: security_audit_fail detected: %s, returning empty results", e)

    except Exception as e:

        if _is_security_audit_error(str(e)):

            logger.warning("PAIR: security_audit_fail in exception: %s", e)

        else:

            logger.error("PAIR attack failed: %s", e)



    return results



