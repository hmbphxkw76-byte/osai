"""escalation_attacks 閳?娴?escalation.py 閹峰棗鍨庨懓灞炬降.



閸栧懎鎯?RedTeaming, Crescendo, TAP, PAIR 閺€璇插毊鐎圭偟骞?



PyRIT 閸樼喓鏁撶€靛綊缍?(v51):

    - 閺傛澘顤?RedTeamingAttack: 鐎规ɑ鏌熼張鈧柅姘辨暏閻ㄥ嫬顦挎潪顔芥暰閸? 娴ｆ粈璐?Crescendo 閸撳秶鐤?

      (arXiv:2407.01232 閳?RedTeaming 閺?multi-turn baseline)

    - Crescendo 濞ｈ濮?system_prompt: 娴ｈ法鏁ょ€规ɑ鏌?EXECUTOR_SEED_PROMPT_PATH

      (arXiv:2402.12109 閳?Crescendo 闂団偓鐟曚椒绗撻悽銊ф畱濞撴劘绻樺?system prompt)

    - 閹碘偓閺堝顦挎潪顔芥暰閸戣崵绮烘稉鈧担璺ㄦ暏 AttackAdversarialConfig(target=..., system_prompt=...)

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



# 閳光偓閳光偓 L5 v13: security_audit exception capture 閳光偓閳光偓

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

    """鐎电懓銇戠拹銉ф窗閺嶅洦澧界悰?RedTeamingAttack 婢舵俺鐤嗛弨璇插毊閵?



    PyRIT 閸樼喓鏁撶€靛綊缍?(v51): 閺傛澘顤?RedTeamingAttack 娴ｆ粈璐熼崡鍥╅獓闁炬儳澧犵純顔衡偓?

    RedTeamingAttack 閺?PyRIT 閺堚偓闁氨鏁ら惃鍕樋鏉烆喗鏁鹃崙? 鐎佃濮夊Ο鈥崇€烽柅鎰枂閻㈢喐鍨?prompt,

    scorer 閸掋倖鏌囨潻娑樺, 瀵邦亞骞嗛崚鐗堝灇閸旂喐鍨?max_turns閵?



    娴ｆ粈璐?Crescendo 閸撳秶鐤嗛惃鍕喘閸?

        1. API 鐠嬪啰鏁ら弴鏉戠毌 (max_turns from SSOT vs Crescendo from SSOT), 鐠囨洘甯伴幋鎰拱閺囩繝缍?

        2. 闁氨鏁ら幀褎娲垮?(娑撳秳绶风挧鏍ㄧ瑤鏉╂稑绱＄粵鏍殣, 闁倸鎮庨幍鈧張澶屾窗閺嶅洨琚崹?

        3. 閸欘垯濞囬悽?RTASystemPromptPaths 闁瀚ㄧ化鑽ょ埠閹绘劗銇?

    鐎涳附婀虫笟婵囧祦:

        - PyRIT (arXiv:2407.01232) 閳?RedTeamingAttack 閺?multi-turn baseline

        - 鐎规ɑ鏌熼弬鍥ㄣ€? RedTeamingAttack 娴ｈ法鏁?RTASystemPromptPaths.TEXT_GENERATION



    Args:

        ctx: 濞翠焦鎸夌痪澶哥瑐娑撳鏋冮妴?

        objectives: 婢惰精瑙﹂惄顔界垼閸掓銆冮妴?



    Returns:

        RedTeaming 閺€璇插毊缂佹挻鐏夐妴?

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



        # 閺嬪嫬缂撶€佃濮夐柊宥囩枂 閳?娴ｈ法鏁ょ€规ɑ鏌?RTASystemPromptPaths.TEXT_GENERATION

        # PyRIT 閸樼喓鏁? AttackAdversarialConfig(target=..., system_prompt=SeedPrompt.from_yaml_file(...))

        adversarial_config_kwargs: dict[str, Any] = {

            "target": ctx.adversarial_target,

        }



        # 鐏忔繆鐦崝鐘烘祰鐎规ɑ鏌?RTA system prompt (TEXT_GENERATION 娑撶儤娓堕柅姘辨暏閻?

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

            max_turns=_get_config_int(ctx, "red_teaming_max_turns", 5),  # v51: 5 turns, quick probe (Crescendo escalation)

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

            timeout=150,  # L5浼樺寲: 300鈫?50s, max_turns=3 (3 LLM calls/obj), 150s 瓒冲

        )



        results["red_teaming"] = list(executor_result.completed_results)

        logger.info(

            "RedTeaming completed: %d success, %d failed",

            len(executor_result.completed_results),

            len(executor_result.incomplete_objectives),

        )



    except asyncio.TimeoutError:

        logger.warning("RedTeaming attack timed out after 150s")

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

    """鐎电懓銇戠拹銉ф窗閺嶅洦澧界悰?Crescendo 婢舵俺鐤嗛弨璇插毊閵?



    PyRIT 閸樼喓鏁撶€靛綊缍?(v51):

        - 濞ｈ濮?Crescendo 娑撴挾鏁?system_prompt (鐎规ɑ鏌?EXECUTOR_SEED_PROMPT_PATH)

        - AttackAdversarialConfig(target=..., system_prompt=...) 鐎瑰本鏆ｉ柊宥囩枂

    L5 v20: 娣囶喖顦?sqlite3.IntegrityError (UNIQUE constraint failed: ScoreEntries.id)

    鐎涳附婀虫笟婵囧祦: Heroux et al. (arXiv:2403.04206) 閳?闂娧勨偓褍浼愮粙? 闁劌鍨庣紒鎾寸亯閹垹顦?

    闂勫嫬濮? Crescendo 閺堫剝闊╅弰顖氼樋鏉烆喖顕拠? 閸愬懘鍎村鍙夋箒 turn-by-turn 娑撹尪顢戦柅鏄忕帆,

           AttackExecutor 楠炶泛褰傛惔锔跨矌瑜板崬鎼锋径姘嚋 seed_groups 閻ㄥ嫬鑻熺悰灞藉,

           闂勫秳璐?1 娑撳秴濂栭崫宥呭礋 seed 閻ㄥ嫬顦挎潪顔碱嚠鐠囨繃澧界悰?



    Args:

        ctx: 濞翠焦鎸夌痪澶哥瑐娑撳鏋冮妴?

        objectives: 婢惰精瑙﹂惄顔界垼閸掓銆冮妴?



    Returns:

        Crescendo 閺€璇插毊缂佹挻鐏夐妴?

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



        # v51: PyRIT 閸樼喓鏁撶€靛綊缍?閳?濞ｈ濮?Crescendo 娑撴挾鏁?system_prompt

        # 鐎规ɑ鏌熼弬鍥ㄣ€? CrescendoAttack 闁俺绻?AttackAdversarialConfig(system_prompt=...) 鐠佸墽鐤?

        # 娴ｈ法鏁?EXECUTOR_SEED_PROMPT_PATH / "crescendo" / "text_generation.yaml"

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


            max_backtracks=_get_config_int(ctx, "crescendo_max_backtracks", 10),  # L5 v3: 8->10, more backtrack opportunities

            prepended_conversation_config=crescendo_prepended_config,

        )

        # L5 v12: Crescendo 娑撳﹣绗呴弬鍥╃崶閸欙絼绱崠?(娣囶喖顦?dead code)

        # 鐎涳附婀虫笟婵囧祦: Crescendo (arXiv:2402.12109) 鎼?.3 閳?max_turns from SSOT 闂団偓鐟?

        # 鐡掑啿顧勬径褏娈戞稉濠佺瑓閺傚洨鐛ラ崣锝勭箽鐠囦礁顕拠婵嗗坊閸欐彃鐣弫瀛樷偓褋鈧?

        # PyRIT 1.0.1 CrescendoAttack 闁俺绻冩径姘鳖潚閸欘垵鍏樼仦鐐粹偓褏顓搁悶鍡曠瑐娑撳鏋?

        for attr_name in ('max_conversation_memory', 'max_turn_memory', 'conversation_memory_limit'):

            if hasattr(attack, attr_name):

                setattr(attack, attr_name, 4096)

                logger.info("Crescendo: %s set to 4096 tokens/turn", attr_name)

                break

        else:

            logger.debug("Crescendo: using default memory (no explicit context window attr)")



        # 閺嬪嫬缂?seed groups (with Skeleton Key pre-injection + L5 v15 MTOS ranking)

        seed_groups = _build_skeleton_key_seed_groups(crescendo_objectives, ctx=ctx)



        # L5 v45: 缂佺喍绔存禒?ctx.args 鐠囪褰囬獮璺哄絺閺?(SSOT: config/defaults.yaml max_concurrency=3)

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

            timeout=max(150, len(seed_groups) * 30),  # L5浼樺寲: 300鈫?50, max_turns=5 (15 LLM calls/obj), 30s/鐩爣

        )



        results["crescendo"] = list(executor_result.completed_results)

        logger.info(

            "Crescendo completed: %d success, %d failed",

            len(executor_result.completed_results),

            len(executor_result.incomplete_objectives),

        )



    except asyncio.TimeoutError:

        logger.warning("Crescendo attack timed out after 150s")

        # 鐏忔繆鐦Λ鈧槐銏ゅ劥閸掑棛绮ㄩ弸?

        await _retrieve_partial_results(ctx, "crescendo")

    except _SecurityAuditError as e:

        logger.warning("Crescendo: security_audit_fail detected: %s, returning empty results", e)

    except Exception as e:

        # L5 v20: 閹规洝骞?IntegrityError, 鐏忔繆鐦幁銏狀槻闁劌鍨庣紒鎾寸亯

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

            # L5 v20: 閸楀厖濞囬弰顖炴姜 IntegrityError, 娑旂喎鐨剧拠鏇熶划婢跺秹鍎撮崚鍡欑波閺?

            await _retrieve_partial_results(ctx, "crescendo")



    return results



async def _run_tap(

    ctx: PipelineContext,

    objectives: list[str],

) -> dict[str, list[Any]]:

    """鐎电懓銇戠拹銉ф窗閺嶅洦澧界悰?TAP 閺嶆垶鎮崇槐銏℃暰閸戞眹鈧?



    L5 optimization: tree_width from SSOT (reduced), tree_depth from SSOT (reduced)

    閸戝繐鐨?API 鐠嬪啰鏁?~75%閿涘奔绻氶幐?ASR~50%閵?



    Args:

        ctx: 濞翠焦鎸夌痪澶哥瑐娑撳鏋冮妴?

        objectives: 婢惰精瑙﹂惄顔界垼閸掓銆冮妴?



    Returns:

        TAP 閺€璇插毊缂佹挻鐏夐妴?

    """

    from pyrit.executor.attack import (
        AttackAdversarialConfig,
        TAPAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective



    results: dict[str, list[Any]] = {}



    # L5 v36: suitable_for 閸掑棗褰?閳?閸欘亝澧界悰宀勨偓鍌氭値 TAP 閻ㄥ嫮顫掔€?

    # 鐎涳附婀虫笟婵囧祦: Mehrotra et al. (arXiv:2312.02191) 閳?TAP 閺嶆垶鎮崇槐銏狀嚠闂団偓鐟?

    # 婢舵艾鍨庨弨顖涘赴缁便垻娈戠粔宥呯摍 (婵″倸浼愰崗鐑芥懠瀵繗鐨熼悽? 閺囧瓨婀侀弫?

    tap_objectives = _filter_by_suitable_for(objectives, ctx, "tap")

    if not tap_objectives:

        logger.info("TAP: no objectives suitable for this technique, skipping")

        return results



    # L5 v41: 閺€鎯ь啍闂勬劕鍩楁禒?3 閳?8 閳?鐎圭偞鍨崷鐑樻珯娑?ASR 娴兼ê鍘?

    # 鐎涳附婀虫笟婵囧祦: Mehrotra et al. (arXiv:2312.02191) 閳?TAP 閺嶆垶鎮崇槐?ASR=50-80%

    # 閺囨潙顦块惄顔界垼 = 閺囨潙顦块幋鎰閺堣桨绱?(閼辨柨鎮庡鍌滃芳 P=1-閳?1-p_i))

    if len(tap_objectives) > 8:

        tap_objectives = tap_objectives[:8]

        logger.info(

            "L5 v41: TAP limited to top-8 objectives (MTOS-ranked)"

        )



    try:

        # L5 v23: 閻╁瓨甯存担璺ㄦ暏閸樼喓鏁?FloatScaleThresholdScorer, 缁夊娅?AdaptiveDualFloatJudgeScorer

        # 閸樼喎娲? AdaptiveDualFloatJudgeScorer 缂佈勫 FloatScaleThresholdScorer 娴ｅ棗鍞撮柈?

        # 鐠嬪啰鏁ょ€?scorer 閺冩儼绻戦崶鐐烘姜閺嶅洤鍣崐? 鐎佃壈鍤?TAP 閼哄倻鍋ｉ幎銉╂晩:

        # "TrueFalseScorer score value must be True or False"

        # TAP 閸樼喓鏁撶拋鎹愵吀鐟曚焦鐪?FloatScaleThresholdScorer (arXiv:2312.02191 鎼?.2)

        # 鐎涳附婀虫笟婵囧祦: Mehrotra et al. (arXiv:2312.02191) 閳?TAP 娴ｈ法鏁?FloatScaleScorer



        from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig



        scorer = _create_fallback_fsts(ctx)

        logger.info("TAP scorer: FloatScaleThresholdScorer (threshold=0.2) 閳?L5 v34 tuned")



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



        # L5 v16: TAP 闂嗗棙鍨?MTOS 婢舵俺鐤嗛柅澶岊潚閹烘帒绨?

        # 鐎涳附婀虫笟婵囧祦: Chao et al. (arXiv:2310.08419) 閳?TAP 閺勵垰顦挎潪顔界埐閹兼粎鍌ㄩ弨璇插毊,

        # 娴?娑?ASR 缁夊秴鐡欓弴鎾偓鍌氭値婢舵俺鐤嗘潻顓濆敩娴兼ê瀵? 妤?ASR 缁夊秴鐡欓崡鏇＄枂瀹稿弶鍨氶崝?

        # L5 v36: 娴肩姴鍙?technique_name='tap' 閸氼垳鏁ゆ禍銈呭级 ASR 閸忓牓鐛欓崝鐘虫綀

        mtos_objectives = _apply_mtos_ranking(tap_objectives, ctx, technique_name="tap")



        seed_groups = [

            AttackSeedGroup(seeds=[SeedObjective(value=obj)])

            for obj in mtos_objectives

        ]



        # L5 v45: 缂佺喍绔存禒?ctx.args 鐠囪褰囬獮璺哄絺閺?(SSOT: config/defaults.yaml max_concurrency=3)

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

            timeout=200,  # L5浼樺寲: 400鈫?00s, depth=3/width=2 (12 nodes/obj), 200s 瓒冲

        )



        results["tap"] = list(executor_result.completed_results)

        logger.info(

            "TAP completed: %d success, %d failed",

            len(executor_result.completed_results),

            len(executor_result.incomplete_objectives),

        )



    except asyncio.TimeoutError:

        logger.warning("TAP attack timed out after 200s")

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

    """鐎电懓銇戠拹銉ф窗閺嶅洦澧界悰?PAIR 鏉╊厺鍞导妯哄閺€璇插毊閵?



    L5 閺傛澘顤? PAIR 娴ｆ粈璐熺粭顑跨瑏閸楀洨楠囬梼鑸殿唽閵?

    tree_width from SSOT (single-stream), tree_depth from SSOT (iterations)

    API 鐠嬪啰鏁ら柌蹇旂€亸蹇ョ礉ASR 40-60%閵?



    鐎涳附婀虫笟婵囧祦: Chao et al. (arXiv:2310.08419)



    Args:

        ctx: 濞翠焦鎸夌痪澶哥瑐娑撳鏋冮妴?

        objectives: 婢惰精瑙﹂惄顔界垼閸掓銆冮妴?



    Returns:

        PAIR 閺€璇插毊缂佹挻鐏夐妴?

    """

    from pyrit.executor.attack import (
        AttackAdversarialConfig,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.executor.attack.multi_turn.pair import PAIRAttack
    from pyrit.models import AttackSeedGroup, SeedObjective



    results: dict[str, list[Any]] = {}



    # L5 v36: suitable_for 閸掑棗褰?閳?閸欘亝澧界悰宀勨偓鍌氭値 PAIR 閻ㄥ嫮顫掔€?

    # 鐎涳附婀虫笟婵囧祦: Chao et al. (arXiv:2310.08419) 閳?PAIR 鐎靛綊娓剁憰浣藉嚡娴狅絼绱崠鏍畱缁夊秴鐡欓張澶嬫櫏

    pair_objectives = _filter_by_suitable_for(objectives, ctx, "pair")

    if not pair_objectives:

        logger.info("PAIR: no objectives suitable for this technique, skipping")

        return results



    try:

        # L5 v23: 閻╁瓨甯存担璺ㄦ暏閸樼喓鏁?FloatScaleThresholdScorer, 缁夊娅?AdaptiveDualFloatJudgeScorer

        # 閸樼喎娲? 娑?_run_tap 娣囶喖顦查惄绋挎倱 閳?AdaptiveDualFloatJudgeScorer 鏉╂柨娲栭棃鐐寸垼閸戝棗鈧?

        # 鐎佃壈鍤?PAIR 閼哄倻鍋ｉ幎銉╂晩閵嗕揪AIR 缂佈勫 TAP, 閸樼喓鏁撴担璺ㄦ暏 FloatScaleScorer閵?

        # 鐎涳附婀虫笟婵囧祦: Chao et al. (arXiv:2310.08419) 閳?PAIR 娴ｈ法鏁?FloatScaleScorer



        from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig



        scorer = _create_fallback_fsts(ctx)

        logger.info("PAIR scorer: FloatScaleThresholdScorer (threshold=0.2) 閳?L5 v34 tuned")



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

            tree_width=_get_config_int(ctx, "pair_tree_width", 1),    # PAIR: 閸楁洘绁︽潻顓濆敩

            tree_depth=_get_config_int(ctx, "pair_tree_depth", 7),   # L5 v50: depth=10閳?, 楠炲疇銆€ ASR 娑撳氦绉撮弮鍫曨棑闂?(arXiv:2406.12609)

            prepended_conversation_config=pair_prepended_config,

        )



        # L5 v16: PAIR 闂嗗棙鍨?MTOS 婢舵俺鐤嗛柅澶岊潚閹烘帒绨?

        # 鐎涳附婀虫笟婵囧祦: Chao et al. (arXiv:2310.08419) 閳?PAIR 閺勵垰顦挎潪顔垮嚡娴狅絼绱崠鏍ㄦ暰閸?

        # 娴?娑?ASR 缁夊秴鐡欓弴鎾偓鍌氭値婢舵俺鐤嗘潻顓濆敩, 妤?ASR 缁夊秴鐡欓崡鏇＄枂瀹稿弶鍨氶崝?

        # L5 v36: 娴肩姴鍙?technique_name='pair' 閸氼垳鏁ゆ禍銈呭级 ASR 閸忓牓鐛欓崝鐘虫綀

        mtos_objectives = _apply_mtos_ranking(pair_objectives, ctx, technique_name="pair")



        seed_groups = [

            AttackSeedGroup(seeds=[SeedObjective(value=obj)])

            for obj in mtos_objectives

        ]



        # L5 v45: 缂佺喍绔存禒?ctx.args 鐠囪褰囬獮璺哄絺閺?(SSOT: config/defaults.yaml max_concurrency=3)

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

            timeout=150,  # L5优化: 300→150s, depth=4 (8 LLM calls/obj), 150s 足够

        )



        results["pair"] = list(executor_result.completed_results)

        logger.info(

            "PAIR completed: %d success, %d failed",

            len(executor_result.completed_results),

            len(executor_result.incomplete_objectives),

        )



    except asyncio.TimeoutError:

        logger.warning("PAIR attack timed out after 150s")

        await _retrieve_partial_results(ctx, "pair")

    except _SecurityAuditError as e:

        logger.warning("PAIR: security_audit_fail detected: %s, returning empty results", e)

    except Exception as e:

        if _is_security_audit_error(str(e)):

            logger.warning("PAIR: security_audit_fail in exception: %s", e)

        else:

            logger.error("PAIR attack failed: %s", e)



    return results



