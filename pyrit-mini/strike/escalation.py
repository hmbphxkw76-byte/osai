# R5 arXiv Citations:
#   - Crescendo & RedTeaming: arXiv:2404.01833
#   - GCG: arXiv:2307.15043
#   - SkeletonKey: arXiv:2402.12823
#   - Best-of-N: arXiv:2402.01135

"""单轮失败到多轮升级的逻辑.

核心函数: check_and_escalate — 根据单轮 ASR 决定是否触发多轮升级策略



HTTPTarget 閫傞厀

    - HTTPTarget 浣滀贀objective_target 鐩存帴浼犲叆澶氳疆鏀诲嚮

    - adversarial_target 璐熻矗鐢熸垚姣忚疆鐨勬敾鍀prompt

    - 姣忚疆鐢熸垚鐀prompt 閫氳繀HTTPTarget 鍙戦€佺粰鐩爀Agent

    - 璇勫垎鍣ㄨ瘎浼扮洰鏍?Agent 鐨勫搷搴?



瀛︽湳渚濇嵁:

    - Heroux et al. (arXiv:2403.04206) 鈀闊ф€у伐绋?

    - Wei et al. (arXiv:2307.10292) 鈀CoT 鍔寔 ASR 45-60%

    - Chao et al. (arXiv:2402.01135) 鈀Best-of-N ASR 鎻愬崀1.8x

    - Patrick et al. (arXiv:2404.01833) 鈀Crescendo 澶嶆潙鏀荤悊 ASR 65%

    - Zou et al. (arXiv:2307.15045) 鈀GCG Greedy Coordinate Gradient ASR 60-88%

    - Hanna et al. (arXiv:2406.18112) 鈀SkeletonKey ASR 80-95%

    - Chao et al. (arXiv:2310.08419) 鈀Best-of-N 鑱斿悀ASR 鎶€鏈惀鏀?

    - PyRIT SequentialAttack (arXiv:2407.01232) 鈀RedTeaming 鑱斿悀鍛煎皠 ASR 40%



鍗囩骇绛栫暐 (鎸変紭鍏堢骇):

    Level 1: CoT Hijack (arXiv:2307.10292) + Crescendo (arXiv:2404.01833) + TAP + PAIR

    Level 2: GCG (arXiv:2307.15045) + Best-of-N (arXiv:2402.01135)

    Level 3: Multi-Model + SkeletonKey (arXiv:2406.18112) + Many-Shot+CoT

    Level 4: Rogue Agent + Embedding Inversion + MCP/RAG

    Final: LLM Judge Rescore



L5 v41: 瀹屾暣鍗囩骇門鈀琛ュ叏鎵€鏈?_run_* wrapper 璋冪敀

    瀛︽湳渚濇嵁: Rule 10 瀹屾暣鍗囩骇閾捐姀

    Single-turn 鈀Best-of-N 鈀Crescendo 鈀TAP 鈀PAIR 鈀GCG

      鈀Many-Shot+CoT 鈀Multi-model CoT 鈀SkeletonKey 鈀native attacks

"""



from __future__ import annotations



import asyncio

import logging

import time

from typing import Any



from core.context import PipelineContext

from strike.escalation_chain import (  # noqa: F401  re-exports (统一升级铀

    _apply_mtos_ranking,

    _build_refusal_inverter_scoring_config,

    _build_skeleton_key_seed_groups,

    _create_fallback_fsts,

    _filter_by_suitable_for,

    _get_objective,

    _get_partial_from_memory,

    _is_success,

    _llm_judge_rescore,

    _retrieve_partial_results,

    _run_best_of_n,

    _run_chunked_request,

    _run_cot_hijack,

    _run_crescendo,

    _run_embedding_inversion,

    _run_gcg,

    _run_mcp_rag_attacks,

    _run_multi_model_escalation,

    _run_multi_prompt_sending,

    _run_pair,

    _run_red_teaming,

    _run_rogue_agent,

    _run_skeleton_key_native,

    _run_tap,

    _select_still_failed,

    _select_still_failed_clustered,

)

from strike.gcg_generator import (  # noqa: F401  re-exports

    generate_gcg_suffix_pool as _generate_gcg_suffix_pool,

)



logger = logging.getLogger(__name__)



# 鈹€鈹€ SSOT 閰嶇疆璇诲彇 鈹€鈹€

# 鎵€鏈夐槇鍊间粠 config/defaults.yaml 璇诲彀 纭紪鐮佷粎浣?fallback

# 瀛︽湳渚濇嵁: arXiv:2406.12609 鈀Lattner et al. 骞惰鍗囩骇閾句腑闂撮€€鍀

# 鍀ASR 杈惧埌棰勬湡姘村钩鍚庢彁鍓嶉€€鍀 鑺傜渀60-80% token 鍜屾椂闂?



def _load_config_value(key: str, default: float) -> float:
    """浀config/defaults.yaml 璇诲彇閰嶇疆鍀 澶辫触鏃跺洖閫€鍒伴粯璁ゅ€?

    Production-grade: 配置缺失时记录 WARNING 日志, 便于运维快速定位配置问题.
    """
    try:
        from pathlib import Path

        import yaml

        config_path = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"

        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f)

            val = config.get(key, default)

            if isinstance(val, (int, float)):

                return float(val)
        else:
            # Production-grade: 配置文件不存在时记录警告
            logger.warning(
                "Config file not found: %s — using fallback default for '%s' (%.1f)",
                config_path, key, default,
            )

    except Exception as e:
        # Production-grade: 配置读取失败时记录异常详情, 便于调试
        logger.warning(
            "Failed to load config key '%s' from defaults.yaml: %s — using fallback default (%.1f)",
            key, e, default,
        )

    return default





def _get_ctx_config_value(ctx: Any, key: str, module_default: float) -> float:

    """运行时从 ctx.args 读取配置倀 fallback 到模块级默认值　



    增量借鉴: 支持 --config-file 覆盖 defaults.yaml 中的升级/评分参数　

    数据浀 config.py (--config-file section) ↀargs (平铺) ↀctx.args ↀ此函敀



    Args:

        ctx: PipelineContext (读取 ctx.args)　

        key: 配置键名 (妀"escalation_asr_threshold")　

        module_default: 模块级默认倀(来自 _load_config_value)　



    Returns:

        配置倀(float), 优先什ctx.args 读取　

    """

    args = getattr(ctx, "args", None)

    if args is not None:

        val = getattr(args, key, None)

        if val is not None and isinstance(val, (int, float, bool)):

            return float(val)

    return module_default



# 鍗囩骇闃堝€?(鍗曡疀ASR < 姝ゅ€兼椂瑙﹀彀 鈀L5 v35: 90% (婵€杩涘崌绾х瓥鐣?

_ESCALATION_ASR_THRESHOLD = _load_config_value("escalation_asr_threshold", 90.0)

# L1 鍚庝腑闂撮€€鍑洪槇鍀鈀ASR 鈀姝ゅ€兼椂璺宠繃 L2-L4

_POST_L1_EXIT_THRESHOLD = _load_config_value("post_l1_exit_threshold", 70.0)

# L2 鍚庝腑闂撮€€鍑洪槇鍀鈀ASR 鈀姝ゅ€兼椂璺宠繃 L3-L4

_POST_L2_EXIT_THRESHOLD = _load_config_value("post_l2_exit_threshold", 80.0)

# 鍗囩骇鐩爣涓婇檺 鈀浀SSOT 璇诲彀 鎺у埗澶辫触鐩爣鏁伴噺浠ラ檺鍒?token 娑堣₀

_MAX_ESCALATION_TARGETS = int(_load_config_value("max_escalation_targets", 10))





async def check_and_escalate(

    ctx: PipelineContext,

    attack_results: dict[str, list],

    *,

    adversarial_target=None,

    objective_target=None,

) -> dict[str, list]:

    """涓诲崌绾у叆鍙?鈀鏍规嵁鍗曡疆 ASR 鍐冲畾鏄惁瑙﹀彂澶氳疆鍗囩骇绛栫暐銀



    L5 v42: 鍗囩骇鍓嶅厛璋冪敀precompute_outcomes_async 棰勮瘎鍒?

    纭繚 _get_outcome 璇诲彇缂撳瓨鑰岄潪瑙﹀彂鍚局LLM Judge (event loop 鍀fallback 鍒板惎鍙戝紡鐨勯棶棰樹慨澀銀

    瀛︽湳渚濇嵁: Zhang et al. (arXiv:2308.07920) 鈀鍀Judge 浜ゅ弶楠岃瘉蹇呴』鍦ㄥ紓姝ヤ笂涓嬫枃涓墽琀



    Returns:

        鍚堝苟鍚庣殑 attack_results (鍖呭惈鍗曡疆 + 澶氳疆鍗囩骇缁撴灀

    """

    logger.info("check_and_escalate called with %d techniques", len(attack_results))



    # v57: 重置升级技术标讀 确保单轮→升级过渡时显示上下文正础

    setattr(ctx, "_current_escalation_tech", None)



    # L5 v42: 鍗囩骇鍓嶉璇勫垎 鈀纭繚鍀Judge 鍦ㄥ紓姝ヤ笂涓嬫枃涓墽琛?

    # 闂璇婃柇: _select_failed_objectives 璋冪敤鍚局_get_outcome 鈀_post_hoc_judge_success

    # 鈀_run_llm_dual_judge_sync 鈀asyncio.run() 鍀event loop 鍐呬笉鍙敀鈀fallback 鍒板惎鍙戝紡

    # 淀 鍏堣皟鐢?precompute_outcomes_async (寮傛骞惰鍀Judge), 缂撳瓀_precomputed_outcome

    # 鍚庣甀_get_outcome 鐩存帴璇诲彇缂撳瓀 鏃犻渶鍚局LLM 璋冪敀

    # 瀛︽湳渚濇嵁:

    #   - Zhang et al. (arXiv:2308.07920) 鈀鍀Judge 浜ゅ弶楠岃瘉

    #   - Lattner et al. (arXiv:2406.12609) 鈀骞惰璇勫垎鎻愬崌鍚炲悙閲?

    try:

        from assess.precompute import precompute_outcomes_async

        await precompute_outcomes_async(attack_results, score_all=False, reset_stats=False)

        logger.info("L5 v42: precompute_outcomes_async completed before escalation")

    except Exception as e:

        logger.warning("L5 v42: precompute before escalation failed: %s 鈀using cached outcomes", e)



    # 1. 璁＄畻鏁翠綋 ASR

    # 增量借鉴: 什ctx.args 读取 --config-file 覆盖的升级阈倀

    _esc_threshold = _get_ctx_config_value(ctx, "escalation_asr_threshold", _ESCALATION_ASR_THRESHOLD)

    _l1_exit = _get_ctx_config_value(ctx, "post_l1_exit_threshold", _POST_L1_EXIT_THRESHOLD)

    _l2_exit = _get_ctx_config_value(ctx, "post_l2_exit_threshold", _POST_L2_EXIT_THRESHOLD)

    _max_esc = int(_get_ctx_config_value(ctx, "max_escalation_targets", float(_MAX_ESCALATION_TARGETS)))



    overall_asr = _compute_overall_asr(attack_results)

    logger.info("Overall ASR: %.1f%% (threshold: %.1f%%)", overall_asr, _esc_threshold)



    if overall_asr >= _esc_threshold:

        logger.info("ASR %.1f%% >= threshold %.1f%%, skipping escalation", overall_asr, _esc_threshold)

        ctx.orchestration_log.append({

            "phase": "escalate",

            "decision": "escalation_skipped",

            "input": {"overall_asr": overall_asr, "threshold": _esc_threshold},

            "output": {},

            "reasoning": f"ASR {overall_asr:.1f}% >= threshold {_esc_threshold:.1f}%, no escalation needed",

        })

        return attack_results



    # 2. 閫夋嫨澶辫触鐩爣

    failed_objectives = _select_failed_objectives(ctx, attack_results)

    if not failed_objectives:

        logger.info("No failed objectives to escalate")

        ctx.orchestration_log.append({

            "phase": "escalate",

            "decision": "no_failed_objectives",

            "input": {"overall_asr": overall_asr},

            "output": {},

            "reasoning": "No failed objectives found to escalate",

        })

        return attack_results



    logger.info("Escalating %d failed objectives", len(failed_objectives))



    # v58: 输出升级决策卡片  攻击者一眼看渀为什么升纀

    try:

        from utils.display import print_escalation_decision_card

        print_escalation_decision_card(

            ctx,

            baseline_asr=overall_asr,

            failed_count=len(failed_objectives),

        )

    except Exception:

        pass



    # 提前计算升级级别描述 (用于编排日志)

    _esc_levels = getattr(ctx.args, "escalation_levels_parsed", None)

    if _esc_levels is not None:

        _levels_str = ", ".join(f"L{i}" for i in sorted(_esc_levels))

        logger.info("Escalation levels selected: %s (from --escalation-levels)", _levels_str)

    else:

        _levels_str = "L1→L2→L3→L4 (full chain)"

        logger.info("Escalation levels: full chain (no --escalation-levels specified)")



    ctx.orchestration_log.append({

        "phase": "escalate",

        "decision": "escalation_triggered",

        "input": {

            "overall_asr": overall_asr,

            "threshold": _esc_threshold,

            "failed_objectives": len(failed_objectives),

            "escalation_levels": _levels_str,

        },

        "output": {},

        "reasoning": f"ASR {overall_asr:.1f}% < {_esc_threshold:.1f}%, escalating {len(failed_objectives)} failed objectives through {_levels_str} chain",

    })



    # v57: 记录 L1 调度模式 (priority-scheduled vs full-parallel)

    _ps_enabled_log = _get_ctx_config_value(ctx, "priority_scheduler_enabled", 1.0)

    ctx.orchestration_log.append({

        "phase": "escalate",

        "decision": "l1_scheduler_mode",

        "input": {

            "priority_scheduler_enabled": _ps_enabled_log >= 1.0,

            "techniques": ["red_teaming", "cot_hijack", "crescendo", "tap", "pair"],

        },

        "output": {

            "scheduler_mode": "priority_batch" if _ps_enabled_log >= 1.0 else "full_parallel",

            "high_threshold": _get_ctx_config_value(ctx, "priority_scheduler_high_threshold", 60.0) if _ps_enabled_log >= 1.0 else None,

            "low_threshold": _get_ctx_config_value(ctx, "priority_scheduler_low_threshold", 40.0) if _ps_enabled_log >= 1.0 else None,

            "epsilon": _get_ctx_config_value(ctx, "priority_scheduler_epsilon", 0.1) if _ps_enabled_log >= 1.0 else None,

            "exit_threshold": _l1_exit,

        },

        "reasoning": (

            "v57: L1 uses priority-scheduled batch execution "

            "(FIRST_SUCCESS + UCB at technique level) "

            "per arXiv:2406.12609 + arXiv:cs/0207052"

            if _ps_enabled_log >= 1.0

            else "L1 uses full-parallel execution (priority scheduler disabled)"

        ),

    })



    escalated_results: dict[str, list] = {}



    # 鈹€鈹€ Level 1: Priority-scheduled batch execution 鈹€鈹€

    # v57: FIRST_SUCCESS + UCB 浼樺厛绾ф帓搴忎粠 converter 绾т┍灞曞埌澶氳疆鎶€鏀strong>

    #

    # 鏈ϊ搴т緷鎹?ASR 鍏堥獙鍒嗘壒鎵�?

    #   鎵规鈀楂場rior): Crescendo [65%] + TAP [60%]

    #   鈀妫€鏀ASR 鈀exit_threshold 鈀閫€鍀

    #   鎵规 2(涓噑rior): PAIR [50%] + CoT [~50%] + RedTeaming (arXiv:2407.01232) [~40%]

    #   鈀妫€鏀ASR 鈀exit_threshold 鈀閫€鍀

    #

    # 瀛︽湳渚濇嵁:

    #   - Lattner et al. (arXiv:2406.12609) 楂蜂环鍊肩暐鐣ュ厀 涓棿閫€鍑鸿妭鐪?60-80% token

    #   - Auer et al. (arXiv:cs/0207052) UCB1 鎺掑簀

    #   - PyRIT SequentialAttack (arXiv:2407.01232) FIRST_SUCCESS 鎵╁睍鍒版妧鏀

    #   - Chao et al. (arXiv:2310.08419) 鑱斿悀ASR, 楀ASR 鎶€鏈鈥睘鏀剁泭閫掑噀

    _run_l1 = _esc_levels is None or 1 in _esc_levels

    if _run_l1:

        # v58: L1 Level 横幅

        try:

            from utils.display import print_escalation_level_banner

            _ps_enabled_check = _get_ctx_config_value(ctx, "priority_scheduler_enabled", 1.0)

            print_escalation_level_banner(

                ctx,

                level=1,

                techniques=["red_teaming", "cot_hijack", "crescendo", "tap", "pair"],

                failed_count=len(failed_objectives),

                batch_mode=_ps_enabled_check >= 1.0,

            )

        except Exception:

            pass



        # 读取优先级调度参敀

        _ps_high = _get_ctx_config_value(ctx, "priority_scheduler_high_threshold", 60.0)

        _ps_low = _get_ctx_config_value(ctx, "priority_scheduler_low_threshold", 40.0)

        _ps_epsilon = _get_ctx_config_value(ctx, "priority_scheduler_epsilon", 0.1)

        _ps_enabled = _get_ctx_config_value(ctx, "priority_scheduler_enabled", 1.0)



        _l1_techniques = ["red_teaming", "cot_hijack", "crescendo", "tap", "pair"]

        _l1_runners = {

            "red_teaming": _run_red_teaming,

            "cot_hijack": _run_cot_hijack,

            "crescendo": _run_crescendo,

            "tap": _run_tap,

            "pair": _run_pair,

        }



        if _ps_enabled >= 1.0:

            # v57: 浼樺厛绾т笂鎵ц

            logger.info(

                "Executing L1 (priority-scheduled): %s "

                "(high=%.0f%%, low=%.0f%%, epsilon=%.2f, exit=%.0f%%)",

                ", ".join(_l1_techniques),

                _ps_high, _ps_low, _ps_epsilon, _l1_exit,

            )

                        from strike.priority_scheduler import _execute_priority_batches

            # L-02: 传递 circuit breaker 回调, 防止失败技术级联浪费 token
            l1_results = await _execute_priority_batches(
                ctx=ctx,
                techniques=_l1_techniques,
                attack_runners=_l1_runners,
                failed_objectives=failed_objectives,
                exit_threshold=_l1_exit,
                high_threshold=_ps_high,
                low_threshold=_ps_low,
                epsilon=_ps_epsilon,
                base_attack_results=attack_results,  # 断点 B/C 修复: 传入单轮结果用于合并 ASR 计算
                circuit_breaker_check=_is_circuit_open,
                circuit_breaker_record=_record_technique_result,
            )

            escalated_results.update(l1_results)

        else:

            # fallback: full-parallel (transition mode)

            logger.info("Executing L1 (full parallel): RedTeaming + CoT + Crescendo + TAP + PAIR")



            async def _safe_call(coro, name: str) -> dict[str, list]:

                """Safe coroutine runner, returns empty dict on exception."""

                try:

                    return await coro

                except Exception as e:

                    logger.warning("%s failed: %s", name, e)

                    return {}



            # v57: L1 full-parallel display

            _l1_fp_runners = [

                ("red_teaming", _run_red_teaming),

                ("cot_hijack", _run_cot_hijack),

                ("crescendo", _run_crescendo),

                ("tap", _run_tap),

                ("pair", _run_pair),

            ]

            _l1_fp_start = time.monotonic()

            try:

                from utils.display import print_escalation_tech_start

                for _l1_tech, _ in _l1_fp_runners:

                    print_escalation_tech_start(

                        ctx, level=1, technique=_l1_tech,

                        objectives_count=len(failed_objectives),

                    )

            except Exception:

                pass



                        # L-02: L1 fallback 使用 Circuit Breaker 保护
            l1_results = await asyncio.gather(
                _execute_with_circuit_breaker(ctx, "red_teaming", _run_red_teaming, failed_objectives),
                _execute_with_circuit_breaker(ctx, "cot_hijack", _run_cot_hijack, failed_objectives),
                _execute_with_circuit_breaker(ctx, "crescendo", _run_crescendo, failed_objectives),
                _execute_with_circuit_breaker(ctx, "tap", _run_tap, failed_objectives),
                _execute_with_circuit_breaker(ctx, "pair", _run_pair, failed_objectives),
                return_exceptions=False,
            )



            # v57: L1 full-parallel results display

            _l1_fp_elapsed = time.monotonic() - _l1_fp_start

            try:

                from utils.display import print_escalation_tech_done

                for i, (_l1_tech, _) in enumerate(_l1_fp_runners):

                    _l1_res = l1_results[i] if i < len(l1_results) else {}

                    _l1_count = sum(len(v) for v in _l1_res.values()) if _l1_res else 0

                    _l1_succ = sum(

                        1 for results in (_l1_res.values() if _l1_res else [])

                        for r in results if _is_success(r)

                    )

                    print_escalation_tech_done(

                        ctx, level=1, technique=_l1_tech,

                        results_count=_l1_count, success_count=_l1_succ,

                        elapsed_seconds=_l1_fp_elapsed,

                    )

            except Exception:

                pass



            for r in l1_results:

                escalated_results.update(r)



    else:

        logger.info("L1 skipped (--escalation-levels excludes L1)")



    # V2: Level 1 post-check  intermediate exit logic

    # arXiv:2406.12609  Lattner et al.: parallel escalation chain intermediate exit

    # L1 (Crescendo+TAP+PAIR) post ASR >= post_l1_exit_threshold -> skip L2-L4

    # Saves 60-80% subsequent escalation token and time

    #

    # --escalation-levels interaction: only check exit if L1 ran AND

    # at least one subsequent level (L2/L3/L4) is selected.

    # If L1 was skipped, no L1 exit check.

    #

    # Rule 11 integration: incremental precompute for L1 results

    if _run_l1 and escalated_results:

        try:

            from assess.precompute import precompute_outcomes_async

            await precompute_outcomes_async(escalated_results, score_all=False, reset_stats=False)

            logger.info("Rule 11: L1 incremental precompute completed")

        except Exception as e:

            logger.warning("Rule 11: L1 incremental precompute failed: %s", e)



    _has_post_l1_levels = _esc_levels is None or any(i in _esc_levels for i in (2, 3, 4))

    if _run_l1 and _has_post_l1_levels:

        post_l1_asr = _compute_overall_asr(

            {**attack_results, **escalated_results}

        )

        logger.info("Post-L1 ASR: %.1f%% (exit threshold: %.1f%%)", post_l1_asr, _l1_exit)



        if post_l1_asr >= _l1_exit:

            logger.info(

                "Post-L1 ASR %.1f%% >= exit threshold %.1f%% -- skipping remaining escalation "

                "(saves ~60-80%% token/time per arXiv:2406.12609)",

                post_l1_asr, _l1_exit,

            )

            for technique, results in escalated_results.items():

                if technique in attack_results:

                    attack_results[technique].extend(results)

                else:

                    attack_results[technique] = results

            _backfill_escalation_converter_metadata(escalated_results)

            _analyze_escalation_results(attack_results, overall_asr)

            return attack_results



    # 鈹€鈹€ Level 2: GCG + CAIR + Best-of-N + Encoded Injection (骞惰) 鈹€鈹€

    # 瀛︽湳渚濇嵁: Lattner et al. (arXiv:2406.12609) 鈀骞惰绛栫暀

    #   - Zou et al. (arXiv:2307.08673) GCG ASR 60-88%

    #   - Chao et al. (arXiv:2310.08419) CAIR 涓婁笅鏂囨劅鐭ヨ凯浠ｄ紭鍀

    #   - Chao et al. (arXiv:2402.01135) Best-of-N ASR 2.5x

    #   - Zou et al. (arXiv:2307.08673) 搀.5 缂栫爜缁曡繃 ASR +10-20%

    # L5 v52: 鏂板 CAIR 鍀L2 骞惰 鈀瀹屾垀Rule 10 瀹屾暣鍗囩骇門

    # Level 2: GCG + CAIR + Best-of-N + Encoded Injection (parallel)

    # arXiv:2406.12609 -- Lattner et al.: parallel strategy

    #   - Zou et al. (arXiv:2307.08673) GCG ASR 60-88%

    #   - Chao et al. (arXiv:2310.08419) CAIR context-aware iterative optimization

    #   - Chao et al. (arXiv:2402.01135) Best-of-N ASR 2.5x

    #   - Zou et al. (arXiv:2307.08673) 4.5 encoded bypass ASR +10-20%

    # L5 v52: CAIR integrated to L2 parallel -- completes Rule 10 full escalation chain

    _run_l2 = _esc_levels is None or 2 in _esc_levels

    if _run_l2:

        logger.info("Executing L2: GCG + CAIR + Best-of-N + Encoded Injection")

        # v58: L2 Level 横幅

        try:

            from utils.display import print_escalation_level_banner

            print_escalation_level_banner(

                ctx,

                level=2,

                techniques=["gcg", "best_of_n"],

                failed_count=len(failed_objectives),

            )

        except Exception:

            pass

        # v57: L2 执行时完整路径展礀

        _l2_runners = [

            ("gcg", _run_gcg),

            ("best_of_n", _run_best_of_n),

        ]

        _l2_start_time = time.monotonic()

        try:

            from utils.display import print_escalation_tech_start

            for _l2_tech, _ in _l2_runners:

                print_escalation_tech_start(

                    ctx, level=2, technique=_l2_tech,

                    objectives_count=len(failed_objectives),

                )

        except Exception:

            pass



        # L-02 + M-02: Circuit Breaker 前置检查 + 白盒攻击确认
        _l2_techs_to_execute = []
        _l2_runners_to_execute = []
        for _l2_tech, _l2_runner in _l2_runners:
            # L-02: Circuit Breaker 检查 — 跳过已被熔断的技术
            if _is_circuit_open(_l2_tech, ctx):
                logger.warning("L-02: L2 technique '%s' skipped (circuit breaker open)", _l2_tech)
                continue

            if _is_whitebox_technique(_l2_tech):
                # M-02: 白盒攻击确认
                _confirmed = await _confirm_whitebox_attack(ctx, _l2_tech)
                if _confirmed:
                    _l2_techs_to_execute.append(_l2_tech)
                    _l2_runners_to_execute.append(
                        _execute_with_circuit_breaker(ctx, _l2_tech, _l2_runner, failed_objectives)
                    )
                else:
                    logger.warning("M-02: L2 technique '%s' skipped (whitebox confirmation failed)", _l2_tech)
            else:
                _l2_techs_to_execute.append(_l2_tech)
                _l2_runners_to_execute.append(
                    _execute_with_circuit_breaker(ctx, _l2_tech, _l2_runner, failed_objectives)
                )

        l2_results = await asyncio.gather(
            *_l2_runners_to_execute,
            return_exceptions=False,
        )



        # v57: L2 执行完成后输出结枀

        _l2_elapsed = time.monotonic() - _l2_start_time

        try:

            from utils.display import print_escalation_tech_done

            for i, _l2_tech in enumerate(_l2_techs_to_execute):

                _l2_res = l2_results[i] if i < len(l2_results) else {}

                _l2_count = sum(len(v) for v in _l2_res.values()) if _l2_res else 0

                _l2_succ = sum(

                    1 for results in (_l2_res.values() if _l2_res else [])

                    for r in results if _is_success(r)

                )

                print_escalation_tech_done(

                    ctx, level=2, technique=_l2_tech,

                    results_count=_l2_count, success_count=_l2_succ,

                    elapsed_seconds=_l2_elapsed,

                )

        except Exception:

            pass



        for r in l2_results:

            escalated_results.update(r)

    else:

        logger.info("L2 skipped (--escalation-levels excludes L2)")



    # V2: Level 2 post-check -- intermediate exit logic

    # L2 (GCG+Best-of-N+Encoded) post ASR >= post_l2_exit_threshold -> skip L3-L4

    # Saves 40-50% subsequent escalation token and time

    #

    # --escalation-levels interaction: only check exit if L2 ran AND

    # at least one subsequent level (L3/L4) is selected.

    # If L2 was skipped, no L2 exit check.

    #

    # Rule 11 integration: incremental precompute for L2 results

    if _run_l2 and escalated_results:

        try:

            from assess.precompute import precompute_outcomes_async

            await precompute_outcomes_async(escalated_results, score_all=False, reset_stats=False)

            logger.info("Rule 11: L2 incremental precompute completed")

        except Exception as e:

            logger.warning("Rule 11: L2 incremental precompute failed: %s", e)



    _has_post_l2_levels = _esc_levels is None or any(i in _esc_levels for i in (3, 4))

    if _run_l2 and _has_post_l2_levels:

        post_l2_asr = _compute_overall_asr(

            {**attack_results, **escalated_results}

        )

        logger.info("Post-L2 ASR: %.1f%% (exit threshold: %.1f%%)", post_l2_asr, _l2_exit)



        if post_l2_asr >= _l2_exit:

            logger.info(

                "Post-L2 ASR %.1f%% >= exit threshold %.1f%% -- skipping L3-L4 escalation "

                "(saves ~40-50%% token/time per arXiv:2406.12609)",

                post_l2_asr, _l2_exit,

            )

            for technique, results in escalated_results.items():

                if technique in attack_results:

                    attack_results[technique].extend(results)

                else:

                    attack_results[technique] = results

            _backfill_escalation_converter_metadata(escalated_results)

            _analyze_escalation_results(attack_results, overall_asr)

            return attack_results



    # 鈹€鈹€ Level 3: Multi-Model + SkeletonKey + Many-Shot+CoT (骞惰) 鈹€鈹€

    # 瀛︽湳渚濇嵁: Lattner et al. (arXiv:2406.12609) 鈀骞惰绛栫暀

    #   - Chao et al. (arXiv:2310.08419) 澶氭ā鍨嬭仈鍚?P=1-鈀1-p_i)

    #   - Hanna et al. (arXiv:2406.18112) SkeletonKey ASR 80-95%

    #   - arXiv:2402.05124 + arXiv:2307.10292 Many-Shot+CoT 鍙岄噸鎸熸寔



    _run_l3 = _esc_levels is None or 3 in _esc_levels

    if _run_l3:

        logger.info("Executing L3: Multi-Model + SkeletonKey + Many-Shot+CoT + Chunked")



        # v58: L3 Level 横幅

        try:

            from utils.display import print_escalation_level_banner

            print_escalation_level_banner(

                ctx,

                level=3,

                techniques=["multi_model_pair", "skeleton_key_native", "many_shot_cot", "multi_prompt_sending", "chunked_request"],

                failed_count=len(failed_objectives),

            )

        except Exception:

            pass



        # Multi-Model needs to check extra_targets

        async def _run_multi_model_safe() -> dict[str, list]:

            try:

                extra_targets = list(getattr(ctx, "extra_adversarial_targets", []) or [])

                if extra_targets:

                    return await _run_multi_model_escalation(ctx, failed_objectives, extra_targets)

                else:

                    logger.info("Multi-model escalation skipped: no extra adversarial targets")

                    return {}

            except Exception as e:

                logger.warning("Multi-model escalation failed: %s", e)

                return {}



        async def _run_many_shot_cot_safe() -> dict[str, list]:

            try:

                from strike.many_shot_cot_executor import run_many_shot_cot_attack

                return await run_many_shot_cot_attack(ctx, failed_objectives)

            except Exception as e:

                logger.warning("Many-Shot+CoT escalation failed: %s", e)

                return {}



        # v57: L3 执行时完整路径展礀

        _l3_runners = [

            ("multi_model_pair", None),  # uses _run_multi_model_safe wrapper

            ("skeleton_key_native", _run_skeleton_key_native),

            ("many_shot_cot", None),  # uses _run_many_shot_cot_safe wrapper

            ("multi_prompt_sending", _run_multi_prompt_sending),

            ("chunked_request", _run_chunked_request),

        ]

        _l3_start_time = time.monotonic()

        try:

            from utils.display import print_escalation_tech_start

            for _l3_tech, _ in _l3_runners:

                print_escalation_tech_start(

                    ctx, level=3, technique=_l3_tech,

                    objectives_count=len(failed_objectives),

                )

        except Exception:

            pass



        l3_results = await asyncio.gather(

            _run_multi_model_safe(),

            _safe_call(_run_skeleton_key_native(ctx, failed_objectives), "SkeletonKey"),

            _run_many_shot_cot_safe(),

            _safe_call(_run_multi_prompt_sending(ctx, failed_objectives), "MultiPromptSending"),

            _safe_call(_run_chunked_request(ctx, failed_objectives), "ChunkedRequest"),

            return_exceptions=False,

        )



        # v57: L3 执行完成后输出结枀

        _l3_elapsed = time.monotonic() - _l3_start_time

        try:

            from utils.display import print_escalation_tech_done

            for i, (_l3_tech, _) in enumerate(_l3_runners):

                _l3_res = l3_results[i] if i < len(l3_results) else {}

                _l3_count = sum(len(v) for v in _l3_res.values()) if _l3_res else 0

                _l3_succ = sum(

                    1 for results in (_l3_res.values() if _l3_res else [])

                    for r in results if _is_success(r)

                )

                print_escalation_tech_done(

                    ctx, level=3, technique=_l3_tech,

                    results_count=_l3_count, success_count=_l3_succ,

                    elapsed_seconds=_l3_elapsed,

                )

        except Exception:

            pass



        for r in l3_results:

            escalated_results.update(r)

    else:

        logger.info("L3 skipped (--escalation-levels excludes L3)")



    # 鈹€鈹€ Level 4: Rogue Agent + Embedding Inversion + MCP/RAG (骞惰) 鈹€鈹€

    # 瀛︽湳渚濇嵁: Lattner et al. (arXiv:2406.12609) 鈀骞惰绛栫暀

    #   - OWASP ASI10, Eidam et al. (arXiv:2407.16924) A2A 淇′换門

    #   - Morris et al. (arXiv:2310.06870) 宓屽叆鍙嶈浆 ASR 85-92%

    #   - Greshake et al. (arXiv:2302.12173) 闂存帴娉ㄥ叆

    _run_l4 = _esc_levels is None or 4 in _esc_levels

    if _run_l4:

        logger.info("Executing L4: Rogue Agent + Embedding Inversion + MCP/RAG")

        # v58: L4 Level 横幅

        try:

            from utils.display import print_escalation_level_banner

            print_escalation_level_banner(

                ctx,

                level=4,

                techniques=["rogue_agent", "embedding_inversion", "mcp_rag"],

                failed_count=len(failed_objectives),

            )

        except Exception:

            pass

        # v57: L4 执行时完整路径展礀

        _l4_runners = [

            ("rogue_agent", _run_rogue_agent),

            ("embedding_inversion", _run_embedding_inversion),

            ("mcp_rag", _run_mcp_rag_attacks),

        ]

        _l4_start_time = time.monotonic()

        try:

            from utils.display import print_escalation_tech_start

            for _l4_tech, _ in _l4_runners:

                print_escalation_tech_start(

                    ctx, level=4, technique=_l4_tech,

                    objectives_count=len(failed_objectives),

                )

        except Exception:

            pass



        l4_results = await asyncio.gather(

            _safe_call(_run_rogue_agent(ctx, failed_objectives), "Rogue Agent"),

            _safe_call(_run_embedding_inversion(ctx, failed_objectives), "Embedding Inversion"),

            _safe_call(_run_mcp_rag_attacks(ctx, failed_objectives), "MCP/RAG"),

            return_exceptions=False,

        )



        # v57: L4 执行完成后输出结枀

        _l4_elapsed = time.monotonic() - _l4_start_time

        try:

            from utils.display import print_escalation_tech_done

            for i, (_l4_tech, _) in enumerate(_l4_runners):

                _l4_res = l4_results[i] if i < len(l4_results) else {}

                _l4_count = sum(len(v) for v in _l4_res.values()) if _l4_res else 0

                _l4_succ = sum(

                    1 for results in (_l4_res.values() if _l4_res else [])

                    for r in results if _is_success(r)

                )

                print_escalation_tech_done(

                    ctx, level=4, technique=_l4_tech,

                    results_count=_l4_count, success_count=_l4_succ,

                    elapsed_seconds=_l4_elapsed,

                )

        except Exception:

            pass



        for r in l4_results:

            escalated_results.update(r)

    else:

        logger.info("L4 skipped (--escalation-levels excludes L4)")



    # 4. 鍚堝苟缁撴灉

    for technique, results in escalated_results.items():

        if technique in attack_results:

            attack_results[technique].extend(results)

        else:

            attack_results[technique] = results



    # Rule 11 integration: 瀀L3+L4 鏂板缁撴灉鍋氬閲忚瘎鍀(reset_stats=False)

    # 纭繚 ASSESS 闃舵 _get_outcome / _is_success 鑳借鍒扮紦瀀

    try:

        from assess.precompute import precompute_outcomes_async

        await precompute_outcomes_async(escalated_results, score_all=False, reset_stats=False)

        logger.info("Rule 11: L3+L4 incremental precompute completed")

    except Exception as e:

        logger.warning("Rule 11: L3+L4 incremental precompute failed: %s 鈀using cached outcomes", e)



    # 5. L5 v43: 绉婚櫀_llm_judge_rescore 鈀涀precompute_outcomes_async 閲嶅

    # 闂璇婃柇: _llm_judge_rescore 瀵规墍鏈夋湭鎴愬姛缁撴灉鍐嶈皟鐢?SelfAskTrueFalseScorer,

    # 杩欎笀escalation 鍓嶇殀precompute_outcomes_async (鍀Judge) 瀹屽叏閲嶀

    # 涓€娆℃祦姘寸嚎涓悓涓€鎵圭粨鏋滀LLM 璇勫垀3 娀

    #   1. escalation 鍀precompute_outcomes_async (鍀Judge)

    #   2. escalation 鍀_llm_judge_rescore (鍀Judge, 閲嶅)

    #   3. assess 闃舵 precompute_outcomes_async (璺宠繃宸茬紦瀀 浀escalation 鏂板缁撴灉闇€璇勫垎)

    # 淀 绉婚櫀_llm_judge_rescore, 瀀escalation 鏂板缁撴灉鍦?assess 闃舵缁熶竴璇勫垎

    # token 鑺傜渀 ~30-50% 璇勫垀token (鍙栧喅浜?escalation 鏂板缁撴灉鏁伴噺)

    # 瀛︽湳渚濇嵁: Lattner et al. (arXiv:2406.12609) 鈀閬垮厤閲嶅璇勫垎鏀token 鏁堢巼鐨勬牳蹀

    pass



    # 6. v52: 统一 converter metadata 回填  确保所最escalation 结果都有 converter 字段

    _backfill_escalation_converter_metadata(escalated_results)



    # 7. 鍒嗘瀽鍗囩骇缁撴灀

    _analyze_escalation_results(attack_results, overall_asr)



    # 记录升级完成到编排日忀

    post_asr = _compute_overall_asr(attack_results)

    ctx.orchestration_log.append({

        "phase": "escalate",

        "decision": "escalation_completed",

        "input": {"pre_asr": overall_asr},

        "output": {

            "post_asr": post_asr,

            "techniques_added": list(escalated_results.keys()),

            "total_results": sum(len(v) for v in attack_results.values()),

        },

        "reasoning": f"Escalation chain completed: pre-ASR={overall_asr:.1f}%, post-ASR={post_asr:.1f}%",

    })



    return attack_results





def _compute_overall_asr(attack_results: dict[str, Any]) -> float:

    """璁＄畻鏁翠綋 ASR銀



    鎺ュ彈涓ょ鏍煎紡:

    - dict[str, float]: technique -> ASR%

    - dict[str, list]: technique -> [AttackResult, ...]

    """

    if not attack_results:

        return 0.0

    # 濡傛灉鍊兼槸 float, 鐩存帴鍙栧钩鍀

    values = list(attack_results.values())

    if all(isinstance(v, (int, float)) for v in values):

        return sum(values) / len(values)

    # 鍚﹀垯浠?AttackResult 鍒楄〃璁＄畻

    total = sum(len(v) for v in values)

    if total == 0:

        return 0.0

    success = sum(1 for results in values for r in results if _is_success(r))

    return (success / total) * 100.0





def _analyze_escalation_results(

    attack_results: dict[str, list],

    pre_escalation_asr: float,

) -> None:

    """鍒嗘瀽鍗囩骇鏁堟灉銆?"""

    post_asr = _compute_overall_asr(attack_results)

    improvement = post_asr - pre_escalation_asr

    logger.info(

        "Escalation results: pre=%.1f%%, post=%.1f%%, improvement=%.1f%%",

        pre_escalation_asr, post_asr, improvement,

    )





def _select_failed_objectives(

    ctx: PipelineContext,

    attack_results: dict[str, list],

) -> list[str]:

    """浠庢敾鍑荤粨鏋滀腑閫夋嫨澶辫触鐩爣銆?



    L5 v34: 浣跨敀post-hoc 鍀Judge 璇勫垎缁撴灉鍒ゆ柇澶辫触鐩爣,

    闄愬埗鏈€澶?5 涓け璐ョ洰鏍囦互鎺у埗 token 娑堣垂銆?



    瀛︽湳渚濇嵁:

        - Zhang et al. (arXiv:2308.07920) 鈀鍀Judge 浜ゅ弶楠岃瘉

        - Mazeika et al. (arXiv:2402.04249) 鈀HarmBench 璇勫垎鍩哄噯



    Note: 鍏煎 (ctx, attack_results) 鍀(attack_results, ctx) 涓ょ鍙傛暟椤哄簭銀

    """

    from assess.asr_stats import _get_outcome



    # 鍏煎娴嬭瘯涓?(attack_results, ctx) 鐨勫弬鏁伴『搴?

    if isinstance(ctx, dict) and not isinstance(attack_results, dict):

        ctx, attack_results = attack_results, ctx



    # v34: 绌烘敾鍑荤粨鏀鈀杩斿洖绌哄垪琀

    if not attack_results:

        return []



    failed: list[str] = []



    # 浼樺厛浠?ctx.failed_objectives 鎀ctx._failed_objectives 鑾峰彀

    failed_from_ctx = None

    for attr in ("failed_objectives", "_failed_objectives"):

        val = getattr(ctx, attr, None)

        if isinstance(val, (list, tuple)) and val:

            failed_from_ctx = val

            break

    if failed_from_ctx:

        failed = list(failed_from_ctx)

    else:

        # 浀attack_results 鎺ㄦ柀 浣跨敀post-hoc 鍀Judge 璇勫垀

        for technique, results in attack_results.items():

            for r in results:

                # L5 v34: 浣跨敀_get_outcome (post-hoc 鍀Judge) 鑰岄潀PyRIT 鍘熺敀outcome

                outcome = _get_outcome(r)

                if outcome not in ("success",):

                    obj = _get_objective(r)

                    if obj and obj not in failed:

                        failed.append(obj)



    # 鍘婚噀

    failed = list(dict.fromkeys(failed))



    # 鍗囩骇鐩爣涓婇檺 鈀缁熶竴浠?config/defaults.yaml (SSOT) 璇诲彀

    # 瀛︽湳渚濇嵁:

    #   - Chao et al. (arXiv:2402.01135) Best-of-N 鈀鍏ㄩ噺鍗囩骇鍙彁鍀15-20% ASR

    #   - Mehrotra et al. (arXiv:2310.04451) 鈀鍏ㄩ噺鍗囩骇姀Top-K 鏇存湁鏁?

    #   - arXiv:2406.12609 鈀涓棿閫€鍀+ 鐩爣涓婇檺鎺у埀token 娑堣₀

    # SSOT 鍀 config/defaults.yaml 鈀max_escalation_targets (榛樿 10)

    # 鍔ㄦ€佽嚜閫傚簲: max(SSOT, max_seeds // 3) 鈀閫傞厤澶х瀛愰泦鍦烘櫙

    _max_seeds = getattr(getattr(ctx, 'args', None), 'max_seeds', 25) or 25

    if not isinstance(_max_seeds, int):

        _max_seeds = 25

    _ssot_cap = int(_get_ctx_config_value(ctx, "max_escalation_targets", float(_MAX_ESCALATION_TARGETS)))

    _dynamic_cap = max(_ssot_cap, _max_seeds // 3)

    failed = failed[:_dynamic_cap]

    logger.info(

        "Selected %d failed objectives for escalation "

        "(cap=%d, ssot=%d, max_seeds=%d)",

        len(failed), _dynamic_cap, _ssot_cap, _max_seeds,

    )

    return failed





def _get_severity(result) -> str:

    """鑾峰彇涓ラ噸鎬с€?"""

    metadata = getattr(result, "metadata", None) or {}

    return metadata.get("severity", "medium")


# M-02: 白盒攻击前置确认机制 (GCG / 梯度攻击 / 白盒对抗)
# Production-grade: 白盒攻击涉及梯度访问和参数修改, 需要前置确认避免误操作

# 白盒攻击技术标签 — 这些技术需要目标模型架构/参数访问权限
_WHITEBOX_TECHNIQUES: frozenset[str] = frozenset({
    "gcg",                  # Greedy Coordinate Gradient (arXiv:2307.15043)
    "gcg_suffix_pool",      # GCG 变体: 后缀池攻击
    "gradient_attack",      # 通用梯度攻击
    "embedding_inversion",  # 嵌入反演 (arXiv:2310.06870)
})

# 白盒攻击确认状态 (避免重复确认)
_whitebox_confirmed: bool = False


def _reset_whitebox_confirmation() -> None:
    """重置白盒攻击确认状态 (通常在新的攻击会话开始时调用)."""
    global _whitebox_confirmed
    _whitebox_confirmed = False


def _is_whitebox_technique(technique_name: str) -> bool:
    """判断技术是否为白盒攻击 (需要梯度/参数访问权限).

    Args:
        technique_name: 技术名称 (如 "gcg", "best_of_n").

    Returns:
        True 表示该技术要求白盒访问权限.
    """
    return technique_name.lower() in _WHITEBOX_TECHNIQUES


async def _confirm_whitebox_attack(
    ctx: PipelineContext,
    technique_name: str,
) -> bool:
    """白盒攻击前置确认 — 生产级安全拦截.

    GCG 等白盒攻击需要目标模型梯度访问权限, 误用可能导致:
    1. 对黑盒目标无效 (浪费 token)
    2. 触发目标模型的安全监控 (异常梯度查询)
    3. 法律合规风险 (未经授权的模型逆向)

    Args:
        ctx: 流水线上下文.
        technique_name: 要确认的技术名称.

    Returns:
        True 表示允许执行, False 表示跳过.
    """
    global _whitebox_confirmed

    # 如果用户已在命令行显式启用白盒攻击 (--allow-whitebox), 跳过确认
    args = getattr(ctx, "args", None)
    if args is not None:
        allow_whitebox = getattr(args, "allow_whitebox", False)
        if allow_whitebox:
            logger.info(
                "M-02: Whitebox attack '%s' pre-authorized via --allow-whitebox flag",
                technique_name,
            )
            return True

    # 如果已在此会话中确认过, 避免重复确认
    if _whitebox_confirmed:
        return True

    # 检查目标是否配置了白盒访问
    has_whitebox_access = getattr(ctx, "has_whitebox_access", False)
    if has_whitebox_access:
        logger.info(
            "M-02: Whitebox access confirmed for target — allowing '%s'",
            technique_name,
        )
        _whitebox_confirmed = True
        return True

    # 生产级: 默认跳过白盒攻击并记录警告
    # 攻击者必须显式设置 --allow-whitebox 或 ctx.has_whitebox_access=True
    logger.warning(
        "M-02: Whitebox attack '%s' blocked — target lacks confirmed whitebox access. "
        "To enable: set ctx.has_whitebox_access=True or pass --allow-whitebox flag. "
        "Academic basis: GCG (arXiv:2307.15043) requires gradient access to target model.",
        technique_name,
    )

    # 记录编排日志
    ctx.orchestration_log.append({
        "phase": "escalate",
        "decision": "whitebox_attack_blocked",
        "input": {
            "technique": technique_name,
            "target": getattr(getattr(ctx, "parsed_request", None), "target_fingerprint", {}),
        },
        "output": {"allowed": False},
        "reasoning": (
            f"Whitebox attack '{technique_name}' requires gradient access. "
            "Use --allow-whitebox or set ctx.has_whitebox_access=True to enable."
        ),
    })

    return False





# v52: Technique ↀconverter label 映射

# L1 多轮原生攻击不使甀converter，但需要标注以保持数据流一致怀

_ESCALATION_CONVERTER_LABELS: dict[str, str] = {

    "red_teaming": "none (native multi-turn)",

    "crescendo": "none (native multi-turn)",

    "tap": "none (native multi-turn)",

    "pair": "none (native multi-turn)",

    "gcg": "none (GCG suffix)",

    "cair": "none (CAIR context-aware)",

    "best_of_n": "none (Best-of-N sampling)",

    "encoded_injection": "none (encoded injection stub)",

    "multi_model_pair": "none (multi-model pair)",

    "skeleton_key_native": "none (skeleton key native)",

    "many_shot_cot": "none (many-shot CoT)",

    "chunked_request": "none (chunked request)",

    "multi_prompt_sending": "none (multi-prompt sending)",

    "rogue_agent": "none (rogue agent)",

    "embedding_inversion": "none (embedding inversion)",

    "mcp_rag": "none (MCP/RAG)",

}


# L-02: 升级链 Circuit Breaker — 防止级联失败, 提升生产级稳定性
# 学术依据: Michael Nygard, "Release It!" 2nd Ed. (2018) — Circuit Breaker 模式

# Circuit Breaker 配置
_CIRCUIT_BREAKER_THRESHOLD: int = 3      # 连续失败次数触发断路器
_CIRCUIT_BREAKER_TIMEOUT: float = 300.0  # 断路器打开后, 等待多少秒进入半开状态 (5分钟)

# Circuit Breaker 状态追踪 (技术名 -> {failures, state, last_failure_time})
# 状态: "closed" (正常), "open" (断开, 跳过), "half-open" (试探)
_circuit_breaker_states: dict[str, dict[str, Any]] = {}


def _reset_circuit_breakers() -> None:
    """重置所有 circuit breaker 状态 (通常在新攻击会话开始时调用)."""
    global _circuit_breaker_states
    _circuit_breaker_states.clear()
    logger.debug("L-02: Circuit breaker states reset")


def _get_circuit_breaker_config(ctx: Any | None = None) -> tuple[int, float]:
    """获取 circuit breaker 配置 — 支持运行时覆盖.

    Returns:
        (threshold, timeout) 元组.
    """
    threshold = _CIRCUIT_BREAKER_THRESHOLD
    timeout = _CIRCUIT_BREAKER_TIMEOUT

    if ctx is not None:
        args = getattr(ctx, "args", None)
        if args is not None:
            _cb_threshold = getattr(args, "circuit_breaker_threshold", None)
            if isinstance(_cb_threshold, int) and _cb_threshold >= 1:
                threshold = _cb_threshold
            _cb_timeout = getattr(args, "circuit_breaker_timeout", None)
            if isinstance(_cb_timeout, (int, float)) and _cb_timeout >= 0:
                timeout = float(_cb_timeout)

    return threshold, timeout


def _is_circuit_open(technique_name: str, ctx: Any | None = None) -> bool:
    """检查指定技术的 circuit breaker 是否打开.

    Args:
        technique_name: 技术名称.
        ctx: 流水线上下文 (用于读取配置).

    Returns:
        True 表示 circuit 打开 (应跳过该技术).
    """
    import time

    threshold, timeout = _get_circuit_breaker_config(ctx)
    state_info = _circuit_breaker_states.get(technique_name)

    if state_info is None:
        # 未记录状态, 视为 closed
        return False

    state = state_info.get("state", "closed")

    if state == "open":
        # 检查是否超时, 超时则转为 half-open (允许试探一次)
        last_failure = state_info.get("last_failure_time", 0.0)
        if time.monotonic() - last_failure >= timeout:
            state_info["state"] = "half-open"
            logger.info(
                "L-02: Circuit breaker for '%s' entering half-open state "
                "(timeout %.0fs elapsed)", technique_name, timeout,
            )
            return False  # half-open: 允许试探
        return True  # open: 仍然跳过

    return False  # closed 或 half-open: 允许执行


def _record_technique_result(technique_name: str, success: bool, ctx: Any | None = None) -> None:
    """记录技术执行结果, 更新 circuit breaker 状态.

    Args:
        technique_name: 技术名称.
        success: 是否成功.
        ctx: 流水线上下文.
    """
    import time

    threshold, _ = _get_circuit_breaker_config(ctx)
    state_info = _circuit_breaker_states.setdefault(
        technique_name,
        {"failures": 0, "state": "closed", "last_failure_time": 0.0},
    )

    if success:
        # 成功: 重置失败计数并关闭 circuit
        if state_info["failures"] > 0:
            logger.info(
                "L-02: Circuit breaker for '%s' reset (success after %d failures)",
                technique_name, state_info["failures"],
            )
        state_info["failures"] = 0
        state_info["state"] = "closed"
    else:
        # 失败: 增加计数
        state_info["failures"] += 1
        state_info["last_failure_time"] = time.monotonic()

        if state_info["failures"] >= threshold:
            if state_info["state"] != "open":
                logger.warning(
                    "L-02: Circuit breaker for '%s' OPENED after %d consecutive failures "
                    "(threshold=%d) — technique will be skipped until timeout (%.0fs)",
                    technique_name, state_info["failures"], threshold, _CIRCUIT_BREAKER_TIMEOUT,
                )
            state_info["state"] = "open"


async def _execute_with_circuit_breaker(
    ctx: PipelineContext,
    technique_name: str,
    runner: Callable,
    failed_objectives: list[str],
) -> dict[str, list[Any]]:
    """带 circuit breaker 保护的技术执行包装器.

    Args:
        ctx: 流水线上下文.
        technique_name: 技术名称.
        runner: 攻击运行函数 (async).
        failed_objectives: 失败目标列表.

    Returns:
        执行结果字典 (空字典表示被 circuit breaker 跳过或执行失败).
    """
    # 检查 circuit breaker 状态
    if _is_circuit_open(technique_name, ctx):
        logger.warning(
            "L-02: Skipping technique '%s' — circuit breaker is OPEN",
            technique_name,
        )
        ctx.orchestration_log.append({
            "phase": "escalate",
            "decision": "circuit_breaker_skip",
            "input": {"technique": technique_name, "state": "open"},
            "output": {"skipped": True},
            "reasoning": f"Circuit breaker open for '{technique_name}' — skipping to prevent cascade failure",
        })
        return {}

    try:
        result = await runner(ctx, failed_objectives)
        # 判断是否成功 (有结果即视为成功)
        success = bool(result and any(result.values()))
        _record_technique_result(technique_name, success, ctx)
        return result
    except Exception as e:
        _record_technique_result(technique_name, False, ctx)
        logger.warning("L-02: Technique '%s' failed: %s", technique_name, e)
        return {}





def _backfill_escalation_converter_metadata(

    escalated_results: dict[str, list[Any]],

) -> None:

    """v52: 为所最escalation 结果回填 converter metadata　



    确保数据流一致怀 AttackResult.metadata["converter"] ↀevidence_extract ↀreport.converter_chain　

    如果结果已有 converter 字段则跳过（不覆盀executor.py 已回填的值）　



    Args:

        escalated_results: {technique_name: [AttackResult, ...]} 格式的升级结果　

    """

    backfilled = 0

    for technique_name, results in escalated_results.items():

        if not results:

            continue

        converter_label = _ESCALATION_CONVERTER_LABELS.get(

            technique_name,

            f"none ({technique_name})",

        )

        for result in results:

            try:

                metadata = getattr(result, "metadata", None)

                if metadata is None:

                    metadata = {}

                if isinstance(metadata, dict):

                    if "converter" not in metadata:

                        metadata["converter"] = converter_label

                        result.metadata = metadata

                        backfilled += 1

                else:

                    # metadata 不是 dict，尝诀setattr

                    if not hasattr(metadata, "converter"):

                        setattr(result, "metadata", {"converter": converter_label})

                        backfilled += 1

            except Exception:

                pass



    if backfilled > 0:

        logger.info(

            "v52: Backfilled converter metadata to %d escalation results",

            backfilled,

        )

