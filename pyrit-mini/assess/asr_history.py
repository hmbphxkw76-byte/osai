# arXiv:2307.08673 — Zou et al., GCG (adversarial suffixes ASR 60-88%)
# arXiv:2308.07920 — Zhang et al., Dual Judge cross-validation
"""asr_history 鈥?浠?asr_tracker.py 鎷嗗垎鑰屾潵.

鍖呭惈 ASR 鍘嗗彶淇濆瓨, converter ASR 鍘嗗彶, GCG 鍚庣紑 ASR 鍘嗗彶.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _get_asr_history_path():
    """鍔ㄦ€佽幏鍙?ASR 鍘嗗彶璺緞 (鏀寔娴嬭瘯鏃?monkey-patch seed_ranker._ASR_HISTORY_PATH)銆?"""
    from arm import seed_ranker
    return seed_ranker._ASR_HISTORY_PATH


def save_asr_history(
    asr_per_technique: dict[str, float],
    *,
    attack_results: dict[str, list[Any]] | None = None,
) -> None:
    """灏?ASR 鍘嗗彶鍐欏叆 data/seeds/asr_history.json銆?

    L5 v9: 鍚屾椂鍐欏叆绉嶅瓙绾?ASR, 渚?UCB 鎺掑簭浣跨敤銆?
    瀛︽湳渚濇嵁: Auer et al. (arXiv:cs/0207052) 鈥?UCB1 绠楁硶
    闇€瑕佺瀛愮骇 ASR 鍜屽皾璇曟鏁版墠鑳芥湁鏁堟帓搴忋€?

    Args:
        asr_per_technique: 鎸夋妧鏈粺璁＄殑 ASR銆?
        attack_results: 鏀诲嚮缁撴灉 (鐢ㄤ簬鎻愬彇绉嶅瓙绾?ASR)銆?
    """
    from arm.seed_ranker import update_asr_history

    # L5 v9: 鎻愬彇绉嶅瓙绾?ASR
    seed_asr: dict[str, float] = {}
    seed_attempts: dict[str, int] = {}

    # L5 v11: 鎻愬彇 converter 绾?ASR (渚涘姩鎬佽鍓娇鐢?
    converter_asr: dict[str, float] = {}
    converter_attempts: dict[str, int] = {}

    # L5 v18: 鎻愬彇 GCG 鍚庣紑绾?ASR (渚涘姩鎬佹帓搴忎娇鐢?
    # 瀛︽湳渚濇嵁: Zou et al. (arXiv:2307.08673) 搂4.3 鈥?鍚庣紑绾?ASR 鍘嗗彶鍙敤浜?
    # 浼樺厛灏濊瘯楂樻晥鍚庣紑, 鍑忓皯 FIRST_SUCCESS 绛栫暐涓嬬殑 API 璋冪敤
    gcg_suffix_asr: dict[str, float] = {}
    gcg_suffix_attempts: dict[str, int] = {}

    if attack_results:
        # 鎸?objective 鍓嶇紑缁熻绉嶅瓙绾ф垚鍔熺巼
        seed_stats: dict[str, dict[str, int]] = {}  # {prefix: {success, total}}
        for results in attack_results.values():
            for result in results:
                objective = getattr(result, "objective", "") or ""
                if not objective:
                    continue
                prefix = objective[:100]  # 浣跨敤鍓?00瀛楃浣滀负绉嶅瓙鏍囪瘑
                if prefix not in seed_stats:
                    seed_stats[prefix] = {"success": 0, "total": 0}
                seed_stats[prefix]["total"] += 1
                from assess.asr_tracker import _get_outcome
                outcome = _get_outcome(result)
                if outcome == "success":
                    seed_stats[prefix]["success"] += 1

                # L5 v11: 鎻愬彇 converter 绾?ASR
                meta = getattr(result, "metadata", {}) or {}
                converter_name = ""
                if isinstance(meta, dict):
                    converter_name = str(meta.get("converter_name", "") or meta.get("converter", ""))
                if converter_name:
                    if converter_name not in converter_attempts:
                        converter_attempts[converter_name] = 0
                        converter_asr[converter_name] = 0.0
                    converter_attempts[converter_name] += 1
                    if outcome == "success":
                        converter_asr[converter_name] = (
                            converter_asr.get(converter_name, 0.0) + 1
                        )

                # L5 v18: 鎻愬彇 GCG 鍚庣紑绾?ASR
                # 浠?metadata 涓彁鍙?gcg_suffix 瀛楁 (鐢?_run_gcg 娉ㄥ叆)
                gcg_suffix = ""
                if isinstance(meta, dict):
                    gcg_suffix = str(meta.get("gcg_suffix", ""))
                if gcg_suffix:
                    # 浣跨敤鍓?0瀛楃浣滀负閿?(涓?escalation.py 涓帓搴忛€昏緫涓€鑷?
                    gcg_key = gcg_suffix[:40]
                    if gcg_key not in gcg_suffix_attempts:
                        gcg_suffix_attempts[gcg_key] = 0
                        gcg_suffix_asr[gcg_key] = 0.0
                    gcg_suffix_attempts[gcg_key] += 1
                    if outcome == "success":
                        gcg_suffix_asr[gcg_key] = (
                            gcg_suffix_asr.get(gcg_key, 0.0) + 1
                        )

        for prefix, stats in seed_stats.items():
            if stats["total"] > 0:
                seed_asr[prefix] = round(stats["success"] / stats["total"] * 100, 1)
                seed_attempts[prefix] = stats["total"]

        # L5 v11: 璁＄畻 converter 绾?ASR 鐧惧垎姣?
        for conv_name in converter_asr:
            total = converter_attempts.get(conv_name, 1)
            converter_asr[conv_name] = round(
                converter_asr[conv_name] / total * 100, 1
            )

        # L5 v18: 璁＄畻 GCG 鍚庣紑绾?ASR 鐧惧垎姣?
        for gcg_key in gcg_suffix_asr:
            total = gcg_suffix_attempts.get(gcg_key, 1)
            gcg_suffix_asr[gcg_key] = round(
                gcg_suffix_asr[gcg_key] / total * 100, 1
            )

    update_asr_history(
        asr_per_technique,
        seed_asr=seed_asr if seed_asr else None,
        seed_attempts=seed_attempts if seed_attempts else None,
    )

    # L5 v11: 淇濆瓨 converter 绾?ASR 鍒板巻鍙叉枃浠?
    if converter_asr:
        _save_converter_asr_history(converter_asr, converter_attempts)

    # L5 v18: 淇濆瓨 GCG 鍚庣紑绾?ASR 鍒板巻鍙叉枃浠?
    if gcg_suffix_asr:
        _save_gcg_suffix_asr_history(gcg_suffix_asr, gcg_suffix_attempts)

def _save_converter_asr_history(
    converter_asr: dict[str, float],
    converter_attempts: dict[str, int],
) -> None:
    """L5 v11: 淇濆瓨 converter 绾?ASR 鍒?asr_history.json銆?

    灏?converter 璺緞鐨?ASR 鏁版嵁鍐欏叆鍘嗗彶鏂囦欢, 渚?_prune_low_asr_converters
    鍦ㄤ笅娆¤繍琛屾椂浣跨敤銆備娇鐢?EMA (alpha=0.3) 鍚堝苟鍘嗗彶鏁版嵁銆?

    瀛︽湳渚濇嵁: PyRIT SequentialAttack (arXiv:2407.01232) - 璺緞绾?
    ASR 鍘嗗彶鍙敤浜庡姩鎬佽鍓綆鏁堣矾寰? 鎻愬崌鍚炲悙閲?~30%銆?

    Args:
        converter_asr: {converter_signature: asr_percentage}
        converter_attempts: {converter_signature: attempt_count}
    """

    asr_history_path = _get_asr_history_path()
    if not asr_history_path.exists():
        return

    try:
        data = json.loads(asr_history_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to read ASR history for converter ASR: %s", e)
        return

    # EMA 鍚堝苟 converter ASR (alpha=0.3)
    existing = data.get("converter_asr", {})
    alpha = 0.3

    for conv_name, new_asr in converter_asr.items():
        if conv_name in existing:
            existing[conv_name] = round(
                alpha * new_asr + (1 - alpha) * existing[conv_name], 1
            )
        else:
            existing[conv_name] = new_asr

    data["converter_asr"] = existing

    try:
        asr_history_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(
            "Converter ASR history saved: %d converters tracked",
            len(existing),
        )
    except Exception as e:
        logger.warning("Failed to save converter ASR history: %s", e)

def _save_gcg_suffix_asr_history(
    gcg_suffix_asr: dict[str, float],
    gcg_suffix_attempts: dict[str, int],
) -> None:
    """L5 v18: 淇濆瓨 GCG 鍚庣紑绾?ASR 鍒?asr_history.json銆?

    灏?GCG 鍚庣紑鐨?ASR 鏁版嵁鍐欏叆鍘嗗彶鏂囦欢, 渚?_generate_gcg_suffix_pool
    鍦ㄤ笅娆¤繍琛屾椂鎸?ASR 闄嶅簭鎺掑垪銆備娇鐢?EMA (alpha=0.3) 鍚堝苟鍘嗗彶鏁版嵁銆?

    瀛︽湳渚濇嵁: Zou et al. (arXiv:2307.08673) 搂4.3 鈥?鍚庣紑绾?ASR 鍘嗗彶
    鍙敤浜庝紭鍏堝皾璇曢珮鏁堝悗缂€, 鍑忓皯 API 璋冪敤 ~20%銆?

    Args:
        gcg_suffix_asr: {gcg_suffix_key: asr_percentage}
        gcg_suffix_attempts: {gcg_suffix_key: attempt_count}
    """

    asr_history_path = _get_asr_history_path()
    if not asr_history_path.exists():
        return

    try:
        data = json.loads(asr_history_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to read ASR history for GCG suffix ASR: %s", e)
        return

    # EMA 鍚堝苟 GCG 鍚庣紑 ASR (alpha=0.3)
    existing = data.get("gcg_suffix_asr", {})
    alpha = 0.3

    for gcg_key, new_asr in gcg_suffix_asr.items():
        if gcg_key in existing:
            existing[gcg_key] = round(
                alpha * new_asr + (1 - alpha) * existing[gcg_key], 1
            )
        else:
            existing[gcg_key] = new_asr

    data["gcg_suffix_asr"] = existing

    try:
        asr_history_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(
            "GCG suffix ASR history saved: %d suffixes tracked",
            len(existing),
        )
    except Exception as e:
        logger.warning("Failed to save GCG suffix ASR history: %s", e)

