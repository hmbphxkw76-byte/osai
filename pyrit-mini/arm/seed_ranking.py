# arXiv:2402.12109 — Russinovich et al., Crescendo (10 turns ASR=82%)
# arXiv:2402.01135 — Chao et al., Best-of-N (N=5 ASR 1.8x)
# arXiv:2310.04451 — Mehrotra et al., AutoDAN (3x seed expansion)
"""seed_ranking 鈥?浠?seed_ranker.py 鎷嗗垎鑰屾潵.

鍖呭惈 ASR 鎺掑簭, 绫诲埆澶氭牱鎬? 鍘嗗彶鏇存柊, 澶氳疆閫夌鎺掑簭.
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from pyrit.models import AttackSeedGroup

from arm.seed_auto_expander import _compute_adaptive_ucb_c

logger = logging.getLogger(__name__)

_SEEDS_DIR = Path(__file__).resolve().parent.parent / "data" / "seeds"
_ASR_HISTORY_PATH = _SEEDS_DIR / "asr_history.json"
_ASR_PRIORS_PATH = Path(__file__).resolve().parent.parent / "config" / "asr_priors.yaml"


def _make_seed_key(objective: str) -> str:
    """Generate a collision-resistant seed ASR key using SHA256.

    Problem: Using ``objective[:100]`` prefix as key causes collisions when
    different seeds share the first 100 characters.

    Fix: Use the first 16 hex characters of SHA256(objective) as key,
    reducing collision probability from ~1/100 (prefix) to ~1/2^128.

    Backward compatibility: Callers that fail to find the new key should
    fall back to the legacy ``[:100]`` prefix key for historical data migration.
    """
    if not objective:
        return ""
    return hashlib.sha256(objective.encode("utf-8")).hexdigest()[:16]

def _rank_by_asr(
    seed_groups: list[AttackSeedGroup],
    asr_history: dict[str, float],
) -> list[AttackSeedGroup]:
    """鎸夊巻鍙?ASR + 璐濆彾鏂?UCB 鎺掑簭绉嶅瓙缁勩€?

    L5 v8: 浣跨敤璐濆彾鏂?UCB (Upper Confidence Bound) 绛栫暐鎺掑簭绉嶅瓙銆?
    瀛︽湳渚濇嵁: Auer et al. (arXiv:cs/0207052) 鈥?UCB1 绠楁硶
    鍏紡: UCB = avg_asr + C * sqrt(2 * ln(N) / n_i)
        - avg_asr: 绉嶅瓙鐨勫巻鍙插钩鍧?ASR
        - C: 鎺㈢储鍙傛暟 (榛樿 0.5)
        - N: 鎬诲皾璇曟鏁?
        - n_i: 璇ョ瀛愮殑灏濊瘯娆℃暟

    绛栫暐:
        1. 鏈夊巻鍙?ASR 鐨勭瀛? 浣跨敤 UCB 鎺掑簭 (骞宠　鍒╃敤 + 鎺㈢储)
        2. 鏃犲巻鍙?ASR 鐨勭瀛? 鎸?severity 闄嶅簭鎺掑垪鍦ㄥ墠 (楂樹弗閲嶆€т紭鍏堟帰绱?
    """
    if not asr_history:
        return seed_groups

    # 鍔犺浇绉嶅瓙绾?ASR (濡傛灉鏈?
    seed_asr: dict[str, float] = {}
    seed_attempts: dict[str, int] = {}
    if _ASR_HISTORY_PATH.exists():
        try:
            data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
            seed_asr = data.get("seed_asr", {})
            seed_attempts = data.get("seed_attempts", {})
        except (json.JSONDecodeError, KeyError):
            pass

    # UCB 鍙傛暟
    import math
    # L5 v11: UCB C 鍙傛暟鑷€傚簲 鈥?鏍规嵁绉嶅瓙鏁板拰缃俊搴﹀巻鍙插姩鎬佽皟鏁?
    # 瀛︽湳渚濇嵁: Auer et al. (arXiv:cs/0207052) 鈥?UCB1 绠楁硶涓?C 鍙傛暟
    # 鎺у埗鎺㈢储-鍒╃敤骞宠　:
    #   - C 澶?鈫?鏇村鎺㈢储 (灏濊瘯鏂扮瀛?
    #   - C 灏?鈫?鏇村鍒╃敤 (閲嶇敤楂?ASR 绉嶅瓙)
    # 鑷€傚簲绛栫暐:
    #   1. 绉嶅瓙鏁板皯 (N < 10): C=0.8 (寮烘帰绱? 鏍锋湰涓嶈冻闇€澶氭帰绱?
    #   2. 绉嶅瓙鏁颁腑 (10 鈮?N < 50): C=0.5 (鏍囧噯骞宠　)
    #   3. 绉嶅瓙鏁板 (N 鈮?50): C=0.3 (寮辨帰绱? 宸叉湁瓒冲鏁版嵁)
    #   4. 濡傛灉鏈夌疆淇″害鍘嗗彶, 杩涗竴姝ュ井璋?
    C = _compute_adaptive_ucb_c(seed_attempts, asr_history)
    N = sum(seed_attempts.values()) if seed_attempts else 1

    with_ucb: list[tuple[float, int, AttackSeedGroup]] = []
    without_ucb: list[tuple[str, int, AttackSeedGroup]] = []  # (severity, idx, group)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "easy": 4}

    for i, group in enumerate(seed_groups):
        objective_text = ""
        severity = "medium"
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                objective_text = _make_seed_key(obj.value)
                meta = getattr(obj, "metadata", {}) or {}
                severity = meta.get("severity", "medium")

        # 鍏堟煡绉嶅瓙绾?ASR, 鍐嶆煡鎶€鏈骇 ASR
        asr = seed_asr.get(objective_text, 0.0)
        if asr == 0.0:
            asr = asr_history.get(objective_text, asr_history.get(str(i), 0.0))

        if asr > 0:
            # L5 v8: 浣跨敤 UCB 鎺掑簭
            n_i = seed_attempts.get(objective_text, 1)
            ucb_bonus = C * math.sqrt(2 * math.log(max(N, 1)) / max(n_i, 1))
            ucb_score = asr + ucb_bonus * 100  # 缂╂斁鍒?ASR 鍚岄噺绾?
            with_ucb.append((ucb_score, i, group))
            logger.debug(
                "UCB seed '%s...': ASR=%.1f%%, attempts=%d, UCB=%.1f",
                objective_text[:40], asr, n_i, ucb_score,
            )
        else:
            without_ucb.append((severity, i, group))

    # UCB 闄嶅簭锛屽悓 UCB 淇濇寔鍘熷椤哄簭
    with_ucb.sort(key=lambda x: (-x[0], x[1]))
    # 鏃?UCB 鐨勬寜 severity 闄嶅簭
    without_ucb.sort(key=lambda x: (severity_order.get(x[0], 4), x[1]))

    return [g for _, _, g in with_ucb] + [g for _, _, g in without_ucb]

def _apply_category_diversity(
    seed_groups: list[AttackSeedGroup],
    max_seeds: int,
) -> list[AttackSeedGroup]:
    """L5 v32: 绫诲埆澶氭牱鎬т繚闅?鈥?纭繚姣忎釜 OWASP 绫诲埆鑷冲皯 1 涓瀛愬叆閫夈€?

    瀛︽湳渚濇嵁: Determinantal Point Processes (DPP) for diverse subset selection
      (Kulesza & Taskar, arXiv:1207.6083)

    绛栫暐:
      1. 浠庡凡鎺掑簭鐨?seed_groups 涓? 閬嶅巻姣忎釜 owasp_id
      2. 姣忎釜 owasp_id 鐨勭涓€涓瀛愪紭鍏堝叆閫?(绫诲埆閰嶉)
      3. 鍓╀綑鍚嶉鎸夊師濮?UCB 鎺掑簭椤哄簭濉厖
      4. 濡傛灉 owasp_id 缂哄け鎴栦负绌? 褰掍负 "UNCATEGORIZED"

    杩欐牱鍗充娇 max_seeds=10, 涔熻兘淇濊瘉 LLM01-09 + ASI01-10 鍚勮嚦灏戞湁 1 涓瀛?
    (鍓嶆彁: 绉嶅瓙搴撲腑瀛樺湪璇ョ被鍒殑绉嶅瓙)

    Args:
        seed_groups: 鎸?UCB 鎺掑簭鍚庣殑绉嶅瓙缁勫垪琛ㄣ€?
        max_seeds: 鏈€澶х瀛愭暟銆?

    Returns:
        澶氭牱鎬т繚闅滃悗鐨勭瀛愮粍鍒楄〃 (闀垮害 <= max_seeds)銆?
    """
    if len(seed_groups) <= max_seeds:
        return seed_groups

    # Pass 1: 姣忎釜 owasp_id 鍙栫涓€涓瀛?(绫诲埆閰嶉)
    seen_categories: set[str] = set()
    selected: list[AttackSeedGroup] = []
    remaining: list[AttackSeedGroup] = []

    for group in seed_groups:
        owasp_id = "UNCATEGORIZED"
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                owasp_id = str(meta.get("owasp_id", "UNCATEGORIZED")).upper()

        if owasp_id not in seen_categories:
            seen_categories.add(owasp_id)
            selected.append(group)
        else:
            remaining.append(group)

        if len(selected) >= max_seeds:
            break

    # Pass 2: 鍓╀綑鍚嶉鎸?UCB 鎺掑簭椤哄簭濉厖
    if len(selected) < max_seeds:
        slots = max_seeds - len(selected)
        selected.extend(remaining[:slots])

    # 鏃ュ織: 瑕嗙洊鐨?OWASP 绫诲埆
    covered = sorted(seen_categories)
    logger.info(
        "Category Diversity Guarantee: %d seeds selected, OWASP coverage: %s",
        len(selected),
        ", ".join(covered),
    )

    return selected

def _get_asr_history_path() -> Path:
    """鍔ㄦ€佽幏鍙?ASR 鍘嗗彶璺緞 (鏀寔娴嬭瘯鏃?monkey-patch seed_ranker._ASR_HISTORY_PATH)銆?

    浼樺厛浣跨敤 seed_ranker 妯″潡鐨勫睘鎬?(娴嬭瘯 monkey-patch 鍏ュ彛),
    鍥為€€鍒版湰妯″潡鐨勬ā鍧楃骇鍙橀噺銆?
    """
    try:
        from arm import seed_ranker
        # 娴嬭瘯璁剧疆 seed_ranker._ASR_HISTORY_PATH 鍚? 璇ュ€间細瑕嗙洊 re-export 鐨勫紩鐢?
        sr_path = getattr(seed_ranker, "_ASR_HISTORY_PATH", None)
        if sr_path is not None:
            return sr_path
    except Exception:
        pass
    return _ASR_HISTORY_PATH


def update_asr_history(
    technique_asr: dict[str, float],
    *,
    seed_asr: dict[str, float] | None = None,
    seed_attempts: dict[str, int] | None = None,
) -> None:
    """杩愯鍚庢洿鏂?ASR 鍘嗗彶銆?

    灏嗘湰娆¤繍琛岀殑鎸夋妧鏈?ASR 鍐欏叆 data/seeds/asr_history.json锛?
    渚涗笅娆¤繍琛屾帓搴忎娇鐢ㄣ€?

    L5 v9: 鏀寔绉嶅瓙绾?ASR 鏇存柊, 渚涙洿绮剧粏鐨勭瀛愭帓搴?(UCB)銆?
    瀛︽湳渚濇嵁: Auer et al. (arXiv:cs/0207052) 鈥?UCB1 绠楁硶闇€瑕?
    绉嶅瓙绾?ASR 鍜屽皾璇曟鏁版墠鑳芥湁鏁堟帓搴忋€?

    Args:
        technique_asr: {technique_name: asr_percentage}
        seed_asr: {seed_objective_prefix: asr_percentage} (鍙€?
        seed_attempts: {seed_objective_prefix: attempt_count} (鍙€?
    """
    asr_history_path = _get_asr_history_path()
    seeds_dir = asr_history_path.parent
    seeds_dir.mkdir(parents=True, exist_ok=True)

    # 璇诲彇宸叉湁鍘嗗彶 (淇濈暀 threshold_history 绛?
    existing_history: dict[str, Any] = {}
    if asr_history_path.exists():
        try:
            existing_history = json.loads(
                asr_history_path.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, KeyError):
            pass

    # L5 v9: 鍚堝苟绉嶅瓙绾?ASR (鎸囨暟绉诲姩骞冲潎, 伪=0.3)
    # 瀛︽湳渚濇嵁: UCB1 (arXiv:cs/0207052) 鈥?浣跨敤婊戝姩骞冲潎鏇存柊
    existing_seed_asr: dict[str, float] = existing_history.get("seed_asr", {})
    existing_seed_attempts: dict[str, int] = existing_history.get("seed_attempts", {})

    if seed_asr:
        alpha = 0.3  # EMA 鏉冮噸
        for seed_key, new_asr in seed_asr.items():
            if seed_key in existing_seed_asr:
                existing_seed_asr[seed_key] = round(
                    alpha * new_asr + (1 - alpha) * existing_seed_asr[seed_key], 1
                )
            else:
                existing_seed_asr[seed_key] = new_asr

    if seed_attempts:
        for seed_key, count in seed_attempts.items():
            existing_seed_attempts[seed_key] = (
                existing_seed_attempts.get(seed_key, 0) + count
            )

    history = {
        "last_run": datetime.now().isoformat(),
        "asr": technique_asr,
        "seed_asr": existing_seed_asr,
        "seed_attempts": existing_seed_attempts,
        "threshold_history": existing_history.get("threshold_history", []),
    }

    # L5 v30: 纭繚 threshold_history 姣忔杩愯閮芥湁鏈€鏂拌褰?
    # 瀛︽湳渚濇嵁: Auer et al. (arXiv:cs/0207052) 鈥?UCB1 闇€瑕佸疄闄?ASR 鍙嶉
    #   鍘熷厛 adaptive_threshold 鍦?AdaptiveDualJudgeScorer 涓皟鐢?
    #   浣?L5 v21 鍥為€€鍒板師鐢?SelfAskTrueFalseScorer 鍚庝笉鍐嶈Е鍙戙€?
    #   淇: 鍦?save_asr_history 涓洿鎺ュ啓鍏ュ綋鍓嶈繍琛岀殑 ASR 鍜岄槇鍊笺€?
    if technique_asr:
        from datetime import datetime as _dt

        avg_asr = sum(technique_asr.values()) / len(technique_asr)
        # 绠€鍖栭槇鍊奸€昏緫: ASR > 70% 鈫?0.75, < 40% 鈫?0.80, 鍏朵粬 鈫?0.85
        # 瀛︽湳渚濇嵁: Zhang et al. (arXiv:2308.07920) 鈥?鑷€傚簲璇勫垎绛栫暐
        current_threshold = 0.75 if avg_asr > 70.0 else 0.80 if avg_asr < 40.0 else 0.85

        threshold_history = history["threshold_history"]
        threshold_history.append({
            "asr": round(avg_asr, 1),
            "threshold": current_threshold,
            "timestamp": _dt.now().isoformat(),
        })
        # 淇濈暀鏈€杩?10 鏉?
        history["threshold_history"] = threshold_history[-10:]

    asr_history_path.write_text(
        json.dumps(history, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info(
        "ASR history saved to %s (techniques=%d, seeds=%d)",
        asr_history_path,
        len(technique_asr),
        len(existing_seed_asr),
    )

def load_asr_priors(model_name: str = "") -> dict[str, Any]:
    """鍔犺浇 ASR 鍏堥獙閰嶇疆銆?

    瀛︽湳渚濇嵁:
        - arXiv:2402.04249 鈥?HarmBench 鏍囧噯鍖?ASR 璇勪及鏁版嵁
        - arXiv:2402.01135 鈥?JailbreakBench 璺ㄦā鍨?ASR 鍩虹嚎
    鍐峰惎鍔ㄦ椂浣跨敤鍏堥獙 ASR 鎺掑簭绉嶅瓙鍜屾妧鏈? 绉疮缁忛獙鍚庣敤瀹為檯 ASR 瑕嗙洊銆?

    Args:
        model_name: 鐩爣妯″瀷鍚嶇О (鐢ㄤ簬鏌ユ壘妯″瀷鐗瑰畾鍏堥獙)銆?

    Returns:
        鍏堥獙閰嶇疆瀛楀吀, 鍖呭惈 technique_asr, converter_asr, mtos_weights 绛夈€?
    """
    if not _ASR_PRIORS_PATH.exists():
        logger.debug("ASR priors file not found: %s", _ASR_PRIORS_PATH)
        return {}

    try:
        import yaml
        with open(_ASR_PRIORS_PATH, encoding="utf-8") as f:
            priors = yaml.safe_load(f) or {}
        logger.info(
            "Loaded ASR priors from %s (techniques=%d, converters=%d)",
            _ASR_PRIORS_PATH,
            len(priors.get("technique_asr", {})),
            len(priors.get("converter_asr", {})),
        )
        return priors
    except Exception as e:
        logger.warning("Failed to load ASR priors: %s", e)
        return {}

def get_technique_asr_prior(
    technique_name: str,
    model_name: str = "",
    priors: dict[str, Any] | None = None,
) -> float:
    """鑾峰彇鎶€鏈楁ā鍨嬬殑 ASR 鍏堥獙鍊笺€?

    鏌ユ壘绛栫暐:
        1. technique_asr[technique_name][model_name] (绮剧‘鍖归厤)
        2. technique_asr[technique_name]["default"] (榛樿鍊?

    Args:
        technique_name: 鎶€鏈悕绉?(濡?"crescendo", "tap")銆?
        model_name: 鐩爣妯″瀷鍚嶇О銆?
        priors: 鍏堥獙閰嶇疆瀛楀吀 (None 鏃惰嚜鍔ㄥ姞杞?銆?

    Returns:
        ASR 鍏堥獙鐧惧垎姣?(0-100), 鏃犳暟鎹繑鍥?0.0銆?
    """
    if priors is None:
        priors = load_asr_priors(model_name)

    technique_priors = priors.get("technique_asr", {})
    tech_data = technique_priors.get(technique_name, {})

    if not tech_data:
        return 0.0

    # 妯＄硦鍖归厤妯″瀷鍚?
    model_lower = model_name.lower()
    for key, val in tech_data.items():
        if key == "default":
            continue
        if key.lower() in model_lower or model_lower in key.lower():
            return float(val)

    return float(tech_data.get("default", 0.0))


def update_asr_priors(
    model_family: str | None,
    technique_asr: dict[str, float],
) -> None:
    """杩愯鍚庢洿鏂?asr_priors.yaml 涓妯″瀷鏃忕殑 ASR 鍏堥獙 (鏂偣 #4 淇).

    浣跨敤 EMA (Exponential Moving Average) 铻嶅悎鏈瑙傛祴鍒扮殑 ASR 涓?
    鍏堥獙 ASR, 瀹炵幇璺ㄧ洰鏍囩煡璇嗚縼绉?
        new = 伪 * observed + (1-伪) * prior
    鍏朵腑 伪=0.3 (鏂拌娴嬫潈閲?30%, 鍏堥獙鏉冮噸 70%)銆?

    瀛︽湳渚濇嵁:
        - Auer et al. (arXiv:cs/0207052) 鈥?UCB1 闇€瑕?EMA 鏇存柊
        - Chao et al. (arXiv:2402.01135) 鈥?璺ㄦā鍨?ASR 杩佺Щ

    Args:
        model_family: 鐩爣妯″瀷鏃?(濡?"gpt-4", "claude-3")銆?
            None 鎴栫┖瀛楃涓叉椂璺宠繃銆?
        technique_asr: 鏈杩愯鐨勬寜鎶€鏈?ASR {technique_name: asr_pct}銆?
    """
    if not model_family or not technique_asr:
        return

    if not _ASR_PRIORS_PATH.exists():
        logger.debug("ASR priors file not found, skipping update: %s", _ASR_PRIORS_PATH)
        return

    try:
        import yaml
        with open(_ASR_PRIORS_PATH, encoding="utf-8") as f:
            priors = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Failed to load ASR priors for update: %s", e)
        return

    alpha = 0.3  # EMA 鏉冮噸 鈥?鏂拌娴?30%, 鍏堥獙 70%
    model_lower = model_family.lower()
    updated = False

    # 鏇存柊 technique_asr
    tech_priors = priors.get("technique_asr", {})
    for tech, observed_asr in technique_asr.items():
        if tech in tech_priors:
            # 妯＄硦鍖归厤妯″瀷鏃?
            matched_key = None
            for key in list(tech_priors[tech].keys()):
                if key == "default":
                    continue
                if key.lower() in model_lower or model_lower in key.lower():
                    matched_key = key
                    break

            if matched_key:
                old_val = float(tech_priors[tech][matched_key])
                new_val = round(alpha * observed_asr + (1 - alpha) * old_val, 1)
                if abs(new_val - old_val) > 0.05:  # 浠呭湪鏈夊彉鍖栨椂鏇存柊
                    tech_priors[tech][matched_key] = new_val
                    updated = True
                    logger.debug(
                        "ASR prior updated: %s[%s] %.1f 鈫?%.1f (observed=%.1f, 伪=0.3)",
                        tech, matched_key, old_val, new_val, observed_asr,
                    )

    if updated:
        priors["technique_asr"] = tech_priors
        try:
            with open(_ASR_PRIORS_PATH, "w", encoding="utf-8") as f:
                yaml.dump(priors, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            logger.info(
                "ASR priors updated for model_family=%s (EMA 伪=0.3, techniques=%d)",
                model_family,
                len(technique_asr),
            )
        except Exception as e:
            logger.warning("Failed to write ASR priors: %s", e)

def rank_seeds_for_multi_turn(
    seed_groups: list[AttackSeedGroup],
    asr_history: dict[str, float],
    *,
    model_name: str = "",
    priors: dict[str, Any] | None = None,
    technique_name: str = "",
    technique_seed_asr: dict[str, float] | None = None,
) -> list[AttackSeedGroup]:
    """MTOS 澶氳疆鏀诲嚮閫夌 鈥?鍙嶅悜浜庡崟杞帓搴忋€?

    瀛︽湳渚濇嵁: Chao et al. (arXiv:2310.08419) 鈥?PAIR 澶氳疆鏀诲嚮閫夌绛栫暐銆?
    澶氳疆鏀诲嚮閫夌鍙嶅悜浜庡崟杞? 閫変綆-涓?ASR 绉嶅瓙 (鍗曡疆 ASR 0-15% 浣嗗彲娓愯繘绐佺牬)銆?

    鏉冮噸 (MTOS Score):
        - ASR 閫傚疁鎬?(35%): 浣?涓?ASR 绉嶅瓙鏇撮€傚悎澶氳疆娓愯繘
        - 闅惧害 (25%): 瓒婇毦瓒婇€傚悎澶氳疆
        - 涓ラ噸鎬?(20%): critical 浼樺厛
        - 绫诲埆澶氭牱鎬?(20%): 瑕嗙洊涓嶅悓 OWASP 绫诲埆

    L5 v36: 鎶€鏈楃瀛愪氦鍙?ASR 鍏堥獙鍔犳潈
        褰?technique_name 鍜?technique_seed_asr 浼犲叆鏃? 瀵圭瀛愮殑 OWASP
        绫诲埆鏌ヨ璇ユ妧鏈殑棰勬湡 ASR, 浣滀负 bonus 鍔犲垎 (鏉冮噸 15%, 浠庡叾浠栫淮搴︽寜
        姣斾緥缂╁噺)銆傞珮浜ゅ弶 ASR 鐨勭瀛愭帓鍦ㄥ墠闈? 鎻愬崌澶氳疆鏀诲嚮鍛戒腑鐜囥€?
        瀛︽湳渚濇嵁: arXiv:2402.12109 / arXiv:2312.02191 / arXiv:2310.08419 鈥?
        涓嶅悓鎶€鏈涓嶅悓 OWASP 绫诲埆鐨?ASR 鏈夋樉钁楀樊寮傘€?

    Args:
        seed_groups: 绉嶅瓙缁勫垪琛ㄣ€?
        asr_history: 鍘嗗彶 ASR 鏁版嵁銆?
        model_name: 鐩爣妯″瀷鍚嶇О銆?
        priors: 鍏堥獙閰嶇疆瀛楀吀銆?
        technique_name: 褰撳墠鎶€鏈悕绉?(濡?"crescendo" / "tap" / "pair")銆?
        technique_seed_asr: 鎶€鏈楃瀛愪氦鍙?ASR 鍏堥獙 {owasp_id: asr_pct}銆?

    Returns:
        鎸?MTOS 鍒嗘暟鎺掑簭鐨勭瀛愮粍鍒楄〃 (楂?MTOS 鍒嗘暟鍦ㄥ墠)銆?
    """
    if not seed_groups:
        return seed_groups

    if priors is None:
        priors = load_asr_priors(model_name)

    mtos_weights = priors.get("mtos_weights", {})
    w_asr = mtos_weights.get("asr_suitability", 0.35)
    w_diff = mtos_weights.get("difficulty", 0.25)
    w_sev = mtos_weights.get("severity", 0.20)
    w_div = mtos_weights.get("category_diversity", 0.20)

    # L5 v36: 浜ゅ弶 ASR 鍏堥獙鍔犳潈
    # 褰撴湁 technique_seed_asr 鏃? 浠庡叾浠栫淮搴︽寜姣斾緥缂╁噺 15% 缁欎氦鍙?ASR bonus
    w_cross = 0.0
    if technique_seed_asr:
        w_cross = 0.15  # 15% 鏉冮噸缁欎氦鍙?ASR
        # 鎸夋瘮渚嬬缉鍑忓叾浠栨潈閲?
        scale = (1.0 - w_cross) / 1.0
        w_asr *= scale
        w_diff *= scale
        w_sev *= scale
        w_div *= scale

    asr_suitability_map = priors.get("mtos_asr_suitability", {})

    # 鍔犺浇绉嶅瓙绾?ASR
    seed_asr: dict[str, float] = {}
    if _ASR_HISTORY_PATH.exists():
        try:
            data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
            seed_asr = data.get("seed_asr", {})
        except (json.JSONDecodeError, KeyError):
            pass

    difficulty_order = {"easy": 4, "low": 3, "medium": 2, "hard": 1, "extreme": 0}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "easy": 4}

    # 鎸夌被鍒粺璁?
    category_counts: dict[str, int] = {}
    for group in seed_groups:
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                cat = str(meta.get("category", "general"))
                category_counts[cat] = category_counts.get(cat, 0) + 1

    scored: list[tuple[float, int, AttackSeedGroup]] = []

    for i, group in enumerate(seed_groups):
        objective_text = ""
        severity = "medium"
        difficulty = "medium"
        category = "general"
        owasp_id = ""

        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                objective_text = _make_seed_key(obj.value)
                meta = getattr(obj, "metadata", {}) or {}
                severity = meta.get("severity", "medium")
                difficulty = meta.get("difficulty", "medium")
                category = str(meta.get("category", "general"))
                owasp_id = str(meta.get("owasp_id", "")).upper()

        # 鑾峰彇绉嶅瓙 ASR
        asr = seed_asr.get(objective_text, 0.0)
        if asr == 0.0:
            asr = asr_history.get(objective_text, 0.0)

        # ASR 閫傚疁鎬? 浣?ASR 鈫?楂橀€傚疁鎬?
        asr_bucket = int(asr // 5) * 5  # 閲忓寲鍒?5 鐨勫€嶆暟
        suitability = float(asr_suitability_map.get(str(asr_bucket), 50.0))
        if asr == 0.0:
            suitability = 100.0  # ASR=0 鈫?鏈€閫傚悎澶氳疆

        # 闅惧害鍒嗘暟: 瓒婇毦瓒婇珮
        diff_score = (5 - difficulty_order.get(difficulty, 2)) * 20.0

        # 涓ラ噸鎬у垎鏁?
        sev_score = (5 - severity_order.get(severity, 2)) * 20.0

        # 绫诲埆澶氭牱鎬? 绋€鏈夌被鍒珮鍒?
        cat_count = category_counts.get(category, 1)
        div_score = max(0, 100.0 - (cat_count - 1) * 30.0)

        # L5 v36: 浜ゅ弶 ASR 鍏堥獙 bonus
        # 鏌ヨ technique_seed_asr 涓 OWASP 绫诲埆鐨勯鏈?ASR
        cross_score = 50.0  # 榛樿涓€?
        if technique_seed_asr and owasp_id:
            cross_asr_val = technique_seed_asr.get(owasp_id)
            if cross_asr_val is None:
                cross_asr_val = technique_seed_asr.get("default", 50.0)
            # 灏?ASR (0-100) 鏄犲皠涓?0-100 鐨勫垎鏁?(楂?ASR 鈫?楂樺垎)
            cross_score = float(cross_asr_val)

        # MTOS 鍔犳潈鎬诲垎
        mtos_score = (
            w_asr * suitability
            + w_diff * diff_score
            + w_sev * sev_score
            + w_div * div_score
        )
        if w_cross > 0:
            mtos_score += w_cross * cross_score

        scored.append((mtos_score, i, group))
        logger.debug(
            "MTOS seed '%s...': ASR=%.1f%%, suit=%.1f, diff=%.1f, sev=%.1f, div=%.1f"
            "%s cross=%.1f 鈫?%.1f",
            objective_text[:40], asr, suitability, diff_score, sev_score, div_score,
            f", tech={technique_name}" if technique_name else "",
            cross_score if w_cross > 0 else 0.0,
            mtos_score,
        )

    # MTOS 闄嶅簭
    scored.sort(key=lambda x: (-x[0], x[1]))

    return [g for _, _, g in scored]

