"""绉嶅瓙鍔犺浇 + ASR 鎺掑簭銆?

鍔犺浇 PyRIT 鍘熺敓 SeedPrompt YAML 鏍煎紡鐨勭瀛愭枃浠讹紝鎸夊巻鍙?ASR 鎺掑簭銆?
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pyrit.models import AttackSeedGroup, SeedObjective

from arm.seed_auto_expander import (  # noqa: F401 鈥?re-exports for main.py
    _auto_generate_seeds_sync,
    _compute_adaptive_ucb_c,
    auto_generate_seeds,
    auto_generate_seeds_async,
)
from arm.seed_ranking import (  # noqa: F401 鈥?re-exports for main.py
    _ASR_HISTORY_PATH,
    _ASR_PRIORS_PATH,
    _SEEDS_DIR,
    _apply_category_diversity,
    _rank_by_asr,
    get_technique_asr_prior,
    load_asr_priors,
    rank_seeds_for_multi_turn,
    update_asr_history,
    update_asr_priors,
)

logger = logging.getLogger(__name__)


# 鑳藉姏鈫掔瀛愭枃浠舵槧灏?
# 褰撴繁搴︽帰娴嬫娴嬪埌鐗瑰畾鑳藉姏鏃? 鑷姩杩藉姞瀹氬悜绉嶅瓙鏂囦欢
CAPABILITY_SEED_MAP: dict[str, list[str]] = {
    "mcp": ["mcp_attack"],
    "rag": ["rag_attack"],
    "function_calling": ["function_call_exploit"],
    "tool_hijack": ["tool_hijack"],
    "multi_agent": ["multi_agent_attack"],
    "workflow": ["workflow_chain_attack"],
    "session_auth": ["session_auth_attack"],
    "memory": ["token_smuggling"],
    "a2a": ["multi_agent_attack", "tool_hijack"],
}


def load_seeds(
    seed_file: str,
    max_seeds: int = 10,
    target_language: str | None = None,
    enable_dos: bool = False,
    capabilities: str | None = None,
    model_family: str | None = None,
    seed_filters: dict[str, str] | None = None,
) -> list[AttackSeedGroup]:
    """鍔犺浇绮鹃€夌瀛愭枃浠躲€?

    绉嶅瓙鏂囦欢鏍煎紡: PyRIT 鍘熺敓 SeedPrompt YAML (.prompt)
    姣忎釜绉嶅瓙鍖呭惈:
        - value: 鏀诲嚮 prompt 鏂囨湰
        - metadata: {owasp_id, difficulty, severity, category, language}

    L5 v8: 鏀寔閫楀彿鍒嗛殧鐨勫绉嶅瓙鏂囦欢鍔犺浇銆?
    渚嬪 "elite_jailbreaks,asi_top10,zh_curated" 浼氬悎骞跺姞杞戒笁涓枃浠躲€?

    鍔犺浇鍚庢寜鍘嗗彶 ASR 鎺掑簭:
        1. 璇诲彇 data/seeds/asr_history.json
        2. 鏈夊巻鍙?ASR 鐨勭瀛愭寜 ASR 闄嶅簭鎺掑垪
        3. 鏃犲巻鍙?ASR 鐨勭瀛愪繚鎸佸師濮嬮『搴?
        4. 鎴彇鍓?max_seeds 涓?

    璇█鑷€傚簲:
        - 濡傛灉 target_language 涓?"zh", 浼樺厛閫夋嫨涓枃绉嶅瓙 (language: zh)
        - 濡傛灉 target_language 涓?"en" 鎴?None, 浼樺厛閫夋嫨鑻辨枃绉嶅瓙
        - 娣峰悎妯″紡: 70% 鐩爣璇█ + 30% 鍏朵粬璇█ (纭繚瑕嗙洊)

    DoS 鏀诲嚮杩囨护:
        - enable_dos=False (榛樿): 杩囨护鎺?owasp_id=LLM10 鐨勭瀛?
        - enable_dos=True: 淇濈暀 LLM10 绉嶅瓙
        - 鐞嗙敱: LLM10 (Model DoS / Unbounded Consumption) 鏀诲嚮
          浼氳鐩爣鐢熸垚鏋佸ぇ鍝嶅簲, 娑堣€楀ぇ閲?token, 榛樿绂佺敤浠ユ帶鍒舵垚鏈?

    鑳藉姏鑷€傚簲 (鏂偣 #1 淇):
        - 褰?capabilities 闈炵┖鏃? 鎸?CAPABILITY_SEED_MAP 鑷姩杩藉姞
          瀹氬悜绉嶅瓙鏂囦欢 (濡傛娴嬪埌 MCP 鈫?杩藉姞 mcp_attack)
        - 杩藉姞鐨勭瀛愭枃浠跺幓閲? 涓嶉噸澶嶅姞杞?

    Args:
        seed_file: 绉嶅瓙鏂囦欢鍚?(涓嶅惈鎵╁睍鍚? 鑷姩鍔?.prompt)銆傛敮鎸侀€楀彿鍒嗛殧銆?
        max_seeds: 鏈€澶х瀛愭暟銆?
        target_language: 鐩爣璇█ ("zh" 鎴?"en", None=鑷姩)銆?
        enable_dos: 鏄惁淇濈暀 LLM10 DoS 鏀诲嚮绉嶅瓙 (榛樿 False, 绂佺敤)銆?
        capabilities: 鐩爣鑳藉姏鎸囩汗 (閫楀彿鍒嗛殧, 濡?"mcp,rag,function_calling")銆?
        model_family: 鐩爣妯″瀷鏃?(濡?"gpt-4", "claude-3", 淇濈暀鍙傛暟, 渚涘悗缁墿灞?銆?

    Returns:
        list[AttackSeedGroup]: 鎺掑簭鍚庣殑鏀诲嚮绉嶅瓙缁勫垪琛ㄣ€?
    """
    # L5 v8: 鏀寔閫楀彿鍒嗛殧鐨勫绉嶅瓙鏂囦欢
    seed_files = [s.strip() for s in seed_file.split(",") if s.strip()]
    if not seed_files:
        seed_files = [seed_file]

    # 鏂偣 #1 淇: 鍩轰簬鑳藉姏鎸囩汗鑷姩杩藉姞瀹氬悜绉嶅瓙鏂囦欢
    added_by_capability: list[str] = []
    if capabilities:
        cap_list = [c.strip().lower() for c in capabilities.split(",") if c.strip()]
        for cap in cap_list:
            mapped_seeds = CAPABILITY_SEED_MAP.get(cap, [])
            for ms in mapped_seeds:
                if ms not in seed_files:
                    seed_files.append(ms)
                    added_by_capability.append(ms)
        if added_by_capability:
            logger.info(
                "Capability-adaptive seed augmentation: %s (from capabilities=%s)",
                added_by_capability,
                cap_list,
            )

    all_raw_seeds: list[dict[str, Any]] = []
    loaded_files: list[str] = []

    for sf in seed_files:
        file_path = _SEEDS_DIR / f"{sf}.prompt"
        if not file_path.exists():
            file_path = _SEEDS_DIR / f"{sf}.yaml"
            if not file_path.exists():
                logger.warning("Seed file not found: %s, skipping", sf)
                continue

        import yaml

        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            logger.warning("Invalid seed file format for %s: expected list, skipping", sf)
            continue

        all_raw_seeds.extend(data)
        loaded_files.append(sf)
        logger.info("Loaded %d seeds from %s", len(data), sf)

    if not all_raw_seeds:
        raise FileNotFoundError(f"No seed files found from: {seed_file}")

    logger.info("Total seeds loaded from %d files: %d", len(loaded_files), len(all_raw_seeds))

    # DoS 鏀诲嚮杩囨护: 榛樿绂佺敤 LLM10 绉嶅瓙 (娑堣€楀ぇ閲?token)
    if not enable_dos:
        before_count = len(all_raw_seeds)
        all_raw_seeds = _filter_dos_seeds(all_raw_seeds)
        filtered_count = before_count - len(all_raw_seeds)
        if filtered_count > 0:
            logger.info(
                "DoS attack disabled: filtered %d LLM10 seeds (use --enable-dos to include)",
                filtered_count,
            )

    # 璇█鑷€傚簲绛涢€?
    if target_language:
        all_raw_seeds = _filter_by_language(all_raw_seeds, target_language)
        logger.info("Language-adaptive filtering: target=%s, %d seeds after filter", target_language, len(all_raw_seeds))

    # ── 增量借鉴: 种子元数据过滤 (--seed-filters KEY=VALUE) ──
    # 借鉴 pyrit_scan 的 --seed-filters: 按 metadata KEY=VALUE 精准过滤种子
    # 示例: {"owasp_id": "LLM01", "difficulty": "high"} → 仅保留匹配的种子
    # 多 KEY 为 AND 关系 (必须同时匹配所有 key)
    # 支持 metadata 中值为列表的情况 (如 category: ["attack", "jailbreak"])
    if seed_filters:
        all_raw_seeds = _filter_by_metadata(all_raw_seeds, seed_filters)
        logger.info(
            "Seed metadata filtering: filters=%s, %d seeds after filter",
            seed_filters,
            len(all_raw_seeds),
        )

    # 鏋勫缓 AttackSeedGroup
    seed_groups = _build_seed_groups(all_raw_seeds)

    # 鎸?ASR 鎺掑簭
    asr_history = _load_asr_history()

    # 断点修复: 使用 model_family 加载 ASR 先验并合并到 asr_history
    # 学术依据: Chao et al. (arXiv:2402.01135) — 跨模型 ASR 迁移
    #   不同模型族安全策略不同, 模型特定 ASR 先验可提升种子排序精度
    # 数据流: recon (model_identity probe) → target_fingerprint["model_family"]
    #         → load_seeds (model_family) → load_asr_priors → asr_history 合并
    if model_family:
        priors = load_asr_priors(model_family)
        if priors:
            # 合并 technique_seed_asr 中的模型特定 ASR 到 asr_history
            # 如果 asr_history 中没有某种子的历史, 用先验 ASR 作为初始值
            _model_lower = model_family.lower()
            _tech_seed_asr = priors.get("technique_seed_asr", {})
            for tech_name, owasp_asr in _tech_seed_asr.items():
                if isinstance(owasp_asr, dict):
                    for owasp_id, asr_val in owasp_asr.items():
                        if owasp_id == "default":
                            continue
                        if owasp_id.lower() in _model_lower or _model_lower in owasp_id.lower():
                            # 找到模型特定的 ASR 先验
                            _seed_key = f"{tech_name}:{owasp_id}"
                            if _seed_key not in asr_history:
                                asr_history[_seed_key] = float(asr_val)
            logger.info(
                "Model-specific ASR priors loaded for model_family=%s "
                "(asr_history entries: %d)",
                model_family,
                len(asr_history),
            )

    seed_groups = _rank_by_asr(seed_groups, asr_history)

    # 绉嶅瓙鍔ㄦ€佽鍓?鈥?鑷姩鍓旈櫎 0% ASR 绉嶅瓙 (鏁堢巼浼樺寲)
    # 瀛︽湳渚濇嵁:
    #   - Auer et al. (arXiv:cs/0207052) UCB1 鈥?宸茬煡 0% ASR 绉嶅瓙搴旈檷浣庝紭鍏堢骇
    #   - Chao et al. (arXiv:2402.01135) 鈥?绉嶅瓙璐ㄩ噺鐩存帴褰卞搷 ASR, 浣庢晥绉嶅瓙娴垂 token
    #   - Liu et al. (arXiv:2310.04451) AutoDAN 鈥?瑁佸壀浣庢晥绉嶅瓙鎻愬崌鏁翠綋 ASR
    # 绛栫暐:
    #   1. 璇诲彇 asr_history.json 涓殑 seed_asr
    #   2. 鏈?3+ 娆″皾璇曚笖 ASR=0% 鐨勭瀛愯嚜鍔ㄥ墧闄?
    #   3. 淇濈暀鏂扮瀛?(鏃犲巻鍙茶褰? 浠ユ帰绱㈡綔鍦ㄦ湁鏁堢瀛?
    #   4. 姣忎釜 OWASP 绫诲埆鑷冲皯淇濈暀 1 涓瀛?(绫诲埆瑕嗙洊淇濋殰)
    #   5. 瑁佸壀姣斾緥涓嶈秴杩?50% (閬垮厤杩囧害瑁佸壀)
    seed_groups = _prune_zero_asr_seeds(seed_groups, max_seeds)

    # L5 v32: 绫诲埆澶氭牱鎬т繚闅?(Category Diversity Guarantee)
    # 瀛︽湳渚濇嵁: Determinantal Point Processes (DPP) for diverse subset selection
    #   Kulesza & Taskar (arXiv:1207.6083) 鈥?纭繚閫変腑鐨勭瀛愯鐩栦笉鍚?OWASP 绫诲埆
    # 绛栫暐: 姣忎釜 owasp_id 鑷冲皯 1 涓瀛愬叆閫? 鍓╀綑鍚嶉鎸?UCB 鎺掑簭濉厖
    seed_groups = _apply_category_diversity(seed_groups, max_seeds)

    logger.info("Loaded %d seeds from %s (max=%d, files=%d)", len(seed_groups), seed_file, max_seeds, len(loaded_files))
    return seed_groups


def _filter_dos_seeds(seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """杩囨护 LLM10 (DoS / Unbounded Consumption) 绉嶅瓙銆?

    LLM10 鏀诲嚮 (Model DoS / Unbounded Consumption) 浼氳瀵肩洰鏍囩敓鎴?
    鏋佸ぇ鍝嶅簲 (濡?"鐢熸垚 100 涓?5000 瀛楃殑鏁呬簨"), 娑堣€楀ぇ閲?token銆?
    榛樿绂佺敤浠ユ帶鍒?API 鎴愭湰; 鐢ㄦ埛鍙€氳繃 --enable-dos 鏄惧紡寮€鍚€?

    璇嗗埆鏉′欢: metadata.owasp_id == "LLM10" (澶у皬鍐欎笉鏁忔劅)

    Args:
        seeds: 鍘熷绉嶅瓙鍒楄〃銆?

    Returns:
        杩囨护鍚庣殑绉嶅瓙鍒楄〃 (涓嶅惈 LLM10 绉嶅瓙)銆?
    """
    return [
        seed for seed in seeds
        if str(seed.get("metadata", {}).get("owasp_id", "")).upper() != "LLM10"
    ]


def _prune_zero_asr_seeds(
    seed_groups: list[AttackSeedGroup],
    max_seeds: int,
) -> list[AttackSeedGroup]:
    """鑷姩鍓旈櫎 0% ASR 绉嶅瓙 (鏁堢巼浼樺寲).

    瀛︽湳渚濇嵁:
        - Auer et al. (arXiv:cs/0207052) UCB1 鈥?宸茬煡 0% ASR 绉嶅瓙搴旈檷浣庝紭鍏堢骇
        - Chao et al. (arXiv:2402.01135) 鈥?绉嶅瓙璐ㄩ噺鐩存帴褰卞搷 ASR
        - Liu et al. (arXiv:2310.04451) AutoDAN 鈥?瑁佸壀浣庢晥绉嶅瓙鎻愬崌鏁翠綋 ASR

    绛栫暐:
        1. 璇诲彇 asr_history.json 涓殑 seed_asr 鍜?seed_attempts
        2. 鏈?3+ 娆″皾璇曚笖 ASR=0% 鐨勭瀛愯嚜鍔ㄥ墧闄?
        3. 淇濈暀鏂扮瀛?(鏃犲巻鍙茶褰? 浠ユ帰绱㈡綔鍦ㄦ湁鏁堢瀛?
        4. 姣忎釜 OWASP 绫诲埆鑷冲皯淇濈暀 1 涓瀛?(绫诲埆瑕嗙洊淇濋殰)
        5. 瑁佸壀姣斾緥涓嶈秴杩?50% (閬垮厤杩囧害瑁佸壀)

    Args:
        seed_groups: 宸叉帓搴忕殑绉嶅瓙缁勫垪琛ㄣ€?
        max_seeds: 鏈€澶х瀛愭暟銆?

    Returns:
        瑁佸壀鍚庣殑绉嶅瓙缁勫垪琛ㄣ€?
    """
    import json

    # 鍔犺浇绉嶅瓙绾?ASR 鍘嗗彶
    seed_asr: dict[str, float] = {}
    seed_attempts: dict[str, int] = {}
    if _ASR_HISTORY_PATH.exists():
        try:
            data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
            seed_asr = data.get("seed_asr", {})
            seed_attempts = data.get("seed_attempts", {})
        except (json.JSONDecodeError, KeyError):
            pass

    if not seed_asr:
        logger.debug("L5 v40: No seed ASR history, skipping zero-ASR pruning")
        return seed_groups

    # 鏈€灏忚鍓槇鍊? 3 娆″皾璇曚互涓婃墠瑁佸壀 (缁熻鏄捐憲鎬?
    _MIN_ATTEMPTS_FOR_PRUNE = 3
    # 鏈€澶ц鍓瘮渚? 50% (閬垮厤杩囧害瑁佸壀)
    _MAX_PRUNE_RATIO = 0.5

    # 鏍囪姣忎釜绉嶅瓙鏄惁搴旇瑁佸壀
    prune_indices: set[int] = set()
    for i, group in enumerate(seed_groups):
        objective_text = ""
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                objective_text = obj.value[:100]

        asr = seed_asr.get(objective_text, -1.0)  # -1 = 鏃犲巻鍙?(鏂扮瀛?
        attempts = seed_attempts.get(objective_text, 0)

        # 鏈?3+ 娆″皾璇曚笖 ASR=0% 鈫?鏍囪瑁佸壀
        if asr == 0.0 and attempts >= _MIN_ATTEMPTS_FOR_PRUNE:
            prune_indices.add(i)
            logger.debug(
                "L5 v40: Pruning zero-ASR seed '%s...' (attempts=%d, ASR=0%%)",
                objective_text[:40], attempts,
            )

    if not prune_indices:
        logger.debug("L5 v40: No zero-ASR seeds to prune")
        return seed_groups

    # 闄愬埗瑁佸壀姣斾緥涓嶈秴杩?50%
    max_prune = int(len(seed_groups) * _MAX_PRUNE_RATIO)
    if len(prune_indices) > max_prune:
        # 鎸?attempts 闄嶅簭淇濈暀鍓?max_prune 涓?(灏濊瘯娆℃暟澶氱殑鍏堣鍓?
        prune_candidates: list[tuple[int, int]] = []  # (index, attempts)
        for i in prune_indices:
            obj_text = ""
            if seed_groups[i].seeds:
                obj = next((s for s in seed_groups[i].seeds if hasattr(s, "value")), None)
                if obj:
                    obj_text = obj.value[:100]
            att = seed_attempts.get(obj_text, 0)
            prune_candidates.append((i, att))
        prune_candidates.sort(key=lambda x: -x[1])  # attempts 闄嶅簭
        prune_indices = {c[0] for c in prune_candidates[:max_prune]}

    # 淇濈暀姣忎釜 OWASP 绫诲埆鑷冲皯 1 涓瀛?
    # 鍗充娇 ASR=0% 鐨勭瀛? 濡傛灉鏄绫诲埆鍞竴绉嶅瓙, 浠嶄繚鐣?
    category_counts: dict[str, int] = {}
    for group in seed_groups:
        owasp_id = "UNCATEGORIZED"
        if group.seeds:
            obj = next((s for s in group.seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                owasp_id = str(meta.get("owasp_id", "UNCATEGORIZED")).upper()
        category_counts[owasp_id] = category_counts.get(owasp_id, 0) + 1

    # 浠庤鍓垪琛ㄤ腑绉婚櫎鈥滅被鍒敮涓€绉嶅瓙鈥?
    to_remove_from_prune: set[int] = set()
    for i in prune_indices:
        owasp_id = "UNCATEGORIZED"
        if seed_groups[i].seeds:
            obj = next((s for s in seed_groups[i].seeds if hasattr(s, "value")), None)
            if obj:
                meta = getattr(obj, "metadata", {}) or {}
                owasp_id = str(meta.get("owasp_id", "UNCATEGORIZED")).upper()
        # 濡傛灉璇ョ被鍒彧鍓?1 涓瀛?(灏辨槸褰撳墠杩欎釜), 淇濈暀
        if category_counts.get(owasp_id, 0) <= 1:
            to_remove_from_prune.add(i)
    prune_indices -= to_remove_from_prune

    # 鎵ц瑁佸壀
    pruned = [g for i, g in enumerate(seed_groups) if i not in prune_indices]
    logger.info(
        "L5 v40: Pruned %d zero-ASR seeds (attempts>=%d, ASR=0%%), %d remaining "
        "(%d categories preserved)",
        len(prune_indices), _MIN_ATTEMPTS_FOR_PRUNE, len(pruned),
        len(category_counts),
    )
    return pruned


def _filter_by_language(
    seeds: list[dict[str, Any]],
    target_language: str,
) -> list[dict[str, Any]]:
    """鎸夌洰鏍囪瑷€绛涢€夌瀛?(70% 鐩爣璇█ + 30% 鍏朵粬璇█)銆?

    Args:
        seeds: 鍘熷绉嶅瓙鍒楄〃銆?
        target_language: 鐩爣璇█ ("zh" 鎴?"en")銆?

    Returns:
        绛涢€夊悗鐨勭瀛愬垪琛ㄣ€?
    """
    target_lang_code = target_language.lower()[:2]  # "zh" or "en"

    target_seeds: list[dict[str, Any]] = []
    other_seeds: list[dict[str, Any]] = []

    for seed in seeds:
        metadata = seed.get("metadata", {})
        seed_lang = metadata.get("language", "en")  # 榛樿鑻辨枃

        if seed_lang.lower().startswith(target_lang_code):
            target_seeds.append(seed)
        else:
            other_seeds.append(seed)

    if not target_seeds:
        # 娌℃湁鐩爣璇█绉嶅瓙, 浣跨敤鍏ㄩ儴
        logger.warning("No seeds found for language=%s, using all seeds", target_language)
        return seeds

    # 70% 鐩爣璇█ + 30% 鍏朵粬璇█
    target_count = int(len(target_seeds) * 0.7) + 1
    other_count = int(len(other_seeds) * 0.3) + 1 if other_seeds else 0

    result = target_seeds[:target_count] + other_seeds[:other_count]
    return result


def _filter_by_metadata(
    seeds: list[dict[str, Any]],
    filters: dict[str, str],
) -> list[dict[str, Any]]:
    """按 metadata KEY=VALUE 精准过滤种子。

    增量借鉴 pyrit_scan 的 --seed-filters CLI 模式。

    过滤逻辑:
        - 多 KEY 为 AND 关系 (必须同时匹配所有 key)
        - 值匹配为大小写不敏感的子串匹配 (如 "LLM01" 匹配 "LLM01: Injection")
        - 支持 metadata 中值为列表的情况 (如 category: ["attack", "jailbreak"])
          列表中任一元素匹配即视为匹配

    Args:
        seeds: 原始种子列表。
        filters: {KEY: VALUE} 过滤条件。

    Returns:
        过滤后的种子列表。如果过滤后为空, 返回原始列表 (避免无人攻击)。
    """
    if not filters:
        return seeds

    filtered: list[dict[str, Any]] = []
    for seed in seeds:
        metadata = seed.get("metadata", {})
        if not isinstance(metadata, dict):
            continue

        match_all = True
        for filter_key, filter_val in filters.items():
            seed_val = metadata.get(filter_key)
            if seed_val is None:
                match_all = False
                break

            # 列表值: 任一元素匹配即可
            if isinstance(seed_val, list):
                found = any(
                    filter_val.lower() in str(v).lower()
                    for v in seed_val
                )
                if not found:
                    match_all = False
                    break
            else:
                # 标量值: 大小写不敏感子串匹配
                if filter_val.lower() not in str(seed_val).lower():
                    match_all = False
                    break

        if match_all:
            filtered.append(seed)

    # 如果过滤后为空, 返回原始列表 (避免无人攻击)
    if not filtered:
        logger.warning(
            "Seed metadata filter %s matched 0 seeds, returning all %d seeds",
            filters,
            len(seeds),
        )
        return seeds

    return filtered


def _build_seed_groups(raw_seeds: list[dict[str, Any]]) -> list[AttackSeedGroup]:
    """浠?YAML 鏁版嵁鏋勫缓 AttackSeedGroup 鍒楄〃銆?

    灏嗙瀛?metadata (owasp_id, severity, category 绛? 娉ㄥ叆鍒?
    SeedObjective 鐨?metadata 瀛楁涓紝浣垮叾鍙鍚庣画 AttackExecutor
    浼犻€掑埌 AttackResult.metadata銆?

    娉ㄦ剰: AttackSeedGroup.seeds 鍙寘鍚?SeedObjective锛?
    涓嶅寘鍚?SeedPrompt (SeedPrompt 浼氳 PyRIT 褰撲綔棰濆绉嶅瓙瀵艰嚧閲嶅)銆?
    """
    groups: list[AttackSeedGroup] = []
    for item in raw_seeds:
        value = item.get("value", "")
        metadata = item.get("metadata", {})

        # 灏?metadata 娉ㄥ叆 SeedObjective (鐢ㄤ簬鍚庣画浼犻€掑埌 AttackResult)
        objective = SeedObjective(
            value=value,
            harm_categories=[metadata.get("category", "general")],
            metadata=metadata,
        )
        group = AttackSeedGroup(seeds=[objective])
        groups.append(group)

    return groups


def _load_asr_history() -> dict[str, float]:
    """鍔犺浇 ASR 鍘嗗彶鏂囦欢銆?"""
    if not _ASR_HISTORY_PATH.exists():
        return {}
    try:
        data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
        return data.get("asr", {})
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to load ASR history: %s", e)
        return {}


# 鈹€鈹€ L5 v13: ASR 鍏堥獙 + MTOS 閫夌 鈹€鈹€

