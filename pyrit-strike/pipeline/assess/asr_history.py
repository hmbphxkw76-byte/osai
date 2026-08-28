"""asr_history — 从 asr_tracker.py 拆分而来.

包含 ASR 历史保存, converter ASR 历史, GCG 后缀 ASR 历史.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _get_asr_history_path():
    """动态获取 ASR 历史路径 (支持测试时 monkey-patch seed_ranker._ASR_HISTORY_PATH)。"""
    from pipeline.arm import seed_ranker
    return seed_ranker._ASR_HISTORY_PATH


def save_asr_history(
    asr_per_technique: dict[str, float],
    *,
    attack_results: dict[str, list[Any]] | None = None,
) -> None:
    """将 ASR 历史写入 data/seeds/asr_history.json。

    L5 v9: 同时写入种子级 ASR, 供 UCB 排序使用。
    学术依据: Auer et al. (arXiv:cs/0207052) — UCB1 算法
    需要种子级 ASR 和尝试次数才能有效排序。

    Args:
        asr_per_technique: 按技术统计的 ASR。
        attack_results: 攻击结果 (用于提取种子级 ASR)。
    """
    from pipeline.arm.seed_ranker import update_asr_history

    # L5 v9: 提取种子级 ASR
    seed_asr: dict[str, float] = {}
    seed_attempts: dict[str, int] = {}

    # L5 v11: 提取 converter 级 ASR (供动态裁剪使用)
    converter_asr: dict[str, float] = {}
    converter_attempts: dict[str, int] = {}

    # L5 v18: 提取 GCG 后缀级 ASR (供动态排序使用)
    # 学术依据: Zou et al. (arXiv:2307.08673) §4.3 — 后缀级 ASR 历史可用于
    # 优先尝试高效后缀, 减少 FIRST_SUCCESS 策略下的 API 调用
    gcg_suffix_asr: dict[str, float] = {}
    gcg_suffix_attempts: dict[str, int] = {}

    if attack_results:
        # 按 objective 前缀统计种子级成功率
        seed_stats: dict[str, dict[str, int]] = {}  # {prefix: {success, total}}
        for results in attack_results.values():
            for result in results:
                objective = getattr(result, "objective", "") or ""
                if not objective:
                    continue
                prefix = objective[:100]  # 使用前100字符作为种子标识
                if prefix not in seed_stats:
                    seed_stats[prefix] = {"success": 0, "total": 0}
                seed_stats[prefix]["total"] += 1
                from pipeline.assess.asr_tracker import _get_outcome
                outcome = _get_outcome(result)
                if outcome == "success":
                    seed_stats[prefix]["success"] += 1

                # L5 v11: 提取 converter 级 ASR
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

                # L5 v18: 提取 GCG 后缀级 ASR
                # 从 metadata 中提取 gcg_suffix 字段 (由 _run_gcg 注入)
                gcg_suffix = ""
                if isinstance(meta, dict):
                    gcg_suffix = str(meta.get("gcg_suffix", ""))
                if gcg_suffix:
                    # 使用前40字符作为键 (与 escalation.py 中排序逻辑一致)
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

        # L5 v11: 计算 converter 级 ASR 百分比
        for conv_name in converter_asr:
            total = converter_attempts.get(conv_name, 1)
            converter_asr[conv_name] = round(
                converter_asr[conv_name] / total * 100, 1
            )

        # L5 v18: 计算 GCG 后缀级 ASR 百分比
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

    # L5 v11: 保存 converter 级 ASR 到历史文件
    if converter_asr:
        _save_converter_asr_history(converter_asr, converter_attempts)

    # L5 v18: 保存 GCG 后缀级 ASR 到历史文件
    if gcg_suffix_asr:
        _save_gcg_suffix_asr_history(gcg_suffix_asr, gcg_suffix_attempts)

def _save_converter_asr_history(
    converter_asr: dict[str, float],
    converter_attempts: dict[str, int],
) -> None:
    """L5 v11: 保存 converter 级 ASR 到 asr_history.json。

    将 converter 路径的 ASR 数据写入历史文件, 供 _prune_low_asr_converters
    在下次运行时使用。使用 EMA (alpha=0.3) 合并历史数据。

    学术依据: PyRIT SequentialAttack (arXiv:2407.01232) - 路径级
    ASR 历史可用于动态裁剪低效路径, 提升吞吐量 ~30%。

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

    # EMA 合并 converter ASR (alpha=0.3)
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
    """L5 v18: 保存 GCG 后缀级 ASR 到 asr_history.json。

    将 GCG 后缀的 ASR 数据写入历史文件, 供 _generate_gcg_suffix_pool
    在下次运行时按 ASR 降序排列。使用 EMA (alpha=0.3) 合并历史数据。

    学术依据: Zou et al. (arXiv:2307.08673) §4.3 — 后缀级 ASR 历史
    可用于优先尝试高效后缀, 减少 API 调用 ~20%。

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

    # EMA 合并 GCG 后缀 ASR (alpha=0.3)
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
