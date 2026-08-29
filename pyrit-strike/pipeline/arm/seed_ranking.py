"""seed_ranking — 从 seed_ranker.py 拆分而来.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from pyrit.models import AttackSeedGroup

from pipeline.arm.seed_auto_expander import _compute_adaptive_ucb_c

logger = logging.getLogger(__name__)

_SEEDS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "seeds"
_ASR_HISTORY_PATH = _SEEDS_DIR / "asr_history.json"
_ASR_PRIORS_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "asr_priors.yaml"

def _rank_by_asr(
    seed_groups: list[AttackSeedGroup],
    asr_history: dict[str, float],
) -> list[AttackSeedGroup]:
    """按历史 ASR + 贝叶斯 UCB 排序种子组。
    """
    if not asr_history:
        return seed_groups

    # 加载种子级 ASR (如果有)
    seed_asr: dict[str, float] = {}
    seed_attempts: dict[str, int] = {}
    if _ASR_HISTORY_PATH.exists():
        try:
            data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
            seed_asr = data.get("seed_asr", {})
            seed_attempts = data.get("seed_attempts", {})
        except (json.JSONDecodeError, KeyError):
            pass

    # UCB 参数
    import math
    # L5 v11: UCB C 参数自适应 — 根据种子数和置信度历史动态调整
    # 控制探索-利用平衡:
    #   - C 大 → 更多探索 (尝试新种子)
    #   - C 小 → 更多利用 (重用高 ASR 种子)
    # 自适应策略:
    #   1. 种子数少 (N < 10): C=0.8 (强探索, 样本不足需多探索)
    #   2. 种子数中 (10 ≤ N < 50): C=0.5 (标准平衡)
    #   3. 种子数多 (N ≥ 50): C=0.3 (弱探索, 已有足够数据)
    #   4. 如果有置信度历史, 进一步微调
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
                objective_text = obj.value[:100]
                meta = getattr(obj, "metadata", {}) or {}
                severity = meta.get("severity", "medium")

        # 先查种子级 ASR, 再查技术级 ASR
        asr = seed_asr.get(objective_text, 0.0)
        if asr == 0.0:
            asr = asr_history.get(objective_text[:100], asr_history.get(str(i), 0.0))

        if asr > 0:
            # L5 v8: 使用 UCB 排序
            n_i = seed_attempts.get(objective_text, 1)
            ucb_bonus = C * math.sqrt(2 * math.log(max(N, 1)) / max(n_i, 1))
            ucb_score = asr + ucb_bonus * 100  # 缩放到 ASR 同量级
            with_ucb.append((ucb_score, i, group))
            logger.debug(
                "UCB seed '%s...': ASR=%.1f%%, attempts=%d, UCB=%.1f",
                objective_text[:40], asr, n_i, ucb_score,
            )
        else:
            without_ucb.append((severity, i, group))

    # UCB 降序，同 UCB 保持原始顺序
    with_ucb.sort(key=lambda x: (-x[0], x[1]))
    # 无 UCB 的按 severity 降序
    without_ucb.sort(key=lambda x: (severity_order.get(x[0], 4), x[1]))

    return [g for _, _, g in with_ucb] + [g for _, _, g in without_ucb]

def _apply_category_diversity(
    seed_groups: list[AttackSeedGroup],
    max_seeds: int,
) -> list[AttackSeedGroup]:
    """L5 v32: 类别多样性保障 — 确保每个 OWASP 类别至少 1 个种子入选。
    """
    if len(seed_groups) <= max_seeds:
        return seed_groups

    # Pass 1: 每个 owasp_id 取第一个种子 (类别配额)
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

    # Pass 2: 剩余名额按 UCB 排序顺序填充
    if len(selected) < max_seeds:
        slots = max_seeds - len(selected)
        selected.extend(remaining[:slots])

    # 日志: 覆盖的 OWASP 类别
    covered = sorted(seen_categories)
    logger.info(
        "Category Diversity Guarantee: %d seeds selected, OWASP coverage: %s",
        len(selected),
        ", ".join(covered),
    )

    return selected

def _get_asr_history_path() -> Path:
    """动态获取 ASR 历史路径 (支持测试时 monkey-patch seed_ranker._ASR_HISTORY_PATH)。
    """
    try:
        from pipeline.arm import seed_ranker
        # 测试设置 seed_ranker._ASR_HISTORY_PATH 后, 该值会覆盖 re-export 的引用
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
    """运行后更新 ASR 历史。
    """
    asr_history_path = _get_asr_history_path()
    seeds_dir = asr_history_path.parent
    seeds_dir.mkdir(parents=True, exist_ok=True)

    # 读取已有历史 (保留 threshold_history 等)
    existing_history: dict[str, Any] = {}
    if asr_history_path.exists():
        try:
            existing_history = json.loads(
                asr_history_path.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, KeyError):
            pass

    # L5 v9: 合并种子级 ASR (指数移动平均, α=0.3)
    existing_seed_asr: dict[str, float] = existing_history.get("seed_asr", {})
    existing_seed_attempts: dict[str, int] = existing_history.get("seed_attempts", {})

    if seed_asr:
        alpha = 0.3  # EMA 权重
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

    # L5 v30: 确保 threshold_history 每次运行都有最新记录
    #   原先 adaptive_threshold 在 AdaptiveDualJudgeScorer 中调用,
    #   但 L5 v21 回退到原生 SelfAskTrueFalseScorer 后不再触发。
    #   修复: 在 save_asr_history 中直接写入当前运行的 ASR 和阈值。
    if technique_asr:
        from datetime import datetime as _dt

        avg_asr = sum(technique_asr.values()) / len(technique_asr)
        # 简化阈值逻辑: ASR > 70% → 0.75, < 40% → 0.80, 其他 → 0.85
        current_threshold = 0.75 if avg_asr > 70.0 else 0.80 if avg_asr < 40.0 else 0.85

        threshold_history = history["threshold_history"]
        threshold_history.append({
            "asr": round(avg_asr, 1),
            "threshold": current_threshold,
            "timestamp": _dt.now().isoformat(),
        })
        # 保留最近 10 条
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
    """加载 ASR 先验配置。
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
    """获取技术×模型的 ASR 先验值。
    """
    if priors is None:
        priors = load_asr_priors(model_name)

    technique_priors = priors.get("technique_asr", {})
    tech_data = technique_priors.get(technique_name, {})

    if not tech_data:
        return 0.0

    # 模糊匹配模型名
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
    """运行后更新 asr_priors.yaml 中该模型族的 ASR 先验 (断点 #4 修复).
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

    alpha = 0.3  # EMA 权重 — 新观测 30%, 先验 70%
    model_lower = model_family.lower()
    updated = False

    # 更新 technique_asr
    tech_priors = priors.get("technique_asr", {})
    for tech, observed_asr in technique_asr.items():
        if tech in tech_priors:
            # 模糊匹配模型族
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
                if abs(new_val - old_val) > 0.05:  # 仅在有变化时更新
                    tech_priors[tech][matched_key] = new_val
                    updated = True
                    logger.debug(
                        "ASR prior updated: %s[%s] %.1f → %.1f (observed=%.1f, α=0.3)",
                        tech, matched_key, old_val, new_val, observed_asr,
                    )

    if updated:
        priors["technique_asr"] = tech_priors
        try:
            with open(_ASR_PRIORS_PATH, "w", encoding="utf-8") as f:
                yaml.dump(priors, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            logger.info(
                "ASR priors updated for model_family=%s (EMA α=0.3, techniques=%d)",
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
    """MTOS 多轮攻击选种 — 反向于单轮排序。
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

    # L5 v36: 交叉 ASR 先验加权
    # 当有 technique_seed_asr 时, 从其他维度按比例缩减 15% 给交叉 ASR bonus
    w_cross = 0.0
    if technique_seed_asr:
        w_cross = 0.15  # 15% 权重给交叉 ASR
        # 按比例缩减其他权重
        scale = (1.0 - w_cross) / 1.0
        w_asr *= scale
        w_diff *= scale
        w_sev *= scale
        w_div *= scale

    asr_suitability_map = priors.get("mtos_asr_suitability", {})

    # 加载种子级 ASR
    seed_asr: dict[str, float] = {}
    if _ASR_HISTORY_PATH.exists():
        try:
            data = json.loads(_ASR_HISTORY_PATH.read_text(encoding="utf-8"))
            seed_asr = data.get("seed_asr", {})
        except (json.JSONDecodeError, KeyError):
            pass

    difficulty_order = {"easy": 4, "low": 3, "medium": 2, "hard": 1, "extreme": 0}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "easy": 4}

    # 按类别统计
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
                objective_text = obj.value[:100]
                meta = getattr(obj, "metadata", {}) or {}
                severity = meta.get("severity", "medium")
                difficulty = meta.get("difficulty", "medium")
                category = str(meta.get("category", "general"))
                owasp_id = str(meta.get("owasp_id", "")).upper()

        # 获取种子 ASR
        asr = seed_asr.get(objective_text, 0.0)
        if asr == 0.0:
            asr = asr_history.get(objective_text[:100], 0.0)

        # ASR 适宜性: 低 ASR → 高适宜性
        asr_bucket = int(asr // 5) * 5  # 量化到 5 的倍数
        suitability = float(asr_suitability_map.get(str(asr_bucket), 50.0))
        if asr == 0.0:
            suitability = 100.0  # ASR=0 → 最适合多轮

        # 难度分数: 越难越高
        diff_score = (5 - difficulty_order.get(difficulty, 2)) * 20.0

        # 严重性分数
        sev_score = (5 - severity_order.get(severity, 2)) * 20.0

        # 类别多样性: 稀有类别高分
        cat_count = category_counts.get(category, 1)
        div_score = max(0, 100.0 - (cat_count - 1) * 30.0)

        # L5 v36: 交叉 ASR 先验 bonus
        # 查询 technique_seed_asr 中该 OWASP 类别的预期 ASR
        cross_score = 50.0  # 默认中性
        if technique_seed_asr and owasp_id:
            cross_asr_val = technique_seed_asr.get(owasp_id)
            if cross_asr_val is None:
                cross_asr_val = technique_seed_asr.get("default", 50.0)
            # 将 ASR (0-100) 映射为 0-100 的分数 (高 ASR → 高分)
            cross_score = float(cross_asr_val)

        # MTOS 加权总分
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
            "%s cross=%.1f → %.1f",
            objective_text[:40], asr, suitability, diff_score, sev_score, div_score,
            f", tech={technique_name}" if technique_name else "",
            cross_score if w_cross > 0 else 0.0,
            mtos_score,
        )

    # MTOS 降序
    scored.sort(key=lambda x: (-x[0], x[1]))

    return [g for _, _, g in scored]
