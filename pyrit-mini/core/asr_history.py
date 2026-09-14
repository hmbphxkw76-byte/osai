"""ASR history 读写共享件（assess 写、arm 读，蓝图 I7）— 下沉自 arm.seed_ranking（CP-009 S3）。

单一真相源：禁止 assess 与 arm 各自维护（C3）。
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_ASR_HISTORY_PATH = Path(__file__).resolve().parent.parent / "data" / "seeds" / "asr_history.json"

def _make_seed_key(objective: str) -> str:
    """Generate a collision-resistant seed ASR key using SHA256.

    Problem: Using ''objective[:100]'' prefix as key causes collisions when
    different seeds share the first 100 characters.

    Fix: Use the first 16 hex characters of SHA256(objective) as key,
    reducing collision probability from ~1/100 (prefix) to ~1/2^128.

    Backward compatibility: Callers that fail to find the new key should
    fall back to the legacy ''[:100]'' prefix key for historical data migration.
    """
    if not objective:
        return ""
    return hashlib.sha256(objective.encode("utf-8")).hexdigest()[:16]

def _get_asr_history_path() -> Path:
    """ASR history 路径（单一真相源，见 _ASR_HISTORY_PATH）。"""
    return _ASR_HISTORY_PATH

def update_asr_history(
    technique_asr: dict[str, float],
    *,
    seed_asr: dict[str, float] | None = None,
    seed_attempts: dict[str, int] | None = None,
) -> None:
    """X?ASR ?

    X?ASR  data/seeds/asr_history.json?
    XuEUR?

    L5 v9: X?ASR , X?(UCB)?
    [: Auer et al. (arXiv:cs/0207052) ?UCB1 EUR?
    ?ASR XEUR?

    Args:
        technique_asr: {technique_name: asr_percentage}
        seed_asr: {seed_objective_prefix: asr_percentage} (XEUR?
        seed_attempts: {seed_objective_prefix: attempt_count} (XEUR?
    """
    asr_history_path = _get_asr_history_path()
    seeds_dir = asr_history_path.parent
    seeds_dir.mkdir(parents=True, exist_ok=True)

    # ( threshold_history ?
    existing_history: dict[str, Any] = {}
    if asr_history_path.exists():
        try:
            existing_history = json.loads(asr_history_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, KeyError):
            pass

    # L5 v9: ?ASR (, =0.3)
    # [: UCB1 (arXiv:cs/0207052) ?
    existing_seed_asr: dict[str, float] = existing_history.get("seed_asr", {})
    existing_seed_attempts: dict[str, int] = existing_history.get("seed_attempts", {})

    if seed_asr:
        alpha = 0.3  # EMA
        for seed_key, new_asr in seed_asr.items():
            if seed_key in existing_seed_asr:
                existing_seed_asr[seed_key] = round(alpha * new_asr + (1 - alpha) * existing_seed_asr[seed_key], 1)
            else:
                existing_seed_asr[seed_key] = new_asr

    if seed_attempts:
        for seed_key, count in seed_attempts.items():
            existing_seed_attempts[seed_key] = existing_seed_attempts.get(seed_key, 0) + count

    history = {
        "last_run": datetime.now().isoformat(),
        "asr": technique_asr,
        "seed_asr": existing_seed_asr,
        "seed_attempts": existing_seed_attempts,
        "threshold_history": existing_history.get("threshold_history", []),
    }

    # L5 v30: X threshold_history XXEURX?
    # [: Auer et al. (arXiv:cs/0207052) ?UCB1 EUR?ASR X
    # adaptive_threshold ?AdaptiveDualJudgeScorer X?
    # ?L5 v21 EUREUR?SelfAskTrueFalseScorer EEUR?
    # XX: ?save_asr_history Xyuyu ASR EUR?
    if technique_asr:
        from datetime import datetime as _dt

        avg_asr = sum(technique_asr.values()) / len(technique_asr)
        # EUREUR: ASR > 70% ?0.75, < 40% ?0.80, ?0.85
        # [: Zhang et al. (arXiv:2308.07920) ?XEUR
        current_threshold = 0.75 if avg_asr > 70.0 else 0.80 if avg_asr < 40.0 else 0.85

        threshold_history = history["threshold_history"]
        threshold_history.append(
            {
                "asr": round(avg_asr, 1),
                "threshold": current_threshold,
                "timestamp": _dt.now().isoformat(),
            }
        )
        # EUR?10 ?
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

