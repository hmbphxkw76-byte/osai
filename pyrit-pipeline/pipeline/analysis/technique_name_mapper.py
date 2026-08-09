# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""技术名标准化映射器 — 将各种技术名格式统一映射到 PyRIT 原生规范名。.

PyRIT AttackTechniqueRegistry 中的技术名采用 snake_case 规范 (如 "many_shot", "tap")，
但用户输入、数据集元数据、学术文献中可能使用不同的格式:

  - "Many-Shot" / "many-shot" / "manyshot" / "MANY_SHOT" → "many_shot"
  - "Tree of Attacks" / "tree-of-attacks" / "TOA" → "tree_of_attacks"
  - "PAIR" / "pair-attack" → "pair"
  - "Crescendo" / "crescendo-attack" → "crescendo"
  - "Prompt Sending" / "prompt-sending" / "direct" → "prompt_sending"

本模块提供双向映射:
  1. normalize_technique_name() — 将任意格式映射到规范名
  2. get_display_name() — 将规范名映射到人类可读名称
  3. get_arxiv_reference() — 获取技术的 arXiv 引用

学术依据:
  - PyRIT 官方 AttackTechniqueRegistry 命名规范
  - JailbreakBench (arXiv:2402.01135) 标准化技术名称

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


# ============================================================
# 别名 → 规范名映射
# ============================================================

_TECHNIQUE_ALIASES: dict[str, str] = {
    # prompt_sending
    "prompt_sending": "prompt_sending",
    "prompt-sending": "prompt_sending",
    "promptsending": "prompt_sending",
    "direct": "prompt_sending",
    "direct_prompt": "prompt_sending",
    "baseline": "prompt_sending",
    "multi_prompt_sending": "multi_prompt_sending",
    "chunked_request": "chunked_request",
    # many_shot
    "many_shot": "many_shot",
    "many-shot": "many_shot",
    "manyshot": "many_shot",
    "many shot": "many_shot",
    "many_shot_jailbreak": "many_shot",
    # crescendo
    "crescendo": "crescendo",
    "crescendo_attack": "crescendo",
    "crescendo-attack": "crescendo",
    "great_now_we_have_to_sing": "crescendo",
    # crescendo variants
    "crescendo_simulated": "crescendo_simulated",
    "crescendo-simulated": "crescendo_simulated",
    "crescendo_movie_director": "crescendo_movie_director",
    "crescendo_history_lecture": "crescendo_history_lecture",
    "crescendo_journalist_interview": "crescendo_journalist_interview",
    # tap
    "tap": "tap",
    "tree_of_attacks": "tap",
    "tree-of-attacks": "tap",
    "tree_of_attack": "tap",
    "tree_of_attacks_pruned": "tree_of_attacks_pruned",
    "toa": "tap",
    "toap": "tree_of_attacks_pruned",
    # pair
    "pair": "pair",
    "pair_attack": "pair",
    "pair-attack": "pair",
    "jailbreaking_black_box": "pair",
    "twenty_queries": "pair",
    # red_teaming
    "red_teaming": "red_teaming",
    "red-teaming": "red_teaming",
    "redteam": "red_teaming",
    "red_team": "red_teaming",
    "rta": "red_teaming",
    # skeleton_key
    "skeleton_key": "skeleton_key",
    "skeleton-key": "skeleton_key",
    "skeletonkey": "skeleton_key",
    # best_of_n
    "best_of_n_jailbreak": "best_of_n_jailbreak",
    "best_of_n": "best_of_n_jailbreak",
    "best-of-n": "best_of_n_jailbreak",
    "bon": "best_of_n_jailbreak",
    # bad_likert_judge
    "bad_likert_judge": "bad_likert_judge",
    "bad-likert-judge": "bad_likert_judge",
    "badlikert": "bad_likert_judge",
    "likert": "bad_likert_judge",
    # role_play variants
    "role_play_movie_script": "role_play_movie_script",
    "role-play-movie-script": "role_play_movie_script",
    "movie_script": "role_play_movie_script",
    "role_play_persuasion": "role_play_persuasion",
    "role_play_persuasion_written": "role_play_persuasion_written",
    "role_play_trivia_game": "role_play_trivia_game",
    "role_play_video_game": "role_play_video_game",
    # context_compliance
    "context_compliance": "context_compliance",
    "context-compliance": "context_compliance",
    "cca": "context_compliance",
    # wrapping_attack
    "wrapping_attack": "wrapping_attack",
    "wrapping-attack": "wrapping_attack",
    "wrapping": "wrapping_attack",
    # violent_durian
    "violent_durian": "violent_durian",
    "violent-durian": "violent_durian",
    "durian": "violent_durian",
    # Converter 链名 (作为变体后缀)
    "stealth_evasion": "stealth_evasion",
    "stealth-evasion": "stealth_evasion",
    "encoding_bypass": "encoding_bypass",
    "encoding-bypass": "encoding_bypass",
    "unicode_attack": "unicode_attack",
    "unicode-attack": "unicode_attack",
    "multi_encoding_v2": "multi_encoding_v2",
    "multi-encoding-v2": "multi_encoding_v2",
    "random_case": "random_case",
    "random-case": "random_case",
    "format_injection": "format_injection",
    "format-injection": "format_injection",
    "noise_bypass": "noise_bypass",
    "noise-bypass": "noise_bypass",
    "special_chars": "special_chars",
    "special-chars": "special_chars",
    "persuasion_authority": "persuasion_authority",
    "persuasion-authority": "persuasion_authority",
    "decomposition_chain": "decomposition_chain",
    "decomposition-chain": "decomposition_chain",
    "llm_assisted": "llm_assisted",
    "llm-assisted": "llm_assisted",
    "task_framing_chain": "task_framing_chain",
    "task-framing-chain": "task_framing_chain",
}


# ============================================================
# PyRIT 类名 → 规范技术名映射
# ============================================================

_CLASS_NAME_TO_TECHNIQUE: dict[str, str] = {
    # PyRIT 原生攻击策略类名 → 技术名
    "PromptSendingAttack": "prompt_sending",
    "ManyShotJailbreakAttack": "many_shot",
    "CrescendoAttack": "crescendo",
    "TAPAttack": "tap",
    "PAIRAttack": "pair",
    "RedTeamingAttack": "red_teaming",
    "BestOfNJailbreakAttack": "best_of_n_jailbreak",
    "BadLikertJudgeAttack": "bad_likert_judge",
    "SkeletonKeyAttack": "skeleton_key",
    "ContextComplianceAttack": "context_compliance",
    "WrappingAttack": "wrapping_attack",
    "ViolentDurianAttack": "violent_durian",
    # Crescendo 变体
    "CrescendoSimulatedAttack": "crescendo_simulated",
    "CrescendoMovieDirectorAttack": "crescendo_movie_director",
    "CrescendoHistoryLectureAttack": "crescendo_history_lecture",
    "CrescendoJournalistInterviewAttack": "crescendo_journalist_interview",
    # Role Play 变体
    "RolePlayMovieScriptAttack": "role_play_movie_script",
    "RolePlayPersuasionAttack": "role_play_persuasion",
    "RolePlayPersuasionWrittenAttack": "role_play_persuasion_written",
    "RolePlayTriviaGameAttack": "role_play_trivia_game",
    "RolePlayVideoGameAttack": "role_play_video_game",
    # 复合攻击
    "SequentialAttack": "sequential",
    # AtomicAttack (兜底标识)
    "AtomicAttack": "unknown",
}


def map_class_name_to_technique(class_name: str) -> str | None:
    """将 PyRIT 攻击策略类名映射到规范技术名.

    Args:
        class_name: PyRIT 攻击策略类名 (如 "ManyShotJailbreakAttack")

    Returns:
        规范技术名 (如 "many_shot"), 或 None (无映射时)
    """
    return _CLASS_NAME_TO_TECHNIQUE.get(class_name)


# ============================================================
# 规范名 → 显示名映射
# ============================================================

_DISPLAY_NAMES: dict[str, str] = {
    "prompt_sending": "Prompt Sending (Baseline)",
    "multi_prompt_sending": "Multi Prompt Sending",
    "chunked_request": "Chunked Request",
    "many_shot": "Many-Shot Jailbreak",
    "crescendo": "Crescendo",
    "crescendo_simulated": "Crescendo (Simulated)",
    "crescendo_movie_director": "Crescendo (Movie Director)",
    "crescendo_history_lecture": "Crescendo (History Lecture)",
    "crescendo_journalist_interview": "Crescendo (Journalist Interview)",
    "tap": "TAP (Tree of Attacks)",
    "tree_of_attacks_pruned": "TAP (Pruned)",
    "pair": "PAIR",
    "red_teaming": "Red Teaming",
    "skeleton_key": "Skeleton Key",
    "best_of_n_jailbreak": "Best-of-N Jailbreak",
    "bad_likert_judge": "Bad Likert Judge",
    "role_play_movie_script": "Role Play (Movie Script)",
    "role_play_persuasion": "Role Play (Persuasion)",
    "role_play_persuasion_written": "Role Play (Persuasion Written)",
    "role_play_trivia_game": "Role Play (Trivia Game)",
    "role_play_video_game": "Role Play (Video Game)",
    "context_compliance": "Context Compliance Attack",
    "wrapping_attack": "Wrapping Attack",
    "violent_durian": "Violent Durian",
}


# ============================================================
# 规范名 → arXiv 引用映射
# ============================================================

_ARXIV_REFERENCES: dict[str, str] = {
    "many_shot": "arXiv:2402.05124 — Many-shot Jailbreaking (Aggarwal et al.)",
    "crescendo": "arXiv:2402.12109 — Great, Now We Have to Sing (Russinovich et al.)",
    "crescendo_simulated": "arXiv:2402.12109 — Crescendo Simulated",
    "tap": "arXiv:2312.02191 — Tree of Attacks (Mehrotra et al.)",
    "tree_of_attacks_pruned": "arXiv:2312.02191 — TAP Pruned",
    "pair": "arXiv:2310.08437 — Jailbreaking Black Box LLMs (Chao et al.)",
    "red_teaming": "arXiv:2202.01241 — Red Teaming (Perez et al.)",
    "skeleton_key": "arXiv:2407.01576 — Skeleton Key (Microsoft)",
    "best_of_n_jailbreak": "arXiv:2402.01135 — Best-of-N (JailbreakBench)",
    "bad_likert_judge": "arXiv:2311.08268 — Bad Likert Judge",
    "context_compliance": "Context Compliance Attack (PyRIT)",
    "wrapping_attack": "Wrapping Attack (Empirical)",
    "violent_durian": "Violent Durian (PyRIT)",
    "prompt_sending": "Baseline (No Converter)",
    "stealth_evasion": "arXiv:2307.15043 — Unicode + Base64 + Suffix",
    "encoding_bypass": "arXiv:2307.15043 — Encoding Bypass",
    "multi_encoding_v2": "arXiv:2307.15043 — Multi-Layer Encoding",
    "unicode_attack": "arXiv:2307.15043 — Unicode Attack",
    "persuasion_authority": "arXiv:2402.19181 — Persuasion (Zeng et al.)",
    "decomposition_chain": "arXiv:2311.08268 — Decomposition",
}


# ============================================================
# 公共 API
# ============================================================


def normalize_technique_name(name: str) -> str:
    """将任意格式的技术名标准化为 PyRIT 规范名。.

    处理步骤:
    1. 去除首尾空白
    2. 转小写
    3. 查找别名映射
    4. 如果含 "+" (Converter 变体), 分别标准化基础名和链名
    5. 如果未找到映射, 将 "-" 和 " " 替换为 "_" 作为兜底

    Args:
        name: 任意格式的技术名

    Returns:
        PyRIT 规范名 (snake_case)
    """
    if not name:
        return name

    name = name.strip()

    # 处理 Converter 变体 (如 "Many-Shot+stealth-evasion")
    if "+" in name:
        parts = name.split("+", 1)
        base = normalize_technique_name(parts[0])
        chain = normalize_technique_name(parts[1])
        return f"{base}+{chain}"

    # 查找别名映射
    key = name.lower()
    if key in _TECHNIQUE_ALIASES:
        return _TECHNIQUE_ALIASES[key]

    # 兜底: 将 "-" 和 " " 替换为 "_"
    normalized = re.sub(r"[-\s]+", "_", key)
    logger.debug(f"Technique name '{name}' normalized to '{normalized}' (fallback)")
    return normalized


def get_display_name(technique_name: str) -> str:
    """获取技术的人类可读显示名。.

    对于 Converter 变体 (如 "prompt_sending+stealth_evasion"),
    返回 "Prompt Sending (Baseline) + Stealth Evasion" 格式。

    Args:
        technique_name: 规范技术名

    Returns:
        人类可读显示名
    """
    if "+" in technique_name:
        parts = technique_name.split("+", 1)
        base_display = get_display_name(parts[0])
        chain_display = get_display_name(parts[1])
        return f"{base_display} + {chain_display}"

    return _DISPLAY_NAMES.get(technique_name, technique_name.replace("_", " ").title())


def get_arxiv_reference(technique_name: str) -> str | None:
    """获取技术的 arXiv 学术引用。.

    对于 Converter 变体, 优先返回基础技术的引用。

    Args:
        technique_name: 规范技术名

    Returns:
        arXiv 引用字符串, 或 None
    """
    if "+" in technique_name:
        base = technique_name.split("+")[0]
        return _ARXIV_REFERENCES.get(base) or _ARXIV_REFERENCES.get(technique_name)
    return _ARXIV_REFERENCES.get(technique_name)


def normalize_technique_list(names: list[str]) -> list[str]:
    """批量标准化技术名列表。.

    Args:
        names: 任意格式的技术名列表

    Returns:
        规范名列表 (保持顺序, 去重)
    """
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        normalized = normalize_technique_name(name)
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def is_known_technique(name: str) -> bool:
    """检查技术名是否在已知映射中。."""
    normalized = normalize_technique_name(name)
    base = normalized.split("+")[0] if "+" in normalized else normalized
    return base in _DISPLAY_NAMES or base in _TECHNIQUE_ALIASES
