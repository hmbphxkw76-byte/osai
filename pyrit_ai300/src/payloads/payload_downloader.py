"""
Academic Payload Downloader — 高 ASR 学术载荷本地化管理
======================================================

从 JailbreakBench / HarmBench 等学术基准下载高 ASR 攻击载荷到本地 /data 目录，
消除运行时网络依赖，并按 ASR 分层组织文件结构。

设计原则:
  - 高 ASR 优先: 仅下载 ASR >= 15% 的载荷 (Tier S/A/B)
  - 清晰命名: {source}_{technique}_{tier}.yaml
  - 离线可用: 下载后可直接被 DatasetManager 加载
  - ASR 元数据: 每个种子包含 asr_baseline 元数据
  - OWASP 格式对齐: YAML 顶层字段与 OWASP 数据集完全一致
    (name/authors/groups/harm_categories/data_type/seed_type)
  - 自动适配: 新数据集下载后自动生成符合 SeedDataset 标准的 YAML

数据来源:
  1. JailbreakBench (HuggingFace: JailbreakBench/JBB-Behaviors)
  2. HarmBench (HuggingFace: harmbench/harmbench_behaviors)
  3. AdvBench (HuggingFace: walledai/AdvBench)

使用方式:
  # 命令行下载
  python download_academic_payloads.py

  # 代码调用
  from src.payloads.payload_downloader import download_academic_payloads_async
  await download_academic_payloads_async()

目录结构:
  data/academic/
    jailbreakbench/
      tier_s_crescendo.yaml          # ASR >= 70%
      tier_s_red_teaming.yaml
      tier_a_tap.yaml                # ASR 40-70%
      tier_a_pair.yaml
      tier_a_best_of_n.yaml
      tier_b_persuasion.yaml         # ASR 15-40%
      tier_b_context_compliance.yaml
    harmbench/
      tier_s_crescendo_hb.yaml
      tier_a_tap_hb.yaml
      tier_b_persuasion_hb.yaml
    advbench/
      tier_b_direct_injection.yaml
    _manifest.yaml                   # 下载清单（来源/时间/ASR/数量）
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# ── 常量 ──

ACADEMIC_DATA_DIR = Path(__file__).parent.parent.parent / "data" / "academic"

# 最低 ASR 阈值 — 低于此值不下载
MIN_ASR_THRESHOLD = 0.15

# 高优先级远程数据集（按 ASR 贡献排序）
HIGH_ASR_DATASETS = [
    "jailbreakbench",
    "harmbench",
    "advbench",
]

# 技术 → Tier 映射（基于 asr_prior_registry）
TECHNIQUE_TIER_MAP = {
    # Tier S (ASR >= 70%)
    "crescendo": "S",
    "red_teaming": "S",
    # Tier A (ASR 40-70%)
    "tap": "A",
    "tree_of_attacks_pruned": "A",
    "pair": "A",
    "many_shot": "A",
    "crescendo_simulated": "A",
    "best_of_n_jailbreak": "A",
    "role_play_movie_script": "A",
    "role_play_persuasion": "A",
    "wrapping_attack": "A",
    # Tier B (ASR 15-40%)
    "persuasion_authority": "B",
    "context_compliance": "B",
    "decomposition_chain": "B",
    "bad_likert_judge": "B",
    "skeleton_key": "B",
    "direct_injection": "B",
    "agent_injection_chain": "B",
    "stealth_evasion": "B",
    "encoding_bypass": "B",
    "multi_encoding_v2": "B",
    # Tier C (ASR < 15%) — 不下载
    "prompt_sending": "C",
    "rot13": "C",
    "base64": "C",
}

# 技术 → attack_mode 映射
# multi_turn: 需要对抗性对话/迭代轮次的技术
# single_turn: 单轮直接发送的技术
TECHNIQUE_ATTACK_MODE_MAP = {
    # Multi-turn (需要 adversarial chat / 迭代对话)
    "crescendo": "multi_turn",
    "crescendo_simulated": "multi_turn",
    "red_teaming": "multi_turn",
    "tap": "multi_turn",
    "tree_of_attacks_pruned": "multi_turn",
    "pair": "multi_turn",
    "best_of_n_jailbreak": "multi_turn",
    "role_play_movie_script": "multi_turn",
    "role_play_persuasion": "multi_turn",
    "wrapping_attack": "multi_turn",
    "bad_likert_judge": "multi_turn",
    "decomposition_chain": "multi_turn",
    # Single-turn (单轮直接发送)
    "prompt_sending": "single_turn",
    "rot13": "single_turn",
    "base64": "single_turn",
    "persuasion_authority": "single_turn",
    "context_compliance": "single_turn",
    "direct_injection": "single_turn",
    "agent_injection_chain": "single_turn",
    "many_shot": "single_turn",
    "skeleton_key": "single_turn",
    "stealth_evasion": "single_turn",
    "encoding_bypass": "single_turn",
    "multi_encoding_v2": "single_turn",
}


def _get_tier_for_technique(technique: str) -> Optional[str]:
    """获取技术的 Tier 等级"""
    # 直接匹配
    if technique in TECHNIQUE_TIER_MAP:
        tier = TECHNIQUE_TIER_MAP[technique]
        if tier == "C":
            return None  # Tier C 不下载
        return tier
    # 模糊匹配
    tech_lower = technique.lower()
    for key, tier in TECHNIQUE_TIER_MAP.items():
        if key in tech_lower:
            if tier == "C":
                return None
            return tier
    return "B"  # 未知技术默认 Tier B


def _get_asr_for_technique(technique: str, model_name: str = "gpt-4o") -> float:
    """从 ASR Prior Registry 获取技术的 ASR"""
    try:
        from src.payloads.asr_prior_registry import get_initial_q_value
        return get_initial_q_value(technique, model_name)
    except Exception:
        return 0.3  # 默认中性先验


def _get_attack_mode_for_technique(technique: str) -> str:
    """获取技术的 attack_mode（multi_turn / single_turn）"""
    if technique in TECHNIQUE_ATTACK_MODE_MAP:
        return TECHNIQUE_ATTACK_MODE_MAP[technique]
    # 模糊匹配
    tech_lower = technique.lower()
    for key, mode in TECHNIQUE_ATTACK_MODE_MAP.items():
        if key in tech_lower:
            return mode
    return "single_turn"  # 未知技术默认单轮


async def _fetch_remote_dataset(
    dataset_name: str,
    cache: bool = True,
) -> List[Any]:
    """
    使用 PyRIT 原生 SeedDatasetProvider 获取远程数据集

    Args:
        dataset_name: 数据集名称 (如 "jailbreakbench")
        cache: 是否使用缓存

    Returns:
        SeedPrompt 列表
    """
    try:
        from pyrit.datasets import SeedDatasetProvider
        datasets = await SeedDatasetProvider.fetch_datasets_async(
            dataset_names=[dataset_name],
            cache=cache,
        )
        if not datasets:
            logger.warning(f"No data returned for dataset: {dataset_name}")
            return []
        # 合并所有 seeds
        all_seeds = []
        for ds in datasets:
            seeds = getattr(ds, "seeds", [])
            all_seeds.extend(seeds)
        return all_seeds
    except Exception as e:
        logger.error(f"Failed to fetch {dataset_name}: {e}")
        return []


def _classify_seed(seed: Any) -> Optional[str]:
    """
    分类种子的技术类型，返回技术名

    通过种子 metadata 中的 technique/technique_group 字段判断
    """
    meta = getattr(seed, "metadata", {}) or {}
    technique = meta.get("technique", meta.get("technique_group", ""))
    if technique:
        return technique
    # 尝试从 value 中推断
    value = getattr(seed, "value", "")
    if not value:
        return None
    value_lower = value.lower() if isinstance(value, str) else ""
    # 简单关键词匹配
    keywords = {
        "crescendo": "crescendo",
        "pair": "pair",
        "tap": "tap",
        "tree of attacks": "tap",
        "many_shot": "many_shot",
        "many-shot": "many_shot",
        "skeleton key": "skeleton_key",
        "persuasion": "persuasion_authority",
        "encoding": "encoding_bypass",
        "base64": "encoding_bypass",
        "rot13": "encoding_bypass",
        "injection": "direct_injection",
    }
    for keyword, tech in keywords.items():
        if keyword in value_lower:
            return tech
    return "crescendo_simulated"  # P2-1: ASR 驱动默认技术


def _seed_to_yaml_dict(seed: Any, technique: str, asr: float, tier: str, source: str) -> Dict[str, Any]:
    """将 SeedPrompt 转换为 YAML 可序列化字典（对齐 OWASP seed 格式）"""
    meta = getattr(seed, "metadata", {}) or {}
    attack_mode = _get_attack_mode_for_technique(technique)
    # 合并学术 ASR 元数据 + OWASP 标准字段
    meta_with_asr = {
        **meta,
        "technique": technique,
        "technique_group": technique,
        "attack_mode": attack_mode,
        "asr_baseline": {
            "gpt_4o": asr,
            "source": source,
        },
        "academic_tier": tier,
    }
    return {
        "value": getattr(seed, "value", ""),
        "role": getattr(seed, "role", "user"),
        "data_type": str(getattr(seed, "data_type", "text")),
        "metadata": meta_with_asr,
    }


def _save_yaml(
    seeds: List[Dict[str, Any]],
    output_path: Path,
    source: str,
    technique: str,
    tier: str,
) -> int:
    """保存种子列表为 YAML 文件，返回保存数量"""
    if not seeds:
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # PyRIT 1.0.0 SeedDataset 使用 extra="forbid"，顶层仅允许
    # data_type/name/dataset_name/harm_categories/description/
    # authors/groups/source/date_added/added_by/seed_type/seeds。
    # technique/tier/downloaded_at 已保存在每个 seed 的 metadata 中。
    # 顶层字段与 OWASP 数据集格式完全对齐。
    yaml_data = {
        "dataset_name": f"academic_{source}_{technique}",
        "name": f"Academic {source.title()} {technique} (Tier {tier})",
        "description": f"Academic payload from {source} — {technique} (Tier {tier})",
        "source": source,
        "authors": [source],
        "groups": ["academic"],
        "harm_categories": ["other"],
        "data_type": "text",
        "seed_type": "prompt",
        "seeds": seeds,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(yaml_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

    return len(seeds)


async def download_dataset_to_local(
    dataset_name: str,
    output_dir: Path,
    model_name: str = "gpt-4o",
    cache: bool = True,
) -> Dict[str, Any]:
    """
    下载单个远程数据集到本地 YAML 文件

    Args:
        dataset_name: 数据集名称 (如 "jailbreakbench")
        output_dir: 输出目录 (如 data/academic/jailbreakbench/)
        model_name: 用于 ASR 查询的模型名称
        cache: 是否使用 PyRIT 缓存

    Returns:
        下载统计字典
    """
    stats: Dict[str, Any] = {
        "dataset": dataset_name,
        "total_seeds": 0,
        "downloaded_seeds": 0,
        "skipped_low_asr": 0,
        "files_created": [],
        "technique_distribution": {},
    }

    # 1. 获取远程数据
    seeds = await _fetch_remote_dataset(dataset_name, cache=cache)
    stats["total_seeds"] = len(seeds)
    if not seeds:
        return stats

    # 2. 按技术分类
    tech_buckets: Dict[str, List[Dict[str, Any]]] = {}
    for seed in seeds:
        technique = _classify_seed(seed)
        if not technique:
            continue
        tier = _get_tier_for_technique(technique)
        if tier is None:
            stats["skipped_low_asr"] += 1
            continue
        asr = _get_asr_for_technique(technique, model_name)
        if asr < MIN_ASR_THRESHOLD:
            stats["skipped_low_asr"] += 1
            continue

        yaml_dict = _seed_to_yaml_dict(seed, technique, asr, tier, dataset_name)
        if technique not in tech_buckets:
            tech_buckets[technique] = []
        tech_buckets[technique].append(yaml_dict)
        stats["downloaded_seeds"] += 1
        stats["technique_distribution"][technique] = \
            stats["technique_distribution"].get(technique, 0) + 1

    # 3. 按技术保存为 YAML 文件
    for technique, seed_list in tech_buckets.items():
        tier = _get_tier_for_technique(technique) or "B"
        filename = f"tier_{tier.lower()}_{technique}.yaml"
        output_path = output_dir / filename
        count = _save_yaml(seed_list, output_path, dataset_name, technique, tier)
        stats["files_created"].append({
            "file": str(output_path),
            "technique": technique,
            "tier": tier,
            "count": count,
        })
        logger.info(f"  {dataset_name}/{technique}: {count} seeds → {filename}")

    return stats


async def download_academic_payloads_async(
    output_base: Path | None = None,
    model_name: str = "gpt-4o",
    datasets: List[str] | None = None,
    cache: bool = True,
) -> Dict[str, Any]:
    """
    下载所有高 ASR 学术载荷到本地 /data/academic/ 目录

    Args:
        output_base: 输出根目录 (默认 data/academic/)
        model_name: 用于 ASR 查询的模型名称
        datasets: 要下载的数据集列表 (默认 HIGH_ASR_DATASETS)
        cache: 是否使用 PyRIT 缓存

    Returns:
        完整下载统计
    """
    if output_base is None:
        output_base = ACADEMIC_DATA_DIR

    if datasets is None:
        datasets = HIGH_ASR_DATASETS

    print("\n" + "=" * 60)
    print("  学术载荷下载器 — 高 ASR Payload Local Cache")
    print("=" * 60)
    print(f"  输出目录: {output_base}")
    print(f"  模型: {model_name}")
    print(f"  数据源: {', '.join(datasets)}")
    print(f"  最低 ASR 阈值: {MIN_ASR_THRESHOLD:.0%}")
    print()

    all_stats: Dict[str, Any] = {
        "start_time": datetime.now().isoformat(),
        "model_name": model_name,
        "output_dir": str(output_base),
        "datasets": {},
        "total_files": 0,
        "total_seeds": 0,
    }

    for ds_name in datasets:
        ds_dir = output_base / ds_name
        print(f"\n  [{ds_name}] 正在下载...")

        stats = await download_dataset_to_local(
            dataset_name=ds_name,
            output_dir=ds_dir,
            model_name=model_name,
            cache=cache,
        )
        all_stats["datasets"][ds_name] = stats

        print(f"  [{ds_name}] 完成: {stats['downloaded_seeds']}/{stats['total_seeds']} seeds "
              f"(跳过 {stats['skipped_low_asr']} 低 ASR)")
        if stats["technique_distribution"]:
            tech_str = ", ".join(f"{t}({c})" for t, c in
                                 sorted(stats["technique_distribution"].items(), key=lambda x: -x[1]))
            print(f"  [{ds_name}] 技术分布: {tech_str}")
        for f in stats["files_created"]:
            print(f"    → {Path(f['file']).name} (Tier {f['tier']}, {f['count']} seeds)")

        all_stats["total_files"] += len(stats["files_created"])
        all_stats["total_seeds"] += stats["downloaded_seeds"]

    # 保存 manifest
    manifest_path = output_base / "_manifest.yaml"
    all_stats["end_time"] = datetime.now().isoformat()
    output_base.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        yaml.dump(all_stats, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

    print(f"\n  {'='*56}")
    print(f"  下载完成: {all_stats['total_files']} 文件, {all_stats['total_seeds']} seeds")
    print(f"  Manifest: {manifest_path}")
    print(f"  {'='*56}")

    return all_stats


def list_local_academic_payloads(
    output_base: Path | None = None,
) -> List[Dict[str, Any]]:
    """
    列出本地已下载的学术载荷

    Returns:
        载荷信息列表
    """
    if output_base is None:
        output_base = ACADEMIC_DATA_DIR

    if not output_base.exists():
        return []

    results = []
    for yaml_file in sorted(output_base.rglob("*.yaml")):
        if yaml_file.name.startswith("_"):
            continue
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            # technique/tier 不在顶层（SeedDataset extra="forbid"），
            # 从 description 或首个 seed 的 metadata 中提取。
            seeds_list = data.get("seeds", [])
            first_meta = seeds_list[0].get("metadata", {}) if seeds_list else {}
            results.append({
                "file": str(yaml_file),
                "source": data.get("source", "unknown"),
                "technique": first_meta.get("technique", "unknown"),
                "tier": first_meta.get("academic_tier", "unknown"),
                "seed_count": len(seeds_list),
            })
        except Exception as e:
            logger.warning(f"Failed to read {yaml_file}: {e}")

    return results


def get_academic_data_dir() -> Path:
    """获取学术数据目录路径"""
    return ACADEMIC_DATA_DIR
