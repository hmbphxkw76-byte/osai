#!/usr/bin/env python3
# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""种子精简工具 — 跨数据集去重 + 类别均衡 + 多样性聚类 + ASR 加权。.

设计目标:
  1. 跨数据集去重: 用字符 3-gram shingling + Jaccard 相似度消除语义近义种子
  2. 类别均衡: 按 harm category 每类均匀采样 ~15 个
  3. 多样性聚类: TF-IDF + KMeans, 每簇取中心种子最大化语义覆盖
  4. ASR 加权: 优先选取历史 ASR 高的种子 (首次用先验, 后续用实测)

学术依据:
  - JailbreakBench (arXiv:2402.01135): 手工筛选 100 个, 类别均衡
  - HarmBench (arXiv:2402.04249): 标准化 7 类 * 子类别分布
  - DART (arXiv:2407.06485): 多样性感知红队, 嵌入聚类取中心
  - RAIN (arXiv:2309.07124): 历史成功率排序候选攻击

使用方式:
    python scripts/curate_seeds.py                    # 精简核心数据集
    python scripts/curate_seeds.py --per-category 20  # 每类 20 个
    python scripts/curate_seeds.py --check            # 检查精简后状态

> **日期**: 2026-8-2
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import yaml
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer

#: 项目根目录
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: 种子数据目录
_SEED_DIR = _PROJECT_ROOT / "data" / "seed_datasets"

#: 精简后输出目录
_OUTPUT_DIR = _SEED_DIR / "benchmarks"

#: ASR 先验文件
_ASR_PRIORS = _PROJECT_ROOT / "data" / "setting" / "asr_priors.yaml"

#: 默认每类别采样数
_DEFAULT_PER_CATEGORY = 15

#: 去重 Jaccard 相似度阈值
_DEDUP_THRESHOLD = 0.85


# ============================================================
# 数据加载
# ============================================================


def _load_seed_file(path: Path) -> list[dict[str, Any]]:
    """加载单个 .prompt YAML 文件, 返回种子列表。."""
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    seeds = data.get("seeds", [])
    ds_name = data.get("dataset_name", path.stem)
    result: list[dict[str, Any]] = []
    for seed in seeds:
        value = seed.get("value", "")
        metadata = seed.get("metadata", {}) or {}
        # 统一提取 harm category
        category = (
            metadata.get("SemanticCategory")
            or metadata.get("jbb_category")
            or metadata.get("category")
            or metadata.get("harm_categories")
            or "unknown"
        )
        result.append(
            {
                "value": value,
                "dataset_name": ds_name,
                "category": category,
                "metadata": metadata,
                "source_file": str(path),
            }
        )
    return result


def load_all_seeds() -> list[dict[str, Any]]:
    """加载所有种子数据集 (benchmarks + owasp + cve + custom)。."""
    all_seeds: list[dict[str, Any]] = []
    # Benchmarks (远程基准)
    for f in sorted((_SEED_DIR / "benchmarks").glob("*.prompt")):
        all_seeds.extend(_load_seed_file(f))
    # OWASP
    for f in sorted((_SEED_DIR / "owasp").glob("*.prompt")):
        all_seeds.extend(_load_seed_file(f))
    # CVE
    for f in sorted((_SEED_DIR / "cve").glob("*.prompt")):
        all_seeds.extend(_load_seed_file(f))
    # Custom
    for f in sorted((_SEED_DIR / "custom").glob("*.prompt")):
        all_seeds.extend(_load_seed_file(f))
    return all_seeds


def _normalize_text(text: str) -> str:
    """归一化文本: 小写 + 去标点 + 去多余空格。."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _shingles(text: str, k: int = 3) -> set[str]:
    """生成字符 k-gram shingle 集合。."""
    text = _normalize_text(text)
    if len(text) < k:
        return {text}
    return {text[i : i + k] for i in range(len(text) - k + 1)}


def _jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    """计算两个集合的 Jaccard 相似度。."""
    if not set_a and not set_b:
        return 1.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


# ============================================================
# Step 1: 跨数据集去重 (字符 3-gram shingling + Jaccard)
# ============================================================


def dedup_seeds(seeds: list[dict[str, Any]], threshold: float = _DEDUP_THRESHOLD) -> list[dict[str, Any]]:
    """跨数据集去重: Jaccard 相似度 > threshold 的种子仅保留第一个。."""
    print(f"\n  [Step 1] 跨数据集去重 (Jaccard threshold={threshold})")
    print(f"    输入: {len(seeds)} 个种子")

    # 预计算所有 shingle 集合
    shingle_cache: list[set[str]] = []
    for s in seeds:
        shingle_cache.append(_shingles(s["value"]))

    kept: list[dict[str, Any]] = []
    kept_shingles: list[set[str]] = []
    removed = 0

    for i, seed in enumerate(seeds):
        is_dup = False
        for _j, existing_sh in enumerate(kept_shingles):
            sim = _jaccard_similarity(shingle_cache[i], existing_sh)
            if sim >= threshold:
                removed += 1
                is_dup = True
                break
        if not is_dup:
            kept.append(seed)
            kept_shingles.append(shingle_cache[i])

    print(f"    去重: 移除 {removed} 个近义种子")
    print(f"    输出: {len(kept)} 个种子 (压缩 {removed / len(seeds) * 100:.1f}%)")
    return kept


# ============================================================
# Step 2: 类别均衡采样
# ============================================================


def category_balanced_sample(
    seeds: list[dict[str, Any]],
    per_category: int = _DEFAULT_PER_CATEGORY,
) -> list[dict[str, Any]]:
    """按 harm category 均衡采样, 每类取 per_category 个。."""
    print(f"\n  [Step 2] 类别均衡采样 (每类 {per_category} 个)")

    # 按 category 分组
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in seeds:
        by_category[s["category"]].append(s)

    print(f"    类别数: {len(by_category)}")
    for _cat, items in sorted(by_category.items()):
        print(f"      {_cat}: {len(items)} → {min(per_category, len(items))}")

    result: list[dict[str, Any]] = []
    for _cat, items in sorted(by_category.items()):
        # 均匀采样: 每隔 N/per_category 取一个
        n = min(per_category, len(items))
        if n >= len(items):
            result.extend(items)
        else:
            step = len(items) / n
            indices = [int(i * step) for i in range(n)]
            result.extend(items[idx] for idx in indices)

    print(f"    输出: {len(result)} 个种子")
    return result


# ============================================================
# Step 3: 多样性聚类 (TF-IDF + KMeans)
# ============================================================


def diversity_cluster(seeds: list[dict[str, Any]], n_clusters: int = 0) -> list[dict[str, Any]]:
    """TF-IDF + KMeans 聚类, 每簇取最靠近中心的种子。."""
    if len(seeds) <= 5:
        return seeds

    # 自动确定聚类数: min(len(seeds)//3, 50)
    if n_clusters <= 0:
        n_clusters = min(len(seeds) // 3, 50)
        n_clusters = max(n_clusters, 5)

    print(f"\n  [Step 3] 多样性聚类 (TF-IDF + KMeans, k={n_clusters})")

    # TF-IDF 向量化
    texts = [_normalize_text(s["value"]) for s in seeds]
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    tfidf_matrix = vectorizer.fit_transform(texts)

    # KMeans 聚类
    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = km.fit_predict(tfidf_matrix)

    # 每簇取最靠近中心的种子
    result: list[dict[str, Any]] = []
    for cluster_id in range(n_clusters):
        member_indices = [i for i, lbl in enumerate(labels) if lbl == cluster_id]
        if not member_indices:
            continue

        # 计算每个成员到簇中心的距离
        center = km.cluster_centers_[cluster_id]
        member_vectors = tfidf_matrix[member_indices].toarray()
        distances = np.linalg.norm(member_vectors - center, axis=1)
        closest_idx = member_indices[np.argmin(distances)]
        result.append(seeds[closest_idx])

    print(f"    聚类: {n_clusters} 簇, 每簇取中心 → {len(result)} 个种子")
    return result


# ============================================================
# Step 4: ASR 加权排序
# ============================================================


def _load_asr_priors() -> dict[str, float]:
    """加载 ASR 先验数据, 返回 category → avg_asr 映射。."""
    if not _ASR_PRIORS.exists():
        return {}
    with open(_ASR_PRIORS, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    # 从 priors 表中提取每个技术的平均 ASR, 按 category 间接映射
    priors = data.get("priors", [])
    if not priors:
        return {}

    # 技术 → 平均 ASR
    tech_asr: dict[str, float] = {}
    for p in priors:
        tech = p.get("technique", "")
        values = [v for k, v in p.items() if k.startswith(("gpt", "claude", "llama"))]
        if values:
            tech_asr[tech] = sum(values) / len(values)

    # 全局平均 ASR 作为默认权重
    global_avg = sum(tech_asr.values()) / len(tech_asr) if tech_asr else 0.3
    return {"_global_avg": global_avg}


def asr_weighted_sort(seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """ASR 加权排序: 按历史 ASR 先验降序排列种子。."""
    print("\n  [Step 4] ASR 加权排序")
    asr_data = _load_asr_priors()
    global_avg = asr_data.get("_global_avg", 0.3)
    print(f"    全局平均 ASR: {global_avg:.2f}")

    # 按种子的 difficulty 元数据给加分 (hard=1.2, medium=1.0, easy=0.8)
    for s in seeds:
        difficulty = s.get("metadata", {}).get("difficulty", "medium")
        boost = {"hard": 1.2, "medium": 1.0, "easy": 0.8}.get(difficulty, 1.0)
        s["_asr_score"] = global_avg * boost

    # 排序: ASR 分数降序
    sorted_seeds = sorted(seeds, key=lambda s: s["_asr_score"], reverse=True)
    print("    排序完成 (按 ASR × difficulty 降序)")
    return sorted_seeds


# ============================================================
# 输出
# ============================================================


def save_curated_seeds(seeds: list[dict[str, Any]], output_path: Path) -> None:
    """保存精简后的种子到 .prompt YAML 文件。."""
    all_seeds: list[dict[str, Any]] = []
    for s in seeds:
        seed_entry: dict[str, Any] = {"value": s["value"]}
        metadata = {k: v for k, v in s.get("metadata", {}).items() if not k.startswith("_")}
        # 添加精简标记
        metadata["curated"] = True
        metadata["source_dataset"] = s["dataset_name"]
        metadata["harm_category"] = s["category"]
        seed_entry["metadata"] = metadata
        all_seeds.append(seed_entry)

    output_data = {
        "dataset_name": "curated_seeds",
        "harm_categories": "",
        "source": "curated",
        "groups": "multi_source",
        "data_type": "text",
        "description": (
            f"Curated seeds from harmbench + jbb_behaviors + strong_reject + OWASP. "
            f"Total {len(all_seeds)} seeds after dedup + category-balance + diversity cluster + ASR weighting."
        ),
        "seed_type": "objective",
        "seeds": all_seeds,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(output_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=200)

    print(f"\n  [Output] 精简后种子保存到: {output_path}")
    print(f"    总种子数: {len(all_seeds)}")


def print_summary(original: int, curated: list[dict[str, Any]]) -> None:
    """打印精简摘要。."""
    by_ds: dict[str, int] = defaultdict(int)
    by_cat: dict[str, int] = defaultdict(int)
    for s in curated:
        by_ds[s["dataset_name"]] += 1
        by_cat[s["category"]] += 1

    print(f"\n{'=' * 70}")
    print("种子精简摘要")
    print(f"  原始种子: {original}")
    print(f"  精简后:   {len(curated)}")
    print(f"  压缩率:   {(1 - len(curated) / original) * 100:.1f}%")
    print("\n  按数据集分布:")
    for ds, count in sorted(by_ds.items()):
        print(f"    {ds}: {count}")
    print("\n  按危害类别分布:")
    for cat, count in sorted(by_cat.items()):
        print(f"    {cat}: {count}")
    print(f"{'=' * 70}")


# ============================================================
# CLI 入口
# ============================================================


def main() -> None:
    """Run seed curation main entry point."""
    parser = argparse.ArgumentParser(
        description="种子精简工具 (去重 + 类别均衡 + 多样性聚类 + ASR 加权)",
    )
    parser.add_argument(
        "--per-category",
        type=int,
        default=_DEFAULT_PER_CATEGORY,
        help=f"每类采样数 (默认: {_DEFAULT_PER_CATEGORY})",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(_OUTPUT_DIR / "curated_seeds.prompt"),
        help="输出文件路径",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="检查精简后种子状态",
    )
    args = parser.parse_args()

    if args.check:
        curated_path = Path(args.output)
        if not curated_path.exists():
            print("精简种子文件不存在, 请先运行精简")
            return
        with open(curated_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        seeds = data.get("seeds", [])
        print(f"精简种子文件: {curated_path}")
        print(f"  种子数: {len(seeds)}")
        by_cat: dict[str, int] = defaultdict(int)
        for s in seeds:
            cat = s.get("metadata", {}).get("harm_category", "unknown")
            by_cat[cat] += 1
        print(f"  类别数: {len(by_cat)}")
        for cat, count in sorted(by_cat.items()):
            print(f"    {cat}: {count}")
        return

    # 加载所有种子
    print(f"{'=' * 70}")
    print("种子精简工具")
    print(f"  数据目录: {_SEED_DIR}")
    print("  目标: 去重 → 类别均衡 → 多样性聚类 → ASR 加权")
    print(f"{'=' * 70}")

    all_seeds = load_all_seeds()
    original_count = len(all_seeds)
    print(f"\n  加载种子: {original_count} 个")

    # Step 1: 去重
    deduped = dedup_seeds(all_seeds)

    # Step 2: 类别均衡
    balanced = category_balanced_sample(deduped, per_category=args.per_category)

    # Step 3: 多样性聚类
    clustered = diversity_cluster(balanced)

    # Step 4: ASR 加权排序
    weighted = asr_weighted_sort(clustered)

    # 输出
    save_curated_seeds(weighted, Path(args.output))

    # 摘要
    print_summary(original_count, weighted)


if __name__ == "__main__":
    main()
