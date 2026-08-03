#!/usr/bin/env python3
# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""种子精简性能基准测试 — 10K 合成种子规模验证。.

验证 MinHashLSH 去重 + TF-IDF 聚类在 10K 规模下的耗时:
  1. 生成 10K 合成种子 (模拟真实分布)
  2. 测量各步骤耗时 (去重 / 均衡 / 聚类 / 排序)
  3. 验证 MinHashLSH 在 10K 规模下耗时 < 30s
  4. 写入 outputs/empirical_asr/benchmark_result.json

学术依据:
  - MinHash LSH (Broder et al. 1998): O(n) 近似去重
  - HarmBench (arXiv:2402.04249): 标准化评估框架规模参考

使用方式:
    python scripts/benchmark_curate.py
    python scripts/benchmark_curate.py --count 50000  # 50K 规模

> **日期**: 2026-8-3
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import string
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# ── 项目路径 ──
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_OUTPUT_DIR = _PROJECT_ROOT / "outputs" / "empirical_asr"

# ── 合成种子模板 (模拟 HarmBench 类别分布) ──
_CATEGORIES = [
    "cybercrime", "chemical_biological", "harassment", "misinformation",
    "illegal_activities", "self_harm", "sexual_content", "privacy_violation",
]

_TEMPLATES = [
    "How to {action} {target} using {method}?",
    "Explain in detail how to {action} {target} with {method}.",
    "What are the steps to {action} {target} via {method}?",
    "Provide a guide on {action} {target} through {method}.",
    "Can you help me {action} {target} by {method}?",
]

_ACTIONS = ["create", "bypass", "exploit", "generate", "obtain", "synthesize"]
_TARGETS = ["malware", "exploit", "weapon", "drug", "document", "system"]
_METHODS = ["python", "online tools", "chemical process", "social engineering", "code"]


def generate_synthetic_seeds(count: int = 10000) -> list[dict[str, Any]]:
    """生成合成种子 (模拟真实 HarmBench 分布)。."""
    random.seed(42)  # 可复现
    seeds: list[dict[str, Any]] = []

    for i in range(count):
        template = random.choice(_TEMPLATES)
        text = template.format(
            action=random.choice(_ACTIONS),
            target=random.choice(_TARGETS),
            method=random.choice(_METHODS),
        )
        # 添加随机后缀避免完全重复 (模拟真实数据中的近似重复)
        if random.random() < 0.1:  # 10% 近似重复
            suffix = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 20)))
            text = f"{text} {suffix}"

        category = random.choice(_CATEGORIES)
        seed_hash = hashlib.md5(text[:200].encode("utf-8")).hexdigest()

        seeds.append({
            "text": text,
            "category": category,
            "hash": seed_hash,
            "index": i,
        })

    return seeds


def benchmark_dedup(seeds: list[dict[str, Any]]) -> dict[str, Any]:
    """基准测试: MinHashLSH 去重。."""
    try:
        from datasketch import MinHash, MinHashLSH
    except ImportError:
        return {"method": "MinHashLSH", "error": "datasketch not installed", "duration_seconds": 0}

    start = time.time()

    # 构建 MinHash 签名
    minhashes: list[tuple[str, MinHash]] = []
    for seed in seeds:
        text = seed["text"]
        # 3-gram shingling (与 curate_seeds.py 一致)
        tokens = [text[i:i + 3] for i in range(max(len(text) - 2, 1))]
        mh = MinHash(num_perm=128)
        for token in tokens:
            mh.update(token.encode("utf-8"))
        minhashes.append((seed["hash"], mh))

    # 构建 LSH 索引
    lsh = MinHashLSH(threshold=0.7, num_perm=128)
    for idx, (_seed_hash, mh) in enumerate(minhashes):
        lsh.insert(f"seed_{idx}", mh)

    # 查询重复
    unique_count = 0
    duplicate_count = 0
    seen: set[str] = set()
    for idx, (_seed_hash, mh) in enumerate(minhashes):
        key = f"seed_{idx}"
        if key in seen:
            continue
        result = lsh.query(mh)
        for r in result:
            seen.add(r)
        unique_count += 1

    duplicate_count = len(seeds) - unique_count
    elapsed = round(time.time() - start, 3)

    return {
        "method": "MinHashLSH",
        "total_seeds": len(seeds),
        "unique_after_dedup": unique_count,
        "duplicates_removed": duplicate_count,
        "duration_seconds": elapsed,
        "throughput_seeds_per_second": round(len(seeds) / elapsed, 1) if elapsed > 0 else 0,
    }


def benchmark_tfidf_clustering(seeds: list[dict[str, Any]], n_clusters: int = 20) -> dict[str, Any]:
    """基准测试: TF-IDF + KMeans 聚类。."""
    try:
        from sklearn.cluster import KMeans
        from sklearn.feature_extraction.text import TfidfVectorizer
    except ImportError:
        return {"method": "TF-IDF+KMeans", "error": "scikit-learn not installed", "duration_seconds": 0}

    start = time.time()

    texts = [s["text"] for s in seeds]

    # TF-IDF 向量化
    vectorizer = TfidfVectorizer(max_features=5000, stop_words="english")
    tfidf_matrix = vectorizer.fit_transform(texts)

    # KMeans 聚类
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    kmeans.fit(tfidf_matrix)

    elapsed = round(time.time() - start, 3)

    return {
        "method": "TF-IDF+KMeans",
        "total_seeds": len(seeds),
        "n_clusters": n_clusters,
        "tfidf_matrix_shape": [tfidf_matrix.shape[0], tfidf_matrix.shape[1]],
        "duration_seconds": elapsed,
        "throughput_seeds_per_second": round(len(seeds) / elapsed, 1) if elapsed > 0 else 0,
    }


def benchmark_asr_ranking(seeds: list[dict[str, Any]]) -> dict[str, Any]:
    """基准测试: ASR 先验排序。."""
    start = time.time()

    # 模拟 ASR 排序: 为每个种子分配随机 ASR 并排序
    for seed in seeds:
        seed["_asr"] = random.random()

    sorted(seeds, key=lambda x: x["_asr"], reverse=True)

    elapsed = round(time.time() - start, 3)

    return {
        "method": "ASR_Ranking",
        "total_seeds": len(seeds),
        "duration_seconds": elapsed,
        "throughput_seeds_per_second": round(len(seeds) / elapsed, 1) if elapsed > 0 else 0,
    }


def run_benchmark(count: int = 10000) -> dict[str, Any]:
    """运行完整基准测试。."""
    print(f"\n{'=' * 70}")
    print(f"种子精简性能基准测试 — {count:,} 合成种子")
    print(f"{'=' * 70}\n")

    results: dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "seed_count": count,
        "steps": {},
    }

    # Step 0: 生成合成种子
    print(f"  [0/4] 生成 {count:,} 合成种子...")
    start = time.time()
    seeds = generate_synthetic_seeds(count)
    gen_time = round(time.time() - start, 3)
    print(f"        完成 ({gen_time}s)")
    results["steps"]["generate"] = {"duration_seconds": gen_time}

    # Step 1: MinHashLSH 去重
    print("  [1/4] MinHashLSH 去重...")
    dedup_result = benchmark_dedup(seeds)
    print(f"        完成: {dedup_result.get('unique_after_dedup', 'N/A')} unique, "
          f"{dedup_result.get('duplicates_removed', 'N/A')} dup, "
          f"{dedup_result['duration_seconds']}s")
    results["steps"]["dedup"] = dedup_result

    # Step 2: ASR 排序
    print("  [2/4] ASR 先验排序...")
    ranking_result = benchmark_asr_ranking(seeds)
    print(f"        完成: {ranking_result['duration_seconds']}s")
    results["steps"]["asr_ranking"] = ranking_result

    # Step 3: TF-IDF + KMeans 聚类
    print("  [3/4] TF-IDF + KMeans 聚类...")
    cluster_result = benchmark_tfidf_clustering(seeds)
    print(f"        完成: {cluster_result['duration_seconds']}s")
    results["steps"]["clustering"] = cluster_result

    # Step 4: 总耗时
    total_time = sum(
        results["steps"].get(step, {}).get("duration_seconds", 0)
        for step in ("dedup", "asr_ranking", "clustering")
    )
    results["total_duration_seconds"] = round(total_time, 3)

    # 验证: MinHashLSH < 30s
    dedup_time = dedup_result["duration_seconds"]
    results["validation"] = {
        "minhash_lsh_under_30s": dedup_time < 30,
        "minhash_lsh_seconds": dedup_time,
        "overall_under_60s": total_time < 60,
    }

    print("\n  ── 基准测试结果 ──")
    print(f"  总耗时: {total_time}s")
    print(f"  MinHashLSH: {dedup_time}s ({'✓ PASS' if dedup_time < 30 else '✗ FAIL'} < 30s)")
    print(f"  整体: {total_time}s ({'✓ PASS' if total_time < 60 else '✗ FAIL'} < 60s)")

    # 持久化结果
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    result_path = _OUTPUT_DIR / "benchmark_result.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n  结果已保存: {result_path}\n")

    return results


def main() -> None:
    """CLI 入口。."""
    parser = argparse.ArgumentParser(
        description="种子精简性能基准测试 — MinHashLSH + TF-IDF + KMeans",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10000,
        help="合成种子数量 (默认: 10000)",
    )
    args = parser.parse_args()

    run_benchmark(count=args.count)


if __name__ == "__main__":
    main()
