# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""性能基准测试脚本 — 记录关键模块延迟和吞吐量。

使用方式:
  python -m benchmark.run_benchmarks
  python -m benchmark.run_benchmarks --output benchmark_results.json

学术依据:
  - HarmBench (arXiv:2402.04249): 标准化评估需要可复现的性能基准
  - JailbreakBench (arXiv:2402.01135): 评估工具链性能透明度要求

> **日期**: 2026-8-2
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

from pipeline.analysis.evidence_collector import EvidenceCollector
from pipeline.asr.optimizer import (
    merge_empirical_with_priors,
    query_historical_asr_by_category,
    sort_datasets_by_asr,
)
from pipeline.converters.factory import build_technique_converter_map


# ============================================================
# 基准测试函数
# ============================================================


def _benchmark_asr_query(n_iterations: int = 100) -> dict[str, float]:
    """ASR 查询延迟基准。"""
    start = time.perf_counter()
    for _ in range(n_iterations):
        query_historical_asr_by_category()
    elapsed = time.perf_counter() - start
    return {
        "total_seconds": elapsed,
        "per_call_ms": (elapsed / n_iterations) * 1000,
        "iterations": n_iterations,
    }


def _benchmark_sort_datasets(n_iterations: int = 100) -> dict[str, float]:
    """数据集排序延迟基准。"""
    datasets = ["harmbench", "jbb_behaviors", "strong_reject", "airt_jailbreak"]
    start = time.perf_counter()
    for _ in range(n_iterations):
        sort_datasets_by_asr(datasets, asr_by_category={})
    elapsed = time.perf_counter() - start
    return {
        "total_seconds": elapsed,
        "per_call_ms": (elapsed / n_iterations) * 1000,
        "iterations": n_iterations,
    }


def _benchmark_evidence_collection(n_attacks: int = 100) -> dict[str, float]:
    """证据收集延迟基准。"""
    from pyrit.models import AttackOutcome

    # 模拟 n_attacks 个结果
    results: dict[str, list] = {}
    for i in range(n_attacks // 10):
        tech_name = f"tech_{i}"
        ars = []
        for j in range(10):
            ar = MagicMock()
            ar.outcome = AttackOutcome.SUCCESS if j % 3 == 0 else AttackOutcome.FAILURE
            ar.last_request = MagicMock(request_pieces=[])
            ar.last_response = MagicMock(request_pieces=[])
            ar.get_attack_strategy_identifier = MagicMock(
                return_value=MagicMock(class_name=tech_name)
            )
            ars.append(ar)
        results[tech_name] = ars

    asr_data = {f"tech_{i}": 33.3 for i in range(n_attacks // 10)}

    collector = EvidenceCollector()
    start = time.perf_counter()
    collector.collect(
        attack_results=results,
        asr_per_technique=asr_data,
        overall_asr=33.3,
    )
    elapsed = time.perf_counter() - start

    return {
        "total_seconds": elapsed,
        "n_attacks": n_attacks,
        "per_attack_ms": (elapsed / n_attacks) * 1000,
    }


def _benchmark_converter_routing(n_techniques: int = 50) -> dict[str, float]:
    """Converter 路由构建延迟基准。"""
    from pipeline.asr.optimizer import compute_stats

    techniques = [f"tech_{i}" for i in range(n_techniques)]

    # 用真实 AttackStats 对象传入
    asr_by_technique = {
        f"tech_{i}": compute_stats(successes=i % 3, failures=10 - i % 3, undetermined=0, errors=0)
        for i in range(n_techniques)
    }

    start = time.perf_counter()
    build_technique_converter_map(
        converter_names=["base64", "rot13", "morse", "binary", "leetspeak"],
        technique_names=techniques,
        asr_by_technique=asr_by_technique,
    )
    elapsed = time.perf_counter() - start

    return {
        "total_seconds": elapsed,
        "n_techniques": n_techniques,
        "per_technique_ms": (elapsed / n_techniques) * 1000,
    }


def _benchmark_merge_empirical(n_techniques: int = 100) -> dict[str, float]:
    """经验 ASR 合并延迟基准。"""
    academic = {f"tech_{i}": 0.3 for i in range(n_techniques)}
    empirical = {f"tech_{i}": 0.5 for i in range(n_techniques)}

    start = time.perf_counter()
    merge_empirical_with_priors(academic, empirical)
    elapsed = time.perf_counter() - start

    return {
        "total_seconds": elapsed,
        "n_techniques": n_techniques,
        "per_technique_ms": (elapsed / n_techniques) * 1000,
    }


# ============================================================
# 主入口
# ============================================================


def run_all_benchmarks(output_path: str | None = None) -> dict:
    """运行全部基准测试。"""
    print("=" * 70)
    print("PyRIT-Pipeline 性能基准测试")
    print(f"时间: {datetime.now().isoformat()}")
    print("=" * 70)

    results: dict = {
        "timestamp": datetime.now().isoformat(),
        "python_version": f"{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}",
        "benchmarks": {},
    }

    benchmarks = [
        ("asr_query", _benchmark_asr_query, {}),
        ("sort_datasets", _benchmark_sort_datasets, {}),
        ("evidence_collection_100", _benchmark_evidence_collection, {"n_attacks": 100}),
        ("converter_routing_50", _benchmark_converter_routing, {"n_techniques": 50}),
        ("merge_empirical_100", _benchmark_merge_empirical, {"n_techniques": 100}),
    ]

    for name, func, kwargs in benchmarks:
        print(f"\n  [{name}] 运行中...")
        try:
            result = func(**kwargs)
            results["benchmarks"][name] = result
            print(f"  [{name}] {result}")
        except Exception as e:
            results["benchmarks"][name] = {"error": str(e)[:200]}
            print(f"  [{name}] SKIPPED: {e}")

    print("\n" + "=" * 70)
    print("基准测试完成")
    print("=" * 70)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"  结果保存到: {path}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyRIT-Pipeline 性能基准测试")
    parser.add_argument("--output", "-o", default=None, help="结果输出 JSON 路径")
    args = parser.parse_args()
    run_all_benchmarks(output_path=args.output)
