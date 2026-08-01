#!/usr/bin/env python3
# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ASR 先验数据月度自动同步脚本 (消除2)。.

从 JailbreakBench / HarmBench 公开数据源同步最新 ASR 数据到
``data/asr_priors.yaml``, 并自动检测 ``patched`` 状态。

数据来源 (R-007 规则, 优先 arXiv 学术文献):
1. JailbreakBench (arXiv:2402.01135) — 标准化越狱基准排行榜
   GitHub: https://github.com/JailbreakBench/jailbreakbench
2. HarmBench (arXiv:2402.04249) — 自动化红队评估框架
   GitHub: https://github.com/centerforaisafety/harmbench

使用方式:
    python scripts/sync_asr_priors.py              # 同步外部基准
    python scripts/sync_asr_priors.py --bayesian    # 运行后贝叶斯更新
    python scripts/sync_asr_priors.py --auto        # 自动模式 (同步 + 贝叶斯)

学术依据:
- JailbreakBench 版本化数据接口设计 (arXiv:2402.01135)
- Thompson Sampling: 先验→后验贝叶斯更新 (MAB 标准方法)
- HarmBench 持续评估框架 (arXiv:2402.04249)

> **日期**: 2026-8-1
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

# 项目根目录
_PROJECT_ROOT = Path(__file__).parent.parent
_YAML_PATH = _PROJECT_ROOT / "data" / "config" / "asr_priors.yaml"

logger = logging.getLogger(__name__)


def sync_external_benchmarks() -> dict[str, Any]:
    """从 JailbreakBench / HarmBench 同步 ASR 数据。.

    尝试从以下来源获取数据:
    1. JailbreakBench GitHub 仓库的 leaderboard CSV
    2. HarmBench GitHub 仓库的 evaluation results

    Returns:
        更新后的 priors 列表 (与 YAML 格式一致)
    """
    updated_priors: dict[str, dict[str, Any]] = {}

    # ── JailbreakBench 同步 ──
    try:
        updated = _sync_jailbreakbench(updated_priors)
        if updated:
            logger.info(f"JailbreakBench: {len(updated)} techniques updated")
    except Exception as e:
        logger.warning(f"JailbreakBench sync failed: {e}")

    # ── HarmBench 同步 ──
    try:
        updated = _sync_harmbench(updated_priors)
        if updated:
            logger.info(f"HarmBench: {len(updated)} techniques updated")
    except Exception as e:
        logger.warning(f"HarmBench sync failed: {e}")

    return updated_priors


def _sync_jailbreakbench(existing: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """从 JailbreakBench 同步 ASR 数据。.

    JailbreakBench 提供 CSV 格式的排行榜数据:
    https://github.com/JailbreakBench/jailbreakbench/blob/main/data/leaderboard.csv

    列: technique, model, attack_success_rate, date
    """
    try:
        import csv
        import io
        import urllib.request

        url = "https://raw.githubusercontent.com/JailbreakBench/jailbreakbench/main/data/leaderboard.csv"

        logger.info(f"Fetching JailbreakBench leaderboard from {url}...")
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8")

        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            technique = row.get("technique", "").lower().strip()
            if not technique:
                continue

            model = row.get("model", "").lower()
            asr_str = row.get("attack_success_rate", row.get("asr", ""))
            try:
                asr = float(asr_str)
                if asr > 1.0:
                    asr = asr / 100.0
            except (ValueError, TypeError):
                continue

            if technique not in existing:
                existing[technique] = {}

            # 按模型更新 ASR
            if "gpt-4o" in model or "gpt4o" in model:
                existing[technique]["gpt_4o"] = asr
            elif "gpt-4" in model or "gpt4" in model:
                existing[technique]["gpt_4"] = asr
            elif "gpt-3.5" in model or "gpt-35" in model:
                existing[technique]["gpt_35"] = asr
            elif "claude" in model and "3.5" in model:
                existing[technique]["claude_3_5"] = asr
            elif "llama" in model and "3" in model:
                existing[technique]["llama_3_1"] = asr

            existing[technique]["source"] = "jailbreakbench"
            existing[technique]["last_updated"] = row.get("date", "2025-06")

    except ImportError:
        logger.warning("urllib not available, skipping JailbreakBench sync")
    except Exception as e:
        logger.warning(f"JailbreakBench sync error: {e}")

    return existing


def _sync_harmbench(existing: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """从 HarmBench 同步 ASR 数据。.

    HarmBench 提供评估结果:
    https://github.com/centerforaisafety/harmbench/blob/main/results/summary.json
    """
    try:
        import urllib.request

        url = "https://raw.githubusercontent.com/centerforaisafety/harmbench/main/results/summary.json"

        logger.info(f"Fetching HarmBench results from {url}...")
        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))

        for technique, models in data.items():
            technique_lower = technique.lower().strip()
            if technique_lower not in existing:
                existing[technique_lower] = {}

            for model, asr in models.items():
                model_lower = model.lower()
                try:
                    asr_val = float(asr)
                    if asr_val > 1.0:
                        asr_val = asr_val / 100.0
                except (ValueError, TypeError):
                    continue

                if "gpt-4o" in model_lower:
                    existing[technique_lower]["gpt_4o"] = asr_val
                elif "gpt-4" in model_lower:
                    existing[technique_lower]["gpt_4"] = asr_val
                elif "gpt-3.5" in model_lower:
                    existing[technique_lower]["gpt_35"] = asr_val
                elif "claude" in model_lower:
                    existing[technique_lower]["claude_3_5"] = asr_val
                elif "llama" in model_lower:
                    existing[technique_lower]["llama_3_1"] = asr_val

            existing[technique_lower].setdefault("source", "harmbench")
            existing[technique_lower].setdefault("last_updated", "2025-06")

    except ImportError:
        logger.warning("urllib not available, skipping HarmBench sync")
    except Exception as e:
        logger.warning(f"HarmBench sync error: {e}")

    return existing


def auto_detect_patched(updated: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """自动检测 patched 状态。.

    规则:
    - 如果历史 ASR > 0.30 且当前 ASR < 0.05 → patched = True
    - 如果历史 ASR > 0.30 且当前 ASR < 历史 * 0.3 → patched = True
    - 否则保持 patched = False
    """
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed, skipping patched detection")
        return updated

    # 加载当前 YAML 数据作为历史基准
    if not _YAML_PATH.exists():
        return updated

    with open(_YAML_PATH, encoding="utf-8") as f:
        yaml_data = yaml.safe_load(f)

    historical = {p["technique"]: p for p in yaml_data.get("priors", [])}

    for tech, new_data in updated.items():
        hist = historical.get(tech, {})
        hist_asr = float(hist.get("gpt_4o", 0))
        new_asr = float(new_data.get("gpt_4o", hist_asr))

        if hist_asr > 0.30 and new_asr < 0.05 or hist_asr > 0.30 and new_asr < hist_asr * 0.3:
            new_data["patched"] = True
            logger.info(f"Auto-detected patched: {tech} (ASR {hist_asr:.0%} → {new_asr:.0%})")
        else:
            new_data.setdefault("patched", False)

    return updated


def update_yaml(updated: dict[str, dict[str, Any]]) -> bool:
    """将更新后的 ASR 数据写入 ``data/asr_priors.yaml``。."""
    try:
        import yaml
    except ImportError:
        logger.error("PyYAML not installed, cannot update YAML")
        return False

    if not _YAML_PATH.exists():
        logger.error(f"YAML file not found: {_YAML_PATH}")
        return False

    with open(_YAML_PATH, encoding="utf-8") as f:
        yaml_data = yaml.safe_load(f)

    # 合并更新到现有 priors
    priors = yaml_data.get("priors", [])
    tech_map = {p["technique"]: p for p in priors}

    for tech, new_data in updated.items():
        if tech in tech_map:
            # 更新现有条目
            for k, v in new_data.items():
                tech_map[tech][k] = v
        else:
            # 新增条目
            new_entry = {"technique": tech, **new_data}
            priors.append(new_entry)
            tech_map[tech] = new_entry

    yaml_data["priors"] = priors

    with open(_YAML_PATH, "w", encoding="utf-8") as f:
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    logger.info(f"YAML updated: {_YAML_PATH} ({len(priors)} techniques)")
    return True


def bayesian_update_from_central_memory() -> dict[str, Any]:
    """从 CentralMemory 读取经验 ASR, 贝叶斯更新 YAML 先验。.

    贝叶斯更新公式:
        posterior = (w_prior * academic_asr + w_empirical * empirical_asr) / (w_prior + w_empirical)

    其中 w_empirical 随运行次数增长。

    学术依据:
    - Thompson Sampling (多臂老虎机标准方法)
    - MAB 综述 (arXiv:1907.05271)
    """
    try:
        from pipeline.asr.prior_registry import get_initial_q_value
    except ImportError:
        logger.error("Cannot import asr_prior_registry, is the project in PYTHONPATH?")
        return {}

    try:
        from pyrit.memory import CentralMemory

        CentralMemory.get_memory_instance()
    except Exception as e:
        logger.warning(f"Cannot access CentralMemory: {e}")
        return {}

    # 查询经验 ASR
    try:
        from pipeline.asr.optimizer import query_historical_asr_by_technique

        empirical_asr = query_historical_asr_by_technique()
    except Exception as e:
        logger.warning(f"Cannot query historical ASR: {e}")
        return {}

    if not empirical_asr:
        logger.info("No empirical ASR data available for Bayesian update")
        return {}

    updated: dict[str, dict[str, Any]] = {}

    for tech_name, stats in empirical_asr.items():
        if stats.total_decided == 0:
            continue

        empirical = stats.successes / stats.total_decided

        # 学术先验
        academic = get_initial_q_value(tech_name, "gpt-4o", "unknown", "")

        # 贝叶斯权重: 经验数据越多, 权重越大
        w_prior = 1.0
        w_empirical = min(stats.total_decided / 10.0, 3.0)  # 最多 3x 先验权重

        posterior = (w_prior * academic + w_empirical * empirical) / (w_prior + w_empirical)
        posterior = max(0.0, min(posterior, 0.99))

        if abs(posterior - academic) > 0.01:
            updated[tech_name] = {
                "gpt_4o": round(posterior, 4),
                "source": "bayesian_updated",
                "last_updated": "2026-08",
            }
            logger.info(
                f"Bayesian update: {tech_name} "
                f"academic={academic:.2f} → posterior={posterior:.2f} "
                f"(empirical={empirical:.2f}, n={stats.total_decided})"
            )

    return updated


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ASR 先验数据月度自动同步 + 贝叶斯更新 (消除2)",
    )
    parser.add_argument(
        "--bayesian",
        action="store_true",
        help="从 CentralMemory 经验数据贝叶斯更新 YAML 先验",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="自动模式: 同步外部基准 + 贝叶斯更新 + patched 检测",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.auto or (not args.bayesian):
        logger.info("=== 同步外部基准数据 ===")
        updated = sync_external_benchmarks()
        if updated:
            updated = auto_detect_patched(updated)
            if update_yaml(updated):
                logger.info("外部基准同步完成")
            else:
                logger.error("YAML 更新失败")
        else:
            logger.info("无外部基准更新")

    if args.bayesian or args.auto:
        logger.info("=== 贝叶斯更新 ===")
        bayesian_updated = bayesian_update_from_central_memory()
        if bayesian_updated:
            if update_yaml(bayesian_updated):
                logger.info(f"贝叶斯更新完成: {len(bayesian_updated)} 个技术")
            else:
                logger.error("贝叶斯更新 YAML 写入失败")
        else:
            logger.info("无贝叶斯更新 (经验数据不足或无变化)")

    logger.info("=== 同步完成 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
