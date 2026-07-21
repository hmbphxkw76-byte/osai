# -*- coding: utf-8 -*-
"""
AI-300 Framework - ASR Updater (REV-12 / GAP-12)
动态 ASR 更新闭环：将实战结果反馈到载荷库的 ASR 基线

核心功能：
1. 从 FeedbackAnalyzer 报告中提取实战 ASR 数据
2. 使用贝叶斯平滑更新载荷 YAML 中的 asr_baseline 字段
3. 更新 last_tested 时间戳和 test_count 测试次数
4. 支持增量更新和批量更新

设计原则：
- 贝叶斯平滑：新 ASR = (实战成功数 + α) / (实战总数 + α + β)
  - α=1, β=1 (Beta分布先验)
  - 防止小样本偏差（1/1=100% 不会直接覆盖原有 0.5 的 ASR）
- 保留原始数据：更新前备份原 ASR 到 asr_history
- 幂等性：同一结果重复更新不会产生副作用

使用方式：
    updater = ASRUpdater(data_dir="data/owasp")
    updater.update_from_feedback(feedback_report, target_model="gpt-4o")

对齐文档：docs/architecture_review.md §5.2 GAP-12
预期收益：载荷库随实战自优化，长期 ASR 准确度提升 15%+
"""
from __future__ import annotations

import logging
import os
import shutil
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

# ── 贝叶斯平滑参数 ──
# Beta 分布先验参数：α=1, β=1 (均匀先验)
# 新 ASR = (success_count + α) / (total_count + α + β)
BAYESIAN_ALPHA = 1.0
BAYESIAN_BETA = 1.0

# 实战数据权重：与静态 ASR 的加权混合比例
# 当实战样本充足时（test_count >= MIN_SAMPLE_FOR_FULL_WEIGHT），完全使用实战 ASR
# 当实战样本不足时，按比例混合
MIN_SAMPLE_FOR_FULL_WEIGHT = 20
STATIC_WEIGHT_WHEN_LOW_SAMPLE = 0.5  # 样本不足时静态 ASR 权重


class ASRUpdater:
    """
    动态 ASR 更新器 (REV-12)

    将攻击实战结果反馈到载荷库，更新 ASR 基线数据。

    使用方式：
        updater = ASRUpdater(data_dir="data/owasp")
        updater.update_from_feedback(feedback_report, target_model="gpt-4o")

    或直接更新单个载荷：
        updater.update_single_payload(
            ref_path="owasp:llm:llm01:skeleton_key",
            target_model="gpt-4o",
            success_count=8,
            total_count=10,
        )
    """

    def __init__(
        self,
        data_dir: str = "data/owasp",
        backup_dir: str = "results/asr_backups",
        bayesian_alpha: float = BAYESIAN_ALPHA,
        bayesian_beta: float = BAYESIAN_BETA,
    ):
        """
        Args:
            data_dir: 载荷数据目录路径
            backup_dir: ASR 备份目录（更新前自动备份）
            bayesian_alpha: Beta 分布先验 α 参数
            bayesian_beta: Beta 分布先验 β 参数
        """
        self.data_dir = Path(data_dir)
        self.backup_dir = Path(backup_dir)
        self.alpha = bayesian_alpha
        self.beta = bayesian_beta
        self._updated_count = 0
        self._skipped_count = 0
        self._error_count = 0

    @property
    def updated_count(self) -> int:
        """本次更新成功修改的载荷数"""
        return self._updated_count

    @property
    def skipped_count(self) -> int:
        """本次跳过的载荷数（无匹配/无变化）"""
        return self._skipped_count

    @property
    def error_count(self) -> int:
        """本次更新出错的载荷数"""
        return self._error_count

    # ──────────────────────────────────────────────────────────────────────────
    # 从 FeedbackAnalyzer 报告更新
    # ──────────────────────────────────────────────────────────────────────────

    def update_from_feedback(
        self,
        feedback_report: Any,
        target_model: str = "",
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        从 FeedbackAnalyzer 报告更新载荷 ASR

        Args:
            feedback_report: FeedbackAnalyzer.analyze() 返回的 FeedbackReport 对象或字典
            target_model: 目标模型名称
            dry_run: 仅模拟运行，不实际写入文件

        Returns:
            更新统计字典
        """
        self._reset_counters()

        # 提取实战 ASR 数据
        battle_results = self._extract_battle_results(feedback_report, target_model)

        if not battle_results:
            logger.warning("No battle results found in feedback report")
            return self._get_stats()

        logger.info(
            "ASR update: %d payloads with battle results for model '%s'",
            len(battle_results), target_model or "unknown",
        )

        # 按载荷逐个更新
        for ref_path, (success_count, total_count) in battle_results.items():
            try:
                updated = self.update_single_payload(
                    ref_path=ref_path,
                    target_model=target_model,
                    success_count=success_count,
                    total_count=total_count,
                    dry_run=dry_run,
                )
                if updated:
                    self._updated_count += 1
                else:
                    self._skipped_count += 1
            except Exception as e:
                logger.error("Failed to update ASR for '%s': %s", ref_path, e)
                self._error_count += 1

        stats = self._get_stats()
        logger.info(
            "ASR update complete: %d updated, %d skipped, %d errors",
            stats["updated"], stats["skipped"], stats["errors"],
        )
        return stats

    # ──────────────────────────────────────────────────────────────────────────
    # 单个载荷 ASR 更新
    # ──────────────────────────────────────────────────────────────────────────

    def update_single_payload(
        self,
        ref_path: str,
        target_model: str,
        success_count: int,
        total_count: int,
        dry_run: bool = False,
    ) -> bool:
        """
        更新单个载荷的 ASR 基线

        Args:
            ref_path: 载荷引用路径 (如 "owasp:llm:llm01:skeleton_key")
            target_model: 目标模型名称
            success_count: 实战成功次数
            total_count: 实战总次数
            dry_run: 仅模拟运行

        Returns:
            是否成功更新
        """
        if total_count <= 0:
            logger.debug("Skip '%s': total_count=0", ref_path)
            return False

        # 解析 ref_path 到文件路径
        yaml_path = self._resolve_ref_to_path(ref_path)
        if not yaml_path or not yaml_path.exists():
            logger.debug("Skip '%s': file not found", ref_path)
            return False

        # 加载 YAML
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.error("Failed to load '%s': %s", yaml_path, e)
            raise

        if not data or not isinstance(data, dict):
            return False

        # 找到对应的载荷条目
        payloads = data.get("payloads", [])
        if not isinstance(payloads, list):
            return False

        # 从 ref_path 提取 technique/name 用于匹配
        ref_parts = ref_path.split(":")
        target_technique = ref_parts[-1] if ref_parts else ""

        model_key = self._normalize_model_key(target_model)
        today_str = date.today().isoformat()
        updated = False

        for payload in payloads:
            if not isinstance(payload, dict):
                continue

            # 匹配载荷（通过 technique 或 name）
            technique = payload.get("technique", "")
            name = payload.get("name", "")
            if target_technique and target_technique not in technique and target_technique not in name:
                continue

            # 计算贝叶斯平滑后的新 ASR
            battle_asr = (success_count + self.alpha) / (total_count + self.alpha + self.beta)

            # 获取原 ASR
            asr_baseline = payload.get("asr_baseline")
            if not isinstance(asr_baseline, dict):
                asr_baseline = {}

            old_asr = asr_baseline.get(model_key, asr_baseline.get("default", 0.3))

            # 混合策略：样本充足时用实战 ASR，样本不足时加权混合
            if total_count >= MIN_SAMPLE_FOR_FULL_WEIGHT:
                new_asr = battle_asr
            else:
                weight = total_count / MIN_SAMPLE_FOR_FULL_WEIGHT
                new_asr = old_asr * (1 - weight) + battle_asr * weight

            new_asr = round(new_asr, 4)

            # 备份原 ASR 到 history
            asr_history = payload.get("asr_history", [])
            if not isinstance(asr_history, list):
                asr_history = []

            if old_asr != new_asr:
                asr_history.append({
                    "date": today_str,
                    "model": model_key,
                    "old_asr": old_asr,
                    "new_asr": new_asr,
                    "battle_success": success_count,
                    "battle_total": total_count,
                })
                payload["asr_history"] = asr_history

                # 更新 ASR 基线
                asr_baseline[model_key] = new_asr
                payload["asr_baseline"] = asr_baseline

                # 更新元数据
                old_test_count = payload.get("test_count", 0)
                if not isinstance(old_test_count, (int, float)):
                    old_test_count = 0
                payload["test_count"] = int(old_test_count) + total_count
                payload["last_tested"] = today_str

                updated = True

        if updated and not dry_run:
            # 备份原文件
            self._backup_file(yaml_path)
            # 写入更新后的 YAML
            try:
                with open(yaml_path, "w", encoding="utf-8") as f:
                    yaml.dump(
                        data, f,
                        allow_unicode=True,
                        default_flow_style=False,
                        sort_keys=False,
                    )
            except Exception as e:
                logger.error("Failed to write '%s': %s", yaml_path, e)
                raise

        return updated

    # ──────────────────────────────────────────────────────────────────────────
    # 内部方法
    # ──────────────────────────────────────────────────────────────────────────

    def _reset_counters(self) -> None:
        """重置计数器"""
        self._updated_count = 0
        self._skipped_count = 0
        self._error_count = 0

    def _get_stats(self) -> Dict[str, Any]:
        """获取更新统计"""
        return {
            "updated": self._updated_count,
            "skipped": self._skipped_count,
            "errors": self._error_count,
            "total_processed": self._updated_count + self._skipped_count + self._error_count,
        }

    def _extract_battle_results(
        self,
        feedback_report: Any,
        target_model: str,
    ) -> Dict[str, Tuple[int, int]]:
        """
        从 FeedbackReport 中提取每个载荷的实战结果

        Returns:
            {ref_path: (success_count, total_count)}
        """
        results: Dict[str, Tuple[int, int]] = {}

        # 支持 FeedbackReport 对象或字典
        if hasattr(feedback_report, "category_stats"):
            stats = feedback_report.category_stats
        elif isinstance(feedback_report, dict):
            stats = feedback_report.get("category_stats", {})
        else:
            return results

        # 从 category_stats 提取
        for category, stat in stats.items():
            if not isinstance(stat, dict):
                continue
            success = stat.get("success", 0)
            failure = stat.get("failure", 0)
            total = success + failure
            if total > 0:
                # 用 category 作为 ref_path 的一部分
                results[category] = (success, total)

        # 从原始攻击结果中提取更精确的 per-payload 数据
        if hasattr(feedback_report, "payload_stats"):
            for ref, stat in feedback_report.payload_stats.items():
                if isinstance(stat, dict):
                    success = stat.get("success", 0)
                    failure = stat.get("failure", 0)
                    total = success + failure
                    if total > 0:
                        results[ref] = (success, total)
        elif isinstance(feedback_report, dict):
            for ref, stat in feedback_report.get("payload_stats", {}).items():
                if isinstance(stat, dict):
                    success = stat.get("success", 0)
                    failure = stat.get("failure", 0)
                    total = success + failure
                    if total > 0:
                        results[ref] = (success, total)

        return results

    def _resolve_ref_to_path(self, ref_path: str) -> Optional[Path]:
        """
        将 ref_path (如 "owasp:llm:llm01:skeleton_key") 解析为 YAML 文件路径

        查找策略：
        1. 尝试 owasp/{group}/{category}/{name}.yaml
        2. 尝试 owasp/{group}/{category}/ 下的所有 YAML 文件匹配 technique/name
        """
        parts = ref_path.split(":")
        if len(parts) < 3:
            return None

        # owasp:llm:llm01:skeleton_key → owasp/llm/llm01/skeleton_key.yaml
        if parts[0] == "owasp":
            group = parts[1] if len(parts) > 1 else ""
            category = parts[2] if len(parts) > 2 else ""
            name = parts[3] if len(parts) > 3 else ""

            # 直接路径
            if name:
                direct_path = self.data_dir / group / category / f"{name}.yaml"
                if direct_path.exists():
                    return direct_path

            # 搜索目录
            search_dir = self.data_dir / group / category
            if search_dir.exists():
                return search_dir  # 返回目录，调用方需要遍历

        return None

    def _normalize_model_key(self, model_name: str) -> str:
        """归一化模型名称为 ASR 键名"""
        if not model_name:
            return "default"
        normalized = model_name.lower().strip().replace("-", "_").replace(":", "_")
        for suffix in ["_latest", "_preview"]:
            if normalized.endswith(suffix):
                normalized = normalized[: -len(suffix)]
        return normalized

    def _backup_file(self, yaml_path: Path) -> None:
        """备份 YAML 文件"""
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{yaml_path.stem}_{timestamp}.yaml"
            backup_path = self.backup_dir / backup_name
            shutil.copy2(yaml_path, backup_path)
            logger.debug("Backed up '%s' → '%s'", yaml_path, backup_path)
        except Exception as e:
            logger.warning("Backup failed for '%s': %s", yaml_path, e)
