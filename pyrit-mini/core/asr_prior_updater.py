"""
ASR Prior Updater — ASR Priors 时效性管理系统
==============================================

解决 ASR priors 时效性问题，实现季度自动更新机制。

核心能力:
1. **时效性检测**: 检测 priors 文件最后更新时间，超过阈值告警
2. **衰减因子 (Temporal Decay)**: 根据数据年龄自动衰减 ASR 权重
3. **季度更新调度**: 自动计算下次更新日期，支持 CI/CD 集成
4. **增量热更新**: 无需重启即可热更新部分 priors
5. **变更日志**: 追踪 priors 变化，支持审计和回滚

Academic Concept:
- 概念漂移 (Concept Drift): 模型安全对齐随时间变化，历史 ASR 需衰减
- 半衰期模型: ASR 数据有效性按指数衰减，半衰期 90 天

Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────
# 常量配置
# ─────────────────────────────────────────────────────────

_DEFAULT_HALF_LIFE_DAYS: int = 90  # 半衰期 90 天 (季度)
_WARNING_THRESHOLD_DAYS: int = 60  # 60 天未更新则警告
_CRITICAL_THRESHOLD_DAYS: int = 120  # 120 天未更新则严重告警
_DECAY_MIN_FACTOR: float = 0.3  # 最小衰减因子 (不低于此值)
_VERSION_FILE: str = "config/asr_priors_version.json"


# ─────────────────────────────────────────────────────────
# 数据结构
# ─────────────────────────────────────────────────────────

@dataclass
class PriorFreshnessReport:
    """ASR Priors 新鲜度报告"""
    file_path: str
    last_updated: datetime
    days_since_update: int
    total_entries: int
    freshness_level: str  # fresh/warning/critical/expired
    decay_factor: float  # 当前衰减因子 [0,1]
    next_update_due: datetime
    recommendation: str


@dataclass
class PriorUpdateRecord:
    """单次更新记录"""
    timestamp: datetime
    technique: str
    model: str
    old_value: float
    new_value: float
    change_reason: str  #/manual/auto_decay/benchmark_import/user_feedback


@dataclass
class TemporalDecayConfig:
    """时序衰减配置"""
    half_life_days: int = _DEFAULT_HALF_LIFE_DAYS
    min_factor: float = _DECAY_MIN_FACTOR
    reference_date: datetime = field(default_factory=datetime.utcnow)
    
    def compute_decay_factor(self, data_date: datetime) -> float:
        """
        计算时序衰减因子
        
        使用指数衰减: factor = max(min_factor, 0.5^(age_days / half_life))
        """
        age_days = (self.reference_date - data_date).days
        if age_days <= 0:
            return 1.0
        decay = math.pow(0.5, age_days / self.half_life_days)
        return max(self.min_factor, decay)


# ─────────────────────────────────────────────────────────
# 核心管理类
# ─────────────────────────────────────────────────────────

class ASRPriorUpdater:
    """
    ASR Priors 时效性管理器
    
    用法:
        updater = ASRPriorUpdater()
        
        # 检查新鲜度
        report = updater.check_freshness()
        print(report.freshness_level)  # fresh/warning/critical/expired
        
        # 应用衰减
        decayed_priors = updater.apply_temporal_decay(priors_dict)
        
        # 增量更新
        updater.incremental_update({"prompt_sending": {"gpt-5": 75.0}})
        
        # 获取更新计划
        schedule = updater.get_update_schedule()
    """
    
    def __init__(
        self,
        priors_path: str = "config/asr_priors.yaml",
        version_path: str = _VERSION_FILE,
    ) -> None:
        self._priors_path = Path(priors_path)
        self._version_path = Path(version_path)
        self._decay_config = TemporalDecayConfig()
        self._update_history: list[PriorUpdateRecord] = []
        self._original_values: dict[str, float] = {}  # 用于追踪衰减
        
    def check_freshness(self) -> PriorFreshnessReport:
        """
        检查 ASR priors 文件的新鲜度
        
        检测维度:
        1. 文件修改时间
        2. 内置版本记录时间
        3. 总条目数
        """
        now = datetime.utcnow()
        days_since = 0
        freshness_level = "fresh"
        
        # 获取文件实际修改时间
        if self._priors_path.exists():
            mtime = os.path.getmtime(self._priors_path)
            last_updated = datetime.utcfromtimestamp(mtime)
            days_since = (now - last_updated).days
        else:
            last_updated = now
            days_since = 999  # 文件不存在
        
        # 判定新鲜度等级
        if days_since >= _CRITICAL_THRESHOLD_DAYS:
            freshness_level = "critical"
            recommendation = f"⚠️ 严重: {days_since} 天未更新，ASR priors 已严重过时，建议立即更新"
        elif days_since >= _WARNING_THRESHOLD_DAYS:
            freshness_level = "warning"
            recommendation = f"⚠️ 警告: {days_since} 天未更新，建议尽快更新 ASR priors"
        elif days_since >= 30:
            freshness_level = "aging"
            recommendation = f"注意: {days_since} 天未更新，建议安排更新"
        else:
            freshness_level = "fresh"
            recommendation = "✅ ASR priors 新鲜度良好"
        
        # 统计条目数
        total_entries = 0
        if self._priors_path.exists():
            with open(self._priors_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    total_entries = sum(
                        len(v) for v in data.values()
                        if isinstance(v, dict)
                    )
        
        # 计算衰减因子
        decay = self._decay_config.compute_decay_factor(last_updated)
        
        # 下次更新日期: 每 90 天
        next_update = last_updated + timedelta(days=self._decay_config.half_life_days)
        
        return PriorFreshnessReport(
            file_path=str(self._priors_path),
            last_updated=last_updated,
            days_since_update=days_since,
            total_entries=total_entries,
            freshness_level=freshness_level,
            decay_factor=decay,
            next_update_due=next_update,
            recommendation=recommendation,
        )
    
    def apply_temporal_decay(
        self,
        priors: dict[str, dict[str, float]],
        data_date: datetime | None = None,
    ) -> dict[str, dict[str, float]]:
        """
        对 priors 应用时序衰减
        
        旧的 ASR 数据会因模型更新/安全对齐增强而失效。
        使用时间衰减因子降低旧数据的权重。
        """
        if data_date is None:
            data_date = self.check_freshness().last_updated
        
        decay_factor = self._decay_config.compute_decay_factor(data_date)
        
        if decay_factor >= 0.99:
            return priors  # 数据很新，无需衰减
        
        decayed: dict[str, dict[str, float]] = {}
        
        for technique, models in priors.items():
            if not isinstance(models, dict):
                continue
            decayed[technique] = {}
            for model, asr_value in models.items():
                # 衰减后 ASR: 向均值 (50%) 回归
                # 这是我们不确定新 ASR 时的最大熵估计
                decayed_value = asr_value * decay_factor + 50.0 * (1 - decay_factor)
                decayed[technique][model] = round(decayed_value, 1)
                
                # 记录原始值
                key = f"{technique}::{model}"
                if key not in self._original_values:
                    self._original_values[key] = asr_value
        
        logger.info(
            f"Applied temporal decay (factor={decay_factor:.3f}, age={self._decay_config.reference_date - data_date})"
        )
        return decayed
    
    def incremental_update(
        self,
        new_values: dict[str, dict[str, float]],
        reason: str = "manual",
    ) -> list[PriorUpdateRecord]:
        """
        增量更新部分 priors
        
        无需替换整个文件，只更新指定的技术-模型组合。
        适用于:
        - 用户反馈修正
        - 新 benchmark 数据导入
        - 运行后 ASR 统计回写
        """
        # 读取现有 priors
        current: dict[str, dict[str, float]] = {}
        if self._priors_path.exists():
            with open(self._priors_path, 'r', encoding='utf-8') as f:
                current = yaml.safe_load(f) or {}
        
        records: list[PriorUpdateRecord] = []
        now = datetime.utcnow()
        
        for technique, models in new_values.items():
            if technique not in current:
                current[technique] = {}
            
            for model, new_value in models.items():
                old_value = current[technique].get(model, 0.0)
                
                # 记录变更
                record = PriorUpdateRecord(
                    timestamp=now,
                    technique=technique,
                    model=model,
                    old_value=old_value,
                    new_value=new_value,
                    change_reason=reason,
                )
                records.append(record)
                self._update_history.append(record)
                
                # 应用更新 (EMA 平滑: 70% 旧 + 30% 新，避免突变)
                smoothed = old_value * 0.7 + new_value * 0.3
                current[technique][model] = round(smoothed, 1)
                
                logger.debug(
                    f"Prior update: {technique}/{model} "
                    f"{old_value} -> {current[technique][model]} (raw={new_value})"
                )
        
        # 写回文件
        with open(self._priors_path, 'w', encoding='utf-8') as f:
            yaml.dump(current, f, default_flow_style=False, allow_unicode=True)
        
        # 更新版本记录
        self._save_version_info(now, len(records))
        
        logger.info(
            f"Incremental update complete: {len(records)} entries updated (reason={reason})"
        )
        return records
    
    def get_update_schedule(self) -> dict[str, Any]:
        """
        获取更新计划
        
        返回下次更新时间、当前状态、历史变更统计
        """
        freshness = self.check_freshness()
        
        # 统计历史变更
        recent_changes = [
            r for r in self._update_history
            if (datetime.utcnow() - r.timestamp).days <= 90
        ]
        
        # 找出变化最大的技术-模型组合
        top_changes: list[dict[str, Any]] = []
        if self._update_history:
            sorted_history = sorted(
                self._update_history[-50:],  # 最近 50 条
                key=lambda r: abs(r.new_value - r.old_value),
                reverse=True,
            )
            for r in sorted_history[:5]:
                top_changes.append({
                    "technique": r.technique,
                    "model": r.model,
                    "old": r.old_value,
                    "new": r.new_value,
                    "delta": round(r.new_value - r.old_value, 1),
                })
        
        return {
            "current_freshness": freshness.freshness_level,
            "days_since_update": freshness.days_since_update,
            "decay_factor": freshness.decay_factor,
            "next_update_due": freshness.next_update_due.isoformat(),
            "total_entries": freshness.total_entries,
            "recent_changes_count": len(recent_changes),
            "top_changes": top_changes,
            "recommendation": freshness.recommendation,
        }
    
    def import_from_benchmark(
        self,
        benchmark_data: dict[str, dict[str, float]],
        benchmark_name: str = "unknown",
        benchmark_date: datetime | None = None,
    ) -> list[PriorUpdateRecord]:
        """
        从 benchmark 结果导入 ASR 数据
        
        支持导入外部 benchmark (如 HarmBench, WildBench) 的结果
        """
        if benchmark_date is not None:
            # 根据 benchmark 数据的时间调整衰减
            self._decay_config.reference_date = benchmark_date
        
        return self.incremental_update(
            benchmark_data,
            reason=f"benchmark_import:{benchmark_name}",
        )
    
    def auto_regress_expired_priors(self) -> dict[str, dict[str, float]]:
        """
        自动回归过期 priors
        
        对于超过临界值的 priors，将其 ASR 向均值 (50%) 回归
        因为过期的 ASR 数据不可靠，不如使用无信息先验
        """
        freshness = self.check_freshness()
        
        if freshness.freshness_level in ("fresh", "aging"):
            logger.info("Priors are fresh, no regression needed")
            return {}
        
        # 读取现有 priors
        if not self._priors_path.exists():
            return {}
        
        with open(self._priors_path, 'r', encoding='utf-8') as f:
            current = yaml.safe_load(f) or {}
        
        # 应用衰减
        decayed = self.apply_temporal_decay(current, freshness.last_updated)
        
        # 写回
        with open(self._priors_path, 'w', encoding='utf-8') as f:
            yaml.dump(decayed, f, default_flow_style=False, allow_unicode=True)
        
        logger.info(
            f"Auto-regressed {freshness.total_entries} priors "
            f"(decay_factor={freshness.decay_factor:.3f})"
        )
        
        return decayed
    
    def _save_version_info(self, timestamp: datetime, changes: int) -> None:
        """保存版本信息"""
        version_info = {
            "last_updated": timestamp.isoformat(),
            "last_changes_count": changes,
            "total_history_records": len(self._update_history),
            "decay_half_life_days": self._decay_config.half_life_days,
        }
        
        with open(self._version_path, 'w', encoding='utf-8') as f:
            json.dump(version_info, f, indent=2, ensure_ascii=False)
    
    def get_quarterly_update_command(self) -> str:
        """生成季度更新命令 (用于 CI/CD)"""
        return (
            "python -c \""
            "from core.asr_prior_updater import ASRPriorUpdater; "
            "u = ASRPriorUpdater(); "
            "print(u.check_freshness().recommendation); "
            "print(u.get_update_schedule())\""
        )


# ─────────────────────────────────────────────────────────
# 全局辅助函数
# ─────────────────────────────────────────────────────────

def check_priors_freshness() -> PriorFreshnessReport:
    """快速检查 priors 新鲜度 (命令行入口)"""
    updater = ASRPriorUpdater()
    return updater.check_freshness()


def apply_decay_if_needed() -> float:
    """
    主入口: 如果 priors 过期则自动应用衰减
    
    返回当前衰减因子
    """
    updater = ASRPriorUpdater()
    freshness = updater.check_freshness()
    
    if freshness.freshness_level in ("critical", "expired"):
        logger.warning(
            f"ASR priors are {freshness.days_since_update} days old, "
            f"applying temporal decay (factor={freshness.decay_factor:.3f})"
        )
        updater.auto_regress_expired_priors()
    
    return freshness.decay_factor
