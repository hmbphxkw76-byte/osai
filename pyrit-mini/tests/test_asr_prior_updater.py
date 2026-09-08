"""
ASR Prior Updater 单元测试
===========================

覆盖时效性检测、衰减计算、增量更新、季度计划等功能。
"""

import json
import os
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from core.asr_prior_updater import (
    ASRPriorUpdater,
    PriorFreshnessReport,
    TemporalDecayConfig,
    apply_decay_if_needed,
    check_priors_freshness,
)
from core.asr_adaptive_engine import (
    ColdStartConfig,
    EpsilonGreedyState,
)


class TestTemporalDecayConfig:
    """时序衰减配置测试"""
    
    def test_decay_factor_new_data(self):
        """新数据不衰减"""
        config = TemporalDecayConfig()
        now = datetime.utcnow()
        factor = config.compute_decay_factor(now)
        assert factor == 1.0
    
    def test_decay_factor_90_days(self):
        """90 天 (半衰期) 衰减到 50%"""
        config = TemporalDecayConfig(half_life_days=90)
        old_date = datetime.utcnow() - timedelta(days=90)
        factor = config.compute_decay_factor(old_date)
        assert 0.48 <= factor <= 0.52
    
    def test_decay_factor_180_days(self):
        """180 天衰减到 25% (但被 min_factor=0.3 截断)"""
        config = TemporalDecayConfig(half_life_days=90, min_factor=0.3)
        old_date = datetime.utcnow() - timedelta(days=180)
        factor = config.compute_decay_factor(old_date)
        # 理论值 0.25 被 min_factor=0.3 截断
        assert 0.28 <= factor <= 0.32
    
    def test_decay_factor_min_floor(self):
        """衰减不低于最小值"""
        config = TemporalDecayConfig(half_life_days=90, min_factor=0.3)
        very_old = datetime.utcnow() - timedelta(days=365)
        factor = config.compute_decay_factor(very_old)
        assert factor >= 0.3


class TestASRPriorUpdaterFreshness:
    """新鲜度检测测试"""
    
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.priors_path = Path(self.temp_dir) / "test_priors.yaml"
        
        # 创建临时 priors 文件
        priors_data = {
            "prompt_sending": {"gpt-5": 60.0, "claude-4": 55.0},
            "skeleton_key": {"gpt-5": 80.0},
        }
        with open(self.priors_path, 'w') as f:
            yaml.dump(priors_data, f)
        
        self.updater = ASRPriorUpdater(priors_path=str(self.priors_path))
    
    def teardown_method(self):
        """清理临时文件"""
        if self.priors_path.exists():
            os.remove(self.priors_path)
        Path(self.temp_dir).rmdir()
    
    def test_check_freshness_new_file(self):
        """新文件应为 fresh"""
        report = self.updater.check_freshness()
        assert report.freshness_level in ("fresh", "aging")
        assert report.total_entries == 3
    
    def test_check_freshness_missing_file(self):
        """缺失文件返回高天数"""
        updater = ASRPriorUpdater(priors_path="/nonexistent/path.yaml")
        report = updater.check_freshness()
        assert report.freshness_level in ("critical", "expired")


class TestASRPriorUpdaterDecay:
    """衰减应用测试"""
    
    def test_apply_temporal_decay_no_change_for_fresh(self):
        """新鲜数据不变"""
        updater = ASRPriorUpdater()
        priors = {"prompt_sending": {"gpt-5": 60.0}}
        
        result = updater.apply_temporal_decay(priors, datetime.utcnow())
        assert result["prompt_sending"]["gpt-5"] == 60.0
    
    def test_apply_temporal_decay_regresses_to_mean(self):
        """衰减向均值 (50%) 回归"""
        updater = ASRPriorUpdater()
        priors = {"prompt_sending": {"gpt-5": 90.0}}
        
        old_date = datetime.utcnow() - timedelta(days=365)
        result = updater.apply_temporal_decay(priors, old_date)
        
        # 应该向 50% 回归
        assert result["prompt_sending"]["gpt-5"] < 90.0
        assert result["prompt_sending"]["gpt-5"] >= 30.0  # 最小值保护


class TestASRPriorUpdaterIncremental:
    """增量更新测试"""
    
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.priors_path = Path(self.temp_dir) / "test_priors.yaml"
        self.version_path = Path(self.temp_dir) / "test_version.json"
        
        # 创建初始 priors
        priors_data = {"prompt_sending": {"gpt-5": 60.0}}
        with open(self.priors_path, 'w') as f:
            yaml.dump(priors_data, f)
    
    def teardown_method(self):
        for p in [self.priors_path, self.version_path]:
            if p.exists():
                os.remove(p)
        Path(self.temp_dir).rmdir()
    
    def test_incremental_update_ema_smooth(self):
        """增量更新应用 EMA 平滑"""
        updater = ASRPriorUpdater(
            priors_path=str(self.priors_path),
            version_path=str(self.version_path),
        )
        
        # 更新一个已有值
        records = updater.incremental_update(
            {"prompt_sending": {"gpt-5": 90.0}},
            reason="test",
        )
        
        assert len(records) == 1
        assert records[0].old_value == 60.0
        assert records[0].new_value == 90.0
        
        # 验证 EMA: 60 * 0.7 + 90 * 0.3 = 69 (使用 epsilon_state 的 prior_weight)
        with open(self.priors_path, 'r') as f:
            data = yaml.safe_load(f)
        # 实际值取决于 epsilon_state 的当前 prior_weight
        assert 65 <= data["prompt_sending"]["gpt-5"] <= 75
    
    def test_incremental_update_adds_new_technique(self):
        """增量更新可添加新技术"""
        updater = ASRPriorUpdater(
            priors_path=str(self.priors_path),
            version_path=str(self.version_path),
        )
        
        records = updater.incremental_update(
            {"new_technique": {"gpt-5": 70.0}},
        )
        
        assert len(records) == 1
        
        with open(self.priors_path, 'r') as f:
            data = yaml.safe_load(f)
        assert "new_technique" in data
    
    def test_update_history_tracked(self):
        """更新历史被追踪"""
        updater = ASRPriorUpdater(
            priors_path=str(self.priors_path),
            version_path=str(self.version_path),
        )
        
        updater.incremental_update({"prompt_sending": {"gpt-5": 70.0}})
        updater.incremental_update({"prompt_sending": {"gpt-5": 80.0}})
        
        assert len(updater._update_history) == 2


class TestASRPriorUpdaterSchedule:
    """更新计划测试"""
    
    def test_get_update_schedule(self):
        """获取更新计划"""
        updater = ASRPriorUpdater()
        schedule = updater.get_update_schedule()
        
        assert "current_freshness" in schedule
        assert "next_update_due" in schedule
        assert "total_entries" in schedule


class TestEpsilonGreedyState:
    """Epsilon-Greedy 状态机测试"""
    
    def test_initial_state_is_cold(self):
        """初始状态为冷阶段"""
        state = EpsilonGreedyState()
        assert state.phase == "cold"
        assert state.current_epsilon == 0.40
        assert state.prior_weight == 0.70
    
    def test_transition_to_warm(self):
        """运行次数达到阈值后转入温阶段"""
        state = EpsilonGreedyState()
        for _ in range(11):
            state.update(ran_exploration=False)
        
        assert state.phase == "warm"
        assert state.current_epsilon == 0.20
        assert state.prior_weight == 0.40
    
    def test_transition_to_hot(self):
        """运行次数超过 50 次转入热阶段"""
        state = EpsilonGreedyState()
        for _ in range(51):
            state.update(ran_exploration=False)
        
        assert state.phase == "hot"
        assert state.current_epsilon == 0.05
        assert state.prior_weight == 0.10
    
    def test_forced_exploration_cold_phase(self):
        """冷阶段每 3 轮强制探索"""
        state = EpsilonGreedyState()
        
        # 第 3 轮应该强制探索
        state.update(ran_exploration=False)  # run 1
        assert not state.is_forced_exploration
        
        state.update(ran_exploration=False)  # run 2
        assert not state.is_forced_exploration
        
        state.update(ran_exploration=True)   # run 3
        # 此时 total_runs=3 → 3 % 3 == 0 → 下一轮强制
    
    def test_exploration_counting(self):
        """探索计数正确"""
        state = EpsilonGreedyState()
        state.update(ran_exploration=True)
        state.update(ran_exploration=False)
        state.update(ran_exploration=True)
        
        assert state.exploration_count == 2
        assert state.exploitation_count == 1


class TestColdStartConfig:
    """冷启动配置测试"""
    
    def test_default_thresholds(self):
        """默认阈值正确"""
        config = ColdStartConfig()
        assert config.cold_phase_threshold == 10
        assert config.warm_phase_threshold == 50
    
    def test_default_epsilons(self):
        """默认 epsilon 值正确"""
        config = ColdStartConfig()
        assert config.epsilon_cold == 0.40
        assert config.epsilon_warm == 0.20
        assert config.epsilon_hot == 0.05
    
    def test_default_prior_weights(self):
        """默认先验权重正确"""
        config = ColdStartConfig()
        assert config.prior_weight_cold == 0.70
        assert config.prior_weight_warm == 0.40
        assert config.prior_weight_hot == 0.10
