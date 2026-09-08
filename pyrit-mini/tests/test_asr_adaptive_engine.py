"""
ASR Adaptive Engine 单元测试
============================

覆盖核心功能: 单例初始化、UCB排序、EMA更新、漂移检测、零日晋升
"""

import pytest
import time
from unittest.mock import MagicMock

from core.asr_adaptive_engine import (
    ASRAdaptiveEngine,
    AdaptiveBudget,
    DefenseSignature,
    TechniquePerformance,
    get_adaptive_engine,
)


class TestTechniquePerformance:
    """TechniquePerformance 数据类测试"""
    
    def test_empirical_asr_zero_attempts(self):
        perf = TechniquePerformance(technique="test", model_family="gpt-5")
        assert perf.empirical_asr == 0.0
    
    def test_empirical_asr_calculation(self):
        perf = TechniquePerformance(
            technique="prompt_sending",
            model_family="gpt-4",
            attempts=10,
            successes=3,
        )
        assert perf.empirical_asr == 0.3
    
    def test_ucb_score_infinite_when_unattempted(self):
        perf = TechniquePerformance(technique="test", model_family="gpt-5")
        assert perf.ucb_score == float('inf')
    
    def test_ucb_score_finite_when_attempted(self):
        perf = TechniquePerformance(
            technique="test",
            model_family="gpt-5",
            attempts=10,
            successes=5,
            ema_asr=0.5,
        )
        score = perf.ucb_score
        assert 0 < score < float('inf')
        assert score > 0.5  # UCB 应该高于纯经验值


class TestDefenseSignature:
    """DefenseSignature 数据类测试"""
    
    def test_is_hardened_frontier(self):
        sig = DefenseSignature(adaptive_level="frontier")
        assert sig.is_hardened is True
    
    def test_is_hardened_strong(self):
        sig = DefenseSignature(adaptive_level="strong")
        assert sig.is_hardened is True
    
    def test_is_hardened_weak(self):
        sig = DefenseSignature(adaptive_level="weak")
        assert sig.is_hardened is False


class TestAdaptiveBudget:
    """AdaptiveBudget 数据类测试"""
    
    def test_remaining(self):
        budget = AdaptiveBudget(total_budget=100, consumed=30)
        assert budget.remaining == 70
    
    def test_remaining_not_negative(self):
        budget = AdaptiveBudget(total_budget=100, consumed=150)
        assert budget.remaining == 0
    
    def test_current_asr(self):
        budget = AdaptiveBudget(total_budget=100, consumed=20, successes=5)
        assert budget.current_asr == 0.25
    
    def test_exploration_ratio_high_when_plenty(self):
        budget = AdaptiveBudget(total_budget=100, consumed=10)
        ratio = budget.exploration_ratio
        assert 0.30 < ratio <= 0.40
    
    def test_exploration_ratio_low_when_scarce(self):
        budget = AdaptiveBudget(total_budget=100, consumed=90)
        ratio = budget.exploration_ratio
        assert 0.05 <= ratio < 0.10


class TestASRAdaptiveEngine:
    """ASR Adaptive Engine 核心测试"""
    
    def setup_method(self):
        """每个测试前重置单例"""
        ASRAdaptiveEngine._instance = None
        self.engine = ASRAdaptiveEngine()
    
    def test_singleton_behavior(self):
        """验证单例模式"""
        engine2 = ASRAdaptiveEngine()
        assert self.engine is engine2
    
    def test_initialize_from_priors_no_file(self):
        """测试缺失 priors 文件时的优雅降级"""
        # Should not raise
        self.engine.initialize_from_priors("nonexistent_file.yaml")
    
    def test_rank_techniques_empty(self):
        """无先验数据时返回空列表"""
        result = self.engine.rank_techniques("gpt-5")
        assert result == []
    
    def test_rank_techniques_with_data(self):
        """有数据时按 UCB 分数排序"""
        # 手动注入性能数据
        self.engine._performance["gpt-5::technique_a"] = TechniquePerformance(
            technique="technique_a", model_family="gpt-5", attempts=10, successes=8, ema_asr=0.8
        )
        self.engine._performance["gpt-5::technique_b"] = TechniquePerformance(
            technique="technique_b", model_family="gpt-5", attempts=0, ema_asr=0.5
        )
        
        result = self.engine.rank_techniques("gpt-5")
        assert len(result) == 2
        # 未尝试过的 technique_b 应有更高 UCB (探索奖励)
        assert result[0][0] == "technique_b"  # UCB = inf
    
    def test_update_performance_creates_entry(self):
        """新模型-技术组合自动创建条目"""
        self.engine.update_performance("gpt-5", "prompt_sending", success=True)
        
        key = "gpt-5::prompt_sending"
        assert key in self.engine._performance
        assert self.engine._performance[key].attempts == 1
    
    def test_update_performance_ema_calculation(self):
        """验证 EMA 更新公式"""
        self.engine.update_performance("gpt-5", "test_tech", success=True)
        self.engine.update_performance("gpt-5", "test_tech", success=False)
        self.engine.update_performance("gpt-5", "test_tech", success=True)
        
        perf = self.engine._performance["gpt-5::test_tech"]
        assert perf.ema_asr > 0
        assert perf.ema_asr < 1
    
    def test_update_performance_confidence_growth(self):
        """验证置信度随样本量增长"""
        for _ in range(25):
            self.engine.update_performance("gpt-5", "test_tech", success=True)
        
        perf = self.engine._performance["gpt-5::test_tech"]
        assert perf.confidence > 0.8
    
    def test_zero_day_promotion(self):
        """验证零日技术晋升机制"""
        # 零日技术命名前缀 t3_
        for _ in range(5):
            self.engine.update_performance("gpt-5", "t3_experimental_x", success=True)
        
        assert "t3_experimental_x" in self.engine._zero_day_promoted
    
    def test_drift_detection(self):
        """验证 ASR 漂移检测"""
        # 先注入历史数据
        self.engine._technique_history["drifted_tech"] = [True]*5 + [False]*5
        
        # 触发漂移检测
        self.engine.update_performance("gpt-5", "drifted_tech", success=False)
        
        # 应该有漂移事件记录
        assert len(self.engine._drift_log) > 0
        assert self.engine._drift_log[-1]["signal"] == "DEFENSE_UPGRADE"
    
    def test_update_defense_signature(self):
        """测试防御签名更新"""
        self.engine.update_defense_signature(
            model_family="claude-4-opus",
            refused=True,
            block_reason="content_policy",
            response_time_ms=800,
        )
        
        sig = self.engine.get_defense_signature()
        assert sig.model_family == "claude-4-opus"
        assert "content_policy" in sig.refusal_patterns
    
    def test_budget_recommendation_exploitation(self):
        """高 ASR 时进入利用模式"""
        self.engine._budget.total_budget = 100
        self.engine._budget.consumed = 50
        self.engine._budget.successes = 20  # ASR = 40%
        
        rec = self.engine.get_budget_recommendation()
        assert rec["phase"] == "exploitation"
    
    def test_budget_recommendation_exploration(self):
        """低 ASR 时进入探索模式"""
        self.engine._budget.total_budget = 100
        self.engine._budget.consumed = 50
        self.engine._budget.successes = 2  # ASR = 4%
        
        rec = self.engine.get_budget_recommendation()
        assert rec["phase"] == "exploration"
    
    def test_export_performance_snapshot(self):
        """测试快照导出"""
        self.engine.update_performance("gpt-5", "test_tech", success=True)
        
        snapshot = self.engine.export_performance_snapshot()
        assert "timestamp" in snapshot
        assert "technique_performance" in snapshot
        assert "gpt-5::test_tech" in snapshot["technique_performance"]
    
    def test_optimal_category_sequence_hardened(self):
        """加固目标返回编码优先序列"""
        self.engine._defense.adaptive_level = "strong"
        categories = self.engine.get_optimal_category_sequence("gpt-5")
        assert categories[0] == "encoding_evasion"
    
    def test_optimal_category_sequence_default(self):
        """非加固目标返回默认序列"""
        self.engine._defense.adaptive_level = "weak"
        categories = self.engine.get_optimal_category_sequence("gpt-5")
        assert categories[0] == "prompt_injection"


class TestIntegration:
    """集成测试: 完整工作流"""
    
    def setup_method(self):
        ASRAdaptiveEngine._instance = None
        self.engine = ASRAdaptiveEngine()
    
    def test_full_attack_cycle(self):
        """模拟完整攻击周期"""
        # 1. 初始化
        self.engine._budget.total_budget = 50
        
        # 2. 首轮攻击 (30% ASR → exploitation 模式)
        for i in range(10):
            success = i < 3  # 30% ASR
            self.engine.update_performance("gpt-5", "prompt_sending", success=success)
            # 同时更新防御签名
            self.engine.update_defense_signature(
                model_family="gpt-5",
                refused=not success,
                block_reason="content_policy" if not success else "",
                response_time_ms=500.0,
            )
        
        # 3. 检查状态 (ASR >= 30% 应进入 exploitation)
        rec = self.engine.get_budget_recommendation()
        assert rec["phase"] in ("exploitation", "diversification", "exploration")
        
        # 4. 调整策略 (防御等级应从 unknown 变为有效等级)
        defense = self.engine.get_defense_signature()
        assert defense.adaptive_level in ("weak", "moderate", "strong", "frontier")
        assert defense.model_family == "gpt-5"
    
    def test_multi_model_tracking(self):
        """同时追踪多个模型"""
        self.engine.update_performance("gpt-5", "tech_a", success=True)
        self.engine.update_performance("claude-4", "tech_a", success=False)
        self.engine.update_performance("gemini-2.5", "tech_b", success=True)
        
        gpt_perfs = [k for k in self.engine._performance if k.startswith("gpt-5")]
        claude_perfs = [k for k in self.engine._performance if k.startswith("claude-4")]
        
        assert len(gpt_perfs) == 1
        assert len(claude_perfs) == 1
