"""
Exam Module
============

本模块负责考试专用功能，包括时间管理。
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from src.core.models import (
    ExamProgress,
    TargetPriority,
    TimeWarning,
)


# ============================================================
# 时间管理器
# ============================================================


class ExamTimeManager:
    """考试时间管理器 - 管理考试时间分配和提醒"""

    def __init__(self, exam_duration_hours: int = 24):
        """
        初始化时间管理器

        Args:
            exam_duration_hours: 考试时长（小时）
        """
        self.exam_duration = timedelta(hours=exam_duration_hours)
        self.start_time = datetime.now()
        self.target_priorities: Dict[str, int] = {}
        self.time_allocation: Dict[str, int] = {}
        self.warning_interval = timedelta(minutes=30)

    def get_remaining_time(self) -> timedelta:
        """
        获取剩余时间

        Returns:
            剩余时间
        """
        elapsed = datetime.now() - self.start_time
        remaining = self.exam_duration - elapsed
        return max(remaining, timedelta(0))

    def should_switch_target(self, current_target: str) -> bool:
        """
        判断是否应该切换目标

        Args:
            current_target: 当前目标 URL

        Returns:
            是否应该切换目标
        """
        remaining = self.get_remaining_time()
        allocated = self.time_allocation.get(current_target, 0)

        # 如果当前目标已超时或剩余时间不足10分钟
        if allocated <= 0 or remaining.total_seconds() < 600:
            return True
        return False

    def prioritize_targets(self, targets: List[str]) -> List[str]:
        """
        按优先级排序目标

        Args:
            targets: 目标 URL 列表

        Returns:
            排序后的目标列表
        """
        return sorted(
            targets,
            key=lambda t: self.target_priorities.get(t, 50),
            reverse=True,
        )

    def allocate_time(self, targets: List[str], total_minutes: int = 1440) -> None:
        """
        根据优先级分配每个目标的攻击时间

        Args:
            targets: 目标 URL 列表
            total_minutes: 总时间（分钟）
        """
        total_priority = sum(self.target_priorities.get(t, 50) for t in targets)
        for target in targets:
            priority = self.target_priorities.get(target, 50)
            allocated = int(total_minutes * (priority / total_priority))
            self.time_allocation[target] = allocated

    def check_time_warnings(self) -> List[TimeWarning]:
        """
        检查时间警告

        Returns:
            时间警告列表
        """
        warnings: List[TimeWarning] = []
        remaining = self.get_remaining_time()

        # 检查警告间隔
        elapsed = datetime.now() - self.start_time
        intervals_elapsed = int(elapsed / self.warning_interval)

        # 每个间隔检查一次
        if intervals_elapsed > 0:
            hours = int(remaining.total_seconds() // 3600)
            minutes = int((remaining.total_seconds() % 3600) // 60)

            message = f"剩余时间: {hours}小时 {minutes}分钟"

            # 根据剩余时间确定警告级别
            if remaining < timedelta(minutes=30):
                priority = "CRITICAL"
            elif remaining < timedelta(hours=1):
                priority = "WARNING"
            else:
                priority = "INFO"

            warning = TimeWarning(
                warning_time=datetime.now(),
                remaining_time_seconds=int(remaining.total_seconds()),
                message=message,
                priority=priority,
            )
            warnings.append(warning)

        return warnings

    def get_exam_progress(self) -> ExamProgress:
        """
        获取考试进度

        Returns:
            考试进度
        """
        return ExamProgress(
            exam_id="exam",
            start_time=self.start_time,
            end_time=None,
            total_duration_hours=int(self.exam_duration.total_seconds() / 3600),
            elapsed_time_seconds=(datetime.now() - self.start_time).total_seconds(),
            remaining_time_seconds=self.get_remaining_time().total_seconds(),
            completed_targets=len(self.time_allocation),
            total_targets=0,  # 需要传入
            completed_attacks=0,  # 需要从 Memory 获取
            successful_attacks=0,  # 需要从 Memory 获取
        )


# ============================================================
# 目标优先级评估器
# ============================================================


class TargetPriorityEvaluator:
    """目标优先级评估器 - 评估目标攻击优先级"""

    def evaluate(self, recon_result) -> int:
        """
        评估目标优先级（0-100）

        Args:
            recon_result: 侦察结果

        Returns:
            优先级分数
        """
        score = 0

        # PyRIT 可攻击类型得分更高
        if recon_result.ai_system_type.is_pyrit_attackable():
            if recon_result.ai_system_type.value == "multi_agent":
                score += 30
            elif recon_result.ai_system_type.value == "mcp_server":
                score += 28
            elif recon_result.ai_system_type.value == "llm":
                score += 25
            elif recon_result.ai_system_type.value == "rag":
                score += 22
        else:
            # 非优势类型得分较低
            score += 5

        # 认证复杂度评分
        if recon_result.auth_type.value == "none":
            score += 20
        elif recon_result.auth_type.value == "api_key":
            score += 15
        elif recon_result.auth_type.value == "form_based":
            score += 10

        # 能力评分
        if recon_result.capabilities.supports_multi_turn:
            score += 5

        return min(score, 100)

    def create_target_priority(
        self, recon_result, allocated_time_minutes: int
    ) -> TargetPriority:
        """
        创建目标优先级对象

        Args:
            recon_result: 侦察结果
            allocated_time_minutes: 分配的时间（分钟）

        Returns:
            目标优先级对象
        """
        priority_score = self.evaluate(recon_result)
        attack_suitability = 1.0 if recon_result.ai_system_type.is_pyrit_attackable() else 0.0

        return TargetPriority(
            target_url=recon_result.target_url,
            ai_system_type=recon_result.ai_system_type,
            priority_score=priority_score,
            allocated_time_minutes=allocated_time_minutes,
            attack_suitability=attack_suitability,
        )


# ============================================================
# 工厂函数
# ============================================================


def create_exam_time_manager(exam_duration_hours: int = 24) -> ExamTimeManager:
    """
    创建考试时间管理器（工厂函数）

    Args:
        exam_duration_hours: 考试时长（小时）

    Returns:
        考试时间管理器
    """
    return ExamTimeManager(exam_duration_hours=exam_duration_hours)