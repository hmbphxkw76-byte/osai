"""
Retry Configuration — 对齐 PyRIT 三层重试机制
================================================

PyRIT 1.0.0 Resiliency 文档定义三层重试：

  1. Low-level (pyrit_target_retry):
     - 处理 RateLimitError / EmptyResponseException
     - 指数退避
     - 环境变量: RETRY_MAX_NUM_ATTEMPTS / RETRY_WAIT_MIN_SECONDS / RETRY_WAIT_MAX_SECONDS

  2. Mid-level (pyrit_json_retry):
     - 处理 InvalidJsonException
     - 立即重试（无退避）
     - 复用 RETRY_MAX_NUM_ATTEMPTS

  3. High-level (Scenario max_retries):
     - 重试整个 Scenario 工作流
     - 从记忆中恢复，跳过已完成目标
     - ScenarioResult.number_tries 跟踪总尝试次数

本模块负责：
  - 从 config/defaults/pipeline.yaml 读取重试配置
  - 将配置传播到 PyRIT 原生重试环境变量
  - 提供 RetryConfig 数据类供 ScenarioOrchestrator 使用
  - 支持 scenario-level max_retries 参数

设计原则：
  - 只有已知异常才重试（RateLimit / EmptyResponse / InvalidJson）
  - 未知异常（如 Auth 失败）不重试
  - 开发时 max_retries=0 快速失败，生产时 max_retries=3 弹性恢复
"""

import os
from dataclasses import dataclass
from typing import Optional

from src.core.config_loader import get_config_loader


# ============================================================
# 重试配置数据类
# ============================================================

@dataclass
class RetryConfig:
    """
    三层重试配置

    属性对应 PyRIT 1.0.0 Resiliency 文档的三层重试机制：
      - target_level: 低层 API 重试（指数退避）
      - json_level: 中层 JSON 解析重试（立即重试）
      - scenario_level: 高层 Scenario 工作流重试（恢复式重试）
    """
    # Low-level: Target HTTP 重试
    max_num_attempts: int = 10
    wait_min_seconds: int = 5
    wait_max_seconds: int = 220

    # High-level: Scenario 重试
    scenario_max_retries: int = 0

    @property
    def total_scenario_attempts(self) -> int:
        """Scenario 总尝试次数 = 1 + max_retries"""
        return 1 + self.scenario_max_retries

    def to_env_dict(self) -> dict[str, str]:
        """转换为环境变量字典"""
        return {
            "RETRY_MAX_NUM_ATTEMPTS": str(self.max_num_attempts),
            "RETRY_WAIT_MIN_SECONDS": str(self.wait_min_seconds),
            "RETRY_WAIT_MAX_SECONDS": str(self.wait_max_seconds),
        }

    def __repr__(self) -> str:
        return (
            f"RetryConfig(target: max={self.max_num_attempts} "
            f"wait={self.wait_min_seconds}-{self.wait_max_seconds}s, "
            f"scenario: max_retries={self.scenario_max_retries} "
            f"total={self.total_scenario_attempts})"
        )


# ============================================================
# 配置传播
# ============================================================

def configure_retry_env_vars(
    config: Optional[RetryConfig] = None,
    *,
    override: bool = True,
) -> RetryConfig:
    """
    将重试配置传播到环境变量

    PyRIT 原生 pyrit_target_retry 和 pyrit_json_retry 装饰器
    通过环境变量读取配置。本函数将 YAML 配置传播到这些环境变量。

    P2 对齐：统一配置源为 pipeline.yaml（单一真相源）
    - override 默认改为 True：强制用 YAML 值覆盖 .env 中可能残留的旧值
    - 防止 .env 的 RETRY_MAX_NUM_ATTEMPTS 覆盖 pipeline.yaml 的 retry.max_num_attempts
    - 确保 pipeline.yaml 的 retry 配置段始终生效

    Args:
        config: 重试配置；None 时从 ConfigLoader 读取
        override: 是否覆盖已存在的环境变量（默认 True）

    Returns:
        生效的 RetryConfig
    """
    if config is None:
        config = get_retry_config()

    env_dict = config.to_env_dict()

    for key, value in env_dict.items():
        if override or os.getenv(key) is None:
            os.environ[key] = value

    return config


def get_retry_config() -> RetryConfig:
    """
    从 ConfigLoader 获取重试配置

    P2 对齐：单一真相源为 config/defaults/pipeline.yaml
    - 不再从 .env 环境变量读取 RETRY_MAX_NUM_ATTEMPTS 等
    - 仅从 pipeline.yaml 的 retry 配置段读取
    - configure_retry_env_vars(override=True) 会将 YAML 值传播到环境变量
    - 这确保 pipeline.yaml 是唯一配置源，.env 中的 RETRY_* 不会覆盖

    Returns:
        RetryConfig 实例
    """
    loader = get_config_loader()

    # P2: 直接从 pipeline.yaml 读取，不检查 .env 环境变量
    retry_config = loader.get_pipeline_defaults().get("retry", {})
    max_attempts = retry_config.get("max_num_attempts", 3)
    wait_min = retry_config.get("wait_min_seconds", 1)
    wait_max = retry_config.get("wait_max_seconds", 10)

    # Scenario-level retry
    scenario_retries_env = os.getenv("SCENARIO_MAX_RETRIES")
    if scenario_retries_env is not None and scenario_retries_env.strip():
        scenario_retries = int(scenario_retries_env)
    else:
        scenario_retries = loader.get_pipeline_defaults().get("scenario_max_retries", 0)

    return RetryConfig(
        max_num_attempts=max_attempts,
        wait_min_seconds=wait_min,
        wait_max_seconds=wait_max,
        scenario_max_retries=scenario_retries,
    )


# ============================================================
# Scenario-level 重试辅助
# ============================================================

def should_retry_scenario(
    exception: Exception,
    attempt: int,
    max_retries: int,
) -> bool:
    """
    判断是否应该重试 Scenario

    遵循 PyRIT 最佳实践：
      - 开发时 max_retries=0 快速失败
      - 生产时 max_retries=3 弹性恢复
      - 所有异常都会被重试（因为低层重试已处理已知异常）

    Args:
        exception: 捕获的异常
        attempt: 当前尝试次数（1-based）
        max_retries: 最大重试次数

    Returns:
        是否应该重试
    """
    if attempt > max_retries:
        return False

    # PyRIT 文档: scenario-level 重试捕获 ANY 异常
    # 低层重试已处理 RateLimit / EmptyResponse / InvalidJson
    # 到达 scenario-level 的异常通常是未知的、需要工作流级恢复
    return True


def get_scenario_retry_message(
    attempt: int,
    max_retries: int,
    exception: Exception,
) -> str:
    """
    生成 scenario 重试日志消息

    遵循 PyRIT 文档建议的 ERROR 级别日志格式
    """
    remaining = max_retries - attempt + 1
    return (
        f"Scenario failed on attempt {attempt} "
        f"({exception.__class__.__name__}: {exception}). "
        f"Retrying... ({remaining} retries remaining)"
    )
