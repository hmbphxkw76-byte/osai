# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Target 包装与数据加载子包。.

包含以下模块:
  - rate_limited_target: 限速 Target 包装器 (RPM 委托 + 并发重试)
  - rich_metadata_loader: 富元数据数据集格式支持

统一入口:
    from pipeline.targets import RateLimitedTarget, wrap_target_with_rate_limit
    from pipeline.targets import load_rich_prompt_as_native
"""

from pipeline.targets.rate_limited_target import RateLimitedTarget, wrap_target_with_rate_limit
from pipeline.targets.rich_metadata_loader import load_rich_prompt_as_native

__all__ = [
    "RateLimitedTarget",
    "wrap_target_with_rate_limit",
    "load_rich_prompt_as_native",
]
