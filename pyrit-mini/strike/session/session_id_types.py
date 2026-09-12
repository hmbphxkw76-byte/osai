# -*- coding: utf-8 -*-
"""session_id_types.py — Session ID 分析类型定义

定义 Session ID 分析器的数据类和枚举类型。

Constitution compliance:
    - R-SIZE: < 300 lines
    - R-H3: 单一职责 — 仅定义类型
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PatternType(Enum):
    """Session ID 模式类型"""

    STRUCTURED_SEQ = "structured_seq"  # OffSec: MC-20260325-0016
    TIMESTAMP_MS = "timestamp_ms"  # 1711363200000 (13 digits)
    TIMESTAMP_S = "timestamp_s"  # 1711363200 (10 digits)
    UUID_V1 = "uuid_v1"  # 时间+MAC based
    UUID_V4 = "uuid_v4"  # Random
    MD5_HASH = "md5_hash"  # 32 hex chars
    SHA1_HASH = "sha1_hash"  # 40 hex chars
    INCREMENTAL_INT = "incremental_int"  # 1, 2, 3...
    USER_DERIVED = "user_derived"  # user_session_alice
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """风险等级"""

    CRITICAL = "critical"  # < 100 requests to enumerate
    HIGH = "high"  # < 1000 requests
    MEDIUM = "medium"  # < 10000 requests or needs side-channel
    LOW = "low"  # Requires additional leakage
    MINIMAL = "minimal"  # Practically unpredictable


@dataclass
class AnalysisResult:
    """Session ID 可预测性分析结果"""

    pattern_type: PatternType
    risk_level: RiskLevel
    entropy_bits: float = 0.0
    predictability_score: float = 0.0  # 0.0 (random) → 1.0 (fully predictable)
    search_space: int = 0  # Estimated candidates to enumerate
    sample_count: int = 0
    # 结构化序列专用
    prefix: str = ""
    date_format: str = ""
    counter_width: int = 0
    counter_base: int = 10
    # 时间戳专用
    time_correlation: float = 0.0  # 0.0-1.0 correlation with request time
    # 递增序列专用
    increment_value: int = 0  # Typical increment step
    # 推荐攻击向量
    attack_vectors: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_type": self.pattern_type.value,
            "risk_level": self.risk_level.value,
            "entropy_bits": self.entropy_bits,
            "predictability_score": self.predictability_score,
            "search_space": self.search_space,
            "sample_count": self.sample_count,
            "prefix": self.prefix,
            "date_format": self.date_format,
            "counter_width": self.counter_width,
            "time_correlation": self.time_correlation,
            "increment_value": self.increment_value,
            "attack_vectors": self.attack_vectors,
            "recommendations": self.recommendations,
        }
