# -*- coding: utf-8 -*-
"""
AI-300 Framework - Core Shared Library
共享核心库：数据模型、工具函数、接口定义

设计原则：
- 无外部依赖（仅依赖 Python 标准库）
- 各业务模块（reconnaissance/pipeline/orchestrators）单向依赖 core
- core 不依赖任何业务模块，避免循环依赖
"""

from .utils import (
    detect_target_type,
    extract_spa_llm_endpoint,
    extract_spa_model_name,
    build_aimap_data_from_spa_profile,
    inject_credentials_to_recon,
    inject_credentials_to_attack,
)
from .protocols import (
    StageInput,
    StageOutput,
    PipelineResult,
    PipelineStage,
    PHASE_CREDENTIAL,
    PHASE_RECON,
    PHASE_ATTACK,
    PHASE_REPORT,
    ALL_PHASES,
)
from .models import (
    EndpointInfo,
    FingerprintContract,
    ProfileContract,
)

__all__ = [
    # Utils
    "detect_target_type",
    "extract_spa_llm_endpoint",
    "extract_spa_model_name",
    "build_aimap_data_from_spa_profile",
    "inject_credentials_to_recon",
    "inject_credentials_to_attack",
    # Protocols
    "StageInput",
    "StageOutput",
    "PipelineResult",
    "PipelineStage",
    "PHASE_CREDENTIAL",
    "PHASE_RECON",
    "PHASE_ATTACK",
    "PHASE_REPORT",
    "ALL_PHASES",
    # Models
    "EndpointInfo",
    "FingerprintContract",
    "ProfileContract",
]
