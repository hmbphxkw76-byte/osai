"""
===============================================================================
OffSec AI-300 — Target 模块
===============================================================================
统一对外接口: load_env_config, CustomHttpChatTarget,
              create_scorer_target, create_attack_target,
              SCENARIO_PRESETS, build_custom_target, register_scenario,
              probe_model_info, ModelProbeResult

import 兼容: from targets import load_env_config, CustomHttpChatTarget, ...
===============================================================================
"""
from targets.config import load_env_config
from targets.http_target import CustomHttpChatTarget
from targets.factories import (
    create_scorer_target, create_attack_target,
)
from targets.scenarios import (
    SCENARIO_PRESETS, build_custom_target, register_scenario,
)
from targets.model_probe import probe_model_info, ModelProbeResult, check_target_reachable

__all__ = [
    "load_env_config",
    "CustomHttpChatTarget",
    "create_scorer_target",
    "create_attack_target",
    "SCENARIO_PRESETS",
    "build_custom_target",
    "register_scenario",
    "probe_model_info",
    "ModelProbeResult",
    "check_target_reachable",
]
