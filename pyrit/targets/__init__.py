"""
===============================================================================
PyRIT Red Team — Target 模块
===============================================================================
统一对外接口: load_env_config, CustomHttpChatTarget,
              create_scorer_target, create_attack_target,
              SCENARIO_PRESETS, build_custom_target, register_scenario,
              probe_model_info, ModelProbeResult, check_target_reachable,
              probe_target_type, TargetTypeResult, TargetType, generate_dynamic_prompts,
              auto_probe_target_model, auto_probe_target_type,
              build_attack_target_from_args

import 兼容: from targets import load_env_config, CustomHttpChatTarget, ...
===============================================================================
"""
from targets.config import load_env_config, load_target_preset, load_recon_preset
from targets.http_target import CustomHttpChatTarget
from targets.factories import (
    create_scorer_target, create_attack_target,
)
from targets.scenarios import (
    SCENARIO_PRESETS, build_custom_target, register_scenario,
)
from targets.model_probe import probe_model_info, ModelProbeResult, check_target_reachable
from targets.target_type_probe import (
    probe_target_type, TargetTypeResult, TargetType, generate_dynamic_prompts,
)
from targets.auto_probe import auto_probe_target_model, auto_probe_target_type
from targets.target_builder import build_attack_target_from_args

__all__ = [
    "load_env_config",
    "load_target_preset",
    "load_recon_preset",
    "CustomHttpChatTarget",
    "create_scorer_target",
    "create_attack_target",
    "SCENARIO_PRESETS",
    "build_custom_target",
    "register_scenario",
    "probe_model_info",
    "ModelProbeResult",
    "check_target_reachable",
    "probe_target_type",
    "TargetTypeResult",
    "TargetType",
    "generate_dynamic_prompts",
    "auto_probe_target_model",
    "auto_probe_target_type",
    "build_attack_target_from_args",
]
