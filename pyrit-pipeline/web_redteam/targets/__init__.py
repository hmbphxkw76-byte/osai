# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""目标档案包: YAML 配置 + Profile 模型。."""

from web_redteam.targets.dynamic_profile import create_profile_from_url
from web_redteam.targets.target_profile import (
    AttackDefaults,
    AuthConfig,
    CrossDomainAuthConfig,
    DetectionConfig,
    InputConfig,
    InteractionConfig,
    RedirectChainEntry,
    ResponseConfig,
    SameDomainAuthConfig,
    SendConfig,
    TargetProfile,
)

__all__ = [
    "AttackDefaults",
    "AuthConfig",
    "create_profile_from_url",
    "CrossDomainAuthConfig",
    "DetectionConfig",
    "InputConfig",
    "InteractionConfig",
    "RedirectChainEntry",
    "ResponseConfig",
    "SameDomainAuthConfig",
    "SendConfig",
    "TargetProfile",
]
