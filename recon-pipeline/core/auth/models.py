# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证相关数据模型。

从 web_redteam/targets/target_profile.py 迁移的认证配置数据类。
这些类是纯数据模型, 不涉及攻击逻辑, 可以安全地放在 recon-kit 中。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionConfig:
    """认证完成检测策略配置。."""

    strategy: str
    pattern: str | None = None
    selector: str | None = None
    timeout_seconds: int = 300
    cookie_names: list[str] | None = None
    domain: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetectionConfig:
        """Create DetectionConfig from dictionary."""
        return cls(
            strategy=data.get("strategy", ""),
            pattern=data.get("pattern"),
            selector=data.get("selector"),
            timeout_seconds=data.get("timeout_seconds", 300),
            cookie_names=data.get("cookie_names"),
            domain=data.get("domain"),
        )


@dataclass
class RedirectChainEntry:
    """跨域重定向链中的一个节点。."""

    domain: str
    auth_action: str = ""
    human_steps: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RedirectChainEntry:
        """Create RedirectChainEntry from dictionary."""
        return cls(
            domain=data.get("domain", ""),
            auth_action=data.get("auth_action", ""),
            human_steps=data.get("human_steps", []),
        )


@dataclass
class SameDomainAuthConfig:
    """同域认证配置。."""

    detection: list[DetectionConfig] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SameDomainAuthConfig:
        """Create SameDomainAuthConfig from dictionary."""
        if data is None:
            return cls()
        detection_list = [DetectionConfig.from_dict(d) for d in data.get("detection", [])]
        return cls(detection=detection_list)


@dataclass
class CrossDomainAuthConfig:
    """跨域认证配置。."""

    redirect_chain: list[RedirectChainEntry] = field(default_factory=list)
    detection: list[DetectionConfig] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> CrossDomainAuthConfig:
        """Create CrossDomainAuthConfig from dictionary."""
        if data is None:
            return cls()
        chain = [RedirectChainEntry.from_dict(e) for e in data.get("redirect_chain", [])]
        detection_list = [DetectionConfig.from_dict(d) for d in data.get("detection", [])]
        return cls(redirect_chain=chain, detection=detection_list)
