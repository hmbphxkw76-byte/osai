# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证相关数据模型.

独立的纯数据模型, 不依赖 recon-pipeline 的 core.auth 模块。
从 TargetProfile 的认证配置中提取的数据类。

数据流:
  YAML → TargetProfile.auth → AuthConfig → SameDomainAuthConfig / CrossDomainAuthConfig
  → DetectionConfig / RedirectChainEntry
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionConfig:
    """认证完成检测策略配置。.

    支持四种策略:
      - url_pattern:     page.url 正则匹配
      - dom_element:     CSS 选择器元素存在
      - cookie_presence: Cookie 名称集合存在
      - network_token:   网络响应 Token 拦截
    """

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
    """跨域重定向链中的一个节点。.

    用于描述 SSO/OAuth/CAS 场景中, 域名跳转的每个阶段:
      app.com → (redirect_to_idp) → idp.com → (login_form, human_steps) → app.com → (callback)
    """

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
    """同域认证配置。.

    包含认证完成检测策略列表 (多策略 OR 逻辑)。
    """

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
    """跨域认证配置。.

    包含重定向链 (redirect_chain) 和认证完成检测策略列表。
    重定向链用于指导跨域认证流程中每个域名的预期行为。
    """

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
