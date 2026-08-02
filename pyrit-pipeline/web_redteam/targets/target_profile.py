# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""TargetProfile: 从 YAML 加载的目标配置模型。.

对齐 PyRIT 的 YamlLoadable 模式，通过 from_yaml_file() 加载配置。
所有字段都有默认值，确保向前兼容。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from pyrit.common.yaml_loadable import YamlLoadable


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


@dataclass
class AuthConfig:
    """认证配置。.

    支持四种 auth.type:
      - "auto":        自动探测目标是否需要认证及认证拓扑 (默认行为)
      - "none":        无需认证, 直接访问 target_url
      - "same_domain":  同域认证 (login_url → target_url 在同一域名内)
      - "cross_domain": 跨域认证 (SSO/OAuth/CAS, 涉及多域名跳转)
    """

    type: str = "auto"
    login_url: str = ""
    target_url: str = ""
    same_domain: SameDomainAuthConfig = field(default_factory=SameDomainAuthConfig)
    cross_domain: CrossDomainAuthConfig = field(default_factory=CrossDomainAuthConfig)
    auto_fill: dict[str, str] = field(default_factory=dict)
    human_assisted_steps: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AuthConfig:
        """Create AuthConfig from dictionary."""
        if data is None:
            return cls()
        auto_fill_raw = data.get("auto_fill", {})
        # 展开 ${ENV_VAR} 环境变量
        auto_fill = {}
        for selector, value in auto_fill_raw.items():
            auto_fill[selector] = _expand_env_vars(value)

        return cls(
            type=data.get("type", "same_domain"),
            login_url=data.get("login_url", ""),
            target_url=data.get("target_url", ""),
            same_domain=SameDomainAuthConfig.from_dict(data.get("same_domain")),
            cross_domain=CrossDomainAuthConfig.from_dict(data.get("cross_domain")),
            auto_fill=auto_fill,
            human_assisted_steps=data.get("human_assisted_steps", []),
        )


@dataclass
class InputConfig:
    """输入框配置。."""

    selector: str = ""
    type: str = "textarea"


@dataclass
class SendConfig:
    """发送按钮配置。."""

    selector: str = ""
    keyboard_shortcut: str | None = None


@dataclass
class ResponseConfig:
    """响应容器配置。."""

    selector: str = ""
    wait_strategy: str = "new_element"
    stability_threshold_ms: int = 2000
    loading_selector: str | None = None


@dataclass
class ExtractionConfig:
    """响应文本提取配置。."""

    text_selector: str | None = None
    wait_for_images: bool = False


@dataclass
class InteractionConfig:
    """交互配置。."""

    input: InputConfig = field(default_factory=InputConfig)
    send: SendConfig = field(default_factory=SendConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    extraction: ExtractionConfig = field(default_factory=ExtractionConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> InteractionConfig:
        """Create InteractionConfig from dictionary."""
        if data is None:
            return cls()
        input_data = data.get("input", {})
        send_data = data.get("send", {})
        response_data = data.get("response", {})
        extraction_data = data.get("extraction", {})
        return cls(
            input=InputConfig(
                selector=input_data.get("selector", ""),
                type=input_data.get("type", "textarea"),
            ),
            send=SendConfig(
                selector=send_data.get("selector", ""),
                keyboard_shortcut=send_data.get("keyboard_shortcut"),
            ),
            response=ResponseConfig(
                selector=response_data.get("selector", ""),
                wait_strategy=response_data.get("wait_strategy", "new_element"),
                stability_threshold_ms=response_data.get("stability_threshold_ms", 2000),
                loading_selector=response_data.get("loading_selector"),
            ),
            extraction=ExtractionConfig(
                text_selector=extraction_data.get("text_selector"),
                wait_for_images=extraction_data.get("wait_for_images", False),
            ),
        )


@dataclass
class AttackDefaults:
    """攻击默认参数。."""

    attack_type: str = "prompt_sending"
    max_turns: int = 10
    objective: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AttackDefaults:
        """Create AttackDefaults from dictionary."""
        if data is None:
            return cls()
        return cls(
            attack_type=data.get("attack_type", "prompt_sending"),
            max_turns=data.get("max_turns", 10),
            objective=data.get("objective", ""),
        )


@dataclass
class TargetMeta:
    """目标元信息。."""

    name: str = ""
    description: str = ""
    type: str = "web_chat"


@dataclass
class TargetProfile(YamlLoadable):
    """目标配置 Profile — 从 YAML 文件加载的完整目标定义。.

    包含: 目标元信息、认证拓扑、交互配置、攻击默认参数。
    一个 YAML 文件完整定义一个认证目标，零代码接入新目标。

    用法:
        profile = TargetProfile.from_yaml_file("targets/same_domain/example.yaml")
    """

    target: TargetMeta = field(default_factory=TargetMeta)
    auth: AuthConfig = field(default_factory=AuthConfig)
    interaction: InteractionConfig = field(default_factory=InteractionConfig)
    attack_defaults: AttackDefaults = field(default_factory=AttackDefaults)

    def __post_init__(self) -> None:
        """校验必填字段。."""
        if not self.auth.target_url:
            raise ValueError("TargetProfile: auth.target_url is required")
        if self.auth.type not in ("auto", "none", "same_domain", "cross_domain"):
            raise ValueError(
                f"TargetProfile: auth.type must be 'auto', 'none', 'same_domain' or 'cross_domain', "
                f"got '{self.auth.type}'"
            )
        # login_url 仅 same_domain / cross_domain 必填
        if self.auth.type in ("same_domain", "cross_domain") and not self.auth.login_url:
            raise ValueError(f"TargetProfile: auth.login_url is required when auth.type='{self.auth.type}'")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetProfile:
        """从字典创建 TargetProfile。."""
        target_data = data.get("target", {})
        return cls(
            target=TargetMeta(
                name=target_data.get("name", ""),
                description=target_data.get("description", ""),
                type=target_data.get("type", "web_chat"),
            ),
            auth=AuthConfig.from_dict(data.get("auth")),
            interaction=InteractionConfig.from_dict(data.get("interaction")),
            attack_defaults=AttackDefaults.from_dict(data.get("attack_defaults")),
        )

    def get_detection_configs(self) -> list[DetectionConfig]:
        """获取当前认证类型的检测策略列表。."""
        if self.auth.type == "cross_domain":
            return self.auth.cross_domain.detection
        elif self.auth.type == "same_domain":
            return self.auth.same_domain.detection
        # auto / none: 返回空列表 (auto 由 AuthProbe 动态生成, none 无需检测)
        return []


def _expand_env_vars(value: str) -> str:
    """展开 ${ENV_VAR} 格式的环境变量引用。.

    对齐 shell 变量替换语义: ${VAR} → os.environ.get("VAR", "")
    未设置的环境变量替换为空字符串。
    """

    def replace_match(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    return re.sub(r"\$\{(\w+)\}", replace_match, value)
