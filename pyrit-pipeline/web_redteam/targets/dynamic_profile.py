# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""动态 Profile 生成器。.

当用户通过 --target-url 快速模式运行时, 从 URL 自动生成最小化 TargetProfile。

生成的 Profile 包含:
  - auth.type = "auto" (自动探测认证)
  - auth.target_url = 用户指定的 URL
  - interaction = 通用默认选择器 (可被 CLI 覆盖)
  - attack_defaults = 合理默认值 (可被 CLI 覆盖)

设计原则:
  快速模式不是"阉割版", 而是"智能默认版"。
  auto 探测 + 通用选择器 覆盖 80% 的 Web 聊天目标。
"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

from web_redteam.targets.target_profile import (
    AttackDefaults,
    AuthConfig,
    CrossDomainAuthConfig,
    ExtractionConfig,
    InputConfig,
    InteractionConfig,
    ResponseConfig,
    SameDomainAuthConfig,
    SendConfig,
    TargetMeta,
    TargetProfile,
)

logger = logging.getLogger(__name__)

# ── 通用登录表单默认选择器 (覆盖常见前端框架) ──
# 用于 auto_fill: 当 .env 中有 TARGET_USERNAME / TARGET_PASSWORD 时自动匹配
DEFAULT_USERNAME_SELECTORS = [
    'input[name="username"]',
    'input[name="user"]',
    'input[name="account"]',
    'input[type="email"]',
    'input[id*="username"]',
    'input[id*="user"]',
    'input[placeholder*="用户名"]',
    'input[placeholder*="账号"]',
    'input[placeholder*="email"]',
    'input[placeholder*="Username"]',
]
DEFAULT_PASSWORD_SELECTORS = [
    'input[name="password"]',
    'input[type="password"]',
    'input[id*="password"]',
    'input[placeholder*="密码"]',
    'input[placeholder*="Password"]',
]


# ── 通用 Web 聊天 UI 默认选择器 ──
# 覆盖常见前端框架 (React/Vue/原生) 的聊天组件模式
DEFAULT_INPUT_SELECTOR = "textarea, [contenteditable='true']"
DEFAULT_SEND_SELECTOR = 'button[type="submit"], button[class*="send"], button[aria-label*="send"]'
DEFAULT_RESPONSE_SELECTOR = '[class*="message"], [class*="response"], [class*="chat-msg"], [data-role="assistant"]'


def create_profile_from_url(
    target_url: str,
    attack_type: str | None = None,
    objective: str | None = None,
    max_turns: int | None = None,
) -> TargetProfile:
    """从 URL 动态生成最小化 TargetProfile。.

    如果环境变量 TARGET_USERNAME 和 TARGET_PASSWORD 已设置,
    自动生成 auto_fill 配置, Playwright 会自动填充登录表单, 无需人工输入。

    Args:
        target_url: 目标页面 URL。
        attack_type: 攻击类型 (可选, 覆盖默认值)。
        objective: 攻击目标 (可选, 覆盖默认值)。
        max_turns: 最大轮次 (可选, 覆盖默认值)。

    Returns:
        TargetProfile 实例, auth.type=auto, 使用默认交互选择器。
    """
    # 从 URL 提取域名作为目标名称
    domain = urlparse(target_url).netloc or "unknown"
    target_name = domain.replace(".", "_").replace(":", "_")

    # 检测环境变量中的凭据, 自动注入 auto_fill
    auto_fill = _build_auto_fill_from_env()
    if auto_fill:
        logger.info(
            f"DynamicProfile: detected credentials in env (TARGET_USERNAME/TARGET_PASSWORD), "
            f"auto_fill configured with {len(auto_fill)} selectors"
        )

    profile = TargetProfile(
        target=TargetMeta(
            name=f"auto_{target_name}",
            description=f"动态生成 (URL: {target_url})",
            type="web_chat",
        ),
        auth=AuthConfig(
            type="auto",
            login_url="",  # auto 模式不需要
            target_url=target_url,
            same_domain=SameDomainAuthConfig(),
            cross_domain=CrossDomainAuthConfig(),
            auto_fill=auto_fill,
        ),
        interaction=InteractionConfig(
            input=InputConfig(
                selector=DEFAULT_INPUT_SELECTOR,
                type="textarea",
            ),
            send=SendConfig(
                selector=DEFAULT_SEND_SELECTOR,
            ),
            response=ResponseConfig(
                selector=DEFAULT_RESPONSE_SELECTOR,
                wait_strategy="new_element",
            ),
            extraction=ExtractionConfig(),
        ),
        attack_defaults=AttackDefaults(
            attack_type=attack_type or "prompt_sending",
            max_turns=max_turns or 1,
            objective=objective or "",
        ),
    )

    logger.info(f"DynamicProfile: generated profile for {target_url} (auth=auto, name={target_name})")
    return profile


def _build_auto_fill_from_env() -> dict[str, str]:
    """从环境变量构建 auto_fill 配置。.

    检测 TARGET_USERNAME 和 TARGET_PASSWORD, 如果存在,
    使用通用登录表单选择器构建 auto_fill 字典。
    Playwright 会尝试每个选择器, 找到第一个存在的元素并填充。

    Returns:
        {selector: value} 字典, 如果环境变量未设置则返回空字典。
    """
    auto_fill: dict[str, str] = {}

    username = os.environ.get("TARGET_USERNAME", "")
    password = os.environ.get("TARGET_PASSWORD", "")

    if username:
        for selector in DEFAULT_USERNAME_SELECTORS:
            auto_fill[selector] = username

    if password:
        for selector in DEFAULT_PASSWORD_SELECTORS:
            auto_fill[selector] = password

    return auto_fill
