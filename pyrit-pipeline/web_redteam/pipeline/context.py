# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""WebRedTeamContext: 贯穿流水线所有阶段的状态容器。.

对齐 pipeline/context.py 的 PipelineContext 设计模式:
  - 阶段间通信仅通过 Context 字段
  - 每个字段标注所属阶段
  - 新增阶段只需新增字段

双模式支持:
  - Browser 模式: profile + browser_session + page + PlaywrightTarget
  - API 模式: api_config + HTTPTarget (无浏览器依赖)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.async_api import Page
    from pyrit.prompt_target import PromptTarget

    from web_redteam.auth.browser_session import BrowserSession
    from web_redteam.targets.api_config import APITargetConfig
    from web_redteam.targets.target_profile import TargetProfile


@dataclass
class WebRedTeamContext:
    """贯穿流水线所有阶段的状态容器。.

    Attributes:
        args: 命令行参数 (Config 阶段产出).
        api_mode: 是否为 API 模式 (True=API POST, False=Browser UI).
        api_config: API 目标配置 (API 模式 Stage 0 产出).
        recon_result: 侦察结果 (Stage 1 产出, dict 或 None).
        config: PyRIT 配置实例 (Stage 1 产出).
        profile: TargetProfile (Browser 模式 Stage 2 产出).
        browser_session: BrowserSession 实例 (Browser 模式 Stage 2 产出).
        page: 已认证的 Playwright Page (Browser 模式 Stage 2 产出).
        target: PromptTarget 实例 (Stage 3 产出, PlaywrightTarget 或 HTTPTarget).
        result: AttackResult 执行结果 (Stage 4 产出).
        output_dir: 报告输出目录 (Stage 5 产出).
        metadata: 自由扩展字段.
    """

    # Config 阶段产出
    args: Any = None

    # Stage 0 产出 (模式判定)
    api_mode: bool = False
    api_config: APITargetConfig | None = None

    # Stage 1 产出 (侦察) — 类型为 Any, 避免与 recon-pipeline 的循环依赖
    recon_result: Any = None

    # Stage 1 产出
    config: Any = None

    # Stage 2 产出 (认证 — 仅 Browser 模式)
    profile: TargetProfile | None = None
    browser_session: BrowserSession | None = None
    page: Page | None = None

    # Stage 3 产出 (目标创建)
    target: PromptTarget | None = None

    # Stage 4 产出 (攻击执行)
    result: Any = None

    # Stage 5 产出
    output_dir: Path | None = None

    # 自由扩展
    metadata: dict[str, Any] = field(default_factory=dict)
