# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""从 .env + config/ 加载流水线上下文。

设计原则:
  - 必须通过环境变量修改的值 (TARGET_URL / API_KEY / 组织域名 等) 走 .env
  - 开箱即用的最优参数集中在 config/settings.py (无需修改)
  - 本模块仅做"加载 + 合并 + 类型化", 不持有任何业务默认值

加载优先级 (高 → 低):
  1. 显式传入的 overrides 参数
  2. 环境变量 (.env 文件或系统环境)
  3. config/settings.py 的默认参数 (非用户变量)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DOTENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def _load_dotenv(path: Path = _DOTENV_PATH) -> dict[str, str]:
    """极简 .env 解析 (不引入 python-dotenv 依赖)。"""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            env[key] = val
    except Exception as e:  # noqa: BLE001
        logger.warning(f"context_loader: failed to parse .env: {e}")
    return env


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def load_context(overrides: dict[str, Any] | None = None) -> Any:
    """加载 PipelineContext。

    Args:
        overrides: 优先级最高的覆盖字典 (如 CLI 参数)。

    Returns:
        pipeline.models.PipelineContext
    """
    from pipeline.models import PipelineContext

    # 1. 加载 .env
    dotenv = _load_dotenv()

    def get(key: str, default: str = "") -> str:
        return os.environ.get(key) or dotenv.get(key) or default

    # 2. 必改变量从 .env 读取
    target_url = get("TARGET_URL")
    target_type_hint = get("TARGET_TYPE", "auto")
    api_key = get("API_KEY")
    auth_type_hint = get("AUTH_TYPE", "auto")
    org_domains = _split_csv(get("ORG_DOMAINS"))
    allowed_hosts = _split_csv(get("ALLOWED_HOSTS")) or org_domains
    disallow_patterns = _split_csv(get("DISALLOW_PATTERNS"))
    output_dir = get("OUTPUT_DIR", "outputs/reports")
    export_formats = _split_csv(get("EXPORT_FORMATS")) or ["json", "pyrit", "garak"]

    ctx = PipelineContext(
        target_url=target_url,
        target_type_hint=target_type_hint,
        api_key=api_key,
        auth_type_hint=auth_type_hint,
        org_domains=org_domains,
        allowed_hosts=allowed_hosts,
        disallow_patterns=disallow_patterns,
        output_dir=output_dir,
        export_formats=export_formats,
    )

    # 3. 显式覆盖
    if overrides:
        for k, v in overrides.items():
            if hasattr(ctx, k):
                setattr(ctx, k, v)

    logger.info(
        f"context_loader: target={target_url!r} type_hint={target_type_hint!r} "
        f"formats={export_formats}"
    )
    return ctx
