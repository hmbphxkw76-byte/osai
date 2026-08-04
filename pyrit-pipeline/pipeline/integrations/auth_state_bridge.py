# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证状态文件级共享 — pyrit-pipeline 与外部工具 (如 recon-pipeline) 之间的认证数据传递。.

**核心原则**: pyrit-pipeline 和 recon-pipeline 各自拥有独立的认证体系，
两者功能完备，不互相代码依赖。仅通过 JSON 文件传递认证数据，减少重复认证次数。

数据流:
  1. pyrit-pipeline 完成认证 → 导出 auth_state.json
  2. 外部工具读取 auth_state.json → 复用认证态 (跳过登录)
  3. 或反向: 外部工具完成认证 → 导出 auth_state.json
  4. pyrit-pipeline 读取 auth_state.json → 复用认证态

认证场景覆盖:
  - 无认证 (none): 直接访问
  - 同域认证 (same_domain): 用户名/密码 + 可选 MFA
  - 跨域认证 (cross_domain): SSO/OAuth/CAS + 可选 MFA
  - MFA 类型: OTP, SMS, 滑窗, 扫码, CAPTCHA (人工完成后自动接管)

学术依据:
  - OWASP ASVS V2.4: 认证验证要求
  - NIST SP 800-63B: 多因素认证分类
  - PyRIT CopilotAuthenticator: page 交互模式

> **日期**: 2026-8-4
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)

_DEFAULT_AUTH_STATE_DIR = Path("outputs/auth_state")
_DEFAULT_AUTH_STATE_FILE = "auth_state.json"


@dataclass
class AuthState:
    """认证状态数据 — 可在 pyrit 和外部工具之间传递。.

    Attributes:
        auth_type: 认证类型 ("none" / "same_domain" / "cross_domain")。
        target_url: 目标 URL。
        login_url: 登录页 URL (如有)。
        cookies: 浏览器 cookie 列表 (Playwright 格式)。
        headers: 认证 header 字典 (如 Authorization: Bearer xxx)。
        tokens: 认证 token 字典 (如 access_token, refresh_token)。
        storage_state_path: Playwright storage_state 文件路径。
        mfa_required: 是否需要 MFA。
        mfa_types: 检测到的 MFA 类型列表。
        authenticated_at: 认证完成时间戳 (ISO 格式)。
        expires_at: 认证过期时间戳 (ISO 格式, 可选)。
        source: 认证来源 ("pyrit" / "recon" / "manual")。
    """

    auth_type: str = "none"
    target_url: str = ""
    login_url: str = ""
    cookies: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    storage_state_path: str = ""
    mfa_required: bool = False
    mfa_types: list[str] = field(default_factory=list)
    authenticated_at: str = ""
    expires_at: str = ""
    source: str = "pyrit"

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthState:
        """从字典反序列化。."""
        valid_keys = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in valid_keys})

    def is_valid(self) -> bool:
        """检查认证状态是否有效。."""
        if self.auth_type == "none":
            return True
        return bool(self.cookies or self.headers or self.tokens or self.storage_state_path)

    def to_auth_headers(self) -> dict[str, str]:
        """提取认证 header (供 HTTPTarget 使用)。."""
        headers = dict(self.headers)
        if "access_token" in self.tokens and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.tokens['access_token']}"
        return headers


def export_auth_state(
    auth_state: AuthState,
    *,
    output_dir: Path | None = None,
    filename: str = _DEFAULT_AUTH_STATE_FILE,
) -> Path:
    """导出认证状态到 JSON 文件。.

    Args:
        auth_state: 认证状态数据。
        output_dir: 输出目录 (默认 outputs/auth_state/)。
        filename: 文件名。

    Returns:
        保存的文件路径。
    """
    out_dir = output_dir or _DEFAULT_AUTH_STATE_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    file_path = out_dir / filename
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(auth_state.to_dict(), f, indent=2, ensure_ascii=False)

    logger.info(f"Auth state exported to {file_path} (source={auth_state.source})")
    return file_path


def import_auth_state(
    file_path: Path | None = None,
) -> AuthState | None:
    """从 JSON 文件导入认证状态。.

    Args:
        file_path: 认证状态文件路径 (默认 outputs/auth_state/auth_state.json)。

    Returns:
        AuthState 实例, 文件不存在时返回 None。
    """
    path = file_path or (_DEFAULT_AUTH_STATE_DIR / _DEFAULT_AUTH_STATE_FILE)
    if not path.exists():
        logger.debug(f"Auth state file not found: {path}")
        return None

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        state = AuthState.from_dict(data)
        logger.info(f"Auth state imported from {path} (source={state.source})")
        return state
    except (json.JSONDecodeError, OSError, TypeError) as e:
        logger.warning(f"Failed to import auth state from {path}: {e}")
        return None


def build_auth_state_from_context(ctx: PipelineContext) -> AuthState:
    """从 PipelineContext 构建认证状态。.

    在 pyrit-pipeline 完成认证后，从 ctx.metadata 中提取认证数据。

    Args:
        ctx: PipelineContext。

    Returns:
        AuthState 实例。
    """
    from datetime import datetime, timezone

    auth_state = AuthState(
        auth_type=ctx.metadata.get("auth_type", "none"),
        target_url=ctx.metadata.get("target_url", ""),
        login_url=ctx.metadata.get("login_url", ""),
        source="pyrit",
        authenticated_at=datetime.now(timezone.utc).isoformat(),
    )

    # Playwright storage_state
    storage_state = ctx.metadata.get("storage_state_path", "")
    if storage_state:
        auth_state.storage_state_path = str(storage_state)

    # Cookies
    cookies = ctx.metadata.get("auth_cookies", [])
    if cookies:
        auth_state.cookies = cookies

    # API 模式 headers
    api_config = ctx.metadata.get("api_config")
    if api_config is not None:
        headers = getattr(api_config, "headers", {}) or {}
        auth_state.headers = dict(headers)

    # MFA 信息
    mfa_result = ctx.metadata.get("mfa_result")
    if mfa_result is not None:
        auth_state.mfa_required = getattr(mfa_result, "has_mfa", False)
        auth_state.mfa_types = getattr(mfa_result, "mfa_types", [])

    return auth_state


def inject_auth_state_to_context(
    ctx: PipelineContext,
    auth_state: AuthState,
) -> None:
    """将认证状态注入 PipelineContext。.

    Args:
        ctx: PipelineContext。
        auth_state: 认证状态数据。
    """
    ctx.metadata["auth_type"] = auth_state.auth_type
    ctx.metadata["auth_headers"] = auth_state.to_auth_headers()
    ctx.metadata["auth_cookies"] = auth_state.cookies
    ctx.metadata["auth_tokens"] = auth_state.tokens

    if auth_state.storage_state_path:
        ctx.metadata["storage_state_path"] = auth_state.storage_state_path

    if auth_state.mfa_required:
        ctx.metadata["mfa_required"] = True
        ctx.metadata["mfa_types"] = auth_state.mfa_types

    logger.info(
        f"Auth state injected to context "
        f"(type={auth_state.auth_type}, source={auth_state.source}, "
        f"valid={auth_state.is_valid()})"
    )


def try_reuse_auth_state(ctx: PipelineContext) -> bool:
    """尝试复用已有认证状态 (非异步, 文件读取)。.

    在认证流程开始前调用:
      1. 检查 --auth-state-file CLI 参数
      2. 检查默认路径 outputs/auth_state/auth_state.json
      3. 如果找到且有效, 注入到 ctx.metadata

    Args:
        ctx: PipelineContext。

    Returns:
        True 如果成功复用, False 需要重新认证。
    """
    auth_state_file = getattr(ctx.args, "auth_state_file", None)
    file_path = Path(auth_state_file) if auth_state_file else None

    auth_state = import_auth_state(file_path)
    if auth_state is None:
        return False

    if not auth_state.is_valid():
        logger.info("Auth state found but invalid, need re-authentication")
        return False

    inject_auth_state_to_context(ctx, auth_state)
    return True


def load_recon_result_from_file(file_path: Path) -> Any:
    """从 JSON 文件加载侦察结果 (不依赖 recon-pipeline 代码)。.

    pyrit-pipeline 可以独立消费 recon-pipeline 产出的 JSON 报告，
    无需安装 recon-pipeline 包。

    Args:
        file_path: 侦察报告 JSON 文件路径。

    Returns:
        ReconReport 兼容对象 (SimpleNamespace), 或 None。
    """
    from types import SimpleNamespace

    if not file_path.exists():
        logger.debug(f"Recon result file not found: {file_path}")
        return None

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)

        # 将 dict 转为属性可访问的对象 (兼容 getattr)
        def _to_namespace(obj: Any) -> Any:
            if isinstance(obj, dict):
                return SimpleNamespace(**{k: _to_namespace(v) for k, v in obj.items()})
            if isinstance(obj, list):
                return [_to_namespace(item) for item in obj]
            return obj

        report = _to_namespace(data)
        logger.info(f"Recon result loaded from {file_path}")
        return report

    except (json.JSONDecodeError, OSError, TypeError) as e:
        logger.warning(f"Failed to load recon result from {file_path}: {e}")
        return None
