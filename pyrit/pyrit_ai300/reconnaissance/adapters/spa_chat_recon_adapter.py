# -*- coding: utf-8 -*-
"""
SPA Chat Recon Adapter - 向后兼容 shim

原 6163 行单文件已模块化拆分到 spa_chat/ 包目录：
  - constants.py          : 常量定义（选择器/关键词/模式，~2050 行）
  - traffic_capture.py    : 网络流量捕获（NetworkTrafficCapture，~316 行）
  - auth_mixin.py         : 认证 Mixin（SSO/credentials/preflight/captcha，~1373 行）
  - dom_mixin.py          : DOM 侦测 Mixin（选择器评分/自动检测，~752 行）
  - chat_entry_mixin.py   : 聊天入口点击 Mixin（~468 行）
  - probe_mixin.py        : 探测消息 + LLM 信息提取 Mixin（~432 行）
  - adapter.py            : SPAChatReconAdapter 主类（编排逻辑，~954 行）

此文件仅用于向后兼容，所有实际代码已迁移到 spa_chat/ 包。
"""

# 从新包重新导出所有公共接口
from .spa_chat import SPAChatReconAdapter, NetworkTrafficCapture
from .spa_chat.constants import (
    LLM_PATH_KEYWORDS,
    LLM_BODY_FIELDS,
    LLM_RESPONSE_FIELDS,
    RAG_PATH_KEYWORDS,
    DEFAULT_CHAT_ENTRY_SELECTORS,
    CHAT_URL_PATTERNS,
    CHAT_PAGE_DOM_FEATURES,
    CAPTCHA_SELECTORS,
    OIDC_CALLBACK_PATTERNS,
    WAF_SAFE_DELAYS,
    LOGIN_PAGE_PATTERNS,
    OIDC_CALLBACK_WHITELIST,
    LOGIN_PAGE_DOM_FEATURES,
    HIGH_CONFIDENCE_CHAT_URL_PATTERNS,
    AI_APP_TYPE_RULES,
    GENERIC_SELECTOR_CATEGORY_NUMBERS,
    HIGH_SIGNAL_DOM_FEATURES,
    SCORE_WEIGHTS,
    SIGNAL_KEYWORDS,
    ROLE_TO_SNAPSHOT_KEY,
    PROBE_MESSAGES,
    MODEL_FAMILY_PATTERNS,
)

__all__ = [
    "SPAChatReconAdapter",
    "NetworkTrafficCapture",
]
