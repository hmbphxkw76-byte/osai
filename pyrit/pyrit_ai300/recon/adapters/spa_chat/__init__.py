# -*- coding: utf-8 -*-
"""
SPA Chat Recon 模块化包

从 spa_chat_recon_adapter.py（原 6163 行）模块化拆分而来。

模块结构：
    constants.py          - 常量定义（选择器/关键词/模式，~2050 行）
    traffic_capture.py    - 网络流量捕获（NetworkTrafficCapture，~316 行）
    auth_mixin.py         - 认证 Mixin（SSO/credentials/preflight/captcha，~1373 行）
    dom_mixin.py          - DOM 侦测 Mixin（选择器评分/自动检测，~752 行）
    chat_entry_mixin.py   - 聊天入口点击 Mixin（~468 行）
    probe_mixin.py        - 探测消息 + LLM 信息提取 Mixin（~432 行）
    adapter.py            - SPAChatReconAdapter 主类（编排逻辑，~954 行）

向后兼容：
    from pyrit_ai300.recon.adapters.spa_chat import SPAChatReconAdapter
    # 等价于旧的:
    from pyrit_ai300.recon.adapters.spa_chat import SPAChatReconAdapter
"""

from .adapter import SPAChatReconAdapter
from .traffic_capture import NetworkTrafficCapture

__all__ = [
    "SPAChatReconAdapter",
    "NetworkTrafficCapture",
]

__version__ = "1.5.0"
