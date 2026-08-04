# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""pipeline.integrations — 跨子系统集成桥接模块。.

G-09: web_redteam 等子系统与主 pipeline 的集成层。
R-T: recon_target_bridge — 从 JSON 文件加载侦察结果, 构建 HTTPTarget (文件级共享, 无代码耦合).
R-S: recon_strategy_bridge — 从侦察结果驱动 Converter 链 / Payload / 攻击序列.
R-A: auth_state_bridge — 认证状态文件级共享 (JSON), 两流水线完全独立.

**核心原则**: pyrit-pipeline 和 recon-pipeline 完全独立, 不代码耦合,
仅通过 JSON 文件传递数据 (recon 报告 / 认证状态).
"""
