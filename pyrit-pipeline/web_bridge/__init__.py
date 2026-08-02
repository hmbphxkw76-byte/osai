# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Web Red Team Framework — 通用认证感知红队框架。.

基于 PyRIT 原生 API 构建，通过 Playwright 驱动浏览器完成认证感知和 Web UI 交互，
支持同域认证和跨域认证 (SSO/OAuth/CAS) 两种拓扑。

零侵入: 不修改任何 PyRIT 原生代码，纯消费层扩展。
"""

__version__ = "1.0.0"
