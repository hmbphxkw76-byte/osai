# -*- coding: utf-8 -*-
"""
glue/ - 企业AI红队Glue代码层（精简版）

连接专用工具（PyJWT、HTTP工具等）与PyRIT原生框架。
遵循宪法C1条款：Glue代码为连接原生组件的三类自研代码之一。

仅保留可通过HTTP端点黑盒测试的攻击模块：
- enterprise_auth_glue: 认证攻击Glue（JWT/OAuth/Session）
- api_gateway_glue: API Gateway攻击Glue（速率限制/请求走私/缓存投毒）
- audit_evasion_glue: 审计逃逸Glue（日志注入）
- enterprise_orchestrator: 企业攻击统一编排器

已移除模块（黑盒场景100%无效）：
- vector_db_glue: 需要向量DB SDK直接访问，通过间接注入seed覆盖
- fine_tuning_glue: 需要训练环境API访问，通过间接注入seed覆盖

Academic basis:
    - Zeng et al. (arXiv:2402.19181): Enterprise AI attack surfaces
    - Greshake et al. (arXiv:2302.12173): RAG poisoning attacks
    - PyRIT (arXiv:2407.01232): Native attack framework

版本: v1.1 (2026-09-08 精简)
"""

from __future__ import annotations

__version__ = "1.1.0"
__all__ = [
    "EnterpriseAuthGlue",
    "APIGatewayGlue",
    "AuditEvasionGlue",
    "EnterpriseAttackOrchestrator",
]

def __getattr__(name: str) -> object:
    """延迟导入 - 避免循环导入和未用依赖。"""
    if name == "EnterpriseAuthGlue":
        from glue.enterprise_auth_glue import EnterpriseAuthGlue
        return EnterpriseAuthGlue
    if name == "APIGatewayGlue":
        from glue.api_gateway_glue import APIGatewayGlue
        return APIGatewayGlue
    if name == "AuditEvasionGlue":
        from glue.audit_evasion_glue import AuditEvasionGlue
        return AuditEvasionGlue
    if name == "EnterpriseAttackOrchestrator":
        from glue.enterprise_orchestrator import EnterpriseAttackOrchestrator
        return EnterpriseAttackOrchestrator
    raise AttributeError(f"module 'glue' has no attribute {name!r}")
