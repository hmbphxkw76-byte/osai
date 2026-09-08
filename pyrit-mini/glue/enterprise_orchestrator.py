# -*- coding: utf-8 -*-
"""
enterprise_orchestrator.py - 企业AI红队统一编排器（精简版）

整合保留的Glue模块，提供统一的企业AI红队评估入口。
遵循宪法C1：Glue代码为连接原生组件的三类自研代码。

仅编排可通过HTTP端点黑盒测试的攻击模块：
- auth: JWT/OAuth认证攻击
- gateway: 速率限制/请求走私/缓存投毒
- audit: 日志注入

Academic basis:
    - Zeng et al. (arXiv:2402.19181): Enterprise AI attack surfaces
    - PyRIT (arXiv:2407.01232): Native attack framework
    - OWASP LLM Top 10 2025: Enterprise deployment risks

版本: v1.1 (2026-09-08 精简)
"""

from __future__ import annotations

import logging
from typing import Any

from pyrit.prompt_target import HTTPTarget

from glue.api_gateway_glue import APIGatewayGlue
from glue.audit_evasion_glue import AuditEvasionGlue
from glue.enterprise_auth_glue import EnterpriseAuthGlue

logger = logging.getLogger(__name__)

class EnterpriseAttackOrchestrator:
    """企业AI红队统一编排器（精简版）

    整合保留的3个Glue模块，提供统一入口。

    使用方式：
        orchestrator = EnterpriseAttackOrchestrator(
            target_endpoint="https://api.enterprise.com/v1/chat",
            adversarial_target=pyrit_adversarial_target,
            scoring_target=pyrit_scoring_target,
        )
        results = orchestrator.run_full_assessment()
    """

    def __init__(
        self,
        target_endpoint: str,
        adversarial_target: Any = None,
        scoring_target: Any = None,
    ):
        """
        Args:
            target_endpoint: 企业API endpoint
            adversarial_target: PyRIT adversarial chat target
            scoring_target: PyRIT scoring target
        """
        self.target_endpoint = target_endpoint
        self.adversarial_target = adversarial_target
        self.scoring_target = scoring_target

        # PyRIT原生HTTPTarget
        self.http_target = HTTPTarget(endpoint=target_endpoint)

        # 初始化保留的Glue模块
        self.auth_glue = EnterpriseAuthGlue(
            target_endpoint=target_endpoint,
            adversarial_target=adversarial_target,
            scoring_target=scoring_target,
        )
        self.gateway_glue = APIGatewayGlue(
            target_endpoint=target_endpoint,
            pyrit_target=self.http_target,
        )
        self.audit_glue = AuditEvasionGlue(
            pyrit_target=self.http_target,
        )

    def run_full_assessment(
        self,
        target_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """运行完整的企业AI红队评估（仅黑盒可测试攻击）
        Academic basis:
            - Zeng et al. (arXiv:2402.19181): Multi-vector enterprise attacks

        Args:
            target_info: 目标信息（JWT、OAuth等）

        Returns:
            完整评估结果
        """
        if target_info is None:
            target_info = {}

        results: dict[str, Any] = {
            "target_endpoint": self.target_endpoint,
            "attacks": [],
            "summary": {},
        }

        # 1. 认证攻击
        auth_results = self.auth_glue.run_all_auth_attacks(target_info)
        results["attacks"].extend(auth_results)

        # 2. API Gateway攻击 (P2-1 增强)
        rate_limit = self.gateway_glue.rate_limit_test()
        smuggling = self.gateway_glue.request_smuggling_attack()
        cache_poison = self.gateway_glue.cache_poisoning_attack()
        http_tamper = self.gateway_glue.http_method_tampering_attack()
        header_inject = self.gateway_glue.header_injection_attack()
        version_bypass = self.gateway_glue.api_version_bypass_attack()
        results["attacks"].extend([
            rate_limit, smuggling, cache_poison,
            http_tamper, header_inject, version_bypass,
        ])

        # 3. 审计逃逸攻击（P2-3 增强）
        log_injection = self.audit_glue.log_injection_attack()
        results["attacks"].append(log_injection)

        # 汇总
        results["summary"] = {
            "total_attacks": len(results["attacks"]),
            "attack_types": [a.get("attack_type") for a in results["attacks"]],
        }

        return results

    def run_targeted_attack(
        self,
        attack_category: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """运行特定类别的攻击

        Args:
            attack_category: 攻击类别 ("auth", "gateway", "audit")
            **kwargs: 攻击参数

        Returns:
            攻击结果
        """
        # P2-4 增强: 新增攻击类别映射
        attack_map = {
            "auth": lambda: self.auth_glue.run_all_auth_attacks(kwargs),
            "auth_jwt_jwk": lambda: self.auth_glue.jwt_jwk_injection_attack(**kwargs),
            "auth_jwt_x5u": lambda: self.auth_glue.jwt_x5u_bypass_attack(**kwargs),
            "auth_jwt_typ": lambda: self.auth_glue.jwt_typ_manipulation_attack(**kwargs),
            "auth_session": lambda: self.auth_glue.session_fixation_attack(**kwargs),
            "gateway": lambda: self.gateway_glue.rate_limit_test(**kwargs),
            "gateway_smuggling": lambda: self.gateway_glue.request_smuggling_attack(),
            "gateway_cache": lambda: self.gateway_glue.cache_poisoning_attack(),
            "gateway_http_tamper": lambda: self.gateway_glue.http_method_tampering_attack(),
            "gateway_header_inject": lambda: self.gateway_glue.header_injection_attack(),
            "gateway_version_bypass": lambda: self.gateway_glue.api_version_bypass_attack(),
            "audit": lambda: self.audit_glue.log_injection_attack(**kwargs),
        }

        attack_func = attack_map.get(attack_category)
        if attack_func:
            return attack_func()
        return {"error": f"Unknown attack category: {attack_category}"}
