# -*- coding: utf-8 -*-
"""
web_orchestrator.py - Web攻击统一编排器

整合所有Web攻击模块，提供统一的Web应用安全评估入口。
遵循宪法C1：Glue代码为连接原生组件的三类自研代码。

重构改进:
- 移除run_targeted_attack的lambda映射（过度设计）
- 简化为直接方法调用
- 代码量从166行减少到约100行（减少40%）

Academic basis:
    - Zeng et al. (arXiv:2402.19181): Enterprise AI attack surfaces
    - PyRIT (arXiv:2407.01232): Native attack framework
    - OWASP LLM Top 10 2025: Enterprise deployment risks

版本: v3.0 (2026-09-08 扁平化到 strike/)
"""

from __future__ import annotations

import logging
from typing import Any

from pyrit.prompt_target import HTTPTarget

from strike.evasion.audit import AuditEvasionAttacks
from strike.injection.auth_attacks import AuthAttacks
from strike.web.attacks import WebAttacks

logger = logging.getLogger(__name__)


class WebAttackOrchestrator:
    """Web攻击统一编排器

    整合所有Web攻击模块，提供统一入口。

    使用方式:
        orchestrator = WebAttackOrchestrator(
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
            target_endpoint: 目标API endpoint
            adversarial_target: PyRIT adversarial chat target
            scoring_target: PyRIT scoring target
        """
        self.target_endpoint = target_endpoint
        self.adversarial_target = adversarial_target
        self.scoring_target = scoring_target

        self.http_target = HTTPTarget(endpoint=target_endpoint)

        # 初始化攻击模块
        self.auth_attacks = AuthAttacks(
            target_endpoint=target_endpoint,
            adversarial_target=adversarial_target,
            scoring_target=scoring_target,
        )
        self.web_attacks = WebAttacks(
            target_endpoint=target_endpoint,
        )
        self.audit_attacks = AuditEvasionAttacks(
            pyrit_target=self.http_target,
        )

    def run_full_assessment(
        self,
        target_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """运行完整的Web应用安全评估

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
        auth_results = self.auth_attacks.run_all_auth_attacks(target_info)
        results["attacks"].extend(auth_results)

        # 2. Web应用攻击
        results["attacks"].extend(
            [
                self.web_attacks.rate_limit_test(),
                self.web_attacks.request_smuggling_attack(),
                self.web_attacks.cache_poisoning_attack(),
                self.web_attacks.http_method_tampering_attack(),
                self.web_attacks.header_injection_attack(),
                self.web_attacks.api_version_bypass_attack(),
            ]
        )

        # 3. 审计逃逸攻击
        results["attacks"].append(self.audit_attacks.log_injection_attack())

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
            attack_category: 攻击类别 ("auth", "web", "audit")
            **kwargs: 攻击参数

        Returns:
            攻击结果
        """
        if attack_category == "auth":
            return self.auth_attacks.run_all_auth_attacks(kwargs)
        if attack_category == "web":
            return self.web_attacks.rate_limit_test(**kwargs)
        if attack_category == "audit":
            return self.audit_attacks.log_injection_attack(**kwargs)
        return {"error": f"Unknown attack category: {attack_category}"}
