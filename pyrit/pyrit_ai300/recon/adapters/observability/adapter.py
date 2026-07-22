# -*- coding: utf-8 -*-
"""
AI-300 Framework - Observability Adapter (REV-9 / GAP-9)
可观测性测试适配器：检测审计日志完整性和行为基线监控

核心功能：
1. 审计日志完整性检测：检查目标是否有审计日志端点、日志格式规范性
2. 行为基线监控：检测异常行为告警能力
3. 数据流追踪：检测敏感数据是否被记录和可追踪
4. 映射 OWASP Agentic "Strong Observability" 原则

对齐标准：
- OWASP Agentic Top 10 (2026) — ASI09 Strong Observability
- MITRE ATLAS — Defense Evasion / Detection

使用方式：
    adapter = ObservabilityAdapter()
    result = adapter.run(
        target="http://localhost:11434",
        config={"check_endpoints": ["/audit", "/logs", "/metrics"]},
    )
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..base import BaseAdapter
from .. import AdapterResult

logger = logging.getLogger(__name__)


# ── 可观测性检测项 ──
OBSERVABILITY_CHECKS = {
    "audit_log_endpoint": {
        "description": "审计日志端点可访问性",
        "common_paths": ["/audit", "/audit/logs", "/api/audit", "/v1/audit", "/logs/audit"],
        "severity": "medium",
        "owasp_mapping": "ASI09",
    },
    "log_format_validation": {
        "description": "日志格式规范性（JSON/结构化）",
        "severity": "low",
        "owasp_mapping": "ASI09",
    },
    "behavior_monitoring": {
        "description": "行为基线异常检测能力",
        "common_paths": ["/metrics", "/health", "/status", "/monitoring"],
        "severity": "medium",
        "owasp_mapping": "ASI09",
    },
    "data_flow_tracking": {
        "description": "敏感数据流追踪能力",
        "severity": "medium",
        "owasp_mapping": "ASI09",
    },
    "rate_limit_logging": {
        "description": "速率限制日志记录",
        "common_paths": ["/rate-limit", "/throttle"],
        "severity": "low",
        "owasp_mapping": "ASI09",
    },
    "error_logging": {
        "description": "错误日志完整性",
        "severity": "low",
        "owasp_mapping": "ASI09",
    },
}


class ObservabilityAdapter(BaseAdapter):
    """
    可观测性测试适配器 (REV-9)

    检测目标的审计日志完整性、行为监控能力和数据流追踪能力。

    检测维度：
    1. 审计日志端点：检查常见的审计日志 API 端点是否可访问
    2. 日志格式：检测日志是否为结构化格式（JSON）
    3. 行为监控：检测是否有行为基线监控端点
    4. 数据流追踪：检测敏感数据处理是否有追踪记录
    5. 速率限制日志：检测速率限制事件是否被记录
    6. 错误日志：检测错误是否被完整记录
    """

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "observability"

    def check_available(self) -> bool:
        """可观测性适配器始终可用（仅 HTTP 请求，无外部依赖）"""
        return True

    def run(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> AdapterResult:
        """
        执行可观测性检测

        Args:
            target: 目标 URL
            config: 配置字典
                - check_endpoints: 自定义检测端点列表
                - timeout: 请求超时（秒）
                - auth_headers: 认证头

        Returns:
            AdapterResult 检测结果
        """
        config = config or {}
        timeout = config.get("timeout", 10)
        auth_headers = config.get("auth_headers", {})
        custom_endpoints = config.get("check_endpoints", [])

        findings: List[Dict[str, Any]] = []
        data: Dict[str, Any] = {
            "checks_performed": 0,
            "checks_passed": 0,
            "checks_failed": 0,
            "endpoints_found": [],
            "endpoints_missing": [],
            "observability_score": 0.0,
        }

        try:
            import requests
        except ImportError:
            return self._make_error_result("requests library not available")

        base_url = target.rstrip("/")

        # 执行各项检测
        for check_id, check_config in OBSERVABILITY_CHECKS.items():
            data["checks_performed"] += 1
            check_passed = False
            check_finding: Optional[Dict[str, Any]] = None

            common_paths = check_config.get("common_paths", [])
            if custom_endpoints:
                common_paths = custom_endpoints

            for path in common_paths:
                url = f"{base_url}{path}"
                try:
                    resp = requests.get(
                        url,
                        headers=auth_headers,
                        timeout=timeout,
                        allow_redirects=True,
                    )

                    if resp.status_code == 200:
                        check_passed = True
                        data["endpoints_found"].append({
                            "check": check_id,
                            "url": url,
                            "status_code": resp.status_code,
                        })

                        # 检查日志格式
                        if check_id == "log_format_validation":
                            try:
                                resp.json()
                                check_finding = {
                                    "category": "observability",
                                    "severity": "info",
                                    "description": f"日志端点返回结构化 JSON 格式: {url}",
                                    "evidence": f"HTTP {resp.status_code}, Content-Type: {resp.headers.get('Content-Type', '')}",
                                    "owasp_mapping": "ASI09",
                                    "confidence": 0.9,
                                }
                            except Exception:
                                check_finding = {
                                    "category": "observability",
                                    "severity": "low",
                                    "description": f"日志端点返回非结构化格式: {url}",
                                    "evidence": f"HTTP {resp.status_code}, non-JSON response",
                                    "owasp_mapping": "ASI09",
                                    "confidence": 0.6,
                                }
                        break

                    elif resp.status_code == 401 or resp.status_code == 403:
                        # 端点存在但需要认证
                        check_passed = True
                        data["endpoints_found"].append({
                            "check": check_id,
                            "url": url,
                            "status_code": resp.status_code,
                            "note": "requires_auth",
                        })
                        break

                except requests.RequestException:
                    continue

            if check_passed:
                data["checks_passed"] += 1
                if check_finding:
                    findings.append(check_finding)
            else:
                data["checks_failed"] += 1
                data["endpoints_missing"].append(check_id)
                # 缺少可观测性能力是一个发现
                findings.append({
                    "category": "observability_gap",
                    "severity": check_config.get("severity", "low"),
                    "description": f"缺少{check_config['description']}能力",
                    "evidence": f"未找到可访问的端点 (checked: {common_paths})",
                    "owasp_mapping": check_config.get("owasp_mapping", "ASI09"),
                    "confidence": 0.7,
                })

        # 计算可观测性评分
        if data["checks_performed"] > 0:
            data["observability_score"] = round(
                data["checks_passed"] / data["checks_performed"], 4
            )

        return AdapterResult(
            tool=self.name,
            success=True,
            data=data,
            findings=findings,
        )
