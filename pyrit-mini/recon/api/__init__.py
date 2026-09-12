# -*- coding: utf-8 -*-
"""recon/api - API 通用侦察模块

对 HTTP API 执行通用侦察:
- 认证检测 (Auth Detection)
- 端点排序 (Endpoint Sorting)
- OpenAPI 发现 (OpenAPI Discovery)
- 递归展开 (Recursive Expansion)
- SSE 解析 (SSE Parser)
- 自适应探测配置 (Adaptive Probe Config)

模块清单:
    - auth_detector     : 认证机制检测器
    - endpoint_sorter   : 端点价值排序器
    - openapi_discoverer: OpenAPI 发现器
    - recursive_expander: 递归端点展开器
    - sse_parser        : SSE 响应解析器
    - adaptive_config   : 自适应探测配置

Academic basis:
    - OWASP API Security Top 10 2023
    - fielding (arXiv:2108.13321) — API Security Testing Patterns

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from recon.api.adaptive_config import compute_probe_budget
from recon.api.auth_detector import AuthDetector, AuthState, decode_jwt_payload
from recon.api.endpoint_sorter import (
    ClassificationResult,
    classify_http_content,
    sort_burp_list_by_priority,
    sort_endpoints_by_priority,
)
from recon.api.openapi_discoverer import (
    OpenAPIDiscovery,
    OpenAPIEndpoint,
    build_openapi_attack_seeds,
    discover_openapi_spec,
)
from recon.api.recursive_expander import (
    ExpansionPlan,
    analyze_for_expansion,
    execute_recursive_expansion,
    run_recursive_probe,
)

# sse_parser exposes only private helpers — not re-exported at package level

__all__ = [
    # adaptive_config
    "compute_probe_budget",
    # auth_detector
    "AuthDetector",
    "AuthState",
    "decode_jwt_payload",
    # endpoint_sorter
    "ClassificationResult",
    "sort_burp_list_by_priority",
    "sort_endpoints_by_priority",
    "classify_http_content",
    # openapi_discoverer
    "OpenAPIEndpoint",
    "OpenAPIDiscovery",
    "discover_openapi_spec",
    "build_openapi_attack_seeds",
    # recursive_expander
    "ExpansionPlan",
    "analyze_for_expansion",
    "run_recursive_probe",
    "execute_recursive_expansion",
]
