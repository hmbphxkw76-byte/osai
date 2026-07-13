"""基础设施攻击模块（AI-300 Ch9: Infrastructure Attacks on AI Systems）。

覆盖 AI-300 课程 Ch9 的完整攻击技术：
  - cloud_misconfig.py: 云 AI 服务配置错误检测（S3/GCS/Azure Blob/IAM）
  - findings.py: Findings 生成（对齐 OWASP LLM Top 10）

Library-First：执行层委托 httpx，载荷资产自研。
"""

from .cloud_misconfig import (
    scan_cloud_misconfigs,
    check_supply_chain_risks,
    _extract_context,
    _CLOUD_AI_CHECK_PATTERNS,
)
from .findings import (
    generate_infra_findings,
)

__all__ = [
    # 云配置错误检测
    "scan_cloud_misconfigs",
    # 供应链风险检测
    "check_supply_chain_risks",
    # 辅助函数
    "_extract_context",
    "_CLOUD_AI_CHECK_PATTERNS",
    # Findings 生成
    "generate_infra_findings",
]