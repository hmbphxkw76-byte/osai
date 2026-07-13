"""基础设施攻击模块（向后兼容 shim）—— AI-300 Ch9: Infrastructure Attacks on AI Systems。

**注意**：此文件为向后兼容层，实际实现已迁移到 attack/infra/ 子模块。
请使用新的导入路径：
    from redteam.attack.infra import scan_cloud_misconfigs, generate_infra_findings

保留原有 API 签名以确保向后兼容。
"""

from redteam.attack.infra import (
    scan_cloud_misconfigs,
    check_supply_chain_risks,
    generate_infra_findings,
    _extract_context,
    _CLOUD_AI_CHECK_PATTERNS,
)

__all__ = [
    "scan_cloud_misconfigs",
    "check_supply_chain_risks",
    "generate_infra_findings",
    "_extract_context",
    "_CLOUD_AI_CHECK_PATTERNS",
]