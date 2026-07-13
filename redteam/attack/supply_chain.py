"""AI 供应链攻击模块（向后兼容 shim）—— AI-300 Ch8: Supply Chain Attacks on AI/ML Systems。

**注意**：此文件为向后兼容层，实际实现已迁移到 attack/supply_chain/ 子模块。
请使用新的导入路径：
    from redteam.attack.supply_chain import detect_hf_model_source, check_pickle_deserialization_risk

保留原有 API 签名以确保向后兼容。
"""

from redteam.attack.supply_chain import (
    detect_hf_model_source,
    check_pickle_deserialization_risk,
    check_dataset_poisoning_risks,
    check_dependency_risks,
    generate_supply_chain_findings,
    _TRUSTED_MODEL_SOURCES,
    _HIGH_RISK_SOURCES,
    _PICKLE_RISK_PATTERNS,
    _extract_context,
)

__all__ = [
    "detect_hf_model_source",
    "check_pickle_deserialization_risk",
    "check_dataset_poisoning_risks",
    "check_dependency_risks",
    "generate_supply_chain_findings",
    "_TRUSTED_MODEL_SOURCES",
    "_HIGH_RISK_SOURCES",
    "_PICKLE_RISK_PATTERNS",
    "_extract_context",
]