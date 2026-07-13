"""AI 供应链攻击模块（AI-300 Ch8: Supply Chain Attacks on AI/ML Systems）。

覆盖 AI-300 课程 Ch8 的完整攻击技术：
  - hf_model.py: HuggingFace 模型来源可信度检查
  - pickle_risk.py: Pickle 反序列化 RCE 风险检测
  - dataset_poison.py: 数据集投毒风险检测
  - dependency.py: 依赖攻击风险检测
  - findings.py: Findings 生成（对齐 OWASP LLM Top 10）

Library-First：执行层委托 httpx，载荷资产自研。
"""

from .hf_model import (
    detect_hf_model_source,
    _TRUSTED_MODEL_SOURCES,
    _HIGH_RISK_SOURCES,
)
from .pickle_risk import (
    check_pickle_deserialization_risk,
    _PICKLE_RISK_PATTERNS,
)
from .dataset_poison import (
    check_dataset_poisoning_risks,
    _extract_context,
)
from .dependency import (
    check_dependency_risks,
)
from .findings import (
    generate_supply_chain_findings,
)

__all__ = [
    # HuggingFace 模型来源检测
    "detect_hf_model_source",
    "_TRUSTED_MODEL_SOURCES",
    "_HIGH_RISK_SOURCES",
    # Pickle 反序列化检测
    "check_pickle_deserialization_risk",
    "_PICKLE_RISK_PATTERNS",
    # 数据集投毒检测
    "check_dataset_poisoning_risks",
    "_extract_context",
    # 依赖风险检测
    "check_dependency_risks",
    # Findings 生成
    "generate_supply_chain_findings",
]