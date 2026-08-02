# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""后执行分析与证据子包。.

包含以下模块:
  - attack_result_analyzer: AttackResult 分析基类 (消除跨模块重复)
  - diversity_analyzer: 攻击多样性分析器 (Shannon 熵、覆盖度)
  - evidence_collector: 证据收集器 (结构化漏洞证据)
  - technique_name_mapper: 技术名标准化映射器

统一入口:
    from pipeline.analysis import (
        AttackResultAnalyzer,
        DiversityAnalyzer,
        EvidenceCollector,
        normalize_technique_name,
    )
"""

from pipeline.analysis.attack_result_analyzer import OWASP_LLM_CATEGORY_COUNT, AttackResultAnalyzer
from pipeline.analysis.diversity_analyzer import DiversityAnalyzer
from pipeline.analysis.evidence_collector import EvidenceCollector, get_owasp_category
from pipeline.analysis.technique_name_mapper import normalize_technique_name

__all__ = [
    # attack_result_analyzer
    "AttackResultAnalyzer",
    "OWASP_LLM_CATEGORY_COUNT",
    # diversity_analyzer
    "DiversityAnalyzer",
    # evidence_collector
    "EvidenceCollector",
    "get_owasp_category",
    # technique_name_mapper
    "normalize_technique_name",
]
