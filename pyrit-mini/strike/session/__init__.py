# -*- coding: utf-8 -*-
"""strike/session - 会话感知攻击框架 (Session-Aware Attack Framework)

为任意 stateful agent 提供通用的会话状态管理能力。
通过配置驱动，支持 JSON/Header/Cookie 等多种会话追踪方式。

架构对齐:
    - PyRIT 原生优先: 利用 HTTPTarget.callback_function 机制
    - 配置驱动: YAML 定义提取/注入规则
    - 通用适配: 不硬编码任何特定 agent 格式

模块清单:
    - session_config.py     : 配置模型 (SessionConfig, ExtractionRule, InjectionRule)
    - session_manager.py    : 会话状态管理器 (SessionStateManager) SSOT
    - extraction.py         : 状态提取器 (SessionExtractor)
    - injection.py          : 状态注入器 (SessionInjector)
    - validation.py         : 会话一致性验证 (SessionValidator)
    - rotation.py           : 轮换策略 (SessionRotationPolicy)
    # Agent Memory Attack modules (P0)
    - session_id_analyzer.py: Session ID 可预测性分析器 (Pattern/Risk analysis)
    - session_enumerator.py : Session ID 自动枚举器 (Automated probing)
    - idor_tester.py        : IDOR 漏洞验证器 (Cross-user access)
    - session_brute_forcer.py: 智能暴力破解器 (Smart brute-force)

Academic basis:
    - Perez et al. (arXiv:2202.03286) — Session-based attack persistence
    - Russinovich et al. (arXiv:2404.01833) — Crescendo multi-turn state tracking

Constitution compliance:
    - R-SIZE: 每模块 < 300 行
    - R-H3: 单一职责，无双重实现
    - R-SESSION: 会话感知架构完整性
"""

# 会话枚举攻击引擎 (ASI09)
from strike.session.enumerator import (
    EnumerationFinding,
    EnumerationRequestBuilder,
    ResponseCategory,
    ResponseClassifier,
    SessionEnumerationReport,
    SessionIDGenerator,
    SessionIDPattern,
    SessionPatternInferer,
)
from strike.session.idor_tester import (
    AccessType,
    IdorConfig,
    IdorResult,
    IdorTester,
    Severity,
    test_idor_via_session,
)
from strike.session.session_brute_forcer import (
    BruteConfig,
    BruteResult,
    BruteStrategy,
    SessionBruteForcer,
)
from strike.session.session_config import (
    ExtractionRule,
    InjectionRule,
    RotationPolicy,
    SessionConfig,
    SessionEnumerationConfig,
    SessionValidationConfig,
)
from strike.session.session_enumerator import (
    EnumerationConfig,
    EnumerationResult,
    EnumStrategy,
    ProbeMethod,
    ProbeResult,
    SessionEnumerationSuite,
    SessionEnumerator,
)

# Agent Memory Attack modules (P0)
from strike.session.session_id_analyzer import (
    AnalysisResult,
    PatternType,
    RiskLevel,
    SessionIDAnalyzer,
    analyze_session_ids,
)
from strike.session.session_manager import SessionStateManager

__all__ = [
    "SessionConfig",
    "ExtractionRule",
    "InjectionRule",
    "SessionValidationConfig",
    "RotationPolicy",
    "SessionEnumerationConfig",
    "SessionStateManager",
    # 会话枚举引擎
    "EnumerationFinding",
    "EnumerationRequestBuilder",
    "ResponseCategory",
    "ResponseClassifier",
    "SessionEnumerationReport",
    "SessionIDGenerator",
    "SessionIDPattern",
    "SessionPatternInferer",
    # Agent Memory Attack — Session ID Analysis
    "SessionIDAnalyzer",
    "PatternType",
    "RiskLevel",
    "AnalysisResult",
    "analyze_session_ids",
    # Agent Memory Attack — Session Enumeration
    "SessionEnumerator",
    "EnumerationConfig",
    "EnumerationResult",
    "EnumStrategy",
    "ProbeMethod",
    "ProbeResult",
    "SessionEnumerationSuite",
    # Agent Memory Attack — IDOR Testing
    "IdorTester",
    "IdorConfig",
    "IdorResult",
    "AccessType",
    "Severity",
    "test_idor_via_session",
    # Agent Memory Attack — Brute Forcing
    "SessionBruteForcer",
    "BruteConfig",
    "BruteResult",
    "BruteStrategy",
]
