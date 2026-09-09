# -*- coding: utf-8 -*-
"""strike/memory - 持久化内存攻击框架 (Agent Memory Attack Framework)

对 stateful agent 的持久化存储 (笔记/记忆/知识库) 执行安全测试:
- 跨会话数据读取 (Cross-session data read)
- 持久指令注入 (Persistent prompt injection)
- 取证证据收集 (Forensic evidence collection)

模块清单:
    - memory_reader.py      : 跨会话数据读取器 (MemoryReader)
    - memory_injector.py    : 持久指令注入器 (MemoryInjector)
    - forensics_extractor.py: 取证数据收集器 (ForensicsExtractor)

Academic basis:
    - Greshake et al. (arXiv:2302.12173) — Indirect Prompt Injection
    - Zou et al. (arXiv:2406.04245) — PoisonedRAG
    - Shayegani et al. (arXiv:2306.13254) — Multi-modal cyber security
    - OWASP ASI09:2025 — Trust Boundary Violation

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from strike.memory.forensics_extractor import (
    EvidenceType,
    ForensicEvidence,
    ForensicsConfig,
    ForensicsExtractor,
    generate_forensics_summary,
)
from strike.memory.memory_injector import (
    InjectionConfig,
    InjectionResult,
    InjectStrategy,
    InjectTarget,
    MemoryInjector,
    inject_memory_payload,
)
from strike.memory.memory_reader import (
    DataType,
    MemoryReadConfig,
    MemoryReader,
    MemoryReadResult,
    SessionData,
    read_cross_session_memory,
)

__all__ = [
    # Memory Reader
    "MemoryReader",
    "MemoryReadConfig",
    "MemoryReadResult",
    "SessionData",
    "DataType",
    "read_cross_session_memory",
    # Memory Injector
    "MemoryInjector",
    "InjectionConfig",
    "InjectionResult",
    "InjectTarget",
    "InjectStrategy",
    "inject_memory_payload",
    # Forensics Extractor
    "ForensicsExtractor",
    "ForensicsConfig",
    "ForensicEvidence",
    "EvidenceType",
    "generate_forensics_summary",
]
