# -*- coding: utf-8 -*-
"""strike/rag - RAG/KB 投毒攻击框架 (RAG Poisoning Framework)

对 RAG-based 应用的向量数据库和知识库执行安全测试:
- 向量数据库投毒 (Vector DB poisoning)
- 知识库文档注入 (KB document injection)
- 检索操纵 (Retrieval manipulation)

模块清单:
    - vector_db_poisoner.py : 向量数据库投毒器 (VectorDBPoisoner)
    - kb_injector.py        : 知识库文档注入器 (KBInjector)

Academic basis:
    - Zou et al. (arXiv:2406.04245) — PoisonedRAG
    - Bagdasaryan et al. (arXiv:2302.10149) — Diffusion Model Backdoor
    - Greshake et al. (arXiv:2302.12173) — Indirect Prompt Injection
    - Kandpal et al. (arXiv:2308.14032) — Document Enumeration

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from strike.rag.kb_injector import (
    InjectPhase,
    KBInjectConfig,
    KBInjector,
    KBInjectResult,
    KBLocation,
    inject_kb_document,
)
from strike.rag.vector_db_poisoner import (
    PoisonConfig,
    PoisonResult,
    PoisonStrategy,
    VectorDBPoisoner,
    poison_vector_db,
)

__all__ = [
    # Vector DB Poisoner
    "VectorDBPoisoner",
    "PoisonConfig",
    "PoisonResult",
    "PoisonStrategy",
    "poison_vector_db",
    # KB Injector
    "KBInjector",
    "KBInjectConfig",
    "KBInjectResult",
    "KBLocation",
    "InjectPhase",
    "inject_kb_document",
]
