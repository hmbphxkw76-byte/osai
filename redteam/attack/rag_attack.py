"""RAG 流水线攻击（向后兼容 shim）—— AI-300 Ch5: Exploiting RAG Pipelines。

**注意**：此文件为向后兼容层，实际实现已迁移到 attack/rag/ 子模块。
请使用新的导入路径：
    from redteam.attack.rag import probe_vector_dbs, inject_rag_poison, check_retrieval_leakage

保留原有 API 签名以确保向后兼容。
"""

from redteam.attack.rag import (
    probe_vector_dbs,
    RAG_POISON_PAYLOADS,
    inject_rag_poison,
    check_retrieval_leakage,
    generate_rag_findings,
    _VECTOR_DB_PATHS,
)

__all__ = [
    "probe_vector_dbs",
    "RAG_POISON_PAYLOADS",
    "inject_rag_poison",
    "check_retrieval_leakage",
    "generate_rag_findings",
    "_VECTOR_DB_PATHS",
]