"""RAG 流水线攻击模块（AI-300 Ch5: Exploiting RAG Pipelines）。

覆盖 AI-300 课程 Ch5 的完整攻击技术：
  - vector_db.py: 向量数据库端点探测（Qdrant/Chroma/Weaviate/Pinecone/Milvus）
  - knowledge_poison.py: RAG 知识库投毒（排名操纵/命名空间遍历/嵌入混淆/间接注入）
  - retrieval_leak.py: 检索泄露检测（跨命名空间数据泄露）
  - cross_tenant.py: 跨租户数据泄露检测（多租户隔离测试）
  - findings.py: Findings 生成（对齐 OWASP LLM Top 10）

Library-First：执行层委托 httpx，载荷资产自研。
技术来源：Adapted from mcp-attack-labs/labs/04-rag-security/
"""

from .vector_db import (
    probe_vector_dbs,
    _VECTOR_DB_PATHS,
)
from .knowledge_poison import (
    RAG_POISON_PAYLOADS,
    RAG_INDIRECT_INJECTION_PAYLOADS,
    _ADVERSARIAL_EMBEDDING_PAYLOADS,
    inject_rag_poison,
    inject_rag_indirect,
    inject_adversarial_embedding,
)
from .retrieval_leak import (
    check_retrieval_leakage,
)
from .cross_tenant import (
    CROSS_TENANT_PROBES,
    check_cross_tenant_leakage,
)
from .findings import (
    generate_rag_findings,
)

__all__ = [
    # 向量数据库探测
    "probe_vector_dbs",
    "_VECTOR_DB_PATHS",
    # 知识库投毒
    "RAG_POISON_PAYLOADS",
    "RAG_INDIRECT_INJECTION_PAYLOADS",
    "_ADVERSARIAL_EMBEDDING_PAYLOADS",
    "inject_rag_poison",
    "inject_rag_indirect",
    "inject_adversarial_embedding",
    # 检索泄露检测
    "check_retrieval_leakage",
    # 跨租户数据泄露
    "CROSS_TENANT_PROBES",
    "check_cross_tenant_leakage",
    # Findings 生成
    "generate_rag_findings",
]