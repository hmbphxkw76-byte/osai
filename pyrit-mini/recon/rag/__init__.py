# -*- coding: utf-8 -*-
"""recon/rag - RAG (Retrieval-Augmented Generation) 侦察模块

对 RAG-based 应用执行侦察:
- RAG 管道探测 (Pipeline Probe)
- 元数据解析 (Metadata Parser)
- 检索模式分析 (Retrieval Pattern Analysis)
- 知识库枚举 (Knowledge Base Enumeration)
- Embedding 维度扫描 (Embedding Dimension Scan)

模块清单:
    - pipeline_probe    : RAG 管道探测器
    - metadata_parser   : RAG 元数据解析器
    - kb_enumerator     : 知识库枚举器
    - embedding_scan    : Embedding 维度扫描器
    - typo_fuzzer       : 拼写变体模糊测试

Academic basis:
    - Greshake et al. (arXiv:2302.12173) — Indirect Prompt Injection
    - Zou et al. (arXiv:2406.04245) — PoisonedRAG
    - Kandpal et al. (arXiv:2308.14032) — Document Enumeration
    - Song et al. (arXiv:2005.09680) — Embedding Extraction Attacks

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from recon.rag.embedding_scan import (
    EmbeddingDimension,
    EmbeddingDimensionScanner,
    EmbeddingScanResult,
    scan_embedding_dimensions,
)
from recon.rag.kb_enumerator import (
    KBEnumerator,
    KBEnumResult,
    KBInfo,
    enumerate_rag_knowledge_bases,
)
from recon.rag.metadata_parser import (
    KnowledgeBaseMap,
    RAGResponseMetadata,
    RetrievalTiming,
    RetrievedChunk,
    parse_rag_response,
)
from recon.rag.pipeline_probe import (
    RAGPipelineProfile,
    run_rag_pipeline_probe,
)

__all__ = [
    # metadata_parser
    "KnowledgeBaseMap",
    "parse_rag_response",
    "RAGResponseMetadata",
    "RetrievedChunk",
    "RetrievalTiming",
    # pipeline_probe
    "RAGPipelineProfile",
    "run_rag_pipeline_probe",
    # kb_enumerator
    "KBEnumResult",
    "KBEnumerator",
    "KBInfo",
    "enumerate_rag_knowledge_bases",
    # embedding_scan
    "EmbeddingDimension",
    "EmbeddingDimensionScanner",
    "EmbeddingScanResult",
    "scan_embedding_dimensions",
]
