# -*- coding: utf-8 -*-
"""recon/embedding - Embedding 模型侦察模块

对 Embedding API 执行侦察:
- 向量维度探测 (Vector Dimension Probe)
- 嵌入空间边界测试 (Embedding Space Boundary Testing)

模块清单:
    - vector_probe      : 向量探测器

Academic basis:
    - Qi et al. (arXiv:2302.10149) — Universal Adversarial Triggers
    - Carlini et al. (arXiv:2102.12520) — Extracting Training Data

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
    - R-S1 (Embedding): 仅注册结果不执行黑盒 HTTP 不可测试内容
"""

from recon.embedding.vector_probe import (
    EmbeddingVectorProbe,
    VectorProbeResult,
    probe_embedding_vector,
)

__all__ = [
    # vector_probe
    "EmbeddingVectorProbe",
    "VectorProbeResult",
    "probe_embedding_vector",
]
