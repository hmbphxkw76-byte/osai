# RAG 攻击面分析

> **载荷查询**: `manager.get_payloads_by_surface("rag")`
> **AI-300 章节**: Ch5 (RAG Security), Ch6 (Vector DB)

## 攻击向量

### 1. 知识库投毒 (Knowledge Base Poisoning)
- **原理**: 向 RAG 知识库注入恶意文档，操纵检索结果
- **载荷文件**: `owasp/llm/llm04/rag_poison.yaml`
- **技术**: 排名操纵、命名空间遍历、数据泄露

### 2. 检索劫持 (Retrieval Hijacking)
- **原理**: 构造查询使恶意文档被优先检索
- **载荷文件**: `owasp/llm/llm04/rag_indirect_injection.yaml`
- **技术**: 相似度操纵、Top-K 利用、上下文窗口溢出

### 3. 源归因伪造 (Source Attribution Forgery)
- **原理**: 伪造知识库引用链，诱导模型输出虚假信息
- **载荷文件**: `owasp/llm/llm04/rag_source_attribution.yaml`
- **技术**: 虚假文档引用、幽灵来源链

### 4. 向量数据库攻击 (Vector DB Attacks)
- **原理**: 直接攻击向量数据库 API
- **载荷文件**: `owasp/llm/llm08/vector_weakness.yaml`
- **技术**: API 攻击、访问绕过

## 适用载荷清单

| 载荷文件 | surfaces | ai300_chapters |
|----------|----------|----------------|
| `llm/llm04/rag_poison.yaml` | rag | Ch5 |
| `llm/llm04/rag_indirect_injection.yaml` | rag | Ch5 |
| `llm/llm04/rag_source_attribution.yaml` | rag | Ch5 |
| `llm/llm08/vector_weakness.yaml` | rag, embedding | Ch5 |
| `llm/llm08/cve_2026_45829_chromadb_rce.yaml` | rag, embedding | Ch5 |
| `llm/llm08/embedding_inversion_practical.yaml` | embedding, rag | Ch6 |
| `llm/llm09/misinformation.yaml` | agent, rag | Ch5 |
| `llm/llm09/hallucination_exploitation.yaml` | agent, rag | Ch3 |
| `llm/llm09/citation_elicitation.yaml` | agent, rag | Ch3 |
| `llm/llm10/resource_exhaustion.yaml` | agent, rag | Ch3 |
| `llm/llm01/indirect_injection.yaml` | rag, agent | Ch3 |
| `llm/llm01/cve_2025_32711_m365_echoleak.yaml` | agent, rag | Ch3 |
| `agentic/asi06.yaml` | agent, rag | Ch3 |
