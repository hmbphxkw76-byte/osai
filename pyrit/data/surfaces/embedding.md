# Embedding 攻击面分析

> **载荷查询**: `manager.get_payloads_by_surface("embedding")`
> **AI-300 章节**: Ch6 (Embedding Attacks)

## 攻击向量

### 1. 嵌入反演 (Embedding Inversion)
- **原理**: 从向量重建原始文本
- **载荷文件**: `owasp/llm/llm08/embedding_inversion_practical.yaml`
- **技术**: 多查询渐进式反演、梯度辅助反演

### 2. 成员推断 (Membership Inference)
- **原理**: 判断特定数据是否在训练集中
- **载荷文件**: `owasp/llm/llm08/embedding_inversion_practical.yaml`
- **技术**: 统计成员推断、困惑度成员推断

### 3. 属性推断 (Attribute Inference)
- **原理**: 从向量预测元数据
- **载荷文件**: `owasp/llm/llm08/embedding_inversion_practical.yaml`
- **技术**: 多轮属性推断

### 4. 向量相似度操纵
- **原理**: 构造高相似度对抗文档
- **载荷文件**: `owasp/llm/llm08/adversarial_embedding.yaml`
- **技术**: 相似度钓鱼、对抗嵌入

### 5. 向量数据库 API 利用
- **原理**: 直接攻击向量数据库端点
- **载荷文件**: `owasp/llm/llm08/vector_weakness.yaml`
- **技术**: API 攻击、访问绕过

## 适用载荷清单

| 载荷文件 | surfaces | ai300_chapters |
|----------|----------|----------------|
| `llm/llm08/embedding_inversion_practical.yaml` | embedding, rag | Ch6 |
| `llm/llm08/adversarial_embedding.yaml` | embedding | Ch6 |
| `llm/llm08/vector_weakness.yaml` | rag, embedding | Ch5 |
| `llm/llm08/cve_2026_45829_chromadb_rce.yaml` | rag, embedding | Ch5 |
| `llm/llm08/embedding_verify.yaml` | embedding | Ch6 |
| `llm/llm02/training_data_extraction.yaml` | agent, embedding | Ch3 |
