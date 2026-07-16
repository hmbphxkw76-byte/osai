# Surfaces 攻击面分析

本目录包含 AI 系统攻击面的分析文档，**不存储具体载荷**。
载荷统一存储在 `owasp/` 目录，通过 `surfaces` 元数据字段实现交叉引用。

## 设计原则

- **唯一真相源**: 所有载荷仅存储在 `owasp/` 目录
- **元数据交叉引用**: 每个载荷文件包含 `surfaces` 字段标注适用攻击面
- **灵活删除**: 本目录内容可随时删除，不影响载荷加载和攻击执行

## 攻击面定义

| 攻击面 | 说明 | 查询方式 |
|--------|------|----------|
| `agent` | 单/多 Agent 系统的对话面攻击 | `manager.get_payloads_by_surface("agent")` |
| `rag` | RAG 管道（知识库投毒、检索劫持） | `manager.get_payloads_by_surface("rag")` |
| `mcp` | MCP 工具协议和工具调用链 | `manager.get_payloads_by_surface("mcp")` |
| `embedding` | Embedding 向量 API | `manager.get_payloads_by_surface("embedding")` |

## 使用方式

```python
from pyrit_ai300.payloads import PayloadManager

manager = PayloadManager()
manager.load_data_dir("data/")

# 按 OWASP 分类加载（主要方式）
payloads = manager.resolve_refs(["owasp:llm:llm01"])

# 按攻击面筛选（辅助方式）
rag_payloads = manager.get_payloads_by_surface("rag")

# 按 AI-300 章节筛选
ch3_payloads = manager.get_payloads_by_chapter("Ch3")
```

## AI-300 考试映射

| 章节 | 内容 | 主要攻击面 |
|------|------|-----------|
| Ch3 | Prompt Injection, Jailbreak, System Prompt | agent |
| Ch4 | Multi-Agent, Cross-Agent | agent |
| Ch5 | RAG Security, Vector DB | rag, embedding |
| Ch6 | Embedding Attacks | embedding |
| Ch7 | MCP/Tool Security | mcp, agent |
| Ch8 | Supply Chain | agent |
