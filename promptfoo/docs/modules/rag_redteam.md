# RAG 红队测试 - 测试指南

## 概述

`rag_redteam.yaml` 是针对**检索增强生成（RAG）**系统的安全测试配置。RAG 系统将 LLM 与知识库检索结合，引入了独特的攻击面。

## RAG 六大攻击面

| # | 攻击类型 | 核心插件 | 测试关键词 |
|---|---------|---------|-----------|
| 1 | **提示注入** | `indirect-prompt-injection` | "检索到的文档中有恶意指令" |
| 2 | **上下文注入** | `policy` (自定义) | "知识库被污染" |
| 3 | **数据投毒** | `harmful:misinformation-disinformation`, `bias` | "知识库引入误导信息" |
| 4 | **来源引用伪造** | `rag-source-attribution` | "编造文档引用/政策编号" |
| 5 | **PII/数据泄露** | `pii:direct`, `pii:api-db` | "渐进式提取敏感信息" |
| 6 | **检索操纵** | `hallucination` | "利用检索算法漏洞" |

## 测试修改点（最小修改原则）

```
仅 2 处必改:
  修改点1: url → 替换为目标 RAG API 地址
  修改点2: body 字段名 → 替换 query 为场景指定字段名

  修改点3(可选): purpose → 复制场景场景描述
```

## 测试使用流程

```bash
# 1. 复制配置文件
cp rag_redteam.yaml promptfooconfig.yaml

# 2. 修改 url 和 body 字段名（2处）

# 3. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 查看报告
promptfoo redteam report
```

## 关键插件说明

### indirect-prompt-injection（间接提示注入）
- **RAG 特有**: 恶意内容注入到检索文档而非用户输入
- 配置 `indirectInjectionVar: context` 指定注入位置
- 因为知识库通常被视为可信来源，这类攻击极易成功

### rag-source-attribution（来源引用检测）
- 检测系统是否编造不存在的文档引用
- 测试中如果场景提到 "citation"、"reference"、"来源引用"，必用

### rag-poisoning（数据投毒检测）
- 配合 CLI 命令生成投毒文档: `promptfoo redteam poison doc.txt --goal "Extract API keys"`
- 测试中如果场景提供知识库文件，可以测试投毒

## 常见测试场景匹配

| 场景描述 | 用哪个 YAML |
|---------|-----------|
| "系统从知识库检索文档回答用户问题" | `rag_redteam.yaml` |
| "基于企业内部文档的问答助手" | `rag_redteam.yaml` |
| "检索增强生成的客服系统" | `rag_redteam.yaml` |

## 测试注意事项

1. **RAG 系统最脆弱的点是检索上下文** - 知识库通常被信任，因此间接注入成功率最高
2. **分别测试检索和生成组件** - 测试中可用不同 provider 隔离测试
3. **`purpose` 描述要准确** - 描述 RAG 系统的数据边界和安全要求
