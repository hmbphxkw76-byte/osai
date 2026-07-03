# Promptfoo 红队测试 - OffSec AI-300 / OSAI 考试备考

> **核心原则**: 100% 使用 promptfoo 框架原生 YAML 配置，零 Python 依赖  
> **考试修改量**: 仅改 2 处（URL + 字段名），其他全部预设好  
> **场景覆盖**: 9 种考试场景，按目标类型选择对应 YAML

---

## 📁 文件结构

```
promptfoo/
├── README.md                              # 本文件 - 项目总览
│
├── promptfooconfig.yaml                   # 【通用-标准】default + 场景补充
├── promptfooconfig_simple.yaml            # 【通用-简化】仅 default + 1 条 policy
├── promptfooconfig_advanced.yaml          # 【通用-深度】逐个插件精细配置
├── promptfooconfig.md                     # 通用配置文档
│
├── rag_redteam.yaml                       # 【RAG】检索增强生成系统
├── rag_redteam.md                         # RAG 考试指南
│
├── agent_redteam.yaml                     # 【Agent】LLM Agent 系统
├── agent_redteam.md                       # Agent 考试指南
│
├── mcp_redteam.yaml                       # 【MCP】Model Context Protocol
├── mcp_redteam.md                         # MCP 考试指南
│
├── chatbot_redteam.yaml                   # 【Chatbot】通用聊天机器人
├── chatbot_redteam.md                     # Chatbot 考试指南
│
├── multi_input_redteam.yaml               # 【多输入】多字段 API
├── multi_input_redteam.md                 # 多输入考试指南
│
├── multi_modal_redteam.yaml               # 【多模态】图片+文本 AI
├── multi_modal_redteam.md                 # 多模态考试指南
│
├── foundation_model_redteam.yaml          # 【基础模型】LLM 直接安全测试
├── foundation_model_redteam.md            # 基础模型考试指南
│
├── supply_chain_redteam.yaml              # 【供应链】模型投毒/后门/回归
├── supply_chain_redteam.md                # 供应链考试指南
│
├── model_drift_redteam.yaml               # 【模型漂移】安全态势持续监控
├── model_drift_redteam.md                 # 漂移检测考试指南
│
├── send_redteam.py                        # 【备选】复杂认证 Python Provider
└── send_redteam.md                        # Provider 说明
```

---

## 🚀 考试快速流程（2 步）

### 第 1 步：根据题目类型选 YAML

```
考试题目描述                      →  复制对应 YAML 为 promptfooconfig.yaml

"知识库检索 + LLM"              →  cp rag_redteam.yaml promptfooconfig.yaml
"Agent/工具调用/记忆"            →  cp agent_redteam.yaml promptfooconfig.yaml
"MCP 协议/工具服务器"            →  cp mcp_redteam.yaml promptfooconfig.yaml
"通用聊天机器人"                 →  cp chatbot_redteam.yaml promptfooconfig.yaml
"多字段输入(user_id+message)"   →  cp multi_input_redteam.yaml promptfooconfig.yaml
"图片+文本输入"                  →  cp multi_modal_redteam.yaml promptfooconfig.yaml
"直接测试 LLM API"              →  cp foundation_model_redteam.yaml promptfooconfig.yaml
"供应链/微调模型/安全回归"       →  cp supply_chain_redteam.yaml promptfooconfig.yaml
"持续监控/漂移检测"              →  cp model_drift_redteam.yaml promptfooconfig.yaml
"不确定目标类型"                 →  cp chatbot_redteam.yaml promptfooconfig.yaml
```

### 第 2 步：改 2 处 + 运行

```bash
# 1. 编辑 promptfooconfig.yaml，改 2 处:
#    修改点1: url → 考试提供的 API URL
#    修改点2: body 字段名 → 题目要求的字段名

# 2. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run
promptfoo redteam report
```

---

## 🎯 9 种场景详细对比

| 场景 YAML | 目标类型 | 核心插件数 | 独特插件 | 考试关键词 |
|-----------|---------|:---:|---------|-----------|
| **rag** | RAG 检索系统 | 18 | `rag-source-attribution`, `indirect-prompt-injection` | "知识库"、"检索"、"文档" |
| **agent** | LLM Agent | 19 | `agentic:memory-poisoning`, `tool-discovery`, `mcp` | "工具调用"、"记忆"、"状态" |
| **mcp** | MCP 服务器 | 13 | `mcp`, `ssrf` | "MCP"、"工具描述"、"服务器" |
| **chatbot** | 通用聊天 | 16 | `default` 预设全覆盖 | 无特殊关键词时首选 |
| **multi_input** | 多字段 API | 14 | `bola`, `bfla`(多字段增强) | "多字段"、"user_id"、"上下文" |
| **multi_modal** | 多模态 AI | 15 | `harmful:*` 全系列 | "图片"、"视觉"、"OCR" |
| **foundation_model** | 基础模型 | 18 | `foundation` | "基础模型"、"LLM API"、"安全对齐" |
| **supply_chain** | 供应链 | 20 | `harmful:*` 全系列, `rag-poisoning` | "供应链"、"后门"、"投毒"、"回归" |
| **model_drift** | 漂移监控 | 16 | 核心安全插件精简版 | "漂移"、"基线"、"监控"、"退化" |

---

## 📖 通用配置（非场景特定）

| 文件 | 测试量 | 耗时 | 适用场景 |
|------|:---:|:---:|---------|
| `promptfooconfig_simple.yaml` | ~100 | 5-10min | 快速扫描 |
| `promptfooconfig.yaml` | ~200 | 10-20min | **日常首选** |
| `promptfooconfig_advanced.yaml` | ~300 | 20-30min | 深度测试 |

---

## ⚠️ 考试要点

1. **先设 `OPENAI_API_KEY`** — 不设无法运行
2. **根据题目关键词选 YAML** — 场景越匹配，攻击越精准
3. **只改 2 处** — url 和 body 字段名，其余预设不动
4. **purpose 从题目复制** — 越详细测试越精准
5. **关注报告 FAIL 项** — 最有价值的发现
6. **不确定类型用 `chatbot_redteam.yaml`** — 覆盖面最广

---

## 📚 参考

- [promptfoo 红队快速入门](https://www.promptfoo.dev/docs/red-team/quickstart/)
- [红队配置参考](https://www.promptfoo.dev/docs/red-team/configuration/)
- [LLM 漏洞类型](https://www.promptfoo.dev/docs/red-team/llm-vulnerability-types/)
- [红队测试指南](https://www.promptfoo.dev/docs/red-team/guides/)
