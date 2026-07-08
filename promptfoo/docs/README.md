# Promptfoo 红队测试项目文档

> LLM 渗透测试实战演练 · 生产级 LLM 安全评估
> **核心原则**: 数据与逻辑分离 · 最小化修改 · IDE 无关

本目录是项目的文档中心，按用途分类组织。下方为完整索引。

---

## 📚 文档索引

### 🚀 快速开始

| 文档 | 内容 | 适用 |
|------|------|------|
| [guides/PENETRATING_MODE_GUIDE.md](guides/PENETRATING_MODE_GUIDE.md) | 渗透模式选择指南（快速/标准/深度/全量） | 选择测试模式 |
| [guides/promptfooconfig.md](guides/promptfooconfig.md) | promptfooconfig 配置详解 | 理解配置结构 |
| [reference/module_mapping.md](reference/module_mapping.md) | LLM 渗透测试 测试大纲 → YAML 模块映射 | 按场景选模块 |

### 📐 架构与原理

| 文档 | 内容 | 适用 |
|------|------|------|
| [guides/ARCHITECTURE.md](guides/ARCHITECTURE.md) | 项目整体架构、核心组件、数据流 | 理解项目设计 |
| [guides/PAYLOAD_LOADING.md](guides/PAYLOAD_LOADING.md) | Payload 生成、变换、注入、评估全流程 | 理解攻击流程 |
| [guides/FRONTIER_VULNS.md](guides/FRONTIER_VULNS.md) | OWASP/Agentic AI/MCP/A2A 前沿漏洞类型 | 了解攻击面 |
| [guides/evaluation_strategy.md](guides/evaluation_strategy.md) | 评估策略、断言、回归测试 | 制定评估方案 |

### 🔴 红队模块文档

`modules/` 目录下每个文档对应 `redteam/modules/` 中的一个 YAML 配置：

| 文档 | 场景 | 关键词 |
|------|------|--------|
| [modules/foundation_model_redteam.md](modules/foundation_model_redteam.md) | 基础 LLM 模型 | LLM API, 对齐 |
| [modules/chatbot_redteam.md](modules/chatbot_redteam.md) | 聊天机器人 | jailbreak, injection |
| [modules/rag_redteam.md](modules/rag_redteam.md) | RAG 系统 | 知识库, 检索 |
| [modules/agent_redteam.md](modules/agent_redteam.md) | 多智能体 | Agent, 工具调用 |
| [modules/mcp_redteam.md](modules/mcp_redteam.md) | MCP 协议 | MCP, 工具服务器 |
| [modules/a2a_redteam.md](modules/a2a_redteam.md) | A2A 协议 | Agent-to-Agent |
| [modules/multi_modal_redteam.md](modules/multi_modal_redteam.md) | 多模态 AI | 图片, 视觉 |
| [modules/multi_input_redteam.md](modules/multi_input_redteam.md) | 多输入 API | 多字段, user_id |
| [modules/supply_chain_redteam.md](modules/supply_chain_redteam.md) | 供应链安全 | 后门, 投毒 |
| [modules/model_drift_redteam.md](modules/model_drift_redteam.md) | 模型漂移监控 | 漂移, 基线 |
| [modules/broad_automated_scan.md](modules/broad_automated_scan.md) | 全量扫描 | 综合覆盖 |
| [modules/owasp_llm_top10.md](modules/owasp_llm_top10.md) | OWASP LLM Top 10 | 合规标准 |
| [modules/agentic_ai_top10.md](modules/agentic_ai_top10.md) | Agentic AI Top 10 | ASI 标准 |
| [modules/mcp_top10.md](modules/mcp_top10.md) | MCP Top 10 | MCP 标准 |
| [modules/a2a_top10.md](modules/a2a_top10.md) | A2A Top 10 | A2A 标准 |

### 🛠️ 开发规范（IDE 无关）

| 文档 | 内容 | 适用 |
|------|------|------|
| [dev-standards/README.md](dev-standards/README.md) | 规范入口与索引 | 了解规范全貌 |
| [dev-standards/architecture-design.md](dev-standards/architecture-design.md) | 目录结构、命名、注释、版本控制 | 新建/重构项目 |
| [dev-standards/config-patterns.md](dev-standards/config-patterns.md) | 核心配置、环境变量、Provider、测试实践 | 编写配置 |
| [dev-standards/yaml-patterns.md](dev-standards/yaml-patterns.md) | 测试用例、断言、红队配置 | 编写测试 |

### 📖 其他

| 文档 | 内容 |
|------|------|
| [guides/send_redteam.md](guides/send_redteam.md) | 自定义 Provider 使用说明 |
| [changelog.md](changelog.md) | 项目变更日志 |

---

## 📁 目录结构

```
docs/
 ├── README.md                # 本文件（文档总索引）
 ├── changelog.md             # 变更日志
 │
 ├── guides/                  # 用户指南（面向使用者）
 │   ├── ARCHITECTURE.md
 │   ├── FRONTIER_VULNS.md
 │   ├── PAYLOAD_LOADING.md
 │   ├── PENETRATING_MODE_GUIDE.md
 │   ├── evaluation_strategy.md
 │   ├── promptfooconfig.md
 │   └── send_redteam.md
 │
 ├── modules/                 # 红队模块文档（对应 redteam/modules/*.yaml）
 │   ├── foundation_model_redteam.md
 │   ├── chatbot_redteam.md
 │   └── ... (共 15 个)
 │
 ├── reference/               # 参考资料
 │   └── module_mapping.md
 │
 └── dev-standards/           # 开发规范（IDE 无关，自包含）
     ├── README.md
     ├── architecture-design.md
     ├── config-patterns.md
     └── yaml-patterns.md
```

---

## 🚀 测试三步法

```bash
# 第 0 步：配置环境变量
cp .env.example .env  # 填入 TARGET_URL, AUTH_TOKEN, OPENAI_API_KEY

# 第 1 步：根据场景选模块（参考 reference/module_mapping.md）
cp redteam/modules/rag_redteam.yaml promptfooconfig.yaml

# 第 2 步：改 body 字段名 + 运行
promptfoo redteam run && promptfoo redteam report
```

详见 [guides/PENETRATING_MODE_GUIDE.md](guides/PENETRATING_MODE_GUIDE.md) 和 [dev-standards/config-patterns.md](dev-standards/config-patterns.md)。
