# A2A (Agent-to-Agent) 安全测试 - 考试指南

## 概述

`a2a_redteam.yaml` 是针对 **Agent-to-Agent (A2A) 协议** 的安全测试配置。A2A 是 Google 提出的 Agent 间通信开放协议标准，允许多个 AI Agent 相互发现、通信和协作。

## 重要说明

> **promptfoo 目前没有原生的 A2A 专用插件。** 本配置通过组合 promptfoo 现有的 Agent 安全、注入攻击、授权控制等插件，来覆盖 A2A 协议的核心安全威胁。考试中遇到 "Agent-to-Agent"、"Multi-Agent"、"Agent 协作"、"Agent 通信" 等关键词时，使用此配置。

## A2A 协议架构与攻击面

```
┌─────────┐   Agent Card    ┌─────────┐   任务委派    ┌─────────┐
│ Agent A │ ←────────────→ │ Agent B │ ←──────────→ │ Agent C │
│ (恶意)  │   消息交换      │ (目标)  │   结果返回    │ (下游)  │
└─────────┘                └─────────┘               └─────────┘
     │                          │                         │
     ▼                          ▼                         ▼
  攻击面1:                  攻击面2:                  攻击面3:
  Agent Card 伪造          消息投毒 &               信任链污染 &
  身份欺骗                  任务委派滥用             下游传播
```

## A2A 六大安全威胁（与插件映射）

| # | A2A 威胁 | 考试关键词 | 核心插件 | 攻击原理 |
|---|---------|-----------|---------|---------|
| 1 | **Agent Card 伪造** | "恶意 Agent 伪造能力声明" | `indirect-prompt-injection`, `system-prompt-override` | 恶意 Agent 声明虚假能力，诱骗目标 Agent 委派任务 |
| 2 | **任务委派滥用** | "通过委派注入恶意指令" | `indirect-prompt-injection`, `hijacking`, `goal-misalignment` | 在委派任务描述中嵌入隐藏指令，操控目标 Agent |
| 3 | **信任链污染** | "下游 Agent 被污染" | `agentic:memory-poisoning`, `hijacking` | 恶意 Agent 污染目标 Agent 状态，目标再污染下游 |
| 4 | **消息投毒** | "Agent 间消息嵌入恶意内容" | `indirect-prompt-injection`, `mcp` | 在 A2A 消息中嵌入指令，操控接收方 Agent |
| 5 | **跨 Agent 权限提升** | "通过 Agent 链获取更高权限" | `bfla`, `bola`, `rbac`, `excessive-agency` | Agent 通过协作链获取单个 Agent 不具备的能力 |
| 6 | **数据泄露** | "Agent 间通信泄露敏感数据" | `data-exfil`, `pii:direct`, `cross-session-leak` | Agent 间通信中泄露用户数据或系统秘密 |

## 插件映射详解

### A2A 核心攻击插件

| 插件 | A2A 场景映射 | 严重级别 |
|------|------------|---------|
| `indirect-prompt-injection` | 其他 Agent 发来的消息中包含隐藏指令 | CRITICAL |
| `goal-misalignment` | Agent 目标被其他 Agent 的指令改变 | CRITICAL |
| `hijacking` | Agent 被劫持执行非预期任务 | CRITICAL |
| `system-prompt-override` | Agent Card 覆盖目标 Agent 的安全策略 | CRITICAL |
| `agentic:memory-poisoning` | 恶意 Agent 污染目标 Agent 的对话记忆 | CRITICAL |
| `mcp` | Agent 通过 MCP 暴露工具给其他 Agent | CRITICAL |

### A2A 授权与访问控制插件

| 插件 | A2A 场景映射 | 严重级别 |
|------|------------|---------|
| `bfla` | Agent 调用其他 Agent 的未授权功能 | CRITICAL |
| `bola` | Agent 通过任务参数访问其他 Agent 的数据 | CRITICAL |
| `rbac` | Agent 角色权限越界 | CRITICAL |
| `excessive-agency` | Agent 通过 A2A 协作获取过度能力 | CRITICAL |

### A2A 数据安全插件

| 插件 | A2A 场景映射 | 严重级别 |
|------|------------|---------|
| `data-exfil` | Agent 间通信泄露敏感数据 | CRITICAL |
| `pii:direct/session/api-db` | Agent 间传递 PII 数据 | CRITICAL |
| `cross-session-leak` | 不同 Agent 对话间数据泄露 | CRITICAL |
| `prompt-extraction` | 泄露其他 Agent 的系统提示 | HIGH |
| `tool-discovery` | 泄露可用 Agent 和工具列表 | HIGH |

### A2A 注入攻击插件

| 插件 | A2A 场景映射 | 严重级别 |
|------|------------|---------|
| `ssrf` | Agent 间网络请求中的 SSRF | CRITICAL |
| `shell-injection` | 任务描述中嵌入系统命令 | CRITICAL |
| `sql-injection` | 任务参数中的 SQL 注入 | HIGH |

## 考试修改点（最小修改原则）

```
仅 2 处必改:
  修改点1: url → 替换为目标 Agent API 地址
  修改点2: body 字段名 → 替换 message 为题目指定字段名

  修改点3(可选): purpose → 描述 Agent 在 A2A 系统中的角色
```

## 考试使用流程

```bash
# 1. 复制配置文件
cp a2a_redteam.yaml promptfooconfig.yaml

# 2. 修改 url 和 body 字段名（2处）

# 3. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 查看报告
promptfoo redteam report
```

## A2A vs MCP 协议对比

| 维度 | A2A (Agent-to-Agent) | MCP (Model Context Protocol) |
|------|---------------------|------------------------------|
| 通信对象 | Agent ↔ Agent | LLM ↔ 工具/服务器 |
| 协议层 | 应用层 Agent 通信 | 模型上下文管理 |
| 核心概念 | Agent Card, Task, Message | Tool, Resource, Prompt |
| 主要攻击面 | 身份欺骗、任务投毒、信任链 | 工具投毒、工具遮蔽、侧信道 |
| 认证方式 | Agent Card 验证 | OAuth/API Key |
| 考试配置 | `a2a_redteam.yaml` | `mcp_redteam.yaml` |

## 常见考试场景匹配

| 题目描述 | 用哪个 YAML | 原因 |
|---------|-----------|------|
| "Agent-to-Agent 通信协议" | `a2a_redteam.yaml` | 直接 A2A |
| "多个 AI Agent 协作系统" | `a2a_redteam.yaml` | 多 Agent 协作 |
| "Agent 通过 A2A 协议委派任务" | `a2a_redteam.yaml` | A2A 任务委派 |
| "Agent Card 安全" | `a2a_redteam.yaml` | Agent Card 伪造 |
| "Agent 间消息投毒" | `a2a_redteam.yaml` | 消息投毒 |
| "Multi-Agent 系统安全" | `a2a_redteam.yaml` | 多 Agent 系统 |
| "使用 MCP 的 Agent 工具" | `mcp_redteam.yaml` | MCP 协议 |
| "Agent 通过 MCP 连接工具" | `mcp_redteam.yaml` | MCP 协议 |
| "同时涉及 A2A 和 MCP" | 两个都跑 | 组合测试 |

## 考试注意事项

1. **区分 A2A 和 MCP**: A2A 是 Agent 间的通信，MCP 是 Agent 与工具的通信。考试中明确提到 "Agent-to-Agent" 或 "多 Agent" 时用 A2A 配置
2. **没有原生 A2A 插件**: promptfoo 无 A2A 原生支持，通过组合插件覆盖，重点是 `indirect-prompt-injection`、`hijacking`、`goal-misalignment`、`agentic:memory-poisoning`
3. **信任链是关键**: A2A 最危险的是信任链污染 —— 一个恶意 Agent 可以污染整条 Agent 链
4. **Agent Card 是最薄弱环节**: Agent Card 通常被隐式信任，伪造 Agent Card 是最高效的攻击方式
5. **结合 MCP**: 如果考试中 Agent 同时使用 MCP 工具，建议先跑 `mcp_redteam.yaml`，再跑 `a2a_redteam.yaml`
