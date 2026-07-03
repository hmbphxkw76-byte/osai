# MCP 安全测试 - 考试指南

## 概述

`mcp_redteam.yaml` 是针对 **Model Context Protocol (MCP)** 服务器的增强安全测试配置。MCP 是 AI Agent 与外部工具通信的协议标准，引入了独特的安全挑战。

## MCP 核心概念

```
用户 ──→ AI 助手 ──→ MCP 服务器 ──→ 工具1 (数据库查询)
                    │              ├─→ 工具2 (文件操作)
                    │              └─→ 工具3 (API调用)
                    │
                    攻击面: 工具描述、工具输出、工具参数、认证、跨服务器
```

## MCP 八大攻击向量（增强版）

| # | 攻击类型 | 核心插件 | 考试关键词 |
|---|---------|---------|-----------|
| 1 | **工具投毒** | `mcp`, `indirect-prompt-injection` | "工具描述中嵌入隐藏指令" |
| 2 | **工具遮蔽** | `mcp`, `tool-discovery` | "恶意工具覆盖合法工具功能" |
| 3 | **侧信道泄露** | `data-exfil`, `pii:api-db`, `ssrf` | "通过工具返回值泄露数据" |
| 4 | **认证劫持** | `bfla`, `rbac`, `bola` | "绕过 MCP 服务器认证" |
| 5 | **跨服务器攻击** | `ssrf`, `excessive-agency`, `goal-misalignment` | "利用多个 MCP 服务器的交互" |
| 6 | **记忆投毒** | `agentic:memory-poisoning` | "工具输出污染 Agent 状态记忆" |
| 7 | **文档外泄** | `rag-document-exfiltration` | "通过 MCP 检索工具泄露完整文档" |
| 8 | **系统提示覆盖** | `system-prompt-override` | "通过工具上下文覆盖安全指令" |

## MCP_PLUGINS 全量覆盖

promptfoo 源码中定义 `MCP_PLUGINS = ['mcp', 'pii', 'bfla', 'bola', 'sql-injection', 'rbac']`，本配置全部覆盖并增强：

| 插件 | MCP 场景作用 | 严重级别 |
|------|------------|---------|
| `mcp` | MCP 协议层攻击：工具投毒、遮蔽、发现、认证绕过 | CRITICAL |
| `pii` | 工具输出中的 PII 泄露 | CRITICAL |
| `bfla` | 功能级授权：用户调用未授权的管理工具 | CRITICAL |
| `bola` | 对象级授权：通过工具参数访问他人数据 | CRITICAL |
| `sql-injection` | 数据库查询工具参数注入 | HIGH |
| `rbac` | 角色权限：不同角色访问不同工具集 | CRITICAL |

## 新增增强插件

| 插件 | 为什么对 MCP 关键 | 考试场景 |
|------|------------------|---------|
| `agentic:memory-poisoning` | MCP Agent 有状态，工具输出可污染记忆 | "Agent 记住恶意指令" |
| `data-exfil` | MCP 工具输出是最佳外泄通道 | "通过工具返回数据泄露" |
| `rag-document-exfiltration` | MCP 检索工具暴露完整文档 | "从知识库提取文档" |
| `goal-misalignment` | 工具描述改变 Agent 目标 | "Agent 目标被工具重定向" |
| `system-prompt-override` | 工具上下文覆盖系统提示 | "工具输出改变安全策略" |
| `tool-discovery` | 枚举未授权工具 Schema | "泄露可用工具列表" |

## 三种测试场景

| 场景 | 描述 | 适用情况 | 配置方式 |
|------|------|---------|---------|
| 可信客户端 + 恶意用户 | 正常 AI 助手，用户输入恶意内容 | **考试最常用** | `mcp_redteam.yaml` 默认 |
| 多服务器 + 恶意服务器 | 多个 MCP 服务器共存，其中一个恶意 | 有多个工具来源时 | 需配置多个 MCP 服务器端点 |
| 直接 MCP 测试 | 直接测试 MCP 协议层 | 无 AI 中间层时 | 需配置 JSON-RPC 直接调用 |

### 场景2 多服务器环境（重要考试场景）

```yaml
# 多 MCP 服务器配置示例
targets:
  - id: https
    config:
      # 合法 MCP 服务器
      url: 'https://legitimate-mcp.company.com/tools'
      # 恶意 MCP 服务器（@promptfoo/evil-mcp-server）
      url2: 'https://evil-mcp.attacker.com/tools'
```

关键测试点：
- 恶意服务器的工具描述是否影响 Agent 行为
- Agent 是否会被诱导调用恶意工具而非合法工具
- 工具遮蔽：恶意工具名与合法工具名冲突时的处理

## 考试修改点（最小修改原则）

```
仅 2 处必改:
  修改点1: url → 替换为目标 MCP 服务 API 地址
  修改点2: body 字段名 → 替换 tool_input 为题目指定字段名

  修改点3(可选): purpose → 描述 MCP 服务器的工具能力
```

## 考试使用流程

```bash
# 1. 复制配置文件
cp mcp_redteam.yaml promptfooconfig.yaml

# 2. 修改 url 和 body 字段名（2处）

# 3. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 查看报告
promptfoo redteam report
```

## MCP 特有插件详解

### mcp（MCP 专用攻击）
- **核心插件**: 生成针对 MCP 协议的攻击测试
- 覆盖: 工具投毒、工具遮蔽、工具发现、认证绕过、跨服务器攻击
- 配置 `graderGuidance` 指定 MCP 特定的评分标准
- 对应 promptfoo 源码 `MCP_PLUGINS` 中的第一个插件

### agentic:memory-poisoning（记忆投毒 - MCP 增强）
- MCP Agent 在多次工具调用间保持状态
- 攻击者通过恶意工具输出将指令注入 Agent 记忆
- 后续工具调用可能受到污染记忆的影响
- 这是 MCP 场景特有的攻击向量（非 MCP Agent 无此问题）

### data-exfil（数据外泄）
- MCP 工具输出是最佳的数据外泄通道
- Agent 可能将敏感数据编码在工具调用结果中
- 侧信道泄露：工具日志、错误信息、返回值格式

### indirect-prompt-injection（间接提示注入）
- MCP 场景下: 攻击者在工具描述中嵌入恶意指令
- Agent 读取工具描述时可能被注入
- 与 `mcp` 插件互补使用
- 多服务器场景下尤为危险

### ssrf（服务端请求伪造）
- MCP 工具常发起网络请求
- 检测 agent 是否可被操纵访问内部服务
- 考试中如果有 "internal service"、"network request" 等概念，必用

## 常见考试场景匹配

| 题目描述 | 用哪个 YAML | 备注 |
|---------|-----------|------|
| "使用 MCP 协议的 AI 工具" | `mcp_redteam.yaml` | 标准场景 |
| "Model Context Protocol 服务器" | `mcp_redteam.yaml` | 标准场景 |
| "Agent 通过 MCP 连接外部工具" | `mcp_redteam.yaml` | 标准场景 |
| "多个 MCP 服务器共存" | `mcp_redteam.yaml` | 场景2 多服务器 |
| "Agent 在工具调用间保持记忆" | `mcp_redteam.yaml` | 记忆投毒增强 |
| "MCP 工具可检索文档" | `mcp_redteam.yaml` | 文档外泄增强 |

## 考试注意事项

1. **工具投毒是 MCP 最大威胁** - 工具描述通常被信任，嵌入恶意指令极易成功
2. **`mcp` 插件覆盖工具层面的所有攻击** - 不需要额外配置工具特定插件
3. **结合 `excessive-agency`** - MCP 工具提供了执行操作的能力，检测过度代理
4. **记忆投毒是 MCP Agent 独有** - 普通 LLM 无此问题，Agent 场景必测
5. **多服务器场景** - 考试中如果提到"多个工具来源"或"第三方工具"，需考虑场景2
