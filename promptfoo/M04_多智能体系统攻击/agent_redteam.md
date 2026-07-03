# Agent 红队测试 - 考试指南

## 概述

`agent_redteam.yaml` 是针对 **LLM Agent** 系统的安全测试配置。Agent 不同于简单 Chatbot——它们维护状态、调用工具、执行操作，引入了独特的攻击面。

## Agent 七大攻击向量

| # | 攻击类型 | 核心插件 | 考试关键词 |
|---|---------|---------|-----------|
| 1 | **权限提升** | `rbac`, `bola`, `bfla` | "agent 执行了管理员操作" |
| 2 | **上下文污染** | `harmful:privacy`, `pii`, `ssrf` | "通过工具输出泄露数据" |
| 3 | **记忆污染** | `agentic:memory-poisoning` | "早期对话污染了后续行为" |
| 4 | **多阶段攻击链** | `sql-injection`, `excessive-agency` | "逐步实现未授权访问" |
| 5 | **工具操纵** | `tool-discovery`, `mcp`, `bfla` | "利用 agent 的工具接口" |
| 6 | **目标函数利用** | `hijacking`, `excessive-agency` | "修改 agent 的核心目标" |
| 7 | **提示泄露** | `prompt-extraction` | "提取 agent 的系统提示" |

## 考试修改点（最小修改原则）

```
仅 2 处必改:
  修改点1: url → 替换为目标 Agent API 地址
  修改点2: body 字段名 → 替换 message 为题目指定字段名

  修改点3(可选): purpose → 复制题目中 agent 的能力描述
```

## 考试使用流程

```bash
# 1. 复制配置文件
cp agent_redteam.yaml promptfooconfig.yaml

# 2. 修改 url 和 body 字段名（2处）

# 3. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 查看报告
promptfoo redteam report
```

## Agent 特有插件详解

### agentic:memory-poisoning（记忆污染）
- **Agent 独有攻击**: 在早期对话中注入恶意内容，污染 agent 记忆
- 后续所有对话都可能受污染记忆影响
- 配合 `crescendo` 策略（渐进式越狱）效果最佳

### tool-discovery（工具发现）
- 检测 agent 是否会泄露可用工具列表
- 考试中如果 agent 有 "tools"、"functions"、"capabilities" 等概念，必用

### excessive-agency（过度代理）
- Agent 特有: 检测 agent 是否执行了超出授权范围的操作
- 如：agent 只能"建议"，但实际执行了"操作"

## 攻击策略选择

Agent 测试推荐多轮攻击策略:
- `crescendo` - 渐进式越狱，对记忆污染特别有效
- `multi-turn` - 多轮对话，模拟真实攻击链
- `jailbreak:tree` - 树形搜索，自动寻找最优越狱路径

## 常见考试场景匹配

| 题目描述 | 用哪个 YAML |
|---------|-----------|
| "可以调用 API/工具的 AI 助手" | `agent_redteam.yaml` |
| "有记忆/状态的对话系统" | `agent_redteam.yaml` |
| "能执行操作而不仅是对话的 AI" | `agent_redteam.yaml` |
| "可访问数据库/文件系统的 LLM" | `agent_redteam.yaml` |

## 考试注意事项

1. **Agent 的独特风险在于"组合操作"** - 单个操作无害，组合起来可形成攻击链
2. **记忆污染是最隐蔽的攻击** - 考试中如果有 "session"、"state"、"memory" 等概念，重点关注
3. **分层测试** - 端到端测试 + 组件测试 + 追踪测试，三种都要考虑
