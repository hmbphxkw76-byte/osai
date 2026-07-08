# A2A (Agent-to-Agent) Top 10 - 测试指南

## 概述

`a2a_top10.yaml` 严格按 A2A (Agent-to-Agent) 协议 Top 10 安全风险标准组织。A2A 是 Agent 间通信协议，引入独特的多 Agent 安全挑战。

## A2A Top 10 插件映射表

| # | 漏洞 | 中文 | promptfoo 插件 | 严重级别 |
|---|------|------|---------------|---------|
| A01 | Agent Card Forgery | Agent Card 伪造 | `indirect-prompt-injection`, `system-prompt-override` | CRITICAL |
| A02 | Task Delegation Poisoning | 任务委派投毒 | `indirect-prompt-injection`, `hijacking` | CRITICAL |
| A03 | Trust Chain Contamination | 信任链污染 | `agentic:memory-poisoning`, `hijacking` | CRITICAL |
| A04 | Message Injection | 消息注入 | `indirect-prompt-injection`, `mcp` | CRITICAL |
| A05 | Cross-Agent Privilege Escalation | 跨Agent权限提升 | `bfla`, `bola`, `rbac`, `excessive-agency` | CRITICAL |
| A06 | Data Leakage via A2A | A2A 数据泄露 | `data-exfil`, `pii:*`, `cross-session-leak` | CRITICAL |
| A07 | Capability Declaration Fraud | 能力声明欺诈 | `tool-discovery`, `system-prompt-override` | HIGH |
| A08 | Agent Impersonation | Agent 冒充 | `imitation`, `rbac` | HIGH |
| A09 | Multi-Agent Goal Corruption | 多Agent目标腐化 | `goal-misalignment`, `hijacking` | CRITICAL |
| A10 | Inter-Agent DoS | Agent 间拒绝服务 | `reasoning-dos`, `divergent-repetition`, `excessive-agency` | MEDIUM |

## 与 a2a_redteam.yaml 的区别

| 维度 | a2a_top10.yaml | a2a_redteam.yaml |
|------|---------------|-----------------|
| 组织方式 | 按 A01-A10 标准 | 按攻击面 + 威胁 |
| 适用场景 | A2A Top 10 标准测试 | 通用 A2A 安全测试 |
| 标准对齐 | 严格对应 A2A Top 10 | 实战攻击覆盖 |

## 重要说明

> promptfoo 没有原生的 A2A 专用插件。本配置通过组合现有插件覆盖 A2A Top 10 安全威胁。

## 测试修改点

```
仅 2 处必改:
  修改点1: url → 替换为 Agent API URL
  修改点2: body 字段名 → 替换 message 为场景指定字段名
  修改点3(可选): purpose → 描述 Agent 在 A2A 系统中的角色
```

## 测试使用流程

```bash
cp a2a_top10.yaml promptfooconfig.yaml
# 修改 url 和 body 字段名
export OPENAI_API_KEY="sk-..."
promptfoo redteam run
promptfoo redteam report
```

## 常见测试场景

| 场景关键词 | 对应 A2A | 核心插件 |
|-----------|---------|---------|
| "恶意 Agent 伪造身份" | A01 | indirect-prompt-injection |
| "委派任务中包含恶意指令" | A02 | hijacking, indirect-prompt-injection |
| "一个 Agent 污染整条链" | A03 | agentic:memory-poisoning |
| "Agent 间消息被注入" | A04 | indirect-prompt-injection |
| "Agent 通过协作提升权限" | A05 | bfla, bola, rbac |
| "Agent 间通信泄露数据" | A06 | data-exfil, pii |
| "Agent 虚报能力" | A07 | tool-discovery |
| "Agent 冒充其他 Agent" | A08 | imitation |
| "多个 Agent 目标被腐化" | A09 | goal-misalignment |
| "Agent 间请求导致拒绝服务" | A10 | reasoning-dos |
