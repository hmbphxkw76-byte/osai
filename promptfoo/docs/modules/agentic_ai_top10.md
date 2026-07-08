# OWASP Agentic AI Top 10 (ASI) - 测试指南

## 概述

`agentic_ai_top10.yaml` 严格按 OWASP Top 10 for Agentic Applications (ASI) 标准组织。这是 OWASP GenAI Security Project 下的 Agentic App Security Initiative 发布的针对自主 AI Agent 的 Top 10 安全风险。

## OWASP Agentic AI Top 10 插件映射表

| # | 漏洞 | 中文 | promptfoo 插件 | 严重级别 |
|---|------|------|---------------|---------|
| ASI01 | Agent Goal Hijacking | Agent 目标劫持 | `hijacking`, `goal-misalignment` | CRITICAL |
| ASI02 | Tool & API Misuse | 工具与 API 滥用 | `tool-discovery`, `excessive-agency`, `mcp` | CRITICAL |
| ASI03 | Identity & Privilege Abuse | 身份与权限滥用 | `rbac`, `bola`, `bfla` | CRITICAL |
| ASI04 | Memory & Context Poisoning | 记忆与上下文投毒 | `agentic:memory-poisoning`, `cross-session-leak` | CRITICAL |
| ASI05 | Insecure Inter-Agent Comm | Agent 间不安全通信 | `indirect-prompt-injection`, `mcp`, `ssrf` | CRITICAL |
| ASI06 | Cascading Failures | 级联故障 | `excessive-agency`, `hijacking` | CRITICAL |
| ASI07 | Trust Exploitation | 信任利用 | `imitation`, `system-prompt-override`, `debug-access` | CRITICAL |
| ASI08 | Rogue Agent Behavior | 恶意 Agent 行为 | `goal-misalignment`, `excessive-agency`, `harmful:illegal-activities` | CRITICAL |
| ASI09 | Supply Chain in Agent Ecosystem | Agent 生态供应链 | `rag-poisoning`, `coding-agent:automation-poisoning`, `data-exfil` | CRITICAL |
| ASI10 | Unbounded Autonomy | 无限自主 | `excessive-agency`, `reasoning-dos`, `divergent-repetition` | CRITICAL |

## 与 agent_redteam.yaml 的区别

| 维度 | agentic_ai_top10.yaml | agent_redteam.yaml |
|------|----------------------|-------------------|
| 组织方式 | 按 ASI01-ASI10 标准 | 按攻击向量分类 |
| 适用场景 | OWASP ASI 标准测试 | 通用 Agent 测试 |
| 标准对齐 | 严格对应 OWASP ASI | 实战攻击覆盖 |

## 测试修改点

```
仅 2 处必改:
  修改点1: url → 替换为实际 Agent API URL
  修改点2: body 字段名 → 替换 message 为场景指定字段名
  修改点3(可选): purpose → 描述 Agent 的能力和工具
```

## 测试使用流程

```bash
cp agentic_ai_top10.yaml promptfooconfig.yaml
# 修改 url 和 body 字段名
export OPENAI_API_KEY="sk-..."
promptfoo redteam run
promptfoo redteam report
```

## 常见测试场景

| 场景关键词 | 对应 ASI | 核心插件 |
|-----------|---------|---------|
| "Agent 目标被改变" | ASI01 | hijacking, goal-misalignment |
| "Agent 滥用工具/API" | ASI02 | excessive-agency, tool-discovery |
| "Agent 越权访问" | ASI03 | rbac, bola, bfla |
| "Agent 记忆被污染" | ASI04 | agentic:memory-poisoning |
| "多 Agent 通信安全" | ASI05 | indirect-prompt-injection |
| "一个 Agent 故障影响全局" | ASI06 | excessive-agency |
| "Agent 信任被利用" | ASI07 | imitation, system-prompt-override |
| "Agent 行为失控" | ASI08 | goal-misalignment |
| "Agent 第三方组件安全" | ASI09 | rag-poisoning |
| "Agent 自主权过大" | ASI10 | excessive-agency, reasoning-dos |
