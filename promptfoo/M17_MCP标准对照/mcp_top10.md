# MCP Top 10 - 考试指南

## 概述

`mcp_top10.yaml` 严格按 MCP (Model Context Protocol) Top 10 安全风险标准组织。基于 OWASP Agentic AI + MCP 协议特性归纳的十大安全风险。

## MCP Top 10 插件映射表

| # | 漏洞 | 中文 | promptfoo 插件 | 严重级别 |
|---|------|------|---------------|---------|
| M01 | Tool Description Poisoning | 工具描述投毒 | `mcp`, `indirect-prompt-injection` | CRITICAL |
| M02 | Tool Shadowing | 工具遮蔽 | `mcp`, `tool-discovery` | CRITICAL |
| M03 | Side-Channel Data Leak | 侧信道数据泄露 | `data-exfil`, `pii:api-db`, `ssrf` | CRITICAL |
| M04 | Authentication Hijacking | 认证劫持 | `bfla`, `rbac`, `bola` | CRITICAL |
| M05 | Cross-Server Attack | 跨服务器攻击 | `mcp`, `ssrf`, `excessive-agency` | CRITICAL |
| M06 | Memory Poisoning via Tools | 工具记忆投毒 | `agentic:memory-poisoning` | CRITICAL |
| M07 | Document Exfiltration | 文档外泄 | `rag-document-exfiltration`, `data-exfil` | CRITICAL |
| M08 | System Prompt Override | 系统提示覆盖 | `system-prompt-override`, `goal-misalignment` | CRITICAL |
| M09 | Input Validation Bypass | 输入验证绕过 | `sql-injection`, `shell-injection`, `special-token-injection`, `ascii-smuggling` | CRITICAL |
| M10 | Resource Exhaustion | 资源耗尽 | `reasoning-dos`, `divergent-repetition` | MEDIUM |

## 与 mcp_redteam.yaml 的区别

| 维度 | mcp_top10.yaml | mcp_redteam.yaml |
|------|---------------|-----------------|
| 组织方式 | 按 M01-M10 标准 | 按攻击场景 + 插件 |
| 适用场景 | MCP Top 10 标准考试 | 通用 MCP 安全测试 |
| 插件数量 | ~25 个 | ~22 个 |
| 标准对齐 | 严格对应 MCP Top 10 | 实战攻击覆盖 |

## MCP_PLUGINS 内置支持

promptfoo 源码定义 `MCP_PLUGINS = ['mcp', 'pii', 'bfla', 'bola', 'sql-injection', 'rbac']`，这些在本配置中全部覆盖并增强了 MCP Top 10 场景映射。

## 考试修改点

```
仅 2 处必改:
  修改点1: url → 替换为 MCP 服务端 API URL
  修改点2: body 字段名 → 替换 tool_input 为题目指定字段名
  修改点3(可选): purpose → 描述 MCP 服务器的工具能力
```

## 考试使用流程

```bash
cp mcp_top10.yaml promptfooconfig.yaml
# 修改 url 和 body 字段名
export OPENAI_API_KEY="sk-..."
promptfoo redteam run
promptfoo redteam report
```

## 常见考试场景

| 题目关键词 | 对应 MCP | 核心插件 |
|-----------|---------|---------|
| "工具描述中包含恶意指令" | M01 | mcp, indirect-prompt-injection |
| "恶意工具覆盖了合法工具" | M02 | mcp, tool-discovery |
| "工具返回值泄露了数据" | M03 | data-exfil, pii:api-db |
| "未认证用户调用管理工具" | M04 | bfla, rbac |
| "多个 MCP 服务器安全问题" | M05 | mcp, ssrf |
| "工具输出污染了 Agent 记忆" | M06 | agentic:memory-poisoning |
| "通过检索工具泄露完整文档" | M07 | rag-document-exfiltration |
| "工具上下文覆盖了安全策略" | M08 | system-prompt-override |
| "工具参数注入攻击" | M09 | sql-injection, shell-injection |
| "工具调用导致资源耗尽" | M10 | reasoning-dos |
