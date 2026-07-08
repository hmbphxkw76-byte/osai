# Chatbot 红队测试 - 测试指南

## 概述

`chatbot_redteam.yaml` 是**通用 Chatbot** 安全测试配置，覆盖面最广。测试中如果不确定目标具体类型，优先使用此配置。

## Chatbot 覆盖的攻击面

| # | 类别 | 核心插件 |
|---|------|---------|
| 1 | **有害内容** | `default`(含 harmful 全系列) + 补充 harmful 子类 |
| 2 | **注入攻击** | `sql-injection`, `shell-injection`, `ssrf` |
| 3 | **越狱/提示提取** | `prompt-extraction`(在 default 中), `system-prompt-override` |
| 4 | **数据泄露** | `pii`(在 default 中), `cross-session-leak`, `data-exfil` |
| 5 | **访问控制** | `rbac`, `bola`, `bfla`(在 default 中) |
| 6 | **社交工程** | `imitation`, `contracts` |

## 测试修改点（最小修改原则）

```
仅 2 处必改:
  修改点1: url → 替换为目标 Chatbot API 地址
  修改点2: body 字段名 → 替换 user_message 为场景指定字段名

  修改点3(可选): purpose → 复制场景中 chatbot 的角色描述
```

## 测试使用流程

```bash
# 1. 复制配置文件
cp chatbot_redteam.yaml promptfooconfig.yaml

# 2. 修改 url 和 body 字段名（2处）

# 3. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 查看报告
promptfoo redteam report
```

## 设计思路

- **`default` 预设覆盖 9 类核心漏洞**（harmful, pii, rbac, bola, bfla, prompt-extraction, indirect-prompt-injection, excessive-agency, hallucination）
- **补充插件**针对 Chatbot 常见弱点（有害内容、注入、社交工程）
- **8 种语言**覆盖多语言绕过
- **适中测试量** - 测试时间有限时优先选择

## 常见测试场景匹配

| 场景描述 | 用哪个 YAML |
|---------|-----------|
| "客户服务聊天机器人" | `chatbot_redteam.yaml` |
| "产品咨询助手" | `chatbot_redteam.yaml` |
| "不确定目标类型" | `chatbot_redteam.yaml`（首选） |
| "通用对话 AI" | `chatbot_redteam.yaml` |

## 测试注意事项

1. **Chatbot 场景最通用** - 如果场景没有明确指定 RAG/Agent/MCP，用此配置
2. **`default` 预设已经覆盖 80% 的漏洞** - 补充插件针对剩余 20%
3. **多语言测试很重要** - Chatbot 常有多语言支持，编码绕过是常见漏洞
4. **时间紧张时优先用这个** - 覆盖面广，一次运行出结果多
