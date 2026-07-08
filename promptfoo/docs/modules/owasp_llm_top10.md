# OWASP LLM Top 10 (2025) - 测试指南

## 概述

`owasp_llm_top10.yaml` 严格按 OWASP Top 10 for LLM Applications (2025) 标准组织，每个 LLM01-LLM10 都有明确的插件映射。

## OWASP LLM Top 10 插件映射表

| # | 漏洞 | promptfoo 插件 | 严重级别 |
|---|------|---------------|---------|
| LLM01 | Prompt Injection | `indirect-prompt-injection`, `prompt-extraction`, `system-prompt-override` | CRITICAL |
| LLM02 | Sensitive Info Disclosure | `pii:direct`, `pii:api-db`, `pii:session`, `pii:social`, `harmful:privacy`, `data-exfil`, `cross-session-leak` | CRITICAL |
| LLM03 | Supply Chain | `rag-poisoning`, `rag-document-exfiltration` | CRITICAL |
| LLM04 | Data & Model Poisoning | `harmful:misinformation-disinformation`, `hallucination`, `overreliance` | HIGH |
| LLM05 | Improper Output Handling | `sql-injection`, `shell-injection`, `ssrf`, `ascii-smuggling` | CRITICAL |
| LLM06 | Excessive Agency | `excessive-agency`, `rbac`, `bola`, `bfla`, `hijacking` | CRITICAL |
| LLM07 | System Prompt Leakage | `system-prompt-override`, `prompt-extraction` | CRITICAL |
| LLM08 | Vector & Embedding | `indirect-prompt-injection`, `rag-poisoning`, `rag-source-attribution` | CRITICAL |
| LLM09 | Misinformation | `harmful:misinformation-disinformation`, `hallucination`, `overreliance`, `unverifiable-claims` | HIGH |
| LLM10 | Unbounded Consumption | `divergent-repetition`, `reasoning-dos` | MEDIUM |

## 快捷用法 vs 详细用法

```yaml
# 快捷（一行覆盖 LLM01-LLM10）
plugins:
  - 'owasp:llm'

# 详细（本配置 - 每个 LLM 独立可控）
plugins:
  - id: 'owasp:llm'          # 全量内置
  - id: 'indirect-prompt-injection'  # LLM01
  - id: 'pii:direct'               # LLM02
  # ... 完整 30+ 插件
```

## 测试修改点

```
仅 2 处必改:
  修改点1: url → 替换为实际 API URL
  修改点2: body 字段名 → 替换 message 为场景指定字段名
  修改点3(可选): purpose → 描述系统用途
```

## 测试使用流程

```bash
cp owasp_llm_top10.yaml promptfooconfig.yaml
# 修改 url 和 body 字段名
export OPENAI_API_KEY="sk-..."
promptfoo redteam run
promptfoo redteam report
```

## 常见测试场景

| 场景关键词 | 对应漏洞 | 核心插件 |
|-----------|---------|---------|
| "用户输入改变 LLM 行为" | LLM01 | indirect-prompt-injection |
| "LLM 泄露了用户数据" | LLM02 | pii:direct, data-exfil |
| "第三方模型/插件安全问题" | LLM03 | rag-poisoning |
| "训练数据被污染" | LLM04 | hallucination, overreliance |
| "LLM 输出未经验证传入系统" | LLM05 | sql-injection, shell-injection |
| "LLM 执行了不应有的操作" | LLM06 | excessive-agency, rbac |
| "系统提示被泄露" | LLM07 | prompt-extraction |
| "RAG 系统安全问题" | LLM08 | indirect-prompt-injection, rag-poisoning |
| "LLM 生成虚假信息" | LLM09 | hallucination |
| "LLM 资源被耗尽" | LLM10 | reasoning-dos |
