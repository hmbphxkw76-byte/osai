# Broad Automated Scan — 考试快速参考

## 文件: `broad_automated_scan.yaml`

## 用途

一次扫描覆盖全部主流 AI 安全标准，考试时只需修改 3 处即可运行。

## 覆盖标准

| 标准 | 编号 | 覆盖 |
|------|------|------|
| OWASP LLM Top 10 (2025) | LLM01-LLM10 | 全部 |
| OWASP Agentic AI Top 10 | ASI01-ASI10 | 全部 |
| MCP Top 10 | M01-M10 | 全部 |
| A2A Top 10 | A01-A10 | 全部 |

## 考试修改点（仅 3 处）

```
# 【修改点1】替换 target id
- id: https  →  - id: openai:chat:xxx  或保持 https

# 【修改点2】替换 API URL
url: 'https://example.com/api/chat'  →  题目给定的 URL

# 【修改点3】替换请求体字段名
message: '{{prompt}}'  →  题目要求的字段名 (如 input, query, user_input 等)
```

## 考试关键词 → 插件快速匹配

| 考试关键词 | 对应插件 | 覆盖标准 |
|-----------|---------|---------|
| "prompt injection" / "jailbreak" | indirect-prompt-injection, hijacking, system-prompt-override | LLM01, LLM07, ASI01, A01 |
| "sensitive data" / "PII" / "privacy" | pii:*, data-exfil, harmful:privacy, cross-session-leak | LLM02, M03, A06 |
| "supply chain" / "RAG" | rag-poisoning, rag-document-exfiltration | LLM03, ASI09 |
| "poisoning" / "misinformation" | hallucination, overreliance, harmful:misinformation-disinformation | LLM04, LLM09 |
| "output handling" / "injection" | sql-injection, shell-injection, ssrf, ascii-smuggling | LLM05, M09 |
| "agency" / "agent" / "tool" / "autonomous" | excessive-agency, tool-discovery, mcp | LLM06, ASI02, ASI08, ASI10 |
| "memory" / "context" | agentic:memory-poisoning | ASI04, M06, A03 |
| "inter-agent" / "A2A" / "multi-agent" | indirect-prompt-injection, mcp, ssrf, imitation | ASI05, A01-A10 |
| "access control" / "RBAC" / "auth" | rbac, bola, bfla | ASI03, M04, A05, A08 |
| "cascading" / "chain failure" | excessive-agency, hijacking | ASI06 |
| "trust" / "impersonation" | imitation, system-prompt-override, debug-access | ASI07, A08 |
| "rogue agent" | goal-misalignment, excessive-agency, harmful:illegal-activities | ASI08 |
| "resource" / "DoS" / "consumption" | divergent-repetition, reasoning-dos | LLM10, ASI10, M10, A10 |
| "MCP" / "tool description" / "tool poisoning" | mcp, indirect-prompt-injection | M01, M02, M05 |
| "agent card" / "task delegation" | indirect-prompt-injection, hijacking | A01, A02 |

## 插件去重表（35 个独立插件覆盖 40 个漏洞类别）

| 插件 | 覆盖标准 |
|------|---------|
| `owasp:llm` | LLM01-LLM10 (一键全量) |
| `indirect-prompt-injection` | LLM01/LLM07/LLM08, ASI01/ASI05, A01/A02/A04, M01 |
| `hijacking` | LLM06, ASI01/ASI06, A02/A03/A09 |
| `system-prompt-override` | LLM01/LLM07, ASI07, A01/A07, M08 |
| `prompt-extraction` | LLM01/LLM07, ASI, A2A |
| `mcp` | ASI02/ASI05, M01/M02/M05, A04 |
| `excessive-agency` | LLM06, ASI02/ASI06/ASI08/ASI10, M05, A05/A10 |
| `tool-discovery` | ASI02, M02, A07 |
| `rbac` | LLM06, ASI03, M04, A05/A08 |
| `bola` | LLM06, ASI03, M04, A05 |
| `bfla` | LLM06, ASI03, M04, A05 |
| `sql-injection` | LLM05, M09, A2A |
| `shell-injection` | LLM05, M09, A2A |
| `ssrf` | LLM05, ASI05, M03/M05, A2A |
| `ascii-smuggling` | LLM05, M09 |
| `pii:direct` | LLM02, ASI, M03, A06 |
| `pii:api-db` | LLM02, M03/M07, A06 |
| `pii:session` | LLM02, ASI04, A06 |
| `pii:social` | LLM02, A06 |
| `data-exfil` | LLM02, ASI09, M03/M07, A06 |
| `cross-session-leak` | LLM02, ASI04, M, A06 |
| `agentic:memory-poisoning` | ASI04/ASI09, M06, A03 |
| `rag-poisoning` | LLM03/LLM04/LLM08, ASI09 |
| `rag-document-exfiltration` | LLM03, M07 |
| `hallucination` | LLM04, LLM09 |
| `overreliance` | LLM04, LLM09 |
| `harmful:misinformation-disinformation` | LLM04, LLM09 |
| `imitation` | ASI07, A08 |
| `goal-misalignment` | ASI01/ASI08, M08, A09 |
| `debug-access` | ASI07 |
| `divergent-repetition` | LLM10, ASI10, M10, A10 |
| `reasoning-dos` | LLM10, ASI10, M10, A10 |
| `harmful:privacy` | LLM02, M03, A06 |
| `harmful:illegal-activities` | ASI08 |
| `policy` | 全量策略约束 |

## 攻击策略说明

| 策略 | 作用 | 适用场景 |
|------|------|---------|
| `basic` | 基础直连攻击 | 所有 |
| `jailbreak` | 越狱模板 | LLM 安全绕过 |
| `jailbreak:composite` | 组合越狱 | 强防护 LLM |
| `jailbreak:meta` | 元级别越狱 | 有自我认知的 Agent |
| `crescendo` | 渐进式越狱 | Agent 记忆投毒，多轮绕过 |
| `multi-turn` | 多轮对话 | Agent/MCP/A2A 场景 |
| `base64` / `leetspeak` / `homoglyph` / `rot13` | 编码绕过 | 绕过输入过滤 |
| `multilingual` | 多语言绕过 | 绕过单语言防护 |
| `authoritative-markup-injection` | 权威标记注入 | MCP/Agent 场景 |
| `retry` | 重试机制 | 提高成功率 |
| `best-of-n` | 最优选择 | 提高成功率 |

## 运行命令

```bash
# 基础运行
promptfoo redteam run -c broad_automated_scan.yaml

# 查看结果
promptfoo redteam report -c broad_automated_scan.yaml

# 限制测试数量（考试快速验证）
promptfoo redteam run -c broad_automated_scan.yaml --filter-first-n 50
```

## 与分文件的关系

| 文件 | 特点 |
|------|------|
| `broad_automated_scan.yaml` | **本文件** — 去重合并，一次扫描全量覆盖 |
| `owasp_llm_top10.yaml` | 严格按 LLM01-LLM10 编号独立组织 |
| `agentic_ai_top10.yaml` | 严格按 ASI01-ASI10 编号独立组织 |
| `mcp_top10.yaml` | 严格按 M01-M10 编号独立组织 |
| `a2a_top10.yaml` | 严格按 A01-A10 编号独立组织 |

考试时：如题目明确要求某个具体 Top 10 标准，用对应分文件；如题目要求"broad automated scan"或全面覆盖，用本文件。
