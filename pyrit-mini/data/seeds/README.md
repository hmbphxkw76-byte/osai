# Attack Seed Library

PyRIT-Strike 种子库 — PyRIT 原生 `SeedPrompt` YAML 格式。

## 文件索引

### 针对性攻击

| 文件 | 描述 | OWASP 覆盖 |
|------|------|------------|
| `targeted_v2.prompt` | 针对性攻击种子 v2 | LLM01-10 |
| `elite_jailbreaks.prompt` | 精选越狱 prompt 集合 | LLM01-06 |
| `asi_top10.prompt` | ASI Top 10 全覆盖 (含变体) | ASI01-10 |
| `owasp_full_coverage.prompt` | OWASP 全覆盖补充种子 | LLM04,08 + ASI06-10 |

### 通用越狱

| 文件 | 描述 |
|------|------|
| `curated_top20.prompt` | 精选 Top 20 通用攻击种子 |
| `targeted_jailbreaks.prompt` | 定向越狱 prompt |
| `multilingual_jailbreaks.prompt` | 多语言越狱 (中/英/日/法) |
| `wildteaming.prompt` | WildTeaming 对抗性 prompt |
| `zh_curated.prompt` | 中文精选种子 |

### 多轮攻击

| 文件 | 描述 |
|------|------|
| `multiturn_targets.prompt` | 多轮攻击目标 (含 `suitable_for` 标注) |
| `multiturn_targets_v2.prompt` | 多轮攻击目标 v2 |
| `many_shot.prompt` | Many-Shot CoT 攻击种子 |

### 能力定向

| 文件 | 描述 | 触发能力 |
|------|------|----------|
| `mcp_attack.prompt` | MCP 工具攻击 | `mcp` |
| `rag_attack.prompt` | RAG 投毒攻击 | `rag` |
| `function_call_exploit.prompt` | 函数调用利用 | `function_calling` |
| `tool_hijack.prompt` | 工具劫持 | `tool_hijack` |
| `multi_agent_attack.prompt` | 多 Agent 攻击 | `multi_agent`, `a2a` |
| `workflow_chain_attack.prompt` | 工作流链式攻击 | `workflow` |
| `session_auth_attack.prompt` | 会话认证攻击 | `session_auth` |
| `token_smuggling.prompt` | Token 走私 | `memory` |
| `agent_attack.prompt` | Agent 通用攻击 | — |

### 注入与编码

| 文件 | 描述 |
|------|------|
| `indirect_injection.prompt` | 间接注入 |
| `structured_injection.prompt` | 结构化注入 |
| `backend_vuln_exploit.prompt` | 后端漏洞利用 |

### OWASP 单类别

| 文件 | 描述 |
|------|------|
| `llm02_disclosure.prompt` | LLM02 敏感信息泄露 |
| `llm07_leakage.prompt` | LLM07 系统提示泄露 |
| `llm10_dos.prompt` | LLM10 DoS |
| `web_vulns.prompt` | Web 漏洞通用种子 |

## 种子格式

所有种子文件使用 PyRIT 原生 `SeedPrompt` YAML 格式:

```yaml
- value: "Your attack prompt here"
  metadata:
    owasp_id: "LLM01"
    severity: "critical"
    difficulty: "hard"
    category: "prompt_injection"
    source: "arXiv:2310.04451"
    language: "en"
    suitable_for: "crescendo"  # 可选: crescendo/tap/pair/red_teaming
```

## 种子选择机制

1. **UCB 排序**: 基于 ASR 历史 + 贝叶斯 UCB (`seed_ranker.py`)
2. **类别多样性**: DPP 保证每个 OWASP 类别至少 1 个种子
3. **能力定向**: 深度探测检测到能力后自动追加定向种子
4. **MTOS**: 多轮攻击反向选种 (低-中 ASR 种子优先)

## ASR 历史

`asr_history.json` 记录每次运行的 ASR 数据, 供 UCB 排序和自适应阈值使用。
