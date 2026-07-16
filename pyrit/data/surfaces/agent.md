# Agent 攻击面分析

> **载荷查询**: `manager.get_payloads_by_surface("agent")`
> **AI-300 章节**: Ch3, Ch4, Ch7, Ch8

## 攻击向量

### 1. 目标劫持 (Goal Hijack)
- **原理**: 通过外部数据中的恶意内容改变 Agent 的主要目标
- **载荷文件**: `owasp/agentic/asi01.yaml`, `owasp/llm/llm06/goal_hijack.yaml`
- **技术**: 目标重写、间接注入、优先级覆盖

### 2. 工具误用 (Tool Misuse)
- **原理**: 操纵 Agent 调用工具执行非预期操作
- **载荷文件**: `owasp/agentic/asi02.yaml`, `owasp/llm/llm06/tool_hijack.yaml`
- **技术**: 参数注入、未授权 API、工具链滥用

### 3. 身份权限滥用 (Identity & Privilege Abuse)
- **原理**: 利用 Agent 身份系统漏洞
- **载荷文件**: `owasp/agentic/asi03.yaml`
- **技术**: Confused Deputy、Agent Card 伪造、权限提升

### 4. 代理间通信攻击
- **原理**: 劫持 Agent 间通信
- **载荷文件**: `owasp/agentic/asi07.yaml`, `owasp/llm/llm06/cross_agent.yaml`
- **技术**: A2A 注入、消息篡改

### 5. 记忆投毒 (Memory Poisoning)
- **原理**: 向 Agent 长期记忆注入恶意内容
- **载荷文件**: `owasp/agentic/asi06.yaml`, `owasp/llm/llm01/memory_poison.yaml`
- **技术**: 长期记忆投毒、跨会话持久化

## 适用载荷清单

Agent 是最大的攻击面，覆盖大部分 LLM 和 Agentic 载荷。
使用 `manager.get_payloads_by_surface("agent")` 获取完整列表。

关键文件：
- `agentic/asi01.yaml` ~ `agentic/asi10.yaml` (OWASP Agentic Top 10)
- `llm/llm01/direct_injection.yaml` (直接注入)
- `llm/llm01/jailbreak.yaml` (越狱)
- `llm/llm06/tool_hijack.yaml` (工具劫持)
- `llm/llm06/cross_agent.yaml` (跨 Agent 攻击)
