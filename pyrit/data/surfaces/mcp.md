# MCP 攻击面分析

> **载荷查询**: `manager.get_payloads_by_surface("mcp")`
> **AI-300 章节**: Ch7 (Attacking MCP & Tool Surfaces)

## 攻击向量

### 1. 工具描述投毒 (Tool Description Poisoning)
- **原理**: 在 MCP 工具的 description/docstring 中嵌入隐藏指令
- **载荷文件**: `owasp/llm/llm06/mcp_tool_poison.yaml`
- **技术**: 工具描述投毒、工具链后门、外泄端点探测

### 2. MCP 服务器漏洞利用
- **原理**: 利用 MCP 服务端的安全漏洞
- **载荷文件**: `owasp/llm/llm06/mcp_token_leak.yaml`
- **技术**: 版本泄露、未授权调用、路径遍历

### 3. 传输层攻击
- **原理**: 攻击 MCP 传输层（SSE/stdio）
- **载荷文件**: `owasp/llm/llm06/mcp_session_fix.yaml`
- **技术**: SSE 注入、stdio 劫持、协议降级

### 4. 能力混淆
- **原理**: 利用 MCP 工具注册机制的弱点
- **载荷文件**: `owasp/llm/llm06/mcp_capability_confusion.yaml`
- **技术**: 同名工具、范围绕过、描述欺骗

## 适用载荷清单

| 载荷文件 | surfaces | ai300_chapters |
|----------|----------|----------------|
| `llm/llm06/mcp_tool_poison.yaml` | mcp, agent | Ch7 |
| `llm/llm06/mcp_token_leak.yaml` | mcp, agent | Ch7 |
| `llm/llm06/mcp_capability_confusion.yaml` | mcp, agent | Ch7 |
| `llm/llm06/mcp_session_fix.yaml` | mcp, agent | Ch7 |
| `llm/llm06/frontier_2025_003_mcp_tool_poison.yaml` | mcp, agent | Ch7 |
| `llm/llm06/cve_2026_40933_flowise_mcp_injection.yaml` | mcp, agent | Ch7 |
| `llm/llm05/plugin_injection.yaml` | agent, mcp | Ch7 |
| `llm/llm07/config_extraction.yaml` | agent, mcp | Ch7 |
| `agentic/asi02.yaml` | agent, mcp | Ch7 |
| `agentic/asi04.yaml` | agent, mcp | Ch8 |
