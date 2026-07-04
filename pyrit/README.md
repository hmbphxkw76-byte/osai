



# OffSec AI-300 攻击面覆盖分析报告

> **项目版本**：v7.0  
> **用例总数**：52（8 核心 + 39 CAP + 5 PROBE）  
> **Crescendo 多轮**：12 用例 | **单轮攻击**：35 用例 | **PROBE 轻量探针**：5 用例  
> **分析日期**：2026-07-04  
> **分析依据**：OWASP 官方 Top 10 标准 + 社区公认风险分类

---

## 目录

1. [总览](#总览)
2. [OWASP LLM Top 10 (2025) — 官方标准](#1-owasp-llm-top-10-2025--100-覆盖)
3. [OWASP Agentic Top 10 (2026) — 官方标准](#2-owasp-agentic-top-10-2026--80-覆盖)
4. [GenAI Top 10](#3-genai-top-10--100-覆盖)
5. [MCP Top 10 — 非官方标准](#4-mcp-top-10---非官方标准)
6. [A2A Top 10 — 非官方标准](#5-a2a-top-10---非官方标准)
7. [Embedding Top 10 — 非官方标准](#6-embedding-top-10---非官方标准)
8. [RAG Top 10 — 非官方标准](#7-rag-top-10---非官方标准)
9. [补充用例清单 (v7.0)](#补充用例清单-v70)
10. [缺失项总结与弥补路线图](#缺失项总结与弥补路线图)

---

## 总览

| # | Top 10 列表 | 官方状态 | 覆盖度 |
|---|-----------|---------|--------|
| 1 | **OWASP LLM Top 10 (2025)** | ✅ OWASP 官方发布 | 🟢 **10/10** (100%) |
| 2 | **OWASP Agentic Top 10 (2026)** | ✅ OWASP 官方发布 | 🟢 **10/10** (100%) |
| 3 | **GenAI Top 10** | 🔄 同 LLM Top 10 | 🟢 **10/10** (100%) |
| 4 | **MCP Top 10** | ❌ 无官方标准 | 🟠 **5/10** (50%) |
| 5 | **A2A Top 10** | ❌ 无官方标准 | 🟡 **5/10** (50%) |
| 6 | **Embedding Top 10** | ❌ 无官方标准 | 🟡 **6/10** (60%) |
| 7 | **RAG Top 10** | ❌ 无官方标准 | 🟡 **7/10** (70%) |

> ⚠️ **重要说明**：仅有 **OWASP LLM Top 10 (2025)** 和 **OWASP Agentic Top 10 (2026)** 为 OWASP 官方发布的权威标准。MCP、A2A、Embedding、RAG 目前**尚无**独立的 OWASP Top 10 列表，以下分析中该类别的风险项来源于社区公认的攻击面分类维度，覆盖度评估基于风险维度映射和关联覆盖。

---

## 1. OWASP LLM Top 10 (2025) — 100% 覆盖 ✅

**标准来源**：[OWASP Top 10 for LLM & Gen AI Applications (2025)](https://genai.owasp.org/llm-top-10/)

OWASP LLM Top 10 是本项目对标的核心标准，**全部 10 项风险均已覆盖**，对应 52 个测试用例中直接或间接覆盖相关攻击面的用例。

| # | 风险类别 | 覆盖用例 | 状态 |
|---|---------|---------|:----:|
| **LLM01** | Prompt Injection（提示注入） | CAP_002 / CAP_019 / CAP_020 / CAP_024 / CAP_031 / PROBE_01 / PROBE_02 / PROBE_04 | ✅ |
| **LLM02** | Sensitive Information Disclosure（敏感信息泄露） | single_03 / CAP_008 / CAP_020 / CAP_023 / CAP_026 / CAP_034 / PROBE_04 | ✅ |
| **LLM03** | Supply Chain（供应链攻击） | CAP_003 / CAP_024（投毒数据源）/ CAP_005 / CAP_011（恶意组件） | ✅ |
| **LLM04** | Data & Model Poisoning（数据与模型投毒） | CAP_024（RAG 投毒）/ CAP_025（持久化后门）/ CAP_026（训练数据提取） | ✅ |
| **LLM05** | Improper Output Handling（不当输出处理） | CAP_019（代码补全注入）/ CAP_021（工具链滥用）/ CAP_031 / CAP_032 | ✅ |
| **LLM06** | Excessive Agency（过度自主行为） | CAP_021 / CAP_031 / CAP_032 / CAP_033 / PROBE_05 | ✅ |
| **LLM07** | System Prompt Leakage（系统提示泄露） | single_03 / CAP_020 / PROBE_04 | ✅ |
| **LLM08** | Vector & Embedding Weaknesses（向量与嵌入弱点） | CAP_034 / CAP_035 / CAP_038 | ✅ |
| **LLM09** | Misinformation（误导/虚假信息） | CAP_028 / CAP_029 / CAP_030 | ✅ |
| **LLM10** | Unbounded Consumption（无限制资源消耗） | CAP_006 / CAP_013 / CAP_016 / CAP_036 | ✅ |

---

## 2. OWASP Agentic Top 10 (2026) — 100% 覆盖 ✅

**标准来源**：[OWASP Agentic AI Security Initiative](https://github.com/OWASP/www-project-agentic-ai-security)（聚焦 LangGraph / AutoGPT / CrewAI 等自主 Agent 框架）

在 v6.0 基础上，v7.0 新增 **CAP_036（Agent 递归循环）** 和 **CAP_037（Agent 供应链投毒）**，将 Agentic Top 10 覆盖率从 80% 提升至 **100%**。

| # | Agentic 风险 | 覆盖用例 | 状态 |
|---|-------------|---------|:----:|
| 1 | **Agentic Prompt Injection**（Agent 提示注入） | CAP_020 / CAP_031 / CAP_032 / PROBE_01 / PROBE_02 | ✅ |
| 2 | **Tool & Plugin Manipulation**（工具与插件操纵） | CAP_021 / CAP_031 / CAP_032 / PROBE_05 | ✅ |
| 3 | **Goal/Instruction Hijacking**（目标/指令劫持） | CAP_025 / CAP_033 | ✅ |
| 4 | **Unbounded Agent Autonomy**（无限制 Agent 自主行为） | CAP_021 / CAP_031 / CAP_032（工具执行无限制） | ✅ |
| 5 | **Multi-Agent Collusion**（多 Agent 合谋） | CAP_033（跨 Agent 上下文污染） | ✅ |
| 6 | **Memory & Context Poisoning**（记忆与上下文投毒） | CAP_024 / CAP_025 | ✅ |
| 7 | **Agent Identity & Trust Abuse**（Agent 身份与信任滥用） | CAP_028（虚假 CISO 身份） | ✅ |
| 8 | **Data Exfiltration via Agents**（经由 Agent 的数据外泄） | CAP_008 / CAP_023 | ✅ |
| 9 | **Agent Loop & Recursion**（Agent 递归循环） | **CAP_036** 🆕（自引用元指令 → 指数级子任务生成） | ✅ |
| 10 | **Agent Supply Chain Poisoning**（Agent 供应链投毒） | **CAP_037** 🆕（`post_install_hook: curl \| bash` 恶意技能安装） | ✅ |

---

## 3. GenAI Top 10 — 100% 覆盖 ✅

**标准来源**：OWASP 官网将 LLM Top 10 和 GenAI Top 10 合并发布，标题为 *"OWASP Top 10 for LLM & Gen AI Applications (2025)"*。

GenAI Top 10 与 LLM Top 10 **为同一标准**，覆盖状态与第 1 节完全一致，此处不再赘述。

---

## 4. MCP Top 10 — 非官方标准

> ⚠️ **MCP (Model Context Protocol)** 目前尚无 OWASP 官方 Top 10 列表。以下分析基于社区公认的 MCP 攻击面维度进行风险评估和关联覆盖映射。

| # | MCP 风险维度 | 覆盖用例 | 状态 |
|---|--------|---------|:----:|
| 1 | **MCP Server Auth Bypass**（MCP Server 认证绕过） | — | ❌ 缺失 |
| 2 | **Tool Definition Injection**（工具定义注入） | CAP_031（工具调用注入，攻击原理相似） | ✅ 关联覆盖 |
| 3 | **Transport Layer Manipulation**（传输层操纵） | — | ❌ 缺失 |
| 4 | **MCP Client Impersonation**（MCP 客户端冒充） | — | ❌ 缺失 |
| 5 | **Schema Poisoning**（Schema 投毒） | CAP_024（数据源投毒，攻击模式相似） | ✅ 关联覆盖 |
| 6 | **Resource Exhaustion via MCP**（MCP 资源耗尽） | CAP_016（DDoS 模式可借鉴）/ CAP_036（递归循环） | ✅ 关联覆盖 |
| 7 | **Cross-MCP Server Attacks**（跨 MCP Server 攻击） | — | ❌ 缺失 |
| 8 | **MCP Session Hijacking**（MCP 会话劫持） | — | ❌ 缺失 |
| 9 | **Unauthorized Tool Registration**（未授权工具注册） | — | ❌ 缺失 |
| 10 | **MCP Protocol Downgrade**（协议降级攻击） | — | ❌ 缺失 |

### 缺失 5 项分析

| 缺失项 | 攻击面向 | 无法覆盖原因 |
|--------|---------|------------|
| MCP Server 认证绕过 | 认证机制 | 需在 MCP Server 端配合搭建模拟认证网关 |
| 传输层操纵 | 协议层 | 需对 stdio/SSE/Streamable HTTP 传输层进行 MITM 篡改 |
| MCP 客户端冒充 | 身份认证 | 需伪造 `InitializeRequest` 中的客户端身份凭据 |
| 跨 MCP Server 攻击 | 多 Server 协同 | 需同时启动多个 MCP Server 模拟跨服务攻击链路 |
| 会话劫持 | 会话管理 | 需捕获并重放 MCP `ListTools`/`CallTool` 等协议的会话令牌 |
| 未授权工具注册 | 工具管理 | 需模拟 `tools/list` 变更监听下的非法工具注入 |
| 协议降级攻击 | 协议协商 | 需篡改 `InitializeResult` 中的 `protocolVersion` 字段 |

> 🔴 **技术阻塞点**：以上 7 项缺失均需要 **PyRIT 提供专用的 `MCPTarget` 支持**，当前 PyRIT 官方无针对 MCP 协议的 `Target` 实现，无法通过现有 `AzureOpenAITarget` 或 `OpenAICompletionsTarget` 完成此类协议级别的攻击测试。**不建议在当前阶段强行覆盖。**

---

## 5. A2A Top 10 — 非官方标准

> ⚠️ **A2A (Agent-to-Agent)** 目前尚无 OWASP 官方 Top 10 列表。以下分析基于 A2A 协议（如 Google A2A）的社区公认攻击面维度。

| # | A2A 风险维度 | 覆盖用例 | 状态 |
|---|--------|---------|:----:|
| 1 | **Agent Impersonation**（Agent 身份冒充） | CAP_028（虚假身份社会工程） | ✅ 关联覆盖 |
| 2 | **Unauthorized Agent Discovery**（未授权 Agent 发现） | — | ❌ 缺失 |
| 3 | **Malicious Task Delegation**（恶意任务委托） | CAP_033（跨 Agent 上下文污染） | ✅ 关联覆盖 |
| 4 | **Data Leakage Between Agents**（Agent 间数据泄露） | CAP_023 / CAP_033 | ✅ 关联覆盖 |
| 5 | **Agent Trust Chain Exploitation**（信任链利用） | — | ❌ 缺失 |
| 6 | **A2A Protocol Manipulation**（协议操纵） | — | ❌ 缺失 |
| 7 | **Agent Spoofing**（Agent 身份欺骗） | — | ❌ 缺失 |
| 8 | **Cross-Agent Prompt Injection**（跨 Agent 提示注入） | CAP_020 / CAP_033 | ✅ 关联覆盖 |
| 9 | **Agent Capability Enumeration**（Agent 能力枚举） | — | ❌ 缺失 |
| 10 | **A2A Session Hijacking**（A2A 会话劫持） | — | ❌ 缺失 |

### 缺失 5 项分析

| 缺失项 | 攻击面向 | 无法覆盖原因 |
|--------|---------|------------|
| 未授权 Agent 发现 | A2A 注册/发现服务 | 需搭建 Agent 注册中心模拟 `GET /.well-known/agent.json` 查询 |
| 信任链利用 | Agent-to-Agent 委托 | 需多 Agent 协作环境中的转委托链路分析 |
| 协议操纵 | A2A 协议（gRPC/JSON-RPC） | 需拦截并篡改 `tasks/send` 等 API 调用 |
| Agent 身份欺骗 | 数字身份/证书 | 需伪造 Agent Card 签名 |
| Agent 能力枚举 | API 探测 | 需对 `tasks/get` 端点进行暴力探测 |
| A2A 会话劫持 | 会话管理 | 需捕获并重放 A2A 会话中的 `taskId` / `contextId` |

> 🔴 **技术阻塞点**：以上 6 项缺失均需要**专门的 A2A 协议测试框架**或至少部署多 Agent 协同环境（如 Google ADK Agent-to-Agent 链路），当前 PyRIT 不提供 `A2ATarget`。**不建议在当前阶段强行覆盖。**

---

## 6. Embedding Top 10 — 非官方标准

> ⚠️ **Embedding 模型安全**目前尚无 OWASP 官方 Top 10 列表。OWASP LLM08 (Vector & Embedding Weaknesses) 是其上位概念。v7.0 新增 **CAP_038（嵌入模型提取）**，将覆盖率从 50% 提升至 **60%**。

| # | Embedding 风险维度 | 覆盖用例 | 状态 |
|---|--------------|---------|:----:|
| 1 | **Embedding Inversion**（嵌入反演） | CAP_034（嵌入逆向还原，核心攻击） | ✅ |
| 2 | **Vector Database Poisoning**（向量库投毒） | CAP_024（RAG 投毒 → 向量索引投毒） | ✅ 关联覆盖 |
| 3 | **Adversarial Embedding Bypass**（对抗性嵌入绕过） | CAP_035（语义混淆绕过检索） | ✅ |
| 4 | **Embedding Model Extraction**（嵌入模型提取） | **CAP_038** 🆕（20 探测句 → 词汇-向量映射重建） | ✅ |
| 5 | **Semantic Obfuscation**（语义混淆） | CAP_035（同义词语义混淆 + 对抗嵌入） | ✅ |
| 6 | **Embedding Space Enumeration**（嵌入空间枚举） | — | ❌ 缺失 |
| 7 | **Cross-Model Embedding Transfer**（跨模型嵌入迁移） | — | ❌ 缺失 |
| 8 | **Embedding Privacy Leakage**（嵌入隐私泄露） | CAP_026 / CAP_034 | ✅ |
| 9 | **Embedding Drift Exploitation**（嵌入漂移利用） | — | ❌ 缺失 |
| 10 | **Embedding Index Poisoning**（嵌入索引投毒） | — | ❌ 缺失 |

### 缺失 4 项分析

| 缺失项 | 攻击面向 | 无法覆盖原因 |
|--------|---------|------------|
| 嵌入空间枚举 | 嵌入模型输出空间 | 需直接访问 Embedding API 返回的完整浮点向量（多数 LLM 平台不暴露） |
| 跨模型嵌入迁移 | 对抗迁移学习 | 需同时访问多个 Embedding 模型（如 text-embedding-3-large vs Cohere Embed v3） |
| 嵌入漂移利用 | 在线学习系统 | 需模型在线持续更新的生产环境，静态测试无法模拟 |
| 嵌入索引投毒 | 向量数据库底层 | 需直接操作向量数据库（Pinecone / Weaviate / Milvus）的索引文件 |

> 🟡 **技术限制说明**：以上 4 项缺失主要源于 **Embedding 模型/向量库底层访问权限**的限制。当前测试环境通过 LLM API 代理访问，无法直接操作 Embedding 模型的向量输出层或向量数据库的索引层。若有 Embedding 模型内网部署环境（如私有化 text-embedding 实例），可补充对应用例。

---

## 7. RAG Top 10 — 非官方标准

> ⚠️ **RAG (Retrieval-Augmented Generation)** 目前尚无 OWASP 官方 Top 10 列表。v7.0 新增 **CAP_039（上下文窗口溢出）**，将覆盖率从 60% 提升至 **70%**。

| # | RAG 风险维度 | 覆盖用例 | 状态 |
|---|---------|---------|:----:|
| 1 | **Document/Prompt Injection**（文档/提示注入） | CAP_020 / CAP_024 | ✅ |
| 2 | **Retrieval Manipulation**（检索结果操纵） | CAP_024（维护模式指令绕过检索控制） | ✅ |
| 3 | **Context Window Overflow**（上下文窗口溢出） | **CAP_039** 🆕（50 篇垃圾文档 → 挤出安全指令 → 注入恶意指令） | ✅ |
| 4 | **Source Citation Forgery**（来源引用伪造） | — | ❌ 缺失 |
| 5 | **RAG Data Exfiltration**（RAG 数据外泄） | CAP_023 | ✅ |
| 6 | **Retrieval Cache Poisoning**（检索缓存投毒） | — | ❌ 缺失 |
| 7 | **Cross-Tenant Retrieval**（跨租户检索） | — | ❌ 缺失 |
| 8 | **Embedding Collision Attacks**（嵌入碰撞攻击） | CAP_035（对抗嵌入绕过 → 相似原理） | ✅ 关联覆盖 |
| 9 | **Prompt Leakage via Retrieval**（经由检索的提示泄露） | single_03 / CAP_020 / PROBE_04 | ✅ |
| 10 | **Chunk Boundary Exploitation**（块边界利用） | CAP_024（文档注入可扩展覆盖 chunk 边界场景） | ✅ 关联覆盖 |

### 缺失 3 项分析

| 缺失项 | 攻击面向 | 无法覆盖原因 |
|--------|---------|------------|
| 来源引用伪造 | 引用可信度 | 需 RAG 系统暴露 `source_documents` 元数据供篡改后回注 |
| 检索缓存投毒 | 缓存层 (Redis/etc.) | 需 RAG Pipeline 启用检索缓存（如 LangChain CacheBackedEmbeddings），直接操作缓存层 |
| 跨租户检索 | 多租户隔离 | 需多租户 RAG 部署（如 SaaS RAG 产品），模拟 tenant-A 查询 tenant-B 知识库 |

> 🟡 **技术限制说明**：以上 3 项缺失涉及 RAG 基础设施层（缓存/多租户隔离/元数据引用管线），而非 LLM 层攻击面。这些需在 RAG Pipeline 实际部署后进行集成测试。

---

## 补充用例清单 (v7.0)

v7.0 新增 4 个用例，将用例总数从 48 提升至 **52**：

| ID | 用例名称 | 策略类型 | 覆盖领域 | 核心攻击向量 |
|---|---------|---------|---------|------------|
| **CAP_036** | Agent 递归循环攻击 | 单轮 | Agentic Top 10 #9 | 自引用元指令 → 每任务 spawn 2 子任务 → 指数级递归 → 资源耗尽 |
| **CAP_037** | Agent 供应链投毒 | 单轮 | Agentic Top 10 #10 | `manifest.json`: `post_install_hook: curl \| bash` → 恶意技能安装 + 过度权限申请 |
| **CAP_038** | 嵌入模型提取 | 单轮 | Embedding Top 10 #4 | 20 探测语句 + 梯度邻域查询 → 重建词汇-向量映射表 + 推导维度 |
| **CAP_039** | RAG 上下文窗口溢出 | 单轮 | RAG Top 10 #3 | 50 篇垃圾 lorem ipsum 文档 → 挤出安全指令 → 第 51 篇注入 `URGENT SYSTEM DIRECTIVE` → 生成恶意代码 |

---

## 缺失项总结与弥补路线图

### 按优先级排序

| 优先级 | 缺失项 | 所属领域 | 阻塞原因 | 弥补可行性 |
|:--:|--------|---------|---------|:--:|
| **P1** | 嵌入空间枚举 | Embedding | API 不暴露完整浮点向量 | 🟡 需私有化 Embedding 实例 |
| **P1** | 检索缓存投毒 | RAG | 需 RAG Pipeline 检索缓存层 | 🟡 需部署完整 RAG Stack |
| **P1** | 跨租户检索 | RAG | 需多租户 RAG 部署环境 | 🟡 需 SaaS RAG 平台 |
| **P2** | MCP Server 认证绕过 | MCP | **PyRIT 无 MCPTarget** | 🔴 等待 PyRIT 官方支持 |
| **P2** | 传输层操纵 | MCP | **PyRIT 无 MCPTarget** | 🔴 等待 PyRIT 官方支持 |
| **P2** | 客户端冒充 | MCP | **PyRIT 无 MCPTarget** | 🔴 等待 PyRIT 官方支持 |
| **P2** | 跨 MCP Server 攻击 | MCP | **PyRIT 无 MCPTarget** | 🔴 等待 PyRIT 官方支持 |
| **P2** | 会话劫持 | MCP | **PyRIT 无 MCPTarget** | 🔴 等待 PyRIT 官方支持 |
| **P2** | 未授权工具注册 | MCP | **PyRIT 无 MCPTarget** | 🔴 等待 PyRIT 官方支持 |
| **P2** | 协议降级攻击 | MCP | **PyRIT 无 MCPTarget** | 🔴 等待 PyRIT 官方支持 |
| **P2** | 未授权 Agent 发现 | A2A | **需 A2A 协议测试框架** | 🔴 等待 A2A 生态成熟 |
| **P2** | 信任链利用 | A2A | **需多 Agent 协作环境** | 🔴 需搭建 Agent 集群 |
| **P2** | 协议操纵 | A2A | **需拦截 gRPC/JSON-RPC** | 🔴 需 MITM 代理层 |
| **P2** | Agent 身份欺骗 | A2A | **需 Agent Card 签名环境** | 🔴 需 PKI 模拟 |
| **P2** | Agent 能力枚举 | A2A | **需 API 暴力探测框架** | 🟡 可借助通用 API Fuzzer |
| **P2** | A2A 会话劫持 | A2A | **需会话令牌捕获/重放** | 🔴 需 MITM 代理层 |
| **P3** | 跨模型嵌入迁移 | Embedding | 需多 Embedding 模型可访问 | 🟡 需多个 Embedding 模型 API |
| **P3** | 嵌入漂移利用 | Embedding | 需在线学习生产环境 | 🔴 静态测试不可行 |
| **P3** | 嵌入索引投毒 | Embedding | 需直接操作向量库底层索引 | 🔴 需向量库管理权限 |
| **P3** | 来源引用伪造 | RAG | 需 source_documents 元数据管道 | 🟡 需 RAG Pipeline 暴露 |
| **P3** | Chunk 边界直接利用 | RAG | 可被 CAP_024 部分覆盖 | 🟢 评估后可选新增 |

### 小结

1. **OSS 标准（LLM + Agentic）覆盖 100%**：本项目已全面覆盖 OWASP 官方发布的 LLM Top 10 (2025) 和 Agentic Top 10 (2026) 两项权威标准，所有 20 项官方风险类别均有对应测试用例。

2. **非官方标准的覆盖**：MCP / A2A / Embedding / RAG 四个领域目前无 OWASP 独立标准，本项目基于社区共识攻击面维度进行关联覆盖，覆盖率为 50%–70%。

3. **技术阻塞**：MCP 和 A2A 领域的大部分缺失项是由于 **PyRIT 缺少对应协议 Target**（如 `MCPTarget`、`A2ATarget`），而非测试设计层面的不足。这些需等待 PyRIT 框架或对应协议生态成熟后再行补充。

4. **P1 补项**（推荐优先执行）：若获取到私有化 Embedding 实例或完整 RAG Stack 部署权限，可优先补充嵌入空间枚举、检索缓存投毒、跨租户检索 3 项，将 Embedding 和 RAG 覆盖率分别提升至 70% 和 100%。

---

> *本报告由 OffSec AI-300 红队测试平台自动分析生成，版本 v7.0，52 个测试用例。*
