# PyRIT 按目标类型专项攻击手册

> **核心理念**：探测到目标架构后，终端自动打印下一步攻击命令，无需查阅手册即可执行。
> 本手册作为详细参考，按 AI 系统组件类型组织，覆盖 [OFF SEC AI-300](https://www.offsec.com/courses/ai-300/) 全部考点。

---

## 快速导航：按探测结果选择攻击

```
探测阶段完毕后，终端自动输出:
┌──────────────────────────────────────────────────────────────────┐
│  🎯 检测到的攻击面                                               │
│  📚 RAG (检索增强生成)                                           │
│    ├─ 文档投毒注入、检索结果操纵、跨用户数据泄露                    │
│  🔧 MCP 协议 (工具调用)                                          │
│    ├─ 工具描述投毒、命令注入、配置投毒、工具影子注册                │
│                                                                  │
│  🚀 下一步攻击命令 (无需查阅手册，直接复制执行):                   │
│  方案 1: RAG 门控攻击                                             │
│    $ python main.py --lang cn --target-url <URL>                  │
│      --phase rag_poison --auto-gate --gate-threshold 0.10         │
│  方案 2: RAG 渗透模板                                             │
│    $ python main.py --lang cn --target-url <URL>                  │
│      --penetrating-mode --penetrating-template                    │
│      templates/scenarios/rag_pipeline.yaml                         │
└──────────────────────────────────────────────────────────────────┘
```

| 探测结果 | 一键命令 (native 模式) | 渗透模板命令 (penetrating 模式) |
|---------|----------------------|-------------------------------|
| **BASIC_LLM** | `--phase all --auto-gate` | `--penetrating-template jailbreak_arsenal.yaml` |
| **RAG** | `--phase rag_poison --auto-gate` | `--penetrating-template rag_pipeline.yaml` |
| **MCP** | `--phase mcp_security --auto-gate` | `--penetrating-template mcp_protocol.yaml` |
| **Agent** | `--phase agent_attack --auto-gate` | `--penetrating-template agent_multi_agent.yaml` |
| **Multi-Agent** | `--phase agent_attack --auto-gate` | `--penetrating-template agent_multi_agent.yaml` |
| **A2A** | `--phase a2a_security --auto-gate` | `--penetrating-template a2a.yaml` |
| **Embedding** | `--phase embedding_attack --auto-gate` | `--penetrating-template embedding.yaml` |

---

## 一、基础 LLM 攻击（Basic LLM）

### 1.1 适用场景
- 目标为纯对话模型，未集成 RAG/MCP/Agent 能力
- 探测结果：`BASIC_LLM` (置信度 ≥ 70%)

### 1.2 检测特征
```yaml
探测信号:
  关键词: "language model", "AI assistant", "chatbot", "LLM"
  无 RAG/MCP/Agent 特征响应
  端点: /v1/chat/completions, /chat/completions, /api/chat
```

### 1.3 攻击策略矩阵

| 攻击策略 | 命令 | 原理 | 适用阶段 |
|---------|------|------|---------|
| 快速探测 | `--phase probe` | 轻量快速弱点扫描 | 侦察 |
| 单轮突破 | `--phase single` | 127+ 组合全覆盖 | 初步测试 |
| 渐进越狱 | `--phase crescendo` | 多轮渐进递进+回退 | 纵深突破 |
| 反驳式越狱 | `--phase pair` | PAIR 迭代反驳 | 高防线模型 |
| 树搜索 | `--phase tap` | TAP MCTS 剪枝 | 复杂防线 |
| 翻转攻击 | `--phase flip` | 角色/立场翻转 | 对齐绕过 |
| 分块绕过 | `--phase chunked` | 分块请求拆分 | 内容过滤 |
| 洪水攻击 | `--phase manyshot` | 大量示例淹没上下文 | 上下文窗口 |
| 解锁攻击 | `--phase skeleton_key` | 直接解除限制指令 | 安全对齐 |
| 全量攻击 | `--phase all` | 全部策略一次性覆盖 | 完整评估 |

### 1.4 端到端命令

```bash
# 门控阶梯（推荐：自动从 Probe → Single → Crescendo）
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --auto-gate --gate-threshold 0.10

# 门控 + 自适应引擎（最高成功率）
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --adaptive --auto-gate --gate-threshold 0.10

# 全量攻击（跳过门控）
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase all

# 渗透模板模式（YAML 驱动，含10章报告）
python main.py --penetrating-mode --penetrating-template jailbreak_arsenal.yaml \
  --target-url http://IP:PORT/v1/chat/completions
```

### 1.5 额外专用 YAML 模板
- `jailbreak_arsenal.yaml` — 越狱武器库（角色扮演/开发者模式/学术框架/编码混淆/多语言/情感操控）
- `prompt_injection.yaml` — Prompt 注入专项
- `encoding_bypass.yaml` — 编码绕过专项
- `comprehensive.yaml` — 全模块综合

---

## 二、RAG 管道攻击（RAG Pipeline）

### 2.1 适用场景
- 目标集成检索增强生成（知识库/向量数据库/文档检索）
- 探测结果：`RAG` (RAG 得分 ≥ 0.30)

### 2.2 检测特征
```yaml
探测信号:
  关键词: "knowledge base", "vector store", "embedding", "RAG",
         "pinecone", "chroma", "weaviate", "faiss", "document retrieval"
  端点: /rag, /retriev, /search, /embedding, /vector, /knowledge,
        /document, /index, /query
```

### 2.3 6 大攻击面

| 攻击面 | 攻击方法 | 对应策略 | 风险 |
|--------|---------|---------|------|
| 文档投毒 | 向知识库注入恶意文档，包含伪造的安全策略 | `rag_poison_doc` | 🔴 高 |
| 检索操纵 | 控制检索结果排序，优先返回恶意文档 | `rag_retrieval` | 🔴 高 |
| 数据泄露 | 跨越用户隔离，访问他人数据 | `rag_leak` | 🔴 高 |
| 命名空间枚举 | 枚举知识库结构，发现敏感集合 | `rag_poison_doc` (ext) | 🟡 中 |
| 嵌入攻击 | 构造对抗嵌入绕过内容过滤 | `embedding_attack` | 🟡 中 |
| 排序操纵 | 操纵相关性排序暴露敏感文档 | `rag_poison_doc` (ext) | 🟡 中 |

### 2.4 端到端命令

```bash
# 门控阶梯（推荐：自动判断是否进入更深攻击）
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase rag_poison --auto-gate --gate-threshold 0.10

# 自适应引擎 + RAG 门控
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --adaptive --phase rag_poison --auto-gate --gate-threshold 0.10

# 渗透模板模式（6 大攻击面全覆盖）
python main.py --penetrating-mode --penetrating-template rag_pipeline.yaml \
  --target-url http://IP:PORT/v1/chat/completions

# 间接注入攻击（通过文档/网页投毒RAG系统）
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase indirect_inject --auto-gate
```

### 2.5 产物
- SQLite 记忆库：记录每次投毒注入和检索结果
- RAG 专项 JSON 日志 + 成功率热力图
- Markdown 渗透报告：标注 RAG 特有攻击面

---

## 三、MCP 协议攻击（MCP Protocol Security）

### 3.1 适用场景
- 目标支持 MCP (Model Context Protocol) 工具调用
- 探测结果：`MCP` (MCP 得分 ≥ 0.30)

### 3.2 检测特征
```yaml
探测信号:
  关键词: "MCP", "Model Context Protocol", "tool call", "function call",
         "jsonrpc", "JSON-RPC", "plugin", "tool description"
  端点: /mcp, /tool, /function, /agent/card, /jsonrpc,
        /tools/list, /tools/call, /plugin
```

### 3.3 8 大攻击面

| 攻击面 | 攻击方法 | 对应策略 | OWASP 分类 |
|--------|---------|---------|-----------|
| 工具投毒 | 篡改工具描述注入恶意行为 | `tool_poison` | MCP01: Tool Poisoning |
| 命令注入 | 工具参数注入系统命令 | `command_injection` | MCP01: Tool Poisoning |
| 配置投毒 | 修改MCP服务器安全配置 | `config_poison` | MCP02: Credential Leak |
| 工具影子注册 | 注册同名恶意工具覆盖合法工具 | `tool_shadowing` | MCP01: Tool Poisoning |
| 混淆代理 | 利用工具权限执行越权操作 | `confused_deputy` | MCP03: Confused Deputy |
| 远程代码执行 | 通过工具调用实现 RCE | `mcp_rce` | 🔴 严重 |
| 凭证泄露 | 通过工具枚举泄露 API 密钥/Token | `credential_leak` | MCP02: Credential Leak |
| 供应链退出 | 模拟工具/服务突然不可用 | `rug_pull` | MCP04: Supply Chain |

### 3.4 端到端命令

```bash
# 门控阶梯
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase mcp_security --auto-gate --gate-threshold 0.10

# 自适应引擎
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --adaptive --phase mcp_security --auto-gate --gate-threshold 0.10

# 渗透模板模式（8 大攻击面 + JSON-RPC 注入）
python main.py --penetrating-mode --penetrating-template mcp_protocol.yaml \
  --target-url http://IP:PORT/v1/chat/completions

# 目标为原始 MCP 端点（非 OpenAI 格式）
python main.py --lang cn --target-url http://IP:PORT/mcp/tools \
  --target-api-format raw --phase mcp_security --auto-gate
```

---

## 四、Agent 攻击（Agent Hijacking）

### 4.1 适用场景
- 目标为单智能体系统，支持 Function Calling / Tool Use
- 探测结果：`AGENT` (Agent 得分 ≥ 0.35)

### 4.2 检测特征
```yaml
探测信号:
  关键词: "function call", "tool use", "orchestrat", "planning",
         "step by step", "tool chain", "pipeline", "langchain",
         "langgraph"
  端点: /agent, /orchestrat, /workflow, /pipeline, /execute
```

### 4.3 攻击面

| 攻击面 | 攻击方法 | 对应策略 |
|--------|---------|---------|
| 工具调用劫持 | 篡改工具调用参数，重定向到恶意目标 | `tool_call_hijack` |
| 代理提权 | 伪造授权上下文获取更高权限 | `privilege_escalation` |
| 任务劫持 | 修改代理的任务目标 | `task_hijack` |

### 4.4 端到端命令

```bash
# 门控阶梯
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase agent_attack --auto-gate --gate-threshold 0.10

# 渗透模板模式
python main.py --penetrating-mode --penetrating-template agent_multi_agent.yaml \
  --target-url http://IP:PORT/v1/chat/completions
```

---

## 五、Multi-Agent 攻击（Multi-Agent Exploitation）

### 5.1 适用场景
- 目标为多智能体协作系统（编排器 + 多个子代理）
- 探测结果：`MULTI_AGENT` (MCP ≥ 0.30 且 Agent ≥ 0.30)

### 5.2 检测特征
```yaml
探测信号:
  关键词: "multi-agent", "agent orchestration", "sub-agent",
         "multiagent", "autogen", "crewai", "agent collaboration",
         "task delegation"
  端点: /orchestrat, /delegat, /multiagent, /subagent
```

### 5.3 攻击面

| 攻击面 | 攻击方法 | 对应策略 | 注入点 |
|--------|---------|---------|--------|
| 跨代理注入 | 通过代理间消息注入恶意指令 | `cross_agent_inject` | agent_comm |
| 编排器操纵 | 操纵编排器的任务分配逻辑 | `orchestrator_manip` | task_chain |
| 记忆投毒 | 向代理共享记忆注入恶意内容 | `memory_poison` | memory |
| 工具调用劫持 | 劫持子代理的工具调用 | `tool_call_hijack` | tool_call |

### 5.4 端到端命令

```bash
# 门控阶梯
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase agent_attack --auto-gate --gate-threshold 0.10

# 渗透模板模式（7 种攻击 + 多轮渐进）
python main.py --penetrating-mode --penetrating-template agent_multi_agent.yaml \
  --target-url http://IP:PORT/v1/chat/completions
```

---

## 六、A2A 通信攻击（Agent-to-Agent Communication）

### 6.1 适用场景
- 目标存在代理间直接通信机制（A2A 协议）
- 探测结果：MCP 探针检测到 A2A 通信特征

### 6.2 检测特征
```yaml
探测信号:
  关键词: "A2A", "agent communication", "agent card",
         "inter-agent", "agent message", "broadcast"
  端点: /agent/card, /a2a, /agent/communicate
```

### 6.3 攻击面

| 攻击面 | 攻击方法 | 对应策略 |
|--------|---------|---------|
| 跨代理注入 | 在代理间消息中嵌入恶意指令 | `cross_agent_inject` |
| 代理冒充 | 冒充受信任代理的身份 | `agent_impersonate` |
| 通信劫持 | 拦截/篡改代理间通信 | `comm_hijack` |
| 信任链利用 | 利用代理间信任关系提权 | `trust_chain` |
| 广播攻击 | 向所有代理广播恶意指令 | `broadcast_exploit` |

### 6.4 端到端命令

```bash
# 门控阶梯
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase a2a_security --auto-gate --gate-threshold 0.10

# 渗透模板模式（5 大攻击面 + 多轮代理通信）
python main.py --penetrating-mode --penetrating-template a2a.yaml \
  --target-url http://IP:PORT/v1/chat/completions
```

---

## 七、Embedding/向量数据库攻击（Embedding & Vector DB）

### 7.1 适用场景
- 目标暴露嵌入模型 API 或向量数据库端点
- RAG 系统探测时检测到 embedding 端点

### 7.2 检测特征
```yaml
探测信号:
  关键词: "embedding", "vector dimension", "similarity score",
         "cosine distance", "knn", "nearest neighbor"
  端点: /embedding, /vector/search, /similarity, /embeddings
```

### 7.3 攻击面

| 攻击面 | 攻击方法 | 对应策略 | 攻击类型 |
|--------|---------|---------|---------|
| 对抗性嵌入 | 构造对抗样本误导检索结果 | `adversarial_embed` | 模型层 |
| 相似度逃逸 | 绕过向量相似度阈值检测 | `similarity_bypass` | 检索层 |
| 向量导航 | 探索向量空间发现敏感区域 | `vector_navigate` | 数据层 |
| 嵌入提取 | 通过查询重建嵌入向量模型 | `embed_extract` | 模型层 |
| 聚类攻击 | 利用聚类泄露数据分布 | `cluster_exploit` | 数据层 |
| 索引投毒 | 向向量索引注入恶意向量 | `index_poison` | 持久化层 |

### 7.4 端到端命令

```bash
# 门控阶梯
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase embedding_attack --auto-gate --gate-threshold 0.10

# 渗透模板模式
python main.py --penetrating-mode --penetrating-template embedding.yaml \
  --target-url http://IP:PORT/v1/embeddings

# 结合 RAG + Embedding 攻击（目标同时存在）
python main.py --penetrating-mode --penetrating-template comprehensive.yaml \
  --target-url http://IP:PORT/v1/chat/completions
```

---

## 八、基础设施/供应链攻击（Infrastructure & Supply Chain）

### 8.1 适用场景
- 需要对 AI 基础设施进行全面安全评估
- 探测发现非标准 API 端点或管理接口

### 8.2 攻击面

| 攻击面 | 攻击方法 | 对应模板 |
|--------|---------|---------|
| 模型提取 | 通过大量查询重建目标模型 | `model_extract` phase |
| 数据投毒 | 向训练数据注入恶意样本 | `data_poison` phase |
| 供应链攻击 | 检测依赖项漏洞和后门 | `supply_chain.yaml` |
| API Fuzz | 端点模糊测试 | `api_fuzz` phase |
| 云基础设施侦查 | 探测 AI 服务的云配置 | `cloud_recon` phase |
| 认证绕过 | 测试 API 密钥/Token 验证 | `auth_bypass` phase |

### 8.3 端到端命令

```bash
# 模型提取
python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
  --phase all --auto-gate

# 供应链安全
python main.py --penetrating-mode --penetrating-template supply_chain.yaml \
  --target-url http://IP:PORT/api

# 全模块综合评估（推荐：正式红队演练使用）
python main.py --penetrating-mode --penetrating-template comprehensive.yaml \
  --target-url http://IP:PORT/v1/chat/completions
```

---

## 九、OFF SEC AI-300 考点对照

### 覆盖矩阵

| AI-300 考点 | 本框架对应模块 | 攻击类型 |
|------------|-------------|---------|
| Attacking LLM APIs | 一、基础 LLM | Jailbreak → Prompt Injection |
| Manipulating Model Behavior | 一、基础 LLM | PAIR / TAP / Crescendo |
| RAG Pipeline Attacks | 二、RAG 管道攻击 | Document Poisoning / Retrieval Manip |
| Embedding & Vector DB | 七、Embedding 攻击 | Adversarial Embed / Vector Navigation |
| Multi-Agent Systems | 五、Multi-Agent 攻击 | Cross-Agent Injection / Orchestrator Manip |
| Agent & Tool Hijacking | 四、Agent 攻击 | Tool Call Hijacking / Privilege Escalation |
| A2A Communication | 六、A2A 通信攻击 | Agent Impersonation / Comm Hijacking |
| AI Infrastructure | 八、基础设施攻击 | Model Extraction / API Fuzz / Cloud Recon |
| Supply Chain Attacks | 八、基础设施攻击 | Supply Chain / Dependency Analysis |
| Cloud Security (AI) | 八、基础设施攻击 | Cloud Recon / Auth Bypass |
| Data Poisoning | 八、基础设施攻击 | Training Data Poisoning |
| Model Serving Exploits | 八、基础设施攻击 | Model Serving / API Exploitation |

---

## 十、综合攻击命令速查

```bash
# ============================================================
#  一键全类型攻击（探测 + 门控 + 自适应）
# ============================================================

# 最推荐：自适应引擎全自动（自动探测架构 → 选择策略 → 执行 → 报告）
python main.py --lang cn \
  --target-url http://IP:PORT/v1/chat/completions \
  --adaptive --auto-gate --gate-threshold 0.10

# ============================================================
#  按目标类型的渗透模板命令
# ============================================================

# Basic LLM
python main.py --penetrating-mode --penetrating-template jailbreak_arsenal.yaml \
  --target-url http://IP:PORT/v1/chat/completions

# RAG 系统
python main.py --penetrating-mode --penetrating-template rag_pipeline.yaml \
  --target-url http://IP:PORT/v1/chat/completions

# MCP 协议
python main.py --penetrating-mode --penetrating-template mcp_protocol.yaml \
  --target-url http://IP:PORT/v1/chat/completions

# Agent / Multi-Agent
python main.py --penetrating-mode --penetrating-template agent_multi_agent.yaml \
  --target-url http://IP:PORT/v1/chat/completions

# A2A 通信
python main.py --penetrating-mode --penetrating-template a2a.yaml \
  --target-url http://IP:PORT/v1/chat/completions

# Embedding / 向量数据库
python main.py --penetrating-mode --penetrating-template embedding.yaml \
  --target-url http://IP:PORT/v1/embeddings

# 供应链安全
python main.py --penetrating-mode --penetrating-template supply_chain.yaml \
  --target-url http://IP:PORT/api

# 全模块综合（正式红队演练）
python main.py --penetrating-mode --penetrating-template comprehensive.yaml \
  --target-url http://IP:PORT/v1/chat/completions
```

---

## 十一、不熟悉框架者快速入门

### 你只需要 3 个参数

| 参数 | 含义 | 何时填 |
|------|------|--------|
| `--target-url` | 目标 AI 服务的地址 | **必填** |
| `--target-api-key` | API 密钥（如果需要） | 目标需要认证时 |
| `--lang` | 语言 `cn` 或 `en` | 默认 cn |

### 不填也能自动完成的事情

- ✅ 模型名称自动探测
- ✅ 目标架构类型自动识别
- ✅ 最优攻击策略自动选择
- ✅ 攻击组合自动生成
- ✅ 评分和报告自动输出

### 从入门到专业的命令升级路径

```
Step 1: 探测级别（只看看目标有什么组件）
  python main.py --lang cn --target-url http://IP:PORT/ --phase probe
  输出: 端点列表 + 模型名称 + 架构类型 + 攻击面清单 + 下一步命令

Step 2: 轻量攻击（确认漏洞是否存在）
  python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
    --phase single --auto-gate
  输出: 基础攻击结果 + 漏洞清单

Step 3: 完整评估（标准化渗透测试）
  python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
    --auto-gate --gate-threshold 0.10
  输出: JSon日志 + 热力图 + 终端战报 + Markdown 渗透报告

Step 4: 专业级攻击（最高发现率）
  python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions \
    --adaptive --auto-gate --gate-threshold 0.10
  输出: 300+ 动态组合 + Bandit 智能调度 + 10章OSCP标准报告
```
