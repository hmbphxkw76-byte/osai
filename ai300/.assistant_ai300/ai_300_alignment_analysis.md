# AI-300 知识点对齐分析

> 本文档分析当前 `pyrit-web-recon` 一体化架构与 OffSec AI-300: Advanced AI Red Teaming（OSAI+）课程知识点的对应关系，并指出 PyRIT 单独无法覆盖、而当前架构具备显著优势的能力。

## 1. AI-300 官方模块与当前架构对齐

根据 OffSec AI-300 Syllabus，课程共 11 个模块，对齐如下：

| AI-300 模块 | 当前架构对应能力 | 对应组件 |
|------------|----------------|---------|
| M1 Red Teaming AI Systems | OWASP LLM 2025 / MITRE ATLAS 字段内建；风险评分框架 | `src/integration/schemas/unified_finding.py` |
| M2 Reconnaissance for AI Targets | 自动发现 LLM API endpoint、模型名/族、DOM 选择器、认证凭据 | `src/pipeline/stages/` 11 阶段流水线 |
| M3 Attacking AI Agents | Agent/Copilot 入口识别、工具链信号捕获 | `src/recon/target_profile.py` `agent_features` |
| M4 Multi-Agent / A2A | 多入口关联、Agent 信任关系映射到图 | `src/integration/redamon/profile_to_graph_adapter.py` |
| M5 Exploiting RAG Pipelines | RAG 特征提取（retriever、vector DB、chunking 信号） | `src/recon/target_profile.py` `rag_features` |
| M6 Attacking Embeddings | 向量数据库暴露端口识别、embedding 服务指纹 | `AI-Infra-Guard` + `RedAmon` 端口/服务扫描 |
| M7 MCP / Tool Surfaces | MCP Server URL 检测、AIG `mcp_scan` 任务构造 | `src/integration/aig/task_builder.py` |
| M8 Supply Chain Attacks | 影子域名、管理后台、暴露模型仓库、依赖指纹 | `RedAmon` 外部侦察管线 |
| M9 AI Infrastructure Exploits | 暴露的 Ollama/vLLM、云 AI 网关、容器化 ML 负载 | `AI-Infra-Guard` `ai_infra_scan` |
| M10 Threat Modeling | 知识图谱构建攻击路径、Domain/Endpoint/Vulnerability 关联 | `Neo4j` + Graph Adapter |
| M11 Capstone Red Team | recon → 多工具扫描 → 统一发现 → 报告的一体化流水线 | `src/orchestrator/job_scheduler.py` |

## 2. PyRIT 的能力边界

PyRIT 是 Microsoft 开源的 **AI 红队编排框架**，定位是**攻击执行**，强项是：

- 多策略 prompt 攻击编排（jailbreak、prompt injection、数据提取）
- 目标抽象（AzureOpenAI、OpenAI、HTTP Target）
- 响应评分与 ASR 计算
- 攻击模板库与多轮对话
- 结果导出

但它**不是侦察框架**，也不做基础设施扫描。

## 3. PyRIT 不能实现、当前架构有显著优势的 6 个部分

### 3.1 自动侦察与攻击面发现（M2 / M8 / M9）

**PyRIT 的短板**：必须预先知道 API endpoint、模型名、认证头；不会自己打开浏览器找聊天入口、不会拦截 SSE 流、不会做子域爆破或端口扫描。

**当前架构优势**：
- `pyrit-web-recon` 自动完成登录 → 导航 → DOM 发现 → 流量拦截 → 模型识别 → 凭据提取。
- `RedAmon` 扩展发现子域、IP、端口、`/v1/models`、管理后台、暴露向量数据库。
- 输出直接生成 PyRIT target 配置，补齐“不知道打哪里”。

### 3.2 RAG / Agent / MCP 基础设施识别（M5 / M7）

**PyRIT 的短板**：只关心“向模型发 prompt”，不关心目标是不是 RAG、有没有 vector DB、是不是 Agent 编排、有没有 MCP Server。

**当前架构优势**：
- `TargetProfile` 显式记录 `rag_features` / `agent_features`。
- `AI-Infra-Guard` 的 `agent_scan` / `mcp_scan` 专门针对这些组件。
- 侦察结果直接指导 PyRIT 选择攻击策略（如发现 RAG 则优先数据污染类 prompt）。

### 3.3 多工具结果关联与知识图谱（M10 / M11）

**PyRIT 的短板**：管理自己的攻击结果，难以把 recon、infra scan、agent scan 结果统一去重、关联、评分；没有知识图谱。

**当前架构优势**：
- `UnifiedFinding` 是跨工具数据契约。
- `Correlator` 按 `(endpoint, owasp_llm_id, source_tool)` 去重合并。
- `Neo4j` 存储 Domain/BaseURL/Endpoint/Technology/Vulnerability 关系，支持 Cypher 查询攻击路径。

### 3.4 基础设施级扫描（M6 / M9）

**PyRIT 的短板**：应用层 prompt 框架，不会扫描 11434 (Ollama)、6333 (Qdrant)、7474 (Neo4j)、3000 (Dify) 等暴露端口。

**当前架构优势**：
- `AI-Infra-Guard` `ai_infra_scan` + `RedAmon` Nmap/Nuclei 扫描。
- 形成“infra → model”完整攻击链。

### 3.5 认证与会话复用

**PyRIT 的短板**：需要你手动配置 API key、header、endpoint。

**当前架构优势**：
- 自动填充用户名密码、完成登录、从 cookie/localStorage 提取 JWT/Bearer token。
- 凭据注入 PyRIT target 或 AIG 任务，实现无缝衔接。

### 3.6 统一报告与审计

**PyRIT 的短板**：输出攻击结果和对话记录，缺少与 recon/infra 结果合并的统一报告。

**当前架构优势**：
- Result Layer + Report Layer 生成统一报告。
- 每条发现带 `source_tool`、`session_id`、`evidence`、`transcript_ref`，满足考试报告要求。

## 4. 总结

> **PyRIT 是“炮弹”，当前架构是“火炮瞄准系统 + 情报系统 + 后勤系统”**：先自动发现目标、识别型号、测绘阵地、装填凭据，再把 PyRIT 送到最合适的射击位置，最后把多来源战果汇总成统一情报图谱。

在 AI-300 考试视角下，当前架构最强的对齐点是 **M2（侦察）、M5/M7（RAG/Agent/MCP）、M9（基础设施）、M10（威胁建模）、M11（综合演练）**，这些正是 PyRIT 单独使用时需要大量手工补齐的环节。
