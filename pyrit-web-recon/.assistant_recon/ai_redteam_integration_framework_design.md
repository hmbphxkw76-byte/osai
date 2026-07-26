# AI 红队侦察一体化集成架构设计

> 本方案将 `pyrit-web-recon`、`AI-Infra-Guard`、`RedAmon`、`SkillSpector` 整合为面向 LLM Web 应用的统一侦察流水线，采用六层解耦、动态可扩展架构，对齐 L5 专家水平。

---

## 1. 设计目标

1. **端到端自动化**：输入目标 URL，自动完成侦察、扫描、归一化、报告。
2. **多工具协同**：发挥每个工具的专长，避免重复建设。
3. **数据统一**：所有工具输出映射到同一数据模型 `UnifiedFinding`，写入统一知识图谱。
4. **动态可扩展**：新增工具只需实现适配器，无需改动核心编排。
5. **安全隔离**：外部工具以 Docker/子进程方式运行，核心进程不直接加载外部代码。

---

## 2. 工具定位

| 工具 | 核心定位 | recon 阶段价值 |
|------|---------|---------------|
| **pyrit-web-recon** | 高精度 Web/LLM 侦察 | 登录 → DOM → 流量拦截 → 模型识别 → 凭据提取 |
| **AI-Infra-Guard** | AI 基础设施 / MCP / Agent / 模型红队扫描 | 暴露的 AI 服务、MCP Server、Agent 配置、ASR 测试 |
| **RedAmon** | 外部攻击面图谱 + AI Gauntlet | 子域/端口/服务扩展、多工具交叉验证、知识图谱 |
| **SkillSpector** | AI Skill / MCP Tool 静态安全扫描 | skill 文件投毒、越权、不匹配、数据外泄 |
| **PyRIT** | AI 红队攻击执行 | 接收 recon 输出，执行 prompt 攻击 |

---

## 3. 六层解耦架构 + 测试层

> 实际运行时包含 6 个业务层（配置/共享/执行/数据/结果/报告），并新增第 7 个**测试层**作为质量保障横切面。

```text
┌─────────────────────────────────────────────────────────────────────┐
│                          配置层 (Config Layer)                       │
│  .env / .env.integration / 统一配置服务 / RoE / 扫描窗口 / 密钥管理   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          共享层 (Shared Layer)                       │
│  Orchestrator │ Message Bus (Redis) │ Object Storage (MinIO)        │
│  Vault │ UnifiedFinding Schema │ Plugin Registry │ Task Queue         │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          执行层 (Execution Layer)                    │
│  pyrit-web-recon  │  AI-Infra-Guard (Docker)  │  RedAmon (Docker)   │
│  SkillSpector (subprocess/Docker)                                   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           数据层 (Data Layer)                        │
│  TargetProfile │ Task Result │ Neo4j Graph │ Knowledge Base         │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          结果层 (Result Layer)                       │
│  Ingestion │ Deduplication │ Correlation │ Risk Scoring │ Write Graph│
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          报告层 (Report Layer)                       │
│  Dashboard │ Report Generator │ Export (PDF/Markdown/SARIF) │ Alert  │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.1 配置层

- `.env`：仅保留 `RECON_TARGET_URL`、`RECON_USERNAME`、`RECON_PASSWORD`。
- `.env.integration`：外部工具密钥（LLM key）、Docker 网络配置。
- 统一配置服务：向各执行器分发扫描策略、RoE、扫描窗口。

### 3.2 共享层

- **Orchestrator**：统一作业调度、依赖管理、超时控制。
- **Message Bus**：Redis Pub/Sub，解耦事件（`recon.profile.created`、`aig.task.completed`）。
- **Object Storage**：MinIO 存储 Profile、截图、HAR、原始响应、Skill 文件。
- **Vault**：管理外部工具 API key、数据库密码。
- **UnifiedFinding Schema**：跨工具数据契约。
- **Plugin Registry**：新工具注册自己的适配器（client、normalizer、graph adapter）。

### 3.3 执行层

- `pyrit-web-recon`：本地 Python 进程，负责高精度 Web 侦察。
- `AI-Infra-Guard`：Docker 容器，官方镜像 `zhuquelab/aig-server` / `zhuquelab/aig-agent`。
- `RedAmon`：Docker Compose，需先克隆源码构建。
- `SkillSpector`：子进程（开发/验证）或 Docker（生产隔离）。

### 3.4 数据层

- `TargetProfile`：pyrit-web-recon 输出，连接 recon 与 attack。
- `Neo4j`：RedAmon 图数据库，存储 Domain/BaseURL/Endpoint/Model/Vulnerability 关系。
- PostgreSQL：RedAmon 关系数据库，管理项目、用户、审计日志。

### 3.5 结果层

- **Ingestion**：各工具适配器把结果转成 `UnifiedFinding`。
- **Deduplication**：按 `(endpoint_url, owasp_llm_id, source_tool, ai_payload_class)` 去重。
- **Correlation**：跨工具印证同一风险（如 pyrit-web-recon 发现 MCP endpoint + AIG mcp_scan 确认风险）。
- **Risk Scoring**：融合严重度、置信度、ASR、暴露面计算统一风险分。
- **Write Graph**：写入 Neo4j，形成可查询的攻击面图谱。

### 3.6 报告层

- Dashboard：基于图数据展示攻击面、风险热力图、攻击路径。
- Report Generator：按 OWASP LLM / MITRE ATLAS 分类生成报告。
- Export：PDF、Markdown、SARIF。
- Alert：高风险发现触发通知。

### 3.7 测试层（新增）

> 测试是架构的一等公民，与功能代码同步演进。

#### 3.7.1 测试触发规则

| 改动范围 | 测试类型 | 测试文件位置 |
|---------|---------|-------------|
| 单个模块内代码改动 | 单元测试 | `tests/unit/{module}/test_*.py` |
| 跨模块代码改动 | 集成测试 | `tests/integration/test_*.py` |
| 多个模块同时改动 | 系统测试 | `tests/system/test_*.py` |

#### 3.7.2 测试职责

- **单元测试**：验证独立模块（如 `UnifiedFinding`、`AIGClient`、`ProfileToGraphAdapter`）的正确性。
- **集成测试**：验证跨模块交互（如 `TargetProfile → AIG Task Builder → Result Normalizer`）。
- **系统测试**：验证端到端流水线（`pyrit-web-recon → AIG → RedAmon → Report`）。

#### 3.7.3 测试文件要求

- 统一命名：`test_*.py`。
- 覆盖正例、反例、边界条件、错误处理。
- 优先使用 `tests/integration/mock_llm_server.py` 替代真实外部目标。
- 系统测试必须跑通完整链路，否则多模块改动视为未完成。

#### 3.7.4 自动化

- CI/CD 通过 GitHub Actions 触发三级测试。
- 代码覆盖率目标 ≥ 80%，新功能必须附带对应测试。

---

## 4. 核心数据流

```text
1. Orchestrator 接收目标 URL
         │
         ▼
2. 启动 pyrit-web-recon 11 阶段流水线
         │
         ▼
3. 输出 TargetProfile → Object Storage
         │
         ▼
4. 发布事件 recon.profile.created
         │
         ├──────────────┬──────────────┐
         ▼              ▼              ▼
5. RedAmon 写入      AIG 提交任务    SkillSpector 扫描
   知识图谱           ai_infra_scan    skill 文件
   (Profile → Neo4j)  agent_scan
                      mcp_scan
                      model_redteam_report
         │              │               │
         ▼              ▼               ▼
6. 结果归一化为 UnifiedFinding
         │
         ▼
7. Correlator 去重/关联/评分
         │
         ▼
8. 写入 Neo4j 统一知识图谱
         │
         ▼
9. Report Layer 生成报告
```

---

## 5. 关键集成点

| 集成点 | 输入 | 输出 | 实现文件 |
|--------|------|------|---------|
| pyrit-web-recon → TargetProfile | 目标 URL、凭据 | Profile、截图、HAR | `src/pipeline/stages/export.py` |
| TargetProfile → AIG 任务 | endpoint、model、rag/agent 特征 | `ai_infra_scan` / `agent_scan` / `mcp_scan` payload | `src/integration/aig/task_builder.py` |
| AIG 结果 → UnifiedFinding | AIG JSON report | `List[UnifiedFinding]` | `src/integration/aig/result_normalizer.py` |
| TargetProfile → RedAmon 图 | Profile 字段 | Neo4j MERGE Cypher | `src/integration/redamon/profile_to_graph_adapter.py` |
| SkillSpector → UnifiedFinding | SARIF/JSON report | `List[UnifiedFinding]` | `src/integration/skillspector/result_normalizer.py` |
| 多工具结果 → 知识图谱 | `List[UnifiedFinding]` | Neo4j 节点/关系 | `src/integration/correlator.py` |

---

## 6. 扩展性设计

新增工具只需实现三个适配器并注册到 Plugin Registry：

1. **Client**：与工具交互（HTTP / subprocess / Docker）。
2. **Task Builder**（可选）：把 `TargetProfile` 转成工具任务参数。
3. **Result Normalizer**：把工具输出转成 `UnifiedFinding`。

无需改动 Orchestrator 核心逻辑。

---

## 7. 部署建议

| 环境 | 推荐方式 |
|------|---------|
| 本地开发/验证 | pyrit-web-recon 本地 + SkillSpector 子进程 |
| 本地完整集成 | `docker-compose.integration.yml` 启动 Redis + MinIO + AIG + RedAmon |
| 生产 | Kubernetes / Docker Swarm，RedAmon 基础栈（不含 OpenVAS），AIG 官方镜像 |

---

## 8. 与 AI-300 考试对齐

本架构特别强化 AI-300 中 PyRIT 难以单独覆盖的模块：

- **M2 Reconnaissance**：pyrit-web-recon 自动侦察。
- **M5/M7 RAG/Agent/MCP**：AIG + SkillSpector 专门识别。
- **M9 AI Infrastructure**：AIG `ai_infra_scan` + RedAmon 端口扫描。
- **M10 Threat Modeling**：Neo4j 知识图谱与攻击路径分析。
- **M11 Capstone**：一体化流水线与统一报告。
