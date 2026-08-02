# recon-kit 架构设计文档

> **版本**: v0.1.0  
> **日期**: 2026-08-02  
> **规则**: R-009 (优化方案确认流程)  
> **范围**: pyrit-pipeline + garak-pipeline 共享公共侦察模块

---

## 一、问题诊断

### 当前数据流（断裂的）

```
pyrit-pipeline 独立流程:
  web_redteam/recon/stage_recon.py
    → NetworkInterceptor (Playwright 网络拦截)
    → DOMAnalyzer (DOM 注入面)
    → VectorDBFingerprinter (向量库指纹)
    → AttackRecommender (攻击推荐)
    → ReconResult (pyrit 专用格式)
      → Bridge → pipeline/stages/stage_web_auth.py (PyRIT 消费)

garak-pipeline 独立流程:
  pipeline/stage1_recon.py
    → 连通性测试 (openai SDK)
    → enumerate_garak_probes (garak 原生 API)
    → 模态侦察
    → target_profile_*.json (garak 专用格式)
      → pipeline/stage2_configure.py (Garak 消费)
```

### 六大断裂点

| # | 问题 | pyrit-pipeline 现状 | garak-pipeline 现状 |
|---|------|--------------------|--------------------|
| 1 | **认证不共享** | `web_redteam/auth/BrowserSession` (Playwright cookies) | `pipeline/auth/CookieFileProvider` (文件 cookies) — 接口不兼容 |
| 2 | **数据模型不统一** | `ReconResult` dataclass | `target_profile_*.json` + `probe_candidates_*.json` — 格式完全不同 |
| 3 | **侦察探针不共享** | Playwright 驱动 (DOM/网络拦截) | API 驱动 (garak SDK/openai SDK) — 探针无法交叉复用 |
| 4 | **无 LLM 指纹** | ❌ 缺失 | ❌ 缺失 |
| 5 | **无 MCP 侦察** | ❌ 缺失 | ❌ 缺失 |
| 6 | **无 Embedding 专项** | `VectorDBFingerprinter` (URL 指纹) | ❌ 缺失 |

---

## 二、优化后的架构

```
                    ┌─────────────────────────────────┐
                    │      recon-kit (公共模块)     │
                    │  ┌───────────────────────────┐  │
                    │  │   ReconSession (状态容器)   │  │
                    │  │   ├─ AuthState (认证态)     │  │
                    │  │   ├─ BrowserContext (浏览器) │  │
                    │  │   └─ TargetProfile (目标)   │  │
                    │  └───────────────────────────┘  │
                    │         │                        │
                    │    ┌────┴────┐                   │
                    │    ▼         ▼                   │
  认证层             │  Auth      ReconPipeline        │
  (Playwright/      │  Providers  ├─ LLMProbe         │
   Cookie/APIKey/   │             ├─ RAGProbe          │
   OAuth)           │             ├─ AgentProbe        │
                    │             ├─ MCPProbe           │
                    │             ├─ EmbeddingProbe     │
                    │             └─ DOMProbe           │
                    │         │                        │
                    │    ┌────┴────┐                   │
                    │    ▼         ▼                   │
  导出层             │ PyRIT     Garak     JSON         │
                    │ Exporter  Exporter  Exporter     │
                    └─────────────────────────────────┘
                         │              │          │
                    ┌────┘              └────┐     └──→ 通用 JSON
                    ▼                        ▼
              pyrit-pipeline           garak-pipeline
              (PyRIT 原生消费)          (Garak 原生消费)
```

---

## 三、L5 差距分析

| 维度 | 优化前 (现状) | 优化后 (目标) | 学术依据 |
|------|-------------|-------------|---------|
| **认证共享** | 两套独立认证, 认证态不可跨项目传递 | 统一 `AuthState` + `AuthProvider` ABC, 一次认证→两下游消费 | MITRE ATT&CK T1078 (Valid Accounts) |
| **探针复用** | Playwright 探针仅 pyrit 可用, garak API 探针仅 garak 可用 | 统一 `ReconProbe` ABC, 6 类探针可组合启用 | MITRE ATT&CK TA0043 (Reconnaissance) |
| **LLM 指纹** | ❌ 两项目均无 | `LLMProbe` 探测模型族 + system prompt 提取 | arXiv:2406.13352 (AgentDojo) |
| **MCP 侦察** | ❌ 两项目均无 | `MCPProbe` 枚举 MCP server 工具 + 权限 | MCP 协议规范 (2024-11): tools/list JSON-RPC |
| **Embedding 侦察** | `VectorDBFingerprinter` 仅 URL 指纹 | `EmbeddingProbe` 扩展为: URL + 响应体 + 认证态探测 | OWASP LLM08: Vector and Embedding Weaknesses |
| **数据模型** | `ReconResult` (pyrit) vs JSON 文件 (garak), 不兼容 | 统一 `ReconReport` + 双向 Exporter | MITRE ATT&CK: 标准化侦察结果格式 |
| **架构层次** | 探针+认证+导出 耦合在各自 pipeline 中 | 三层分离: Auth / Probe / Export — 可独立扩展 | SOLID 原则 + R-010 (PyRIT 原生优先) |

---

## 四、目录结构

```
osai/
├── recon-kit/                    ← 公共项目
│   ├── pyproject.toml                ← pip install -e .
│   ├── core/
│   │   ├── __init__.py               ← 包入口
│   │   ├── session.py                ← ReconSession (统一状态容器)
│   │   ├── pipeline.py               ← ReconPipeline (探针编排)
│   │   ├── auth/                     ← 认证层
│   │   │   ├── __init__.py
│   │   │   ├── provider.py           ← AuthProvider ABC + NoAuth + APIKey
│   │   │   ├── playwright_auth.py    ← Playwright 认证 (迁移自 pyrit web_redteam/auth)
│   │   │   └── cookie_auth.py        ← Cookie 文件认证 (迁移自 garak pipeline/auth)
│   │   ├── probes/                   ← 探针层 (核心新增)
│   │   │   ├── __init__.py
│   │   │   ├── base.py               ← ReconProbe ABC
│   │   │   ├── llm_probe.py          ← LLM 端点发现 + 指纹识别 (新增)
│   │   │   ├── rag_probe.py          ← RAG API + 知识库投毒入口 (增强)
│   │   │   ├── agent_probe.py        ← Agent 工具枚举 + 权限矩阵 (迁移+增强)
│   │   │   ├── mcp_probe.py          ← MCP server 工具枚举 (新增)
│   │   │   ├── embedding_probe.py   ← 向量库指纹 + 未授权访问 (增强)
│   │   │   └── dom_probe.py          ← DOM 注入面扫描 (迁移)
│   │   ├── models/                   ← 统一数据模型
│   │   │   ├── __init__.py
│   │   │   ├── recon_report.py       ← ReconReport (替代 ReconResult)
│   │   │   └── auth_state.py         ← AuthState (cookies + tokens + headers)
│   │   └── exporters/                ← 导出层
│   │       ├── __init__.py
│   │       ├── base.py               ← ReconExporter ABC + JSONExporter
│   │       ├── pyrit_exporter.py      ← → PyRIT PipelineContext.metadata
│   │       └── garak_exporter.py     ← → garak target_profile + probe_candidates
│   ├── tests/
│   └── docs/
│       └── DESIGN.md                 ← 本文档
│
├── pyrit-pipeline/                   ← 消费方 A
│   ├── pipeline/integrations/
│   │   └── recon_bridge.py           ← 更新: 调用 core.exporters
│   └── web_redteam/recon/            ← 保留: DOM/Playwright 探针委托给 recon-kit
│
└── garak-pipeline/                   ← 消费方 B
    └── pipeline/stage1_recon.py      ← 更新: 调用 core.exporters
```

---

## 五、核心接口

### 5.1 ReconSession — 统一状态容器

```python
session = ReconSession(target_url="http://example.com")
await session.authenticate(APIKeyAuthProvider(key="sk-xxx"))
await session.run_probe(LLMProbe())
await session.run_probe(MCPProbe())
session.export(PyRITExporter(), pipeline_ctx)
```

### 5.2 AuthState — 认证态

```python
auth_state = AuthState(
    auth_type="cookie",
    cookies=[{"name": "session", "value": "xxx", "domain": "example.com"}],
    headers={"X-API-Key": "sk-xxx"},
    tokens={"bearer": "eyJ..."},
    storage_state={...},  # Playwright storage_state
    browser_context=ctx,  # Playwright BrowserContext
)
# 在所有探针间共享
auth_state.to_headers()  # → {"Cookie": "...", "Authorization": "Bearer ...", "X-API-Key": "..."}
```

### 5.3 六类探针

| 探针 | 输入 | 产出 | 浏览器需求 |
|------|------|------|-----------|
| `LLMProbe` | `auth_state` (HTTP headers) | 模型 API 端点 + 模型族指纹 + system prompt 提取 | ❌ 纯 HTTP |
| `RAGProbe` | `auth_state` + `browser_page` | RAG API 端点 + 检索接口 + 知识库投毒入口 | ✅ 如需 DOM |
| `AgentProbe` | `auth_state` + `browser_page` | Agent 工具端点 + 工具权限矩阵 + A2A agent card | ✅ 如需 DOM |
| `MCPProbe` | `auth_state` | MCP server 工具列表 + tool shadowing 检测 + 权限边界 | ❌ JSON-RPC |
| `EmbeddingProbe` | `auth_state` | 向量库类型 + 未授权访问 + embedding 端点 | ❌ 纯 HTTP |
| `DOMProbe` | `browser_page` | DOM 注入面 (文件上传/多模态/聊天输入/工具面板) | ✅ 必须 |

---

## 六、认证数据流

```
用户指定目标 → AuthProvider 认证
      │
      ▼
ReconSession.auth_state = AuthState(cookies, headers, tokens, browser_context)
      │
      ├──→ LLMProbe:        使用 auth_state.to_headers() 发送 HTTP 请求
      ├──→ RAGProbe:        使用 auth_state.to_headers() + browser_page (如需)
      ├──→ AgentProbe:     使用 browser_page (已认证的 Playwright Page)
      ├──→ MCPProbe:       使用 auth_state.to_headers() 发送 JSON-RPC
      ├──→ EmbeddingProbe: 使用 auth_state.to_headers() 发送 HTTP 请求
      └──→ DOMProbe:        使用 browser_page (已认证的 Playwright Page)
      │
      ▼
ReconReport (统一结果)
      │
      ├──→ PyRITExporter → pipeline_ctx.metadata["recon_result"]
      │                     → Stage 2 (Scenario) 消费
      │                     → Stage 1.5 (WebAuth) 复用 auth_state
      │
      └──→ GarakExporter  → target_profile.json + probe_candidates.json
                           → Stage 2 (Configure) 消费
                           → Stage 3 (Execute) 复用 auth headers
```

**关键点**：认证只做一次, `AuthState` 贯穿所有探针和两个下游消费者。Playwright 浏览器会话在探针间共享（同一个 `browser_page`），不重复启动。

---

## 七、迁移策略

| 步骤 | 操作 | 影响 |
|------|------|------|
| 1 | 创建 `recon-kit` 项目骨架 | 零影响（新项目） |
| 2 | 从 pyrit-pipeline 迁移 `web_redteam/recon/` + `web_redteam/auth/` | pyrit-pipeline 改为 `from core import ...` |
| 3 | 从 garak-pipeline 迁移 `pipeline/auth/` + `pipeline/recon_garak.py` | garak-pipeline 改为 `from core import ...` |
| 4 | 新增 `LLMProbe` + `MCPProbe` (之前不存在的探针) | 纯新增 |
| 5 | 更新 `pipeline/integrations/recon_bridge.py` 调用 `PyRITExporter` | pyrit-pipeline Bridge 简化 |
| 6 | 更新 `garak-pipeline/stage1_recon.py` 调用 `GarakExporter` | garak-pipeline Stage 1 简化 |
| 7 | pyrit-pipeline + garak-pipeline 的 `requirements.txt` 添加 `recon-kit` | 安装依赖 |

---

## 八、外部工具集成

| 工具 | 集成到 recon-kit 的位置 |
|------|---------------------------|
| llm-con 指纹逻辑 | `probes/llm_probe.py` — 提取其 RECON + FINGERPRINT 逻辑 |
| MasterMCP 攻击模式 | 不在 recon 中, 留在 `pyrit-pipeline/pipeline/scenarios/mcp_exploitation.py` |
| mcp-shark MCP 通信捕获 | `probes/mcp_probe.py` — 参考其 JSON-RPC 拦截逻辑 |
| PoisonedRAG 攻击 | 不在 recon 中, 留在 `pyrit-pipeline/pipeline/scenarios/rag_poisoning.py` |
| AgentDojo 注入载荷 | 不在 recon 中, 转为 `.prompt` 数据集 |
| InjecAgent 载荷 | 同上 |

**原则**：recon 模块只做发现和指纹, 不做攻击。攻击逻辑留在各自 pipeline 的 scenarios 中。

---

## 九、项目独立性

```
osai/
├── recon-kit/        ← 新增 (共享公共模块, pip install -e .)
├── pyrit-pipeline/      ← 消费方 A (pip install -e ../recon-kit)
└── garak-pipeline/       ← 消费方 B (pip install -e ../recon-kit)
```

两个 pipeline 各自独立安装 recon-kit, 不产生硬依赖。
