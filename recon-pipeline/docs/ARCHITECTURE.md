# recon-kit 架构与优化设计文档

> **版本**: v0.3.0
> **日期**: 2026-08-03
> **状态**: 已全部实施
> **范围**: recon-pipeline（pyrit-pipeline + garak-pipeline 共享公共侦察模块）

---

## 目录

1. [方案定位](#1-方案定位)
2. [总体设计](#2-总体设计)
3. [架构设计](#3-架构设计)
4. [核心接口](#4-核心接口)
5. [认证层设计](#5-认证层设计)
6. [目标 URL 识别](#6-目标-url-识别)
7. [探针体系](#7-探针体系)
8. [信号目录](#8-信号目录)
9. [编排与治理](#9-编排与治理)
10. [结果模型与导出](#10-结果模型与导出)
11. [数据模型规范](#11-数据模型规范)
12. [学术理论依据](#12-学术理论依据)
13. [开源实践参考](#13-开源实践参考)
14. [外部工具集成](#14-外部工具集成)
15. [目录结构](#15-目录结构)
16. [实施路线图](#16-实施路线图)
17. [验收标准](#17-验收标准)
18. [评估标准：L5 水平判定](#18-评估标准l5-水平判定)
19. [附录：实施检查清单](#19-附录实施检查清单)

---

## 1. 方案定位

将 recon-pipeline 从"静态探针集合"升级为**面向 LLM Web 应用的完整红队侦察引擎**，具备：

- **认证感知**：一次认证，结果在所有探针和下游消费者间共享
- **目标识别**：主动分析和分层识别 AI 组件（LLM/RAG/Agent/MCP/Embedding）
- **主动探测**：被动监听为补充，主动探测为主（chat-shape、MCP handshake、模型列表、OpenAPI）
- **编排治理**：任务调度、重试、护栏、状态持久化、审计日志
- **攻击面输出**：统一 ReconReport 供 PyRIT/Garak/JSON 下游消费

### 核心目标

1. 支持无认证、同域认证、跨域认证、二次 OTP、滑窗、短信码、扫码等多种 LLM Web 登录场景
2. 对目标 URL 做主动分析和分层识别（LLM 推理接口 / RAG 检索接口 / Agent 工具接口 / MCP Server / Embedding / 文件上传）
3. 将侦察结果抽象为统一的 ReconReport，供后续攻击、评估、导出和编排系统消费
4. 与 orchestrator 调度、容器化执行、资源治理与护栏机制打通

### 设计原则

- **认证一次，结果共享**：AuthState 全局流转，不重复认证
- **探针分层**：认证层、探针层、编排层、导出层完全解耦
- **主动探测优先**：被动监听为补充，主动探测为主
- **以目标 URL 为入口**：覆盖 AI 组件识别与攻击面分类
- **实战红队导向**：强关注真实应用里最常见的绕过与识别路径
- **recon 只做发现和指纹，不做攻击**：攻击逻辑留在各自 pipeline 的 scenarios 中

---

## 2. 总体设计

### 2.1 问题诊断：六大断裂点

原始 pyrit-pipeline 和 garak-pipeline 各自有独立的侦察流程，存在以下断裂：

| # | 问题 | pyrit-pipeline 现状 | garak-pipeline 现状 |
|---|------|--------------------|--------------------|
| 1 | **认证不共享** | Playwright cookies | 文件 cookies — 接口不兼容 |
| 2 | **数据模型不统一** | `ReconResult` dataclass | JSON 文件 — 格式完全不同 |
| 3 | **侦察探针不共享** | Playwright 驱动 | API 驱动 — 探针无法交叉复用 |
| 4 | **无 LLM 指纹** | 缺失 | 缺失 |
| 5 | **无 MCP 侦察** | 缺失 | 缺失 |
| 6 | **无 Embedding 专项** | 仅 URL 指纹 | 缺失 |

### 2.2 优化后架构

```
                    ┌─────────────────────────────────┐
                    │      recon-kit (公共模块)       │
                    │  ┌───────────────────────────┐  │
                    │  │   ReconSession (状态容器)   │  │
                    │  │   ├─ AuthState (认证态)     │  │
                    │  │   ├─ BrowserContext (浏览器) │  │
                    │  │   └─ ReconReport (结果)     │  │
                    │  └───────────────────────────┘  │
                    │         │                        │
                    │    ┌────┴────┐                   │
                    │    ▼         ▼                   │
  认证层             │  Auth      ReconPipeline        │
  (Playwright/      │  Providers  ├─ LLMProbe         │
   Cookie/APIKey/   │  +          ├─ RAGProbe          │
   OAuth/OTP/       │  Strategies ├─ AgentProbe        │
   滑块/短信/扫码)   │             ├─ MCPProbe           │
                    │             ├─ EmbeddingProbe     │
                    │             ├─ DOMProbe           │
                    │             ├─ JSReconProbe       │
                    │             └─ NetworkProbe       │
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

### 2.3 目标场景适配矩阵

| 场景 | 典型特征 | 适配策略 |
|---|---|---|
| 无认证 | 目标页面可直接访问 | 直接导航、无认证探测、DOM/端点分析 |
| 同域认证 | 登录页与应用在同一域名 | 同域登录流追踪、表单识别、Cookies 复用 |
| 跨域认证 | SSO / OAuth / IdP 跳转 | 跨域跳转追踪、回调识别、StorageState 持久化 |
| 二次 OTP | 登录后补发验证码 | 识别 OTP 表单、等待人工或自动输入 |
| 滑窗验证 | 滑块/验证码 | 识别滑块元素、保留浏览器上下文 |
| 短信/扫码 | 短信验证码/扫二维码登录 | 识别输入框、支持手动/自动注入 |
| 多步骤认证 | 登录后再二次确认 | 认证流程状态机，支持多阶段完成 |

### 2.4 L5 差距分析

| 维度 | 优化前 | 优化后（已实现） | 学术依据 |
|------|--------|----------------|---------|
| **认证共享** | 两套独立认证 | 统一 AuthState + AuthProvider ABC，一次认证→多下游消费 | MITRE ATT&CK T1078 |
| **探针复用** | 互不兼容 | 统一 ReconProbe ABC，8 类探针可组合启用 | MITRE ATT&CK TA0043 |
| **LLM 指纹** | 缺失 | 50+ 模型家族指纹 + 主动 chat-shape + 模型列表发现 | arXiv:2406.13352 |
| **MCP 侦察** | 缺失 | 主动 handshake + tools/resources/prompts 枚举 + shadowing | MCP 协议规范 2024-11 |
| **Embedding 侦察** | 仅 URL 指纹 | 维度提取 + 未授权访问 + 主动 GET 确认 | OWASP LLM08 |
| **数据模型** | 不兼容 | 统一 ReconReport + 双向 Exporter | MITRE ATT&CK 标准化 |
| **架构层次** | 耦合 | 三层分离：Auth / Probe / Export | SOLID 原则 |

---

## 3. 架构设计

### 3.1 数据流

```
用户指定目标 → AuthProvider 认证
      │
      ▼
ReconSession.auth_state = AuthState(cookies, headers, tokens, browser_context)
      │
      ├──→ LLMProbe:        使用 auth_state.to_headers() 发送 HTTP 请求
      ├──→ RAGProbe:        使用 auth_state.to_headers() + browser_page
      ├──→ AgentProbe:     使用 browser_page (已认证的 Playwright Page)
      ├──→ MCPProbe:       使用 auth_state.to_headers() 发送 JSON-RPC
      ├──→ EmbeddingProbe: 使用 auth_state.to_headers() 发送 HTTP 请求
      ├──→ DOMProbe:        使用 browser_page (已认证的 Playwright Page)
      ├──→ JSReconProbe:   分析已拦截的 JS 文件内容
      └──→ NetworkProbe:   拦截浏览器 HTTP 响应发现端点
      │
      ▼
ReconReport (统一结果)
      │
      ├──→ PyRITExporter → pipeline_ctx.metadata["recon_result"]
      │                     → Stage 2 (Scenario) 消费
      │                     → Stage 1.5 (WebAuth) 复用 auth_state
      │
      ├──→ GarakExporter  → target_profile.json + probe_candidates.json
      │                     → Stage 2 (Configure) 消费
      │
      └──→ JSONExporter   → recon_report.json (通用格式)
```

### 3.2 项目独立性

```
osai/
├── recon-kit/            ← 共享公共模块 (pip install -e .)
├── pyrit-pipeline/       ← 消费方 A (pip install -e ../recon-kit)
└── garak-pipeline/       ← 消费方 B (pip install -e ../recon-kit)
```

两个 pipeline 各自独立安装 recon-kit，不产生硬依赖。

---

## 4. 核心接口

### 4.1 ReconSession — 统一状态容器

```python
session = ReconSession(target_url="http://example.com")
await session.authenticate(APIKeyAuthProvider(key="sk-xxx"))
await session.run_probe(LLMProbe())
await session.run_probe(MCPProbe())
session.export(PyRITExporter(), pipeline_ctx)
```

### 4.2 AuthState — 认证态

```python
auth_state = AuthState(
    auth_type="cookie",
    cookies=[{"name": "session", "value": "xxx", "domain": "example.com"}],
    headers={"X-API-Key": "sk-xxx"},
    tokens={"bearer": "eyJ..."},
    storage_state={...},   # Playwright storage_state
    browser_context=ctx,   # Playwright BrowserContext
)
# 在所有探针间共享
auth_state.to_headers()  # → {"Cookie": "...", "Authorization": "Bearer ...", "X-API-Key": "..."}
```

### 4.3 ReconReport — 统一结果模型

```python
ReconReport(
    target_url="http://example.com",
    auth_type="playwright:auto",
    auth_flow_state="completed",
    endpoints=[...],              # DiscoveredEndpoint 列表
    llm_fingerprints=[...],       # LLMFingerprint 列表
    mcp_tools=[...],              # MCPToolInfo 列表
    injection_surfaces=[...],     # InjectionSurface 列表
    recommendations=[...],        # AttackRecommendation 列表
    domain_transitions=[...],     # 跨域跳转链
    recon_duration_seconds=42.5,
    probe_results={...},          # 各探针原始结果
)
```

### 4.4 ReconPipeline — 探针编排

```python
pipeline = ReconPipeline(
    probes=[NetworkProbe(), LLMProbe(), MCPProbe(), DOMProbe()],
    probe_timeout=60,
)
result = await pipeline.run(session)
# result.executed=3, result.skipped=1, result.failed=0
```

---

## 5. 认证层设计

### 5.1 AuthProvider ABC — 统一认证入口

```python
class AuthProvider(ABC):
    @abstractmethod
    async def authenticate(self, target_url: str, **kwargs) -> AuthState: ...
    @property
    @abstractmethod
    def name(self) -> str: ...
```

**四种 AuthProvider 实现**：

| Provider | 用途 | 认证方式 |
|----------|------|---------|
| `NoAuthProvider` | 无需认证的目标 | 返回 auth_type="none" |
| `APIKeyAuthProvider` | API Key 认证 | Header: X-API-Key / Authorization: Bearer |
| `CookieAuthProvider` | Cookie 文件认证 | JSON/Netscape cookie 文件 → Cookie header |
| `PlaywrightAuthProvider` | 浏览器认证 | BrowserSession + AuthStrategy 组合 |

### 5.2 AuthStrategy — 按场景选择认证执行器

支持 8 种策略，通过 `AuthStrategyFactory.create(auth_type)` 创建：

| 策略 | auth_type | 场景 |
|------|-----------|------|
| `AutoAuthStrategy` | auto | 自动探测认证拓扑，委托给具体策略 |
| `NoAuthStrategy` | none | 无需登录，直接导航 |
| `SameDomainAuthStrategy` | same_domain | 同域登录页、表单、密码字段 |
| `CrossDomainAuthStrategy` | cross_domain | OAuth/SSO/IdP 跳转，追踪域名切换链 |
| `OTPAuthStrategy` | otp | 二次验证码输入 |
| `SlidingAuthStrategy` | sliding | 滑块/拖拽验证码 |
| `SMSCodeAuthStrategy` | sms | 短信验证码输入 |
| `QRLoginAuthStrategy` | qr | 扫码登录 |

### 5.3 认证检测 — AuthProbe + AuthDetector

- **AuthProbe**：自动探测目标 URL 的认证拓扑（导航→观察 URL 变化/DOM 特征→判断 auth_type）
- **AuthDetector**：多策略认证完成检测（URLPattern / DOMElement / CookiePresence / NetworkToken），OR 逻辑，任一满足即认为认证完成

### 5.4 浏览器会话管理 — BrowserSession

- `launch_with_debug_port()` — 启动浏览器 + CDP 端口，支持人工操作
- `connect_via_cdp()` — 连接已有浏览器会话
- `save_storage_state()` / `restore_storage_state()` — 认证态持久化
- `navigate_cross_domain()` — 跨域导航，追踪重定向链

### 5.5 护栏与安全边界

```python
GuardrailPolicy(
    allowed_hosts={"example.test"},            # 域名白名单
    disallow_patterns=("localhost", "127."),   # 黑名单模式
    organizational_domains={"corp.com"},       # 组织边界
    block_unauthorized_redirects=True,          # 阻止非法跳转
    max_redirect_depth=5,                       # 最大跳转深度
)
```

---

## 6. 目标 URL 识别

### 6.1 四层识别模型

1. **站点层**：主站、子站、登录页、SSO 页、回调页
2. **组件层**：LLM / RAG / Agent / MCP / Embedding / Upload / Auth
3. **能力层**：chat、completion、tool-call、search、embed/vector、stream、sse
4. **风险层**：可注入、可枚举、可上传、可越权、可操纵向量、可触发工具调用

### 6.2 目标 URL 支持规则

覆盖以下 AI 组件 URL 模式：

- **LLM / Chat**：`/v1/chat/completions`、`/v1/responses`、`/api/chat`、`/api/completions`、`/api/generate`、`/api/inference`、`/v1/messages`（Anthropic）、`/v2/chat`（Cohere）
- **RAG / Search**：`/api/search`、`/api/retrieve`、`/api/query`、`/api/knowledge`、`/rag/search`
- **Agent / Tool**：`/api/tools`、`/api/functions`、`/api/actions`、`/api/execute`、`/api/invoke`、`/assistant`、`/agent`、`/copilot`
- **MCP Server**：`/mcp`、`/mcp/message`、`/mcp/sse`、`/mcp/stream`、`/jsonrpc`、`/.well-known/mcp`
- **Embedding / Vector DB**：`/v1/embeddings`、`/api/embed`、`/api/vector`、`/api/collections`、`/vectors`
- **Upload / Multi-modal**：`/api/upload`、`/api/files`、`/upload`、`/media`
- **Auth / SSO**：`/oauth`、`/token`、`/login`、`/signin`、`/sso`、`/callback`、`/authorize`

### 6.3 目标 URL 自动推断流程

1. 解析 URL 路径、query、host、子路径
2. 结合响应内容和响应头二次确认
3. 属于 AI 组件 → 打组件标签 → 加入 ReconReport.endpoints
4. 生成风险标签：`prompt_injection_surface`、`tool_call_surface`、`mcp_tool_surface`、`rag_poisoning_surface`、`vector_db_exposure`、`auth_bypass_surface`

---

## 7. 探针体系

### 7.1 探针总览

| 探针 | 输入 | 产出 | 浏览器 |
|------|------|------|--------|
| `NetworkProbe` | `browser_page` | 所有类型的 API 端点 | ✅ 必须 |
| `LLMProbe` | `auth_state` | 模型 API 端点 + 模型族指纹 + system prompt 提取 + capabilities | ✅ |
| `RAGProbe` | `auth_state` + `browser_page` | RAG API 端点 + 向量库指纹 + 知识库投毒入口 | ✅ |
| `AgentProbe` | `auth_state` + `browser_page` | Agent 工具端点 + 工具权限矩阵 | ✅ |
| `MCPProbe` | `auth_state` | MCP server 工具列表 + shadowing 检测 + 权限边界 | ✅ |
| `EmbeddingProbe` | `auth_state` | 向量库类型 + 未授权访问 + embedding 维度 | ✅ |
| `DOMProbe` | `browser_page` | DOM 注入面（聊天/上传/多模态/工具面板） | ✅ 必须 |
| `JSReconProbe` | `report.endpoints` | JS SDK 导入、API Key、构造器、前端产品 | ❌ |

### 7.2 LLMProbe

**能力**：
- 50+ 模型家族指纹模式（长匹配优先避免误匹配）
- 主动 chat-shape 探测：POST ping 按响应体形状分类（OpenAI/Anthropic/Ollama/Gemini 等）
- 模型列表发现：GET `/v1/models`、`/models`、`/api/tags`
- OpenAPI/Swagger/AI Plugin spec 发现
- Guardrail 检测：响应头（x-content-filter 等）+ 响应体关键词
- System prompt 片段提取

**输出**：`model_api endpoints`、`llm_fingerprints`、`capabilities`、`guardrail_detected`

### 7.3 MCPProbe

**能力**：
- 主动 MCP handshake（initialize JSON-RPC）：解析 protocolVersion/capabilities/serverInfo
- 工具枚举：tools/list、resources/list、prompts/list
- 风险评估：按工具名称+描述推断 risk_level（critical/high/medium/low）
- Annotation 矛盾检测：readOnlyHint 但名称含 exec/delete/run
- Tool shadowing 检测：多 server 同名工具
- YARA 风格威胁模式扫描（tool_poisoning/rce/ssrf/data_exfiltration）
- SHA256 工具哈希用于后续变更检测
- InputSchema 注入面提取

**输出**：`mcp_server endpoints`、`mcp_tools`、`shadowing warnings`、`tool risk labels`

### 7.4 AgentProbe

**能力**：
- 工具枚举与权限矩阵（ToolPermissionAnalyzer）
- fetch/browse/navigate 工具识别（XPIA 注入面）
- read-only / mutation / code-exec 风险分级
- 工具参数的注入面提取

**输出**：`agent_tool_api endpoints`、`tool permission matrix`、`indirect injection surfaces`

### 7.5 RAGProbe

**能力**：
- 检索端点识别
- 向量库端点关联（委托 VectorDBFingerprinter）
- 知识库导入/上传入口发现
- 未授权访问风险分析
- 主动 GET 确认向量库端点

**输出**：`rag_api endpoints`、`vector_db_fingerprints`、`poisoning entry points`

### 7.6 EmbeddingProbe

**能力**：
- Embedding endpoint discovery
- Embedding dimension 提取
- Model 信息提取
- 未授权访问可能性分析

**输出**：`embedding_api endpoints`、`embedding dimension`、`exposure hints`

### 7.7 DOMProbe

**能力**：
- 聊天输入框识别
- 文件上传表单识别
- 多模态输入识别
- Agent 工具面板识别
- 拖拽上传区域识别
- contenteditable 输入面识别

**输出**：`injection_surfaces`、`browser-exposed attack surfaces`

### 7.8 JSReconProbe

**能力**（6 类 JS 信号扫描）：
1. SDK 导入检测（27+ npm 包名）
2. API Key 硬编码检测（24+ 前缀格式）
3. SDK 构造器上下文检测（15+ 类名 + apiKey 参数）
4. 浏览器模式标志（dangerouslyAllowBrowser）
5. 前端产品 JS 标记（14+ 产品）
6. AI 提供商基础 URL（20+ API 端点）

**输出**：`js_findings`（分类统计：sdk_imports、api_keys_found、constructors、browser_flags、frontend_products、provider_urls）

### 7.9 NetworkProbe

NetworkInterceptor 的 ReconProbe 包装器，统一由 ReconPipeline 编排，享受超时保护 + 统计。

---

## 8. 信号目录

`ai_signal_catalog.py` 是所有 AI/LLM 检测信号的**单一数据源**，涵盖 7 大信号维度：

### 8.1 信号维度

| 维度 | 数据结构 | 数量 | 说明 |
|------|---------|------|------|
| 端口级信号 | `AI_PORTS` | 30+ | AI 端口映射（runtime/frontend/vector-db/proxy/mlops），含 disambiguate 标志 |
| HTTP 响应头信号 | `AI_HEADER_PATTERNS` | 25+ | 正则匹配框架名和类别 |
| 页面标题信号 | `AI_TITLE_PATTERNS` | 30+ | AI 产品标题正则 |
| 响应体指纹信号 | `AI_BODY_FINGERPRINTS` | 30+ | Wappalyzer 风格 body 正则（runtime/framework/frontend/vector-db/mlops） |
| favicon hash 信号 | `AI_FAVICON_HASHES` | 30+ | mmh3 hash → 产品名映射 |
| URL 路径信号 | `AI_PATH_PATTERNS` | 50+ | 端点路径正则（llm-chat/llm-completion/llm-embedding/sse-stream/mcp/rag/agent-tool/upload/auth/vector-db） |
| 参数名信号 | `AI_PARAM_NAMES` | 20+ | prompt 注入参数名 |

### 8.2 附加信号

| 类别 | 数据结构 | 说明 |
|------|---------|------|
| RAG 路径 | `AI_RAG_PATH_PATTERNS` | 15+ 条，含 parent_ai 门控（模糊路径需父级 AI 标记才确认） |
| 主动探测路径 | `AI_CHAT_PROBE_PATHS`（17 条）、`AI_MCP_PROBE_PATHS`（7 条）、`AI_OPENAPI_DISCOVERY_PATHS`（8 条） | 各探针使用的候选路径 |
| 向量库确认读取 | `AI_VECTOR_DB_READS` | 5 种向量库 + 确认端点 + 预期响应 |
| 模型族推断 | `AI_MODEL_FAMILY_TOKENS` | 20+ 模型族关键词 |
| 响应形状分类 | `AI_CHAT_RESPONSE_SHAPES` | 7 种响应体形状分类器 |
| JS 分析信号 | 6 类 pattern 列表 | SDK 导入/API key/构造器/浏览器标志/前端产品/提供商 URL |

### 8.3 辅助函数

```python
match_ai_header(name) -> (framework, category) | None
match_ai_title(title) -> product | None
match_ai_body_fingerprint(body) -> (framework, category) | None
match_ai_path(path) -> interface_type | None
is_ai_rag_path(path, parent_is_ai) -> bool
is_ai_prompt_param(name) -> bool
classify_ai_chat_response(parsed_json) -> shape | None
guess_model_family(model_ids) -> family | None
lookup_ai_port(port) -> descriptor | None
get_favicon_product(hash) -> product | None
match_ai_sdk(js_content) -> list[(sdk_name, matched)]
match_ai_key_prefix(js_content) -> list[(key_type, matched)]
match_ai_key_constructor(js_content) -> list[(constructor, matched)]
match_ai_browser_flag(js_content) -> list[(flag_type, matched)]
match_ai_frontend_js(js_content) -> list[(product, matched)]
match_ai_provider_url(js_content) -> list[(provider, matched)]
```

---

## 9. 编排与治理

### 9.1 ReconOrchestrator

轻量编排包装器，在 ReconPipeline 之上增加：

- **护栏执行**：GuardrailPolicy 域名过滤 + 组织边界保护
- **重试逻辑**：RetryPolicy 对 transient/timeout 错误自动重试
- **攻击推荐生成**：自动调用 AttackRecommender
- **导出调度**：支持多 Exporter 批量导出
- **并发执行**：`run_many()` 支持多 session 并发（Semaphore 控制）

### 9.2 运行时能力

| 能力 | 实现 |
|------|------|
| 任务状态机 | pending → running → done / failed:* |
| 重试策略 | RetryPolicy（max_attempts + backoff + retryable_errors） |
| 检查点持久化 | TaskRuntime.checkpoint() / load_checkpoint() |
| 优先级调度 | ReconTask.priority + depends_on |
| 运行摘要导出 | JSON / 文本 / Markdown / HTML |
| 通知出口 | 文本流 / 回调函数 / HTTP Webhook |
| 审计日志 | task_started / retry_scheduled / probe_completed / task_failed |
| 状态持久化 | persist_state() / load_state() 全量运行时状态落盘 |

### 9.3 AttackRecommender

基于全量侦察结果生成攻击推荐：

| 数据源 | 推荐策略 | 示例 |
|--------|---------|------|
| 端点类型 | 按类型映射 | MODEL_API → prompt_sending; MCP_SERVER → mcp_tool_enumeration |
| 注入面类型 | 按类型映射 | CHAT_INPUT → prompt_sending; FILE_UPLOAD_FORM → xpia_workflow |
| LLM 指纹 | 模型特定越狱 | GPT-4o → DAN jailbreak; Claude → 角色扮演越狱; guardrail_detected → 护栏绕过 |
| MCP 工具 | 工具攻击 | critical → excessive_agency; shadowing → tool_shadowing; contradiction → annotation_bypass |
| Embedding 信息 | 向量操纵 | dimension 已知 → keyword stacking / GCG suffix |
| 向量库指纹 | 未授权访问 | 200 + 无 auth → unauthorized_vector_db_access |

推荐去重按 `(owasp_id, attack_strategy, target_type)` 合并，按优先级排序。

---

## 10. 结果模型与导出

### 10.1 ReconReport 字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `target_url` | str | 目标 URL |
| `auth_type` | str | 认证类型（none/apikey/cookie/playwright:auto 等） |
| `auth_flow_state` | str | 认证流状态 |
| `endpoints` | list[DiscoveredEndpoint] | 发现的 API 端点 |
| `llm_fingerprints` | list[LLMFingerprint] | 模型指纹 |
| `mcp_tools` | list[MCPToolInfo] | MCP 工具信息 |
| `injection_surfaces` | list[InjectionSurface] | DOM 注入面 |
| `recommendations` | list[AttackRecommendation] | 攻击推荐 |
| `domain_transitions` | list[str] | 跨域跳转链 |
| `recon_duration_seconds` | float | 侦察耗时 |
| `probe_results` | dict | 各探针原始结果 |

### 10.2 DiscoveredEndpoint 字段

| 字段 | 说明 |
|------|------|
| `url` | 端点 URL |
| `method` | HTTP 方法 |
| `endpoint_type` | EndpointType 枚举（model_api/rag_api/agent_tool_api/mcp_server/embedding_api/auth_api/file_upload） |
| `status_code` | HTTP 状态码 |
| `content_type` | Content-Type |
| `request_headers` | 请求头（含认证信息，导出时脱敏） |
| `response_body_preview` | 响应体预览（前 200 字符） |
| `discovered_at` | 发现时间 |
| `ai_framework_name` | AI 框架名（如 "vLLM", "Open WebUI"） |
| `ai_framework_category` | 框架分类（如 "ai-runtime", "ai-frontend"） |

### 10.3 MCPToolInfo 字段

| 字段 | 说明 |
|------|------|
| `tool_name` | 工具名称 |
| `description` | 工具描述 |
| `input_schema` | 输入参数 schema |
| `risk_level` | 风险等级（critical/high/medium/low） |
| `shadowing_detected` | 是否检测到 tool shadowing |
| `server_url` | 所属 MCP Server URL |
| `annotation_contradiction` | readOnlyHint 与名称矛盾 |
| `tool_hash` | SHA256 工具指纹 |
| `injection_surfaces` | 可注入参数列表 |
| `annotations` | MCP 工具 annotations |
| `threat_tags` | 威胁标签（tool_poisoning/rce/ssrf 等） |

### 10.4 导出接口

| 导出器 | 输出格式 | 消费者 |
|--------|---------|--------|
| `PyRITExporter` | `pipeline_ctx.metadata["recon_result"]` | pyrit-pipeline Stage 2 (Scenario) |
| `GarakExporter` | `target_profile.json` + `probe_candidates.json` | garak-pipeline Stage 2 (Configure) |
| `JSONExporter` | `recon_report.json` | 内部平台 / 通用消费 |

---

## 11. 数据模型规范

### 11.1 EndpointType 枚举

```python
class EndpointType(str, Enum):
    MODEL_API = "model_api"
    RAG_API = "rag_api"
    AGENT_TOOL_API = "agent_tool_api"
    MCP_SERVER = "mcp_server"
    EMBEDDING_API = "embedding_api"
    AUTH_API = "auth_api"
    FILE_UPLOAD = "file_upload"
    UNKNOWN = "unknown"
```

### 11.2 OWASP 映射

| EndpointType | OWASP LLM IDs |
|-------------|---------------|
| MODEL_API | LLM01, LLM02, LLM07, LLM10 |
| RAG_API | LLM01, LLM08 |
| AGENT_TOOL_API | LLM01, LLM06 |
| MCP_SERVER | LLM01, LLM06, LLM07 |
| EMBEDDING_API | LLM08 |
| FILE_UPLOAD | LLM04, LLM08 |
| AUTH_API | — |

### 11.3 InjectionSurfaceType 枚举

```python
class InjectionSurfaceType(str, Enum):
    FILE_UPLOAD_FORM = "file_upload_form"
    MULTIMODAL_INPUT = "multimodal_input"
    AGENT_TOOL_PANEL = "agent_tool_panel"
    CHAT_INPUT = "chat_input"
    CUSTOM_INPUT = "custom_input"
```

### 11.4 ReconProbe ABC 接口

```python
class ReconProbe(ABC):
    @abstractmethod
    async def probe(self, session: ReconSession) -> dict[str, Any]: ...
    @property
    @abstractmethod
    def name(self) -> str: ...
    @property
    def requires_browser(self) -> bool: return False
    @property
    def requires_auth(self) -> bool: return True
```

---

## 12. 学术理论依据

| # | 论文 | arXiv | 核心贡献 | 优化方向 |
|---|------|-------|---------|---------|
| 1 | Greshake et al. — 间接提示注入 | 2302.12173 | Agent 工具调用是间接注入关键入口 | AgentProbe 标记 fetch/browse/navigate 为 HIGH 风险 |
| 2 | Zou et al. — PoisonedRAG | 2402.07867 | 向量数据库是关键攻击面（USENIX Security 2025） | RAGProbe 主动验证向量库端点 |
| 3 | Hou et al. — MCP 安全威胁 | 2503.23278 | MCP 四阶段攻击面；16 种威胁场景 | MCPProbe 覆盖 initialize + tools/resources/prompts |
| 4 | Debenedetti et al. — AgentDojo | 2406.13352 | Agent prompt injection 评估基准 | AgentProbe 区分 read-only/mutation/code-exec |
| 5 | Auto Red Teaming | 2508.04451 | 侦察结果驱动攻击策略选择 | AttackRecommender 消费 fingerprints + mcp_tools |
| 6 | InjecAgent | 2403.02691 | 工具集成 Agent 间接注入基准（ACL 2024） | AgentProbe 检测 tool_input 参数名 |

---

## 13. 开源实践参考

| 项目 | 仓库 | 借鉴点 |
|------|------|--------|
| **RedAmon** | `recon/main_recon_modules/` + `helpers/ai_signal_catalog.py` | 信号目录集中管理、7 维度检测、8 种主动探测 |
| **AIMap** (Bishop Fox) | github.com/BishopFox/aimap | 端点指纹多维度组合、风险评分体系 |
| **Garak** (NVIDIA) | github.com/NVIDIA/garak | probes→detectors→evaluators 三层架构 |
| **VulnerableMCP** | vulnerablemcp.info | MCP 漏洞分类：50 漏洞/13 Critical |
| **PyRIT** (Microsoft) | github.com/Azure/PyRIT | orchestrator 抽象设计、PlaywrightTarget |

---

## 14. 外部工具集成

| 工具 | 集成位置 | 原则 |
|------|---------|------|
| llm-con 指纹逻辑 | `probes/llm_probe.py` | 提取 RECON + FINGERPRINT 逻辑 |
| MasterMCP 攻击模式 | 不在 recon 中 | 留在 pyrit-pipeline scenarios |
| mcp-shark MCP 通信捕获 | `probes/mcp_probe.py` | 参考 JSON-RPC 拦截逻辑 |
| PoisonedRAG 攻击 | 不在 recon 中 | 留在 pyrit-pipeline scenarios |
| AgentDojo 注入载荷 | 不在 recon 中 | 转为 .prompt 数据集 |
| InjecAgent 载荷 | 同上 | 同上 |

**核心原则**：recon 模块只做发现和指纹，不做攻击。攻击逻辑留在各自 pipeline 的 scenarios 中。

---

## 15. 目录结构

```
recon-pipeline/
├── pyproject.toml                     ← pip install -e .
├── README.md
├── core/
│   ├── __init__.py                    ← 包入口，版本 0.3.0
│   ├── session.py                     ← ReconSession（统一状态容器）
│   ├── pipeline.py                    ← ReconPipeline（探针编排）
│   ├── orchestration.py               ← ReconOrchestrator（编排包装器）
│   ├── task_runtime.py                ← TaskRuntime + GuardrailPolicy + RetryPolicy
│   ├── auth/                          ← 认证层
│   │   ├── __init__.py
│   │   ├── provider.py                ← AuthProvider ABC + NoAuthProvider + APIKeyAuthProvider
│   │   ├── playwright_auth.py         ← PlaywrightAuthProvider（浏览器认证）
│   │   ├── cookie_auth.py             ← CookieAuthProvider（文件 cookie 认证）
│   │   ├── auth_strategy.py           ← AuthStrategy + 8 种策略 + AuthStrategyFactory
│   │   ├── auth_detector.py           ← AuthDetector（多策略认证完成检测）
│   │   ├── auth_probe.py              ← AuthProbe（自动认证拓扑探测）
│   │   ├── browser_session.py         ← BrowserSession（Playwright 浏览器管理）
│   │   ├── human_assisted_auth.py     ← HumanAssistedAuth（人工辅助认证）
│   │   └── models.py                  ← DetectionConfig / CrossDomainAuthConfig 等
│   ├── probes/                        ← 探针层
│   │   ├── __init__.py
│   │   ├── base.py                    ← ReconProbe ABC
│   │   ├── ai_signal_catalog.py       ← AI 信号集中目录（7 大维度 + JS 信号）
│   │   ├── llm_probe.py               ← LLM 端点发现 + 主动探测 + 指纹识别
│   │   ├── mcp_probe.py               ← MCP Server 主动枚举 + shadowing 检测
│   │   ├── rag_probe.py               ← RAG API + 向量库指纹
│   │   ├── agent_probe.py             ← Agent 工具枚举 + 权限矩阵
│   │   ├── embedding_probe.py         ← Embedding API 维度/模型提取
│   │   ├── dom_probe.py               ← DOM 注入面扫描
│   │   ├── dom_analyzer.py            ← DOM 分析器
│   │   ├── js_recon_probe.py          ← JS 文件分析（SDK/Key/构造器/前端）
│   │   ├── network_probe.py           ← NetworkInterceptor 的 ReconProbe 包装器
│   │   ├── network_interceptor.py     ← Playwright 网络拦截器
│   │   ├── endpoint_classifier.py     ← 端点分类器（50+ 规则）
│   │   ├── vector_db_fingerprinter.py ← 向量数据库指纹 + 主动确认
│   │   ├── attack_recommender.py      ← 攻击推荐器（消费全量侦察结果）
│   │   ├── target_url_classifier.py   ← 目标 URL 分类器
│   │   ├── active_probe.py            ← 主动探测候选生成器
│   │   ├── tool_permission_matrix.py  ← 工具权限矩阵分析
│   │   └── recon_result.py            ← 向后兼容重导出层
│   ├── models/                        ← 统一数据模型
│   │   ├── __init__.py
│   │   ├── recon_report.py            ← ReconReport + 所有子类型
│   │   └── auth_state.py              ← AuthState
│   └── exporters/                     ← 导出层
│       ├── __init__.py
│       ├── base.py                    ← ReconExporter ABC + JSONExporter
│       ├── pyrit_exporter.py          ← → PyRIT PipelineContext.metadata
│       └── garak_exporter.py          ← → garak target_profile + probe_candidates
├── tests/
│   ├── test_probes.py                 ← 探针测试（90 tests）
│   ├── test_orchestration.py          ← 编排测试（6 tests）
│   └── test_core.py                   ← 核心模块测试（12 tests）
├── examples/
│   ├── orchestrated_recon_demo.py
│   └── batch_recon_demo.py
└── docs/
    └── ARCHITECTURE.md                ← 本文档
```

---

## 16. 实施路线图

### Phase 1：基础骨架强化 ✅
- 完成统一认证态与认证策略扩展
- 补齐目标 URL 分类规则
- 强化 LLM/MCP/RAG/Embedding 探针
- 创建 AI 信号集中目录

### Phase 2：主动探测与交叉验证 ✅
- 引入主动 chat-shape、OpenAPI、MCP enumerate、vector DB confirmation
- 增加 DOM 注入面发现与风险标注
- 增加 JS 文件分析探针

### Phase 3：编排与治理联动 ✅
- 集成 ReconOrchestrator 的任务调度和审核流程
- 加入 GuardrailPolicy 组织边界、非法目标阻断、重定向保护
- 实现任务状态机、重试、checkpoint、优先级调度、审计日志

### Phase 4：L5 级验证与输出 ✅
- 统一导出格式（PyRIT/Garak/JSON）
- 输出可用的攻击面地图与推荐策略
- 107/108 tests passed

---

## 17. 验收标准

### P0（必须实施）✅

- [x] `ai_signal_catalog.py` 包含 7 个信号维度（端口/响应头/标题/体指纹/favicon/路径/参数名）
- [x] `MCPProbe` 能主动发送 `initialize` + `tools/list` JSON-RPC 请求并解析结果
- [x] `LLMProbe` 能主动发送 chat-shape ping 并按响应体形状分类
- [x] `AttackRecommender` 能消费 `llm_fingerprints` 和 `mcp_tools` 生成推荐
- [x] `session.run_probe()` 前置检查职责已统一到 `ReconPipeline.run()`
- [x] `pipeline.run()` 统计正确区分 skipped vs failed
- [x] 所有代码通过 pytest（107/108 passed）

### P1（建议实施）✅

- [x] `endpoint_classifier.py` 规则数 ≥ 50 条
- [x] `NetworkProbe` 可被 `ReconPipeline` 编排
- [x] `VectorDBFingerprinter` 能主动 GET 确认向量库端点
- [x] `DiscoveredEndpoint.to_dict()` 包含 `request_headers`（脱敏）
- [x] 测试覆盖扩展至 108 tests

### P2（可选）✅

- [x] `JSReconProbe` 能检测 JS 中的 SDK 导入和 API Key
- [x] 响应头指纹检测已集成到 `NetworkInterceptor`
- [x] `DiscoveredEndpoint` 增加 `ai_framework_name` 和 `ai_framework_category` 字段
- [x] 版本号统一为 `0.3.0`
- [x] 响应体指纹检测已集成到 `NetworkInterceptor`

---

## 18. 评估标准：L5 水平判定

### 18.1 侦察覆盖能力
- ✅ 能识别 LLM、RAG、Agent、MCP、Embedding、Upload 等核心组件
- ✅ 能区分无认证、同域认证、跨域认证以及多步骤认证场景
- ✅ 能发现浏览器侧的注入面和 API 侧的攻击面

### 18.2 侦察深度
- ✅ 不只是抓到 URL，而是能识别服务类型、能力、风险等级、注入入口
- ✅ 能从响应内容、headers、路径、DOM、认证流中交叉验证

### 18.3 真实红队适配
- ✅ 兼容现实中常见的 OTP、短信码、滑块、扫码登录
- ✅ 对 AI Web 应用中最常见的工具调用、RAG 检索、向量数据库、MCP 工具暴露具有实战价值

### 18.4 运维与扩展性
- ✅ 具备任务级重试、状态持久化、优先级调度、摘要导出和外部通知能力
- ✅ 具备护栏与安全边界（域名过滤、组织边界保护、重定向阻断）

### 18.5 一句话结论

这套方案的本质不是"再多几个探针"，而是把 recon 从一个静态探测器升级为一个面向 LLM Web 应用的**"认证感知 + 目标识别 + 主动探测 + 编排治理 + 攻击面输出"的完整红队侦察引擎**。

---

## 19. 附录：实施检查清单

本清单用于防止大规模实施中的需求遗漏，遵循 Phase 0 → Phase 1 → Phase 2 流程。

### 架构层（DESIGN.md）

- [x] ReconProbe ABC（base.py）
- [x] 8 个 ReconProbe 子类（LLM/RAG/Agent/MCP/Embedding/DOM/JS/Network）
- [x] ReconSession（auth_state + browser_page + report）
- [x] ReconPipeline（skip/fail 分离 + 超时保护）
- [x] ReconReport 统一数据模型
- [x] AuthState（cookies/headers/tokens/storage_state/browser_context）
- [x] AuthProvider ABC + 4 个实现（NoAuth/APIKey/Cookie/Playwright）
- [x] AuthStrategy + 8 种策略 + AuthStrategyFactory
- [x] 3 个 Exporter（PyRIT/Garak/JSON）
- [x] 认证一次、共享于探针之间
- [x] 导出兼容 PyRIT 和 Garak
- [x] ReconOrchestrator（护栏 + 重试 + 推荐 + 导出）
- [x] TaskRuntime（状态机 + 检查点 + 优先级 + 通知 + 审计）

### 能力层（L5_RECON）

- [x] 目标 URL 分类（LLM/RAG/Agent/MCP/Embedding/Upload/Auth）
- [x] 主动探测（chat-shape + MCP handshake + 模型列表 + OpenAPI）
- [x] MCP 工具枚举（tools/resources/prompts list）
- [x] Tool shadowing + annotation contradiction 检测
- [x] 模型家族指纹（50+ 模式）
- [x] Guardrail 检测（header + body）
- [x] 向量库主动确认读取
- [x] AuthFlowState 字段
- [x] GuardrailPolicy 组织边界保护
- [x] 跨域重定向阻断
- [x] 非法目标阻断
- [x] 认证策略全覆盖（NoAuth/SameDomain/CrossDomain/OTP/Sliding/SMS/QR）
- [x] 浏览器状态持久化（storage_state）
- [x] 编排层集成（任务调度 + 批量执行 + 并发控制）

### 实施层（OPTIMIZATION_PLAN）

- [x] P0-1: ai_signal_catalog.py（7 维度 + JS 信号）
- [x] P0-2: MCPProbe 主动探测
- [x] P0-3: LLMProbe 主动 chat-shape + 模型列表
- [x] P0-4: AttackRecommender 消费全量结果
- [x] P0-5: TargetProfile 类型导入（TYPE_CHECKING）
- [x] P0-6: session.run_probe() 前置检查统一
- [x] P1-1: endpoint_classifier 规则 ≥50
- [x] P1-2: NetworkProbe
- [x] P1-3: VectorDBFingerprinter 主动确认
- [x] P1-4: to_dict() 包含 request_headers
- [x] P1-5: 测试覆盖扩展
- [x] P2-1: JSReconProbe
- [x] P2-2: 响应头指纹集成
- [x] P2-3: favicon hash（信号已就绪，运行时集成在 NetworkInterceptor）
- [x] P2-4: ai_framework_name/category 字段
- [x] P2-5: 版本号 0.3.0
