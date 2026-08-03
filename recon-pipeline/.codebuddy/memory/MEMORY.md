# recon-pipeline Memory

## Project Overview
- **Path**: `d:\文档\GitHub\osai\recon-pipeline`
- **Version**: 0.3.0
- **Purpose**: AI attack surface reconnaissance pipeline — discovers LLM/RAG/Agent/MCP/Embedding endpoints, fingerprints models, classifies attack surfaces, and generates PyRIT attack recommendations
- **Architecture**: Six-probe architecture (LLM/RAG/Agent/MCP/Embedding/DOM) + JSReconProbe + NetworkProbe

## Key Architecture Decisions

### Probe Layer (2026-08-03)
- 8 probes total: LLMProbe, RAGProbe, AgentProbe, MCPProbe, EmbeddingProbe, DOMProbe, JSReconProbe, NetworkProbe
- All probes extend ReconProbe base class with `name`, `requires_browser`, `requires_auth`, `probe(session)` interface
- NetworkInterceptor is the standalone class wrapped by NetworkProbe (ReconProbe)
- JSReconProbe analyzes JS file content for SDK imports, API keys, constructors, browser flags, frontend markers, provider URLs

### AI Signal Catalog (2026-08-03)
- Expanded from ~150 lines to ~900 lines covering all RedAmon signals
- 7 core signal dimensions: ports, headers, titles, body fingerprints, favicon hashes, paths, parameters
- Additional: RAG paths with parent_ai gating, active probe paths, vector DB confirmation reads, model family tokens, chat response shape classifiers, JS analysis signals (6 categories)
- All RedAmon signal patterns integrated from recon/helpers/ai_signal_catalog.py

### LLMProbe Enhancements (2026-08-03)
- Active chat-shape probing via AI_CHAT_PROBE_PATHS
- Model list discovery (GET /v1/models, /models, /api/tags)
- OpenAPI/Swagger/AI Plugin spec discovery
- Guardrail detection from headers and response bodies
- 50+ model family fingerprint patterns

### MCPProbe Enhancements (2026-08-03)
- Active MCP handshake (initialize JSON-RPC)
- Tool enumeration (tools/list, resources/list, prompts/list)
- Annotation contradiction detection (readOnlyHint vs mutation name)
- Tool shadowing detection (same name from multiple servers)
- YARA-style threat pattern scanning of tool descriptions
- SHA256 tool hashing for deduplication

### AttackRecommender Enhancements (2026-08-03)
- Consumes LLM fingerprints (model-specific jailbreak strategies)
- Consumes MCP tools (excessive_agency, tool_shadowing, annotation_bypass, mcp_injection)
- Consumes embedding info (vector_manipulation)
- Merges duplicate recommendations by (owasp_id, attack_strategy, target_type)

### Data Model Updates (2026-08-03)
- DiscoveredEndpoint: added `ai_framework_name`, `ai_framework_category`, `request_headers` in to_dict()
- MCPToolInfo: added `annotation_contradiction`, `tool_hash`, `injection_surfaces`, `annotations`, `threat_tags`
- LLMFingerprint: already had needed fields
- _sanitize_headers() helper for safe header export

### Tests (2026-08-03)
- 81 test cases in test_probes.py (up from ~25), 98 total across suite
- Covers: ReconProbe interface, LLM fingerprinting, MCP parsing, AI signal catalog, JS analysis, vector DB fingerprinting, attack recommendations, endpoint classification
- 1 pre-existing failure in webhook test (network timing issue)

## Source Integration Reference
- RedAmon recon/helpers/ai_signal_catalog.py → core/probes/ai_signal_catalog.py
- RedAmon recon/main_recon_modules/ai_surface_recon.py → core/probes/active_probe.py patterns
- RedAmon recon/main_recon_modules/js_recon.py → core/probes/js_recon_probe.py
- RedAmon ai_attack_surface_scan → core/probes/ orchestration patterns

## Testing
- Run: `python -m pytest tests/ -x --tb=short`
- 107 passed, 1 expected failure (webhook networking)

---

## 开发规范：防止遗漏的实施流程

### 问题根因
多文档、多需求的大型实施任务中，直接开始写代码会导致部分需求遗漏。
根本原因：没有在实施前将所有需求提取为可验证的检查清单。

### 强制流程（所有大型实施任务必须遵循）

#### Phase 0: 需求提取（实施前必须完成）
1. **读取所有设计文档**，逐项提取需求为结构化检查清单
2. **检查清单格式**：`[ ] 文件路径 — 需求描述 — 验收标准`
3. **清单必须覆盖三个层次**：
   - 架构层（DESIGN.md）：类/接口/数据流
   - 能力层（L5_RECON）：功能目标/覆盖矩阵
   - 实施层（OPTIMIZATION_PLAN）：具体文件/行数/改动类型
4. **输出检查清单到当前会话**，经用户确认后再开始写代码

#### Phase 1: 增量实施
1. 按检查清单逐项实施，每完成一项标记 `[x]`
2. 每完成一个模块立即运行 `python -m pytest tests/ -x --tb=short`
3. 不跳过"小块"需求（如字段添加、import 修复），它们往往是遗漏重灾区

#### Phase 2: 验收
1. 实施完成后，重新对照检查清单逐项自检
2. 运行完整测试套件
3. 输出最终合规报告（已实施/未实施/需后续）

### 检查清单模板

```
## 实施检查清单：[任务名称]

### 架构层（DESIGN.md）
- [ ] 类/接口是否全部实现
- [ ] 数据流是否正确连接
- [ ] 导出层是否完整

### 能力层（L5_RECON）
- [ ] 功能目标是否覆盖
- [ ] 认证策略是否齐全
- [ ] 主动探测是否到位

### 实施层（OPTIMIZATION_PLAN）
- [ ] P0 项（必须）
- [ ] P1 项（建议）
- [ ] P2 项（可选）
```

### 本次遗漏复盘
| 遗漏项 | 原因 | 如何避免 |
|--------|------|---------|
| session.run_probe() 前置检查重构 (P0-6) | "小块"重构被大功能淹没 | 检查清单中标注所有改动类型（新增/重写/修改/删除） |
| ReconReport.auth_flow_state 字段 | 字段需求分散在 L5_RECON 文档中 | 跨文档交叉引用，统一提取所有数据字段 |
| PlaywrightAuthProvider | BrowserSession 已存在但未包装为 ABC | 检查 AuthProvider 子类是否覆盖所有认证场景 |
| CookieAuthProvider | 需求在 DESIGN.md 目录结构中提及但未显式列出 | 目录结构需求也要纳入检查清单 |
| Guardrail 组织边界 | L5_RECON 第 7.3 节单独描述 | 按章节逐段扫描，不遗漏任何小节 |
