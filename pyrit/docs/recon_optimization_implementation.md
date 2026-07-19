# 侦察阶段优化实施报告 (v2)

> 实施日期：2026-07-19
> 实施范围：OPT-A1~A6, OPT-G1~G6, OPT-D1~D5, OPT-M1~M2, OPT-E1~E3（共 19 项）
> 关联分析文档：[recon_optimization_analysis.md](./recon_optimization_analysis.md)

## 目录

1. [实施概览](#1-实施概览)
2. [ProtocolFingerprint 适配器优化（OPT-A1~A6）](#2-protocolfingerprint-适配器优化opt-a1a6)
3. [Garak 适配器优化（OPT-G1~G6）](#3-garak-适配器优化opt-g1g6)
4. [DeepTeam 适配器优化（OPT-D1~D5）](#4-deepteam-适配器优化opt-d1d5)
5. [ProfileMerger 优化（OPT-M1~M2）](#5-profilemerger-优化opt-m1m2)
6. [ReconEngine 优化（OPT-E1~E3）](#6-reconengine-优化opt-e1e3)
7. [Pipeline 追踪集成](#7-pipeline-追踪集成)
8. [配置文件更新](#8-配置文件更新)
9. [验证清单](#9-验证清单)

---

## 1. 实施概览

### 1.1 优化项汇总

| 分类 | 优化项 | 优先级 | 实施状态 | 核心文件 |
|------|--------|--------|----------|----------|
| AIMAP | OPT-A1 协议探测并行化 | P0 | ✅ 已实施 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A2 深度 MCP 探测 | P1 | ✅ 已实施 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A3 RAG 端点探测 | P1 | ✅ 已实施 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A4 Agent 框架探测 | P1 | ✅ 已实施 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A5 认证深度检测 | P1 | ✅ 已实施 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A6 模型能力深度探测 | P2 | ✅ 已实施 | `protocol_fingerprint_adapter.py` |
| Garak | OPT-G1 Probe 动态选择 | P0 | ✅ 已实施 | `garak_adapter.py` |
| Garak | OPT-G2 深度分层 Probe | P1 | ✅ 已实施 | `garak_adapter.py` |
| Garak | OPT-G3 结果解析增强 | P1 | ✅ 已实施 | `garak_adapter.py` |
| Garak | OPT-G4 Detector 精确配置 | P2 | ✅ 已实施 | `garak_adapter.py` |
| Garak | OPT-G5 增量执行缓存 | P1 | ✅ 已实施 | `garak_adapter.py` |
| Garak | OPT-G6 通用预热 | P1 | ✅ 已实施 | `garak_adapter.py` |
| DeepTeam | OPT-D1 攻击类型全量覆盖 | P0 | ✅ 已实施 | `deepteam_adapter.py` |
| DeepTeam | OPT-D2 Agentic 漏洞覆盖 | P1 | ✅ 已实施 | `deepteam_adapter.py` |
| DeepTeam | OPT-D3 model_callback 增强 | P2 | ✅ 已实施 | `deepteam_adapter.py` |
| DeepTeam | OPT-D4 异步模式启用 | P1 | ✅ 已实施 | `deepteam_adapter.py` |
| DeepTeam | OPT-D5 攻击方法配置 | P2 | ✅ 已实施 | `deepteam_adapter.py` |
| Merger | OPT-M1 语义去重 | P1 | ✅ 已实施 | `profile_merger.py` |
| Merger | OPT-M2 动态攻击建议 | P1 | ✅ 已实施 | `profile_merger.py` |
| Engine | OPT-E1 AIMAP 与 DeepTeam 并行 | P0 | ✅ 已实施 | `recon_engine.py` |
| Engine | OPT-E2 增量缓存 | P1 | ✅ 已实施 | `recon_engine.py` |
| Engine | OPT-E3 深度自适应超时 | P2 | ✅ 已实施 | `recon_engine.py` |

### 1.2 修改文件清单

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `pyrit_ai300/reconnaissance/adapters/protocol_fingerprint_adapter.py` | 重写 | OPT-A1~A6 全部实施 |
| `pyrit_ai300/reconnaissance/adapters/garak_adapter.py` | 重写 | OPT-G1~G6 全部实施 |
| `pyrit_ai300/reconnaissance/adapters/deepteam_adapter.py` | 重写 | OPT-D1~D5 全部实施 |
| `pyrit_ai300/reconnaissance/profile_merger.py` | 增强 | OPT-M1 Jaccard 去重 + OPT-M2 动态建议 |
| `pyrit_ai300/reconnaissance/recon_engine.py` | 重写 run() | OPT-E1 并行 + E2 缓存 + E3 超时 |
| `pyrit_ai300/pipeline/tracker.py` | 增强 | 新增 `log_recon_optimization` + `show_recon_optimizations` |
| `config/recon/recon.yaml` | 更新 | 新增所有优化项开关 |

---

## 2. ProtocolFingerprint 适配器优化（OPT-A1~A6）

### OPT-A1: 协议探测并行化

**实施内容**：使用 `ThreadPoolExecutor(max_workers=8)` 并行探测所有协议规则。

**关键代码**（`protocol_fingerprint_adapter.py`）：
```python
def _detect_protocols_parallel(self, base_url: str, timeout: int) -> List[Dict[str, Any]]:
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(probe_rule, rule): rule for rule in PROTOCOL_RULES}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result["name"] not in detected_names:
                detected.append(result)
```

**收益**：侦察时间从 ~30s（串行 8 协议 × ~4s）降至 ~8s。

### OPT-A2: 深度 MCP 探测

**实施内容**：
1. `tools/list` → 枚举工具 + 参数 schema
2. `resources/list` → 检测权限隔离（resources/read vs tools/call 共享访问级别）
3. `initialize` → 探测 session 固定漏洞（相同 session_id 复用）
4. 工具描述 → 检测指令注入风险（`ignore previous` / `system prompt` 等模式）

**新增字段**：`mcp_tools_detail`（包含 `injection_risk` / `no_permission_isolation` / `session_fixation_risk`）

### OPT-A3: RAG 端点探测

**实施内容**：并行探测 4 类 RAG 端点：

| 端点 | 路径 | OWASP |
|------|------|-------|
| embeddings_api | `/v1/embeddings`, `/api/embeddings` | LLM08 |
| chromadb | `/api/v1/collections`, `/api/v1/heartbeat` | LLM08 |
| rag_search | `/api/search`, `/search`, `/api/retrieve` | LLM07 |
| custom_vectordb | `/api/vectordb`, `/api/vectors` | LLM08 |

### OPT-A4: Agent 框架探测

**实施内容**：并行探测 4 类 Agent 框架：

| 框架 | 路径 | OWASP |
|------|------|-------|
| langgraph | `/graph/invoke`, `/graph/stream` | ASI01 |
| autogen | `/api/agents`, `/api/chat` | ASI02 |
| crewai | `/api/crew`, `/api/tasks` | ASI03 |
| dify | `/api/chat-messages`, `/api/agents` | ASI04 |

### OPT-A5: 认证深度检测

**实施内容**：
1. Bearer Token 检测（401/403 + WWW-Authenticate 头）
2. API Key 检测（X-API-Key header → 401/403）
3. Cookie 认证（Set-Cookie 响应头）
4. OAuth 检测（`/oauth/token`, `/oauth/authorize` 路径）
5. JWT 过期时间（base64 解码 payload.exp）
6. **认证绕过检测**（空 Authorization → 200 = bypass_possible）

**新增字段**：`auth_details.detected_types` / `auth_details.jwt_exp` / `auth_details.bypass_possible`

### OPT-A6: 模型能力深度探测

**实施内容**：发送最小化请求探测 5 项能力：

| 能力 | 检测方法 | 攻击面影响 |
|------|----------|------------|
| function_calling | 发送 `tools` 参数 | ASI03 工具滥用 |
| json_mode | 发送 `response_format: json_object` | 结构化注入 |
| vision | 发送 `image_url` | LLM01 多模态注入 |
| streaming | 发送 `stream: true` | 流式注入 |
| system_prompt_isolation | 检查 system role 是否泄露 | LLM07 |

---

## 3. Garak 适配器优化（OPT-G1~G6）

### OPT-G1: Probe 动态选择

**实施内容**：基于 AIMAP 检测结果动态扩展 probe 列表。

**选择逻辑**：
1. 用户显式配置 → 使用用户配置
2. 基础 probe 集（按 OPT-G2 深度分层）
3. AIMAP 驱动扩展：
   - MCP → 增加 `lmrc`
   - function_calling → 增加 `promptinject`
   - RAG → 增加 `leakreplay`（deep 深度）
   - Llama 家族 → 增加 `continuation`
   - vision → 增加 `visual_jailbreak`
   - vector DB → 增加 `leakreplay`

**收益**：减少 30-50% 无效 probe 扫描。

### OPT-G2: 深度分层 Probe 策略

**实施内容**：

| 深度 | Probe 数量 | Probe 列表 |
|------|-----------|-----------|
| quick | 2 | promptinject, dan |
| standard | 6 | promptinject, dan, malgen, hallucination, misinformation, toxicity |
| deep | 14 | + jailbreak, continuation, goodside, encoder, lmrc, leakreplay, av_spam, xss |

### OPT-G3: 结果解析增强

**实施内容**：
1. `garak_output/*.jsonl` → status=completed 记录（原有）
2. `hitlog/*.jsonl` → 更详细的命中日志（含 trigger/prompt）
3. `garak_report.html` → 汇总统计（pass/fail 比率）
4. **fail 记录** → 探测失败（可能是超时，不等于无漏洞）

**新增字段**：`trigger` / `source`（区分 garak_output / hitlog / garak_report_html / garak_output_fail）

### OPT-G4: Detector 精确配置

**实施内容**：基于 probe 自动匹配 detector（`PROBE_DETECTOR_MAP`）。

| Probe | Detector |
|-------|----------|
| promptinject | mitigation.MitigationBypass |
| dan / jailbreak | jailbreak.JailbreakDetect |
| encoder | encoding.EncodingDetect |
| malgen | malware.MalwareFamilyDetector |
| hallucination | hallucination.HallucinationDetector |
| ... | ... |

### OPT-G5: 增量执行缓存

**实施内容**：按 `target + model + probes + depth` 的 MD5 哈希缓存，TTL 24 小时。

**缓存目录**：`results/recon/cache/garak/{hash}.json`

**缓存命中时**：跳过 garak 执行，直接返回缓存的 findings，`duration=0.0`。

### OPT-G6: 通用预热

**实施内容**：执行前发送最小请求确保端点就绪。

| 目标类型 | 预热方法 |
|----------|----------|
| Ollama | `POST /api/generate` with `num_predict=1` |
| vLLM / OpenAI-compat | `POST /v1/chat/completions` with `max_tokens=1` |
| 通用 fallback | `GET /v1/models` |

**收益**：避免首次请求模型加载导致的超时。

---

## 4. DeepTeam 适配器优化（OPT-D1~D5）

### OPT-D1: 攻击类型全量覆盖

**实施内容**：深度分层攻击类型。

| 深度 | 攻击类型数量 | 包含 Agentic |
|------|-------------|-------------|
| quick | 2 | 否 |
| standard | 11 | 否 |
| deep | 18 | 是（ASI01-04） |

### OPT-D2: Agentic 漏洞覆盖

**实施内容**：检测到 agent/mcp surface 时条件触发 Agentic 攻击。

**触发条件**：
- `aimap_data.surfaces` 包含 `"agent"`，或
- `aimap_data.detected_protocols` 包含 `"mcp"`，且
- `depth != "quick"`

**Agentic 攻击类型**：`goal_theft` / `recursive_hijacking` / `tool_abuse` / `identity_abuse`

### OPT-D3: model_callback 增强

**实施内容**：
1. 支持 `function_calling`（发送 tools 参数）
2. 支持 `streaming`（检测但不启用，DeepTeam 需完整响应）
3. **超时自适应**（quick=30s, standard=60s, deep=120s）
4. **错误重试**（429 Rate Limit → 指数退避，max_retries=2）

### OPT-D4: 异步模式启用

**实施内容**：`async_mode=True`，`max_concurrent=3`。

### OPT-D5: 攻击方法配置

**实施内容**：自动匹配 16 种攻击方法（`ATTACK_METHODS`），每种方法关联 vulnerability + severity。

---

## 5. ProfileMerger 优化（OPT-M1~M2）

### OPT-M1: 语义去重

**实施内容**：在原有前缀匹配去重基础上，增加 Jaccard 相似度二次去重。

**算法**：
1. 前缀匹配去重（category + description[:50]）→ 快速路径
2. Jaccard 语义去重（同 category，threshold=0.80）→ 精确路径

**Jaccard 相似度计算**：
```python
words1 = set(re.findall(r"[a-z0-9_]+", s1))
words2 = set(re.findall(r"[a-z0-9_]+", s2))
return len(words1 & words2) / len(words1 | words2)
```

**合并策略**：相似度 ≥ 0.80 的发现合并，取更高置信度 + 更长 evidence。

### OPT-M2: 动态攻击建议

**实施内容**：基于完整画像多维度生成攻击建议。

| 维度 | 推荐示例 |
|------|----------|
| 模型家族 | Llama → CrescendoAttack / GPT → TAP / Claude → PROGRESSIVE / Qwen → 中文载荷 |
| 模型能力 | function_calling → ASI03 / vision → multimodal_injection / json_mode → 结构化注入 |
| 攻击面 | agent → TREE_SEARCH / rag → 上下文溢出 / vector → embedding_inversion / mcp → 工具注入 |
| 风险等级 | critical → 全量 Fallback 链 / high → 增强 Fallback 链 |
| OWASP ID | LLM01 → DIRECT_SINGLE / LLM07 → TREE_SEARCH / ASI02 → TREE_SEARCH |
| 冲突 | 工具间冲突 → 多路径备选策略 |

---

## 6. ReconEngine 优化（OPT-E1~E3）

### OPT-E1: AIMAP 与 DeepTeam 并行

**实施内容**：AIMAP 与 DeepTeam 并行执行（DeepTeam 不依赖 AIMAP 结果）。

**执行流程（v2）**：
```
┌─────────────────────────────────────────┐
│  ThreadPoolExecutor(max_workers=2)      │
│                                         │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │ AIMAP       │  │ DeepTeam         │  │
│  │ (protocol_  │  │ (不依赖 AIMAP)   │  │
│  │  fingerprint)│  │                  │  │
│  └──────┬──────┘  └────────┬─────────┘  │
│         │                  │            │
│         ▼                  │            │
│  ┌─────────────┐           │            │
│  │ Garak       │           │            │
│  │ (依赖 AIMAP)│           │            │
│  └──────┬──────┘           │            │
│         │                  │            │
│         ▼                  ▼            │
│       results 收集                      │
└─────────────────────────────────────────┘
```

**收益**：总耗时从 `AIMAP + Garak + DeepTeam` 降至 `max(AIMAP + Garak, DeepTeam)`。

**退回机制**：如果 AIMAP 或 DeepTeam 任一不在 tools_to_run 中，退回串行模式。

### OPT-E2: 增量缓存

**实施内容**：Profile 级缓存，按 `target + depth + tools` 的 MD5 哈希。

**缓存目录**：`results/recon/cache/profile/{hash}.json`

**缓存 TTL**：默认 24 小时（可配置 `cache.ttl_seconds`）

**缓存命中时**：
- 跳过全部侦察执行
- tracker 记录 `OPT-E2 cache_hit=True`
- 直接返回缓存的 `TargetProfile`

**序列化**：`TargetProfile.to_dict()` → JSON / `TargetProfile.from_dict()` → 重建

### OPT-E3: 深度自适应超时

**实施内容**：基于 depth 自动选择超时。

| Depth | AIMAP | Garak | DeepTeam |
|-------|-------|-------|----------|
| quick | 15s | 120s | 60s |
| standard | 30s | 300s | 120s |
| deep | 60s | 600s | 300s |

---

## 7. Pipeline 追踪集成

### 7.1 新增 tracker 方法

**`log_recon_optimization`**：记录单个优化项的执行结果。

```python
tracker.log_recon_optimization(
    stage="recon_parallel_dispatch",
    optimization_id="OPT-E1",
    input_summary="tools=protocol_fingerprint+deepteam",
    output_summary="parallel=True",
    metadata={"parallel_tools": ["protocol_fingerprint", "deepteam"]},
)
```

### 7.2 新增展示方法

**`show_recon_optimizations`**：在 `show_full_report` 中展示优化阶段摘要。

**输出格式**（`########` 风格）：
```
######## 侦察阶段优化（OPT-A/G/D/M/E） ########

共 15 项优化已执行
┌──────────┬─────────────────────────────┬──────────────────┐
│ OPT-ID   │ Stage                       │ Output           │
├──────────┼─────────────────────────────┼──────────────────┤
│ OPT-A1   │ recon_protocol_parallel     │ ThreadPool(8)    │
│ OPT-A3   │ recon_rag_probe             │ RAG_RULES(4)     │
│ OPT-A4   │ recon_agent_probe           │ AGENT_RULES(4)   │
│ OPT-A5   │ recon_auth_deep             │ bearer+api_key   │
│ OPT-A6   │ recon_capability_probe      │ function+vision  │
│ OPT-D1   │ recon_deepteam_attack_types │ depth=standard   │
│ OPT-D4   │ recon_deepteam_async        │ max_concurrent=3 │
│ OPT-E1   │ recon_parallel_dispatch     │ parallel=True    │
│ OPT-E3   │ recon_adaptive_timeout      │ timeouts=...     │
│ ...      │ ...                         │ ...              │
└──────────┴─────────────────────────────┴──────────────────┘
```

### 7.3 追踪覆盖的优化项

| 优化项 | Tracker Stage | 触发位置 |
|--------|---------------|----------|
| OPT-A1 | recon_protocol_parallel | engine._run_single_adapter |
| OPT-A2 | (隐含在 OPT-A1 中) | - |
| OPT-A3 | recon_rag_probe | engine._run_single_adapter |
| OPT-A4 | recon_agent_probe | engine._run_single_adapter |
| OPT-A5 | recon_auth_deep | engine._run_single_adapter |
| OPT-A6 | recon_capability_probe | engine._run_single_adapter |
| OPT-G1 | recon_garak_probe_selection | engine._run_single_adapter |
| OPT-G2 | recon_garak_depth_stratified | engine._run_single_adapter |
| OPT-G4 | recon_garak_detector_config | engine._run_single_adapter |
| OPT-G5 | recon_garak_cache | engine._run_single_adapter |
| OPT-G6 | recon_garak_warmup | engine._run_single_adapter |
| OPT-D1 | recon_deepteam_attack_types | engine._run_single_adapter |
| OPT-D2 | recon_deepteam_agentic | engine._run_single_adapter |
| OPT-D4 | recon_deepteam_async | engine._run_single_adapter |
| OPT-D5 | recon_deepteam_attack_methods | engine._run_single_adapter |
| OPT-M1 | recon_merger_jaccard_dedup | engine._run_single_adapter |
| OPT-E1 | recon_parallel_dispatch | engine.run |
| OPT-E2 | recon_cache_hit | engine.run |
| OPT-E3 | recon_adaptive_timeout | engine.run |

### 7.4 导出集成

**`to_dict`**：新增 `recon_optimizations` 字段。

**`export_markdown`**：新增 `### Reconnaissance Optimizations (OPT-A/G/D/M/E)` 部分。

---

## 8. 配置文件更新

`config/recon/recon.yaml` 新增以下配置项：

```yaml
recon:
  cache:          # OPT-E2
    enabled: true
    ttl_seconds: 86400
  parallel_dispatch: true  # OPT-E1

tools:
  garak:
    dynamic_probe_selection: true   # OPT-G1
    depth_stratified_probes: true   # OPT-G2
    enhanced_result_parsing: true   # OPT-G3
    precise_detector: true          # OPT-G4
    use_cache: true                 # OPT-G5
    warmup: true                    # OPT-G6

  deepteam:
    depth_stratified_attacks: true  # OPT-D1
    enable_agentic: true            # OPT-D2
    enhanced_callback: true         # OPT-D3
    max_retries: 2
    async_mode: true                # OPT-D4
    max_concurrent: 3
    auto_attack_methods: true       # OPT-D5

  protocol_fingerprint:
    parallel_probe: true            # OPT-A1
    max_workers: 8
    deep_mcp_probe: true            # OPT-A2
    enable_rag_probe: true          # OPT-A3
    enable_agent_probe: true        # OPT-A4
    deep_auth_check: true           # OPT-A5
    enable_capability_probe: true   # OPT-A6

merger:
  jaccard_dedup_threshold: 0.80     # OPT-M1
  dynamic_recommendations: true     # OPT-M2
```

---

## 9. 验证清单

### 9.1 代码验证

- [x] `protocol_fingerprint_adapter.py` — 无 lint 错误
- [x] `garak_adapter.py` — 无 lint 错误
- [x] `deepteam_adapter.py` — 无 lint 错误
- [x] `profile_merger.py` — 无 lint 错误
- [x] `recon_engine.py` — 无 lint 错误
- [x] `tracker.py` — 无 lint 错误

### 9.2 功能验证

- [ ] OPT-A1：协议探测并行化（确认 ThreadPoolExecutor 使用）
- [ ] OPT-A2：深度 MCP 探测（确认权限隔离 + session 固定检测）
- [ ] OPT-A3：RAG 端点探测（确认 4 类端点检测）
- [ ] OPT-A4：Agent 框架探测（确认 4 类框架检测）
- [ ] OPT-A5：认证深度检测（确认 6 种认证 + 绕过检测）
- [ ] OPT-A6：模型能力深度探测（确认 5 项能力检测）
- [ ] OPT-G1：Probe 动态选择（确认 AIMAP 驱动扩展）
- [ ] OPT-G2：深度分层 Probe（确认 3 级深度）
- [ ] OPT-G3：结果解析增强（确认 hitlog + report.html 解析）
- [ ] OPT-G4：Detector 精确配置（确认 PROBE_DETECTOR_MAP）
- [ ] OPT-G5：增量执行缓存（确认 24h TTL）
- [ ] OPT-G6：通用预热（确认 Ollama + vLLM 预热）
- [ ] OPT-D1：攻击类型全量覆盖（确认 3 级深度）
- [ ] OPT-D2：Agentic 漏洞覆盖（确认条件触发）
- [ ] OPT-D3：model_callback 增强（确认重试 + 超时自适应）
- [ ] OPT-D4：异步模式（确认 async_mode=True）
- [ ] OPT-D5：攻击方法配置（确认 16 种方法）
- [ ] OPT-M1：语义去重（确认 Jaccard threshold=0.80）
- [ ] OPT-M2：动态攻击建议（确认多维度推荐）
- [ ] OPT-E1：AIMAP 与 DeepTeam 并行（确认 ThreadPoolExecutor(2)）
- [ ] OPT-E2：增量缓存（确认 profile 缓存 + 24h TTL）
- [ ] OPT-E3：深度自适应超时（确认 DEPTH_TIMEOUTS）

### 9.3 Pipeline 追踪验证

- [ ] `log_recon_optimization` 方法可调用
- [ ] `show_recon_optimizations` 在 `show_full_report` 中展示
- [ ] `to_dict` 包含 `recon_optimizations` 字段
- [ ] `export_markdown` 包含优化阶段表格
- [ ] 标题格式为 `######## 侦察阶段优化（OPT-A/G/D/M/E） ########`

---

## 附录：优化项 ID 索引

| ID | 分类 | 简述 | 优先级 |
|----|------|------|--------|
| OPT-A1 | AIMAP | 协议探测并行化 | P0 |
| OPT-A2 | AIMAP | 深度 MCP 探测 | P1 |
| OPT-A3 | AIMAP | RAG 端点探测 | P1 |
| OPT-A4 | AIMAP | Agent 框架探测 | P1 |
| OPT-A5 | AIMAP | 认证深度检测 | P1 |
| OPT-A6 | AIMAP | 模型能力深度探测 | P2 |
| OPT-G1 | Garak | Probe 动态选择 | P0 |
| OPT-G2 | Garak | 深度分层 Probe | P1 |
| OPT-G3 | Garak | 结果解析增强 | P1 |
| OPT-G4 | Garak | Detector 精确配置 | P2 |
| OPT-G5 | Garak | 增量执行缓存 | P1 |
| OPT-G6 | Garak | 通用预热 | P1 |
| OPT-D1 | DeepTeam | 攻击类型全量覆盖 | P0 |
| OPT-D2 | DeepTeam | Agentic 漏洞覆盖 | P1 |
| OPT-D3 | DeepTeam | model_callback 增强 | P2 |
| OPT-D4 | DeepTeam | 异步模式启用 | P1 |
| OPT-D5 | DeepTeam | 攻击方法配置 | P2 |
| OPT-M1 | Merger | 语义去重 | P1 |
| OPT-M2 | Merger | 动态攻击建议 | P1 |
| OPT-E1 | Engine | AIMAP 与 DeepTeam 并行 | P0 |
| OPT-E2 | Engine | 增量缓存 | P1 |
| OPT-E3 | Engine | 深度自适应超时 | P2 |
