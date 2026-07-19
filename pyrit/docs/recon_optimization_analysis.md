# Recon 阶段优化分析 — 从 Garak / AIMAP / DeepTeam 架构师视角

> **分析日期**: 2026-07-19
> **分析范围**: `pyrit_ai300/reconnaissance/` 完整侦察引擎
> **视角**: 分别从三个工具的核心架构师角度审视当前实现的局限性与优化方向

---

## 一、当前架构概览

```
ReconEngine.run()
    |
    +-- [1] ProtocolFingerprint (AIMAP) 先执行
    |       5 步探测：协议/模型/认证/系统提示/MCP工具
    |       输出：fingerprint + surfaces + entry_points
    |
    +-- [2] AIMAP -> Garak 桥接
    |       提取端点 -> 配置 model_type/model_name
    |
    +-- [3] Garak + DeepTeam 并发执行
    |       Garak: subprocess JSONL
    |       DeepTeam: Python import red_team()
    |
    +-- [4] ProfileMerger 合并
            OWASP ID 对齐 + 冲突检测 + 交叉验证
```

**三工具职责矩阵：**

| 维度 | ProtocolFingerprint | Garak | DeepTeam |
|------|--------------------|-------|----------|
| 定位 | 协议/框架识别 | 漏洞扫描 | OWASP 红队 |
| 调用 | HTTP 探测 | subprocess venv | Python import |
| Probe 数 | 8 协议规则 | 12 probe | 16 漏洞类型 |
| 耗时 | ~30s | 1-3min | 2-5min |
| 权重 | 0.90 | 0.85 | 0.85 |
| 输出 | 元数据 | JSONL findings | test_cases |

---

## 二、ProtocolFingerprint（AIMAP）架构师视角

### 2.1 当前局限

| 问题 | 影响 | 严重度 |
|------|------|--------|
| **协议探测串行** | 8 个协议规则逐个 HTTP 请求，最坏 24 次串行请求 | 高 |
| **无超时自适应** | 固定 30s 超时，大模型端点可能需要更长 | 中 |
| **MCP 探测浅层** | 仅 `tools/list` 枚举，不检测工具权限/沙箱 | 高 |
| **RAG 探测缺失** | 未检测向量数据库/嵌入端点（LLM07/LLM08） | 高 |
| **Agent 探测缺失** | 未检测 LangGraph/AutoGen/CrewAI 等 Agent 框架 | 高 |
| **认证类型单一** | 仅检测 Bearer，不检测 API Key/Cookie/OAuth | 中 |
| **无重试机制** | HTTP 请求失败直接跳过，不重试 | 中 |
| **模型能力探测不足** | 仅提取 model_name，不探测 function_calling/json_mode/vision | 中 |

### 2.2 优化建议

#### OPT-A1: 协议探测并行化
```
当前：for rule in PROTOCOL_RULES: for path in rule["paths"]: http_get(...)
优化：ThreadPoolExecutor 并行探测所有协议规则
预期收益：30s -> 8-10s
```

#### OPT-A2: 深度 MCP 探测
```
当前：仅 tools/list 枚举工具名
优化：
  1. tools/list -> 枚举工具 + 参数 schema
  2. 检测工具是否有权限隔离（resources/read vs tools/call）
  3. 探测 MCP session 固定漏洞（同一 session_id 跨用户复用）
  4. 检测 MCP 工具注入风险（tool description 中是否有指令注入）
映射：ASI03 (Tool Abuse) / ASI06 (Excessive Agency)
```

#### OPT-A3: RAG 端点探测
```
新增探测路径：
  - /v1/embeddings -> 嵌入 API（LLM08 向量弱点）
  - /api/v1/collections -> ChromaDB 集合枚举（LLM08）
  - /api/vectordb -> 自定义向量 DB 端点
  - /api/search -> RAG 检索端点（LLM07）
检测内容：
  - 是否无需认证即可查询
  - 是否可枚举集合/文档
  - 嵌入模型是否可提取
映射：LLM07 (RAG) / LLM08 (Vector Weakness)
```

#### OPT-A4: Agent 框架探测
```
新增协议规则：
  - LangGraph: /graph/invoke, /graph/stream
  - AutoGen: /api/agents, /api/chat
  - CrewAI: /api/crew, /api/tasks
  - Dify: /api/chat-messages, /api/agents
检测内容：
  - Agent 是否暴露任务列表
  - 是否可枚举可用工具
  - 是否存在 goal hijack 面
映射：ASI01-ASI10
```

#### OPT-A5: 认证深度检测
```
当前：仅检测 401/403 -> bearer
优化：
  - 检测 API Key（X-API-Key header）
  - 检测 Cookie 认证（Set-Cookie 响应头）
  - 检测 OAuth（/oauth/token, /authorize 路径）
  - 检测 JWT 过期时间（解码 exp 字段）
  - 检测认证绕过（空 Authorization / 空白 token）
映射：LLM02 / ASI04
```

#### OPT-A6: 模型能力深度探测
```
当前：仅提取 model_name
优化：发送探测请求检测：
  - function_calling：发送 tools 参数，检查是否支持
  - json_mode：发送 response_format=json，检查响应
  - vision：发送 image_url，检查是否处理
  - streaming：发送 stream=true，检查 SSE
  - system_prompt 隔离：检查 system role 是否可被覆盖
这些能力直接驱动攻击策略选择：
  - function_calling -> ASI03 工具滥用
  - vision -> 多模态注入
  - json_mode -> 结构化注入
```

---

## 三、Garak 架构师视角

### 3.1 当前局限

| 问题 | 影响 | 严重度 |
|------|------|--------|
| **Probe 列表硬编码** | `DEFAULT_PROBES` 固定 6 个，不根据目标特征调整 | 高 |
| **无深度分层** | quick/standard/deep 深度未影响 probe 选择 | 高 |
| **结果解析脆弱** | 仅读取 `garak_output/*.jsonl`，不解析 hitlog | 中 |
| **无增量执行** | 每次全量运行，不支持只跑失败的 probe | 中 |
| **Detector 未配置** | detectors 为空，使用默认，不够精确 | 中 |
| **无进度回调** | subprocess 阻塞，无法实时输出进度 | 低 |
| **预热逻辑硬编码 Ollama** | 其他后端（vLLM/TGI）无预热 | 低 |

### 3.2 优化建议

#### OPT-G1: Probe 动态选择（基于 AIMAP 结果）
```
当前：DEFAULT_PROBES = ["promptinject", "dan", "malgen", ...]
优化：根据 AIMAP 检测到的协议/能力动态选择

if "mcp" in detected_protocols:
    probes.append("lmrc")  # MCP 相关
if "function_calling" in capabilities:
    probes.append("promptinject")  # 指令注入
if "rag" in surfaces:
    probes.append("leakreplay")  # 数据泄露
if model_family == "llama":
    probes.append("continuation")  # Llama 特有
if "vision" in capabilities:
    probes.append("visual_jailbreak")  # 多模态

预期收益：减少无效 probe 执行，扫描时间降低 30-50%
```

#### OPT-G2: 深度分层 Probe 策略
```
quick (30s-1min):
    probes = ["promptinject", "dan"]  # 最核心 2 个

standard (1-3min):
    probes = ["promptinject", "dan", "malgen", "hallucination", "toxicity"]

deep (3-10min):
    probes = ALL_PROBES  # 全部 12 个
    + 迭代执行（每个 probe 跑 3 次取最优）
    + 生成对抗后缀探测
```

#### OPT-G3: 结果解析增强
```
当前：仅解析 *.jsonl 中 status=completed 的记录
优化：
  1. 解析 hitlog/ 目录（更详细的命中日志）
  2. 提取 garak_report.html 中的汇总统计
  3. 解析 fail 记录（探测失败 != 无漏洞，可能是超时）
  4. 提取 trigger 信息（具体触发的 payload）
预期收益：findings 从 ~5 个提升到 ~15-20 个
```

#### OPT-G4: Detector 精确配置
```
当前：detectors = []  # 使用默认
优化：根据 OWASP 类别配置精确 detector

probe_to_detector = {
    "promptinject": "mitigation.MitigationBypass",
    "dan": "jailbreak.JailbreakDetect",
    "malgen": "malware.MalwareFamilyDetector",
    "hallucination": "hallucination.HallucinationDetector",
    "toxicity": "toxicity.ToxicityDetector",
    "xss": "xss.XPathDetector",
}
预期收益：减少误报，提高 finding 置信度
```

#### OPT-G5: 增量执行与缓存
```
当前：每次全量执行所有 probe
优化：
  1. 缓存上次执行结果（按 target+model+probe 哈希）
  2. 仅执行未缓存或缓存过期的 probe
  3. --force 标志强制全量执行
  4. 失败 probe 自动重试（最多 2 次）
预期收益：重复侦察同一目标时，时间从 3min 降至 30s
```

#### OPT-G6: 通用预热
```
当前：仅 Ollama 预热（_warmup_ollama）
优化：
  - vLLM: GET /v1/models 触发模型加载
  - TGI: POST /generate with max_new_tokens=1
  - OpenAI-compat: POST /v1/chat/completions with max_tokens=1
  - 通用：发送最小请求确保端点就绪
```

---

## 四、DeepTeam 架构师视角

### 4.1 当前局限

| 问题 | 影响 | 严重度 |
|------|------|--------|
| **attack_types 固定 3 个** | recon.yaml 仅配置 prompt_injection/jailbreak/leakage | 高 |
| **无 Agentic 漏洞** | ASI01-ASI10 完全未覆盖 | 高 |
| **model_callback 简单** | 仅 urllib POST，不支持 streaming/multimodal | 中 |
| **无 async_mode** | 强制 `async_mode=False`，未利用并发 | 中 |
| **attacks 为空** | 未配置具体攻击方法，使用 DeepTeam 默认 | 中 |
| **无结果去重** | DeepTeam 可能返回大量相似 finding | 低 |

### 4.2 优化建议

#### OPT-D1: 攻击类型全量覆盖
```
当前：attack_types = ["prompt_injection", "jailbreak", "leakage"]
优化：根据 depth 分层

quick:
    attack_types = ["prompt_injection", "jailbreak"]
standard:
    attack_types = DEFAULT_VULNERABILITIES  # 11 个
deep:
    attack_types = ALL_VULNERABILITY_TYPES  # 16 个（含 Agentic）
    + attacks 配置具体攻击方法
```

#### OPT-D2: Agentic 漏洞覆盖
```
新增 attack_types:
  - "goal_theft"      -> ASI01
  - "recursive_hijacking" -> ASI02
  - "tool_abuse"      -> ASI03
  - "identity_abuse"  -> ASI04

条件触发：仅当 AIMAP 检测到 agent/mcp surface 时启用
（避免对非 Agent 目标浪费扫描时间）
```

#### OPT-D3: model_callback 增强
```
当前：urllib POST，不支持 streaming/multimodal/system_prompt
优化：
  1. 支持 system_prompt 注入（检测 system role 隔离）
  2. 支持 function_calling（发送 tools 参数）
  3. 支持 streaming 响应（SSE 解析）
  4. 超时自适应（quick=30s, standard=60s, deep=120s）
  5. 错误重试（429 Rate Limit -> 指数退避）
```

#### OPT-D4: 异步模式启用
```
当前：async_mode=False（同步）
优化：async_mode=True + max_concurrent=3
预期收益：standard 深度扫描时间从 5min 降至 2min
注意：需要确保 model_callback 线程安全
```

#### OPT-D5: 攻击方法配置
```
当前：attacks = []  # 使用 DeepTeam 默认
优化：为每个漏洞类型配置精确攻击方法

attacks = [
    {"vulnerability": "prompt_injection", "attack": "dan_66", "severity": "high"},
    {"vulnerability": "jailbreak", "attack": "crescendo", "severity": "high"},
    {"vulnerability": "leakage", "attack": "grandma_attack", "severity": "medium"},
    {"vulnerability": "hallucination", "attack": "false_facts", "severity": "medium"},
]
预期收益：更精确的攻击覆盖，减少无效探测
```

---

## 五、ProfileMerger 架构师视角

### 5.1 当前局限

| 问题 | 影响 | 严重度 |
|------|------|--------|
| **去重仅按 description 前 50 字符** | 长描述可能误判为重复 | 中 |
| **冲突检测仅 severity** | 不检测 confidence 冲突 | 低 |
| **无时间衰减** | 旧结果与新结果权重相同 | 低 |
| **攻击建议静态** | 固定 14 条 owasp_recommendations，不根据画像动态调整 | 中 |

### 5.2 优化建议

#### OPT-M1: 语义去重
```
当前：key = f"{category}:{description[:50].lower()}"
优化：使用 Jaccard 相似度（复用 payload_dedup.py 的逻辑）
阈值：0.80（比载荷去重更宽松，因为漏洞描述更结构化）
```

#### OPT-M2: 动态攻击建议
```
当前：固定 owasp_recommendations 字典
优化：基于完整画像动态生成

if model_family == "llama":
    recommendations += "Llama 系列对 crescendo 攻击敏感"
if "function_calling" in capabilities:
    recommendations += "支持 function calling，增加 ASI03 工具滥用攻击"
if "vision" in capabilities:
    recommendations += "支持多模态，增加图像注入攻击"
if risk_level == "critical":
    recommendations += "高风险目标，启用全量 Fallback 链"
```

---

## 六、ReconEngine 调度优化

### 6.1 当前局限

| 问题 | 影响 | 严重度 |
|------|------|--------|
| **AIMAP 串行阻塞** | AIMAP 必须完成后才能启动 Garak | 高 |
| **无缓存机制** | 重复侦察同一目标全量执行 | 高 |
| **超时全局固定** | 不根据 depth 调整 | 中 |
| **无断点续传** | 执行中断需从头开始 | 中 |

### 6.2 优化建议

#### OPT-E1: AIMAP 与 DeepTeam 并行启动
```
当前：AIMAP -> Garak -> DeepTeam（串行+并行混合）
优化：
  1. AIMAP 独立执行（必须先完成）
  2. DeepTeam 不依赖 AIMAP，可并行启动
  3. 仅 Garak 等待 AIMAP 结果
  4. AIMAP 完成后立即启动 Garak

时间线：
  当前：[AIMAP 30s] -> [Garak 2min + DeepTeam 3min 并行] = 3.5min
  优化：[AIMAP 30s + DeepTeam 3min 并行] -> [Garak 2min] = 3min
  （如果 DeepTeam 比 AIMAP 长则不阻塞）
```

#### OPT-E2: 增量缓存
```
缓存策略：
  - 缓存键：hash(target_url + depth + tools)
  - 缓存目录：results/recon/cache/
  - 过期时间：24h（可配置）
  - 命中时：跳过已缓存的工具，仅执行新工具
  - --force-recon：强制忽略缓存

缓存结构：
  cache/
    {target_hash}/
      protocol_fingerprint.json  # AIMAP 结果
      garak.jsonl                # Garak 结果
      deepteam.json               # DeepTeam 结果
      metadata.json              # 时间戳 + 工具版本
```

#### OPT-E3: 深度自适应超时
```
quick:   timeout = 60s per tool
standard: timeout = 300s per tool
deep:    timeout = 600s per tool

协议探测：固定 30s（快速）
Garak:    quick=120s, standard=300s, deep=600s
DeepTeam: quick=120s, standard=300s, deep=600s
```

---

## 七、优化优先级矩阵

| 编号 | 优化项 | 工具 | 收益 | 复杂度 | 优先级 |
|------|--------|------|------|--------|--------|
| OPT-A1 | 协议探测并行化 | AIMAP | 高 | 低 | P0 |
| OPT-G1 | Probe 动态选择 | Garak | 高 | 中 | P0 |
| OPT-D1 | 攻击类型全量覆盖 | DeepTeam | 高 | 低 | P0 |
| OPT-A3 | RAG 端点探测 | AIMAP | 高 | 中 | P1 |
| OPT-A4 | Agent 框架探测 | AIMAP | 高 | 中 | P1 |
| OPT-A2 | 深度 MCP 探测 | AIMAP | 高 | 高 | P1 |
| OPT-E2 | 增量缓存 | Engine | 高 | 中 | P1 |
| OPT-G2 | 深度分层 Probe | Garak | 中 | 低 | P1 |
| OPT-D2 | Agentic 漏洞覆盖 | DeepTeam | 高 | 中 | P2 |
| OPT-A6 | 模型能力深度探测 | AIMAP | 中 | 中 | P2 |
| OPT-G3 | 结果解析增强 | Garak | 中 | 低 | P2 |
| OPT-E1 | AIMAP 与 DeepTeam 并行 | Engine | 中 | 中 | P2 |
| OPT-D4 | 异步模式 | DeepTeam | 中 | 低 | P2 |
| OPT-G4 | Detector 精确配置 | Garak | 中 | 低 | P3 |
| OPT-A5 | 认证深度检测 | AIMAP | 中 | 中 | P3 |
| OPT-M1 | 语义去重 | Merger | 低 | 低 | P3 |
| OPT-M2 | 动态攻击建议 | Merger | 中 | 中 | P3 |
| OPT-G5 | 增量执行缓存 | Garak | 中 | 高 | P3 |
| OPT-E3 | 深度自适应超时 | Engine | 低 | 低 | P3 |

---

## 八、实施路线图

### Phase 1 (P0) — 快速收益，1-2 天
1. **OPT-A1**: 协议探测并行化 -> 侦察时间减半
2. **OPT-G1**: Probe 动态选择 -> Garak 扫描更精准
3. **OPT-D1**: 攻击类型全量覆盖 -> DeepTeam 覆盖更全

### Phase 2 (P1) — 深度扩展，3-5 天
4. **OPT-A3**: RAG 端点探测 -> 覆盖 LLM07/LLM08
5. **OPT-A4**: Agent 框架探测 -> 覆盖 ASI01-ASI10
6. **OPT-A2**: 深度 MCP 探测 -> 覆盖 ASI03/ASI06
7. **OPT-E2**: 增量缓存 -> 重复侦察提速 10x
8. **OPT-G2**: 深度分层 Probe -> 精细化扫描

### Phase 3 (P2) — 质量提升，3-5 天
9. **OPT-D2**: Agentic 漏洞覆盖 -> 完整 ASI 覆盖
10. **OPT-A6**: 模型能力探测 -> 驱动攻击策略
11. **OPT-G3**: 结果解析增强 -> findings 数量 3x
12. **OPT-E1**: 调度并行优化 -> 整体时间 -15%
13. **OPT-D4**: DeepTeam 异步 -> 扫描时间 -40%

### Phase 4 (P3) — 精细化，2-3 天
14. **OPT-G4**: Detector 精确配置
15. **OPT-A5**: 认证深度检测
16. **OPT-M1/M2**: Merger 语义去重 + 动态建议
17. **OPT-G5**: Garak 增量缓存
18. **OPT-E3**: 超时自适应

---

## 九、预期效果

### 量化收益（Phase 1-2 完成后）

| 指标 | 当前 | 优化后 | 提升 |
|------|------|--------|------|
| 侦察总耗时（standard） | ~5min | ~2.5min | 50% |
| 协议探测耗时 | ~30s | ~8s | 73% |
| OWASP 覆盖 | 10/20 | 18/20 | 80% |
| Garak probe 命中率 | ~40% | ~70% | 75% |
| DeepTeam 漏洞类型 | 3/16 | 11/16 | 267% |
| 重复侦察耗时 | ~5min | ~30s | 90% |
| findings 数量 | ~10 | ~25 | 150% |

### 定性收益
- **完整覆盖**: 从 10/20 OWASP 提升到 18/20（新增 RAG/Agent/MCP 深度探测）
- **精准扫描**: Probe/Attack 类型根据目标特征动态选择，减少无效扫描
- **增量能力**: 缓存机制支持快速重测，适配迭代开发场景
- **深度分层**: quick/standard/deep 三级真正影响扫描范围，而非仅超时
