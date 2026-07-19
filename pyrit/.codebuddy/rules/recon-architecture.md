# 侦察架构规则 — 调度器 + 格式转换器原则

## 规则编号: ARCH-001

**生效日期**: 2026-07-19（v2 更新）
**优先级**: 强制（MUST）

---

## 规则正文

### 1. 核心原则

本框架只做"调度器 + 格式转换器"，不重复造轮子。

**调度器**：统一调度开源工具，编排执行顺序，处理并发和错误。
**格式转换器**：将各工具的输出格式转为统一的 TargetProfile JSON。
**不重复造轮子**：所有侦察/攻击能力来自开源工具，本框架不重写任何探测逻辑。

### 2. 架构约束

| 约束 | 说明 |
|------|------|
| 模块独立 | `reconnaissance/` 不 import `attack/` 或 `orchestrators/` |
| 接口契约 | 侦察与攻击通过 `target_profile.json` 文件通信 |
| 薄壳适配 | 每个 Adapter 仅做格式转换，不重写探测逻辑 |
| 失败隔离 | 任一工具失败不影响其他工具，ProfileMerger 合并可用结果 |
| 可扩展 | 新增工具只需实现 BaseAdapter 接口 |

### 3. 当前工具架构（实际实现）

#### 3.1 ProtocolFingerprintAdapter（AIMAP 指纹逻辑）

| 属性 | 值 |
|------|-----|
| 定位 | AI 框架/协议识别（零外部依赖，纯 stdlib urllib） |
| 调用方式 | Python import（`http_get` / `http_post`） |
| 输出 | fingerprint + surfaces + entry_points + auth + system_prompt_leak + mcp_tools |
| 支持协议 | MCP / Ollama / vLLM / LangServe / Gradio / Streamlit / OpenWebUI / TGI / OpenAI-compat |
| 探测步骤 | 5 步：协议检测 -> 模型提取 -> 认证检测 -> 系统提示泄露 -> MCP 工具枚举 |

#### 3.2 GarakAdapter（LLM 漏洞扫描）

| 属性 | 值 |
|------|-----|
| 定位 | LLM 漏洞扫描（NVIDIA Garak v0.15.1） |
| 调用方式 | subprocess 调用独立 venv（`.garak/`） |
| 输出 | findings（JSONL 解析）|
| Probe 映射 | 12 个 probe -> OWASP 映射（promptinject/dan/malgen/hallucination 等） |
| 特殊功能 | Ollama 预热（避免首次请求超时） |
| AIMAP 桥接 | 从 AIMAP 结果提取端点 -> 配置 Garak model_type/model_name |

#### 3.3 DeepTeamAdapter（OWASP 红队扫描）

| 属性 | 值 |
|------|-----|
| 定位 | OWASP 红队扫描（Confident AI DeepTeam v1.0.7） |
| 调用方式 | Python import（`from deepteam import red_team`） |
| 输出 | findings（test_cases 提取） |
| 漏洞映射 | 16 个类型 -> OWASP 映射（prompt_injection/jailbreak/leakage/poisoning 等） |
| model_callback | 构建目标 LLM 调用函数（urllib + Bearer auth） |

### 4. 执行流程（v2 优化版，AIMAP || DeepTeam 并行）

```
┌─── OPT-E2: 检查 Profile 缓存 ───┐
│  cache hit? → 直接返回           │
│  cache miss? → 继续执行           │
└──────────────────────────────┘
         │
         ▼
┌─── OPT-E1: ThreadPoolExecutor(2) ───┐
│                                      │
│  ┌─────────────┐  ┌──────────────┐  │
│  │ AIMAP        │  │ DeepTeam     │  │
│  │ (OPT-A1~A6)  │  │ (OPT-D1~D5)  │  │
│  └──────┬───────┘  └──────┬───────┘  │
│         │                 │          │
│         ▼                 │          │
│  ┌─────────────┐          │          │
│  │ Garak       │          │          │
│  │ (OPT-G1~G6) │          │          │
│  └──────┬───────┘          │          │
│         │                 │          │
│         ▼                 ▼          │
│       results 收集                   │
└──────────────────────────────────────┘
         │
         ▼
ProfileMerger 合并所有结果
    +-- OWASP ID 对齐
    +-- 冲突检测（severity 差异 >= 2）
    +-- 交叉验证（多工具一致 -> 置信度提升）
    +-- OPT-M1: Jaccard 语义去重（threshold=0.80）
    +-- OPT-M2: 动态攻击建议（模型家族/能力/攻击面/风险等级）
    +-- 风险等级计算
         │
         ▼
OPT-E2: 保存 Profile 到缓存
```

### 5. ProfileMerger 合并策略

| 策略 | 说明 |
|------|------|
| OWASP ID 对齐 | 多工具发现同一 OWASP ID 自动合并 |
| 冲突检测 | severity 差异 >= 2 级标记为 conflict |
| 交叉验证 | 多工具一致发现 -> 置信度提升 |
| 加权融合 | 各工具有独立权重（protocol_fingerprint=0.90, garak=0.85, deepteam=0.85） |
| 去重 | 无 OWASP 映射的发现按 category + description 去重 |
| OPT-M1 语义去重 | Jaccard 相似度 >= 0.80 的同 category 发现合并（2026-07-19 新增） |
| OPT-M2 动态建议 | 基于模型家族/能力/攻击面/风险等级生成多维度攻击建议（2026-07-19 新增） |

### 6. 目录结构（实际）

```
pyrit_ai300/reconnaissance/
+-- recon_engine.py          # 统一调度入口（AIMAP->Garak 顺序 + 流式）
+-- target_profile.py        # TargetProfile 数据模型
+-- profile_merger.py        # 多工具结果合并（增量 + 批量）
+-- owasp_taxonomy.py        # OWASP 分类法 + 冲突解决
+-- adapters/
|   +-- base_adapter.py      # 抽象基类（AdapterResult）
|   +-- protocol_fingerprint_adapter.py  # AIMAP 指纹（5步探测）
|   +-- garak_adapter.py     # Garak subprocess 适配器
|   +-- deepteam_adapter.py  # DeepTeam import 适配器
+-- utils/
    +-- http_client.py       # HTTP 客户端（urllib 封装）
    +-- result_parser.py     # 结果解析器
```

### 7. 流式侦察（run_streaming）

- AIMAP 优先执行 -> 配置 Garak
- 剩余工具通过 `ThreadPoolExecutor` + `as_completed()` 流式执行
- 每个工具完成后 `merge_incremental()` 增量合并
- yield `(tool_name, partial_profile, is_complete)`

### 8. 违规示例

```python
# 错误：在 Adapter 中重写探测逻辑
class GarakAdapter(BaseAdapter):
    def scan(self, target):
        # 自己写 prompt injection 检测逻辑 -- 重复造轮子！
        result = self._custom_injection_check(target)
        ...

# 正确：调用 Garak 原生 API，只做格式转换
class GarakAdapter(BaseAdapter):
    def scan(self, target):
        report = garak.run(target)  # 调用原生 API
        return self._to_profile(report)  # 格式转换
```

```python
# 错误：侦察模块 import 攻击模块
from pyrit_ai300.attack.attack_engine import AttackEngine

# 正确：通过 TargetProfile JSON 文件通信
profile = TargetProfile.load("results/profiles/target.json")
```

### 9. PipelineTracker 集成

侦察引擎全面集成 PipelineTracker：
- `log_recon_start`：侦察开始
- `log_recon_tool`：每个工具执行结果
- `log_recon_aimap_garak_bridge`：AIMAP->Garak 端点桥接
- `log_recon_merge`：合并结果（含冲突 + 交叉验证）
- `log_recon_complete`：侦察完成
- `log_recon_optimization`（v2 新增）：记录 OPT-A/G/D/M/E 优化项执行
- `show_recon_optimizations`（v2 新增）：在 `show_full_report` 中展示优化摘要
  - 标题格式：`######## 侦察阶段优化（OPT-A/G/D/M/E） ########`
  - `to_dict` 导出 `recon_optimizations` 字段
  - `export_markdown` 导出优化阶段表格

---

## 考试映射

| 考试模块 | 侦察工具 | 覆盖 |
|---------|---------|------|
| LLM01 Prompt Injection | Garak + DeepTeam | Prompt Injection, Jailbreak |
| LLM02 Sensitive Disclosure | Garak + DeepTeam | Data Leakage, PII |
| LLM03 Training Data Poisoning | DeepTeam | Bias, Toxicity |
| LLM04 Insecure Output | Garak + DeepTeam | XSS, Insecure Output |
| LLM05 Excessive Agency | DeepTeam | Excessive Agency |
| LLM06 System Prompt | ProtocolFingerprint + DeepTeam | System Prompt Leak |
| LLM07 RAG | DeepTeam | RAG Vulnerability |
| LLM08 Bias | DeepTeam | Bias, Misinformation |
| LLM09 Overreliance | Garak + DeepTeam | Hallucination |
| LLM10 Model Theft | DeepTeam | Model Theft |
| ASI01-ASI10 Agentic | DeepTeam + ProtocolFingerprint | Goal Theft, MCP Tools, Agent |

---

## 优化方向（2026-07-19 分析 + 实施完成）

详见：
- `docs/recon_optimization_analysis.md`：优化分析文档（19 项）
- `docs/recon_optimization_implementation.md`：实施报告（已全部实施）

### v2 已实施优化项（19 项）

| 分类 | 优化项 | 优先级 | 状态 |
|------|--------|--------|------|
| AIMAP | OPT-A1 协议探测并行化 | P0 | ✅ 已实施 |
| AIMAP | OPT-A2 深度 MCP 探测 | P1 | ✅ 已实施 |
| AIMAP | OPT-A3 RAG 端点探测 | P1 | ✅ 已实施 |
| AIMAP | OPT-A4 Agent 框架探测 | P1 | ✅ 已实施 |
| AIMAP | OPT-A5 认证深度检测 | P1 | ✅ 已实施 |
| AIMAP | OPT-A6 模型能力深度探测 | P2 | ✅ 已实施 |
| Garak | OPT-G1 Probe 动态选择 | P0 | ✅ 已实施 |
| Garak | OPT-G2 深度分层 Probe | P1 | ✅ 已实施 |
| Garak | OPT-G3 结果解析增强 | P1 | ✅ 已实施 |
| Garak | OPT-G4 Detector 精确配置 | P2 | ✅ 已实施 |
| Garak | OPT-G5 增量执行缓存 | P1 | ✅ 已实施 |
| Garak | OPT-G6 通用预热 | P1 | ✅ 已实施 |
| DeepTeam | OPT-D1 攻击类型全量覆盖 | P0 | ✅ 已实施 |
| DeepTeam | OPT-D2 Agentic 漏洞覆盖 | P1 | ✅ 已实施 |
| DeepTeam | OPT-D3 model_callback 增强 | P2 | ✅ 已实施 |
| DeepTeam | OPT-D4 异步模式启用 | P1 | ✅ 已实施 |
| DeepTeam | OPT-D5 攻击方法配置 | P2 | ✅ 已实施 |
| Merger | OPT-M1 语义去重 | P1 | ✅ 已实施 |
| Merger | OPT-M2 动态攻击建议 | P1 | ✅ 已实施 |
| Engine | OPT-E1 AIMAP 与 DeepTeam 并行 | P0 | ✅ 已实施 |
| Engine | OPT-E2 增量缓存 | P1 | ✅ 已实施 |
| Engine | OPT-E3 深度自适应超时 | P2 | ✅ 已实施 |

### 配置文件
- `config/recon/recon.yaml`：所有优化项均有独立开关（默认全部启用）
