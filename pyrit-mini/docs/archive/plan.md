# PyRIT-Mini 优化总方案：面向企业级 LLM 应用的多组件组合体攻击

> **文档层级**：执行方案（承接 `docs/specs/00-CONSTITUTION.md` 裁决序第 ④ 层：任务规格）
> **版本**：v1.0
> **日期**：2026-09-11
> **适用对象**：参与本项目的 AI 编码代理与人类评审
> **遵循规范**：`00-CONSTITUTION.md` C1–C14（v2.2）、`80-COMPONENT-ARCHITECTURE-RULES.md`（v1.0）、`40-GUARDRAILS.md`

---

## 第 0 章 执行摘要

### 0.1 项目使命（宪法第 0 条）

> 对 Burp Suite 拦截的、基于 LLM 开发的 AI 应用（黑盒 HTTP 目标），以攻击成功率（ASR）为首要度量，交付可复现的完整攻击证据链。

### 0.2 当前能力判定（实测，非估计）

| 层 | 水平 | 关键证据 |
|---|---|---|
| 评测 / 统计 / 报告（`assess/`、`report/`） | **L4** | T0→J1→J2 双 Judge、Wilson CI、Cohen's Kappa、SARIF、OWASP/CVSS/MITRE 映射，代码完整 |
| 编排骨架（`core/phases/`） | L3 | 六阶段设计正确，但 escalate 无调用点、`--stage` 语义破损 |
| 攻击执行（`strike/`） | **L1.5** | 67 个模块仅 16 个可达；主链路实际只有 `PromptSendingAttack` + `SequentialAttack` 两个算法 |
| 侦察（`recon/`） | L2 | 组件化设计良好，但重构后遗留 8 条失效 import |
| **端到端可用性** | **L1** | 默认命令在 RECON 阶段 `NameError` 崩溃，**退出码 0**，用户无感 |

**量化落差**：模块可达率 23.9%、技术真实执行率 8.3%（12 个技术名仅为标签）、多轮对抗式攻击可达率 0%、Converter builder 注册率 54.2%。

### 0.3 本方案的目标态

针对**真实企业级 LLM 应用的多组件组合体**，交付：

1. **多组件组合体识别**：不再假定目标是单一组件，而是还原其组件拓扑（`ComponentGraph`）
2. **有状态攻击链**：跨多轮、跨组件携带状态的攻击编排（`StatefulAttackChain`）
3. **影响链举证**：从入口组件到最终业务影响的因果链证据（`ImpactChain`）
4. **全组件覆盖**：补齐当前缺失的企业组件类别，做到「每种组件都有全套配套」

### 0.4 最重要的杠杆点（复用而非重写）

`tools/architecture_validator.py:79-114` **已存在**一张「组件 → recon / strike / assess / report 四层模块」映射表；`recon/a2a/` 下**已存在** `TopologyGraph`、`TrustChainSegment`、`AttackPathPlanner`、`_dfs_chains`；`strike/` 下**已存在**多种 chain 生成器。

**问题只有一个：它们全部零生产调用。**

本方案的实施主线是**接线与提升为运行时 SSOT**，而非重写。这同时满足宪法 C4（最小变更）与 C3（SSOT）。

---

## 第一章 specs 合规裁决矩阵

### 1.1 宪法 `00-CONSTITUTION.md`（C1–C14）裁决

| 条款 | 条款名 | 裁定 | 证据坐标 |
|---|---|---|---|
| C1 | PyRIT 原生优先 | **部分违例** | 见 1.1.1 |
| C2 | ASR 至上 | **严重违例** | 见 1.1.2 |
| C3 | 单一事实源 SSOT | **违例** | 见 1.1.3 |
| C4 | 最小变更 | 待观察 | 本方案所有改动均限定在「改动坐标总表」（附录 A） |
| C5 | 先读后写 | 执行时遵守 | 每个文件修改前必须完整读取 |
| C6 | 规格先行 | **部分违例** | 既有代码大量无法关联 TASK/REQ ID |
| C7 | 配置数据流不可断 | **违例** | 见 1.1.4 |
| C8 | 学术留痕 | **部分违例** | mojibake 已破坏大量 arXiv 注释（`arm/converter_chains.py` 60 处等） |
| C9 | 诚实汇报 | **违例** | 20+ 处 `except Exception: logger.debug` 静默吞错而未声明 |
| C10 | 验证义务 | **违例** | 五步门禁无 CI 执行；e2e 为 `assert module is not None` 烟雾测试 |
| C11 | 停止权 | 遵守 | 本方案歧义点已在第 9 章登记为待裁决项 |
| C13 | 企业攻击扩展 | **违例** | 见 1.1.5 |
| C14 | 跨模型一致性 | 待执行 | 本方案需 ≥2 独立模型交叉确认后方可合入规约层 |

#### 1.1.1 C1 违例明细（R-NATIVE-1 ~ R-NATIVE-6）

| 检查项 | 裁定 | 证据 |
|---|---|---|
| R-NATIVE-1 攻击类 | ⚠️ 部分 | ✅ 主链路用原生 `PromptSendingAttack`/`SequentialAttack`；❌ 宪法 7B 登记的 `SkeletonKeyAttack`/`CrescendoAttack`/`TAPAttack`/`PAIRAttack` **全部零触发** |
| R-NATIVE-2 Converter | ✅ 基本合规 | `arm/converter_chains.py` 经 `importlib` 动态取 `pyrit.converter` 原生类 |
| R-NATIVE-3 Scorer | ⚠️ 部分 | ✅ J1/J2 用原生 `SelfAskTrueFalseScorer`/`SelfAskRefusalScorer`；❌ `judge_manager.py:260-425` 自研正则词表打分替代原生 Scorer |
| R-NATIVE-4 Target | **❌ 违例** | `strike/web/http_engine.py` 用 `urllib.request` 自研 HTTP，替代原生 `HTTPTarget` |
| R-NATIVE-5 Memory | ✅ 合规 | 使用 PyRIT `CentralMemory` / `SQLiteMemory` |
| **R-NATIVE-6 Output** | **⚠️ 半违例** | `utils/display.py:417/440` **已正确封装** `output_attack_async`/`output_scenario_async` + `StdoutSink`，但**零调用点**；实际仅 `report/pyrit_native_output.py:89/114/199/212` 用 `FileSink` 写文件 |

> **R-NATIVE-6 是本方案的核心交付之一**：「攻击过程中用 PyRIT 原生 output 函数打印攻击者关心的信息到终端」在宪法中已登记为强制项，当前代码**只写文件不打印**。为此不需新开发，只需**接通**。

#### 1.1.2 C2 违例（严重）

宪法原文（`00-CONSTITUTION.md:89`）：

> 单轮 ASR < 90% 必须可触发升级链；评分分歧默认 OR 聚合；每 `ConverterConfiguration` 恰 1 个 converter；攻击执行路径只准 0-token 评分器。

| 要求 | 现状 | 裁定 |
|---|---|---|
| ASR<90% 触发升级链 | `_run_escalate_phase`（`core/phases/strike.py:683`）**零调用点**；`strike.py:711` import 路径失效 | ❌ 从不触发 |
| 每个 ConverterConfiguration 恰 1 converter | `arm/converter_presets.py:599-617` 已正确实现 1:1 路径 | ✅ 合规 |
| 攻击执行路径只准 0-token 评分器 | `core/phases/strike.py:163` 与 `assess.py:42` 均调用含 LLM 的 `precompute_outcomes_async` | ⚠️ 需区分 pre-vs-post-hoc 边界 |

#### 1.1.3 C3 违例明细（双轨实现）

| 概念 | 实现套数 | 参数/语义差异 | 坐标 |
|---|---|---|---|
| TAP | **4** | `depth`=3/2/3；`width`=3/3/5 | `escalation_runtime.py:205`、`progressive_strike.py:525`、`pair_tap.py:150`、`dispatcher.py:56` |
| PAIR | **2** | `max_iterations`=5/10 | `progressive_strike.py:575`、`pair_tap.py:89` |
| Crescendo | **3** | `max_backtracks`=2（两套一致） | `escalation_runtime.py:180`、`progressive_strike.py:475`、`dispatcher.py:55` |
| `_is_success` | **3** | SSOT 用 `score_val > 0`；另两份用 `bool(score_val)` | `utils/attack_utils.py:33`、`progressive_strike.py:671`、`adaptive_executor.py:19` |
| 组件类型键映射 | **4** | 各存一份硬编码 | `architecture_validator.py:36-41`、`component_audit_core.py:141-146`、`component_scorers.py`、`component_reports.py` |
| `_best_of_n_retry` | 调用签名不匹配，恒空转 | 第二实参传 list 而非 callable | `executor.py:580` vs `adaptive_executor.py:90` |

#### 1.1.4 C7 违例（硬编码效率参数）

| 位置 | 字面量 |
|---|---|
| `core/context.py:222` | `max_val=3`（与 `config/defaults.yaml:5 max_concurrency: 5` 冲突） |
| `assess/_or_and_calibration.py:20/21/73` | `0.30` / `10` / `0.75` |
| `strike/common/escalation_runtime.py:133-141` | `0.15 / 0.40 / 0.65 / 0.80` |
| `arm/converter_selector.py:669` | `_MIN_PATHS = 4` |
| `arm/seed_ranking.py:318,578` | EMA `alpha=0.3`（重复三处） |
| `core/seed_quality_assessor.py:30-34` | `_MIN_SEED_SAMPLES=10`、`_RETIREMENT_THRESHOLD=0.10` |
| `recon/api/recursive_expander.py:348`、`recon/rag/pipeline_probe.py:162` | 并发 `5` / `2` |

#### 1.1.5 C13 违例

`strike/web/http_engine.py` 内含**攻击执行逻辑**（`urllib` 建连发请求），违反 C13 原则 2「扩展层仅构造 payload/target/scorer 配置，攻击执行一律委托给 PyRIT 原生类」。

### 1.2 `80-COMPONENT-ARCHITECTURE-RULES.md` 裁决

| 规则 | 裁定 | 证据 |
|---|---|---|
| **S-DIR-1** strike/ 根目录无攻击实现 | ✅ **合规** | 根目录现只剩 `__init__.py` + `_strategies.yaml` |
| **F-DIR-2** 框架层禁止直接 import 组件实现 | ⚠️ 部分 | 大量延迟 import 打补丁（变相解耦但不规范） |
| **C-NAME-1** 组件键与目录语义一致 | ✅ 合规 | 6 个键与目录语义一致；但 `recon/embedding/` **无对应键**（见 1.3） |
| **C-NAME-2** 种子 `suitable_for` 匹配注册键 | ⚠️ 待校验 | 无自动化校验，`core/seed_loader.py:220-257` 只做 `isinstance(list)` 判定 |
| **CB-1** `component_type` 由 `_component_bridge` 统一写入 | ✅ **合规** | `core/phases/strike.py:169-171` 确实调用 `stamp_component_metadata` |
| **CB-2** 下游通过 `metadata.get("component_type")` 读取 | **❌ 断裂** | `report/component_reports.py:96/109/167` 读 `getattr(ev, "metadata", {})`，而 `VulnerabilityEvidence`（`report/evidence.py:96-141`）**无 metadata 字段** → 恒 `{}` → `_determine_dominant_component()` 恒 `None` → **组件专属报告永不生成** |
| **IA-3** 组件类型键由注册中心统一管理 | **❌ 违例** | 四份分散硬编码映射（见 1.1.3） |
| **IA-6** 未知组件返回 None 不崩溃 | ✅ 模板合规（但 CB-2 断裂导致实际恒 None） |
| **IA-7** 开放-封闭原则 | ❌ 违例 | 新增组件需改 4 处硬编码映射 |

### 1.3 组件覆盖缺口（本方案必须补齐）

`tools/architecture_validator.py:36-41` 仅登记 6 个组件键，而 `recon/` 实际有 **8 个**子包：

| recon 子包 | 对应组件键 | 状态 |
|---|---|---|
| `recon/a2a/` | `a2a_agent_integrity` | ✅ 已登记 |
| `recon/api/` | `web_api` | ✅ 已登记（与 `recon/web/` 重复归属） |
| `recon/mcp/` | `mcp_tool_poisoning` | ✅ 已登记 |
| `recon/model/` | `model_behavior_shift` | ✅ 已登记 |
| `recon/rag/` | `rag_pipeline` | ✅ 已登记 |
| `recon/session/` | `session_memory` | ⚠️ 已登记但 `architecture_validator.py:83` 的 recon 清单为**空数组** → 无法识别 |
| `recon/web/` | `web_api` | ⚠️ 与 `recon/api/` 双轨（违 C3） |
| **`recon/embedding/`** | **无键** | **❌ 完全缺失** |

**结论**：距离「覆盖真实企业 LLM 应用所有组件」还差：① `embedding` 组件键缺失；② `session_memory` 无侦察实现绑定；③ `api` 与 `web` 双轨。

---

## 第二章 目标场景建模：企业级 LLM 应用的多组件组合体

> 本章是本方案相对既有设计的核心增量。真实企业 LLM 应用**几乎从不是单一组件**，而是多组件组合体。

### 2.1 真实企业 LLM 应用的组件全景

一次典型的 Burp 拦截请求背后，通常是如下拓扑：

```
用户请求
   │
   ▼
[1] web_api            接入/Web 层：认证、API 网关、限流、WAF
   │
   ▼
[2] llm_gateway        模型网关/编排层：路由、prompt 模板、护栏(guardrail)
   │
   ├────────────► [3] rag_pipeline     检索增强：向量库、KB、重排、引用注入
   │
   ├────────────► [4] embedding        嵌入层：embedding 模型、相似度检索
   │
   ├────────────► [5] mcp_tool_poisoning   MCP 工具层：工具注册、Schema、外部能力
   │
   ├────────────► [6] a2a_agent_integrity  多智能体：AgentCard、编排拓扑、跨 agent 调用
   │
   ├────────────► [7] session_memory   会话/记忆：会话态、长期记忆、跨会话上下文
   │
   └────────────► [8] model_behavior_shift 模型本体：越狱、输出过滤绕过、多模态、后门
                        │
                        ▼
                  [9] audit_evasion    审计/可观测面：日志、追踪、告警（规避对象）
                        │
                        ▼
                  [10] supply_chain    插件/供应链：第三方 skill、plugin、注册中心
```

**本方案要求上述 10 类组件全部具备**：`recon` 专项侦察 + `seeds` + `converters` + `strike` 模块 + `assess` T0 评分与 rubric + `report` 专属报告 + `PoC`。

### 2.2 三类核心模型

#### 2.2.1 `ComponentGraph`：多组件组合体

单一 `component_type` 标签无法表达组合体。引入**组件拓扑图**：

```python
# core/contracts/component_graph.py
class ComponentNode(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    component_key: str                  # mcp_tool_poisoning / rag_pipeline / ...
    confidence: float                   # 0.0–1.0，来自 ComponentClassifier
    evidence_refs: list[str]            # 命中的信号，可回溯
    endpoints: list[str] = []           # 该组件暴露的端点
    attributes: dict[str, Any] = {}     # 组件特定事实（如 mcp tools 清单、rag_kb_map）

class ComponentEdge(BaseModel):
    src: str                            # 上游组件 key
    dst: str                            # 下游组件 key
    relation: Literal["calls", "retrieves_from", "delegates_to",
                      "persists_to", "gated_by", "observes"]
    confidence: float
    evidence_refs: list[str] = []

class ComponentGraph(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    nodes: list[ComponentNode]
    edges: list[ComponentEdge]
    entry_points: list[str]             # 可从外部直接触达的节点

    def neighbors(self, key: str, *, relation: str | None = None) -> list[str]: ...
    def shortest_path(self, src: str, dst: str) -> list[str] | None: ...
    def reachable(self, src: str) -> set[str]: ...
```

> **复用既有资产**：`recon/a2a/topology.py:105 TopologyGraph`、`:151 TopologyAnalyzer`、`recon/a2a/discoverer.py:106 AgentTopologyNode`、`recon/a2a/topology_mapper.py:89 A2ATopologyMapper` 已是该模型的 A2A 特化版本。**任务是将其泛化到全部组件，而非重写。**

#### 2.2.2 `StatefulAttackChain`：有状态攻击链

单组件、单轮、无状态攻击无法还原企业场景。引入**跨阶段、跨组件携带状态**的攻击链：

```python
# core/contracts/attack_chain.py
class ChainState(BaseModel):
    """攻击链在任意时刻的完整状态，可序列化 → 支持 checkpoint / resume。"""
    schema_version: Literal["1.0"] = "1.0"
    chain_id: UUID
    step_index: int
    acquired: dict[str, Any] = {}       # 已获取的能力/凭据/知识（跨步骤传递）
    visited_components: list[str] = []
    failed_steps: list[FailedStep] = []

class AttackStep(BaseModel):
    id: str
    component_key: str                  # 本步骤作用的组件
    action: str                         # 对应 strike 模块 id
    depends_on: list[str] = []          # 前置步骤（形成 DAG）
    produces: list[str] = []            # 产出物，写入 ChainState.acquired
    budget_cost: int = 1                # 供 BudgetController 计费

class StatefulAttackChain(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    steps: list[AttackStep]
    state: ChainState
    # 关键：steps 为 DAG 而非线性表，允许条件分支与回退
```

> **复用既有资产**：
> - `strike/common/escalation_runtime.py:294 run_escalation_chain` —— 线性升级链雏形（当前因 `strike.py:711` 路径失效而不可达）
> - `strike/injection/indirect_pi.py:319 generate_recursive_attack_chain(chain_depth=3)`
> - `strike/injection/file_upload_executor.py:341 execute_file_upload_attack_chain`
> - `strike/web/link_evasion.py:265 generate_gradual_injection_chain`
> - `strike/evasion/sql.py:243 generate_gradual_escalation_chain`
> - `strike/session/session_manager.py:36 SessionStateManager`、`recon/target_builder.py:57 ChatIdStateManager`、`recon/api/auth_detector.py:39 AuthState` —— 各类状态持有者，需统一到 `ChainState`
>
> **任务是把这些已有散点收敛到统一契约，并接入主链路。**

#### 2.2.3 `ImpactChain`：影响链举证

红队报告的价值不在「某个 prompt 生效了」，而在**证明一条从入口到业务影响的因果链**。引入：

```python
# core/contracts/impact_chain.py
class ImpactLink(BaseModel):
    from_step: str                      # AttackStep.id
    to_step: str
    mechanism: str                      # 因果机制说明（人类可读）
    evidence_ids: list[str]             # 关联的 EVD-* 证据编号

class ImpactNode(BaseModel):
    step_id: str
    component_key: str
    outcome: str                        # 该步骤达成的技术结果
    business_impact: str                # 映射到的业务影响
    severity: Literal["critical", "high", "medium", "low"]
    owasp: list[str] = []
    cvss_vector: str | None = None

class ImpactChain(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    nodes: list[ImpactNode]
    links: list[ImpactLink]
    terminal_impact: str                # 最终业务影响陈述

    def validate_causality(self) -> list[CausalityGap]:
        """每个 ImpactNode 必须有 ≥1 条入边（entry 除外）且能追溯到 EVD 证据。
           这是「举证」而非「断言」的关键约束。"""
```

> **复用既有资产**：`recon/a2a/trust_analyzer.py:53 TrustChainSegment`、`:182 _discover_chains`、`:200 _dfs_chains`、`recon/trust_chain_probe.py:60 TrustChainResult`、`:281 run_trust_chain_probe`、`recon/trust_level_enum.py:225 TrustEscalationPath`、`recon/a2a/attack_planner.py:115 AttackPathPlanner`。
> **这些正是影响链的 DFS 搜索实现，且全部零生产调用。**

### 2.3 「确保 100% 侦察成功率」的工程口径

**必须诚实声明**：黑盒条件下不存在字面意义的 100% 组件识别率。本方案以**「不静默失败」**为等价目标，通过五层保障达成，并把识别率做成可测指标：

| 层 | 机制 |
|---|---|
| 1. 多信号融合 | 路径指纹 + 响应体特征 + 主动探针（`/tools/list`、AgentCard、citation markers）+ 已知 SaaS 特征库，加权投票输出**置信度而非二值** |
| 2. 显式指定兜底 | `--strike mcp` / `--components mcp,rag` 直接锁定，跳过推断 |
| 3. 组合体推断 | 单组件不确定时，用已确认组件推断邻居（如确认 MCP → 必有上游 `llm_gateway`） |
| 4. 低置信降级 | 置信度 < `min_confidence` → 降级通用 LLM 扫描，**降级原因写入 `orchestration_log`** |
| 5. 强制可观测 | 分类不确定时**必须 `logger.warning`**，禁止当前 `except Exception: logger.debug` 的静默模式（全仓 20+ 处） |

**验收指标**：在 golden set 上组件识别准确率 ≥ 90%、**静默失败率 = 0%**（未识别必须留痕）。

---

## 第三章 目标架构

### 3.1 全景

```
目标 URL / burp.txt
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ ① 通用侦察      recon/fingerprint.py, capability_probe.py        │
│    → HTTPTarget + target_fingerprint + capabilities              │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ ② ComponentClassifier   多信号融合 + 置信度                      │
│    --strike/--components override ──► 直接锁定                   │
│    → list[ComponentNode]（可能多个！多组件组合体）                │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ ③ 组件专项侦察  recon/<component>/*（按 ComponentRegistry）      │
│    → ctx.service_profile[mcpsec_surface / a2a_topology /         │
│                          rag_kb_map / session_state / ...]       │
│    → ComponentGraph（含 nodes + edges + entry_points）           │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ ④ AttackPathPlanner  基于 ComponentGraph 规划 StatefulAttackChain│
│    （DAG 步骤，跨组件携带 ChainState.acquired）                   │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ ⑤ ARM 按组件选型                                                 │
│    seeds（suitable_for 匹配组件键，C-NAME-2）                    │
│    + converters（attack_vector → 链，1 converter = 1 路径，C2）  │
│    + strike 策略（preferred_attack_class 对齐宪法 7B）           │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ ⑥ PyRIT 原生执行   await attack.execute_async()                  │
│    ├─ 实时：output_attack_async + StdoutSink → 终端（R-NATIVE-6）│
│    └─ 有状态：ChainState 在步骤间传递（checkpoint 可续跑）       │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ ⑦ post-hoc ASSESS   component_router.run_component_t0            │
│    → t0_<component>_check + J1/J2 双 Judge + OR/AND 校准         │
│    → VerdictRecord（schema_version + content_hash，幂等）        │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ ⑧ 组件专属报告 + ImpactChain 举证                                │
│    report/component_reports.py + component_poc.py               │
│    → 每个命中组件一节 + 影响链因果图 + EVD-* 证据集              │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 落到既有六阶段骨架

| 阶段 | 入口 | 本方案新增职责 |
|---|---|---|
| RECON | `core/phases/recon.py:52` | 通用侦察 + 组件识别 + **ComponentGraph 构建** + 组件专项侦察 |
| ARM | `core/phases/arm.py:170` | 按每个命中组件选 seeds / converters；**修复 `_get_arm_target_type` 恒 unknown** |
| STRIKE | `core/phases/strike.py:20` | 按 `preferred_attack_class` 选策略 + **StatefulAttackChain 执行** + 原生终端输出 |
| ESCALATE | `core/phases/strike.py:683` | **补调用点**（`core/phases/executor.py:81-141`）；C2 要求 ASR<90% 必触发 |
| ASSESS | `core/phases/assess.py:20` | 组件 T0 + J1/J2；`ImpactNode` 证据回填 |
| REPORT | `core/phases/report.py:20` | 组件专属报告 + **ImpactChain 章节** + 证据打包 |

---

## 第四章 关键设计

### 4.1 `ComponentRegistry`：运行时 SSOT

**数据源升级自** `tools/architecture_validator.py:79-114` 的静态表 → `config/components/*.yaml`（每组件一文件），一处定义、两处使用（运行时调度 + 静态校验），治愈 C3 + IA-3 + 7B 未消费。

```python
# core/component_registry.py
class ComponentSpec(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    component_key: str                    # C-NAME-1：与 strike/<dir>/ 语义一致
    display_name: str
    recon_dir: str                        # recon/<dir>/
    strike_dir: str                       # strike/<dir>/
    detection: DetectionSpec              # 信号 + min_confidence
    recon_modules: list[str] = []
    service_profile_keys: list[str] = []  # 专项侦察写入 ctx.service_profile 的键
    seed_sets: list[str] = []
    seed_suitable_for: list[str] = []     # C-NAME-2
    converter_vectors: list[str] = []
    preferred_attack_class: str           # 宪法 7B
    asr_prior: float
    strike_modules: list[str] = []
    assess: AssessSpec | None = None      # t0_check + rubric
    report_builder: str | None = None
    poc_template: str | None = None
    owasp: list[str] = []
    neighbors: list[str] = []             # 组合体推断：常见共存组件

class ComponentRegistry:
    def load_from_config(self, config_dir: Path) -> None: ...
    def resolve(self, key: str) -> ComponentSpec | None: ...   # unknown → None（IA-6）
    def iter_all(self) -> Iterator[ComponentSpec]: ...
    def keys(self) -> list[str]: ...
    def validate_wiring(self) -> list[WiringError]: ...        # 反向供 architecture_validator 使用
```

### 4.2 `ComponentClassifier`：多信号融合识别

```python
# core/component_classifier.py
class ClassificationResult(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    nodes: list[ComponentNode]            # 可能多个（组合体）
    degraded: bool
    reason: str                           # 必须人类可读，禁止空

def classify(parsed_request, *, override: list[str] | None = None) -> ClassificationResult:
    """override 来自 --strike/--components；无 override 时多信号加权投票。
    低置信 → degraded=True 且强制 logger.warning（禁止 debug 静默）。"""
```

### 4.3 `config/components/*.yaml`（每组件一文件）

对齐 `80-COMPONENT-ARCHITECTURE-RULES.md` §6 Checklist 七要素：

```yaml
# config/components/mcp.yaml
schema_version: "1.0"
component_key: mcp_tool_poisoning
display_name: "MCP Server / Tool Layer"
recon_dir: "mcp"
strike_dir: "mcp"

detection:
  path_patterns: ["/mcp", "/tools/list", "/tools/call", "/sse"]
  body_markers: ["jsonrpc", "tools/list", "tool_call", "mcpServers"]
  active_probes: ["recon.mcp.schema_extractor"]
  min_confidence: 0.60

recon_modules:
  - recon.mcp.endpoint_enumerator
  - recon.mcp.schema_extractor
  - recon.mcp.surface_scanner
  - recon.mcp.tool_inventory
service_profile_keys: ["mcpsec_surface", "mcp_tool_inventory"]

seed_sets:
  - "data/seeds/mcp/"
  - "data/seeds/_attack_surface/T1_ASI02_mcp_full_surface/"
seed_suitable_for: ["mcp_tool_poisoning"]
converter_vectors: ["mcp_tool_registration", "mcp_message_injection", "mcp_schema_poisoning"]

preferred_attack_class: "PromptSendingAttack + MCPSec 动态种子"   # 宪法 7B
asr_prior: 0.90

strike_modules:
  - strike.mcp.orchestrator
  - strike.mcp.malicious_server
  - strike.mcp.schema_manipulator
  - strike.mcp.dynamic_seeds
  - strike.mcp.rag_attack

assess:
  t0_check: "assess.component_scorers:t0_mcp_tool_poisoning_check"
  rubric: "data/scorers/component_scorers/mcp.yaml"

report_builder: "report.component_reports:_build_mcp_tool_poisoning_sections"
poc_template: "report.component_poc:mcp_poc"
owasp: ["ASI02", "ASI05"]
neighbors: ["llm_gateway", "web_api", "a2a_agent_integrity"]
```

**需补齐的组件配置文件**：`mcp.yaml`、`a2a.yaml`、`rag.yaml`、`model.yaml`（→ `llm_gateway` + `model_behavior_shift`）、`session_memory.yaml`、`web_api.yaml`、**`embedding.yaml`（新增）**、**`audit_evasion.yaml`（新增）**、**`supply_chain.yaml`（新增）**。

### 4.4 `BudgetController`：接线后的必需安全阀

51 个模块全量接入会导致攻击规模爆炸。**必须与接线同批落地**，三维度控制：

```python
# strike/budget.py
class BudgetController:
    max_total_attacks: int                # 数量
    per_component_quota: dict[str, int]   # 每组件配额
    per_chain_step_cost: dict[str, int]   # 攻击链每步开销
    wall_clock_deadline: timedelta        # 时间
    token_budget: int                     # 成本（含 judge）

    def consume(self, component_key: str, cost: int = 1) -> bool: ...
    def remaining(self) -> BudgetSnapshot: ...
    # 任一超限 → 按 ComponentSpec.asr_prior 降序裁剪
    # 裁剪原因必须写入 EvidenceCollector 与 orchestration_log
```

### 4.5 PyRIT 原生终端输出（R-NATIVE-6 合规）

**现状**：`utils/display.py:417 print_native_attack_result`、`:440 print_native_scenario_result` 已封装正确，但**零调用点**。

**接通后的实时输出应覆盖攻击者关心的信号**：

| 信号 | 来源 |
|---|---|
| 每条 converter 路径的实时成败 | `SequentialAttack` 各路径结果 |
| 每次 multi-turn 迭代（Crescendo/TAP/PAIR） | `execute_async()` 中间结果 |
| 每步 `AttackStep` 的 `acquired` 产出 | `StatefulAttackChain.state` |
| Judge 逐条裁决（J1/J2/最终） | post-hoc ASSESS |
| token / 成本累计 | `TokenLedger` |

**宪法约束**：`output_attack_async` 等为 Output 类自研范畴内的合规项（C1 允许 Output 类），且不得自研渲染层替代。

### 4.6 契约层（Pydantic v2）

```
core/contracts/
├── component.py        ComponentSpec / DetectionSpec / AssessSpec
├── component_graph.py  ComponentNode / ComponentEdge / ComponentGraph
├── attack_chain.py     ChainState / AttackStep / StatefulAttackChain
├── impact_chain.py     ImpactNode / ImpactLink / ImpactChain
├── evidence.py         EvidenceRecord（**补 metadata 字段** → 修 CB-2）
├── verdict.py          JudgeVerdict / VerdictRecord（schema_version + content_hash）
└── manifest.py         ScoreRunManifest（seed / judge 模型 / rubric 哈希 / temperature）
```

---

## 第五章 现有资产复用清单（接线而非重写）

| 能力 | 既有实现（坐标） | 现状 | 本方案动作 |
|---|---|---|---|
| 组件拓扑图 | `recon/a2a/topology.py:105 TopologyGraph`、`:151 TopologyAnalyzer` | 零调用 | 泛化为 `ComponentGraph` |
| 拓扑映射 | `recon/a2a/topology_mapper.py:89 A2ATopologyMapper` | 零调用 | 接线到 RECON ③ |
| Agent 节点 | `recon/a2a/discoverer.py:106 AgentTopologyNode` | 零调用 | 复用为 `ComponentNode` 来源 |
| 攻击路径规划 | `recon/a2a/attack_planner.py:115 AttackPathPlanner` | 零调用 | **提升为 `StatefulAttackChain` 规划器** |
| 信任链 DFS | `recon/a2a/trust_analyzer.py:53/182/200 TrustChainSegment/_discover_chains/_dfs_chains` | 零调用 | **提升为 `ImpactChain` 搜索引擎** |
| 信任链探测 | `recon/trust_chain_probe.py:60/281 TrustChainResult/run_trust_chain_probe` | 零调用 | 接线到组件专项侦察 |
| 升级路径 | `recon/trust_level_enum.py:225 TrustEscalationPath` | 零调用 | 复用为 `ImpactChain` 边语义 |
| 线性升级链 | `strike/common/escalation_runtime.py:294 run_escalation_chain` | `strike.py:711` 路径失效 | 修路径 + 补调用点 + 泛化为 DAG |
| 递归攻击链 | `strike/injection/indirect_pi.py:319 generate_recursive_attack_chain` | 零调用 | 适配为 `AttackStep` |
| 文件上传攻击链 | `strike/injection/file_upload_executor.py:341` | 零调用 | 接线（`strike.py:660` 路径需修） |
| 渐进注入链 | `strike/web/link_evasion.py:265` | 零调用 | 接线 |
| 渐进升级链 | `strike/evasion/sql.py:243` | 零调用 | 接线 |
| 会话状态 | `strike/session/session_manager.py:36 SessionStateManager` | 零调用 | 归入 `ChainState` |
| Chat 会话态 | `recon/target_builder.py:57 ChatIdStateManager` | 可达 | 归入 `ChainState` |
| 认证状态 | `recon/api/auth_detector.py:39 AuthState` | 可达 | 归入 `ChainState` |
| 知识库/趋势 | `strike/common/attack_knowledge_base.py`、`asr_trend_tracker.py` | 零调用 | 用于 ASR 先验与链排序 |
| 原生终端输出 | `utils/display.py:417/440` | 零调用 | **接通**（R-NATIVE-6） |
| 四层映射表 | `tools/architecture_validator.py:79-114` | 仅静态检查 | **提升为运行时 SSOT** |

---

## 第六章 分 Wave 实施计划

> 执行顺序遵循：**先文档 → 再止血 → 后接线**。每 Wave 独立可验收。

### Wave 0 — 文档与止血（预计 3–4 周）

**目标**：让默认命令端到端跑通，故障不再静默。

| # | 动作 | 坐标 |
|---|---|---|
| 0.1 | 撰写本方案文档 | `docs/plan.md` |
| 0.2 | 修 `rag_profile` 未绑定导致的 `NameError`；`rag_profile = None` 预初始化 | `core/phases/recon.py:85-107` |
| 0.3 | 修 4 条 recon 陈旧 import（`recon.rag_pipeline_probe`→`recon.rag.pipeline_probe`、`recon.rag_typo_fuzzer`→`recon.rag.typo_fuzzer`、`recon.multi_agent_topology`→`recon.a2a.topology`、`recon.a2a_defense_awareness`→`recon.a2a.defense_awareness`、`tools.mcpsec_factory`） | `core/phases/recon.py:87/132/252/266/338` |
| 0.4 | 修 8 条失效 import | `main.py:263`、`core/phases/strike.py:79/95/236/397/660/711`、`core/phases/arm.py:48` |
| 0.5 | 修 `_resolve_burp_list` 缺 return | `core/phases/_helpers.py:14-23` |
| 0.6 | 修 `_get_arm_target_type` 恒 unknown（直接阻塞组件感知 converter 选择） | `core/phases/_helpers.py:183-195` |
| 0.7 | 修 T0 FPR/FNR 告警死代码 | `core/phases/_helpers.py:380-432` |
| 0.8 | 修 `_getData_core` **`architecture_validator.py:83 session_memory` 空 recon 清单** | 绑定 `recon/session/*` |
| 0.9 | 修打包入口 `main:main` → 真实函数；删 `main.py:127` 不存在的 watcher | `pyproject.toml:25`、`main.py:127` |
| 0.10 | **AST 导入连通性测试**（关键防复发手段） | `tests/unit/test_import_graph.py` [NEW] |
| 0.11 | 反静默：20+ 处 `except Exception: logger.debug` → `logger.warning` + 计数器 | 全仓 |
| 0.12 | 修 `_best_of_n_retry` 调用签名 | `strike/common/executor.py:580` |
| 0.13 | 修 `_STRATEGIES_YAML_PATH` 路径 | `strike/common/progressive_strike.py:44` |
| 0.14 | 清理失效白名单 | `tools/guard.py:79`、`guard_extended.py:1760`、`pyproject.toml:47-56` |
| 0.15 | mojibake 修复 + UTF-8 CI 检查 | 全仓受影响文件 |

**验收 DoD（勾选式）**
- [ ] `python main.py --burp config/burp/mocka.txt --offensive` 跑完 6 阶段且退出码 0 且**真正产出 report**
- [ ] `python main.py --target mcp`、`--strike mcp` 不再崩
- [ ] `tests/unit/test_import_graph.py` 全绿（0 个断链）
- [ ] 全仓 `except Exception: pass` = 0；`logger.debug` 吞异常处均有计数器
- [ ] 所有 `.py` 为 UTF-8 且无孤立 `\uXXXX` 字面串
- [ ] C10 五步门禁本地全通过

### Wave 1 — ComponentRegistry 与组件识别（预计 3 周）

**目标**：把静态四层映射表提升为运行时 SSOT，实现多信号组件识别。

| # | 动作 | 坐标 |
|---|---|---|
| 1.1 | 新建契约层 | `core/contracts/` [NEW] |
| 1.2 | 新建 `ComponentRegistry` + `ComponentSpec` | `core/component_registry.py` [NEW] |
| 1.3 | 由 `tools/architecture_validator.py:79-114` 迁移生成 6 个组件 YAML | `config/components/*.yaml` [NEW] |
| 1.4 | **补齐 4 个缺失组件**：`embedding`、`llm_gateway`、`audit_evasion`、`supply_chain` | 同上 |
| 1.5 | 新建 `ComponentClassifier` 多信号融合 + 置信度 | `core/component_classifier.py` [NEW] |
| 1.6 | 新增 `--components mcp,rag` CLI 参数并走 C7 配置链路 | `core/config.py`、`config/defaults.yaml` |
| 1.7 | RECON 阶段插入「识别 → ComponentGraph → 组件专项侦察」 | `core/phases/recon.py` |
| 1.8 | 合并 `recon/api/` 与 `recon/web/` 双轨（C3） | `recon/` |
| 1.9 | `architecture_validator` 改为从 Registry 反向校验（一处定义两处用） | `tools/architecture_validator.py` |
| 1.10 | 分类结果（信号/权重/置信度）落盘 evidence | `core/phases/recon.py` |

**验收 DoD**
- [ ] `ComponentRegistry.keys()` 返回 ≥10 个组件键，含 `embedding`/`llm_gateway`/`audit_evasion`/`supply_chain`
- [ ] 单组件类型的 mock target 识别准确率 ≥ 90%
- [ ] **静默失败率 = 0%**（未识别必须 `logger.warning` 且入 `orchestration_log`）
- [ ] 未知组件类型返回 `None` 不崩溃（IA-6）
- [ ] 组件键映射的代码持有者 = 1（治愈 IA-3）
- [ ] `architecture_validator full` 从 Registry 反向校验通过

### Wave 2 — 组件垂直切片接线（预计 5–6 周，用户第一优先）

**目标**：每个组件都有 seeds / converters / strike / assess 全套，且真正执行。

| # | 动作 | 坐标 |
|---|---|---|
| 2.1 | ARM 按组件选 seeds（`suitable_for` 匹配，`_attack_surface` 目录纳入加载白名单） | `core/seed_loader.py:160/211`、`arm/seed_ranker.py` |
| 2.2 | ARM 按组件选 converters（依赖 0.6 已修的 `target_type`） | `arm/converter_presets.py`、`core/seed_router.py` |
| 2.3 | STRIKE 按 `preferred_attack_class` 选策略（对齐宪法 7B） | `strike/common/dispatcher.py`、`progressive_strike.py` |
| 2.4 | 实现 technique → executor 真实路由（当前 12 个技术名仅为标签） | `strike/common/executor.py` |
| 2.5 | ESCALATE 补调用点（C2 要求） | `core/phases/executor.py:81-141` |
| 2.6 | 统一 PyRIT 命名空间为 `pyrit.executor.attack.*`，废弃 `pyrit.attacks.*` | `strike/common/dispatcher.py:53-62` |
| 2.7 | 接线 51 个零调用点模块（**按组件分批**，每批单独 e2e） | 各 `strike/<component>/` |
| 2.8 | 同批落地 `BudgetController` | `strike/budget.py` [NEW] |
| 2.9 | 安全边界：`authorized_targets` 提升为一等字段并启动期强制校验 | `strike/common/decision_safety.py:49/57`、`core/context.py` |
| 2.10 | `http_engine.py` 改为委托原生 `HTTPTarget`（C1/C13 合规） | `strike/web/http_engine.py` |

**验收 DoD**
- [ ] 每种组件均有 ≥1 条可执行攻击路径，端到端产出 `ctx.attack_results[technique]`
- [ ] `preferred_attack_class` 实际决定使用的 PyRIT 攻击类
- [ ] `--components mcp` 时确实加载 `data/seeds/mcp/` 与 `_attack_surface/T1_ASI02_mcp_full_surface/`
- [ ] ASR < 90% 时升级链真触发（C2 合规）
- [ ] 预算超限时按 `asr_prior` 裁剪，且**裁剪原因出现在报告中**
- [ ] 未授权目标被启动期拒绝（而非静默放行）
- [ ] 单组件 e2e 覆盖 ≥10 种组件

### Wave 3 — 有状态攻击链与影响链（预计 4 周，本轮核心增量）

**目标**：支持多组件组合体上的跨组件、有状态、可举证攻击。

| # | 动作 | 坐标 |
|---|---|---|
| 3.1 | `ComponentGraph` 泛化（复用 `recon/a2a/topology.py:105 TopologyGraph`） | `core/contracts/component_graph.py` [NEW] |
| 3.2 | `AttackPathPlanner` 提升为跨组件链规划器（复用 `recon/a2a/attack_planner.py:115`） | `strike/chain_planner.py` [NEW] |
| 3.3 | `StatefulAttackChain` + `ChainState`（DAG 步骤 + 跨步 `acquired` 传递） | `core/contracts/attack_chain.py` [NEW] |
| 3.4 | 链级状态机 + checkpoint/resume（支持 `--resume` 真语义） | `core/state_machine.py` [NEW] |
| 3.5 | 收敛 `SessionStateManager`/`ChatIdStateManager`/`AuthState` 到 `ChainState`（C3） | 各/src.py |
| 3.6 | `ImpactChain` 引擎（复用 `recon/a2a/trust_analyzer.py:182/200 _discover_chains/_dfs_chains`） | `report/impact_chain.py` [NEW] |
| 3.7 | `AttackKnowledgeBase` / `asr_trend_tracker` 接线，用于链步骤排序与 ASR 先验 | `strike/common/` |
| 3.8 | 多组件组合体场景的 mock target 与 e2e | `tests/mocks/`、`tests/e2e/` |

**验收 DoD**
- [ ] 构造 MCP+RAG+Session 三组件组合体 mock target，链攻击端到端跑通
- [ ] 链中步骤 B 能消费步骤 A 的 `acquired` 产出
- [ ] 中断后 `--resume` 从最后一个完成步骤继续，结果一致
- [ ] `ImpactChain.validate_causality()` 对每条链返回 0 个 `CausalityGap`
- [ ] 每个 `ImpactNode` 可追溯到 ≥1 个 `EVD-*` 证据
- [ ] 报告中输出可读的影响链因果图

### Wave 4 — PyRIT 原生输出与算法收敛（预计 2–3 周）

| # | 动作 | 坐标 |
|---|---|---|
| 4.1 | **接通** `print_native_attack_result` / `print_native_scenario_result`（R-NATIVE-6 合规） | `utils/display.py:417/440` + 调用点 |
| 4.2 | 实时输出：converter 路径成败 / multi-turn 迭代 / 链步骤产出 / Judge 裁决 / token 累计 | 同上 |
| 4.3 | TAP 4→1、PAIR 2→1、Crescendo 3→1，参数外置 `strike/strategies/params.yaml` | `strike/strategies/` [NEW] |
| 4.4 | `_is_success` 3→1（统一 `score_val > 0`） | `utils/attack_utils.py:33` 为 SSOT |
| 4.5 | 旧实现标记弃用装饰器，保留一个 release 周期 | `progressive_strike.py` 等 |
| 4.6 | `CancellationToken` 替代 `os._exit(130)` 强杀 | `core/cancellation.py` [NEW]、`logging_config.py:113` |

**验收 DoD**
- [ ] 攻击过程中终端出现 PyRIT 原生格式输出（非自研 ANSI 拼装）
- [ ] 每个算法类仅剩 1 套实现（grep 验证）
- [ ] 所有算法参数可从 YAML 读取（C7 合规）
- [ ] 二次 SIGINT 仍能执行完整 `finally` 清理

### Wave 5 — 评分可信性（预计 3 周）

| # | 动作 | 坐标 |
|---|---|---|
| 5.1 | 拆 `_HIGH_CONFIDENCE_PATTERNS` 为中性置信 + 独立拒绝表 | `assess/judge_manager.py:59-77` |
| 5.2 | 早返路径不再伪造 `judge2_successes`/`agreements` | `assess/score_pipeline.py:304-315` |
| 5.3 | `asyncio.gather` 使用已创建的信号量（修无界并发） | `assess/score_pipeline.py:237/364` |
| 5.4 | 自适应阈值真实生效；切断 ASR→阈值→ASR 自反馈 | `score_pipeline.py:249`、`judge_manager.py:787-818` |
| 5.5 | 统一成功口径为 `_get_outcome`；删「有 converted_value 即 success」兜底 | `assess/asr_stats.py:211`、`core/phases/executor.py:145-157` |
| 5.6 | `VerdictRecord` 持久化（schema_version + content_hash 幂等） | `assess/persistence.py` [NEW] |
| 5.7 | `ScoreRunManifest`：消费 `defaults.yaml:82 adaptive_random_seed`（当前无人读取） | `core/contracts/manifest.py` |
| 5.8 | C7 合规：所有阈值外置到 `config/defaults.yaml` | `_or_and_calibration.py:20/21/73` 等 |
| 5.9 | 统计量增强：逐组件 Wilson CI + bootstrap + 组间差异检验 + 小样本告警 | `assess/asr_manager.py` |
| 5.10 | 复用 golden set 替代自研正则词表打分（部分场景） | `judge_manager.py:260-425` |

**验收 DoD**
- [ ] 同一输入 + 同 seed，连续 3 次 ASR 差异 ≤ ±2%
- [ ] 含 "I cannot…" 的拒绝 rationale 不再被判成功
- [ ] κ 与一致率统计口径唯一，无重复计算
- [ ] golden set 上 Judge FPR ≤ 5%、FNR ≤ 10%、κ ≥ 0.8
- [ ] 报告含 `ScoreRunManifest` 全字段（seed / judge 模型 / rubric 哈希 / temperature）

### Wave 6 — 组件专属报告与交付加固（预计 3 周）

| # | 动作 | 坐标 |
|---|---|---|
| 6.1 | **修 CB-2 断裂**：补 `EvidenceRecord.metadata`（含 `component_type`）并由 `_component_bridge` 写入 | `core/contracts/evidence.py`、`report/evidence.py`、`core/phases/_component_bridge.py` |
| 6.2 | 组件专属报告真正生成 | `report/component_reports.py:96/109/167` |
| 6.3 | 组件 PoC 真正生效（`_single_evidence_to_dict` 补 metadata 键） | `report/component_poc.py:567`、`generator.py:353-354` |
| 6.4 | 三份核心 Markdown 移出 `except` 分支 | `report/generator.py:270-287` |
| 6.5 | `report.md` 纳入格式开关 | `report/generator.py:253-254` |
| 6.6 | 修 `evidence_id` 跨技术重复导致 EVD 文件互相覆盖 | `report/evidence.py:565` |
| 6.7 | HTML Jinja2 模板化 + 强制 `html.escape` | `report/report_html.py:70/80/124-127` |
| 6.8 | 影响链章节 + 组件覆盖矩阵进报告 | `report/report_markdown.py`、`report_sections.py` |
| 6.9 | token/cost 账本 + Prometheus + OpenTelemetry 六阶段 span | `core/observability/` [NEW] |
| 6.10 | `config_service.py` 单一配置入口（schema + version + extends + `__file__` 相对路径） | `core/config_service.py` [NEW] |
| 6.11 | `uv.lock`、`SECURITY.md`、`CONTRIBUTING.md`、`CHANGELOG.md`、Dockerfile | 仓库根 |
| 6.12 | C10 五步门禁落 CI + 覆盖率门禁 + golden 门禁 | `.github/workflows/ci.yml` [NEW] |
| 6.13 | i18n / 可访问性（表格 caption/scope、热力图加文字符号） | `report/` |

**验收 DoD**
- [ ] MCP 目标产出 MCP 专属章节 + PoC + 专属证据集
- [ ] 同一，`a2a` / `rag` / `session_memory` / `web_api` / `embedding` 各自成立
- [ ] 重跑不重复追加、不覆盖 EVD 文件
- [ ] HTML 无未转义插值（重试 XSS payload 验证）
- [ ] `docs/specs/80` 第八章组件登记表与 `ComponentRegistry` 一致
- [ ] CI 全绿，覆盖率 ≥ 60%（`core/`+`assess/` ≥ 90%）

---

## 第七章 量化验收门禁

| 指标 | 当前 | Wave 0 | Wave 1 | Wave 2 | Wave 3 | Wave 5 | Wave 6 |
|---|---|---|---|---|---|---|---|
| 默认命令端到端可跑 | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 导入连通性断链数 | 8+ | 0 | 0 | 0 | 0 | 0 | 0 |
| 组件键数量 | 6 | 6 | **≥10** | ≥10 | ≥10 | ≥10 | ≥10 |
| 组件识别准确率（golden set） | ~0% | — | **≥90%** | ≥90% | ≥95% | ≥95% | ≥95% |
| **静默失败率** | 高 | **0%** | 0% | 0% | 0% | 0% | 0% |
| strike 模块可达率 | 23.9% | 23.9% | 23.9% | **≥90%** | ≥90% | ≥90% | ≥90% |
| 主链路攻击算法数 | 2 | 2 | 2 | **≥6** | ≥6 | ≥6 | ≥6 |
| 多组件组合体链攻击 | ❌ | ❌ | ❌ | 单组件 | **✅** | ✅ | ✅ |
| 影响链举证 | ❌ | ❌ | ❌ | ❌ | **✅** | ✅ | ✅ |
| 终端 PyRIT 原生输出 | ❌ | ❌ | ❌ | ❌ | ❌ | **✅**（Wave 4） | ✅ |
| ASR 重跑一致性 | 不可复现 | — | — | — | — | **≤±2%** | ≤±2% |
| Judge FPR / FNR / κ | 未测 | — | — | — | — | **≤5% / ≤10% / ≥0.8** | 同 |
| 组件专属报告可用 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| CI 自动化五步门禁 | ❌ | 本地 | 本地 | 本地 | 本地 | 本地 | **✅** |
| 行覆盖率 | 未度量 | — | — | ≥40% | ≥50% | ≥55% | **≥60%（core/assess ≥90%）** |

---

## 第八章 风险与回滚

| 风险 | 影响 | 缓解 |
|---|---|---|
| 51 个模块全量接线导致攻击规模爆炸 | 成本失控、被目标封禁 | `BudgetController` 与接线**同批落地**（Wave 2），不得延后 |
| 未验证模块接线后产生未知故障 | 稳定性下降 | 按组件分批接线，每批单独 e2e；保留 `enabled_by: opt_in` 分级 |
| 安全边界在扩展后失效 | 越界攻击未授权目标 | Wave 2.9 把 `authorized_targets` 提升为一等字段，启动期强校验 |
| 有状态链引入不可预期的跨组件副作用 | 状态污染 | `ChainState` 不可变小步推进 + 每步快照 checkpoint；支持步骤级回滚 |
| `_is_success` 语义统一改变历史基线 | 历史 ASR 不可比 | `CHANGELOG.md` 标注基线重算说明；保留旧口径一个 release |
| 删除重复算法实现遗漏隐式引用 | ImportError | Wave 4 用 `lsp-code-analysis` 做引用闭包确认（含 `__getattr__` 惰性分发与 re-export） |
| 破坏性变更不可回滚 | 无法回退 | 旧实现先加弃用装饰器保留一个 release 周期再删 |

---

## 第九章 待裁决项（C11 停止权）

以下事项需人工/跨模型裁决后方可继续，不得自行猜测：

1. **`recon/api/` 与 `recon/web/` 双轨合并**（Wave 1.8）：合并到哪个目录名？影响案例与文档引用。
2. **新增组件的范围**：`embedding` / `llm_gateway` / `audit_evasion` / `supply_chain` 四个新增键，是否本期全做？还是先做 `embedding` + `llm_gateway`？
3. **攻击执行路径的评分别界**（C2 释义）：`core/phases/strike.py:163` 的 `precompute_outcomes_async(score_all=True)` 是否违反「攻击执行路径只准 0-token 评分器」？需确认 pre-hoc 与 post-hoc 的准确分界。
4. **`asr_priors.yaml` 运行时回写**（`arm/seed_ranking.py:614`）：受版本控制的配置文件被运行时改写，是否改为 outputs 分区 + 显式 promote？
5. **C14 交叉确认**：本方案涉及架构与规约层变更，需 ≥2 独立模型审查、κ ≥ 0.8 方可合入 `docs/specs/`。

---

## 附录 A：缺陷坐标总表

### A.1 主链路阻断（Wave 0）

| 坐标 | 缺陷 |
|---|---|
| `core/phases/recon.py:85-107` | `rag_profile` 未绑定 → `NameError`；`--rag-probe` 参数不存在 |
| `core/phases/recon.py:87/132/252/266/338` | 5 条失效 import |
| `core/phases/_helpers.py:14-23` | `_resolve_burp_list` 正常路径缺 return → 返 None |
| `core/phases/_helpers.py:183-195` | `_get_arm_target_type` 恒返 `"unknown"`，后续全为死代码 |
| `core/phases/_helpers.py:380-432` | T0 FPR/FNR 告警整段不可达 |
| `main.py:263` | `from strike.dispatcher` 路径失效且无 try/except → `--target/--strike` 必崩 |
| `core/phases/strike.py:79/95/236/397/660/711` | 6 条失效 import |
| `core/phases/arm.py:48` | `from strike.dynamic_mcp_seeds` 路径失效且无 try/except |
| `core/phases/strike.py:683` | `_run_escalate_phase` 零调用点（C2 违例） |
| `recon/orchestrator.py:283/339/372/429` | 6 条调度分支引用不存在的函数名 |
| `pyproject.toml:25` | `main:main` 入口不存在 |
| `main.py:127` | 拉起不存在的 `tools.watch_guard` |
| `strike/common/executor.py:580` | `_best_of_n_retry` 传 list 当 callable → 恒空转 |
| `strike/common/progressive_strike.py:44` | `_STRATEGIES_YAML_PATH` 路径错误 → YAML 为死配置 |

### A.2 评分正确性（Wave 5）

| 坐标 | 缺陷 |
|---|---|
| `assess/score_pipeline.py:304-315` | 高置信早返用含拒绝词的表 + 伪造 `judge2_successes`/`agreements` |
| `assess/judge_manager.py:75` | `_HIGH_CONFIDENCE_PATTERNS` 含 `cannot/won't/unable to` |
| `assess/score_pipeline.py:237 vs 364` | 信号量建了不用 → 无界并发 → 429 → 静默判 failure |
| `assess/score_pipeline.py:249-250` | 自适应阈值算了不用 |
| `assess/score_pipeline.py:146-192` | `score_all=False` 时 T0 判定被 LLM 双裁判覆盖 |
| `assess/judge_manager.py:787-818` + `asr_manager.py:306` | ASR→阈值→ASR 自反馈回路 |
| `assess/adaptive_dual_judge.py:171` | 导入不存在的 `_t0_refusal_check` |
| `assess/adaptive_dual_judge.py:322-361` | 引用不存在的 `_stats._or_aggregation_*` |
| `assess/asr_stats.py:105-110` vs `core/phases/assess.py:84-88` | Cohen's Kappa 被算两遍且口径不同 |
| `assess/asr_stats.py:177-184` | `p1_j1` 分母口径不一致，可 >1 |
| `core/phases/executor.py:145-157` | 成功兜底「有 converted_value 即 success」严重失真 |
| `core/phases/assess.py:72 vs 101` | `wilson_confidence_level` 配置读了不传 |

### A.3 组件链路（Wave 1 / 2 / 6）

| 坐标 | 缺陷 |
|---|---|
| `report/component_reports.py:96/109/167` | 读不存在的 `ev.metadata` → 组件报告恒空（CB-2 断裂） |
| `report/component_reports.py:108/181/237/382` | 读不存在的 `ev.response` |
| `core/_helpers.py`（已修）/ `assess/component_router.py` 等 | 组件键映射四份分散（IA-3） |
| `tools/architecture_validator.py:83` | `session_memory` recon 清单为空 → 无法识别 |
| `recon/embedding/` | 无对应组件键 |
| `recon/api/` vs `recon/web/` | 双轨（C3） |
| `arm/converter_presets.py:110-111` | `l5_optimal` 缓存忽略 `converter_target` |
| `arm/converter_presets.py:168` | `_get_converter_asr` 是返回 0.0 的死桩 |
| `arm/converter_presets.py:237-242` | 注释称过滤编码类但只过滤文件类，名不符实 |
| `core/seed_loader.py:160/211` | 目录白名单漏 `_attack_surface`（33 文件/174 条目不可达） |
| `strike/common/dispatcher.py:53-62` | `pyrit.attacks.*` 旧命名空间（与宪法 7C.1 冲突） |
| `strike/common/dispatcher.py:304-331` | 加载了攻击类却不用，无条件回落 `execute_attacks` |
| `strike/web/http_engine.py` | `urllib` 自研 HTTP（违 C1 R-NATIVE-4 / C13） |
| `strike/common/decision_safety.py:49/57` | 授权边界字段不存在 → 检查全跳过 |
| `arm/seed_ranker.py:50-124` | 74 行硬编码 `CAPABILITY_SEED_MAP` |
| `arm/attack_surface_mapper.py` | ~60 处硬编码 `asr_prior`，且文件头自称 "Zero hardcoded payloads" |

### A.4 报告生成（Wave 6）

| 坐标 | 缺陷 |
|---|---|
| `report/generator.py:270-287` | 三份核心 Markdown 生成位于 `except` 分支 → 永不生成 |
| `report/generator.py:253-254` | `report.md` 写在 `if "md" in output_formats:` 之外 |
| `report/evidence.py:565` | `evidence_id` 用每个 technique 内部下标 → 跨技术重复覆盖 |
| `report/evidence.py:620-628` | `_analyze_failures` 用全局分母算单技术成功率 |
| `report/report_html.py:70/80/124-127` | 未转义插值 → XSS |
| `report/report_markdown.py:94-103/585` | Markdown 表缺表头行 |
| `report/report_markdown.py:130-132` | References 段追加空串 |
| `report/sarif_report.py:185` | 所有 result 共用同一 location |
| `report/owasp_mapping.py:225` | 兜底 `return "LLM01"` 抬高命中数 |
| `report/component_poc.py:567` | 组件 PoC 永不生效（读不存在的 metadata 键） |

### A.5 工程化（Wave 6）

| 坐标 | 缺陷 |
|---|---|
| `pyproject.toml` | 无 lock、无 mypy/black/coverage 配置、无 aiohttp 声明 |
| 仓库根 | 无 `.github/workflows`、Dockerfile、SECURITY.md、CONTRIBUTING.md、CHANGELOG.md、py.typed |
| `core/context.py:222` | `max_val=3` 与 `defaults.yaml:5 max_concurrency: 5` 冲突 |
| `core/scenario_router.py:130` | 无条件覆盖 YAML 解析结果 |
| `arm/seed_ranking.py:614` | 运行时回写受版本控制的 `config/asr_priors.yaml` |
| `tools/guard.py:47-91` | `_SIZE_BYPASS_WHITELIST` 90+ 条目大量路径已失效 |
| `core/config.py:59-1048` | `parse_args` 单函数 ~990 行、~120 flag（上帝函数） |
| `core/context.py:24-199` | `PipelineContext` 约 50 字段、20+ 个 `Any`（上帝对象） |
