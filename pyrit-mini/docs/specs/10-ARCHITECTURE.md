# 10 — 架构与设计层：技术蓝图（Architecture Blueprint）

> **文档层级**：L1 / 五层规约金字塔第二层
> **效力**：定义系统的目标架构、模块边界、数据契约与架构不变量。任何代码变更必须能在本蓝图上"落点"——落不了点的变更需要先走 change-proposal 修改蓝图。
> **读者**：实施任务前的 AI（必读相关章节）、评审 diff 的人工/AI。
> **版本**：v1.2（2026-09-05 初版；同日 REV-01/REV-02 修正；版本记录见文末）

---

## 第一章：系统全景

```
输入契约                    六阶段攻击流水线                          输出契约
──────────                ──────────────────────                    ──────────
data/burp/*.txt    ──►     ① RECON    侦察/指纹/Target 构建    ──►    outputs/strike_*/
(Burp 完整 HTTP            ② SYNERGY  攻击面分类/场景路由             ├── report*.md / .html
 交互，含响应)              ③ ARM      种子/Converter/技术             ├── report.sarif
.env 三角色 LLM            ④ STRIKE   单轮多路径 FIRST_SUCCESS         ├── evidence/ + poc/
 config/defaults.yaml      ⑤ ESCALATE L1→L4 升级链                    ├── native_output/
 config/asr_priors.yaml    ⑥ ASSESS   T0→J1→J2 级联评分                └── db/pyrit.db
 data/seeds/*.prompt       (REPORT    证据/多格式报告)
```

**使命映射**（见宪法第 0 条）：蓝图的每个部分都服务于"Burp 黑盒目标 ASR 最大化"。判断一个架构改动是否正当的唯一标准：它是否让 ①-⑥ 链路对 Burp 目标打出更高 ASR、或让证据链更可复现。

### 1.1 阶段词汇映射（口径统一，v1.1 增补）

需求侧/会话中的惯用口径与本蓝图六阶段流水线的**唯一权威对应关系**（防止凭空发明第七阶段或同名模块）：

| 惯用口径 | 架构落点 | 备注 |
|---------|---------|------|
| recon / 侦察 | ① RECON | recon/ 模块；target_fingerprint 是对下游的唯一输出总线 |
| 攻击面分类 / 场景路由 | ② SYNERGY | **无独立模块**：由 core/ 场景路由实现，仅产出 technique_tags（ADR-004）；禁止新建 synergy/ 包。现状违例：data/synergy_orchestrator.py + data/attack_surface_classifier.py 越层存代码（D-13） |
| arm / 武器化 | ③ ARM | arm/ 模块 |
| strike / 打击 / 单轮 | ④ STRIKE | strike/ 模块 |
| escalate / 升级链 | ⑤ ESCALATE | strike/ 模块内部逻辑，非独立模块 |
| 评分 / judge / ASR 统计 | ⑥ ASSESS | assess/ 模块（post-hoc；唯一允许 LLM Judge 的位置，I2/I3） |
| report / 报告 | REPORT | report/ 模块 |
| **evidence / 证据** | **输出契约，非阶段** | 由 ASSESS（评分结论）+ REPORT（证据文件）产出；见 REQ-007 与不变量 I9；**禁止新建 evidence/ 模块** |

**规则**：会话中出现未登记口径（如"改 evidence 阶段"）→ 先查本表映射再动手；映射不出去 → STOP-REPORT（C11），禁止发明新阶段或新建同名模块（C3/C4）。

## 第二章：分层与依赖规则

### 2.1 模块分层

| 层 | 模块 | 职责一句话 |
|----|------|-----------|
| 编排层 | `main.py` | 六阶段顺序编排 + 多 endpoint 循环；**不得包含业务逻辑**（现状违例：87KB 巨石，D-02） |
| 核心层 | `core/` | 配置解析（唯一默认值定义地）、PipelineContext、架构守卫、场景路由 |
| 阶段层 | `recon/ arm/ strike/ assess/ report/` | 各攻击阶段的实现；彼此只通过 PipelineContext 交接 |
| 适配层 | `targets/` | PyRIT Target 的包装（限速/认证恢复/内容过滤标记扩展/路由工厂） |
| 支撑层 | `utils/ pipeline/` | 终端展示、缓存清理、日志、资源清理（现状违例：display.py 119KB，D-14） |
| 数据层 | `data/` + `config/` | 种子、评分器 rubric、ASR 先验、defaults（**全部为声明式资产**；现状违例：4 个 .py 代码文件，D-13） |

### 2.2 依赖方向矩阵（允许 ↓ / 禁止 ✗）

| 依赖方 ↓ 被依赖方 → | core | recon | arm | strike | assess | report | targets | utils | data(config) |
|---|---|---|---|---|---|---|---|---|---|
| main.py | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| core/ | — | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | 读写 defaults.yaml |
| recon/ | ✓（context） | 内部 | ✗ | ✗ | ✗* | ✗ | ✓ | ✓ | 只读 |
| arm/ | ✓ | ✗ | 内部 | ✗ | ✗ | ✗ | ✗ | ✗ | 只读 asr_priors；读 asr_history（I7 运行时账本） |
| strike/ | ✓ | ✗ | ✓ | 内部 | ✓** | ✗ | ✗ | ✓ | 只读 |
| assess/ | ✓ | ✗ | ✗ | ✗ | 内部 | ✗ | ✗ | ✗ | 读写 asr_history |
| report/ | ✓ | ✗ | ✗ | ✗ | ✗ | 内部 | ✗ | ✗ | 只读 |
| targets/ | ✗ | ✓*** | ✗ | ✗ | ✗ | ✗ | 内部 | ✗ | 只读 |
| utils/ | ✓（context 类型） | ✗ | ✗**** | ✗ | ✗ | ✗ | ✗ | 内部 | 只读 |

\* recon/target_router 调 `assess.scorer.validate_scoring_target_capabilities` —— 已登记债务 D-04。
\** strike → assess 仅限 `precompute_outcomes_async`（升级前预评分），不得扩大。
\*** targets/agent_adapter 引用 recon/target_builder 的 JSONSafeHTTPTarget —— 已登记债务 D-05。
\**** utils/display 延迟导入 arm/seed_ranking 读 ASR 历史 —— 已登记债务 D-06（展示层越界）。

**图例**（v1.1）：✓ 允许；✗ 禁止；"—" = 不适用（对角线自身单元格）或禁止（本表仅一处：main.py × 数据层——main 不得直接解析 data/config 资产，一律经 core/config.py 或阶段模块。未来新出现的"—"必须随行注明语义）。

**硬规则**：
1. 阶段层模块之间（recon/arm/strike/assess/report）**只准通过 PipelineContext 字段交接数据**，禁止直接 import 对方实现（表内已标注的既存例外除外，且例外只减不增）。
2. `core/context.py` 是唯一被全员依赖的枢纽；`core/config.py` 是唯一允许定义参数默认值的模块。
3. 循环导入的合法解法只有三种：函数内延迟导入 / TYPE_CHECKING / 合并到同一模块（拆分后 re-export 属于债务，不再新增）。

## 第三章：PyRIT 原生判定决策树

写新能力前的强制四问（对应宪法 C1）：

```
Q1: PyRIT 1.0.1 有现成组件吗？（检索 pyrit.executor.attack / pyrit.prompt_target /
    pyrit.scorer / pyrit.converter / pyrit.memory / pyrit.output）
    ├─ 有 → 直接用，结束
    └─ 无 → Q2: 能用"包装原生组件"实现吗？（继承/组合原生类，原生引擎为主）
             ├─ 能 → Enhancement wrapper（如 RateLimitedTarget 模式），结束
             └─ 不能 → Q3: 属于 Glue / Output 三类自研范畴吗？
                      │  Glue   = 连接原生组件（如 burp 解析 → HTTPTarget）
                      │  Output = 读 PyRIT 结果产证据/报告（如 evidence.py）
                      ├─ 是 → 实现，结束
                      └─ 否 → Q4: 超出 PyRIT 域（ML 推理/HTTP 协议层/供应链）？
                               ├─ 是 → STOP-REPORT（C11）：提案引入外部框架或拒绝
                               └─ 否 → STOP-REPORT（C11）：大概率你错了，重新检索
```

**原生组件强制使用清单**（attack 10 类 + target + scorer + converter + memory + output，详见 SKILL.md R2 表——该表继续有效）。**PyRIT 域边界**：`与 LLM 的 prompt 交互与响应评估`；域外问题（如梯度级 GCG）只能以外部工具形态接入并回填数据。

## 第四章：PipelineContext 数据契约

ctx 字段采用**唯一写者**原则（一个字段只准一个阶段写）：

| 字段 | 唯一写者 | 读者 | 备注 |
|------|---------|------|------|
| `args` / `output_dir` | main | 全部 | 创建后只读 |
| `parsed_request`（含 target_fingerprint） | recon | arm/strike/report | fingerprint 是 recon 对下游的总线 |
| `objective_target` / `multi_turn_target` / `extra_objective_targets` | recon | strike / cleanup | per-endpoint，循环内须重置 |
| `adversarial_target` / `scoring_target` / `converter_target` / `extra_adversarial_targets` | recon | strike/assess | **跨 endpoint 共享**，循环末清理 |
| `synergy_config` / `scenario_config` / `scenario_name` | synergy/scenario 路由 | strike(adaptive) | 攻击面→技术标签 |
| `seeds` / `techniques` / `converter_map` | arm | strike | — |
| `attack_results` / `_failed_objectives` | strike（含 escalate 追加） | assess/report | `{technique: [AttackResult]}` |
| `asr_per_technique` / `overall_asr` / `wilson_ci` / `dual_judge_stats` / `scorer` | assess | report / main | — |
| `orchestration_log` | 各阶段（自己追加自己的条目） | report | 六阶段每阶段至少一条 |
| `_mcp_dynamic_seeds` | recon(MCP 枚举) | strike(mcp_rag) | — |
| Playwright 三字段 | recon | cleanup | 共享，仅末尾清理 |

**新增 ctx 字段的义务**：在本表登记 + 在 20-REQUIREMENTS 对应需求验收标准中体现 + 单 endpoint 循环开始处明确"重置 / 保留"归属（多 endpoint 隔离，见 40-GUARDRAILS 引用的 R8 §8.3）。

## 第五章：Burp 目标数据流（输入契约）

**合法输入**：`data/burp/*.txt`，Burp 保存的完整 HTTP 交互（请求 + 响应）。解析器承诺：

1. `{PROMPT}` 占位符：解析器启发式注入（4 策略）；下游一切攻击注入经由 `JSONSafeHTTPTarget._inject_prompt_into_request` 替换，**任何模块不得自行拼接 prompt 进 body**。
2. 响应提取：回调选择优先级 = 已探测 JSON 路径 → SSE → 自适应 JSON；新增提取逻辑必须挂入 `_select_callback` 优先级链，不得旁路。
3. `target_fingerprint` 是 recon 的唯一输出总线：能力/模型族/MCP 工具/端口/OpenAPI/系统提示泄露全部写入此字典，禁止另立平行结构。
4. 目标不可达（402/503/连接失败）→ `ConnectionError` 终止该 endpoint，禁止静默降级为"跳过"。

**非 Burp 路径**（LiteLLM/API 直连/浏览器）为兼容分支，只准收敛进与 Burp 相同的 ctx 数据契约（`_ensure_parsed_request_for_api_path` 模式），禁止平行数据流。

## 第六章：ASR 架构不变量（Invariants）

以下不变量任何变更不得破坏（均可由 guard 或 dry-run 检查）：

| # | 不变量 | 依据 |
|---|--------|------|
| I1 | 每 `ConverterConfiguration` 恰 1 converter；多路径 = SequentialAttack 独立子路径 + FIRST_SUCCESS | arXiv:2307.15043 / 2407.01232 |
| I2 | 攻击执行路径评分器零 LLM token（0-token 拒绝检测）；LLM Judge 只出现在 post-hoc assess | R6 §6.2 |
| I3 | 评分级联序固定 T0→J1→J2→J3，禁止跳过 T0 直呼 LLM | arXiv:2402.04249 / 2308.07920 |
| I4 | 升级链触发 ASR<90%；中间退出检查点必须在 L1→L2 与 L2→L3 边界 | arXiv:2406.12609 |
| I5 | 三角色分离：objective / adversarial / scoring target 相互独立，.env 配置 | R6 §6.5 |
| I6 | 种子排序 UCB1 + 类别多样性保底 + 零 ASR 剪枝（比例≤50%，每 OWASP 类保底 1） | arXiv:cs/0207052 |
| I7 | ASR 反馈闭环：**asr_history.json 是运行时观测唯一账本**（种子/converter/GCG 后缀三级，EMA α=0.3；assess 唯一写者，arm 读取）；**asr_priors.yaml 是人工先验唯一源，禁止运行时写入**；arm 读取次序：history 命中 > priors 兜底 | 设计决策 |
| I8 | 联合 ASR = 1 - ∏(1-ASRᵢ)，多 endpoint 串行深度攻击 | arXiv:2310.08419 / 2302.12173 |
| I9 | 报告必须含 PyRIT 原生输出（pyrit.output）+ 证据全字段非空 | R2 / R6 §6.6 |
| I10 | 每 endpoint 独立 SQLite（WAL）+ Singleton 三步清除；共享 LLM target 跨 endpoint 复用 | R8 §8.1/8.3 |

## 第七章：决策记录（ADR 索引）

已固化的架构决策（变更需走 change-proposal）：

| ADR | 决策 | 摘要 |
|-----|------|------|
| ADR-001 | OR 聚合评分 | J1/J2 分歧默认 OR（ASR 最大化优先，假阳性 ~3-5% 可接受，v56 起可配置） |
| ADR-002 | GCG 用后缀池非梯度 | 黑盒场景无 logits，用静态池+LLM 变异+历史重排（arXiv:2310.04775） |
| ADR-003 | MCP 枚举旁路 HTTPTarget | JSON-RPC 结构化请求不适合 {PROMPT} 占位符机制，httpx 直发（唯一例外） |
| ADR-004 | 场景路由轻量化 | v60 起 synergy 只产出 technique_tags，种子/评分器选择回归 SSOT 配置 |
| ADR-005 | 升级链技术分四级 | L1 优先级分批（先验排序）→ L2-L4 全并行；仅失败目标进入下一级 |
| ADR-006 | 多 endpoint 串行 | 高价值优先（能力指纹排序）逐个深度攻击，不做并行（全局状态安全） |

## 第八章：架构债务登记簿（冻结区）

以下为已识别的**冻结债务**：日常任务禁止触碰（C3/C4），只能由专项任务（DEBT-xxx）消除。**只减不增**。D-01~D-09 为制宪时登记；D-10~D-16 为 REV-02 源码审计（commit 0b8e28c）新登记。

| ID | 债务 | 现状 | 消除方向 |
|----|------|------|---------|
| D-01 | assess 双轨并存 | judge_manager（74KB）/judge_utils（55KB）/asr_manager/score_pipeline（合并版）与拆分版功能重复 | 保留一套（以运行时 import 路径为准），删除另一套与 asr_tracker re-export |
| D-02 | main/pipeline 镜像 | main.py 87KB 巨石（编排层含业务逻辑，违 2.1）；pipeline/orchestrator.py 实为薄转发（v58 重构半途，委托 main.run） | main 调用 pipeline 包，删除本地副本；业务逻辑下沉阶段层 |
| D-03 | stub 模块 | encoded_injection.py / cair.run_cair_attack / multi_turn_attacks（Best-of-N）返回空 dict，注释自认"调用方 try/except 优雅降级"= R-H1 静默降级 | 要么实现（提 REQ），要么从升级链摘除；禁止维持"编排了但没实现"状态。**注意：Best-of-N 属 REQ-004 P0 验收项，此 stub 是现行 P0 缺口** |
| D-04 | recon → assess 跨层依赖 | target_router 调 assess.scorer 验证函数 | 验证函数移入 core 或 targets |
| D-05 | targets → recon 反向依赖 | agent_adapter 引用 JSONSafeHTTPTarget | JSONSafeHTTPTarget 迁至 targets/ |
| D-06 | utils/display → arm 越界 | 展示层延迟导入 arm.seed_ranking 读 ASR | ASR 数据经 ctx 或独立查询模块传递 |
| D-07 | 硬编码数据快照 | display._CONVERTER_ASR_LABEL 与 asr_priors.yaml 重复 | 展示层读 yaml |
| D-08 | 无代码加载的配置 | config/target_profiles.yaml 26 profile 零消费 | 要么接 asset_mapper 要么删除 |
| D-09 | 规范文档多处冗余 | SKILL.md（实测 57KB）/ docs/ 与 specs 职责重叠 | 按 00-CONSTITUTION 第五章迁移计划收敛 |
| D-10 | escalation 镜像双轨 | strike/escalation.py（41638B）与 escalation_chain.py（41629B）仅差 9 字节，疑似孪生复制；另有 escalation_attacks.py（26.7KB）三轨 | 首个代码会话 diff 确认后保留一套（建议 chain 语义者胜出），孪生删除 |
| D-11 | arm converter 三轨 | converter_chains.py / converter_presets.py / converter_selector.py 各 ~40KB 同源演化 | 按职责裁决合并（选择器/预设/构建三类职责若共存须显式契约分离，否则合并） |
| D-12 | arm 种子排序双轨 | seed_ranker.py（23.8KB）与 seed_ranking.py（27KB）职责重叠 | 合并为单一排序模块 |
| D-13 | data/ 层代码污染 | data/ 下 4 个 .py（asset_mapper / attack_surface_classifier / scorer_selector / synergy_orchestrator），违反 2.1"数据层=声明式资产" | 代码迁至 core/ 或对应阶段层，data/ 只留声明式资产 |
| D-14 | display.py 巨石 | utils/display.py 119KB 全库最大文件（含 D-06/D-07 关联问题） | 拆分展示/数据查询职责；读 yaml 替代硬编码 |
| D-15 | judge 文件群 | judge_manager（74KB）+ judge_utils（55KB）+ dual_judge（27KB）+ adaptive_dual_judge（24KB）四文件，D-01 的具体形态 | 并入 D-01 消除方案统一裁决（单文件 ≤500 行目标） |
| D-16 | 工具链与资产卫生 | ① pyproject.toml ruff exclude pipeline/（门禁 Step 2 空洞）；② report/output.py 注释 mojibake（UTF-8/GBK 混写）；③ 依赖 `pyrit>=1.0.1` 未钉住（规约口径为 1.0.1）；④ data/seeds/asr_history.json 运行时产物入库 | 修 pyproject（去 exclude、钉 1.0.1）；修乱码；asr_history 迁 outputs/ 并入 .gitignore |

**新增债务的流程**：发现新双轨/越界 → 登记 backlog（一行）→ 评估后入本表。**禁止直接修**。

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-05 | 初版：系统全景、分层与依赖矩阵、PyRIT 判定树、ctx 契约、Burp 数据流、不变量 I1-I10、ADR-001~006、债务簿 D-01~D-09 | — |
| v1.1 | 2026-09-05 | REV-01：① §1.1 阶段词汇映射表（统一 recon/arm/strike/report/evidence 口径，防凭空造阶段或模块）；② I7 明确 asr_history（运行时唯一账本）与 asr_priors（人工先验唯一源）的 SSOT 关系；③ 依赖矩阵补 arm 读取 asr_history、"—"图例；④ 版本记录机制 | 用户会话批准 |
| v1.2 | 2026-09-05 | REV-02 源码对齐（审计 @0b8e28c）：① 新登记债务 D-10~D-16（escalation 孪生、converter 三轨、seed 排序双轨、data/ 层代码污染、display 巨石、judge 文件群、工具链卫生）；② D-02/D-03 现状更新（main.py 87KB 巨石证实；Best-of-N stub 定性为 P0 缺口）；③ §1.1/§2.1 标注现状违例。架构本体（分层/契约/不变量/ADR）无变更 | 用户会话批准 |
