# AI-300 框架架构全面审查报告

> **审查日期**: 2026-07-19
> **审查视角**: 项目架构师 + AI Red Team 红队最佳实践
> **审查范围**: 数据驱动架构全链路 — 侦察 → 侦察分析 → 载荷适配 → 攻击编排 → 评分判定 → 报告输出
> **框架版本**: v3.5.0 / PyRIT 0.14.0
> **对齐标准**: OWASP LLM Top 10 (2025) + OWASP Agentic Top 10 (2026) + MITRE ATLAS + OffSec AI-300

---

## 目录

1. [审查方法论](#1-审查方法论)
2. [架构成熟度评估](#2-架构成熟度评估)
3. [全链路管线审查](#3-全链路管线审查)
4. [AI 红队最佳实践对齐分析](#4-ai-红队最佳实践对齐分析)
5. [关键差距识别](#5-关键差距识别)
6. [优化建议与路线图](#6-优化建议与路线图)
7. [结论](#7-结论)

---

## 1. 审查方法论

### 1.1 审查框架

本次审查采用 **四维交叉评估法**，从以下四个维度对架构进行立体审视：

| 维度 | 评估要点 | 对标来源 |
|------|---------|---------|
| **管线完整性** | 侦察→分析→载荷→编排→执行→评分→报告 全链路闭环 | OffSec PTES + AI Red Team |
| **数据驱动度** | 配置即策略、载荷即数据、画像即决策输入 | PyRIT + Garak + DeepTeam |
| **红队实战性** | ASR 优化、Fallback 链、反馈闭环、变异生成 | Microsoft AI Red Team + Anthropic |
| **标准对齐度** | OWASP / MITRE ATLAS / OffSec 报告规范 | OWASP 2025/2026 + OffSec AI-300 |

### 1.2 审查基准

```
审查基线状态：
├── 载荷库: 82 文件 / 632 payloads / _registry.core.yaml v2.0.0
├── 侦察引擎: 3 工具（AIMAP/Garak/DeepTeam）+ 19 项优化（OPT-A/G/D/M/E）
├── 攻击引擎: SmartMatcher v3.0 + 两层策略选择 + 6 攻击探针族
├── 评分系统: ASI 感知自动映射 + 外部 LLM 后端 + 20 类别覆盖
├── 报告系统: 9 段 OffSec 标准结构 + Markdown/HTML 双格式
└── 管线追踪: 20 个 stage 全链路记录 + JSON/Markdown 导出
```

---

## 2. 架构成熟度评估

### 2.1 成熟度评分矩阵

| 领域 | 当前等级 | 目标等级 | 差距分析 |
|------|---------|---------|---------|
| **侦察覆盖** | L4 优化级 | L5 专家级 | 缺少侦察结果→载荷过滤的自动闭环 |
| **载荷库** | L4 优化级 | L5 专家级 | ASR 基线已建立，缺动态 ASR 更新 |
| **攻击编排** | L3 集成级 | L4 优化级 | 缺多阶段攻击链编排 |
| **评分策略** | L3 集成级 | L4 优化级 | 缺多评分器集成投票机制 |
| **报告生成** | L3 集成级 | L4 优化级 | 缺 CVSS 量化 + MITRE ATLAS 映射 |
| **管线追踪** | L4 优化级 | L5 专家级 | 已有全链路追踪，缺可视化 |
| **数据驱动** | L4 优化级 | L5 专家级 | 配置即策略已实现，缺策略 A/B 测试 |

> **等级定义**: L1 初始 → L2 可用 → L3 集成 → L4 优化 → L5 专家

### 2.2 总体成熟度

**综合评分: L4.2 / L5** — 介于"优化级"与"专家级"之间，P0 级闭环优化（REV-1/REV-2）已完成，侦察→载荷过滤→ASR 排序全链路闭环已实现。

### 2.3 核心优势

| # | 优势 | 体现 |
|---|------|------|
| 1 | **三层分离架构** | 数据层(data/) + 配置层(config/) + 引擎层(pyrit_ai300/) 完全解耦 |
| 2 | **侦察-攻击解耦** | 通过 TargetProfile JSON 通信，互不 import，可独立演进 |
| 3 | **PyRIT 原生复用** | 不重复造轮子，6 种攻击 + 10+ 转换器 + 6 评分器全部 import 调用 |
| 4 | **ASR 驱动载荷库** | 632 个载荷全部标注 ASR 基线，Top-5 载荷 ASR ≥ 90% |
| 5 | **两层策略选择** | 规则快速筛选 + 精确模型匹配，兼顾速度与精度 |
| 6 | **全链路追踪** | 20 个 stage 从侦察到反馈完整记录，支持 JSON/Markdown 导出 |
| 7 | **Fallback 增强** | 回退链不仅切换攻击类，还尝试不同转换器组合 |
| 8 | **反馈闭环** | FeedbackAnalyzer → PayloadMutator → 变异体注入下轮攻击 |

---

## 3. 全链路管线审查

### 3.1 管线全景图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AI-300 全链路攻击管线 v3.1                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  阶段 1: 侦察 (Reconnaissance)                                    │   │
│  │  ──────────────────────────────────────────────────────────────  │   │
│  │  ReconEngine.run()                                                │   │
│  │    ├── [并行] AIMAP 协议指纹 (OPT-A1~A6)     ~8s                 │   │
│  │    ├── [并行] DeepTeam OWASP 红队 (OPT-D1~D5) ~2-5min            │   │
│  │    ├── [串行] Garak 漏洞扫描 (OPT-G1~G6)     ~1-3min             │   │
│  │    │     └── 依赖 AIMAP 结果动态选择 probe                        │   │
│  │    └── ProfileMerger 合并 (OPT-M1~M2)                             │   │
│  │          ├── Jaccard 语义去重 (threshold=0.80)                    │   │
│  │          ├── 冲突检测 (severity 差异 ≥ 2)                          │   │
│  │          ├── 交叉验证 (多工具确认 → 置信度提升)                     │   │
│  │          └── 动态攻击建议 (模型/能力/攻击面/风险多维生成)            │   │
│  │                              ↓                                    │   │
│  │  TargetProfile JSON (指纹+漏洞+攻击面+建议+风险等级)               │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                   ↓                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  阶段 2: 侦察分析与载荷适配 (Recon Analysis & Payload Adaptation) │   │
│  │  ──────────────────────────────────────────────────────────────  │   │
│  │  ProfileLoader.load()                                             │   │
│  │    ├── 目标信息提取 (model/family/provider/capabilities)          │   │
│  │    ├── 攻击面解析 (prompt/api/agent/rag/mcp/vector)               │   │
│  │    ├── 漏洞列表加载 (category/severity/owasp/confidence)          │   │
│  │    └── 智能参数推导:                                               │   │
│  │          ├── preferred_probe_families (漏洞驱动)                  │   │
│  │          ├── aggression_level (风险等级驱动)                       │   │
│  │          └── context_window (模型驱动)                            │   │
│  │                              ↓                                    │   │
│  │  PayloadManager + PayloadClassifier                               │   │
│  │    ├── YAML 载荷加载 (82 文件 / 632 payloads)                     │   │
│  │    ├── 归一化 (解码 base64/hex/url)                               │   │
│  │    ├── 语义去重 (Jaccard ≥ 0.85)                                  │   │
│  │    └── 五维分类:                                                   │   │
│  │          ├── technique (direct/role_play/encoded/...)             │   │
│  │          ├── language (en/zh/mixed)                               │   │
│  │          ├── encoding_state (plain/base64/hex/...)                │   │
│  │          ├── length_class (short/medium/long/very_long)           │   │
│  │          └── complexity (low/medium/high)                         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                   ↓                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  阶段 3: 攻击组合自动适配 (Attack Combination Adaptation)         │   │
│  │  ──────────────────────────────────────────────────────────────  │   │
│  │  SmartMatcher (两层选择)                                          │   │
│  │    ├── 第一层: 规则快速筛选 (_fast_rule_filter)                   │   │
│  │    │     └── 13 条规则 (编码/对抗/角色扮演/间接注入/...)           │   │
│  │    ├── 第二层: 精确模型匹配 (_precise_model_match)                │   │
│  │    │     ├── 侦察推荐约束 (preferred_probe_families)              │   │
│  │    │     ├── ASI 类别约束 (ASI_STRATEGY_HINTS)                    │   │
│  │    │     ├── 对抗 LLM 可用性检查 (降级处理)                        │   │
│  │    │     ├── 转换器预设影响评估                                    │   │
│  │    │     └── 动态参数计算 (max_turns/timeout)                     │   │
│  │    ├── 逐载荷转换器选择 (P0-A)                                    │   │
│  │    │     ├── OWASP 过滤 (encoding_selector 三阶段)                │   │
│  │    │     ├── 语言过滤                                             │   │
│  │    │     └── 技术调整 (encoded 排除 re-encode 等)                  │   │
│  │    ├── Fallback 链增强 (P0-B)                                     │   │
│  │    │     └── 每个回退项附加 converter_override                    │   │
│  │    └── 输出: 攻击策略 + 参数 + Fallback 链                        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                   ↓                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  阶段 4: 评分器策略选择 (Scorer Strategy Selection)               │   │
│  │  ──────────────────────────────────────────────────────────────  │   │
│  │  ScorerBuilder.build()                                            │   │
│  │    ├── ASI/LLM 类别 → 评分器类型映射 (20 类别)                    │   │
│  │    │     ├── ASI01/06/09/LLM01/02/09 → refusal (拒绝检测)         │   │
│  │    │     ├── ASI03/08/LLM05/08 → category (类别判定)              │   │
│  │    │     ├── ASI05/LLM04/07/08 → substring (子串匹配)             │   │
│  │    │     └── ASI02/04/07/10/LLM03/06/10 → true_false (布尔判定)   │   │
│  │    ├── LLM 后端选择                                               │   │
│  │    │     ├── CLI --scorer-url (最高优先级)                        │   │
│  │    │     ├── 环境变量 SCORER_API_KEY / SCORER_MODEL_NAME          │   │
│  │    │     ├── config/scores/*.yaml 配置                            │   │
│  │    │     └── 默认 local_ollama (qwen3:0.6b)                      │   │
│  │    └── 对抗性配置 (Crescendo/TAP 需要 adversarial LLM)            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                   ↓                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  阶段 5: PyRIT 原生执行 (PyRIT Native Execution)                 │   │
│  │  ──────────────────────────────────────────────────────────────  │   │
│  │  AttackOrchestrator.execute_attack()                              │   │
│  │    ├── PyRIT 攻击实例化 (6 种攻击类型)                            │   │
│  │    │     ├── PromptSendingAttack (单轮直接)                       │   │
│  │    │     ├── CrescendoAttack (渐进升级)                           │   │
│  │    │     ├── TreeOfAttacksWithPruningAttack (树搜索+剪枝)         │   │
│  │    │     ├── PAIRAttack (迭代优化)                                │   │
│  │    │     ├── RedTeamingAttack (红队探索)                          │   │
│  │    │     └── SequentialAttack (多 preset 早停)                    │   │
│  │    ├── RateController 并发控制 (信号量 + 速率限制)                 │   │
│  │    ├── Fallback 执行 (主策略失败 → 回退链)                        │   │
│  │    ├── 早停机制 (连续失败 ≥ 5 次跳过)                             │   │
│  │    └── 评分执行 (bypass / blocked 判定)                           │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                   ↓                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  阶段 6: 反馈与优化 (Feedback & Optimization)                     │   │
│  │  ──────────────────────────────────────────────────────────────  │   │
│  │  FeedbackAnalyzer.analyze()                                       │   │
│  │    ├── 成功率统计 (按类别/策略/转换器)                             │   │
│  │    ├── 最优策略推荐                                               │   │
│  │    └── PayloadMutator.mutate_from_results()                       │   │
│  │          ├── paraphrase (语义重写)                                │   │
│  │          ├── tone_shift (语气变换)                                │   │
│  │          └── 变异体注入下轮攻击                                    │   │
│  │  _compute_best_combinations() (P0-C)                              │   │
│  │    └── Top-10 高成功率组合 (payload × attack × converter)         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                   ↓                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  阶段 7: 报告生成 (Report Generation)                             │   │
│  │  ──────────────────────────────────────────────────────────────  │   │
│  │  ReportGenerator.generate()                                       │   │
│  │    ├── 1. Executive Summary (关键发现+风险评级)                    │   │
│  │    ├── 2. Scope and Rules of Engagement (范围+交战规则)            │   │
│  │    ├── 3. Methodology (方法论+框架覆盖)                           │   │
│  │    ├── 4. Findings Summary (按 Module 汇总)                      │   │
│  │    ├── 5. Detailed Findings (每个攻击详细结果)                    │   │
│  │    ├── 6. Attack Path Visualization (攻击路径可视化)               │   │
│  │    ├── 7. Risk Assessment (风险评估矩阵)                          │   │
│  │    ├── 8. Remediation Recommendations (修复建议)                  │   │
│  │    └── 9. Appendices (工具/参考/元数据)                           │   │
│  │  输出格式: Markdown (默认) / HTML (可视化)                        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 各阶段审查结论

#### 阶段 1: 侦察 — ✅ 优秀 (L4)

**已实现**:
- 三工具并行调度（AIMAP + DeepTeam 并行，Garak 依赖 AIMAP 串行）
- 19 项优化全部实施（OPT-A1~A6, G1~G6, D1~D5, M1~M2, E1~E3）
- 协议探测并行化（30s → 8s）
- 深度 MCP/RAG/Agent 框架探测
- 模型能力探测（function_calling/vision/json_mode/streaming）
- 增量缓存（24h TTL）
- Jaccard 语义去重 + 动态攻击建议

**审查结论**: 侦察阶段已达到 L4 优化级，覆盖面和效率均优于业界同类工具。AIMAP→Garak 桥接实现了"先识别再扫描"的最佳实践。

#### 阶段 2: 侦察分析与载荷适配 — ⚠️ 良好但有差距 (L3)

**已实现**:
- ProfileLoader 将 TargetProfile 转换为 SmartMatcher 参数
- preferred_probe_families 基于漏洞发现驱动策略选择
- aggression_level 基于风险等级驱动参数调整
- 载荷五维分类 + 语义去重

**关键差距**:
- ⚠️ **缺少侦察→载荷过滤闭环**: 侦察发现"无 RAG 攻击面"时，仍会加载 LLM04/LLM08 载荷。应基于 surfaces 字段自动过滤不相关载荷
- ⚠️ **缺少 ASR-aware 载荷排序**: 载荷已标注 ASR 基线，但 SmartMatcher 未利用 ASR 数据进行载荷优先级排序
- ⚠️ **缺少模型特定载荷选择**: 侦察已检测到 model_family，但未根据模型家族选择最优载荷变体

**建议** (见 §6):
- REV-1: 实现 `PayloadFilter.filter_by_profile()` 基于侦察画像过滤载荷
- REV-2: 实现 `ASRRanker.rank_by_target_model()` 基于目标模型 ASR 排序载荷
- REV-3: 实现 `ModelSpecificSelector` 基于模型家族选择载荷变体

#### 阶段 3: 攻击组合自动适配 — ✅ 优秀 (L4)

**已实现**:
- 两层策略选择（规则筛选 + 精确匹配）
- 13 条快速规则覆盖所有主要 technique
- ASI 类别感知策略约束（10 个 ASI 类别）
- 逐载荷转换器选择（P0-A）— 基于 PayloadProfile 独立选择
- Fallback 链增强（P0-B）— 每个回退项附加 converter_override
- 转换器三阶段过滤（OWASP + 语言 + 技术）
- 对抗 LLM 不可用时自动降级

**审查结论**: 攻击组合适配已达到 L4 优化级，两层选择 + Fallback 增强的设计在业界属于领先水平。逐载荷转换器选择避免了"全局统一转换器"的粗粒度问题。

#### 阶段 4: 评分器策略 — ⚠️ 良好但有差距 (L3)

**已实现**:
- ASI/LLM 类别 → 评分器类型自动映射（20 类别）
- 外部 LLM 评分器后端支持（CLI/环境变量/配置文件三级优先级）
- 对抗性配置构建（Crescendo/TAP 需要 adversarial LLM）
- LLM 后端 vs 规则评分器自动区分

**关键差距**:
- ⚠️ **缺少多评分器集成投票**: 当前每个攻击仅使用单个评分器。应支持多评分器并行判定 + 多数投票
- ⚠️ **缺少语义评分器**: refusal/substring/category 均为基础评分器，缺少 `SelfAskScorer` 的语义级判定（如"是否泄露了敏感信息"的语义判断）
- ⚠️ **缺少评分器置信度**: 评分结果仅 bypass/blocked 二值，缺少置信度分数

**建议** (见 §6):
- REV-4: 实现 `EnsembleScorer` 多评分器集成投票
- REV-5: 为关键类别（LLM02/LLM06/LLM08）增加语义评分器
- REV-6: 评分结果增加 confidence 字段

#### 阶段 5: PyRIT 原生执行 — ✅ 优秀 (L4)

**已实现**:
- 6 种 PyRIT 原生攻击类型完整集成
- RateController 并发控制（信号量 + 速率限制 + 目标类型默认值）
- Fallback 执行链（主策略失败 → 回退链逐项尝试）
- 早停机制（连续失败 ≥ 5 次跳过剩余载荷）
- 异步执行（asyncio.gather + RateController）

**审查结论**: 执行阶段充分利用了 PyRIT 原生能力（重试/升级/回退/剪枝/早停），未重复造轮子。RateController 的目标类型默认值设计合理。

#### 阶段 6: 反馈与优化 — ✅ 优秀 (L4)

**已实现**:
- FeedbackAnalyzer 成功率分析 + 最优策略推荐
- PayloadMutator 变异生成（paraphrase + tone_shift）
- _compute_best_combinations Top-10 高成功率组合
- 反馈数据可导出（JSON/Markdown）

**审查结论**: 反馈闭环是本框架的差异化优势，多数同类工具不具备变异生成能力。

#### 阶段 7: 报告生成 — ⚠️ 良好但有差距 (L3)

**已实现**:
- 9 段 OffSec 标准报告结构
- Markdown + HTML 双格式
- 严重度自动计算（catalog severity + 成功率推算）
- 标题自动生成（OWASP 技术 → 中文标题）
- 证据收集（JSON 格式）

**关键差距**:
- ⚠️ **缺少 CVSS 量化评分**: 报告使用 critical/high/medium/low 定性评级，缺少 CVSS 3.1 数值评分
- ⚠️ **MITRE ATLAS 映射不完整**: 报告中仅部分 finding 包含 ATLAS ID，应全量映射
- ⚠️ **缺少攻击链可视化**: 报告有"Attack Path Visualization"段但仅文本描述，缺图形化展示
- ⚠️ **缺少修复优先级排序**: Remediation 段未按 ROI（修复成本/风险降低）排序

**建议** (见 §6):
- REV-7: 报告增加 CVSS 3.1 评分
- REV-8: 全量 MITRE ATLAS 映射
- REV-9: 攻击链 Mermaid/Graphviz 图形化
- REV-10: Remediation 增加 ROI 排序

---

## 4. AI 红队最佳实践对齐分析

### 4.1 对标 Microsoft AI Red Team

| 实践 | Microsoft AI Red Team | 本框架 | 对齐度 |
|------|----------------------|--------|--------|
| 载荷 ASR 基线 | 维护载荷 ASR 数据库 | ✅ 632 载荷全标注 ASR | 95% |
| Skeleton Key 攻击 | 首次披露并测试 | ✅ 6 变体覆盖 | 100% |
| 多模态攻击 | 图像/PDF/音频 | ✅ FigStep-V2 + PDF + 音频 | 90% |
| 渐进式攻击 | Crescendo | ✅ CrescendoAttack + Fallback | 95% |
| 反馈闭环 | 迭代优化载荷 | ✅ FeedbackAnalyzer + Mutator | 85% |
| 风险评估 | DREAD 模型 | ⚠️ 仅 critical/high/medium/low | 60% |

### 4.2 对标 Anthropic 安全研究

| 实践 | Anthropic | 本框架 | 对齐度 |
|------|-----------|--------|--------|
| Many-Shot 越狱 | 首次研究并披露 | ✅ 11 变体 (8-256 shot) | 100% |
| BoN 越狱 | 首次研究 | ✅ 6 变体 (N=256-1024) | 95% |
| Constitutional AI | 内部防御 | ⚠️ 仅攻击侧，无防御测试 | 30% |
| 有害性分类 | TTSC 分类法 | ⚠️ 未实现 | 20% |

### 4.3 对标 OWASP 红队指南

| 实践 | OWASP 指南 | 本框架 | 对齐度 |
|------|-----------|--------|--------|
| LLM Top 10 覆盖 | 全 10 类 | ✅ 82 文件 / 632 载荷 | 100% |
| Agentic Top 10 覆盖 | 全 10 类 | ✅ 10 文件 / 108 载荷 | 100% |
| 信任边界分析 | Who/What/Proof 三问 | ⚠️ 部分实现 | 50% |
| 最小权限测试 | Agent 权限边界 | ✅ ASI01-10 覆盖 | 85% |
| 可观测性测试 | 审计日志完整性 | ⚠️ 未专门覆盖 | 40% |

### 4.4 对标 MITRE ATLAS

| ATLAS 战术 | 本框架覆盖 | 载荷数 |
|------------|-----------|--------|
| Reconnaissance | ✅ AIMAP 协议探测 | - |
| Resource Development | ✅ 载荷库准备 | 632 |
| Initial Access | ✅ 直接/间接注入 | 45+ |
| Execution | ✅ 代码执行载荷 | 15+ |
| Persistence | ✅ 记忆投毒 | 11+ |
| Defense Evasion | ✅ 编码绕过/角色扮演 | 80+ |
| Discovery | ✅ 系统提示提取 | 12+ |
| Collection | ✅ 数据渗出 | 10+ |
| ML Impact | ✅ 模型 DoS | 5+ |

> **对齐度总评**: 85% — 在攻击战术层面高度对齐 ATLAS，但缺少防御侧（Detection/Recovery）测试。

---

## 5. 关键差距识别

### 5.1 差距优先级矩阵

| 编号 | 差距 | 领域 | 影响 | 复杂度 | 优先级 | 状态 |
|------|------|------|------|--------|--------|------|
| GAP-1 | 侦察→载荷过滤闭环缺失 | 管线 | 高 | 中 | P0 | ✅ 已完成 (REV-1) |
| GAP-2 | ASR-aware 载荷排序未实现 | 载荷 | 高 | 中 | P0 | ✅ 已完成 (REV-2) |
| GAP-3 | 多评分器集成投票缺失 | 评分 | 中 | 高 | P1 | 待实施 |
| GAP-4 | CVSS 量化评分缺失 | 报告 | 中 | 低 | P1 | 待实施 |
| GAP-5 | MITRE ATLAS 全量映射缺失 | 报告 | 中 | 低 | P1 | 待实施 |
| GAP-6 | 模型特定载荷选择缺失 | 载荷 | 中 | 中 | P1 | 待实施 |
| GAP-7 | 攻击链图形化可视化缺失 | 报告 | 低 | 中 | P2 | 待实施 |
| GAP-8 | 语义评分器不足 | 评分 | 中 | 高 | P2 | 待实施 |
| GAP-9 | 可观测性测试缺失 | 侦察 | 低 | 高 | P2 | 待实施 |
| GAP-10 | 修复优先级 ROI 排序缺失 | 报告 | 低 | 低 | P3 | 待实施 |

### 5.2 差距详细分析

#### GAP-1: 侦察→载荷过滤闭环缺失 ✅ 已完成 (REV-1)

**现状**: ~~侦察阶段已能检测攻击面~~ 已于 v3.4 实施 REV-1 PayloadFilter，基于 `surfaces` 字段自动过滤不相关 OWASP 类别。

**实施方案**: 
- 新增 `pyrit_ai300/payloads/payload_filter.py`
- OWASP_SURFACE_MAP 映射表（20 个 OWASP ID → 所需攻击面）
- 集成于 `execute_attack()` 和 `build_attack_list_from_refs()`
- 预期减少 30-50% 无效 API 调用

详见: [rev1_rev2_implementation.md](./rev1_rev2_implementation.md)

#### GAP-2: ASR-aware 载荷排序未实现 ✅ 已完成 (REV-2)

**现状**: ~~载荷已标注 ASR 基线但未利用~~ 已于 v3.4 实施 REV-2 ASRRanker，基于目标模型 ASR 降序排序载荷。

**实施方案**: 
- 新增 `pyrit_ai300/payloads/asr_ranker.py`
- 模型名称归一化 + 家族前缀匹配 + 时间衰减权重
- 集成于 `_execute_smart_match_v3()` 和 `_execute_chain_v3()`
- 预期高 ASR 载荷优先执行，效率提升 2x

详见: [rev1_rev2_implementation.md](./rev1_rev2_implementation.md)

#### GAP-3: 多评分器集成投票缺失

**现状**: 每个攻击仅使用单个评分器（refusal/substring/category/true_false）。

**影响**:
- 单评分器可能误判（如 substring 评分器无法检测语义绕过）
- 关键 finding 缺少交叉验证

**建议实现**:
```python
class EnsembleScorer:
    def score(self, response, scorers: List[Scorer]) -> ScoreResult:
        results = [s.score(response) for s in scorers]
        # 多数投票
        bypass_votes = sum(1 for r in results if r.label == "bypass")
        confidence = bypass_votes / len(results)
        return ScoreResult(label="bypass" if confidence > 0.5 else "blocked",
                          confidence=confidence)
```

#### GAP-4: CVSS 量化评分缺失

**现状**: 报告仅使用 critical/high/medium/low 定性评级。

**影响**:
- 无法进行风险量化比较
- 不符合业界安全报告标准

**建议**: 在 ReportGenerator 中增加 CVSS 3.1 评分计算，基于攻击向量/复杂度/权限要求/用户交互/影响范围/机密性/完整性/可用性 8 维计算。

---

## 6. 优化建议与路线图

### 6.1 优化项汇总

| 编号 | 优化项 | 关联差距 | 优先级 | 预期收益 | 实施复杂度 | 状态 |
|------|--------|---------|--------|---------|-----------|------|
| REV-1 | 侦察→载荷过滤闭环 | GAP-1 | P0 | 减少 30-50% 无效测试 | 中 | ✅ 已完成 |
| REV-2 | ASR-aware 载荷排序 | GAP-2 | P0 | 高 ASR 载荷优先执行，提速 2x | 中 | ✅ 已完成 |
| REV-3 | 模型特定载荷选择 | GAP-6 | P1 | 提升 10-15% ASR | 中 | 待实施 |
| REV-4 | 多评分器集成投票 | GAP-3 | P1 | 减少 20% 误判 | 高 | 待实施 |
| REV-5 | 语义评分器增强 | GAP-8 | P1 | 提升 LLM02/06/08 判定精度 | 高 | 待实施 |
| REV-6 | CVSS 3.1 评分 | GAP-4 | P1 | 报告量化合规 | 低 | 待实施 |
| REV-7 | MITRE ATLAS 全量映射 | GAP-5 | P1 | 报告标准化 | 低 | 待实施 |
| REV-8 | 攻击链图形化 | GAP-7 | P2 | 报告可视化 | 中 | 待实施 |
| REV-9 | 可观测性测试 | GAP-9 | P2 | 覆盖审计日志攻击面 | 高 | 待实施 |
| REV-10 | 修复 ROI 排序 | GAP-10 | P3 | 修复建议可执行性 | 低 | 待实施 |

### 6.2 实施路线图

#### Phase 1 (P0) — 闭环优化，2-3 天

**REV-1: 侦察→载荷过滤闭环**
- 新增 `pyrit_ai300/payloads/payload_filter.py`
- 实现 `PayloadFilter.filter_by_profile()` 方法
- OWASP ID → 所需攻击面映射表
- 在 AttackOrchestrator 中集成：加载载荷后、执行前过滤
- 预期：减少 30-50% 无效 API 调用

**REV-2: ASR-aware 载荷排序**
- 新增 `pyrit_ai300/payloads/asr_ranker.py`
- 实现 `ASRRanker.rank_by_target_model()` 方法
- 从 `payload_metadata.asr_baseline` 提取目标模型 ASR
- 在 PayloadManager 中集成：加载后按 ASR 降序排序
- 预期：高 ASR 载荷优先执行，早停时低 ASR 载荷被跳过

#### Phase 2 (P1) — 精度提升，3-5 天

**REV-3: 模型特定载荷选择**
- 侦察检测到 model_family 后，选择该家族最优载荷变体
- 维护 `data/owasp/_model_optimal.yaml` 模型→载荷映射

**REV-4: 多评分器集成投票**
- 新增 `pyrit_ai300/orchestrators/ensemble_scorer.py`
- 支持 2-3 个评分器并行判定 + 多数投票
- 关键类别（LLM01/LLM02/LLM06）默认启用集成

**REV-5: CVSS 3.1 评分**
- 在 ReportGenerator 中增加 CVSS 计算模块
- 基于 OWASP 类别 + 攻击成功率自动计算 CVSS
- 报告中增加 CVSS 向量字符串和数值

**REV-6: MITRE ATLAS 全量映射**
- 新增 `data/owasp/_atlas_mapping.yaml` OWASP→ATLAS 映射表
- 报告中每个 finding 自动附加 ATLAS 战术/技术 ID

#### Phase 3 (P2) — 可视化与深度，3-5 天

**REV-7: 攻击链图形化**
- 报告中增加 Mermaid 流程图
- 展示：载荷→转换器→攻击策略→评分结果 完整路径

**REV-8: 语义评分器增强**
- 为 LLM02/LLM06/LLM08 增加 SelfAskScorer
- 语义判定"是否泄露了敏感信息/系统提示/嵌入数据"

**REV-9: 可观测性测试**
- 新增侦察探测项：审计日志完整性、行为基线监控
- 映射 OWASP Agentic "Strong Observability" 原则

#### Phase 4 (P3) — 精细化，2-3 天

**REV-10: 修复 ROI 排序**
- Remediation 段按 ROI（风险降低/修复成本）排序
- 高 ROI 修复建议优先展示

### 6.3 预期收益

| 指标 | 当前 | 优化后(P0+P1) | 提升 |
|------|------|-------------|------|
| 无效测试比例 | ~40% | ~15% | -62% |
| 高 ASR 载荷优先级 | 无排序 | ASR 降序 | 2x 提速 |
| 评分误判率 | ~20% | ~10% | -50% |
| 报告合规度 | OffSec 基础 | +CVSS+ATLAS | 90% |
| 整体 ASR | 50-75% | 60-80% | +10% |
| 管线闭环度 | L3.8 | L4.5 | +18% |

---

## 7. 结论

### 7.1 架构评估总结

AI-300 框架在数据驱动架构设计上已达到 **L4.2/L5** 的成熟度（v3.4 更新），P0 级闭环优化已完成，具备以下核心竞争力：

1. **完整的端到端管线**: 从侦察到报告的 7 阶段全链路闭环，20 个追踪 stage
2. **ASR 驱动的载荷库**: 632 个载荷全标注 ASR 基线，Top-5 ASR ≥ 90%
3. **两层策略选择 + Fallback 增强**: 兼顾速度与精度的攻击组合适配
4. **侦察→载荷闭环 (v3.4 新增)**: PayloadFilter 基于攻击面自动过滤不相关载荷
5. **ASR-aware 排序 (v3.4 新增)**: ASRRanker 按目标模型 ASR 降序排序，高 ASR 优先
6. **反馈闭环 + 变异生成**: 差异化于同类工具的自动优化能力
7. **19 项侦察优化**: AIMAP/Garak/DeepTeam 三工具深度集成

### 7.2 核心改进方向

实现 P0-P1 优化后，架构成熟度可提升至 **L4.5/L5**，关键改进：

- **闭环化**: 侦察→载荷过滤→攻击→评分→反馈 全链路自动闭环
- **精准化**: ASR 排序 + 模型特定选择 + 多评分器集成
- **合规化**: CVSS 量化 + ATLAS 全量映射 + OffSec 标准报告

### 7.3 与业界对标

| 对标维度 | 当前对齐度 | P0+P1 后 | 说明 |
|---------|-----------|---------|------|
| Microsoft AI Red Team | 85% | 92% | +载荷过滤闭环 |
| Anthropic 安全研究 | 75% | 85% | +ASR 排序 |
| OWASP 红队指南 | 80% | 90% | +可观测性测试 |
| MITRE ATLAS | 85% | 95% | +全量映射 |
| OffSec 报告标准 | 75% | 90% | +CVSS+图形化 |

### 7.4 最终建议

本架构已具备 **生产级 AI 红队评估能力**，建议按 P0→P1→P2→P3 路线图持续优化，优先实现 **REV-1（载荷过滤闭环）** 和 **REV-2（ASR 排序）** 两项 P0 优化，预期可将管线效率提升 2 倍，无效测试减少 62%。

---

> **文档结束**
> 本审查报告基于 2026-07-19 架构状态，关联文档：
> - [ARCHITECTURE.md](./ARCHITECTURE.md) — 架构设计文档
> - [payload_optimization_implementation.md](./payload_optimization_implementation.md) — 载荷优化实施报告
> - [recon_optimization_implementation.md](./recon_optimization_implementation.md) — 侦察优化实施报告
> - [pipeline_attack_flow.md](./pipeline_attack_flow.md) — 攻击管线流程
> - [pipeline_recon_flow.md](./pipeline_recon_flow.md) — 侦察管线流程
