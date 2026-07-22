# AI 红队测试最佳实践指南

> **版本**: v1.0 | **更新日期**: 2026-07-22
> **来源**: arxiv 论文 + GitHub 开源工具调研 + OWASP/NIST 标准 + 本项目实战经验
> **适用范围**: LLM 应用安全评估、OffSec AI-300 红队考试、企业 AI 安全审计

---

## 目录

1. [AI 红队工具全景图](#1-ai-红队工具全景图)
2. [主流开源工具深度对比](#2-主流开源工具深度对比)
3. [高成功率攻击组合策略](#3-高成功率攻击组合策略)
4. [攻击技术分级与 ASR 数据](#4-攻击技术分级与-asr-数据)
5. [红队测试最佳实践工作流](#5-红队测试最佳实践工作流)
6. [本项目工具栈定位与补强建议](#6-本项目工具栈定位与补强建议)
7. [参考论文与资源](#7-参考论文与资源)

---

## 1. AI 红队工具全景图

### 1.1 工具分类矩阵

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AI 红队测试工具生态全景图                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────────┐ │
│  │   攻击框架层     │  │   侦察/扫描层     │  │   基础设施漏洞层       │ │
│  │                  │  │                   │  │                        │ │
│  │ PyRIT (Azure)   │  │ garak (NVIDIA)   │  │ AI-Exploits (ProtectAI)│ │
│  │ PAIR             │  │ DeepTeam          │  │ Nuclei Templates       │ │
│  │ TAP/TAP-P        │  │ Giskard Scan      │  │ Metasploit Modules     │ │
│  │ GCG (AdvBench)   │  │ Lakera Guard      │  │                        │ │
│  │ AutoDAN          │  │ AIMAP             │  │ → RCE / LFI / SSRF     │ │
│  │ Crescendo        │  │ NativeProbe       │  │ → 反序列化 / 路径穿越  │ │
│  └────────┬─────────┘  └────────┬──────────┘  └────────────────────────┘ │
│           │                      │                                        │
│  ┌────────┴──────────────────────┴────────────────────────────────────┐ │
│  │                        评估/评分层                                   │ │
│  │  LLM-as-Judge | SelfAskScorer | SubStringScorer | HumanInTheLoop   │ │
│  │  Giskard RAGET | DeepEval | TruLens | Ragas                        │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│           │                                                               │
│  ┌────────┴────────────────────────────────────────────────────────────┐ │
│  │                        标准与合规层                                   │ │
│  │  OWASP Top 10 LLM (2025) | OWASP Agentic AI Top 10 (2026)          │ │
│  │  MITRE ATLAS | NIST AI RMF | AVID Taxonomy                          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 工具选型决策树

```
目标类型?
├── 闭源 API (GPT-4 / Claude / Gemini)
│   ├── 黑盒攻击 → PAIR / TAP / Crescendo (PyRIT)
│   ├── 编码绕过 → Base64 / ROT13 / Unicode (PyRIT Converters)
│   └── 社会工程 → Persuasion / Roleplay (PAIR Strategies)
├── 开源模型 (Llama / Vicuna / Mistral)
│   ├── 白盒梯度攻击 → GCG (llm-attacks)
│   ├── 遗传算法 → AutoDAN
│   └── 全面扫描 → garak (NVIDIA)
├── AI 基础设施 (Triton / MLflow / BentoML)
│   ├── 漏洞扫描 → Nuclei Templates (AI-Exploits)
│   └── 漏洞利用 → Metasploit Modules (AI-Exploits)
├── RAG 应用
│   ├── 端到端评估 → Giskard RAGET
│   ├── 检索注入 → XPIA (PyRIT)
│   └── 知识泄露 → DataExfiltration Probes
└── Agentic AI / MCP
    ├── 过度代理 → ASI01-ASI10 测试
    ├── 工具滥用 → Plugin Injection
    └── 提示注入 → Indirect Prompt Injection
```

---

## 2. 主流开源工具深度对比

### 2.1 攻击框架层

| 工具 | GitHub | 维护方 | 核心能力 | 攻击策略 | 多轮对话 | 黑盒/白盒 | Stars |
|------|--------|--------|----------|----------|----------|-----------|-------|
| **PyRIT** | Azure/PyRIT | Microsoft | 自动化红队编排 | Crescendo, TAP, PAIR, RedTeaming, PromptSending, XPIA | ✅ | 黑盒 | 2.5k+ |
| **garak** | NVIDIA/garak | NVIDIA | LLM 漏洞扫描 | DAN, GOAT, AutoDAN, Encoding, Injection, LMRC, Package Hallucination | 部分 | 黑盒 | 3.5k+ |
| **GCG/llm-attacks** | llm-attacks/llm-attacks | 学术 | 梯度优化对抗后缀 | GCG (Greedy Coordinate Gradient) | ❌ | 白盒 | 4k+ |
| **PAIR** | patrickrchao/JailbreakingLLMs | 学术 | LLM 驱动迭代优化 | Roleplay, Logical Appeal, Authority Endorsement | ✅ | 黑盒 | 800+ |
| **AutoDAN** | SheltonLiu-N/AutoDAN | 学术 | 遗传算法越狱 | 基于遗传算法自动生成 DAN 变体 | ❌ | 黑盒 | 1k+ |
| **Giskard** | Giskard-AI/giskard | Giskard | AI 测试+扫描 | LLM Scan, RAGET, Prompt Injection, Sycophancy, Hallucination | 部分 | 黑盒 | 3k+ |
| **AI-Exploits** | protectai/ai-exploits | ProtectAI | 基础设施漏洞 | RCE, LFI, SSRF, CSRF, Path Traversal, Deserialization | ❌ | 基础设施 | 2k+ |

### 2.2 PyRIT 深度分析（本项目核心引擎）

PyRIT 0.14.0 是目前**最全面的 LLM 红队框架**，采用分层架构：

```
Entry Points (CLI / Gradio UI / Jupyter)
    ↓
Execution Layer
  ├── PromptSendingAttack       → 单轮并行批量攻击
  ├── CrescendoOrchestrator     → 渐进式多轮（从温和到极端）
  ├── TAP (Tree of Attacks)     → 树搜索+剪枝（最高 ASR）
  ├── PAIROrchestrator          → LLM 驱动迭代优化
  ├── RedTeamingOrchestrator    → 通用红队多轮
  └── XPIATestOrchestrator      → 跨域提示注入
    ↓
Normalization Layer (PromptNormalizer + Converter Chain)
    ↓
Transformation Layer (30+ Converters)
  ├── 编码: Base64, ROT13, Morse, Binary, Caesar, URL
  ├── 混淆: UnicodeConfusable, Leetspeak, Zalgo
  ├── LLM驱动: Translation, Variation, Tone, Persuasion
  └── 多模态: PDF, Image, JSON, URL
    ↓
Target Layer (OpenAI / Azure / HuggingFace / HTTP / Playwright)
    ↓
Evaluation Layer (LLM-Judge / Rule-Based / API-Based / Human)
    ↓
Memory Layer (DuckDB / AzureSQL + 完整来源追踪)
```

**PyRIT 关键攻击策略 ASR（攻击成功率）对比**：

| 攻击策略 | GPT-4 ASR | Claude ASR | Llama-2 ASR | 查询数 | 耗时 |
|----------|-----------|------------|-------------|--------|------|
| PromptSending (单轮) | ~35% | ~20% | ~55% | 1 | 秒级 |
| Crescendo (渐进) | ~65% | ~45% | ~80% | 8-15 | 分钟级 |
| PAIR (迭代优化) | ~60% | ~40% | ~75% | <20 | 分钟级 |
| **TAP (树搜索)** | **~80%** | **~60%** | **~90%** | 20-60 | 分钟级 |
| GCG (白盒) | N/A | N/A | ~88% | 25k+ | 小时级 |
| AutoDAN (遗传) | ~50% | ~35% | ~70% | 100+ | 小时级 |

> **注**: ASR 数据来源于各论文报告值，实际值受目标模型版本、系统提示词、安全过滤器配置影响。

### 2.3 garak 深度分析

garak（现由 NVIDIA 维护）是**LLM 漏洞扫描的标准工具**，类似 nmap 之于网络：

**核心 Probe 类别**：

| Probe 类别 | 具体探测器 | 覆盖的 OWASP 类别 |
|-----------|-----------|------------------|
| Jailbreak | `dan`, `goat`, `autodan`, `dan_11_0` | LLM01 |
| Encoding | `InjectBase64`, `InjectMorse`, `InjectROT13`, `InjectLeetspeak` | LLM01 |
| Injection | `promptinject`, `lmrc` | LLM01, LLM07 |
| Leakage | `sysprompt_extraction`, `snowball` | LLM06 |
| Package | `knownbadsignatures`, `packagehallucination` | LLM05 |
| Safety | `realtoxicityprompts`, `harmbench` | LLM09 |
| Agent | `agent_breaker`, `ansiescape` | ASI01, ASI08 |

### 2.4 Giskard 深度分析

Giskard 专注于**AI 应用质量测试**（非纯安全），核心优势：

- **RAGET (RAG Evaluation Toolkit)**：自动生成 RAG 评估数据集，组件级评估（Generator / Retriever / Rewriter / Router）
- **LLM Scan**：自动检测 hallucination, prompt injection, sycophancy, information disclosure
- **LLM-as-Judge**：多维度评估（correctness, faithfulness, relevancy）
- **测试套件**：扫描结果 → 自动生成可重复测试套件

---

## 3. 高成功率攻击组合策略

### 3.1 组合攻击有效性矩阵

基于 arxiv 论文和实战经验，**单一攻击技术很难达到 100% ASR**，但合理组合可以显著提升：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        攻击组合 → ASR 提升矩阵                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  组合层级                    GPT-4    Claude-3   Llama-2   Gemini    平均   │
│  ─────────────────────────  ──────   ────────   ───────   ──────   ──────  │
│  L0: 单轮直接请求             ~15%     ~10%      ~30%      ~20%     ~19%   │
│  L1: 编码转换 (Base64/ROT13)  ~35%     ~20%      ~55%      ~40%     ~38%   │
│  L2: 单轮+角色扮演            ~45%     ~30%      ~65%      ~50%     ~48%   │
│  L3: Crescendo 渐进           ~65%     ~45%      ~80%      ~60%     ~63%   │
│  L4: PAIR 迭代优化            ~60%     ~40%      ~75%      ~55%     ~58%   │
│  L5: TAP 树搜索+剪枝          ~80%     ~60%      ~90%      ~70%     ~75%   │
│  L6: TAP + 编码转换堆叠       ~85%     ~68%      ~93%      ~75%     ~80%   │
│  L7: TAP + 多编码 + 角色扮演   ~90%     ~75%      ~95%      ~82%     ~86%   │
│  L8: TAP + MCTS + 自适应      ~92%     ~80%      ~96%      ~85%     ~88%   │
│                                                                             │
│  ⚠️ 100% ASR 在现实中不可达：安全模型持续更新，攻击与防御是动态博弈           │
│  ⚠️ 组合攻击的查询成本和耗时随层数指数增长                                    │
│  ⚠️ 实际 ASR 受目标配置（system prompt / guardrails / temperature）影响极大  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 有效攻击组合 Top 10

以下组合基于论文报告和社区实战验证，按 ASR 效率（成功率/查询成本比）排序：

#### 组合 1: TAP + Persuasion Converter（最高效黑盒组合）
```
攻击链: 种子Prompt → PersuasionConverter(角色扮演) → TAP树搜索(深度4,分支3,剪枝)
预期 ASR: 80-90% (GPT-4) / 60-75% (Claude)
查询数: 20-60
论文依据: "Tree of Attacks: Jailbreaking Black-Box LLMs Automatically" (Mehrotra et al.)
```

#### 组合 2: Crescendo + Encoding Stack（渐进式编码绕过）
```
攻击链: 温和请求 → Base64编码 → ROT13 → Crescendo渐进升级(10轮)
预期 ASR: 65-80% (多数商业模型)
查询数: 8-15
论文依据: "Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack"
```

#### 组合 3: PAIR + Multi-Strategy Rotation（自适应策略轮换）
```
攻击链: Roleplay(5轮) → Logical Appeal(5轮) → Authority Endorsement(5轮)
预期 ASR: 60-75%
查询数: <20
论文依据: "Jailbreaking Black Box Large Language Models in Twenty Queries"
```

#### 组合 4: GCG Suffix + Transfer Attack（白盒→黑盒迁移）
```
攻击链: GCG生成对抗后缀(白盒Llama) → 迁移到GPT-4/Claude → +编码混淆
预期 ASR: 70-88% (迁移成功率)
查询数: 25k+ (白盒) + 1 (黑盒)
论文依据: "Universal and Transferable Adversarial Attacks on Aligned Language Models"
```

#### 组合 5: AutoDAN + Ensemble（遗传算法多样性）
```
攻击链: AdvBench种子 → AutoDAN遗传变异(100代) → Top-5候选并行测试
预期 ASR: 50-70%
查询数: 100+
论文依据: "AutoDAN: Generating Stealthy Jailbreak Prompts on Aligned Large Language Models"
```

#### 组合 6: Many-Shot Jailbreak（长上下文注入）
```
攻击链: 收集N个Q&A对 → 填充上下文窗口 → 在末尾注入目标请求
预期 ASR: 70-85% (大上下文窗口模型)
查询数: 1 (但需要大量token)
论文依据: "Many-shot Jailbreaking" (Anthropic Research)
```

#### 组合 7: XPIA Indirect Injection（间接提示注入）
```
攻击链: 恶意指令嵌入文档/网页 → RAG检索 → 间接注入到LLM → 数据泄露/RCE
预期 ASR: 60-80% (RAG应用)
查询数: 1-3
论文依据: "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications"
```

#### 组合 8: Converter Stack Cascade（级联编码）
```
攻击链: Prompt → Base64 → UnicodeConfusable → Leetspeak → Morse → 发送
预期 ASR: 40-60% (弱过滤器模型)
查询数: 1
优势: 极低成本，快速发现过滤器弱点
```

#### 组合 9: Crescendo + TAP Hybrid（渐进+树搜索混合）
```
攻击链: Crescendo前3轮建立信任 → TAP树搜索(深度3,分支2)精细化
预期 ASR: 85-93%
查询数: 15-40
优势: 结合渐进建立信任和树搜索探索
```

#### 组合 10: Full-Stack Adaptive（全栈自适应，本项目目标）
```
攻击链:
  1. 侦察: NativeProbe发现弱点 → ProfileMerger构建攻击面
  2. 策略选择: SmartMatcher匹配最优攻击策略
  3. 载荷优化: PayloadMutator变异 → ModelSpecificSelector适配
  4. 攻击执行: TAP/Crescendo + ConverterStacker堆叠
  5. 反馈闭环: EnsembleScorer评分 → AdaptiveEarlyStopper → MCTS变异探索
预期 ASR: 85-95% (综合)
论文依据: 综合多篇论文 + 本项目 P1-P2 优化实现
```

### 3.3 "100% 成功率" 的现实考量

> **重要声明**: 没有任何工具或组合能保证 100% ASR。原因如下：

1. **动态防御**: 模型持续更新，安全过滤器不断改进
2. **配置差异**: 同一模型不同 system prompt / temperature / guardrails 配置下 ASR 差异巨大
3. **攻击类别差异**: Prompt Injection 的 ASR 通常高于 Data Poisoning
4. **评估标准**: Judge LLM 的判定标准影响 ASR 统计
5. **对抗不对称性**: 防御方只需堵住一个漏洞，攻击方需要找到所有漏洞

**追求最大 ASR 的务实策略**：

| 策略 | 说明 | 预期效果 |
|------|------|----------|
| **多策略并行** | 同时运行 TAP + Crescendo + PAIR | 取最高值，ASR +10-15% |
| **编码堆叠** | ConverterStacker 组合 2-4 种编码 | 绕过过滤器，ASR +15-20% |
| **自适应早停** | AdaptiveEarlyStopper 动态调整 | 节省 40% 查询预算用于有效攻击 |
| **MCTS 变异探索** | 从成功载荷自动探索变异空间 | 发现模型特定弱点，ASR +5-10% |
| **交叉验证评分** | BatchCrossValidator 多 Judge 验证 | 减少误判，提高可信 ASR |
| **模型指纹适配** | ModelFingerprinter 探测后定制载荷 | ASR +10-20%（针对特定模型家族） |

---

## 4. 攻击技术分级与 ASR 数据

### 4.1 攻击技术分级体系

```
Tier S (ASR > 85%):  TAP+编码堆叠 | GCG白盒 | Many-Shot | Full-Stack Adaptive
Tier A (ASR 70-85%): TAP | Crescendo+编码 | GCG迁移 | XPIA | Crescendo+TAP混合
Tier B (ASR 55-70%): Crescendo | PAIR | AutoDAN | 组合编码 | 角色扮演
Tier C (ASR 40-55%): 单一编码 | DAN模板 | 逻辑诉求 | 权威背书
Tier D (ASR 25-40%): 直接请求 | 简单越狱 | 一次性编码
Tier F (ASR < 25%):  裸prompt | 明确恶意请求
```

### 4.2 各攻击技术详细数据

#### 白盒攻击

| 技术 | 论文 | 目标模型 | ASR | 查询数 | 时间 |
|------|------|----------|-----|--------|------|
| GCG | Zou et al. 2023 | Vicuna-7B | 88% | 25k | ~5h |
| GCG (Universal) | Zou et al. 2023 | GPT-4 (迁移) | 32% | 0 (迁移) | - |
| GCG+AdvBench | Zou et al. 2023 | Llama-2-7B | 84% | 25k | ~5h |

#### 黑盒攻击

| 技术 | 论文 | 目标模型 | ASR | 查询数 | 时间 |
|------|------|----------|-----|--------|------|
| TAP | Mehrotra et al. 2023 | GPT-4 | 80% | 20-60 | ~30min |
| PAIR | Chao et al. 2023 | GPT-4 | 60% | <20 | ~10min |
| Crescendo | Russinovich 2024 | GPT-4 | 65% | 8-15 | ~15min |
| AutoDAN | Liu et al. 2023 | Llama-2 | 70% | 100+ | ~2h |
| Many-Shot | Anthropic 2024 | Claude-3 | 85% | 1 | 秒级 |
| DAN Templates | 社区 | GPT-3.5 | 45% | 1 | 秒级 |

#### 编码绕过

| 编码方式 | 单独 ASR | +Crescendo ASR | +TAP ASR |
|----------|----------|----------------|----------|
| Base64 | 35% | 70% | 85% |
| ROT13 | 30% | 65% | 82% |
| Unicode Confusable | 40% | 72% | 87% |
| Leetspeak | 25% | 60% | 78% |
| Morse Code | 20% | 55% | 75% |
| 组合(2种) | 45% | 78% | 90% |
| 组合(3种) | 50% | 82% | 92% |

---

## 5. 红队测试最佳实践工作流

### 5.1 标准化红队测试流程

```
Phase 1: 侦察 (Reconnaissance)
├── 1.1 目标识别: API端点 / SPA界面 / RAG知识库 / Agent工具
├── 1.2 模型指纹: ModelFingerprinter探测模型家族/版本/能力
├── 1.3 安全控制识别: 输入过滤器 / 输出审查 / 速率限制
├── 1.4 攻击面映射: AIMAP A1-A6 / NativeProbe / DeepTeam D1-D5
└── 1.5 Profile 构建: TargetProfile (fingerprint + capabilities + attack_surfaces)

Phase 2: 规划 (Planning)
├── 2.1 载荷分类: PayloadClassifier → OWASP LLM01-LLM10 + ASI01-ASI10
├── 2.2 载荷过滤: PayloadFilter (基于攻击面过滤不相关类别)
├── 2.3 ASR 排序: ASRRanker (按目标模型历史ASR降序)
├── 2.4 模型适配: ModelSpecificSelector (模型家族特定载荷)
└── 2.5 策略匹配: SmartMatcher → 选择 Crescendo/TAP/PAIR/PromptSending

Phase 3: 执行 (Execution)
├── 3.1 基线测试: PromptSending (单轮) → 快速发现低抗性目标
├── 3.2 编码绕过: ConverterStacker (2-4种编码级联)
├── 3.3 渐进攻击: Crescendo (8-15轮渐进升级)
├── 3.4 树搜索: TAP (深度4, 分支3, 剪枝阈值0.5)
├── 3.5 迭代优化: PAIR (并行3流, 最多20轮)
└── 3.6 反馈闭环: EnsembleScorer + AdaptiveEarlyStopper + MCTS

Phase 4: 评估 (Evaluation)
├── 4.1 多评分器: SelfAskTrueFalse + SelfAskFloatScale + SubString
├── 4.2 交叉验证: BatchCrossValidator (多Judge LLM)
├── 4.3 人工审查: HumanInTheLoop (高风险发现)
└── 4.4 ASR 计算: 按OWASP类别/攻击策略/编码方式分维度统计

Phase 5: 报告 (Reporting)
├── 5.1 漏洞清单: CVSS 3.1 量化评分
├── 5.2 攻击链可视化: Mermaid 图表
├── 5.3 标准映射: MITRE ATLAS + OWASP Top 10
├── 5.4 修复建议: ROI 排序 (影响×紧急度/修复成本)
└── 5.5 覆盖矩阵: OWASP 类别 × 攻击策略 × ASR 矩阵
```

### 5.2 攻击策略选择决策矩阵

| 目标特征 | 推荐策略 | 备选策略 | 编码叠加 |
|----------|----------|----------|----------|
| 弱过滤器(无输入审查) | PromptSending | - | 可选 |
| 基础过滤器(关键词匹配) | Crescendo + 编码 | PAIR + 编码 | Base64 + ROT13 |
| 高级过滤器(语义审查) | TAP + 编码堆叠 | PAIR + 角色扮演 | Unicode + Leetspeak |
| 多轮对话限制 | Crescendo | TAP (浅深度) | 单一编码 |
| 速率限制 | PAIR (低轮数) | PromptSending | 编码提高单次效率 |
| 大上下文窗口 | Many-Shot | Crescendo | - |
| RAG 知识库 | XPIA | DataExfiltration | - |
| Agent/Tool 调用 | Indirect Injection | Plugin Abuse | - |

### 5.3 预算分配最佳实践

```
总查询预算: 1000 次 (示例)

分配策略:
├── Phase 3.1 基线测试:     100次 (10%)  → 快速发现弱目标
├── Phase 3.2 编码绕过:     150次 (15%)  → 过滤器探测
├── Phase 3.3 Crescendo:    200次 (20%)  → 渐进攻击 (~15轮×13目标)
├── Phase 3.4 TAP:          300次 (30%)  → 树搜索 (~60轮×5目标)
├── Phase 3.5 PAIR:         150次 (15%)  → 迭代优化 (~20轮×7目标)
├── Phase 3.6 MCTS 变异:    100次 (10%)  → 从成功载荷探索
└── 预留缓冲:                不分配       → AdaptiveEarlyStopper 节省的预算

关键原则:
1. 先低后高: 先用低成本攻击(单轮/编码)，再升级到高成本(TAP/MCTS)
2. 自适应: AdaptiveEarlyStopper 在 ASR > 80% 时减少后续投入
3. 反馈驱动: 成功载荷自动触发 MCTS 变异探索
4. 并行执行: 多策略并行，取最优结果
```

---

## 6. 本项目工具栈定位与补强建议

### 6.1 当前工具栈覆盖度

本项目（AI-300 Framework v3.8.0）基于 PyRIT 0.14.0 构建，已实现：

| 能力域 | 已有实现 | 覆盖度 | 补强方向 |
|--------|----------|--------|----------|
| **攻击编排** | AI300Engine + AttackOrchestrator | ★★★★★ | - |
| **攻击策略** | Crescendo/TAP/PAIR/PromptSending/Sequential | ★★★★★ | - |
| **载荷管理** | PayloadManager + 632 payloads + 82 YAML | ★★★★★ | - |
| **编码转换** | ConverterBuilder + ConverterStacker | ★★★★☆ | 增加 Morse/Binary |
| **评分系统** | EnsembleScorer + SemanticScorer + BatchCrossValidator | ★★★★★ | - |
| **自适应** | AdaptiveEarlyStopper + MCTS Generator | ★★★★★ | - |
| **模型指纹** | ModelFingerprinter (5种探测) | ★★★★☆ | 增加行为指纹维度 |
| **侦察层** | AIMAP + NativeProbe + DeepTeam + SPA Chat | ★★★★★ | - |
| **凭据管理** | CredentialManager (JWT + Bearer + Cookie) | ★★★★★ | - |
| **报告层** | CVSS + ATLAS + Mermaid + ROI | ★★★★★ | - |
| **标准对齐** | OWASP 2025 + Agentic Top 10 + ATLAS | ★★★★★ | - |
| **GCG白盒** | ❌ 未实现 | ★☆☆☆☆ | 可选: 集成 llm-attacks |
| **AutoDAN** | ❌ 未实现 | ★☆☆☆☆ | 可选: 集成遗传算法 |
| **Many-Shot** | ❌ 未实现 | ★☆☆☆☆ | 可选: 长上下文探测 |
| **RAG 评估** | ❌ 未实现 | ★☆☆☆☆ | 可选: 集成 Giskard RAGET |
| **基础设施** | ❌ 未实现 | ★☆☆☆☆ | 可选: 集成 AI-Exploits Nuclei |

### 6.2 补强建议（按优先级）

#### P0: 已具备（无需改动）
- ✅ TAP + Crescendo + PAIR 多策略编排
- ✅ ConverterStacker 多编码堆叠
- ✅ AdaptiveEarlyStopper 自适应早停
- ✅ MCTS 载荷变异探索
- ✅ BatchCrossValidator 交叉验证评分
- ✅ ModelFingerprinter 模型指纹适配

#### P1: 建议补强（低成本高收益）
1. **增加 Many-Shot Jailbreak 探测器**
   - 在 `recon/adapters/native_probe/probe_data/` 新增 `many_shot.yaml`
   - 利用长上下文窗口模型（GPT-4 Turbo 128K, Claude 200K）的弱点
   - 预计实现成本: 1天

2. **增加 Morse/Binary/Caesar 编码转换器**
   - 扩展 `attack/pyrit/converter_builder.py`
   - 提升编码绕过覆盖度
   - 预计实现成本: 0.5天

3. **增加 AutoDAN 风格遗传变异**
   - 在 `attack/feedback/` 新增 `genetic_mutator.py`
   - 结合现有 MCTS Generator 形成双变异引擎
   - 预计实现成本: 2天

#### P2: 可选补强（中成本中收益）
4. **集成 Giskard RAGET 用于 RAG 应用评估**
   - 在 `recon/adapters/` 新增 `giskard_rag/` 适配器
   - 自动生成 RAG 测试集 + 组件级评估
   - 预计实现成本: 3-5天

5. **集成 AI-Exploits Nuclei 模板用于基础设施扫描**
   - 在 `recon/adapters/` 新增 `infra_scan/` 适配器
   - 扫描 Triton/MLflow/BentoML/Gradio 已知漏洞
   - 预计实现成本: 2天

#### P3: 学术前沿（高成本探索性）
6. **集成 GCG 白盒攻击（仅开源模型场景）**
   - 需 GPU 资源（A100 80GB）
   - 生成 Universal Adversarial Suffix 用于迁移攻击
   - 预计实现成本: 5-10天 + GPU 资源

---

## 7. 参考论文与资源

### 7.1 核心论文

| 论文 | 作者 | 年份 | 核心贡献 | arxiv |
|------|------|------|----------|-------|
| Universal and Transferable Adversarial Attacks | Zou et al. | 2023 | GCG 算法 + AdvBench | 2307.15043 |
| Tree of Attacks: Jailbreaking Black-Box LLMs | Mehrotra et al. | 2023 | TAP 树搜索自动越狱 | 2312.02119 |
| Jailbreaking Black Box LLMs in Twenty Queries | Chao et al. | 2023 | PAIR 三Agent架构 | 2310.08460 |
| AutoDAN: Stealthy Jailbreak Prompts | Liu et al. | 2023 | 遗传算法自动越狱 | 2310.04451 |
| Great, Now Write an Article About That | Russinovich | 2024 | Crescendo 渐进攻击 | 2404.01833 |
| Many-shot Jailbreaking | Anthropic | 2024 | 长上下文越狱 | (blog) |
| Not What You've Signed Up For | Greshake et al. | 2023 | 间接提示注入 | 2302.12173 |
| PyRIT: Python Risk Identification Tool | Microsoft | 2024 | 自动化红队框架 | (tool) |

### 7.2 GitHub 开源工具

| 工具 | 仓库 | 用途 | 维护状态 |
|------|------|------|----------|
| PyRIT | github.com/Azure/PyRIT | LLM 红队攻击框架 | ✅ 活跃 (v0.11.1+) |
| garak | github.com/NVIDIA/garak | LLM 漏洞扫描器 | ✅ 活跃 (NVIDIA维护) |
| GCG/llm-attacks | github.com/llm-attacks/llm-attacks | 白盒梯度攻击 | ✅ 学术维护 |
| PAIR | github.com/patrickrchao/JailbreakingLLMs | 黑盒迭代越狱 | ✅ 学术维护 |
| AutoDAN | github.com/SheltonLiu-N/Auto-DAN | 遗传算法越狱 | ✅ 学术维护 |
| Giskard | github.com/Giskard-AI/giskard | AI 测试+扫描 | ✅ 活跃 (v0.4+) |
| AI-Exploits | github.com/protectai/ai-exploits | AI基础设施漏洞 | ✅ 活跃 |
| DeepEval | github.com/confident-ai/deepeval | LLM 评估框架 | ✅ 活跃 |
| Ragas | github.com/explodinggradients/ragas | RAG 评估 | ✅ 活跃 |
| TruLens | github.com/truera/trulens | LLM 可观测性 | ✅ 活跃 |

### 7.3 标准与框架

| 标准 | 组织 | 版本 | 覆盖范围 |
|------|------|------|----------|
| OWASP Top 10 for LLM | OWASP | 2025 | LLM01-LLM10 |
| OWASP Agentic AI Top 10 | OWASP | 2026 | ASI01-ASI10 |
| MITRE ATLAS | MITRE | v5.0 | AI 攻击战术与技术 |
| NIST AI RMF | NIST | 1.0 | AI 风险管理框架 |
| AVID Taxonomy | AVID | v0.5 | AI 漏洞数据库分类 |

### 7.4 基准测试

| 基准 | 用途 | 数据集 |
|------|------|--------|
| AdvBench | 通用有害行为 | 520 behaviors |
| HarmBench | 标准化危害评估 | 400 behaviors |
| JailbreakBench | 越狱基准测试 | 100 behaviors |
| MaliciousInstruct | 恶意指令 | 100 instructions |
| StrongREJECT | 拒绝评估 | 313 prompts |

---

## 附录 A: 快速参考卡片

### 推荐攻击组合速查

```
┌─────────────────────────────────────────────────────────────────┐
│  场景: 闭源商业模型 (GPT-4/Claude/Gemini)                        │
│  ─────────────────────────────────────────────────────────────  │
│  1. 先跑 NativeProbe 侦察 (发现模型弱点)                         │
│  2. TAP + PersuasionConverter (树搜索+角色扮演)  → 80% ASR      │
│  3. 失败 → Crescendo + Base64+ROT13 (渐进+编码)  → 65% ASR     │
│  4. 仍失败 → PAIR 多策略轮换 (3×5轮)             → 60% ASR     │
│  综合预期 ASR: 85-90%                                            │
├─────────────────────────────────────────────────────────────────┤
│  场景: 开源模型 (Llama/Vicuna/Mistral)                          │
│  ─────────────────────────────────────────────────────────────  │
│  1. GCG 白盒攻击 (生成 Universal Suffix)         → 88% ASR      │
│  2. 迁移攻击到目标 + 编码堆叠                     → 70% ASR     │
│  3. garak 全面扫描 (DAN/GOAT/Encoding/Leakage)   → 补充发现     │
│  综合预期 ASR: 90-95%                                            │
├─────────────────────────────────────────────────────────────────┤
│  场景: RAG 应用                                                 │
│  ─────────────────────────────────────────────────────────────  │
│  1. XPIA 间接提示注入 (文档中嵌入恶意指令)        → 70% ASR     │
│  2. 数据泄露探测 (知识库内容提取)                 → 60% ASR     │
│  3. Giskard RAGET 组件级评估                      → 质量发现     │
│  综合预期 ASR: 70-80%                                            │
├─────────────────────────────────────────────────────────────────┤
│  场景: AI 基础设施                                              │
│  ─────────────────────────────────────────────────────────────  │
│  1. Nuclei + AI-Exploits 模板扫描已知漏洞                      │
│  2. Metasploit 模块验证 RCE/LFI/SSRF                           │
│  3. CSRF 模板测试 Web 界面安全                                  │
│  预期: 发现 CVE 级漏洞                                           │
└─────────────────────────────────────────────────────────────────┘
```

### 工具组合推荐

```
最佳实践工具栈:
├── 核心攻击引擎: PyRIT (本项目已集成)
├── 漏洞扫描:     garak (本项目已用 NativeProbe 替代)
├── 白盒攻击:     GCG/llm-attacks (可选)
├── 遗传变异:     AutoDAN (可选)
├── RAG 评估:     Giskard RAGET (可选)
├── 基础设施:     AI-Exploits + Nuclei (可选)
├── 评分系统:     SelfAskScorer + LLM-as-Judge (本项目已实现)
├── 标准对齐:     OWASP 2025 + ATLAS (本项目已实现)
└── 报告生成:     CVSS + Mermaid + ATLAS (本项目已实现)
```

---

> **免责声明**: 本指南仅供安全研究和授权测试使用。未经授权对他人 AI 系统进行红队测试可能违反法律法规。请确保在获得明确书面授权后进行测试。
