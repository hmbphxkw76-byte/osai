# 架构设计文档

> **版本**: v1.0
> **日期**: 2026-8-1
> **PyRIT 版本**: 1.1.0.dev0
> **学术依据**: PyRIT [[arXiv:2407.01232v1]](https://arxiv.org/abs/2407.01232)

---

## 目录

1. [设计哲学](#一设计哲学)
2. [整体架构](#二整体架构)
3. [六阶段流水线](#三六阶段流水线)
4. [数据 5 层架构](#四数据-5-层架构)
5. [Executor 5 层架构](#五executor-5-层架构)
6. [模块依赖关系](#六模块依赖关系)
7. [配置体系](#七配置体系)
8. [目录结构](#八目录结构)

---

## 一、设计哲学

### 1.1 核心原则

| 原则 | 说明 |
|------|------|
| **PyRIT 原生框架优先** | 核心攻击/评分/输出 100% 原生 API 调用；自研模块仅做数据层增强和选择层路由，不覆盖原生生命周期 |
| **ASR 驱动攻击为王** | 所有技术选择、数据集排序、Converter 路由均以攻击成功率 (ASR) 为核心驱动力 |
| **报告证据齐全** | 三级证据链 (Finding → AttackResult → Conversation) 确保审计可追溯 |
| **阶段隔离** | 六阶段独立文件，通过 PipelineContext 传递状态，改一阶段不影响其他 |
| **韧性恢复** | 原生 max_retries + 断点续跑 + 限速包装 + 失败类型路由 |

### 1.2 设计决策

**为什么自研 FailureTypeRoutingSelector 而非直接用原生 EpsilonGreedyTechniqueSelector？**

原生选择器的 `_estimate()` 对未见技术返回 1.0（乐观初始化），且不感知失败类型。自研选择器在原生基础上增加：
1. 学术 ASR 先验 warm-start — 首次运行用 JailbreakBench 数据替代乐观初始值
2. 失败类型路由 — 根据失败模式动态调整技术排序
3. 动态 Alpha — 先验→经验自然过渡
4. 统一融合函数 — 消除多层权重叠加

**为什么自研 EvidenceCollector 而非仅用原生输出？**

原生 `output_attack_async` 生成 Markdown 报告，但不提供结构化 "漏洞证据" 视图。自研 EvidenceCollector 提取：
- 成功攻击载荷 (jailbreak prompt)
- 目标模型漏洞响应 (harmful output)
- 攻击技术 + Converter 链
- OWASP 分类映射
- ASR 和置信度
- 完整对话历史 + 攻击链路 + Converter 转换日志

**为什么自研 RateLimitedTarget 而非直接用原生 RPM？**

原生 RPM 限速仅控制请求频率，不处理并发信号量和指数退避重试。自研 RateLimitedTarget 包装原始 Target，增加：
- 并发信号量 (Semaphore)
- 指数退避重试 (429/503/504/timeout)
- 原生 RPM 限速集成

### 1.3 学术依据

遵循 R-007 规则，优先引用 arXiv 文献：

| 主题 | 文献 | 贡献 |
|------|------|------|
| PyRIT 框架 | [[arXiv:2407.01232v1]](https://arxiv.org/abs/2407.01232) | 原生框架设计 |
| JailbreakBench | [[arXiv:2402.01135]](https://arxiv.org/abs/2402.01135) | ASR 基线数据 |
| HarmBench | [[arXiv:2402.04249]](https://arxiv.org/abs/2402.04249) | 标准化红队评估 |
| Wei et al. "Jailbroken" | [[arXiv:2307.15043]](https://arxiv.org/abs/2307.15043) | 攻击范式三分法 |
| Crescendo | [[arXiv:2404.01833]](https://arxiv.org/abs/2404.01833) | 多轮递进攻击 |
| TAP | [[arXiv:2312.02191]](https://arxiv.org/abs/2312.02191) | 树搜索攻击优化 |
| PAIR | [[arXiv:2310.08437]](https://arxiv.org/abs/2310.08437) | 对抗迭代优化 |
| Russinovich et al. | [[arXiv:2402.12109]](https://arxiv.org/abs/2402.12109) | Crescendo + encoding 协同 |
| Zeng et al. | [[arXiv:2402.19181]](https://arxiv.org/abs/2402.19181) | 说服策略 ASR |
| StrongREJECT | [[arXiv:2402.10260]](https://arxiv.org/abs/2402.10260) | 拒绝评估 |

---

## 二、整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                        用户输入 (CLI args)                           │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                   ┌───────────────┴───────────────┐
                   │        main.py (薄入口)         │
                   │  75行: 串联六阶段 + R-008清理   │
                   └───────────────┬───────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         │                                                   │
         │  ┌─────────┐  ┌─────────┐  ┌─────────┐          │
         │  │ Stage 1  │→│ Stage 2  │→│ Stage 3  │          │
         │  │ 初始化   │  │ 场景配置 │  │ 场景初始化│          │
         │  └─────────┘  └─────────┘  └─────────┘          │
         │       │            │            │                  │
         │       ↓            ↓            ↓                  │
         │  ┌─────────┐  ┌─────────┐  ┌─────────┐          │
         │  │ Stage 4  │→│ Stage 5  │→│ Stage 6  │          │
         │  │ 场景执行 │  │ 后分析   │  │ 结果输出 │          │
         │  └─────────┘  └─────────┘  └─────────┘          │
         │                                                   │
         │  PipelineContext (贯穿所有阶段的状态容器)          │
         └───────────────────────────────────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         │                                                   │
         │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
         │  │  asr/    │  │converters│  │ analysis/│       │
         │  │ (6模块)  │  │ (6模块)  │  │ (4模块)  │       │
         │  └──────────┘  └──────────┘  └──────────┘       │
         │                                                   │
         │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
         │  │reporting/│  │ targets/ │  │ scenarios│       │
         │  │ (6模块)  │  │ (3模块)  │  │  /工厂   │       │
         │  └──────────┘  └──────────┘  └──────────┘       │
         │                                                   │
         │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
         │  │multimodal│  │promptgen/│  │workflows/│       │
         │  │  /检测   │  │GCG/Fuzzer│  │  XPIA    │       │
         │  └──────────┘  └──────────┘  └──────────┘       │
         │                                                   │
         │  ┌──────────┐                                     │
         │  │  utils/  │  clean + display + noise redirect   │
         │  └──────────┘                                     │
         └───────────────────────────────────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         │              PyRIT 1.1.0.dev0 原生框架             │
         │  ConfigurationLoader / CentralMemory / Registry    │
         │  TextAdaptive / AttackExecutor / ScenarioResult    │
         │  Converters / Scorers / Output / Memory            │
         └───────────────────────────────────────────────────┘
```

---

## 三、六阶段流水线

### 3.1 阶段定义

| 阶段 | 文件 | 职责 | 输入 | 输出 |
|------|------|------|------|------|
| Stage 1 | `stage_init.py` | 原生初始化 + 数据集加载 | `ctx.args` | `ctx.config`, `ctx.scenario_name` |
| Stage 2 | `stage_scenario.py` | ASR 驱动场景配置 | `ctx.config`, `ctx.args` | `ctx.scenario`, `ctx.selector`, `ctx.sorted_datasets` |
| Stage 3 | `stage_initialize.py` | 场景初始化 + ASR 调度 | `ctx.scenario` | `ctx.scenario._atomic_attacks` (重排) |
| Stage 4 | `stage_execute.py` | 场景执行 + ASR 分析 | `ctx.scenario` | `ctx.result`, `ctx.asr_per_technique`, `ctx.overall_asr` |
| Stage 5 | `stage_post_analysis.py` | 执行后分析 | `ctx.result` | `ctx.metadata["post_analysis"]` |
| Stage 6 | `stage_output.py` | 结果输出 + 证据收集 | `ctx.result` | `ctx.output_dir`, `ctx.metadata["evidence_collection"]` |

### 3.2 阶段间数据流

```
Stage 1 → Stage 2:  Registry 初始化 + 种子生成 + 多模态检测
Stage 2 → Stage 3:  场景配置 + 参数注入 + Converter 路由
Stage 3 → Stage 4:  AtomicAttack 构建 + ASR 智能调度
Stage 4 → Stage 5:  ScenarioResult + ASR 统计 + 失败类型分布
Stage 5 → Stage 6:  ASR 实测vs先验 + 经验写回 + 下次建议
```

### 3.3 XPIA 工作流 (可选)

当 `--xpia` 标志启用时，Stage 1 后直接进入 XPIA 工作流：

```
Stage 1 → XPIA (Cross-Domain Prompt Injection Attack) → 结束
```

XPIA 工作流使用原生 `pyrit.executor.workflow.xpia`，需要 `ATTACK_SETUP_TARGET` 和 `PROCESSING_TARGET` 环境变量。

---

## 四、数据 5 层架构

数据从种子源到分析选择，贯穿 5 个抽象层：

```
L1: Seed Source (Stage 1)
   ├── 远程数据集: harmbench, jbb_behaviors, strong_reject (本地预下载)
   ├── 本地数据集: OWASP .prompt, CVE .prompt, 自定义 .prompt
   ├── GCG 生成: 对抗后缀种子 (原生 pyrit.executor.promptgen.gcg)
   └── Fuzzer 变异: MCTS 载荷变异 (原生 pyrit.executor.promptgen.fuzzer)
        │
        ↓
L2: Seed Organization (Stage 1→2)
   └── AttackSeedGroup (原生模型, 含富元数据: asr_baseline, technique_group, owasp_id)
        │
        ↓
L3: Dataset Config (Stage 2)
   └── CompoundDatasetAttackConfiguration.per_dataset (原生, 独立预算 per-dataset)
        │
        ↓
L4: Memory Persistence (Stage 1→6)
   └── CentralMemory SQLite (原生, 全程持久化)
        │
        ↓
L5: Analytics & Select (Stage 2→4)
   ├── FailureTypeRoutingSelector (ASR 驱动技术选择)
   ├── ASRRankBuilder (Tier 分层 + 降级链)
   ├── TieredSelectionWizard (三层渐进式选择)
   └── 经验 ASR 自动写回
```

---

## 五、Executor 5 层架构

执行器从参数到场景，贯穿 5 个抽象层：

```
L1: Attack Parameters (Stage 2)
   ├── max_attempts_per_objective (FIRST_SUCCESS / EXHAUSTIVE)
   ├── max_concurrency (并发 AtomicAttack 数)
   ├── max_retries (失败重试次数)
   └── include_baseline (prompt_sending 对比基线)
        │
        ↓
L2: Attack Strategy (Stage 2)
   ├── TextAdaptive (默认, ASR 驱动自适应)
   ├── AIRT 场景 (jailbreak/cyber/leakage/psychosocial/rapid_response/scam)
   ├── Garak 场景 (encoding/doctor/web_injection)
   ├── Benchmark 场景 (adversarial, 跨模型 ASR 对比)
   └── Foundry 场景 (red_team, 自主红队代理)
        │
        ↓
L3: Attack Config (Stage 2)
   ├── technique_converters (ASR 驱动 + Target 感知双路由)
   ├── objective_scorer (三级 fallback)
   └── memory_labels (运行标签)
        │
        ↓
L4: Compound Attack (Stage 3)
   ├── SequentialAttack(FIRST_SUCCESS) — 首成功即停
   ├── SequentialAttack(EXHAUSTIVE) — 全技术尝试
   └── ASR 智能调度 — 按 ASR 优先级重排执行顺序
        │
        ↓
L5: Scenario (Stage 2→4)
   ├── TextAdaptive 实例 (零覆盖, 原生生命周期)
   ├── FailureTypeRoutingSelector (继承原生 EpsilonGreedy)
   └── FailureTypeEventHandler (后处理扫描, 非侵入式)
```

---

## 六、模块依赖关系

```
main.py
  ├── pipeline.config (parse_args, setup_environment)
  ├── pipeline.context (PipelineContext)
  ├── pipeline.reporting.output_manager (OutputManager)
  ├── pipeline.stages.stage_init (run)
  ├── pipeline.stages.stage_scenario (run)
  ├── pipeline.stages.stage_initialize (run)
  ├── pipeline.stages.stage_execute (run)
  ├── pipeline.stages.stage_post_analysis (run)
  ├── pipeline.stages.stage_output (run)
  ├── pipeline.utils.cleaner (clean_temp_files)
  └── pipeline.utils.display (print_pipeline_header/footer)

stage_init.py
  ├── pyrit.setup.configuration_loader (ConfigurationLoader)
  ├── pyrit.memory (CentralMemory)
  ├── pyrit.registry (TargetRegistry, ScorerRegistry, AttackTechniqueRegistry)
  ├── pipeline.targets.rich_metadata_loader (load_rich_prompt_as_native)
  ├── pipeline.promptgen (GCGSuffixGenerator, FuzzerPayloadGenerator)
  ├── pipeline.multimodal (discover_target_modalities_async, recommend_multimodal_converters)
  ├── pipeline.targets.rate_limited_target (wrap_target_with_rate_limit)
  └── pipeline.utils.noise_redirector (redirect_noise_to_file)

stage_scenario.py
  ├── pyrit.scenario (CompoundDatasetAttackConfiguration)
  ├── pyrit.scenario.scenarios.adaptive (TextAdaptive)
  ├── pyrit.scenario.scenarios.adaptive.selectors (SelectorScope)
  ├── pyrit.registry (AttackTechniqueRegistry, ScorerRegistry, TargetRegistry)
  ├── pipeline.asr.optimizer (query_historical_asr_by_*, sort_datasets_by_asr, merge_empirical_with_priors)
  ├── pipeline.asr.prior_registry (get_initial_q_value)
  ├── pipeline.asr.failure_type_selector (FailureTypeRoutingSelector)
  ├── pipeline.asr.rank_builder (GroupFallbackExecutor)
  ├── pipeline.asr.tiered_selection_wizard (TieredSelectionWizard)
  ├── pipeline.asr.failure_type_event_handler (ParadigmPerformanceTracker)
  ├── pipeline.converters.factory (build_technique_converter_map, build_target_aware_converter_map)
  ├── pipeline.converters.target_aware_router (infer_target_type)
  ├── pipeline.converters.model_tier_detector (detect_model_tier_from_registry)
  └── pipeline.scenarios (create_scenario)

stage_execute.py
  ├── pipeline.asr.failure_type_event_handler (FailureTypeEventHandler)
  ├── pipeline.asr.optimizer (save_empirical_asr)
  └── pyrit.models (AttackOutcome)

stage_output.py
  ├── pyrit.output (FileSink, output_attack_async, output_scenario_async, output_scorer_async)
  ├── pipeline.analysis.evidence_collector (EvidenceCollector)
  ├── pipeline.asr.rank_builder (GroupFallbackExecutor)
  ├── pipeline.analysis.diversity_analyzer (DiversityAnalyzer)
  ├── pipeline.converters.log (ConverterLogCollector)
  ├── pipeline.asr.tiered_selection_wizard (TieredSelectionWizard)
  └── pipeline.reporting.format_converter (convert_report_formats)
```

---

## 七、配置体系

### 7.1 三级配置

| 优先级 | 配置源 | 文件 | 说明 |
|--------|--------|------|------|
| 1 | 环境变量 | `.env` | API Key, Endpoint, Model Name |
| 2 | PyRIT 配置 | `.pyrit_conf` | 初始化器序列 |
| 3 | 命令行参数 | `parse_args()` | 30+ 参数覆盖 |

### 7.2 .env 配置

```bash
# 目标模型 (被攻击)
OPENAI_CHAT_ENDPOINT="https://your-api-endpoint/v1"
OPENAI_CHAT_KEY="${OPENAI_CHAT_KEY}"
OPENAI_CHAT_MODEL="${OPENAI_CHAT_MODEL}"

# 评分器模型 (Judge)
OBJECTIVE_SCORER_CHAT_ENDPOINT="https://your-judge-endpoint/v1"
OBJECTIVE_SCORER_CHAT_KEY="${OBJECTIVE_SCORER_CHAT_KEY}"
OBJECTIVE_SCORER_CHAT_MODEL="${OBJECTIVE_SCORER_CHAT_MODEL}"

# 对抗 LLM (TAP/PAIR/Crescendo)
ADVERSARIAL_CHAT_ENDPOINT="${OBJECTIVE_SCORER_CHAT_ENDPOINT}"
ADVERSARIAL_CHAT_KEY="${OBJECTIVE_SCORER_CHAT_KEY}"
ADVERSARIAL_CHAT_MODEL="${OBJECTIVE_SCORER_CHAT_MODEL}"
```

### 7.3 .pyrit_conf 配置

```yaml
memory_db_type: sqlite

initializers:
  - target                    # 从 .env 注册目标
  - scorer                    # 注册评分器
  - technique:
      args:
        tags: [core, extra]   # 注册技术
  - load_default_datasets      # 加载默认数据集

silent: false
```

### 7.4 YAML 数据配置

| 文件 | 说明 |
|------|------|
| `data/config/asr_priors.yaml` | 学术 ASR 先验数据 (389行, 20+技术) |
| `data/config/paradigms.yaml` | 范式分类关键词 |
| `data/config/converter_chains.yaml` | Converter 链预设 |
| `data/config/model_tiers.yaml` | 模型安全过滤等级 |
| `data/config/target_profiles.yaml` | 目标类型配置 |
| `data/datasets/_manifest.yaml` | 数据集清单 |

---

## 八、目录结构

```
pyrit-pipeline/
├── main.py                         # 薄入口 (75行)
├── conftest.py                     # pytest 配置
├── pyproject.toml                  # 项目配置
├── pipeline/
│   ├── __init__.py                 # 公共接口
│   ├── context.py                  # PipelineContext 状态容器
│   ├── config.py                   # 命令行参数
│   ├── reporting/                 # HTML/PDF 报告 (format_converter + Jinja2)
│   ├── stages/                     # 六阶段
│   ├── asr/                        # ASR 驱动 (6模块)
│   ├── converters/                 # Converter 路由 (6模块)
│   ├── analysis/                   # 分析 (4模块)
│   ├── reporting/                  # 报告 (6模块)
│   ├── targets/                    # 目标层 (3模块)
│   ├── scenarios/                  # 场景工厂
│   ├── multimodal/                 # 多模态检测
│   ├── promptgen/                  # GCG/Fuzzer
│   ├── workflows/                  # XPIA
│   └── utils/                      # 工具
├── data/
│   ├── config/                     # YAML 配置
│   ├── custom/                     # 自定义数据集
│   ├── cve/                        # CVE 数据集
│   ├── datasets/                   # 预下载数据集
│   └── owasp/                      # OWASP 数据集
├── docs/                           # 架构文档
├── output/                         # 运行时输出
├── scripts/                        # 脚本工具
├── tests/                          # 测试
└── web_redteam/                    # Web 红队模块
```

---

*文档结束*
