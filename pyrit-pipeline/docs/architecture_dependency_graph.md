# PyRIT Pipeline 架构依赖图

> **版本**: v1.0 | **日期**: 2026-8-3  
> **设计原则**: R-010 PyRIT 原生优先，自研代码仅作增强层  
> **关联文档**: [architecture_design.md](architecture_design.md) · [executor_principles.md](principles/executor_principles.md) · [l5_gap_analysis.md](l5_gap_analysis.md)

---

## 目录

1. [全局架构总览](#1-全局架构总览)
2. [编排入口层](#2-编排入口层)
3. [六大阶段流水线](#3-六大阶段流水线)
4. [PipelineContext — 状态容器](#4-pipelinecontext--状态容器)
5. [Executor 5 层架构](#5-executor-5-层架构)
6. [数据 5 层架构](#6-数据-5-层架构)
7. [ASR 子系统依赖图](#7-asr-子系统依赖图)
8. [Converter 子系统依赖图](#8-converter-子系统依赖图)
9. [Reporting 子系统依赖图](#9-reporting-子系统依赖图)
10. [Analysis 子系统依赖图](#10-analysis-子系统依赖图)
11. [Integrations 子系统依赖图](#11-integrations-子系统依赖图)
12. [Utils 子系统依赖图](#12-utils-子系统依赖图)
13. [Scenarios 子系统依赖图](#13-scenarios-子系统依赖图)
14. [PromptGen 子系统依赖图](#14-promptgen-子系统依赖图)
15. [Targets 子系统依赖图](#15-targets-子系统依赖图)
16. [web_redteam 子系统依赖图](#16-web_redteam-子系统依赖图)
17. [数据文件与配置依赖图](#17-数据文件与配置依赖图)
18. [PyRIT 原生 API 依赖索引](#18-pyrit-原生-api-依赖索引)
19. [Scripts 脚本依赖图](#19-scripts-脚本依赖图)

---

## 1. 全局架构总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              main.py (编排入口)                               │
│                    setup_environment → parse_args → 六阶段串联                 │
│                   + 契约验证 + 决策追溯 + 事件总线 + 信号处理                    │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   PipelineContext     │  ← 贯穿全流水线的唯一状态容器
                    │   (dataclass)         │
                    └───────────┬───────────┘
                                │
        ┌───────────┬───────────┼───────────┬───────────┬───────────┐
        │           │           │           │           │           │
   ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐
   │ Stage 1 │ │ Stage 2 │ │ Stage 3 │ │ Stage 4 │ │ Stage 5 │ │ Stage 6 │
   │  init   │ │scenario │ │initialize│ │ execute │ │  post   │ │ output  │
   │         │ │         │ │         │ │         │ │analysis │ │         │
   └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
        │           │           │           │           │           │
        ▼           ▼           ▼           ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
   │ PyRIT   │ │ ASR +   │ │PyRIT    │ │PyRIT    │ │ASR +    │ │PyRIT    │
   │ Registry│ │Converter│ │Scenario │ │Scenario │ │Failure  │ │Output + │
    │ init   │ │ +Selector│ │  init   │ │  run    │ │Handler  │ │Evidence │
   └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
        │           │           │           │           │           │
        └─────┬─────┴─────┬─────┴─────┬─────┴─────┬─────┴─────┬─────┘
              │           │           │           │           │
         ┌────▼───────────▼───────────▼───────────▼───────────▼────┐
         │                    PyRIT 原生框架                         │
         │  CentralMemory · TargetRegistry · ScorerRegistry         │
         │  AttackTechniqueRegistry · TextAdaptive · Scenario        │
         │  AttackExecutor · SequentialAttack · AttackResult         │
         │  Converter · Scorer · PromptTarget · Output               │
         └───────────────────────────────────────────────────────────┘
```

**可选阶段 (条件激活)**:
- `Stage 0.5` — `stage_target_classify` (当 `--target-url` 提供时)
- `Stage 1.5` — `stage_web_auth` (当 `--web-target-url` 提供时)
- XPIA 工作流 (当 `--xpia` 标志启用时)
- 多模态注入 (当 `--multimodal` 标志启用时)
- 模型提取 (当 `--scenario model_extraction` 时)

---

## 2. 编排入口层

### 2.1 `main.py` — 流水线编排入口

```
main.py
├── setup_environment()           → pipeline.config.setup_environment()
├── parse_args()                  → pipeline.config.parse_args()
├── OutputManager(base_dir)       → pipeline.reporting.output_manager.OutputManager
├── clean_temp_files("post")      → pipeline.utils.cleaner.clean_temp_files()  [运行后+异常退出]
│
├── stage_init(ctx)               → pipeline.stages.stage_init.run()
├── stage_target_classify(ctx)    → pipeline.stages.stage_target_classify.run()  [可选]
├── stage_scenario(ctx)           → pipeline.stages.stage_scenario.run()
├── stage_initialize(ctx)         → pipeline.stages.stage_initialize.run()
├── stage_execute(ctx)            → pipeline.stages.stage_execute.run()
├── stage_post_analysis(ctx)      → pipeline.stages.stage_post_analysis.run()
├── stage_output(ctx)             → pipeline.stages.stage_output.run()
│
├── _validate_contract(1→2)       → pipeline.utils.contract_validator.ContractValidator
├── _validate_contract(2→3)       → (阶段间数据流契约验证)
├── _validate_contract(3→4)
├── _validate_contract(4→5)
├── _validate_contract(5→6)
│
├── _print_trace_and_event_summary()
│   ├── DecisionTrace.get_instance()   → pipeline.utils.decision_trace
│   └── EventBus.get_instance()        → pipeline.utils.event_bus
│
├── _cleanup_web_session(ctx)     → 关闭 Playwright 浏览器会话
├── _persist_discovered_content_filter_markers()
│   └── persist_discovered_markers()   → pipeline.utils.content_filter_ext
└── clean_temp_files("post")
```

### 2.2 `pipeline/config.py` — 命令行参数解析

```
pipeline/config.py
├── setup_environment()
│   ├── warnings.filterwarnings()
│   └── dotenv.load_dotenv()
│
└── parse_args()
    ├── --datasets (默认: harmbench jbb_behaviors strong_reject)
    ├── --max-dataset-size (默认: 10)
    ├── --local-datasets
    ├── --load-owasp-local / --no-owasp-local
    ├── --model
    ├── --tier-layer (0/1/2/3)
    ├── --auto-tier-params
    ├── --epsilon / --epsilon-decay
    ├── --converters
    ├── --techniques
    ├── --scenario
    ├── --max-attempts / --max-concurrency / --max-retries
    ├── --exhaustive / --no-baseline
    ├── --resume
    ├── --target-url / --target-type
    ├── --web-target-url
    ├── --xpia / --multimodal
    ├── --analyze
    └── --output-dir
```

---

## 3. 六大阶段流水线

### 3.1 Stage 1 — `stage_init.py` (原生初始化)

```
pipeline/stages/stage_init.py
│
├── ConfigurationLoader.load_with_overrides(config_file=".pyrit_conf")
│   └── PyRIT 原生: pyrit.setup.configuration_loader
│
├── _initialize_with_per_run_db(ctx, config)
│   ├── config.resolve_initializers()
│   ├── config.resolve_initialization_scripts()
│   ├── config.resolve_env_files()
│   └── _core_initialize_pyrit()  → pyrit.setup.initialize_pyrit_async
│       ├── CentralMemory (SQLite per-run: outputs/db/redteam_{ts}.db)
│       ├── TargetRegistry (注册 .env 中配置的 Target)
│       ├── ScorerRegistry (注册评分器)
│       └── AttackTechniqueRegistry (注册攻击技术)
│
├── _load_local_datasets(ctx)
│   ├── data/seed_datasets/benchmarks/*.prompt     → CentralMemory
│   ├── data/seed_datasets/owasp/*.prompt          → CentralMemory
│   ├── data/seed_datasets/cve/*.prompt            → CentralMemory
│   └── data/seed_datasets/custom/*.prompt         → CentralMemory
│       └── pipeline.targets.rich_metadata_loader  (富元数据解析)
│
├── _generate_gcg_seeds(ctx) [可选]
│   └── pipeline.promptgen.gcg_integration         → pyrit.executor.promptgen.gcg
│
├── _generate_fuzzer_seeds(ctx) [可选]
│   └── pipeline.promptgen.fuzzer_integration      → pyrit.executor.promptgen.fuzzer
│
├── _detect_multimodal(ctx)
│   └── pipeline.converters.modality_router        (TargetCapabilities 检测)
│
├── _apply_model_specific_seed_priority(ctx)
│   └── 读取 asr_priors.yaml seed_priority_by_model 段
│
└── content_filter_ext.patch_content_filter_markers()
    └── pipeline.utils.content_filter_ext           (扩展 PyRIT 内容过滤标记)
```

**产出 (写入 PipelineContext)**:
- `ctx.config` = ConfigurationLoader 实例
- `ctx.scenario_name` = 场景类型
- `ctx.gcg_seeds_count` / `ctx.fuzzer_seeds_count`
- `ctx.is_multimodal` / `ctx.multimodal_converters`
- `ctx.rate_limited` / `ctx.http_target_configured`

### 3.2 Stage 2 — `stage_scenario.py` (ASR 驱动场景配置)

```
pipeline/stages/stage_scenario.py
│
├── query_historical_asr_by_category()
│   └── pipeline.asr.optimizer → CentralMemory.get_attack_stats()
│
├── sort_datasets_by_asr(args.datasets, asr_by_category)
│   └── pipeline.asr.optimizer
│
├── _get_objective_scorer()
│   └── ScorerRegistry.get_registry_singleton()     (三级 fallback)
│
├── detect_model_tier_from_registry()
│   └── pipeline.converters.model_tier_detector
│
├── should_use_composite_scorer(model_tier)
│   └── pipeline.scenarios.composite_scorer
│       └── create_composite_objective_scorer()
│           ├── pyrit.score.TrueFalseCompositeScorer
│           ├── pyrit.score.TrueFalseInverterScorer
│           ├── pyrit.score.SelfAskTrueFalseScorer
│           └── pyrit.score.SelfAskRefusalScorer
│
├── _build_warm_start_asr(model_name, model_tier, owasp_id)
│   ├── AttackTechniqueRegistry.get_registry_singleton().get_factories()
│   ├── pipeline.asr.prior_registry.get_initial_q_value()
│   │   └── 读取 data/setting/asr_priors.yaml
│   └── pipeline.asr.optimizer.merge_empirical_with_priors()
│       └── 读取 outputs/empirical_asr/seed_level_*.json
│
├── GroupFallbackExecutor.build_fallback_plan()
│   └── pipeline.asr.rank_builder
│
├── FailureTypeRoutingSelector(epsilon, scope, warm_start_asr, ...)
│   └── pipeline.asr.failure_type_selector
│       └── 继承 pyrit.scenario.scenarios.adaptive.EpsilonGreedyTechniqueSelector
│
├── TextAdaptive(objective_scorer, selector, scenario_result_id)
│   └── pyrit.scenario.scenarios.adaptive.TextAdaptive  (零覆盖)
│
├── CompoundDatasetAttackConfiguration.per_dataset(sorted_datasets, max_dataset_size)
│   └── pyrit.scenario.CompoundDatasetAttackConfiguration
│
├── _apply_tier_attack_params(args, model_tier)
│   └── pipeline.converters.model_tier_detector.get_attack_params_by_tier()
│       └── 读取 data/setting/model_tiers.yaml
│
├── _get_converter_target(model_name)
│   └── TargetRegistry 查找 (adversarial_chat → converter_target → ...)
│   └── pipeline.converters.model_tier_detector.get_optimal_attacker()
│
├── ConverterHealthMonitor(failure_threshold=2)
│   └── pipeline.converters.converter_health_monitor
│
├── build_technique_converter_map()  [Layer 1: CLI --converters]
│   └── pipeline.converters.factory
│       └── pipeline.asr.optimizer.query_historical_asr_by_technique()
│
├── build_target_aware_converter_map()  [Layer 2: Target 感知]
│   └── pipeline.converters.target_aware_router
│       └── 读取 data/setting/target_profiles.yaml
│       └── reorder_persuasion_chains_by_model()
│
├── ModalityRouter.filter_techniques_by_capability()
│   └── pipeline.converters.modality_router
│
├── scenario.set_params_from_args(args=params)  (原生单次注入)
│
├── _apply_dynamic_seed_budget(ctx, technique_converter_map)  [B3]
│   └── pipeline.asr.prior_registry.ASRPriorRegistry
│
├── _trace_5_layer_data_lineage(ctx, ...)  [B4]
│   └── pipeline.utils.decision_trace.DecisionTrace
│
├── _apply_seed_mirror_strategy(ctx, ...)  [B5]
│   └── pipeline.utils.decision_trace.DecisionTrace
│
├── _build_plan_pid_map(ctx, sorted_datasets, max_dataset_size)  [Gap 4]
│   └── CentralMemory.get_seed_prompts()
│
└── _print_tech_pool_matrix / handoff_banner
    └── pipeline.utils.display
```

**产出 (写入 PipelineContext)**:
- `ctx.scenario` = TextAdaptive 实例 (已注入参数)
- `ctx.objective_scorer` = 评分器 (可能为复合评分器)
- `ctx.selector` = FailureTypeRoutingSelector
- `ctx.sorted_datasets` / `ctx.warm_start_asr`
- `ctx.max_attempts_per_objective` / `ctx.converter_routing_count`
- `ctx.target_type` / `ctx.ranked_groups` / `ctx.fallback_plan`
- `ctx.tier_layer` / `ctx.plan_pid_map`
- `ctx.converter_health_monitor` (通过 setattr)
- `ctx.metadata["dynamic_seed_budget"]` / `["seed_mirror_strategy"]`

### 3.3 Stage 3 — `stage_initialize.py` (场景初始化)

```
pipeline/stages/stage_initialize.py
│
├── scenario.initialize_async()
│   └── PyRIT 原生: TextAdaptive.initialize_async()
│       └── _build_atomic_attacks_async()
│           ├── AttackTechniqueRegistry.get_registry_singleton().get_factories()
│           ├── CompoundDatasetAttackConfiguration → 遍历数据集
│           ├── CentralMemory.get_seed_prompts(dataset_name=...)
│           └── 构建 AtomicAttack + SequentialAttack(FIRST_SUCCESS/EXHAUSTIVE)
│
├── _feedback_current_run_asr(ctx)
│   └── pipeline.asr.optimizer.query_current_run_asr_by_technique()
│       └── CentralMemory.get_attack_results()
│
├── _reorder_atomic_attacks_by_asr(ctx)
│   └── pipeline.asr.optimizer.get_technique_asr_summary()
│
└── (ASR 优先级重排 AtomicAttack 执行顺序)
```

### 3.4 Stage 4 — `stage_execute.py` (场景执行)

```
pipeline/stages/stage_execute.py
│
├── FailureTypeEventHandler(selector=ctx.selector)
│   └── pipeline.asr.failure_type_event_handler
│       └── 继承 AttackResultAnalyzer (pipeline.analysis.attack_result_analyzer)
│
├── RuntimeStopEventHandler(owasp_threshold, stop_on_first)
│   └── pipeline.asr.runtime_stop_handler
│
├── ProgressPoller (非侵入式背景轮询) [可选]
│   └── pipeline.reporting.output_manager.ProgressPoller
│       └── CentralMemory.get_attack_results(scenario_result_id=...)
│
├── scenario.run_async()
│   └── PyRIT 原生: TextAdaptive.run_async()
│       └── _execute_scenario_async()
│           └── _execute_atomic_attacks_parallel_async(max_concurrency)
│               └── asyncio.Semaphore(max_concurrency)
│
├── _scan_results_post_execution(ctx, result)
│   ├── FailureTypeEventHandler.on_attack_result()
│   │   └── extract_failure_type_from_result()
│   │   └── selector.update_failure_type()
│   └── RuntimeStopEventHandler.check_stop_condition()
│
├── _compute_asr(ctx, result)
│   ├── result.get_display_groups()  (按技术聚合)
│   └── result.objective_achieved_rate()  (ASR 计算)
│
├── EventBus.publish("stage_4", "execution_complete", ...)
│   └── pipeline.utils.event_bus
│
└── DecisionTrace (执行结果记录)
    └── pipeline.utils.decision_trace
```

**产出 (写入 PipelineContext)**:
- `ctx.result` = ScenarioResult 实例
- `ctx.asr_per_technique` = {技术名: ASR%}
- `ctx.overall_asr` = 总体 ASR 百分比
- `ctx.metadata["failure_stats"]` = 失败类型分布
- `ctx.metadata["model_tier"]` / `["model_name"]`

### 3.5 Stage 5 — `stage_post_analysis.py` (执行后分析)

```
pipeline/stages/stage_post_analysis.py
│
├── _print_execution_summary(ctx)
│   └── result.get_display_groups()
│
├── _print_asr_comparison(ctx)
│   ├── pipeline.asr.optimizer.get_asr_summary()
│   └── pipeline.asr.optimizer.get_technique_asr_summary()
│
├── _print_converter_resilience(ctx)
│   └── pipeline.analysis.attack_result_analyzer (Converter 链提取)
│
├── _print_asr_feedback(ctx)
│   ├── pipeline.asr.optimizer.write_empirical_asr()  (经验写回)
│   │   └── 写入 outputs/empirical_asr/seed_level_{model}.json
│   └── 模型 Tier 预警
│
├── _print_recommendations(ctx)
│
├── _print_tech_pool_evolution(ctx)
│
├── _print_asr_trend(ctx)  [D2]
│   └── 读取 outputs/empirical_asr/seed_level_*.json (跨运行)
│
├── _print_fix_recommendations(ctx)  [D3]
│
├── _print_owasp_matrix(ctx)  [D4]
│   └── pipeline.reporting.owasp_data
│
└── handoff_banner(5, 6, ...)
    └── pipeline.utils.display
```

### 3.6 Stage 6 — `stage_output.py` (结果输出)

```
pipeline/stages/stage_output.py
│
├── output_scenario_async(result)
│   └── PyRIT 原生: pyrit.output.output_scenario_async
│
├── output_scorer_async(result)
│   └── PyRIT 原生: pyrit.output.output_scorer_async
│
├── EvidenceExporter.render_async()
│   └── pipeline.reporting.evidence_exporter
│       ├── MarkdownAttackResultMemoryPrinter.render_async()
│       ├── MarkdownConversationMemoryPrinter.render_async()
│       └── MarkdownScorePrinter.render_async()
│
├── EvidenceCollector.collect(ctx, result)
│   └── pipeline.analysis.evidence_collector
│       └── 继承 AttackResultAnalyzer
│       └── pipeline.analysis.technique_name_mapper
│
├── GroupFallbackExecutor 降级链报告
│   └── pipeline.asr.rank_builder
│
├── ReportGenerator.generate_report(ctx, result)
│   └── pipeline.reporting.report_generator
│       ├── pipeline.reporting.owasp_data (OWASP LLM01-10 + ASI01-10)
│       ├── pipeline.reporting.template_renderer (Jinja2)
│       │   └── templates/evidence_card.html / html_wrapper.html
│       └── pipeline.reporting.format_converter (Markdown → HTML → PDF)
│
├── DiversityAnalyzer [可选, --analyze]
│   └── pipeline.analysis.diversity_analyzer
│       └── 继承 AttackResultAnalyzer
│
├── ConverterLogCollector [可选, --analyze]
│   └── pipeline.converters.log
│       └── 继承 AttackResultAnalyzer
│
├── TieredSelectionWizard [可选, --analyze]
│   └── pipeline.asr.tiered_selection_wizard
│
└── OutputManager (目录结构管理)
    └── pipeline.reporting.output_manager
        ├── outputs/reports/
        ├── outputs/evidence/  (attacks/ conversations/ scores/ blurred/)
        ├── outputs/logs/
        ├── outputs/db/
        └── outputs/empirical_asr/
```

---

## 4. PipelineContext — 状态容器

```
pipeline/context.py — PipelineContext (dataclass)
│
├── Config 阶段产出
│   └── args: Any                          (argparse.Namespace)
│
├── Stage 1 产出 — 数据 L1 (Seed Source) + L4 (Memory)
│   ├── config: Any                        (ConfigurationLoader)
│   ├── scenario_name: str                 ("text_adaptive" / "airt_*" / "garak_*")
│   ├── gcg_seeds_count: int
│   ├── fuzzer_seeds_count: int
│   ├── is_multimodal: bool
│   ├── multimodal_converters: list[str]
│   ├── rate_limited: bool
│   └── http_target_configured: bool
│
├── Stage 2 产出 — Executor L1-L3 + L5 + 数据 L3 + L5
│   ├── scenario: Scenario | None          (TextAdaptive 实例)
│   ├── objective_scorer: Scorer | None
│   ├── selector: Any                      (FailureTypeRoutingSelector)
│   ├── sorted_datasets: list[str]
│   ├── warm_start_asr: dict[str, float]
│   ├── max_attempts_per_objective: int
│   ├── converter_routing_count: int
│   ├── target_type: str | None
│   ├── ranked_groups: list
│   ├── fallback_plan: Any
│   ├── tier_layer: int
│   ├── plan_pid_map: dict[str, str]
│   └── converter_health_monitor (via setattr)
│
├── Stage 4 产出
│   ├── result: ScenarioResult | None
│   ├── asr_per_technique: dict[str, float]
│   └── overall_asr: int
│
├── Stage 6 产出
│   └── output_dir: Path | None
│
├── 贯穿全流水线
│   ├── output_manager: OutputManager | None
│   ├── start_time / end_time: datetime | None
│   └── metadata: dict[str, Any]
│       ├── "noise_log_path" / "signal_log_path"
│       ├── "current_run_asr"
│       ├── "failure_stats"
│       ├── "model_tier" / "model_name"
│       ├── "dynamic_seed_budget"
│       ├── "seed_mirror_strategy"
│       ├── "recon_result"
│       └── "web_browser_session"
│
└── 便捷方法
    ├── stage1_summary() → str  (Stage 1 → Stage 2 衔接摘要)
    └── stage2_summary() → str  (Stage 2 → Stage 3 衔接摘要)
```

---

## 5. Executor 5 层架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Executor 5 层架构                                │
│                                                                         │
│  L5: Scenario          TextAdaptive (原生) ← stage_scenario.py 创建     │
│      │                  零覆盖, 仅通过 set_params_from_args 注入参数      │
│      │                                                                  │
│  L4: Compound Attack   SequentialAttack(FIRST_SUCCESS / EXHAUSTIVE)    │
│      │                  原生: scenario.initialize_async() 内部构建       │
│      │                  每个 objective 对应一个 SequentialAttack          │
│      │                                                                  │
│  L3: Attack Config     AttackConverterConfig + AttackScoringConfig      │
│      │                  technique_converters (注入到 params)             │
│      │                  objective_scorer (ScorerRegistry 三级 fallback)   │
│      │                  composite_scorer (G4: task_achieved AND not_refused)│
│      │                                                                  │
│  L2: Attack Strategy   TextAdaptive / AIRT / Garak / Benchmark / Foundry│
│      │                  AttackTechniqueRegistry (14+ 种技术)              │
│      │                  FailureTypeRoutingSelector (继承原生 EpsilonGreedy)│
│      │                  ModalityRouter (能力感知技术过滤)                  │
│      │                                                                  │
│  L1: Attack Parameters max_attempts / max_concurrency / max_retries     │
│                         include_baseline / memory_labels                │
│                         dataset_config (CompoundDatasetAttackConfiguration)│
│                         objective_target (TargetRegistry 动态解析)        │
└─────────────────────────────────────────────────────────────────────────┘

技术选择决策链:
  AttackTechniqueRegistry.get_factories()  →  技术池
       │
       ├── CLI --techniques                →  用户显式选择
       ├── TieredSelectionWizard           →  ASR Tier 分层推荐
       │   └── prior_registry.get_initial_q_value()
       ├── ModalityRouter                  →  能力感知过滤
       │   └── TargetCapabilities (multi_turn / image_input)
       └── FailureTypeRoutingSelector      →  epsilon-greedy + ASR 排序
           ├── warm_start_asr (学术先验)
           ├── merge_empirical_with_priors (经验覆盖先验)
           ├── _composite_score (统一融合)
           └── set_epsilon_decay (线性衰减)
```

---

## 6. 数据 5 层架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        数据 5 层架构                                    │
│                                                                         │
│  L1: Seed Source       远程 .prompt / 本地 .prompt / GCG / Fuzzer       │
│      │                  data/seed_datasets/{benchmarks,owasp,cve,custom}│
│      │                  stage_init.py: _load_local_datasets()           │
│      │                  pipeline.targets.rich_metadata_loader            │
│      │                                                                  │
│  L2: Seed Organization AttackSeedGroup 构造                              │
│      │                  PyRIT 原生: SeedDataset → AttackSeedGroup        │
│      │                  GCG/Fuzzer 种子注入 CentralMemory                 │
│      │                                                                  │
│  L3: Dataset Config    CompoundDatasetAttackConfiguration.per_dataset()  │
│      │                  sort_datasets_by_asr() (ASR 降序)                │
│      │                  max_dataset_size (per-dataset 预算)              │
│      │                  _apply_dynamic_seed_budget() (B3: ASR 加权)      │
│      │                  _apply_seed_mirror_strategy() (B5: 高 ASR 镜像)   │
│      │                                                                  │
│  L4: Memory Persistence CentralMemory (SQLite per-run)                   │
│      │                  outputs/db/redteam_{timestamp}.db               │
│      │                  memory_labels: run_date / pipeline_version / ... │
│      │                  AttackResult 持久化 + 跨运行查询                   │
│      │                                                                  │
│  L5: Analytics & Select EpsilonGreedy + ASR 驱动选择                      │
│                          FailureTypeRoutingSelector (warm-start ASR)    │
│                          ASRRankBuilder (Tier 分层 S/A/B/C/D)            │
│                          TieredSelectionWizard (三层渐进式)               │
│                          GroupFallbackExecutor (降级链)                   │
│                          optimizer.query_historical_asr_by_technique()  │
│                          merge_empirical_with_priors() (经验覆盖先验)     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. ASR 子系统依赖图

```
pipeline/asr/
│
├── prior_registry.py ──────────────────────────────────────────────
│   │  学术 ASR 先验注册表 (纯数据层, YAML 唯一数据源)
│   │
│   ├── 读取: data/setting/asr_priors.yaml
│   │   ├── priors: 22 个技术 × 9 模型变体
│   │   ├── combinations: 5 个组合 × 9 模型变体
│   │   ├── seed_priority_by_model: 8 个模型系列
│   │   └── tier_thresholds: S/A/B/C/D 阈值定义
│   │
│   ├── get_initial_q_value(tech, model, tier, owasp) → float
│   ├── tier_from_asr(asr) → str (S/A/B/C/D/UNKNOWN)
│   ├── ASRPriorRegistry.get_instance().for_model(model, tech) → ASRPrior
│   └── ASRPrior dataclass (success_rate / sample_size / source)
│
├── failure_type_selector.py ──────────────────────────────────────
│   │  失败类型路由技术选择器 (继承原生 EpsilonGreedyTechniqueSelector)
│   │
│   ├── 继承: pyrit.scenario.scenarios.adaptive.EpsilonGreedyTechniqueSelector
│   ├── 依赖: SelectorScope (pyrit.scenario.scenarios.adaptive.selectors)
│   ├── 依赖: pipeline.asr.prior_registry (warm-start ASR)
│   │
│   ├── select_async() → 调用 super().select_async() + _composite_score()
│   ├── _composite_score() = α × base_rank + (1-α) × priority_rank
│   ├── _compute_dynamic_alpha() (先验→经验过渡, 缓存)
│   ├── update_failure_type(failure_type) → 路由策略调整
│   ├── set_epsilon_decay(enabled) → 线性衰减 0.20→0.02 (50步)
│   ├── set_paradigm_tracker(tracker) → 范式性能自动学习
│   └── ParadigmPerformanceTracker (从 failure_type_event_handler 导入)
│
├── optimizer.py ──────────────────────────────────────────────────
│   │  ASR 驱动攻击优化器 (纯数据查询层)
│   │
│   ├── 依赖: CentralMemory.get_attack_stats() / get_attack_results()
│   ├── 依赖: pyrit.analytics.result_analysis.AttackStats
│   ├── 依赖: pyrit.models.AttackOutcome
│   │
│   ├── query_historical_asr_by_category() → dict
│   ├── query_historical_asr_by_technique() → dict
│   ├── query_current_run_asr_by_technique() → dict (同次运行反馈)
│   ├── sort_datasets_by_asr(datasets, asr_by_category) → list
│   ├── get_asr_summary() / get_technique_asr_summary()
│   ├── merge_empirical_with_priors(warm_start, model) → dict
│   │   └── 读取: outputs/empirical_asr/seed_level_{model}.json
│   └── write_empirical_asr(model, asr_data)
│       └── 写入: outputs/empirical_asr/seed_level_{model}.json
│
├── rank_builder.py ───────────────────────────────────────────────
│   │  ASR 排序构建器 + 组级降级链
│   │
│   ├── 依赖: pipeline.asr.prior_registry (tier_from_asr, get_initial_q_value)
│   │
│   ├── ASRTier(str, Enum): S/A/B/C/D/UNKNOWN
│   ├── ASRRankBuilder
│   │   ├── build_ranked_groups() → Tier 分层排序
│   │   └── sample_seed_groups_by_tier() → ASR 加权采样
│   └── GroupFallbackExecutor
│       └── build_fallback_plan() → 降级链 (S→A→B→C→D)
│
├── tiered_selection_wizard.py ────────────────────────────────────
│   │  三层渐进式选择向导
│   │
│   ├── 依赖: pipeline.asr.prior_registry (tier_from_asr, get_initial_q_value)
│   │
│   ├── TierLayerConfig: layer / max_techniques / max_dataset_size
│   ├── TieredSelectionWizard
│   │   └── recommend(available_techniques, owasp_id) → Recommendation
│   └── Layer 1 (S/A) → Layer 2 (+B) → Layer 3 (全技术)
│
├── failure_type_event_handler.py ─────────────────────────────────
│   │  Post-execution 失败类型扫描器
│   │
│   ├── 继承: pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer
│   │
│   ├── FailureTypeEventHandler
│   │   ├── on_attack_result(result) → 失败类型提取
│   │   ├── extract_failure_type_from_result() → str
│   │   └── selector.update_failure_type()
│   │
│   └── ParadigmPerformanceTracker
│       ├── load_from_file(path) → tracker
│       ├── record_result(technique, paradigm, success)
│       └── save_to_file(path)
│
└── runtime_stop_handler.py ───────────────────────────────────────
    │  运行时停止策略 (L2: OWASP 阈值 / L3: 全局首停)
    │
    ├── StopStrategyContext (owasp_success / global_success / should_stop)
    └── RuntimeStopEventHandler
        ├── record_success(owasp_id)
        ├── check_stop_condition() → bool
        └── _check_owasp_threshold() / _check_global_stop()
```

### ASR 数据流闭环

```
                     ┌─────────────────────┐
                     │  asr_priors.yaml    │
                     │  (学术先验数据)      │
                     └────────┬────────────┘
                              │ 加载
                              ▼
              ┌───────────────────────────────┐
              │  prior_registry.py            │
              │  get_initial_q_value()        │
              └───────────┬───────────────────┘
                          │ warm-start
                          ▼
              ┌───────────────────────────────┐
              │  failure_type_selector.py     │
              │  (epsilon-greedy + ASR 融合)  │
              └───────────┬───────────────────┘
                          │ 技术选择
                          ▼
              ┌───────────────────────────────┐
              │  TextAdaptive.run_async()     │
              │  (PyRIT 原生执行)              │
              └───────────┬───────────────────┘
                          │ AttackResult
                          ▼
              ┌───────────────────────────────┐
              │  CentralMemory (SQLite)        │
              │  (持久化)                      │
              └───────────┬───────────────────┘
                          │ 查询
              ┌───────────┴───────────────────┐
              ▼                               ▼
  ┌───────────────────┐           ┌───────────────────────┐
  │  optimizer.py     │           │  failure_type_event   │
  │  query_historical │           │  _handler.py          │
  │  _asr_by_technique│           │  (失败类型反馈)        │
  └────────┬──────────┘           └───────────┬───────────┘
           │                                  │
           ▼                                  ▼
  ┌───────────────────┐           ┌───────────────────────┐
  │  merge_empirical  │           │  selector.update      │
  │  _with_priors()   │           │  _failure_type()      │
  │  (经验覆盖先验)    │           │  (路由策略调整)        │
  └────────┬──────────┘           └───────────────────────┘
           │
           ▼
  ┌───────────────────┐
  │  seed_level_      │
  │  {model}.json     │
  │  (经验写回)        │
  └───────────────────┘
           │
           ▼ 累积 3+ 模型后
  ┌───────────────────┐
  │  asr_priors.yaml   │
  │  (source=empirical)│
  └───────────────────┘
```

---

## 8. Converter 子系统依赖图

```
pipeline/converters/
│
├── factory.py ────────────────────────────────────────────────────
│   │  Converter 工厂: CLI 名称 → PyRIT Converter 实例
│   │
│   ├── 支持的 CLI 名称: rot13 / base64 / leetspeak / morse / binary /
│   │   braille / nato / url / flip / emoji / zalgo / zero_width /
│   │   unicode_sub / caesar / atbash / string_join / superscript / ascii_art
│   │
│   ├── build_technique_converter_map(converters, techniques, asr)
│   │   └── ASR 驱动 per-technique 差异化路由
│   └── merge_converter_maps(base, overlay) → 合并
│
├── chains.py ─────────────────────────────────────────────────────
│   │  Converter 变体链定义 (纯数据层)
│   │
│   ├── 读取: data/setting/converter_chains.yaml
│   │   ├── encoding_bypass (ROT13 + Base64 + Leetspeak)
│   │   ├── stealth_evasion (ZeroWidth + UnicodeSub)
│   │   ├── persuasion_mild / persuasion_strong
│   │   ├── decomposition_reconstruct
│   │   └── crescendo_assist
│   │
│   ├── 惰性导入 PyRIT Converter 类 (避免版本兼容问题)
│   └── get_chain_by_name(name) → list[Converter]
│
├── target_aware_router.py ────────────────────────────────────────
│   │  Target 感知 Converter 路由
│   │
│   ├── 读取: data/setting/target_profiles.yaml
│   │   └── target_type → converter_chain 映射
│   │
│   ├── build_target_aware_converter_map(techniques, target_type, ...)
│   ├── infer_target_type(target_instance) → str
│   └── reorder_persuasion_chains_by_model(chains, model_name)
│       └── 依赖: data/setting/model_tiers.yaml (optimal_attacker_by_target)
│
├── model_tier_detector.py ────────────────────────────────────────
│   │  模型等级自动探测器
│   │
│   ├── 读取: data/setting/model_tiers.yaml
│   │   ├── model_patterns (gpt-4o → strong, gpt-35 → moderate, ...)
│   │   ├── optimal_attacker_by_target (最优对抗 LLM 配对)
│   │   └── tier_params (strong/moderate/weak → max_concurrency/epsilon/...)
│   │
│   ├── detect_model_tier_from_registry() → (model_name, tier)
│   ├── get_optimal_attacker(model_name) → str
│   ├── get_attack_params_by_tier(tier) → dict
│   └── should_use_llm_converters(tier) → bool
│
├── converter_health_monitor.py ───────────────────────────────────
│   │  Converter 熔断器 (Circuit Breaker)
│   │
│   ├── ConverterHealthMonitor(failure_threshold)
│   │   ├── check_health(converter_name) → bool
│   │   ├── record_failure(converter_name)
│   │   ├── record_success(converter_name)
│   │   └── is_circuit_open(converter_name) → bool
│   └── CircuitState: CLOSED / OPEN
│
├── modality_router.py ────────────────────────────────────────────
│   │  能力感知技术过滤
│   │
│   ├── 依赖: pyrit.prompt_target.common.target_capabilities.TargetCapabilities
│   │
│   ├── filter_techniques_by_capability(techniques, target, ...)
│   │   ├── multi_turn_techniques (crescendo / tap / red_teaming / pair / forest)
│   │   └── multimodal_techniques (image_variation / multimodal_jailbreak)
│   └── _get_text_only_capabilities() → TargetCapabilities
│
├── log.py ────────────────────────────────────────────────────────
│   │  Converter 转换日志收集器
│   │
│   ├── 继承: pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer
│   │
│   ├── ConverterLogCollector
│   │   ├── collect(results) → ConverterLogReport
│   │   └── extract_converter_info_from_result(result) → dict
│   └── ConverterLogAggregator
│       └── aggregate(logs) → summary
│
├── steganography_converter.py ────────────────────────────────────
│   │  文本隐写 Converter (自研, OWASP LLM05)
│   └── ZeroWidth / UnicodeSubstitution 隐写实现
│
└── audio_steganography_converter.py ──────────────────────────────
    │  音频隐写 Converter (自研, 多模态)
    └── LSB 隐写嵌入
```

### Converter 路由三层叠加

```
                用户 CLI 输入                    Target 类型自动检测
                    │                                    │
                    ▼                                    ▼
    ┌───────────────────────────┐       ┌───────────────────────────────┐
    │  Layer 1: CLI --converters │       │  Layer 2: Target 感知路由       │
    │  factory.build_technique_  │       │  target_aware_router.build_   │
    │  converter_map()           │       │  target_aware_converter_map() │
    │  (ASR 驱动差异化分配)       │       │  (target_type → 最优链)        │
    └───────────┬───────────────┘       └───────────┬───────────────────┘
                │                                   │
                └───────────┬───────────────────────┘
                            ▼
              ┌───────────────────────────┐
              │  merge_converter_maps()   │
              │  (并集, CLI 优先)          │
              └───────────┬───────────────┘
                          │
                          ▼
              ┌───────────────────────────┐
              │  params["technique_        │
              │  converters"] = merged_map │
              │  → scenario.set_params_    │
              │  from_args(args=params)    │
              └───────────────────────────┘
```

---

## 9. Reporting 子系统依赖图

```
pipeline/reporting/
│
├── output_manager.py ────────────────────────────────────────────
│   │  统一输出管理器
│   │
│   ├── OutputManager(base_dir)
│   │   ├── db_path: outputs/db/redteam_{timestamp}.db
│   │   ├── evidence_dir: outputs/evidence/redteam_{timestamp}/
│   │   ├── log_path: outputs/logs/signal_{timestamp}.md
│   │   ├── noise_log_path: outputs/logs/noise_{timestamp}.log
│   │   ├── reports_dir: outputs/reports/
│   │   └── empirical_asr_dir: outputs/empirical_asr/
│   │
│   ├── DualOutputManager (StdoutSink + FileSink)
│   ├── ProgressDashboard (实时进度仪表盘)
│   ├── ProgressPoller (非侵入式背景轮询)
│   │   └── CentralMemory.get_attack_results(scenario_result_id=...)
│   └── SummaryTable (批量攻击汇总表格)
│
├── evidence_exporter.py ─────────────────────────────────────────
│   │  证据导出器 (PyRIT 原生 render_async)
│   │
│   ├── 依赖: pyrit.output.attack_result.markdown.MarkdownAttackResultMemoryPrinter
│   ├── 依赖: pyrit.output.conversation.markdown.MarkdownConversationMemoryPrinter
│   ├── 依赖: pyrit.output.score.markdown.MarkdownScorePrinter
│   ├── 依赖: pipeline.converters.log (Converter 信息提取)
│   ├── 依赖: pipeline.reporting.report_generator (辅助函数)
│   │
│   ├── EvidenceExporter.render_async(result, output_dir)
│   │   ├── 攻击 Markdown (attacks/)
│   │   ├── 对话 Markdown (conversations/)
│   │   ├── 评分 Markdown (scores/)
│   │   ├── 模糊图片 (blurred/)
│   │   ├── evidence.json
│   │   ├── attack_summary.csv
│   │   ├── owasp_coverage_matrix.csv
│   │   └── ZIP 证据包
│   └── 支持: include_reasoning_trace / blur_images
│
├── report_generator.py ──────────────────────────────────────────
│   │  报告生成器 (三级证据链 + OWASP 映射)
│   │
│   ├── 依赖: pipeline.reporting.owasp_data (OWASP LLM01-10 + ASI01-10)
│   ├── 依赖: pipeline.reporting.template_renderer (Jinja2)
│   ├── 依赖: pipeline.analysis.evidence_collector (证据收集)
│   ├── 依赖: pipeline.analysis.diversity_analyzer (多样性分析)
│   ├── 依赖: pipeline.converters.log (Converter 日志)
│   │
│   ├── ReportGenerator
│   │   ├── generate_report(ctx, result) → Markdown + HTML
│   │   ├── Executive Summary (CVSS × confidence 加权)
│   │   ├── Findings (OWASP 映射, 按严重度降序)
│   │   ├── Attack Timeline
│   │   ├── OWASP Coverage Matrix
│   │   ├── MITRE ATT&CK Mapping
│   │   ├── Tool Usage
│   │   ├── Diversity Analysis (Shannon 熵)
│   │   ├── Converter Transformation Log
│   │   └── Appendix (Configuration + Reproduction)
│   │
│   └── _get_attack_type / _get_outcome_str / _safe_get (辅助函数)
│
├── owasp_data.py ────────────────────────────────────────────────
│   │  OWASP 2025 数据定义
│   │
│   ├── OWASP_LLM_CATEGORIES: LLM01-LLM10
│   ├── OWASP_ASI_CATEGORIES: ASI01-ASI10
│   ├── MITRE_ATT&CK 映射
│   └── CVSS 严重度等级 (CRITICAL / HIGH / MEDIUM / LOW)
│
├── template_renderer.py ─────────────────────────────────────────
│   │  Jinja2 模板渲染器
│   │
│   ├── 依赖: jinja2 (可选, 回退到 f-string)
│   ├── templates/evidence_card.html
│   └── templates/html_wrapper.html
│
└── format_converter.py ──────────────────────────────────────────
    │  格式转换器 (Markdown → HTML → PDF)
    │
    ├── _has_pdf_support() → bool (weasyprint / xhtml2pdf)
    └── convert_markdown_to_html / convert_html_to_pdf
```

---

## 10. Analysis 子系统依赖图

```
pipeline/analysis/
│
├── attack_result_analyzer.py ────────────────────────────────────
│   │  AttackResult 字段提取基类 (DRY 原则)
│   │
│   ├── AttackResultAnalyzer (基类)
│   │   ├── _extract_technique_name(result) → str
│   │   ├── _extract_converter_chain(result) → list
│   │   ├── _extract_conversation(result) → list
│   │   ├── _extract_owasp_id(result) → str
│   │   └── _extract_score(result) → float
│   │
│   └── 被以下模块继承:
│       ├── pipeline.converters.log.ConverterLogCollector
│       ├── pipeline.analysis.diversity_analyzer.DiversityAnalyzer
│       ├── pipeline.analysis.evidence_collector.EvidenceCollector
│       └── pipeline.asr.failure_type_event_handler.FailureTypeEventHandler
│
├── evidence_collector.py ────────────────────────────────────────
│   │  证据收集器
│   │
│   ├── 继承: AttackResultAnalyzer
│   ├── 依赖: pipeline.analysis.technique_name_mapper
│   │
│   ├── EvidenceCollector
│   │   ├── collect(ctx, result) → list[Evidence]
│   │   └── Evidence dataclass
│   │       ├── attack_payload
│   │       ├── target_response
│   │       ├── technique + converter_chain
│   │       ├── owasp_classification
│   │       ├── asr + confidence
│   │       └── conversation_history
│   │
│   └── export_json / export_markdown
│
├── diversity_analyzer.py ────────────────────────────────────────
│   │  攻击多样性分析器
│   │
│   ├── 继承: AttackResultAnalyzer
│   │
│   ├── DiversityAnalyzer
│   │   ├── analyze(results, available_techniques, owasp_mapping) → DiversityMetrics
│   │   └── DiversityMetrics
│   │       ├── shannon_entropy
│   │       ├── owasp_coverage
│   │       ├── paradigm_coverage
│   │       └── technique_distribution
│   │
│   └── render_diversity_section_from_dict(metrics) → str
│
└── technique_name_mapper.py ─────────────────────────────────────
    │  技术名称映射器
    │
    ├── normalize_technique_name(name) → str
    ├── get_display_name(name) → str
    └── get_arxiv_reference(name) → str (如 "arXiv:2310.08437")
```

---

## 11. Integrations 子系统依赖图

```
pipeline/integrations/
│
├── target_classifier.py ─────────────────────────────────────────
│   │  目标 URL 类型自动判别器
│   │
│   ├── 依赖: bs4.BeautifulSoup (HTML 解析)
│   │
│   ├── TargetClassifier
│   │   └── classify(url, force_type) → TargetClassification
│   │       ├── _probe_http_response(url) → HTTP 分析
│   │       ├── _probe_url_pattern(url) → URL 路径模式匹配
│   │       └── _probe_dom_features(url) → SPA DOM 特征检测
│   │           └── _CHAT_UI_SELECTORS (20 个框架选择器)
│   │
│   └── TargetClassification
│       ├── target_type: "llm_web_app" / "llm_api_platform" / "unknown"
│       ├── recommended_mode: "browser" / "api"
│       └── detection_reason: str
│
├── recon_trigger.py ─────────────────────────────────────────────
│   │  Recon 自动触发器
│   │
│   ├── 依赖: pipeline.integrations.target_classifier.TargetClassification
│   ├── 依赖 (外部): recon-pipeline (core.pipeline / core.session / core.probes)
│   │
│   ├── trigger_recon(ctx, page, classification) → ReconReport | None
│   │   ├── 构建 ReconSession
│   │   ├── 选择 ReconProbe 组合 (基于 target_type)
│   │   └── 运行 ReconPipeline
│   │
│   └── 持久化: outputs/evidence/recon_{timestamp}.json
│
└── web_redteam.py ───────────────────────────────────────────────
    │  web_redteam 集成桥接器
    │
    ├── create_shared_output_manager(timestamp) → OutputManager
    ├── collect_web_redteam_evidence(web_ctx, output_mgr) → list[Evidence]
    ├── pass_recon_to_pipeline(web_ctx, pipeline_ctx) → ReconResult
    └── recommend_scenarios_from_recon(recon_result) → list[dict]
        └── 场景推荐: xpia / multimodal / model_extraction / text_adaptive
```

---

## 12. Utils 子系统依赖图

```
pipeline/utils/
│
├── cleaner.py ───────────────────────────────────────────────────
│   │  临时文件清理器 (R-008)
│   └── clean_temp_files(when) → 清理 __pycache__ / .pyc / .pyo
│
├── content_filter_ext.py ────────────────────────────────────────
│   │  内容过滤器标记扩展 (monkey-patch, 不修改 PyRIT 源码)
│   │
│   ├── 读取: data/setting/content_filter_markers.yaml
│   │
│   ├── patch_content_filter_markers()
│   │   ├── 扫描 sys.modules 发现所有持有 CONTENT_FILTER_MARKERS 的模块
│   │   ├── 合并原生标记 + 扩展标记
│   │   ├── 包装 _is_content_filter_error 函数
│   │   └── 功能验证 (补丁后断言扩展标记被识别)
│   │
│   ├── persist_discovered_markers() → 写入 content_filter_discovered.json
│   └── restore_content_filter_markers() (恢复原始引用)
│
├── contract_validator.py ────────────────────────────────────────
│   │  阶段间数据流契约验证
│   │
│   ├── ContractValidator
│   │   └── validate(stage_from, stage_to, ctx) → ContractResult
│   │       ├── 检查发送方产出字段
│   │       └── 检查接收方期望字段
│   │
│   └── ContractResult (passed / missing_fields / warnings)
│
├── decision_trace.py ────────────────────────────────────────────
│   │  决策全链路追溯
│   │
    ├── DecisionTrace (单例)
│   │   ├── record(stage, layer, decision, reason, **data)
│   │   ├── get_records() → list[DecisionRecord]
│   │   ├── record_count → int
│   │   └── export_jsonl(path) → 写入决策日志
│   │
│   └── DecisionRecord (stage / layer / decision / reason / data / timestamp)
│
├── event_bus.py ─────────────────────────────────────────────────
│   │  统一事件总线 (JSONL + stdout)
│   │
│   ├── EventBus (单例)
│   │   ├── publish_simple(stage, event_type, **data)
│   │   ├── event_count → int
│   │   └── jsonl_path → Path (outputs/logs/events_{timestamp}.jsonl)
│   │
    └── PipelineEvent (timestamp / stage / event_type / data)
│
├── display.py ───────────────────────────────────────────────────
│   │  终端显示工具
│   │
    ├── print_pipeline_header(ctx)
    ├── print_pipeline_footer(ctx)
    ├── handoff_banner(stage_from, stage_to, message, highlights)
    ├── info_box(title, lines)
    ├── decision_card(title, subtitle, sub_sections)
    ├── asr_bar(percentage) → str
    └── pad_right(text, width) → str
│
└── noise_redirector.py ──────────────────────────────────────────
    │  噪音重定向器 (PyRIT 过程日志 → 文件)
    │
    └── redirect_noise_to_file(noise_path, signal_path) → contextmanager
```

---

## 13. Scenarios 子系统依赖图

```
pipeline/scenarios/
│
├── __init__.py ──────────────────────────────────────────────────
│   │  场景创建工厂 + OWASP 2025 补充场景
│   │
│   ├── create_scenario(name, objective_scorer, scenario_result_id)
│   │   ├── "airt_*"     → AIRTBenchmarkScenario (PyRIT 原生)
│   │   ├── "garak_*"    → GarakScenario (PyRIT 原生)
│   │   ├── "benchmark"  → BenchmarkScenario (PyRIT 原生)
│   │   ├── "foundry"    → FoundryScenario (PyRIT 原生)
│   │   └── None          → 未知场景 (fallback 到 text_adaptive)
│   │
│   └── OWASP 2025 场景注册:
│       ├── multimodal_injection (LLM01/LLM05)
│       ├── model_extraction (LLM10)
│       ├── data_poisoning (LLM04)
│       ├── pii_extraction (LLM02)
│       ├── vector_manipulation (LLM08)
│       ├── context_bomb (LLM10)
│       ├── hallucination_injection (LLM09)
│       ├── tool_hijack (LLM06)
│       └── system_prompt_leakage (LLM07)
│
├── composite_scorer.py ──────────────────────────────────────────
│   │  复合评分器 (task_achieved AND not_refused)
│   │
│   ├── 依赖: pyrit.score.TrueFalseCompositeScorer
│   ├── 依赖: pyrit.score.TrueFalseInverterScorer
│   ├── 依赖: pyrit.score.SelfAskTrueFalseScorer
│   ├── 依赖: pyrit.score.SelfAskRefusalScorer
│   ├── 依赖: pyrit.score.CompositeScorerOperator
│   │
│   ├── should_use_composite_scorer(tier) → bool
│   └── create_composite_objective_scorer(chat_target) → Scorer
│
├── multimodal_injection.py  → run_multimodal_injection(ctx)
├── model_extraction.py      → run_model_extraction(ctx)
├── data_poisoning.py
├── pii_extraction.py
├── vector_manipulation.py
├── context_bomb.py
├── hallucination_injection.py
├── tool_hijack.py
└── system_prompt_leakage.py
```

---

## 14. PromptGen 子系统依赖图

```
pipeline/promptgen/
│
├── gcg_integration.py ───────────────────────────────────────────
│   │  GCG 对抗后缀生成器 (PyRIT 原生 API)
│   │
│   ├── 依赖: pyrit.executor.promptgen.gcg.GCG
│   ├── 依赖: pyrit.executor.promptgen.gcg.GCGConfig
│   ├── 依赖: pyrit.executor.promptgen.gcg.GCGModelConfig
│   ├── 依赖: pyrit.executor.promptgen.gcg.GCGAlgorithmConfig
│   ├── 依赖: torch / transformers (HuggingFace, GPU 推荐)
│   │
│   ├── GCGSeedGenerator
│   │   ├── generate(goal, target) → list[SeedPrompt]
│   │   └── 生成的后缀注入 CentralMemory
│   │
│   └── 学术依据: arXiv:2307.15043 (Zou et al.)
│
└── fuzzer_integration.py ────────────────────────────────────────
    │  GPTFuzzer 载荷变异生成器 (PyRIT 原生 API)
    │
    ├── 依赖: pyrit.executor.promptgen.fuzzer.Fuzzer
    ├── 依赖: pyrit.models.AttackSeedGroup / SeedDataset / SeedObjective
    │
    ├── FuzzerSeedGenerator
    │   ├── generate(seeds, target, scorer) → list[SeedPrompt]
    │   └── 变异算子: Crossover / Expand / Rephrase / Shorten / Similar
    │
    └── 学术依据: arXiv:2309.11453 (Yu et al.)
```

---

## 15. Targets 子系统依赖图

```
pipeline/targets/
│
├── rate_limited_target.py ───────────────────────────────────────
│   │  限速 Target 包装器
│   │
│   ├── 原生委托 (零自研):
│   │   └── 设置 _max_requests_per_minute → 原生装饰器 limit_requests_per_minute
│   │
│   ├── 自研扩展 (填补原生空白):
│   │   ├── 并发信号量 (同一端点多请求并发控制)
│   │   ├── 错误重试 (429/503/502/500/504)
│   │   ├── 超时重试 (APITimeoutError / APIConnectionError)
│   │   ├── Retry-After 头解析
│   │   └── 指数退避 + 抖动
│   │
│   └── RateLimitedTarget(target, rpm, max_concurrent, max_retries)
│
└── rich_metadata_loader.py ──────────────────────────────────────
    │  富元数据种子加载器
    │
    └── load_rich_metadata_prompt(file_path) → SeedDataset
        └── 解析 .prompt 文件中的 YAML front-matter
            (owasp_id / harm_category / difficulty / tags / ...)
```

---

## 16. web_redteam 子系统依赖图

```
web_redteam/  (独立子模块, 通过 pipeline.integrations.web_redteam 桥接)
│
├── run.py ───────────────────────────────────────────────────────
│   └── WebRedteamPipeline 编排入口
│
├── config.py ────────────────────────────────────────────────────
│   └── WebRedteamConfig (目标配置 / 认证配置 / 攻击配置)
│
├── auth/ ────────────────────────────────────────────────────────
│   ├── auth_detector.py      → AuthDetector (检测认证类型)
│   ├── auth_probe.py         → AuthProbe (探测登录流程)
│   ├── auth_strategy.py      → AutoAuthStrategy (自动认证策略)
│   ├── browser_session.py    → BrowserSession (Playwright 会话管理)
│   ├── human_assisted_auth.py → HumanAssistedAuth (人工辅助认证)
│   ├── mfa_detector.py       → MFADetector (MFA 检测)
│   └── models.py             → AuthConfig / AuthResult dataclass
│
├── interaction/ ─────────────────────────────────────────────────
│   ├── generic_chat_interaction.py → GenericChatInteraction (通用聊天 UI 交互)
│   └── interaction_factory.py      → InteractionFactory (交互模式工厂)
│
├── pipeline/ ────────────────────────────────────────────────────
│   ├── context.py            → WebRedteamContext (子流水线状态容器)
│   ├── stage_init.py         → Stage 1: 初始化
│   ├── stage_target.py       → Stage 2: 目标探测
│   ├── stage_auth.py         → Stage 3: 认证
│   ├── stage_recon.py        → Stage 4: 侦察
│   ├── stage_attack.py       → Stage 5: 攻击执行
│   └── stage_output.py       → Stage 6: 结果输出
│
├── targets/ ─────────────────────────────────────────────────────
│   ├── target_profile.py     → TargetProfile (目标配置模型)
│   ├── dynamic_profile.py    → DynamicProfileBuilder (动态配置生成)
│   ├── api_config.py         → APITargetConfig (API 模式配置)
│   ├── _schema.yaml          → YAML schema 定义
│   ├── same_domain/          → 同域目标配置示例
│   │   ├── example_auto_detect.yaml
│   │   ├── example_open_target.yaml
│   │   └── example_portal.yaml
│   └── cross_domain/         → 跨域目标配置示例
│       └── example_sso.yaml
│
└── tests/ ───────────────────────────────────────────────────────
    └── 13 个测试文件
```

### web_redteam 双模式架构

```
                     --target-url <URL>
                           │
                    ┌──────▼──────┐
                    │TargetClassifier│
                    │  classify()  │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              │                         │
     llm_web_app                llm_api_platform
              │                         │
       ┌──────▼──────┐          ┌───────▼───────┐
       │ Browser Mode │          │  API Mode     │
       │              │          │               │
       │ AuthDetector │          │ APITargetConfig│
       │ AuthProbe    │          │ HTTPTarget     │
       │ MFADetector  │          │ RateLimitedTarget│
       │ AuthStrategy │          │ AIMD 自适应限速 │
       │ PlaywrightTarget│       │ OAuth2 + SSE   │
       └──────┬──────┘          └───────┬───────┘
              │                         │
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │PyRIT 原生    │
                    │AttackExecutor│
                    └─────────────┘
```

---

## 17. 数据文件与配置依赖图

```
┌─ config/ ───────────────────────────────────────────────────────┐
│  .pyrit_conf                                                    │
│  ├── memory_db_type: sqlite                                     │
│  ├── env_files: [./.env]                                        │
│  ├── initializers: [target, scorer, technique]                  │
│  └── max_concurrent_scenario_runs: 3                            │
└──────────────────────────────────────────────────────────────────┘

┌─ data/setting/ ─────────────────────────────────────────────────┐
│                                                                  │
│  asr_priors.yaml                                                 │
│  ├── priors: 22 技术 × 9 模型变体 (gpt_4o/gpt_35/llama_3_8b/    │
│  │   gemini_1_5/mistral_large/qwen_2_5/deepseek_v3/default)     │
│  ├── combinations: 5 组合 × 9 模型变体                           │
│  ├── seed_priority_by_model: 8 模型系列种子优先级                │
│  └── tier_thresholds: S(≥50%) A(≥30%) B(≥15%) C(≥5%) D(<5%)    │
│  ↑                                                               │
│  读取者: prior_registry.py → failure_type_selector.py            │
│         rank_builder.py → tiered_selection_wizard.py             │
│         optimizer.py → stage_scenario.py → stage_init.py         │
│                                                                  │
│  converter_chains.yaml                                           │
│  ├── encoding_bypass / stealth_evasion / persuasion_*            │
│  └── decomposition_reconstruct / crescendo_assist                │
│  ↑ 读取者: chains.py → factory.py                                │
│                                                                  │
│  model_tiers.yaml                                                │
│  ├── model_patterns (gpt-4o→strong, gpt-35→moderate, ...)       │
│  ├── optimal_attacker_by_target (最优对抗 LLM 配对)              │
│  └── tier_params (strong/moderate/weak → 攻击参数)               │
│  ↑ 读取者: model_tier_detector.py                                │
│                                                                  │
│  target_profiles.yaml                                            │
│  └── target_type → converter_chain 映射                          │
│  ↑ 读取者: target_aware_router.py                                │
│                                                                  │
│  content_filter_markers.yaml                                     │
│  └── 第三方 API 安全审查标记                                      │
│  ↑ 读取者: content_filter_ext.py                                 │
│                                                                  │
│  paradigms.yaml                                                  │
│  └── 攻击范式定义 (direct/encoding/persuasion/multiturn/...)     │
│  ↑ 读取者: failure_type_selector.py                              │
│                                                                  │
│  seed_templates.yaml                                             │
│  └── 种子模板定义                                                 │
│  ↑ 读取者: stage_init.py                                         │
│                                                                  │
│  web_target_auto.yaml / web_target_cross_domain.yaml             │
│  / web_target_same_domain.yaml                                   │
│  └── Web 目标配置模板                                             │
│  ↑ 读取者: web_redteam 模块                                       │
└──────────────────────────────────────────────────────────────────┘

┌─ data/seed_datasets/ ───────────────────────────────────────────┐
│                                                                  │
│  benchmarks/                                                     │
│  ├── harmbench.prompt            → HarmBench 标准种子             │
│  ├── jbb_behaviors.prompt        → JailbreakBench 种子            │
│  ├── strong_reject.prompt        → StrongREject 种子              │
│  ├── curated_seeds.prompt        → 精简种子 (通用)                │
│  ├── curated_seeds_gpt_4o.prompt → 精简种子 (GPT-4o 专属)        │
│  ├── curated_seeds_llama_3_8b.prompt → 精简种子 (Llama-3 专属)   │
│  └── _manifest.yaml              → 数据集清单 (default=true 自动加载)│
│                                                                  │
│  owasp/                                                          │
│  ├── llm01_prompt_injection.prompt    → OWASP LLM01              │
│  ├── llm02_sensitive_info_disclosure.prompt → OWASP LLM02        │
│  ├── ... (llm03-llm10)                                          │
│  ├── asi01_agent_identity_spoofing.prompt → OWASP ASI01          │
│  └── ... (asi02-asi10)                                          │
│                                                                  │
│  cve/                                                            │
│  └── prompt_injection_exfiltration.prompt                        │
│                                                                  │
│  custom/                                                         │
│  └── redteam_objectives.prompt                                   │
│                                                                  │
│  加载者: stage_init.py → _load_local_datasets()                  │
│          → CentralMemory.get_seed_prompts()                      │
│          → CompoundDatasetAttackConfiguration                    │
└──────────────────────────────────────────────────────────────────┘

┌─ outputs/ ──────────────────────────────────────────────────────┐
│                                                                  │
│  db/                                                             │
│  └── redteam_{timestamp}.db     → SQLite per-run Memory          │
│      读写者: CentralMemory (PyRIT 原生)                           │
│                                                                  │
│  evidence/                                                       │
│  └── redteam_{timestamp}/                                       │
│      ├── attacks/               → 攻击 Markdown 报告              │
│      ├── conversations/         → 对话 Markdown                   │
│      ├── scores/                → 评分 Markdown                   │
│      └── blurred/               → 模糊图片副本                    │
│      生成者: EvidenceExporter.render_async()                     │
│                                                                  │
│  logs/                                                           │
│  ├── signal_{timestamp}.md      → 信号日志 (主输出)               │
│  ├── noise_{timestamp}.log      → 噪音日志 (PyRIT 过程日志)       │
│  └── events_{timestamp}.jsonl   → 事件总线 JSONL                  │
│      生成者: OutputManager / redirect_noise_to_file / EventBus  │
│                                                                  │
│  reports/                                                        │
│  └── redteam_report_{timestamp}.md / .html / .pdf               │
│      生成者: ReportGenerator.generate_report()                   │
│                                                                  │
│  empirical_asr/                                                 │
│  ├── seed_level_{model}.json    → 经验 ASR (按模型存储)           │
│  ├── paradigm_performance.json  → 范式性能数据                    │
│  └── benchmark_result.json      → 10K 性能基准                    │
│      读写者: optimizer.py (write/read)                           │
│               failure_type_event_handler.py (paradigm)           │
│               scripts/curate_seeds.py (read)                     │
└──────────────────────────────────────────────────────────────────┘
```

---

## 18. PyRIT 原生 API 依赖索引

### 18.1 核心 API

| PyRIT 原生模块 | 被依赖的 pipeline 模块 | 用途 |
|:--|:--|:--|
| `pyrit.setup.configuration_loader.ConfigurationLoader` | `stage_init.py` | 加载 .pyrit_conf 配置 |
| `pyrit.setup.initialize_pyrit_async` | `stage_init.py` | 初始化 CentralMemory + Registry |
| `pyrit.memory.CentralMemory` | `stage_init.py`, `optimizer.py`, `evidence_exporter.py`, `output_manager.py`, `stage_scenario.py` | SQLite Memory 持久化 |
| `pyrit.registry.TargetRegistry` | `stage_scenario.py`, `stage_target_classify.py`, `xpia.py` | 目标注册与查找 |
| `pyrit.registry.ScorerRegistry` | `stage_scenario.py`, `xpia.py` | 评分器注册与查找 |
| `pyrit.registry.AttackTechniqueRegistry` | `stage_scenario.py`, `rank_builder.py` | 攻击技术注册与查找 |

### 18.2 Scenario & Executor API

| PyRIT 原生模块 | 被依赖的 pipeline 模块 | 用途 |
|:--|:--|:--|
| `pyrit.scenario.scenarios.adaptive.TextAdaptive` | `stage_scenario.py` | 主攻击场景 (零覆盖) |
| `pyrit.scenario.scenarios.adaptive.EpsilonGreedyTechniqueSelector` | `failure_type_selector.py` | 技术选择器 (被继承) |
| `pyrit.scenario.scenarios.adaptive.selectors.SelectorScope` | `stage_scenario.py` | 选择器作用域 |
| `pyrit.scenario.CompoundDatasetAttackConfiguration` | `stage_scenario.py` | 数据集配置 |
| `pyrit.scenario.core.scenario.Scenario` | `context.py` (TYPE_CHECKING) | 场景基类 |

### 18.3 Models API

| PyRIT 原生模块 | 被依赖的 pipeline 模块 | 用途 |
|:--|:--|:--|
| `pyrit.models.ScenarioResult` | `context.py`, `stage_execute.py` | 执行结果 |
| `pyrit.models.AttackOutcome` | `optimizer.py` | 攻击结果状态 |
| `pyrit.models.AttackSeedGroup` | `fuzzer_integration.py` | 种子组 |
| `pyrit.models.SeedDataset` | `stage_init.py`, `fuzzer_integration.py` | 种子数据集 |
| `pyrit.models.SeedObjective` | `fuzzer_integration.py` | 种子目标 |

### 18.4 Output API

| PyRIT 原生模块 | 被依赖的 pipeline 模块 | 用途 |
|:--|:--|:--|
| `pyrit.output.output_scenario_async` | `stage_output.py` | 场景结果输出 |
| `pyrit.output.output_scorer_async` | `stage_output.py` | 评分器输出 |
| `pyrit.output.attack_result.markdown.MarkdownAttackResultMemoryPrinter` | `evidence_exporter.py` | 攻击结果 Markdown |
| `pyrit.output.conversation.markdown.MarkdownConversationMemoryPrinter` | `evidence_exporter.py` | 对话 Markdown |
| `pyrit.output.score.markdown.MarkdownScorePrinter` | `evidence_exporter.py` | 评分 Markdown |

### 18.5 Analytics API

| PyRIT 原生模块 | 被依赖的 pipeline 模块 | 用途 |
|:--|:--|:--|
| `pyrit.analytics.result_analysis.AttackStats` | `optimizer.py` | 攻击统计数据结构 |

### 18.6 Prompt Target API

| PyRIT 原生模块 | 被依赖的 pipeline 模块 | 用途 |
|:--|:--|:--|
| `pyrit.prompt_target.OpenAIChatTarget` | `stage_scenario.py` | 自动创建 converter_target |
| `pyrit.prompt_target.common.target_capabilities.TargetCapabilities` | `modality_router.py` | 目标能力检测 |

### 18.7 Converter API

| PyRIT 原生模块 | 被依赖的 pipeline 模块 | 用途 |
|:--|:--|:--|
| `pyrit.converter.*` (ROT13Converter, Base64Converter, ...) | `chains.py`, `factory.py` | Converter 实例化 |

### 18.8 Score API

| PyRIT 原生模块 | 被依赖的 pipeline 模块 | 用途 |
|:--|:--|:--|
| `pyrit.score.TrueFalseCompositeScorer` | `composite_scorer.py` | 复合评分器 |
| `pyrit.score.TrueFalseInverterScorer` | `composite_scorer.py` | 评分反转 |
| `pyrit.score.SelfAskTrueFalseScorer` | `composite_scorer.py` | 任务达成评分 |
| `pyrit.score.SelfAskRefusalScorer` | `composite_scorer.py` | 拒绝检测评分 |
| `pyrit.score.CompositeScorerOperator` | `composite_scorer.py` | 复合操作符 |

---

## 19. Scripts 脚本依赖图

```
scripts/
│
├── curate_seeds.py ──────────────────────────────────────────────
│   │  种子精简系统 (MinHashLSH 去重 + TF-IDF 聚类)
│   │
│   ├── 读取: data/seed_datasets/benchmarks/*.prompt
│   ├── 读取: data/setting/asr_priors.yaml (seed_priority_by_model)
│   ├── 读取: outputs/empirical_asr/seed_level_*.json (实测 ASR)
│   │
│   ├── 输出: data/seed_datasets/benchmarks/curated_seeds_{model}.prompt
│   │
│   ├── --model <name>    → 指定模型精简
│   ├── --list-models     → 查看变体数
│   └── --benchmark       → 10K 性能基准
│       └── 输出: outputs/empirical_asr/benchmark_result.json
│
├── download_datasets.py ─────────────────────────────────────────
│   │  数据集预下载器
│   │
│   ├── 下载: HarmBench / JailbreakBench / StrongREject
│   └── 输出: data/seed_datasets/benchmarks/{name}.prompt
│
├── benchmark_curate.py ──────────────────────────────────────────
│   │  精简系统性能基准测试
│   └── 输出: outputs/empirical_asr/benchmark_result.json
│
├── sync_asr_priors.py ───────────────────────────────────────────
│   │  ASR 先验同步工具
│   └── 将实测 ASR 写入 asr_priors.yaml (source=empirical)
│
├── verify_env.py ────────────────────────────────────────────────
│   │  环境验证器
│   └── 检查 .env / .pyrit_conf / 依赖包 / 模型连接
│
├── verify_integration.py ────────────────────────────────────────
│   │  集成验证器
│   └── 验证 pipeline 模块间导入和函数签名一致性
│
├── clean_outputs.py ─────────────────────────────────────────────
│   │  输出清理器
│   └── 清理 outputs/ 目录 (保留最近的运行)
│
├── deep_investigate2.py ─────────────────────────────────────────
│   │  深度调查工具
│   └── 交互式攻击结果分析
│
├── check_native_api2.py ─────────────────────────────────────────
│   │  原生 API 兼容性检查器
│   └── 验证 PyRIT 版本兼容性
│
├── final_verify.py ──────────────────────────────────────────────
│   │  最终验证器
│   └── 流水线端到端验证
│
└── schedule_monthly_update.sh ───────────────────────────────────
    │  月度更新调度
    └── cron 定时: download_datasets + curate_seeds + sync_asr_priors
```

---

## 附录: 完整模块依赖矩阵

| 模块 | 依赖 pipeline 模块 | 依赖 PyRIT 原生 | 依赖外部库 | 依赖数据文件 |
|:--|:--|:--|:--|:--|
| `stage_init` | `context`, `utils.cleaner`, `utils.noise_redirector`, `utils.content_filter_ext`, `targets.rich_metadata_loader`, `converters.modality_router`, `promptgen.gcg_integration`, `promptgen.fuzzer_integration` | `CentralMemory`, `ConfigurationLoader`, `initialize_pyrit_async`, `TargetRegistry`, `ScorerRegistry`, `AttackTechniqueRegistry` | `dotenv` | `.pyrit_conf`, `.env`, `data/seed_datasets/*`, `data/setting/content_filter_markers.yaml` |
| `stage_scenario` | `context`, `asr.*`, `converters.*`, `scenarios.*`, `utils.*` | `TextAdaptive`, `CompoundDatasetAttackConfiguration`, `SelectorScope`, `TargetRegistry`, `ScorerRegistry`, `AttackTechniqueRegistry` | — | `data/setting/asr_priors.yaml`, `model_tiers.yaml`, `target_profiles.yaml`, `converter_chains.yaml` |
| `stage_initialize` | `context`, `asr.optimizer` | (通过 scenario 间接) | — | — |
| `stage_execute` | `context`, `asr.failure_type_event_handler`, `asr.runtime_stop_handler`, `utils.event_bus`, `reporting.output_manager` | (通过 scenario 间接) | — | — |
| `stage_post_analysis` | `context` | (通过 result 间接) | — | `outputs/empirical_asr/*` |
| `stage_output` | `context`, `reporting.*`, `analysis.*`, `asr.rank_builder`, `converters.log` | `output_scenario_async`, `output_scorer_async`, `Markdown*Printer` | `jinja2` (可选), `weasyprint` (可选) | `docs/principles/*` |
| `stage_target_classify` | `context`, `integrations.target_classifier`, `integrations.recon_trigger`, `utils.decision_trace`, `utils.event_bus` | — | `bs4`, `playwright` (可选) | — |
| `failure_type_selector` | `asr.prior_registry` | `EpsilonGreedyTechniqueSelector`, `SelectorScope` | — | `data/setting/asr_priors.yaml`, `paradigms.yaml` |
| `optimizer` | — | `CentralMemory`, `AttackStats`, `AttackOutcome` | — | `outputs/empirical_asr/*` |
| `prior_registry` | — | — | `yaml` | `data/setting/asr_priors.yaml` |
| `factory` | `asr.optimizer` | `pyrit.converter.*` | — | — |
| `target_aware_router` | `converters.model_tier_detector` | — | `yaml` | `data/setting/target_profiles.yaml`, `model_tiers.yaml` |
| `model_tier_detector` | — | — | `yaml` | `data/setting/model_tiers.yaml` |
| `evidence_exporter` | `converters.log`, `reporting.report_generator` | `CentralMemory`, `Markdown*Printer` | — | — |
| `report_generator` | `reporting.owasp_data`, `reporting.template_renderer`, `analysis.evidence_collector`, `analysis.diversity_analyzer`, `converters.log` | — | `jinja2` (可选) | `templates/*.html` |
| `evidence_collector` | `analysis.technique_name_mapper`, `analysis.attack_result_analyzer` | — | — | — |
| `contract_validator` | `context` | — | — | — |
| `decision_trace` | — | — | — | — |
| `event_bus` | — | — | — | — |
| `content_filter_ext` | — | — | `yaml` | `data/setting/content_filter_markers.yaml` |

---

> **图例说明**:
> - `→` 表示依赖方向 (A → B 表示 A 依赖 B)
> - `├──` / `└──` 表示模块层次结构
> - `[可选]` 表示条件激活的组件
> - `(原生)` 表示 PyRIT 原生 API
> - `(自研)` 表示 pipeline 自研增强代码
> - `(继承)` 表示继承 PyRIT 原生类
