# PyRIT AI-300 跨平台记忆库

> **用途**: 本文件是跨开发平台（CatPaw / Trae IDE / Cursor / Claude Code / Copilot 等）共享的项目记忆库。  
> **更新规则**: 每次架构变更后必须同步更新此文件。  
> **版本**: v5.0 | **更新日期**: 2026-07-27

---

## 一、项目概览

- **项目名称**: PyRIT AI-300 — 端到端全自动 AI 红队框架
- **基础框架**: PyRIT 1.0.0
- **用途**: OffSec AI-300 考试和实际 AI 红队评估
- **总体对齐度**: 98% (L5 专家级)
- **主入口**: `pipeline.py`（九阶段顺序管道）
- **Python 版本**: 3.11+
- **配置体系**: 三级配置（显式参数 > 环境变量 > config.yaml）

---

## 二、架构记忆

### 2.1 五层 + ②.5 数据驱动架构

```
① 数据准备层 → DatasetManager.load_datasets() (OWASP本地/自定义/PyRIT远程)
② 数据管理层 → CentralMemory (add_seed_datasets_to_memory / get_seed_groups)
②.5 交互选择层 → 三层渐进式披露系统
    Layer 1: TargetProfileRouter (目标类型→OWASP映射)
    Layer 2: ASRRankBuilder (ASR分层排序+启发式代理)
    Layer 3: TieredSelectionWizard (交互+降级策略选择)
    Legacy:  SeedGroupSelector (向后兼容)
③ 攻击准备层 → AttackPreparator (SeedGroup → AttackSeedGroup)
④ 攻击执行层 → AI300AdaptiveScenario (统一路径) + NativeAttackExecutor + GroupFallbackExecutor
⑤ 评估与追踪层 → Scorer + PyRIT Memory 审计链
```

**关键约束**:
- 禁止直接构造 `PromptItem`（必须走五层流转）
- 禁止绕过选择层（pipeline 必须经过 `SeedGroupSelector`）
- 禁止修改 `SeedGroup` 对象（`source_seed_group` 保留原始引用）
- 条件分派逻辑不可变

### 2.2 Executor 五层架构 + Scenario 统一路径

```
Layer 1: Prompt Generators → AnecdoctorWrapper + FuzzerWrapper + GCGWrapper
Layer 2: Attack Execution  → SingleTurnExecutor / MultiTurnExecutor / NativeAttackExecutor (Facade)
Layer 3: Compound           → SequentialExecutor (异构技术链)
Layer 4: Workflow           → ScenarioOrchestrator [DEPRECATED] / BatchAttackOrchestrator / AI300AdaptiveScenario
Layer 5: Benchmarks         → FairnessBiasWrapper / QuestionAnsweringWrapper
```

**核心设计**:
- `NativeAttackExecutor` 是 Facade，`execute_single_attack()` 按技术分派
- 核心不变量: `one-objective → one-result`
- 子执行器共享 `_create_scoring_config()` 和 `SeedGroupBuilder`
- **统一 Adaptive 路径**: `AI300AdaptiveScenario` extends 原生 `AdaptiveScenario`，双轨已消除
- **Converter-Aware v3.0**: 原生 `extra_request_converters` 渐进式升级 + `FailureTypeRoutingSelector`
- **三层停止策略**: L1 `FIRST_SUCCESS` + L2 OWASP 阈值 + L3 全局首停

### 2.3 九阶段管道

```
[1/9] 初始化 PyRIT → CentralMemory + SQLite (每次独立 DB)
[2/9] 侦察          → 端点发现 + AI 类型识别 + 能力探测
[3/9] 分析          → 策略选择 + 优先级评估
[4/9] 数据准备+管理  → DatasetManager → CentralMemory
[5/9] 选择+准备     → SeedGroupSelector → AttackPreparator → AttackPlan
[6/9] 批量执行      → AI300AdaptiveScenario (原生+Converter变体+失败类型路由+三层停止)
[7/9] 输出结果      → 双通道输出 (终端 pretty + 文件 Markdown)
[8/9] 报告生成      → OWASP 映射 + 证据导出 + 三级证据链
[9/9] 总结          → 汇总统计
```

---

## 三、模块记忆

### 3.1 src/payloads/（数据集五层架构）

| 文件 | 职责 | 关键类/函数 |
|------|------|------------|
| `dataset_manager.py` | ②数据管理层 | `DatasetManager` (load_datasets/get_seed_groups/get_seeds) |
| `seed_selector.py` | ②.5交互选择层 | `SeedGroupSelector` (build_catalog/filter/prompt_user) |
| `attack_preparator.py` | ③攻击准备层 | `AttackPreparator` (prepare/prepare_batch/select_attack_technique) |
| `seed_adapter.py` | ③→④桥接 | `SeedPromptAdapter` (seed_groups_to_batches) |
| `planner.py` | 兼容模式 | `PayloadPlanner` / `plan_attacks` |
| `models.py` | 数据模型 | `AttackMode`/`PromptItem`/`PromptBatch`/`AttackPlan`/`BatchAttackResult` |
| `source_loader.py` | ①数据准备层 | `PayloadSourceLoader` (旧版加载器) |
| `owasp_provider.py` | OWASP桥接 | OWASP 本地数据集 SeedDatasetProvider |

### 3.2 src/executor/（攻击执行五层架构）

| 文件 | 职责 | 关键类/函数 |
|------|------|------------|
| `attack/core/native_executor.py` | Facade | `NativeAttackExecutor` (execute_single_attack/execute_batch_same_technique) |
| `attack/core/attack_builder.py` | 横切配置 | `ATTACK_CLASS_MAP`/`create_attack_instance`/`create_attack_adversarial_config` |
| `attack/core/constants.py` | 技术分类 | `SINGLE_TURN_ATTACKS`/`MULTI_TURN_TECHNIQUES`/`TAP_FAMILY_ATTACKS` |
| `attack/core/scenario_event_handler.py` | 事件可观测 | `ScenarioEventHandler` |
| `attack/core/modality_router.py` | 模态路由 | `ModalityRouter` (TargetCapabilities/模态检查/多模态消息构建/攻击路由) |
| `attack/single_turn/single_turn_executor.py` | 单轮执行 | `SingleTurnExecutor` |
| `attack/multi_turn/multi_turn_executor.py` | 多轮执行 | `MultiTurnExecutor` |
| `attack/compound/sequential_executor.py` | 顺序组合 | `SequentialExecutor` |
| `attack/component/seed_group_builder.py` | SeedGroup构建 | `SeedGroupBuilder` |
| `workflow/scenario_orchestrator.py` | 批量调度 | `ScenarioOrchestrator` / `execute_batch_attacks` |
| `workflow/batch_orchestrator.py` | 批量编排 | `BatchAttackOrchestrator` |
| `workflow/xpia_workflow.py` | XPIA工作流 | `XPIAWorkflowWrapper` / `RAGXPIAWorkflowWrapper` / `ProcessingCallbackBuilder` |

### 3.3 src/targets/（15种Target类型）

| 类型 | PyRIT 类 | 用途 |
|------|---------|------|
| `openai_chat` | `OpenAIChatTarget` | Chat Completions API |
| `openai_responses` | `OpenAIResponseTarget` | Responses API (o1/o3 + Agentic) |
| `litellm` | `LiteLLMChatTarget` | 100+ Provider |
| `http_api` | `HTTPXAPITarget` | 结构化 HTTP API |
| `http_raw` | `HTTPTarget` | 原始 HTTP / Burp |
| `playwright` | `PlaywrightTarget` | Web UI 自动化 |
| `websocket_copilot` | `WebSocketCopilotTarget` | M365 Copilot |
| `playwright_copilot` | `PlaywrightCopilotTarget` | Copilot Web |
| `azure_blob` | `AzureBlobStorageTarget` | XPIA 载荷投递 |
| `prompt_shield` | `PromptShieldTarget` | 防御测试 |
| `azure_ml` | `AzureMLChatTarget` | Azure ML Managed Endpoint |
| `openai_image` | `OpenAIImageTarget` | DALL-E 图片生成（多模态） |
| `openai_video` | `OpenAIVideoTarget` | Sora 视频生成 |
| `openai_tts` | `OpenAITTSTarget` | 文本转语音 |
| `text` | `TextTarget` | 调试输出 |

**关键设计**:
- `TargetParams` 70+ 字段覆盖全部构造参数（新增 4 个图片参数：image_size/output_format/image_quality/image_background）
- `detect_auth_mode`: Azure → Entra ID, 非Azure → api_key
- `_build_openai_httpx_kwargs`: SDK参数 vs httpx-only参数双路径拆分
- `detect_target_type`: side-effect-free (仅GET请求)
- `_LEGACY_TYPE_ALIASES`: 旧类型名向后兼容（含 dalle/image_generation 别名）
- `CapabilityHandlingPolicy`: 仅包含可适配能力（MULTI_TURN + SYSTEM_PROMPT）
- `TokenizerTemplateNormalizer`: 6 别名（chatml/phi3/qwen/llama3/gemma/mistral）
- `_TARGET_CLASSES` 延迟加载: 核心 5 + 可选 2 = 7 条目

### 3.4 src/scorers/（52个公共API）

**10大功能模块**:
1. `ScorerPromptValidator` 预设配置（7种预设 + 自定义工厂）
2. `ResponseHandler` 响应契约（JsonSchema + Callable 逃生舱）
3. `TrueFalseCompositeScorer` 组合评分器（AND/OR/MAJORITY）
4. `TrueFalseInverterScorer` 逻辑取反
5. `FloatScaleThresholdScorer` + `FloatScaleScoreAggregator`
6. `TrueFalseQuestionPaths` 9种预设评分问题
7. Blocked Content 策略（score_blocked_content / raise_if_scorer_blocks）
8. `score_response` 包装器（role_filter / skip_on_error_result）
9. `ConversationScorer` 对话级评分
10. Scorer Metrics 查询与比较（eval_hash + A/B比较）

**ScorerAccuracyEvaluator**: 封装原生 ScorerEvaluator，三层评估（run_full_evaluation / evaluate_with_dataset / evaluate_quick）

### 3.5 src/reporting/（报告+证据导出）

**L5 对齐**:
- `EvidenceExporter` 使用 `render_async()` 替代 `write_async()`+read-back
- `include_reasoning_trace`（o1/o3 推理模型轨迹）
- `blur_images`（图片模糊保护审查者）
- `_render_conversation_log_async()` 使用原生 `MarkdownConversationMemoryPrinter.render_async()`
- 集成 `output_scenario_async` + `output_scorer_async`
- 三级证据链: Finding → AttackResult → Conversation
- OWASP 覆盖矩阵 + 攻击时间线 CSV

### 3.6 src/converters/（80+ Converter）

**全系列对齐**:
- Text-to-Text / File / Image / Audio / Video Converter
- Selective Converting 子系统（TextSelectionStrategy 全层级 + WordLevelConverter）
- `@apply_defaults` 全局默认值注入
- 模态感知链路验证
- `PolicyPuppetryTemplate` 枚举导出
- 12+ 预置链快捷方法

---

## 四、关键设计决策记忆

### 4.1 为什么用 NativeAttackExecutor 而非直接调 AttackExecutor？

`NativeAttackExecutor` 是 Facade：
- 统一执行入口，按技术类型分派到 SingleTurnExecutor/MultiTurnExecutor
- 共享 `_create_scoring_config()` 和 `SeedGroupBuilder`
- 支持 `AttackResultAttribution` 父级关联
- `execute_batch_same_technique()` 原生并行优化

### 4.2 为什么有 ②.5 交互选择层？

在 CentralMemory 和 AttackPreparator 之间：
- 让用户根据攻击目标选择最合适的攻击组合
- `enabled=false` 全选跳过（CI/CD兼容）
- `preset_owasp`/`preset_modes` 支持脚本模式
- 过滤器不修改 SeedGroup 对象

### 4.3 为什么用差异化超时？

按攻击复杂度设定合理阈值：
- `single_turn=90s`: 1次API调用+评分，应快速完成
- `converter_enhanced=150s`: 额外转换链开销
- `multi_turn=300s`: 多轮对话+adversarial LLM迭代
- `sequential=480s`: 异构技术链，天然更长

### 4.4 为什么每次运行用独立数据库？

`db_path = db_base_path.parent / f"{exam_id}.db"` 彻底避免：
- 旧数据残留
- 文件锁定问题（Windows SQLite）
- 并发运行冲突

### 4.5 为什么单轮攻击不接受 refusal_scorer？

PyRIT 1.0.0 的 `AttackScoringConfig` 对单轮攻击和 `red_teaming` 设置 `refusal_scorer` 会触发 `warn_if_set` 警告。`NO_REFUSAL_SCORER_ATTACKS` 常量集合自动剥离。

### 4.6 为什么 XPIA 使用原生 XPIAWorkflow？

原生 `XPIAWorkflow` 提供：
- 结构化工作流阶段（setup → attack → process → score → teardown）
- `StrategyConverterConfig` 原生 Converter 集成
- `ProcessingCallback` 灵活回调机制
- `XPIAResult` 标准化结果（含 `success`/`status` 属性）
- `XPIAContext` 上下文管理

自实现会错过这些原生能力，且无法保证与 PyRIT 后续版本兼容。

### 4.7 为什么需要模态路由？

不同 Target 支持不同模态（文本/图片/音频/视频）：
- `OpenAIChatTarget`: 仅文本
- `OpenAIResponseTarget` (GPT-4o): 文本+图片
- `OpenAIImageTarget` (DALL-E): 文本输入→图片输出

`ModalityRouter` 在攻击前检查兼容性：
- 不支持多轮 → 降级到单轮
- 不支持图片 → 降级到纯文本
- 全部不支持 → 跳过攻击

### 4.8 为什么 GCG 支持双路径？

- **本地 torch 路径**: 无需 Azure ML，适合本地 GPU 测试和快速迭代
- **AML 管道路径**: 委托原生 `GCGGenerator`，利用 Azure ML 集群算力

两者生成相同的 `SeedPrompt` + 对抗性后缀，通过 `SuffixAppendConverter` 无缝集成到攻击链。

---

## 五、开发规则速查

1. **原生优先**: 使用 PyRIT 原生组件，不造轮子。原生机制能替代自建逻辑时，必须移除自建代码，不允许同时保留两套实现
2. **研究工作流**: 新功能开发前，arXiv 优先查找文献 → GitHub 查找相关代码 → 交叉验证后实施（arXiv 文献参考: PAIR 2310.08437 / TAP 2312.02191 / Many-Shot 2402.05124 / GCG 2307.15043 / Red Teaming 2202.01241 / JailbreakBench 2402.01135 / Crescendo 2402.12109 / Skeleton Key 2407.01576）
3. **避免硬编码**: 所有参数从配置文件读取
4. **PyRIT 优势边界**: 非优势领域推荐外部工具
5. **数据结构传递**: 使用 Pydantic 模型或原生对象
6. **错误处理**: 分层降级，单点失败不中断全局
7. **代码组织**: 按功能模块，`__init__.py` + `__all__`
8. **非PyRIT领域排除**: 不用PyRIT实现非优势功能
9. **代码审查**: 提交前过检查清单
10. **分层测试与回归**: 模块内改动→单元测试；模块间改动→集成测试；多模块改动→完整回归测试。测试失败必须修复，不允许跳过
11. **死代码即时清理**: 每次代码改动后运行 `ruff check --fix` 清理未使用导入/变量，手动清理未使用函数/死分支/过时注释，删除后同步清理 `__init__.py` 导出

详见: `docs/development_guidelines.md`（含全部开发规则，已整合）

---

## 六、配置速查

### 6.1 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `TARGET_ENDPOINT` | `http://localhost:11434/v1` | 目标 API 端点 |
| `TARGET_MODEL` | `qwen3:0.6b` | 目标模型名 |
| `TARGET_API_KEY` | `ollama` | 目标 API Key |
| `JUDGE_ENDPOINT` | 同 TARGET | 评分器端点 |
| `JUDGE_MODEL` | `qwen3:1.7b` | 评分器模型 |
| `BATCH_MAX_CONCURRENCY` | 4 | 批量并发数 |
| `BATCH_PER_ATTACK_TIMEOUT` | 300 | 单次超时(秒) |
| `INTERACTIVE_SELECTION` | true | 交互选择(false=CI/CD) |
| `VERBOSE_SUCCESS` | true | 成功攻击详情输出（合并原 VERBOSE） |
| `OWASP_SUCCESS_THRESHOLD` | 0.5 | L2 OWASP 成功率阈值 |
| `STOP_ON_FIRST_SUCCESS` | false | L3 全局首成功即停 |

### 6.2 差异化超时

```yaml
timeout_overrides:
  single_turn: 90
  converter_enhanced: 150
  multi_turn: 300
  sequential: 480
```

### 6.3 条件分派逻辑（不可变）

```python
if attack_group.prepended_conversation:  return "crescendo"
if attack_group.next_message is not None: return "prompt_sending"
return "red_teaming"
```

### 6.4 停止策略（三层最优策略）

| 层级 | 参数 | 默认 | 说明 |
|------|------|------|------|
| L1 | `completion_policy` | `FIRST_SUCCESS` | PyRIT 原生：同一 objective 多技术链首成功即停 |
| L2 | `owasp_success_threshold` | `0.5` | 同一 OWASP 分类内成功率达标即跳过剩余计划 |
| L3 | `stop_on_first_success` | `false` | 全局首成功即停（最激进） |

**L2 阈值合理范围**（基于 AI-300 考试 4 小时时限）:

| 阈值 | 所需成功数(6计划) | 场景 |
|------|------------------|------|
| 0.3 | 2 (33%) | 快速验证，时间紧迫 |
| 0.5 | 3 (50%) | **考试推荐**，平衡效率与置信度 |
| 0.8 | 5 (83%) | 深度审计，时间充裕 |

计算公式: `required = math.ceil(total * threshold)`

---

## 七、验证命令速查

```bash
# === 分层测试（§1.9）===
# 模块内改动 → 单元测试
pytest tests/unit/test_<module>.py -x -q

# 模块间改动 → 集成测试
pytest tests/integration/ -x -q

# 多模块改动 → 完整回归测试
pytest tests/ -x -q

# === 死代码清理（§1.10）===
python -m ruff check src/ pipeline.py --fix
python -m ruff check src/ pipeline.py --output-format=concise

# === 运行框架 ===
python pipeline.py http://192.168.0.22:11434
python pipeline.py http://192.168.0.22:11434 LLM01,LLM06
```

---

## 八、文档索引

| 文档 | 说明 |
|------|------|
| `docs/architecture_assessment.md` | L5 架构评估报告 v2.0（98/100） |
| `docs/architecture_design.md` | 完整架构设计（v10.0） |
| `docs/development_guidelines.md` | 开发文档规范（v4.0） |
| `docs/end_to_end_architecture.md` | 端到端数据驱动流程（v4.0） |
| `docs/datasets_architecture.md` | 数据集五层架构 |
| `docs/executor.md` | Executor 五层架构 |
| `docs/scenario.md` | Scenario 子系统（v2.0） |
| `docs/targets.md` | Target 15 种类型（v2.1） |
| `docs/converter_aware_adaptive_architecture.md` | Converter-Aware v3.0 架构 |
| `.assistant_pyrit/memory_bank.md` | 本文件（跨平台记忆库） |

---

## 九、待完成事项

- [x] GCG 白盒攻击完整实现 (`src/executor/promptgen/gcg_wrapper.py`) — 双路径（本地 torch + AML 管道）
- [x] XPIA 原生工作流对齐 — `XPIAWorkflowWrapper` 委托原生 `XPIAWorkflow`
- [x] RAG XPIA 专用工作流 — `RAGXPIAWorkflowWrapper`
- [x] ProcessingCallback 构建 — `ProcessingCallbackBuilder`（Agent/RAG/Simple 三种回调）
- [x] 模态路由系统 — `ModalityRouter`（TargetCapabilities + 模态检查 + 多模态消息构建）
- [x] OpenAIImageTarget 集成 — `openai_image` 类型注册到 TargetFactory
- [x] GCG AML 管道 — `generate_via_aml_async` + `SuffixAppendConverter` 集成
- [x] Benchmark 原生返回 — `run_native_async` 返回 `AttackResult`
- [x] WMDP 数据集支持 — `QuestionAnsweringWrapper.run_wmdp_async`
- [x] FuzzerResultPrinter — `FuzzerWrapper.print_result` / `print_templates`
- [x] Anecdoctor processing_model 参数支持
- [ ] 集成测试覆盖增强 (`tests/integration/`)
- [ ] `cli.py` 保留/删除决策评估
- [x] `scenario_orchestrator.py` 拆分升级重试逻辑 — 已由原生 AdaptiveScenario + Converter 变体替代

### Converter-Aware Adaptive Architecture v3.0（统一路径 + 原生优先）

**原生优先，消除双轨，保留自建不可替代部分**

**原生优先规则**:
1. 原生优先: 优先使用 PyRIT 原生组件（AdaptiveScenario、AdaptiveTechniqueDispatcher、SequentialAttack、FIRST_SUCCESS 等）
2. 消除双轨: 原生机制能替代自建逻辑时，必须移除自建代码
   - 自建 `AttackUpgradeStrategy` 多候选递归 → 原生 `SequentialAttack(FIRST_SUCCESS)` 提前停止
   - 自建 `add_converter` 升级策略 → 原生 `extra_request_converters` 渐进式追加
   - 自建 `generate_upgrade_plans` → 原生 `AdaptiveTechniqueDispatcher` 自动构建
   - 自建失败类型路由 → `FailureTypeRoutingSelector`（extends `EpsilonGreedyTechniqueSelector`）
3. 保留自建: 仅当原生框架无法覆盖时才保留自建逻辑
   - `per_attack_timeout` — PyRIT 原生无 per-attack 超时机制
   - OWASP 映射 — 通过原生 `memory_labels` 集成
   - `RateLimitedTarget` 并发信号量 + 503 重试 — PyRIT 原生不覆盖
4. Converter 变体: v3.0 使用原生 `extra_request_converters` 动态创建（Registry 仅保留 ~34 基础技术）
5. 执行路径: 统一走原生 `AI300AdaptiveScenario` 路径，双轨已消除

**研究工作流规则**:
1. arXiv 优先查找: 在 arxiv.org 优先搜索相关学术论文
2. GitHub 查找相关代码: 验证学术方法在生产级框架中的落地方式
3. 学术与实践对齐: 将 arXiv 理论与 GitHub 工程实现交叉验证

**arXiv 文献参考**: PAIR 2310.08437 / TAP 2312.02191 / Many-Shot 2402.05124 / GCG 2307.15043 / Red Teaming 2202.01241 / JailbreakBench 2402.01135 / Crescendo 2402.12109 / Skeleton Key 2407.01576

**GitHub 参考仓库**: Azure/PyRIT — 原生 AdaptiveScenario / EpsilonGreedyTechniqueSelector / SequentialAttack(FIRST_SUCCESS)

**v3.0 优化**:
- P0-B: `extra_request_converters` 替代变体预注册（Registry 精简 110→34）
- P0-A: 失败类型分析 + `selector.update_failure_type()`
- P1-A: `SelectorScope`（all_runs/current_run）
- P1-B: 移除 `per_attack_timeout`（原生 max_retries 足够）
- P1-C: `_get_attack_technique_factories()` 简化为仅 super()
- 三层停止策略: L1 FIRST_SUCCESS + L2 OWASP阈值 + L3 全局首停
- 测试: 1241 单元测试 + 34 集成测试 = 1275 全部通过
- 文档: `docs/converter_aware_adaptive_architecture.md`

---

## 十、二库定义

当说"写入二库"时，指以下两个文件，必须同时更新：
1. `.assistant_pyrit/memory_bank.md` — 记忆库（本文件，跨平台共享，任意 IDE 可读取）
2. `docs/development_guidelines.md` — 开发规范文档

> **更新说明**: v5.0 移除 `.catpawrules` 文件，全部规则仅保存在 `.assistant_pyrit/` 目录下，二库同步更新。

---

## 十一、跨平台同步说明

本文件设计为跨开发平台共享的记忆库，可在以下平台中使用：

| 平台 | 使用方式 |
|------|---------|
| **CatPaw** | 自动加载 `.assistant_pyrit/memory_bank.md` 作为项目记忆 |
| **Trae IDE** | 在项目设置中指定 `.assistant_pyrit/memory_bank.md` 为记忆库文件 |
| **Cursor** | 在 `.cursorrules` 中引用本文件 |
| **Claude Code** | 在 `CLAUDE.md` 中引用本文件 |
| **GitHub Copilot** | 在 `.github/copilot-instructions.md` 中引用本文件 |

**同步规则**:
1. 每次架构变更后更新本文件
2. 保持与 `docs/architecture_assessment.md` 和 `docs/development_guidelines.md` 一致
3. 本文件是速查参考，详细内容见对应文档
