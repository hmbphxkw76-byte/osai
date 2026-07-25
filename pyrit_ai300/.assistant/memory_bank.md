# PyRIT AI-300 跨平台记忆库

> **用途**: 本文件是跨开发平台（CatPaw / Trae IDE / Cursor / Claude Code / Copilot 等）共享的项目记忆库。  
> **更新规则**: 每次架构变更后必须同步更新此文件。  
> **版本**: v1.0 | **更新日期**: 2026-07-25

---

## 一、项目概览

- **项目名称**: PyRIT AI-300 — 端到端全自动 AI 红队框架
- **基础框架**: PyRIT 1.0.0
- **用途**: OffSec AI-300 考试和实际 AI 红队评估
- **总体对齐度**: 96% (L5 专家级)
- **主入口**: `pipeline.py`（九阶段顺序管道）
- **Python 版本**: 3.11+
- **配置体系**: 三级配置（显式参数 > 环境变量 > config.yaml）

---

## 二、架构记忆

### 2.1 五层 + ②.5 数据驱动架构

```
① 数据准备层 → DatasetManager.load_datasets() (OWASP本地/自定义/PyRIT远程)
② 数据管理层 → CentralMemory (add_seed_datasets_to_memory / get_seed_groups)
②.5 交互选择层 → SeedGroupSelector (build_catalog / filter / prompt_user)
③ 攻击准备层 → AttackPreparator (SeedGroup → AttackSeedGroup)
④ 攻击执行层 → ScenarioOrchestrator + NativeAttackExecutor
⑤ 评估与追踪层 → Scorer + PyRIT Memory 审计链
```

**关键约束**:
- 禁止直接构造 `PromptItem`（必须走五层流转）
- 禁止绕过选择层（pipeline 必须经过 `SeedGroupSelector`）
- 禁止修改 `SeedGroup` 对象（`source_seed_group` 保留原始引用）
- 条件分派逻辑不可变

### 2.2 Executor 五层架构

```
Layer 1: Prompt Generators → AnecdoctorWrapper + FuzzerWrapper
Layer 2: Attack Execution  → SingleTurnExecutor / MultiTurnExecutor
Layer 3: Compound           → SequentialExecutor (异构技术链)
Layer 4: Workflow           → ScenarioOrchestrator / BatchAttackOrchestrator
Layer 5: Benchmarks         → FairnessBiasWrapper / QuestionAnsweringWrapper
```

**核心设计**:
- `NativeAttackExecutor` 是 Facade，`execute_single_attack()` 按技术分派
- 核心不变量: `one-objective → one-result`
- 子执行器共享 `_create_scoring_config()` 和 `SeedGroupBuilder`

### 2.3 九阶段管道

```
[1/9] 初始化 PyRIT → CentralMemory + SQLite (每次独立 DB)
[2/9] 侦察          → 端点发现 + AI 类型识别 + 能力探测
[3/9] 分析          → 策略选择 + 优先级评估
[4/9] 数据准备+管理  → DatasetManager → CentralMemory
[5/9] 选择+准备     → SeedGroupSelector → AttackPreparator → AttackPlan
[6/9] 批量执行      → ScenarioOrchestrator (并发+超时+升级重试)
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
| `attack/single_turn/single_turn_executor.py` | 单轮执行 | `SingleTurnExecutor` |
| `attack/multi_turn/multi_turn_executor.py` | 多轮执行 | `MultiTurnExecutor` |
| `attack/compound/sequential_executor.py` | 顺序组合 | `SequentialExecutor` |
| `attack/component/seed_group_builder.py` | SeedGroup构建 | `SeedGroupBuilder` |
| `workflow/scenario_orchestrator.py` | 批量调度 | `ScenarioOrchestrator` / `execute_batch_attacks` |
| `workflow/batch_orchestrator.py` | 批量编排 | `BatchAttackOrchestrator` |
| `workflow/xpia_workflow.py` | XPIA工作流 | `XPIAWorkflowWrapper` |

### 3.3 src/targets/（11种Target类型）

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
| `text` | `TextTarget` | 调试输出 |

**关键设计**:
- `TargetParams` 48 字段覆盖全部构造参数
- `detect_auth_mode`: Azure → Entra ID, 非Azure → api_key
- `_build_openai_httpx_kwargs`: SDK参数 vs httpx-only参数双路径拆分
- `detect_target_type`: side-effect-free (仅GET请求)
- `_LEGACY_TYPE_ALIASES`: 旧类型名向后兼容

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

---

## 五、开发规则速查

1. **原生优先**: 使用 PyRIT 原生组件，不造轮子
2. **避免硬编码**: 所有参数从配置文件读取
3. **PyRIT 优势边界**: 非优势领域推荐外部工具
4. **数据结构传递**: 使用 Pydantic 模型或原生对象
5. **错误处理**: 分层降级，单点失败不中断全局
6. **代码组织**: 按功能模块，`__init__.py` + `__all__`
7. **非PyRIT领域排除**: 不用PyRIT实现非优势功能
8. **代码审查**: 提交前过检查清单
9. **测试先行**: 每次修改后运行测试

详见: `docs/development_guidelines.md`

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
| `VERBOSE` | false | 详细输出 |
| `VERBOSE_SUCCESS` | false | 仅成功详细输出 |

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

---

## 七、验证命令速查

```bash
# 数据集五层架构验证
python verify_5layer.py

# Target 工厂验证
python verify_targets.py

# 全部测试
pytest tests/

# 运行框架
python pipeline.py http://192.168.0.22:11434
python pipeline.py http://192.168.0.22:11434 LLM01,LLM06
```

---

## 八、文档索引

| 文档 | 说明 |
|------|------|
| `docs/architecture_assessment.md` | L5 架构评估报告（96/100） |
| `docs/architecture_design.md` | 完整架构设计（v8.0） |
| `docs/development_guidelines.md` | 开发文档规范 |
| `docs/end_to_end_architecture.md` | 端到端数据驱动流程 |
| `docs/datasets_architecture.md` | 数据集五层架构 |
| `docs/executor.md` | Executor 五层架构 |
| `docs/targets.md` | Target 11 种类型 |
| `docs/pyrit_1_0_0_alignment_report.md` | PyRIT 1.0.0 对齐报告 |
| `.assistant/memory_bank.md` | 本文件（跨平台记忆库） |

---

## 九、待完成事项

- [ ] GCG 白盒攻击完整实现 (`src/executor/promptgen/gcg_wrapper.py`)
- [ ] 集成测试覆盖增强 (`tests/integration/`)
- [ ] `cli.py` 保留/删除决策评估
- [ ] `scenario_orchestrator.py` 拆分升级重试逻辑（983行较长）

---

## 十、跨平台同步说明

本文件设计为跨开发平台共享的记忆库，可在以下平台中使用：

| 平台 | 使用方式 |
|------|---------|
| **CatPaw** | 自动加载 `.assistant/memory_bank.md` 作为项目记忆 |
| **Trae IDE** | 在项目设置中指定 `.assistant/memory_bank.md` 为记忆库文件 |
| **Cursor** | 在 `.cursorrules` 中引用本文件 |
| **Claude Code** | 在 `CLAUDE.md` 中引用本文件 |
| **GitHub Copilot** | 在 `.github/copilot-instructions.md` 中引用本文件 |

**同步规则**:
1. 每次架构变更后更新本文件
2. 保持与 `docs/architecture_assessment.md` 和 `docs/development_guidelines.md` 一致
3. 本文件是速查参考，详细内容见对应文档
