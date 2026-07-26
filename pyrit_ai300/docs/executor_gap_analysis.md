# Executor 子系统：当前代码与 PyRIT 1.0.0 官方标准差距分析

> 评估日期：2026-07-26 | 评估基准：PyRIT 1.0.0 官方文档（11 页）  
> 评估范围：`src/executor/` 全部模块 | 评估方法：逐模块代码审查 + 官方文档对比  
> ⚠️ 本文档仅分析，不包含代码修改

---

## 目录

1. [评估总览](#1-评估总览)
2. [逐层差距分析](#2-逐层差距分析)
3. [XPIA 与 RAG 攻击专项分析](#3-xpia-与-rag-攻击专项分析)
4. [GCG 白盒攻击专项分析](#4-gcg-白盒攻击专项分析)
5. [模态反馈专项分析](#5-模态反馈专项分析)
6. [AI-300 考试就绪度评估](#6-ai-300-考试就绪度评估)
7. [差距优先级排序与建议路线图](#7-差距优先级排序与建议路线图)

---

## 1. 评估总览

### 1.1 评分矩阵

| 层级 | 模块 | 官方对应 | 对齐度 | 评级 |
|:--|:--|:--|:--:|:--:|
| Layer 1 | Prompt Generators (Anecdoctor/Fuzzer) | `pyrit.executor.promptgen` | 80% | 🟡 |
| Layer 1 | GCG Wrapper | `pyrit.executor.promptgen.gcg` | 60% | 🟡 |
| Layer 2 | Attack Core (native_executor) | `pyrit.executor.attack.core` | 95% | 🟢 |
| Layer 2 | Single-Turn Executor | `pyrit.executor.attack.single_turn` | 95% | 🟢 |
| Layer 2 | Multi-Turn Executor | `pyrit.executor.attack.multi_turn` | 95% | 🟢 |
| Layer 2 | Component (SeedGroupBuilder) | `pyrit.executor.attack.component` | 85% | 🟢 |
| Layer 2 | Streaming (BargeIn) | `pyrit.executor.attack.streaming` | 90% | 🟢 |
| Layer 3 | Compound (Sequential) | `pyrit.executor.attack.compound` | 95% | 🟢 |
| Layer 4 | Scenario Orchestrator | — (自研增强) | N/A | 🟢 |
| Layer 4 | **XPIA Workflow** | `pyrit.executor.workflow.xpia` | **40%** | 🔴 |
| Layer 5 | Benchmarks (QA/Fairness) | `pyrit.executor.benchmark` | 85% | 🟢 |
| 横切 | Attack Configuration | `pyrit.executor.attack.core` | 90% | 🟢 |
| 横切 | **Modality Feedback** | TargetCapabilities | **0%** | 🔴 |
| **整体对齐度** | | | **~82%** | 🟡 |

### 1.2 评级标准

| 评级 | 范围 | 含义 |
|:--:|:--|:--|
| 🟢 | 85-100% | 对齐 L5 专家水平，可直接用于生产 |
| 🟡 | 60-84% | 基本对齐但存在功能缺口，需要增强 |
| 🔴 | <60% | 存在重大差距，影响核心功能 |

### 1.3 核心发现

**✅ 已对齐的强项（9/14 项 🟢）**：
- 原生 `AttackExecutor` 集成（使用 `execute_attack_from_seed_groups_async()`）
- 单轮/多轮攻击执行器完整实现，参数映射准确
- 组合攻击（SequentialAttack + 5 种 completion_policy）
- 横切配置工厂（AttackAdversarialConfig / AttackScoringConfig / AttackConverterConfig）
- `AttackResultAttribution` 父级编排器关联
- `PrependedConversationConfig` 前置对话控制
- 基准测试使用原生 benchmark 类
- `ScenarioOrchestrator` 自研增强（并发+超时+升级重试+输出）
- 向后兼容 shim（`src.orchestrators` → `src.executor`）

**⚠️ 需要改进的差距（3/14 项 🟡）**：
- GCG Wrapper 未使用官方 AML 管道 API
- Prompt Generator Wrapper 未完全对齐原生 `execute_async` 返回值
- Benchmark Wrapper 返回 dict 而非原生 `AttackResult`

**🔴 重大差距（2/14 项 🔴）**：
- **XPIA Workflow**：未使用原生 `XPIAWorkflow` 类，缺乏 Converter 集成、Processing Callback 模式和结构化工作流阶段
- **Modality Feedback**：完全缺失 `TargetCapabilities` 系统和模态路由

---

## 2. 逐层差距分析

### 2.1 Layer 1: Prompt Generators 🟡 (80%)

#### 2.1.1 AnecdoctorWrapper

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 类名 | `AnecdoctorGenerator` | `AnecdoctorWrapper` | 命名不一致 |
| API | `execute_async(content_type, language, evaluation_data)` → 返回 `AnecdoctorResult` | `generate_async(evaluation_data, content_type, language)` → 返回 `List[Seed]` | 返回类型不同 |
| 知识图谱 | `processing_model` 参数启用 KG 增强 | ❌ 未实现 | 功能缺失 |
| 多语言 | 支持 `language` 参数切换生成语言 | ✅ 已实现 | 已对齐 |
| 原生委托 | 直接使用 `pyrit.executor.promptgen.AnecdoctorGenerator` | ❌ 自行实现逻辑 | 未使用原生 API |

**差距分析**：
- 项目 `AnecdoctorWrapper` 没有使用原生 `AnecdoctorGenerator` 类，而是自行实现了生成逻辑
- 缺少知识图谱增强功能（`processing_model` 参数），这是官方文档强调的重要特性
- 返回 `List[Seed]` 而非原生的 `AnecdoctorResult`（包含 `generated_content` 元数据）

#### 2.1.2 FuzzerWrapper

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 类名 | `GPTFuzzerGenerator` (via `FuzzerGenerator`) | `FuzzerWrapper` | 命名不一致 |
| 变异算子 | 5 种：Shorten/Expand/Rephrase/Similar/CrossOver | ✅ 已实现 | 已对齐 |
| MCTS 搜索 | 官方使用 MCTS 风格搜索进化模板 | ✅ 已实现 | 已对齐 |
| API | `execute_async(prompts, prompt_templates)` → 返回 `FuzzerResult` | `mutate_async(existing_seeds, num_variants)` → 返回 `List[Seed]` | 返回类型不同 |
| 原生委托 | 直接使用 `pyrit.executor.promptgen.fuzzer.FuzzerGenerator` | ❌ 自行实现 | 未使用原生 API |
| 结果打印 | `FuzzerResultPrinter.print_result()` | ❌ 未实现 | 功能缺失 |

#### 2.1.3 GCGWrapper

详见 [第 4 节：GCG 专项分析](#4-gcg-白盒攻击专项分析)。

---

### 2.2 Layer 2: Attack Execution 🟢 (95%)

#### 2.2.1 NativeAttackExecutor (Facade)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 核心引擎 | `AttackExecutor` (原生并行执行器) | ✅ 使用 `AttackExecutor(max_concurrency=N)` | 已对齐 |
| 执行入口 | `execute_attack_from_seed_groups_async()` | ✅ 使用原生方法 | 已对齐 |
| 分派逻辑 | 根据 Attack 类型自动分派 | ✅ `SINGLE_TURN_ATTACKS` 分派 | 已对齐 |
| 并发控制 | `asyncio.Semaphore` | ✅ 原生 AttackExecutor 内部处理 | 已对齐 |
| 部分失败 | `return_partial_on_failure` | ✅ 已实现 | 已对齐 |
| Attribution | `AttackResultAttribution` | ✅ 已实现 | 已对齐 |

**评价**：这是项目最对齐的部分。`NativeAttackExecutor` 正确使用了原生 `AttackExecutor` 作为核心引擎，通过 `execute_attack_from_seed_groups_async()` 执行攻击，并支持 `AttackResultAttribution`。

#### 2.2.2 SingleTurnExecutor

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 技术覆盖 | PromptSending / ManyShot / SkeletonKey / ChunkedRequest | ✅ 全部覆盖 | 已对齐 |
| Adversarial Config | 单轮不接受 `attack_adversarial_config` | ✅ 不传入 | 已对齐 |
| Refusal Scorer | 单轮剥离 `refusal_scorer`（避免 `warn_if_set`） | ✅ 使用 `NO_REFUSAL_SCORER_ATTACKS` | 已对齐 |
| 参数约束 | `AttackParameters.excluding("prepended_conversation")` | ✅ 已实现 | 已对齐 |
| Converter 链 | `AttackConverterConfig` | ✅ 通过 `load_preset_converter_chain()` | 已对齐 |

**评价**：完全对齐。正确处理了单轮攻击的特殊约束（无 adversarial、无 refusal_scorer、参数排除）。

#### 2.2.3 MultiTurnExecutor

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 技术覆盖 | RedTeaming / Crescendo / TAP / PAIR / TOT | ✅ 全部覆盖 | 已对齐 |
| Adversarial Config | 必填 `AttackAdversarialConfig` | ✅ 使用 `create_attack_adversarial_config()` | 已对齐 |
| 参数映射 | max_turns vs tree_depth vs tree_width | ✅ 通过常量集合正确映射 | 已对齐 |
| TAP 专用评分 | `TAPAttackScoringConfig` | ✅ 使用 `create_tap_scoring_config()` | 已对齐 |
| PrependedConversation | 当 multi_turn_steps > 1 时启用 | ✅ 已实现 | 已对齐 |
| Crescendo 回溯 | `max_backtracks` 参数 | ✅ 已实现 | 已对齐 |
| 自定义系统提示 | 从 YAML metadata 加载 `adversarial_system_prompt` | ✅ 已实现 | 已对齐 |
| 自定义模板 | `adversarial_prompt_template` / `first_message` | ✅ 已实现 | 已对齐 |

**评价**：完全对齐。多轮攻击的参数映射、TAP 专用评分、Crescendo 回溯、自定义系统提示等高级特性均已正确实现。

#### 2.2.4 SeedGroupBuilder

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 角色交替 | even→user, odd→assistant | ✅ 已实现 | 已对齐 |
| 最后一条强制 user | 最后 SeedPrompt role=user | ✅ 已实现 | 已对齐 |
| 三要素提取 | objective / next_message / prepended_conversation | ✅ 委托原生 `from_seed_group_async()` | 已对齐 |
| AttackSeedGroup | 使用原生 `AttackSeedGroup` | ✅ 已使用 | 已对齐 |

**评价**：完全对齐。正确实现了角色交替规则和三要素提取。

#### 2.2.5 BargeInExecutor

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 状态 | 需要 `audio_chunks` (AsyncIterator[bytes]) | ⚠️ stub, deprecated | 已对齐（正确标记为 deprecated） |
| 回退 | 纯文本回退到 `prompt_sending` | ✅ 已实现 | 已对齐 |

---

### 2.3 Layer 3: Compound 🟢 (95%)

#### 2.3.1 SequentialExecutor

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 核心类 | `SequentialAttack` + `SequentialChildAttack` | ✅ 使用原生类 | 已对齐 |
| Completion Policy | 5 种策略 | ✅ 全部支持 | 已对齐 |
| 异构技术链 | 每步可不同 Attack 技术 | ✅ 已实现 | 已对齐 |
| Child 结果保留 | `child_attack_results` | ✅ 原生保留 | 已对齐 |
| SeedGroup 共享 | 每个 child 携带自己的 `AttackSeedGroup` | ✅ 已实现 | 已对齐 |

**评价**：完全对齐。正确使用了原生 `SequentialAttack` 和所有 5 种 completion policy。

---

### 2.4 Layer 4: Workflow

#### 2.4.1 ScenarioOrchestrator 🟢 (自研增强)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 批量并发 | — (自研) | ✅ `asyncio.Semaphore` + `ProgressDashboard` | 自研增强 |
| 升级重试 | — (自研) | ✅ `_try_upgrade_plans()` + 失败类型路由 | 自研增强 |
| 超时控制 | — (自研) | ✅ 差异化超时 | 自研增强 |
| 双通道输出 | — (自研) | ✅ 终端 + Markdown | 自研增强 |
| 原生委托 | 委托 `NativeAttackExecutor` | ✅ | 已对齐 |
| Attribution | `AttackResultAttribution` | ✅ | 已对齐 |

**评价**：`ScenarioOrchestrator` 是项目自研的增强层，在原生 PyRIT 之上添加了批量调度、升级重试、超时控制和双通道输出。这些功能在官方 PyRIT 中不存在，是项目的增值部分。

#### 2.4.2 XPIAWorkflowWrapper 🔴 (40%) — **重大差距**

详见 [第 3 节：XPIA 与 RAG 专项分析](#3-xpia-与-rag-攻击专项分析)。

---

### 2.5 Layer 5: Benchmarks 🟢 (85%)

#### 2.5.1 QuestionAnsweringWrapper

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 核心类 | `QuestionAnsweringBenchmark` | ✅ 使用原生类 | 已对齐 |
| Context | `QuestionAnsweringBenchmarkContext` | ✅ 已使用 | 已对齐 |
| API | `execute_async(question_answering_entry=...)` → `AttackResult` | ⚠️ `run_async()` → `dict` | 返回类型不同 |
| Scorer | `SelfAskQuestionAnswerScorer` | ✅ 已支持 | 已对齐 |
| WMDP 数据集 | `fetch_wmdp_dataset()` | ❌ 未集成 | 功能缺失 |

#### 2.5.2 FairnessBiasWrapper

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 核心类 | `FairnessBiasBenchmark` | ✅ 使用原生类 | 已对齐 |
| API | `execute_async(subject, story_type)` → `AttackResult` | ⚠️ `run_async()` → `dict` | 返回类型不同 |
| 多实验 | `num_experiments` 参数 | ✅ 已支持 | 已对齐 |
| 结果分析 | 官方有 `Analyzing Results` 章节 | ❌ 未实现统计分析 | 功能缺失 |

**评价**：基准测试 Wrapper 正确使用了原生 benchmark 类，但返回 dict 而非原生 `AttackResult`，且缺少 WMDP 数据集集成和结果分析功能。

---

### 2.6 横切配置 🟢 (90%)

#### 2.6.1 AttackBuilder

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| Attack 类映射 | 11 种 Attack 类 | ✅ 全部映射 | 已对齐 |
| 弃用处理 | role_play/flip/context_compliance 已移除 | ✅ 自动回退到 prompt_sending | 已对齐 |
| AdversarialConfig | 完整 4 字段配置 | ✅ system_prompt / first_message / template | 已对齐 |
| ConverterConfig | request/response converters | ✅ 已实现 | 已对齐 |
| PrependedConversationConfig | `apply_converters_to_roles` | ✅ 已实现 | 已对齐 |
| Attribution | `AttackResultAttribution` | ✅ 已实现 | 已对齐 |
| ScenarioEventHandler | 事件可观测性 | ✅ 已实现 | 已对齐（L5 增强） |

**评价**：横切配置工厂非常完善，正确处理了所有 PyRIT 1.0.0 的配置对象，并增加了事件可观测性增强。

---

## 3. XPIA 与 RAG 攻击专项分析

### 3.1 官方 XPIAWorkflow 标准分析

#### 3.1.1 官方 API 签名

```python
# 官方构造
workflow = XPIAWorkflow(
    attack_setup_target=abs_target,        # AzureBlobStorageTarget
    converter_config=converter_config,     # StrategyConverterConfig (含 TextJailbreakConverter)
    scorer=scorer,                         # SubStringScorer
)

# 官方执行
result = await workflow.execute_async(
    attack_content=xpia_prompt_group,      # Message (含 MessagePiece)
    processing_callback=processing_callback,  # Callable[[], Awaitable[str]]
)
```

#### 3.1.2 官方工作流阶段

```
1. Validation（验证）
   → DEBUG: Starting validation for workflow XPIAWorkflow
   → DEBUG: Validation completed for workflow XPIAWorkflow

2. Setup（设置）
   → DEBUG: Starting setup for workflow XPIAWorkflow
   → DEBUG: Setup completed for workflow XPIAWorkflow

3. Execution（执行）
   → INFO: Starting execution of workflow XPIAWorkflow
   → INFO: Sending prompt to prompt target (after applying converters)
   → INFO: Uploading to Azure Storage as blob
   → INFO: Received response from prompt target
   → [processing_callback 执行]
   → [scorer 评分]
```

#### 3.1.3 官方 Converter 集成

```python
from pyrit.converter import TextJailbreakConverter
from pyrit.executor.core import StrategyConverterConfig
from pyrit.prompt_normalizer import ConverterConfiguration

jailbreak_converter = TextJailbreakConverter(jailbreak_template=jailbreak_template)
converter_config = StrategyConverterConfig(
    request_converters=ConverterConfiguration.from_converters(
        converters=[jailbreak_converter],
    )
)
```

官方工作流在发送攻击内容前，会先通过 Converter 链处理内容（如将注入包装到 HTML 模板中），这是 XPIA 攻击的核心步骤。

### 3.2 项目 XPIAWorkflowWrapper 差距分析

#### 3.2.1 API 对比

| 维度 | 官方 `XPIAWorkflow` | 项目 `XPIAWorkflowWrapper` | 差距 |
|:--|:--|:--|:--|
| 基类 | 继承原生 `XPIAWorkflow` | 独立类，不继承 | 🔴 未使用原生类 |
| 构造参数 | `attack_setup_target` / `converter_config` / `scorer` 构造时传入 | 运行时传入 `execute_async()` 参数 | 🔴 API 不一致 |
| 内容类型 | `Message` (含 `MessagePiece`) | `str` 字符串 | 🔴 使用旧 API |
| Converter | `StrategyConverterConfig` 集成 | ❌ 无 Converter 参数 | 🔴 功能缺失 |
| 返回类型 | `XPIAWorkflowResult`（含 `score` 属性） | `dict`（含 status/response/score） | 🟡 返回类型不同 |
| 工作流阶段 | Validation → Setup → Execution（3 阶段） | 直接执行（无阶段划分） | 🟡 缺少结构化阶段 |
| 日志级别 | DEBUG/INFO 结构化日志 | 简单 logger.info | 🟡 可观测性不足 |
| Memory 集成 | 通过 `initialize_pyrit_async` 集成 | 手动 `send_prompt_async` | 🟡 未完全集成 |

#### 3.2.2 代码差距详情

**差距 1：未使用原生 `XPIAWorkflow` 类**

```python
# 项目实现（当前）
class XPIAWorkflowWrapper:
    async def execute_async(self, attack_content: str, attack_setup_target, ...):
        # 手动发送 prompt
        attack_message = Message(role="user", content=attack_content)  # 旧 API
        attack_response = await attack_setup_target.send_prompt_async(...)
        # 手动处理 callback
        # 手动评分
        return {"status": ..., "response": ..., "score": ...}
```

```python
# 官方标准
from pyrit.executor.workflow import XPIAWorkflow

workflow = XPIAWorkflow(
    attack_setup_target=abs_target,
    converter_config=converter_config,
    scorer=scorer,
)
result = await workflow.execute_async(
    attack_content=xpia_prompt_group,  # Message with MessagePiece
    processing_callback=processing_callback,
)
```

**差距 2：缺少 Converter 集成**

项目 `XPIAWorkflowWrapper` 没有 `converter_config` 参数，无法在发送攻击内容前应用 Converter 链（如 `TextJailbreakConverter` 将注入包装到 HTML 模板中）。这是 XPIA 攻击的核心步骤。

**差距 3：使用旧版 Message API**

```python
# 项目（旧 API）
attack_message = Message(role="user", content=attack_content)

# 官方（新 API）
xpia_prompt = MessagePiece(
    role="user",
    original_value=xpia_text,
    original_value_data_type="text",
    prompt_metadata={"file_name": "index.html"},
)
xpia_prompt_group = Message(message_pieces=[xpia_prompt])
```

项目使用 `Message(role="user", content=...)` 旧版 API，而官方使用 `MessagePiece` + `Message(message_pieces=[...])` 新版 API。新 API 支持多模态内容（文本+图片）和元数据（如 `file_name` 用于 Blob 上传）。

**差距 4：缺少 Processing Callback 模式**

虽然项目 `execute_async` 接受 `processing_callback` 参数，但缺少官方文档中的关键模式：
- 官方 Processing Callback 模拟一个完整的 AI Agent（使用 OpenAI Responses API + Function Tool Calling）
- 项目的 callback 只是简单的 `await processing_callback()` 调用，没有展示如何构建 Agent 模拟

**差距 5：缺少 RAG 专用测试流程**

官方 Workflow 页面展示了两个 XPIA 示例：
1. Website XPIA（Blob Storage → Agent fetch）
2. AI Recruiter (RAG) XPIA（简历 → RAG 系统处理）

项目只有通用的 `XPIAWorkflowWrapper`，没有 RAG 专用的测试流程或示例。

### 3.3 RAG 攻击差距分析

#### 3.3.1 当前 RAG 攻击能力

| 能力 | 实现状态 | 说明 |
|:--|:--:|:--|
| AzureBlobStorageTarget | ✅ | `target_factory.py` 中已实现，注释提到"XPIA 载荷投递"和"RAG 系统" |
| XPIA Workflow 框架 | 🟡 | `XPIAWorkflowWrapper` 存在但未使用原生 API |
| Converter 集成 | ❌ | 无 `TextJailbreakConverter` 集成 |
| RAG Processing Callback | ❌ | 无 RAG 系统模拟 callback |
| RAG 注入检测 Scorer | 🟡 | 有 `create_injection_scorer()` 但非 RAG 专用 |
| 知识库投毒测试 | ❌ | 无专用测试流程 |
| 检索操控测试 | ❌ | 无专用测试流程 |
| 数据泄露检测 | ✅ | 有 `create_leakage_scorer()` |

#### 3.3.2 RAG 攻击缺失的关键组件

1. **文档格式适配 Converter**：将注入内容包装到不同文档格式（HTML/PDF/Word/Markdown）中的 Converter
2. **RAG 系统模拟**：模拟 RAG 检索+生成流程的 Processing Callback
3. **向量数据库交互**：向向量数据库投递恶意文档的能力
4. **检索结果操控测试**：测试是否可以通过注入影响检索排序
5. **多文档注入测试**：在多个文档中同时注入，测试累积效果

### 3.4 对 AI-300 考试的影响

| 考试知识点 | 当前就绪度 | 差距 |
|:--|:--:|:--|
| 间接提示注入原理 | 🟢 | 理论理解充分，原理文档已覆盖 |
| XPIA 攻击执行 | 🔴 | 未使用原生 `XPIAWorkflow`，缺乏 Converter 集成 |
| RAG 知识库投毒 | 🔴 | 无 RAG 专用测试流程 |
| Agent 工具调用注入 | 🟡 | Target 层支持但 Workflow 层未集成 |
| 注入检测评分 | 🟡 | 有通用 Scorer 但非专用 |
| 多模态注入 | 🔴 | 完全缺失 Modality Feedback |

---

## 4. GCG 白盒攻击专项分析

### 4.1 官方 GCG 标准分析

#### 4.1.1 官方两种使用方式

**方式一：使用预生成后缀（SuffixAppendConverter）**

```python
from pyrit.converter import SuffixAppendConverter

suffix = '$\\ inqu Here spher =" vas_{( ...'
converter = ConverterConfiguration.from_converters(
    converters=[SuffixAppendConverter(suffix=suffix)]
)
attack = PromptSendingAttack(
    objective_target=target,
    attack_converter_config=AttackConverterConfig(request_converters=converter),
)
```

**方式二：通过 AML 生成 GCG 后缀**

```python
from pyrit.executor.promptgen.gcg import (
    GCGAlgorithmConfig, GCGConfig, GCGDataConfig,
    GCGModelConfig, GCGOutputConfig,
)

config = GCGConfig(
    models=[GCGModelConfig(name="meta-llama/Llama-2-7b-chat-hf")],
    algorithm=GCGAlgorithmConfig(n_steps=5, batch_size=64, test_steps=1),
    output=GCGOutputConfig(result_prefix="gcg_suffix"),
)
```

#### 4.1.2 官方 GCG 架构

```
pyrit.executor.promptgen.gcg/
├── config.py          ← GCGConfig / GCGAlgorithmConfig / GCGModelConfig / GCGDataConfig / GCGOutputConfig
├── experiments/
│   └── run.py         ← AML 训练入口 (python -m pyrit.executor.promptgen.gcg.experiments.run)
├── src/
│   └── Dockerfile     ← CUDA 12.1 + Python 3.11 + pip install -e ".[gcg]"
└── GCGGenerator       ← 原生生成器（execute_async）
```

### 4.2 项目 GCGWrapper 差距分析

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 实现方式 | AML 管道（云端 GPU 训练） | 本地 torch 直接计算 | 🟡 架构不同 |
| 配置 | `GCGConfig` dataclass（含 model/algorithm/data/output 配置） | `GCGConfig` dataclass（含优化参数） | 🟡 配置结构不同 |
| 模型访问 | 通过 AML 远程 GPU 实例 | 本地 HuggingFace 模型 | 🟡 部署方式不同 |
| API 入口 | `GCGGenerator.execute_async()` | `GCGWrapper.generate_async()` | 🟡 命名不同 |
| 后缀使用 | `SuffixAppendConverter` | 直接拼接到 objective | 🟡 未使用 Converter |
| AML 集成 | `MLClient` + `command()` job | ❌ 无 AML 集成 | 🔴 功能缺失 |
| 数据集 | `GCGDataConfig`（CSV 路径/计数） | ❌ 无数据集配置 | 🔴 功能缺失 |
| Dockerfile | CUDA 12.1 环境定义 | ❌ 无 | 🔴 功能缺失 |
| 延迟导入 | N/A（AML 远程执行） | ✅ torch/transformers 延迟导入 | 项目增强 |
| 安全降级 | N/A | ✅ `is_available` 检查 + 空列表降级 | 项目增强 |
| OOM 处理 | N/A | ✅ batch_size 自动减半 | 项目增强 |

### 4.3 GCG 差距评价

**项目的 GCG 实现实际上在某些方面比官方更完整**：
- ✅ 完整的 GCG 梯度优化循环（前向传播→反向传播→top-k 选择→候选评估）
- ✅ 延迟导入机制（不影响无 GPU 环境）
- ✅ 安全降级（不可用时返回空列表而非异常）
- ✅ OOM 自动恢复（batch_size 减半）
- ✅ 提前终止机制

**但缺少官方的关键能力**：
- ❌ AML 云端训练（需要 ≥24GB vRAM GPU）
- ❌ `GCGDataConfig` 数据集配置（AdvBench CSV）
- ❌ `GCGGenerator` 原生 API
- ❌ `SuffixAppendConverter` 集成（生成的后缀应通过 Converter 附加）
- ❌ Dockerfile 环境定义

**建议**：保留项目现有的本地 GCG 实现，同时增加对官方 AML 管道的支持（作为可选后端）。

---

## 5. 模态反馈专项分析

### 5.1 官方 Modality Feedback 标准

#### 5.1.1 TargetCapabilities 系统

```python
from pyrit.prompt_target.common.target_capabilities import TargetCapabilities
from pyrit.prompt_target.common.target_configuration import TargetConfiguration

objective_target = OpenAIImageTarget(
    custom_configuration=TargetConfiguration(
        capabilities=TargetCapabilities(
            supports_multi_turn=True,
            supports_editable_history=True,
            supports_multi_message_pieces=True,
            input_modalities=frozenset({frozenset({"text", "image_path"})}),
            output_modalities=frozenset({frozenset({"image_path"})}),
        )
    )
)
```

#### 5.1.2 模态路由检查

```python
# 检查对抗目标是否接受图片反馈
adversarial_accepts_text_plus_image = frozenset({"text", "image_path"}) in adversarial_input_modalities

if adversarial_accepts_text_plus_image:
    # 转发图片 + 文本评分
else:
    # 仅转发文本评分
```

#### 5.1.3 多模态种子消息

```python
next_message = Message(
    message_pieces=[
        MessagePiece(role="user", original_value="", original_value_data_type="text",
                     prompt_metadata={"adversarial_placeholder": True}),
        MessagePiece(role="user", original_value=str(image_path), original_value_data_type="image_path"),
        MessagePiece(role="user", original_value=str(ship_path), original_value_data_type="image_path"),
    ]
)
```

### 5.2 项目实现状态

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| `TargetCapabilities` | 完整能力声明系统 | ❌ 未实现 | 🔴 |
| `TargetConfiguration` | 目标配置（含 capabilities） | ❌ 未实现 | 🔴 |
| 模态路由 | 根据能力自动转发/不转发媒体 | ❌ 未实现 | 🔴 |
| `OpenAIImageTarget` | 图片生成目标 | ❌ 未实现 | 🔴 |
| 多模态种子 | `MessagePiece` + `data_type="image_path"` | ❌ 未实现 | 🔴 |
| 对抗占位符 | `adversarial_placeholder: True` 元数据 | ❌ 未实现 | 🔴 |
| Crescendo 图片编辑 | 多轮图片编辑攻击 | ❌ 未实现 | 🔴 |
| Red Teaming 多模态 | 多轮多模态红队攻击 | ❌ 未实现 | 🔴 |
| TAP 多模态 | 多模态树搜索攻击 | ❌ 未实现 | 🔴 |

### 5.3 影响评估

模态反馈的完全缺失意味着：
1. 无法测试图片生成 AI 的安全性
2. 无法测试多模态 Agent 的注入攻击
3. 无法在多轮攻击中转发图片反馈
4. 无法使用 Crescendo 进行渐进式图片编辑攻击

这对 AI-300 考试中涉及多模态 AI 系统的测试场景有直接影响。

---

## 6. AI-300 考试就绪度评估

### 6.1 考试知识点覆盖矩阵

| 考试领域 | 知识点 | 代码就绪度 | 文档就绪度 | 综合评估 |
|:--|:--|:--:|:--:|:--:|
| **LLM 攻击** | 直接提示注入 | 🟢 | 🟢 | 🟢 |
| | 越狱（Jailbreak） | 🟢 | 🟢 | 🟢 |
| | 数据泄露 | 🟢 | 🟢 | 🟢 |
| | 多轮自适应攻击 | 🟢 | 🟢 | 🟢 |
| | GCG 对抗后缀 | 🟡 | 🟢 | 🟡 |
| **Agent 攻击** | Agent 工具调用注入 | 🟡 | 🟢 | 🟡 |
| | Agent 劫持 | 🟡 | 🟢 | 🟡 |
| | 工具投毒 | 🔴 | 🟡 | 🔴 |
| | Agent 权限提升 | 🟡 | 🟡 | 🟡 |
| **RAG 攻击** | 间接提示注入 | 🔴 | 🟢 | 🟡 |
| | 知识库投毒 | 🔴 | 🟢 | 🟡 |
| | 检索操控 | 🔴 | 🟡 | 🔴 |
| | 上下文污染 | 🟡 | 🟢 | 🟡 |
| | 数据泄露检测 | 🟢 | 🟢 | 🟢 |
| **多模态** | 图片生成攻击 | 🔴 | 🟢 | 🔴 |
| | 多模态注入 | 🔴 | 🟢 | 🔴 |
| | 媒体反馈控制 | 🔴 | 🟢 | 🔴 |
| **基准测试** | Q&A 准确性 | 🟢 | 🟢 | 🟢 |
| | 公平性偏差 | 🟢 | 🟢 | 🟢 |

### 6.2 就绪度总结

| 领域 | 就绪度 | 主要差距 |
|:--|:--:|:--|
| LLM 攻击 | **90%** | GCG 缺少 AML 管道 |
| Agent 攻击 | **50%** | XPIA 未使用原生 API，缺少工具投毒测试 |
| RAG 攻击 | **35%** | 无 RAG 专用工作流，缺少知识库投毒/检索操控测试 |
| 多模态 | **10%** | 完全缺失 TargetCapabilities 和模态反馈 |
| 基准测试 | **85%** | 缺少 WMDP 数据集和结果分析 |

### 6.3 AI-300 考试核心差距

**🔴 关键差距（直接影响考试通过）**：

1. **XPIA Workflow 未对齐原生 API**：考试可能要求使用 `XPIAWorkflow` 类执行间接注入测试，项目实现不兼容
2. **RAG 攻击能力缺失**：考试重点考察 RAG 系统的红队测试，项目缺少完整的 RAG 攻击管道
3. **多模态攻击完全缺失**：考试可能涉及图片生成 AI 的安全测试，项目无相关能力

**🟡 重要差距（影响考试深度）**：

4. **Agent 工具调用注入不完整**：缺少完整的 Processing Callback 模式（模拟 Agent function calling）
5. **GCG 未使用官方 API**：考试可能要求使用 `GCGConfig` + AML 管道
6. **Prompt Generator 未使用原生 API**：缺少知识图谱增强和 `FuzzerResultPrinter`

---

## 7. 差距优先级排序与建议路线图

### 7.1 优先级矩阵

| 优先级 | 差距项 | 影响范围 | 实现难度 | 建议 |
|:--:|:--|:--|:--:|:--|
| P0 | XPIA Workflow 对齐原生 API | Agent + RAG 攻击 | 中 | 重写 `XPIAWorkflowWrapper` 使用原生 `XPIAWorkflow` |
| P0 | RAG 专用攻击工作流 | RAG 攻击 | 中 | 新建 RAG XPIA 测试流程 + Processing Callback |
| P0 | Converter 集成到 XPIA | XPIA 攻击核心 | 低 | 添加 `converter_config` 参数 |
| P1 | Modality Feedback / TargetCapabilities | 多模态攻击 | 高 | 实现 `TargetCapabilities` 系统 |
| P1 | Processing Callback 模式示例 | Agent 攻击 | 低 | 添加 OpenAI Responses API + Function Tool 示例 |
| P1 | MessagePiece 新 API 迁移 | 全局 API 对齐 | 中 | `Message(role, content)` → `Message(message_pieces=[MessagePiece(...)])` |
| P2 | GCG AML 管道支持 | GCG 攻击 | 高 | 添加 `GCGConfig` + AML job 提交 |
| P2 | WMDP 数据集集成 | 基准测试 | 低 | `fetch_wmdp_dataset()` 集成 |
| P2 | Anecdoctor 知识图谱增强 | 种子生成 | 中 | 添加 `processing_model` 参数 |
| P3 | Benchmark 返回 AttackResult | API 一致性 | 低 | Wrapper 返回原生 `AttackResult` |
| P3 | FuzzerResultPrinter | 可观测性 | 低 | 添加结果打印 |
| P3 | SuffixAppendConverter 集成 | GCG 后缀使用 | 低 | GCG 后缀通过 Converter 附加 |

### 7.2 建议路线图

#### 阶段一：XPIA/RAG 对齐（P0，预计 2-3 天）

1. 重写 `XPIAWorkflowWrapper` 继承原生 `XPIAWorkflow`
2. 添加 `converter_config` 参数支持
3. 迁移到 `MessagePiece` 新 API
4. 新建 RAG XPIA 测试流程（文档投递 → 检索模拟 → 注入检测）
5. 添加 Processing Callback 示例（模拟 Agent function calling）

#### 阶段二：多模态支持（P1，预计 3-5 天）

1. 实现 `TargetCapabilities` 系统
2. 实现模态路由检查
3. 支持多模态种子消息（`MessagePiece` + `data_type="image_path"`）
4. 集成 `OpenAIImageTarget`
5. 添加 Crescendo 图片编辑攻击示例

#### 阶段三：GCG + 基准增强（P2，预计 2-3 天）

1. 添加 GCG AML 管道支持（`GCGConfig` + job 提交）
2. 集成 `SuffixAppendConverter`
3. 集成 WMDP 数据集
4. 添加 Anecdoctor 知识图谱增强

#### 阶段四：API 一致性（P3，预计 1 天）

1. Benchmark Wrapper 返回原生 `AttackResult`
2. 添加 `FuzzerResultPrinter`
3. 统一 Prompt Generator 返回类型

### 7.3 预期效果

完成上述路线图后，预计对齐度提升：

| 维度 | 当前 | 目标 |
|:--|:--:|:--:|
| 整体对齐度 | ~82% | ~95% |
| LLM 攻击就绪度 | 90% | 98% |
| Agent 攻击就绪度 | 50% | 85% |
| RAG 攻击就绪度 | 35% | 85% |
| 多模态就绪度 | 10% | 75% |
| 基准测试就绪度 | 85% | 95% |

---

## 附录：文件清单与审查状态

| 文件路径 | 审查状态 | 主要发现 |
|:--|:--:|:--|
| `src/executor/__init__.py` | ✅ | 导出完整，33 个公共 API |
| `src/executor/promptgen/anecdoctor_wrapper.py` | ✅ | 未使用原生 `AnecdoctorGenerator`，缺 KG 增强 |
| `src/executor/promptgen/fuzzer_wrapper.py` | ✅ | 未使用原生 `FuzzerGenerator`，缺 ResultPrinter |
| `src/executor/promptgen/gcg_wrapper.py` | ✅ | 本地实现完整，缺 AML 管道 |
| `src/executor/attack/core/constants.py` | ✅ | 7 个技术分类常量，完全对齐 |
| `src/executor/attack/core/attack_builder.py` | ✅ | 11 种 Attack 映射 + 弃用处理，完全对齐 |
| `src/executor/attack/core/native_executor.py` | ✅ | 原生 AttackExecutor 集成，完全对齐 |
| `src/executor/attack/core/scenario_event_handler.py` | ✅ | L5 增强事件可观测性 |
| `src/executor/attack/single_turn/single_turn_executor.py` | ✅ | 参数约束 + refusal_scorer 剥离，完全对齐 |
| `src/executor/attack/multi_turn/multi_turn_executor.py` | ✅ | 参数映射 + TAP 评分 + 回溯，完全对齐 |
| `src/executor/attack/compound/sequential_executor.py` | ✅ | 5 种 completion_policy，完全对齐 |
| `src/executor/attack/component/seed_group_builder.py` | ✅ | 角色交替 + 三要素提取，完全对齐 |
| `src/executor/attack/streaming/barge_in_executor.py` | ✅ | 正确标记 deprecated |
| `src/executor/workflow/scenario_orchestrator.py` | ✅ | 自研增强（并发+超时+升级重试） |
| `src/executor/workflow/batch_orchestrator.py` | ✅ | 兼容层 |
| `src/executor/workflow/xpia_workflow.py` | ⚠️ | **重大差距**：未使用原生 XPIAWorkflow |
| `src/executor/benchmark/fairness_bias.py` | ✅ | 使用原生 FairnessBiasBenchmark，返回 dict |
| `src/executor/benchmark/question_answering.py` | ✅ | 使用原生 QuestionAnsweringBenchmark，返回 dict |
