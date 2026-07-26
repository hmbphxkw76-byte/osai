# PyRIT 1.0.0 Memory 子系统差距分析报告

> **文档版本**: v1.0.0 | **评估日期**: 2026-07-26 | **评估者**: AI-300 架构组  
> **对齐目标**: L5 专家水准 | **评估范围**: 非 Azure 内存管理 + Dataset 管理

---

## 目录

1. [评估概要](#1-评估概要)
2. [评估方法论](#2-评估方法论)
3. [模块逐项评估](#3-模块逐项评估)
4. [强项分析](#4-强项分析)
5. [重大差距分析](#5-重大差距分析)
6. [中等差距分析](#6-中等差距分析)
7. [AI-300 考试就绪度](#7-ai-300-考试就绪度)
8. [建议路线图](#8-建议路线图)
9. [结论](#9-结论)

---

## 1. 评估概要

| 维度 | 得分 | 状态 |
|------|------|------|
| CentralMemory 集成 | 100% | 🟢 优秀 |
| 数据库类型支持 | 100% | 🟢 优秀 |
| Memory Labels 使用 | 85% | 🟢 良好 |
| IdentifierFilter 系统 | 0% | 🔴 缺失 |
| 基础 Memory 编程 | 60% | 🟡 部分 |
| 手动 Memory 操作 | 0% | 🔴 缺失 |
| Embeddings 支持 | 0% | 🔴 缺失 |
| Schema 感知 | 50% | 🟡 部分 |
| Score 标识符过滤 | 0% | 🔴 缺失 |
| 种子数据库管理 | 90% | 🟢 优秀 |
| 种子去重 | 100% | 🟢 优秀 |
| 种子查询 | 90% | 🟢 优秀 |
| 模拟对话集成 | 90% | 🟢 优秀 |
| 原生管道 | 85% | 🟢 良好 |
| AttackResult 感知 | 80% | 🟢 良好 |
| **综合对齐度** | **~62%** | 🟡 **需改进** |

> **说明**：Memory 管理维度（前 9 项）平均 ~54%，Dataset 管理维度（后 6 项）平均 ~91%。综合加权后约 62%。主要差距集中在 IdentifierFilter 系统和手动 Memory 操作。

---

## 2. 评估方法论

### 2.1 评估流程

1. **文档梳理**：系统阅读 11 篇 PyRIT 1.0.0 官方 Memory 文档，提取所有 API、概念、最佳实践
2. **代码审查**：对 `src/` 目录下所有涉及 Memory 的代码进行逐文件审查
3. **逐项对比**：将官方文档描述的每个功能点与当前代码实现逐一对比
4. **差距评级**：按严重程度分三档（🟢 强项 / 🟡 中等 / 🔴 重大）

### 2.2 审查文件清单

| 文件 | 审查内容 |
|------|----------|
| `src/setup/setup_manager.py` | Memory 初始化流程 |
| `src/setup/ai300_initializers.py` | 默认数据集加载器 |
| `src/setup/__init__.py` | 公共 API 导出 |
| `src/setup/env_loader.py` | 环境变量加载 |
| `src/core/config_loader.py` | Memory 配置 |
| `src/payloads/dataset_manager.py` | CentralMemory 数据枢纽 |
| `src/payloads/seed_selector.py` | 交互式选择层 |
| `src/payloads/attack_preparator.py` | AttackSeedGroup 准备 |
| `src/payloads/seed_adapter.py` | SeedDataset 适配器 |
| `src/payloads/native_pipeline.py` | 原生管道 |
| `src/payloads/simulated_conversation.py` | 模拟对话 |
| `src/payloads/remote_loaders.py` | 远程数据集加载器 |
| `src/payloads/planner.py` | 载荷规划器 |
| `src/payloads/__init__.py` | 公共 API 导出 |
| `src/executor/workflow/scenario_orchestrator.py` | 场景编排器 |
| `src/executor/attack/core/native_executor.py` | 原生执行器 |
| `src/reporting/report_generator.py` | 报告生成器（Memory 读取） |
| `src/scenarios/scenario_result_bridge.py` | 场景结果桥接 |
| `config/defaults/pipeline.yaml` | 管道配置 |

---

## 3. 模块逐项评估

### 3.1 CentralMemory 集成 — 🟢 100%

**官方文档要求**：
- 使用 `CentralMemory.get_memory_instance()` 获取共享实例
- 通过 `initialize_pyrit_async()` 设置 Memory
- 所有组件通过 CentralMemory 共享同一实例

**当前实现**：
- ✅ `DatasetManager.__init__()` 调用 `CentralMemory.get_memory_instance()` 获取共享实例
- ✅ `AI300SetupManager.initialize_async()` 调用 `initialize_pyrit_async(memory_db_type=...)` 设置 Memory
- ✅ `AI300LoadDefaultDatasets.initialize_async()` 通过 DatasetManager 加载数据集到 CentralMemory
- ✅ `NativePipelineExecutor.execute_from_central_memory()` 直接从 CentralMemory 查询种子组
- ✅ `ReportGenerator` 通过 `CentralMemory.get_memory_instance()` 读取对话和评分

**对齐度**：100% — 完全对齐官方最佳实践。

---

### 3.2 数据库类型支持 — 🟢 100%

**官方文档要求**：
- 支持 `IN_MEMORY`、`SQLITE`、`AZURE_SQL` 三种数据库类型
- 通过 `MemoryDatabaseType` Literal 类型指定
- `memory_instance_kwargs` 传递额外参数（如 `db_path`）

**当前实现**：
- ✅ `AI300SetupManager._resolve_memory_db_type()` 从配置或参数解析数据库类型
- ✅ `_resolve_db_path()` 从配置解析数据库路径
- ✅ 构建 `memory_kwargs` 字典传递 `db_path` 给 `initialize_pyrit_async()`
- ✅ `ConfigLoader.get_memory_db_type()` 默认返回 `"SQLite"`
- ✅ `ConfigLoader.get_db_path()` 默认返回 `"output/db/exam_results.db"`
- ✅ 支持通过 `.pyrit_conf` 配置文件覆盖

**对齐度**：100% — 三种数据库类型完整支持。

---

### 3.3 Memory Labels 使用 — 🟢 85%

**官方文档要求**：
- `memory_labels` 参数在攻击执行时传入
- `GLOBAL_MEMORY_LABELS` 环境变量设置全局标签
- 传入标签与全局标签合并，冲突时传入优先
- 按 `labels` 参数查询 `get_message_pieces(labels={...})`

**当前实现**：
- ✅ `scenario_orchestrator.py` — `memory_labels` 在攻击计划中构建并传播
  - `first_plan.memory_labels` 传递到执行层
  - `**plan.memory_labels` 展开到执行参数
  - `memory_labels_override` 支持步骤级覆盖
- ✅ `planner.py` — 构建 `memory_labels` 字典，包含 `converter_chain_name`、`scenario_name`
- ✅ `native_pipeline.py` — `memory_labels` 参数透传到 `execute_batch_same_technique()`
- ✅ `simulated_conversation.py` — `memory_labels` 传递到 `broadcast_fields`
- ✅ `scenario_result_bridge.py` — `build_memory_labels()` 函数构建含 OWASP ID 的标签
- ✅ `report_generator.py` — `get_message_pieces(conversation_id=conv_id)` 按 conversation_id 查询
- ❌ **缺失**：`GLOBAL_MEMORY_LABELS` 环境变量支持未实现

**对齐度**：85% — Memory Labels 的使用非常全面，但缺少 `GLOBAL_MEMORY_LABELS` 全局标签环境变量支持。

---

### 3.4 IdentifierFilter 系统 — 🔴 0%

**官方文档要求**：
- `IdentifierFilter` 类支持按 `identifier_type`（TARGET/CONVERTER/ATTACK/SCORER）查询
- `property_path` JSON 路径匹配（如 `$.class_name`）
- `partial_match` 子串匹配
- `array_element_path` 数组列匹配
- 多过滤器 AND 组合
- 标签和标识符过滤器混合使用
- 适用于 `get_message_pieces()` 和 `get_scores()`

**当前实现**：
- ❌ **完全缺失**：项目中没有任何 `IdentifierFilter`、`IdentifierType` 的导入或使用
- ❌ 无法按 Target 类名过滤消息
- ❌ 无法按 Converter 类名过滤消息
- ❌ 无法按 Scorer 参数过滤评分
- ❌ 无法组合标签和标识符过滤

**影响**：
- 无法按基础设施维度（哪个 Target、哪个 Converter）查询历史数据
- 无法按 Scorer 参数对比不同评分器配置的效果
- 无法从 Memory 中精确检索特定配置的攻击结果

**对齐度**：0% — 这是最大的单项差距。

---

### 3.5 基础 Memory 编程 — 🟡 60%

**官方文档要求**：
- `add_message_to_memory(request=...)` 手动写入消息
- `get_conversation_messages(conversation_id=...)` 检索对话
- `get_message_pieces(labels=..., conversation_id=...)` 检索消息片段
- `get_scores()` 检索评分

**当前实现**：
- ✅ `report_generator.py` — 使用 `memory.get_message_pieces(conversation_id=conv_id)` 检索消息
- ✅ `report_generator.py` — 使用 `memory.get_conversation_messages(conversation_id=conv_id)` 检索对话
- ✅ `report_generator.py` — 使用 `memory.get_scores()` 检索评分
- ✅ `report_generator.py` — 使用 `memory.get_conversation_stats(conversation_ids=...)` 获取统计
- ❌ **缺失**：无 `add_message_to_memory()` 手动写入场景
- ❌ **缺失**：无手动 `MessagePiece` 构造和写入

**对齐度**：60% — 读取端完整，但缺少手动写入能力（对于测试和调试场景有用）。

---

### 3.6 手动 Memory 操作 — 🔴 0%

**官方文档要求**：
- `update_entries()` — 更新数据库条目（如更正评分）
- `update_labels_by_conversation_id()` — 按对话 ID 更新标签
- 导出/导入数据（部分导出、按标签/时间过滤）
- 与 DBeaver/Excel 配合进行离线分析

**当前实现**：
- ❌ **完全缺失**：项目中没有 `update_entries`、`update_labels_by_conversation_id` 的调用
- ❌ 无数据导出/导入功能
- ❌ 无与外部工具（DBeaver/Excel）的集成接口

**影响**：
- 无法更正错误的评分或标签
- 无法导出部分数据用于离线分析
- 无法在团队间共享本地 SQLite 数据

**对齐度**：0% — 对于 AI-300 考试场景影响较小（考试期间不需要手动操作），但对于 L5 专家级能力评估有影响。

---

### 3.7 Embeddings 支持 — 🔴 0%

**官方文档要求**：
- `OpenAITextEmbedding` 类生成文本嵌入
- `generate_text_embedding_async(text=...)` 异步生成
- `save_to_file()` 保存到磁盘
- `load_from_file()` 从磁盘加载
- `model_dump_json()` 序列化
- `EmbeddingData` 表存储嵌入向量

**当前实现**：
- ❌ **完全缺失**：项目中没有 `embedding`、`OpenAITextEmbedding`、`EmbeddingResponse` 的导入或使用
- ❌ 无嵌入向量生成或存储功能
- ❌ `EmbeddingData` 表未使用

**影响**：
- 无法使用嵌入向量进行语义相似度查询
- 无法利用嵌入进行高级数据分析和聚类
- 对于 AI-300 考试影响较小（嵌入是可选功能），但影响 L5 完整性

**对齐度**：0% — 官方文档标注为 "optional"，但对齐 L5 需要支持。

---

### 3.8 Schema 感知 — 🟡 50%

**官方文档要求**：
- `memory.print_schema()` 可程序化查看 Schema
- 理解 `PromptMemoryEntries`、`ScoreEntries`、`SeedPromptEntries`、`AttackResultEntries`、`ScenarioResultEntries`、`EmbeddingData`、`Conversations` 七张表
- 理解表间关系（conversation_id 关联、prompt_request_response_id 关联等）

**当前实现**：
- ✅ 隐式理解 Schema：`DatasetManager` 正确使用 `get_seed_groups()`、`get_seeds()`、`get_seed_dataset_names()`
- ✅ `ReportGenerator` 正确使用 `get_message_pieces()`、`get_conversation_messages()`、`get_scores()`
- ✅ 理解 `conversation_id` 关联机制（通过 `get_conversation_messages(conversation_id=conv_id)`）
- ✅ 理解 `AttackResult` 和 `Score` 的关联（通过 `last_response_id`、`last_score_id`）
- ❌ **缺失**：无 `print_schema()` 调用（调试/诊断场景）
- ❌ **缺失**：无 Schema 文档引用（缺少 `memory_models.py` 的引用说明）

**对齐度**：50% — 功能使用正确，但缺少显式 Schema 感知工具。

---

### 3.9 Score 标识符过滤 — 🔴 0%

**官方文档要求**：
- `IdentifierFilter` 适用于 `memory.get_scores(identifier_filters=[...])`
- 按 Scorer 类名过滤（`property_path="$.class_name"`）
- 按 Scorer 自定义参数过滤（如 `property_path="$.substring"`）
- 用于对比不同 Scorer 配置的效果

**当前实现**：
- ❌ **完全缺失**：`report_generator.py` 调用 `memory.get_scores()` 但未使用 `identifier_filters` 参数
- ❌ 无法按 Scorer 类名查询评分历史
- ❌ 无法按 Scorer 参数对比不同配置效果

**影响**：
- 在评分器评估场景中，无法从 Memory 精确检索特定 Scorer 配置的历史评分
- 无法做 A/B 对比分析（不同 Scorer 参数的效果差异）

**对齐度**：0% — 与 3.4 IdentifierFilter 同属一个差距。

---

### 3.10 种子数据库管理 — 🟢 90%

**官方文档要求**：
- `add_seed_datasets_to_memory_async(datasets, added_by)` 存入种子
- `get_seeds(dataset_name=..., harm_categories=..., ...)` 查询种子
- `get_seed_groups(dataset_name=..., seed_type=..., ...)` 查询种子组
- `get_seed_dataset_names()` 获取数据集名
- 内容哈希去重
- 多维查询（数据集名、种子类型、数据类型、元数据、危害类别）

**当前实现**：
- ✅ `DatasetManager.load_owasp_datasets()` — 加载 OWASP YAML → `add_seed_datasets_to_memory_async()`
- ✅ `DatasetManager.load_custom_datasets()` — 加载自定义 YAML → `add_seed_datasets_to_memory_async()`
- ✅ `DatasetManager.load_remote_datasets()` — `SeedDatasetProvider.fetch_datasets_async()` → `add_seed_datasets_to_memory_async()`
- ✅ `DatasetManager.get_seed_groups()` — 透传原生 `memory.get_seed_groups()` 全部参数
  - 支持 `harm_categories`、`dataset_name`、`dataset_name_pattern`、`added_by`、`authors`、`groups`、`source`、`seed_type`、`metadata`、`group_length`
- ✅ `DatasetManager.get_seeds()` — 透传原生 `memory.get_seeds()` 全部参数
- ✅ `DatasetManager.get_dataset_names()` — 调用 `memory.get_seed_dataset_names()`
- ✅ 内容哈希去重 — 由原生 `add_seed_datasets_to_memory_async` 自动处理
- ✅ `AI300LoadDefaultDatasets` 初始化器 — 加载 OWASP + Custom + Remote
- ⚠️ **未暴露**：`data_types` 过滤参数未在 `DatasetManager.get_seed_groups()` 中暴露

**对齐度**：90% — 种子数据库管理非常完善，仅缺少 `data_types` 参数暴露。

---

### 3.11 种子去重 — 🟢 100%

**官方文档要求**：
- 相同数据集 + 重复内容 → 拒绝
- 相同数据集 + 修改内容 → 接受
- 不同数据集 + 重复内容 → 接受

**当前实现**：
- ✅ 完全委托原生 `add_seed_datasets_to_memory_async()`，去重逻辑由 PyRIT 原生处理
- ✅ `DatasetManager` 不做任何额外去重逻辑，避免与原生行为冲突

**对齐度**：100% — 完全对齐。

---

### 3.12 种子查询 — 🟢 90%

**官方文档要求**：
- 按数据集名查询
- 按种子类型过滤（objective vs prompt）
- 按数据类型（模态）过滤
- 按元数据查询
- 按危害类别查询

**当前实现**：
- ✅ 数据集名 — `dataset_name` 和 `dataset_name_pattern`
- ✅ 种子类型 — `seed_type` 参数
- ❌ **未暴露**：`data_types`（模态过滤）参数未在 DatasetManager 接口中暴露
- ✅ 元数据 — `metadata` 字典过滤
- ✅ 危害类别 — `harm_categories` 过滤
- ✅ 额外 — `added_by`、`authors`、`groups`、`source`、`group_length`

**对齐度**：90% — 缺少 `data_types` 模态过滤参数暴露。

---

### 3.13 模拟对话集成 — 🟢 90%

**官方文档要求**：
- `SeedSimulatedConversation` 配置动态生成多轮对话
- 指定系统提示路径、对话轮数、序号偏移
- 实际生成在执行层完成

**当前实现**：
- ✅ `simulated_conversation.py` — 完整的模拟对话生成与重放模块
- ✅ `generate_simulated_conversation_async()` — 调用原生生成
- ✅ `precompute_simulated_conversation_async()` — 预计算对话
- ✅ `replay_to_target_async()` — 重放到指定 Target
- ✅ `create_simulated_conversation_seed()` — 编程创建配置
- ✅ `attack_preparator.py` — 检测 `SeedSimulatedConversation` 并验证依赖
- ✅ `seed_adapter.py` — `_extract_simulated_config()` 提取配置
- ⚠️ **部分**：`next_message_system_prompt_path` 处理可能有边界情况

**对齐度**：90% — 模拟对话集成非常完善。

---

### 3.14 原生管道 — 🟢 85%

**官方文档要求**：
- `SeedDataset → SeedGroup → AttackSeedGroup → AttackExecutor` 原生管道
- `AttackParameters.from_seed_group_async()` 自动提取三要素
- `AttackExecutor.execute_attack_from_seed_groups_async()` 批量执行

**当前实现**：
- ✅ `NativePipelineExecutor` — 从 SeedGroup 直接到执行器
- ✅ `AttackPreparator.prepare()` — SeedGroup → AttackSeedGroup
- ✅ `execute_from_central_memory()` — 从 CentralMemory 查询并执行
- ✅ `evaluate_attack_plan_necessity()` — 评估是否需要中间层
- ✅ `execute_native_async()` — 便捷函数
- ⚠️ `execute_batch_same_technique()` — 使用自研批量执行而非原生 `execute_attack_from_seed_groups_async()`

**对齐度**：85% — 管道路径完整，但最终执行调用的是自研方法而非原生方法名。

---

### 3.15 AttackResult 感知 — 🟢 80%

**官方文档要求**：
- `AttackResult` 包含 `conversation_id`、`objective`、`outcome`、`executed_turns`、`execution_time_ms` 等
- `ComponentIdentifier` 内容寻址哈希
- `AtomicAttackIdentifier` 复合标识符
- `EvaluationIdentifier` eval hash

**当前实现**：
- ✅ `scenario_result_bridge.py` — `BatchAttackResult` 到 `ScenarioResult` 适配
- ✅ `report_generator.py` — 使用 `AttackResult` 的 conversation_id、outcome 等字段
- ✅ `core/models.py` — 包含 AttackResult 相关定义
- ✅ 多个执行器文件引用 `AttackResult` 和 `ComponentIdentifier`
- ⚠️ `ComponentIdentifier` 和 `EvaluationIdentifier` 的 eval hash 机制未显式使用

**对齐度**：80% — AttackResult 的使用完整，但 eval hash 高级功能未利用。

---

## 4. 强项分析

### 4.1 五层+②.5 数据驱动架构 — 🟢

项目实现了完整的五层数据驱动架构：
- ① 数据准备层 → `DatasetManager.load_*()`
- ② 数据管理层 → `CentralMemory`（`DatasetManager` 封装）
- ②.5 交互式选择层 → `SeedGroupSelector`
- ③ 攻击准备层 → `AttackPreparator`（`AttackSeedGroup`）
- ④ 攻击执行层 → `NativeAttackExecutor` / `ScenarioOrchestrator`
- ⑤ 评估追踪层 → `Scorer` + `Memory`

这是项目最大的架构优势，完全对齐 PyRIT 1.0.0 的设计理念。

### 4.2 CentralMemory 深度集成 — 🟢

`DatasetManager` 正确且全面地使用了 CentralMemory 的原生 API：
- `add_seed_datasets_to_memory_async()` — 写入
- `get_seed_groups()` — 查询（全部参数透传）
- `get_seeds()` — 查询（全部参数透传）
- `get_seed_dataset_names()` — 数据集列表

没有重新实现原生逻辑，而是正确地委托。

### 4.3 memory_labels 全链路传播 — 🟢

从场景编排到执行层，`memory_labels` 被完整传播：
- `scenario_orchestrator.py` → `first_plan.memory_labels` → 执行参数
- `planner.py` → 构建含 `converter_chain_name`、`scenario_name` 的标签
- `native_pipeline.py` → `memory_labels` 透传
- `simulated_conversation.py` → `broadcast_fields["memory_labels"]`
- `scenario_result_bridge.py` → `build_memory_labels()` 含 OWASP ID

### 4.4 多数据源自由组合 — 🟢

`DatasetManager.load_datasets()` 支持：
- OWASP 本地（`owasp=True`）
- 自定义 YAML（`custom=True`）
- PyRIT 远程（`remote=True`）

各数据源独立选择，非一次性打包，完全对齐官方最佳实践。

### 4.5 种子去重完全委托原生 — 🟢

项目不做任何额外去重逻辑，完全依赖原生 `add_seed_datasets_to_memory_async()` 的内容哈希去重。这是正确的做法 — 避免与原生行为冲突。

### 4.6 模拟对话集成 — 🟢

`SeedSimulatedConversation` 的集成非常完善：
- 检测 + 验证依赖（adversarial_chat + objective_scorer）
- 延迟生成（在执行时由 `from_seed_group_async()` 调用）
- 预计算选项（`precompute_simulated_conversation_async()`）
- 重放选项（`replay_to_target_async()`）

---

## 5. 重大差距分析

### 5.1 IdentifierFilter 系统完全缺失 — 🔴 0%

**官方文档描述**：

PyRIT 1.0.0 的 Advanced Memory 文档详细描述了 `IdentifierFilter` 系统，这是 Memory 查询的核心能力之一。每个 `MessagePiece` 存储了 JSON 标识符列（target、converter、attack），`IdentifierFilter` 允许结构化查询这些列。

**缺失影响**：

1. **无法按 Target 类名查询**：无法从 Memory 中检索发送给特定 Target（如 `OpenAIChatTarget`）的所有消息
2. **无法按 Converter 查询**：无法检索经过特定 Converter（如 `Base64Converter`）处理的消息
3. **无法按 Scorer 参数查询**：无法从 `get_scores()` 中按 Scorer 配置过滤评分
4. **无法组合过滤**：无法 AND 组合多个过滤器，无法混合标签和标识符过滤

**AI-300 影响**：
- 考试中可能需要从 Memory 检索特定 Target 的历史交互
- 评分器评估场景需要按 Scorer 参数对比历史评分
- 多轮攻击分析需要按 Attack 标识符过滤结果

**建议修复**：
- 在 `DatasetManager` 或新模块中添加 `IdentifierFilter` 查询封装
- 在 `ReportGenerator` 中使用 `identifier_filters` 参数增强查询能力
- 在 `ScenarioOrchestrator` 中支持按 Target/Converter 标识符过滤历史数据

### 5.2 手动 Memory 操作完全缺失 — 🔴 0%

**官方文档描述**：

PyRIT 的 "Working with Memory Manually" 文档描述了多种手动操作 Memory 的方式：
- `update_entries()` — 更新数据库条目
- `update_labels_by_conversation_id()` — 按对话更新标签
- 导出/导入数据（支持部分导出）
- 与 DBeaver/Excel 配合进行离线分析

**缺失影响**：

1. **无法更正评分**：如发现评分错误，无法通过 API 更新
2. **无法更新标签**：无法按对话 ID 批量更新标签
3. **无法导出数据**：无法将 Memory 数据导出为 CSV/JSON 供离线分析
4. **无法团队共享**：无法导出 SQLite 数据库供其他用户使用

**建议修复**：
- 在 `DatasetManager` 或新模块中添加 `update_entries` 和 `update_labels_by_conversation_id` 封装
- 添加数据导出/导入便捷函数
- 文档中说明 DBeaver 集成方式

### 5.3 Embeddings 支持完全缺失 — 🔴 0%

**官方文档描述**：

PyRIT 的 Embeddings 文档描述了：
- `OpenAITextEmbedding` 生成文本嵌入
- `save_to_file()` / `load_from_file()` 序列化
- `model_dump_json()` JSON 输出
- `EmbeddingData` 数据库表

**缺失影响**：
- 无法生成和存储文本嵌入向量
- 无法进行语义相似度查询
- `EmbeddingData` 表完全未使用

**建议修复**：
- 添加 `EmbeddingHelper` 或在 `DatasetManager` 中添加嵌入支持
- 封装 `OpenAITextEmbedding` 的便捷函数
- 在报告生成中支持嵌入相似度分析

### 5.4 Score 标识符过滤完全缺失 — 🔴 0%

**与 5.1 同属一个差距**，但侧重点不同：

- 5.1 侧重 `get_message_pieces()` 的标识符过滤
- 本项侧重 `get_scores()` 的标识符过滤

**缺失影响**：
- `ReportGenerator` 调用 `memory.get_scores()` 但不使用 `identifier_filters`
- 无法按 Scorer 类名查询历史评分
- 无法按 Scorer 自定义参数（如 `substring`）过滤评分
- 无法做 A/B 对比分析

---

## 6. 中等差距分析

### 6.1 GLOBAL_MEMORY_LABELS 环境变量未支持 — 🟡

**官方文档**：`GLOBAL_MEMORY_LABELS` 环境变量可设置全局标签，应用于所有攻击。传入标签与全局标签合并，冲突时传入优先。

**当前**：项目支持 `memory_labels` 参数传递，但不支持 `GLOBAL_MEMORY_LABELS` 环境变量。

**影响**：无法设置全局标签（如 `operator`、`operation`）自动应用到所有攻击。

**建议**：在 `EnvLoader` 或 `AI300SetupManager` 中读取 `GLOBAL_MEMORY_LABELS` 环境变量并传播到执行层。

### 6.2 data_types 模态过滤参数未暴露 — 🟡

**官方文档**：`get_seed_groups(data_types=["image_path"])` 支持按模态过滤种子。

**当前**：`DatasetManager.get_seed_groups()` 未暴露 `data_types` 参数。

**影响**：无法从 `DatasetManager` 接口直接按模态过滤种子（需要直接调用 `memory.get_seed_groups()`）。

**建议**：在 `DatasetManager.get_seed_groups()` 和 `get_seeds()` 中添加 `data_types` 参数。

### 6.3 print_schema() 诊断能力缺失 — 🟡

**官方文档**：`memory.print_schema()` 可程序化查看数据库 Schema。

**当前**：项目未调用 `print_schema()`，无诊断工具。

**影响**：调试 Memory 问题时无法快速查看 Schema。

**建议**：在 `AI300SetupManager.initialize_async()` 完成后或诊断模式中调用 `print_schema()`。

### 6.4 原生管道执行方法名不一致 — 🟡

**官方文档**：`AttackExecutor.execute_attack_from_seed_groups_async()` 是原生批量执行方法。

**当前**：`NativePipelineExecutor` 调用 `self._executor.execute_batch_same_technique()`，而非原生方法名。

**影响**：虽然功能等价，但方法名不一致可能影响与 PyRIT 原生生态的兼容性。

### 6.5 EvaluationIdentifier / eval hash 未利用 — 🟡

**官方文档**：`EvaluationIdentifier` 子类的 eval hash 机制，通过 `Evaluate.Include/Exclude/Unwrap` 标记控制。

**当前**：项目使用 `ComponentIdentifier` 但未利用 eval hash 高级功能。

**影响**：无法在不同部署间对比逻辑等价的配置。

---

## 7. AI-300 考试就绪度

| 考试主题 | 就绪度 | 说明 |
|----------|--------|------|
| LLM 攻击 Memory | 95% | CentralMemory 集成完善，memory_labels 全链路传播 |
| 多轮对话追踪 | 95% | conversation_id 分组机制完整使用 |
| 评分器 Memory | 70% | Score 查询有，但缺少 IdentifierFilter 按 Scorer 过滤 |
| 数据集管理 | 95% | 五层架构完整，种子去重和查询完善 |
| 标签系统 | 85% | memory_labels 使用全面，缺 GLOBAL_MEMORY_LABELS |
| 标识符过滤 | 10% | IdentifierFilter 系统完全缺失 |
| 手动 Memory 操作 | 10% | update_entries/export 完全缺失 |
| 嵌入向量 | 10% | Embeddings 完全缺失 |
| 攻击结果分析 | 85% | AttackResult 使用完整，缺 eval hash |
| 场景结果管理 | 85% | ScenarioResultEntries 通过 bridge 集成 |
| **综合就绪度** | **~65%** | **需补充 IdentifierFilter 和手动操作能力** |

---

## 8. 建议路线图

### P0（紧急 — 影响 AI-300 考试核心能力）

| 编号 | 任务 | 影响 | 工作量 |
|------|------|------|--------|
| P0-1 | 添加 `IdentifierFilter` 查询封装 | 按基础设施维度查询 Memory | 中 |
| P0-2 | 添加 `GLOBAL_MEMORY_LABELS` 环境变量支持 | 全局标签自动应用 | 小 |

### P1（重要 — 提升 L5 专家水准）

| 编号 | 任务 | 影响 | 工作量 |
|------|------|------|--------|
| P1-1 | 添加手动 Memory 操作（update_entries/update_labels） | 更正评分和标签 | 中 |
| P1-2 | 添加 Score 标识符过滤（get_scores + identifier_filters） | 评分器 A/B 对比 | 中 |
| P1-3 | 添加数据导出/导入功能 | 团队共享和离线分析 | 中 |

### P2（增强 — 完整性补全）

| 编号 | 任务 | 影响 | 工作量 |
|------|------|------|--------|
| P2-1 | 添加 Embeddings 支持（OpenAITextEmbedding 封装） | 语义相似度查询 | 中 |
| P2-2 | 暴露 `data_types` 模态过滤参数 | 按模态过滤种子 | 小 |
| P2-3 | 添加 `print_schema()` 诊断能力 | 调试支持 | 小 |

### P3（优化 — 锦上添花）

| 编号 | 任务 | 影响 | 工作量 |
|------|------|------|--------|
| P3-1 | 对齐原生管道方法名 | 生态兼容性 | 小 |
| P3-2 | 利用 EvaluationIdentifier eval hash | 跨部署对比 | 大 |
| P3-3 | DBeaver/Excel 集成文档 | 离线分析支持 | 小 |

---

## 9. 结论

### 9.1 整体评估

当前项目的 Memory 子系统对齐度约为 **62%**，呈现明显的**两极分化**：

- **Dataset 管理维度**（~91%）：五层架构完整，CentralMemory 深度集成，种子去重和查询完善，模拟对话和原生管道支持良好
- **Memory 查询维度**（~54%）：CentralMemory 集成和 Memory Labels 使用优秀，但 IdentifierFilter 系统、手动操作和 Embeddings 完全缺失

### 9.2 核心差距

最大的单项差距是 **IdentifierFilter 系统的完全缺失**（0%）。这是 PyRIT 1.0.0 Advanced Memory 文档的核心功能，影响到：
- 按 Target/Converter/Scorer/Attack 标识符查询历史数据
- Score A/B 对比分析
- 混合标签和标识符的高级查询

### 9.3 建议优先级

1. **P0（立即）**：实现 IdentifierFilter 封装 + GLOBAL_MEMORY_LABELS 支持
2. **P1（短期）**：实现手动 Memory 操作 + Score 标识符过滤 + 数据导出/导入
3. **P2（中期）**：Embeddings 支持 + data_types 暴露 + print_schema 诊断
4. **P3（长期）**：原生方法名对齐 + eval hash + DBeaver 集成

### 9.4 L5 达标路径

完成 P0-P2 后，整体对齐度预计可达 **~90%**，达到 L5 专家水准。P3 为锦上添花项。

| 阶段 | 完成后对齐度 |
|------|-------------|
| 当前 | ~62% |
| P0 完成 | ~72% |
| P1 完成 | ~83% |
| P2 完成 | ~90% |
| P3 完成 | ~95% |
