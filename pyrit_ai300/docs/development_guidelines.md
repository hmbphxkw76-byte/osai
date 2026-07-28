# 开发文档规范

**版本**: v4.0  
**创建日期**: 2026-07-25  
**更新日期**: 2026-07-27  
**适用范围**: PyRIT AI-300 全部源码、配置、测试和文档  
**对齐标准**: PyRIT 1.0.0 原生 API + OWASP 双标准 + L5 专家级软件工程实践  
**v4.0 变更**: 统一AdaptiveScenario路径 + Converter-Aware v3.0 + 15种Target + 6个初始化器 + Core原生集成

---

## 〇、三库定义

当说“写入三库”时，指以下三个文件，必须同时更新：

| 序号 | 文件 | 用途 |
|------|------|------|
| 1 | `.catpawrules` | CatPaw IDE 规则文件（项目级 AI 规则） |
| 2 | `.assistant_pyrit/memory_bank.md` | 记忆库（跨平台共享，任意 IDE 可读取） |
| 3 | `docs/development_guidelines.md` | 开发规范文档（本文件） |

**同步规则**: 架构变更、新增模块、新增规则时，必须同时更新以上三个文件。

> **更新说明**: v3.0 恢复 `.catpawrules` 文件（包含原生优先规则），三库同步更新。

---

## 一、核心开发规则

### 1.1 原生优先原则

**规则**: 原生优先，消除双轨，保留自建的不可替代部分。

**说明**: PyRIT 1.0.0 已提供丰富的组件（80+ Converter、40+ Scorer、20+ Attack、15+ Target 类型），直接使用可确保兼容性和可维护性。当原生机制能完全替代自建逻辑时，必须移除自建代码，不允许同时保留两套实现。仅当原生框架无法覆盖时才保留自建逻辑。

**当前保留的自建部分**（原生框架无法覆盖）：
- `per_attack_timeout` — PyRIT 原生无 per-attack 超时机制
- OWASP 映射 — 通过原生 `memory_labels` 集成
- `RateLimitedTarget` 并发信号量 + 503 重试 — PyRIT 原生不覆盖

**已消除的双轨**（自建 → 原生替代）：
- 自建 `AttackUpgradeStrategy` 多候选递归 → 原生 `SequentialAttack(FIRST_SUCCESS)` 提前停止
- 自建 `add_converter` 升级策略 → Converter 变体预注册 + 原生 `FIRST_SUCCESS`
- 自建 `generate_upgrade_plans` → 原生 `AdaptiveTechniqueDispatcher` 自动构建
- 自建失败类型路由 → `FailureTypeRoutingSelector`（extends `EpsilonGreedyTechniqueSelector`）

**必须使用原生 API 的场景**:

| 场景 | 原生 API | 禁止操作 |
|------|---------|---------|
| 内存管理 | `CentralMemory.get_memory_instance()` | 自行实现内存存储 |
| 攻击执行 | `AttackExecutor.execute_attack_from_seed_groups_async()` | 自行实现攻击调度 |
| 证据导出 | `MarkdownAttackResultMemoryPrinter.render_async()` | 自行实现 Markdown 渲染 |
| 对话渲染 | `MarkdownConversationMemoryPrinter.render_async()` | 手工拼接对话 |
| 结果输出 | `output_attack_async` / `output_scenario_async` | 自行实现输出通道 |
| 能力探测 | `discover_target_capabilities_async()` | 自行实现端点探测 |
| 数据集加载 | `SeedDataset.from_yaml_file()` / `SeedDatasetProvider.fetch_datasets_async()` | 自行实现 YAML 解析 |
| 种子查询 | `CentralMemory.get_seed_groups()` / `get_seeds()` | 自行实现数据库查询 |

**示例**:
```python
# ✅ 正确: 使用原生 AttackExecutor
from pyrit.executor.attack import AttackExecutor
executor = AttackExecutor(max_concurrency=1)
result = await executor.execute_attack_from_seed_groups_async(
    attack=attack,
    seed_groups=[seed_group],
    adversarial_chat=adversarial_chat,
)

# ❌ 错误: 自行实现攻击调度
async def my_execute_attack(attack, objective):
    # 不要这样做！
    ...
```

### 1.1.1 研究工作流规则 (arXiv 优先 → GitHub 验证)

**规则**: 在进行新功能开发、架构设计或技术选型前，必须遵循「arXiv 优先 → GitHub 验证」的研究工作流。

**工作流步骤**:
1. **arXiv 优先查找**: 在 `https://arxiv.org/` 优先搜索相关学术论文和文献，了解该领域的最新学术研究进展、方法论基础和理论基础。搜索关键词应覆盖攻击策略选择（attack strategy selection）、自适应红队（adaptive red teaming）、越狱攻击（jailbreaking）、多轮对抗攻击（multi-turn adversarial attack）等主题。
2. **GitHub 查找相关代码**: 在 arXiv 获取理论基础后，到 GitHub 搜索相关主题的开源实现代码（特别是 PyRIT 官方仓库 `Azure/PyRIT`），验证学术方法在生产级框架中的实际落地方式。
3. **学术与实践对齐**: 将 arXiv 的理论方法与 GitHub 的工程实现进行交叉验证，确保自建实现既有学术依据又有工程验证。

**相关 arXiv 文献参考**（LLM 红队/越狱/攻击策略选择领域）:

| 技术名称 | arXiv ID | 论文标题 | 在项目中的对应实现 |
|----------|----------|---------|-------------------|
| PAIR | 2310.08437 | Jailbreaking Black Box LLMs in Twenty Queries | `PAIRAttack` |
| TAP | 2312.02191 | Tree of Attacks: Jailbreaking Black-Box LLMs | `TAPAttack` |
| Many-Shot | 2402.05124 | Many-shot Jailbreaking | `ManyShotJailbreakAttack` |
| GCG | 2307.15043 | Universal and Transferable Adversarial Attacks | `GCGWrapper` (双路径) |
| Red Teaming | 2202.01241 | Red Teaming Language Models to Reduce Harms | `RedTeamingAttack` |
| JailbreakBench | 2402.01135 | An Open Robustness Benchmark | `Benchmark` 模块 |
| Crescendo | 2402.12109 | Great, Now We Have to Sing | `CrescendoAttack` |
| Skeleton Key | 2407.01576 | Skeleton Key: A Multilingual LLM Jailbreak | `SkeletonKeyAttack` |

**GitHub 参考仓库**:
- `Azure/PyRIT` — 原生 `AdaptiveScenario` / `EpsilonGreedyTechniqueSelector` / `SequentialAttack(FIRST_SUCCESS)` / `AttackTechniqueRegistry`
- `JailbreakBench/art` — 攻击成功率（ASR）基准测试
- `textgrad-dev/textgrad` — LLM 梯度引导优化

### 1.2 避免硬编码原则

**规则**: 所有可变参数必须从配置文件读取，严禁硬编码在代码中。

**三级配置优先级**: 显式参数 > 环境变量 > `config.yaml`

**配置文件体系**:

| 配置文件 | 职责 |
|---------|------|
| `config/config.yaml` | 全局配置（目标/认证/AI类型/批量执行/数据集管理） |
| `config/owasp_mapping.yaml` | OWASP 双标准映射 |
| `config/payload_strategy_matrix.yaml` | 载荷策略矩阵 |

**示例**:
```python
# ✅ 正确: 从 config.yaml 读取
max_concurrency = config_loader.get_batch_max_concurrency()
per_attack_timeout = config_loader.get_batch_per_attack_timeout()

# ✅ 正确: 环境变量覆盖配置
max_concurrency = int(os.getenv(
    "BATCH_MAX_CONCURRENCY",
    config_loader.get_batch_max_concurrency(),
))

# ❌ 错误: 硬编码
max_concurrency = 4  # 禁止！
```

### 1.3 PyRIT 优势边界原则

**规则**: 仅在 PyRIT 有优势的提示词攻击领域使用 PyRIT，非优势领域推荐外部工具。

**PyRIT 优势领域**: `llm` / `multi_agent` / `mcp_server` / `rag`  
**非 PyRIT 优势领域**: `embeddings`（推荐 textattack）/ `infrastructure`（推荐 kubeaudit）

**实现方式**: `AISystemType.is_pyrit_attackable()` 自动判断，非优势领域返回空策略并推荐外部工具。

### 1.4 数据结构传递原则

**规则**: 层间数据传递必须使用 Pydantic 模型或 PyRIT 原生对象，确保类型安全和可验证性。

**数据模型传递链**:

```
ReconResult (Pydantic) → StrategySelection (Pydantic) → AttackSeedGroup (PyRIT 原生)
    → BatchAttackResult (Pydantic) → ReportResult (Pydantic)
```

**示例**:
```python
# ✅ 正确: 使用 Pydantic 模型
from src.core.models import ReconResult, AuthType, AISystemType
recon_result = ReconResult(
    target_url=target_url,
    detected_endpoint=endpoint,
    auth_type=AuthType.NONE,
    ai_system_type=AISystemType.LLM,
)

# ❌ 错误: 使用裸字典
recon_result = {"url": target_url, "endpoint": endpoint}  # 禁止！
```

### 1.5 错误处理原则

**规则**: 使用 PyRIT 原生异常体系，分层降级，单点失败不中断全局流程。

**错误处理策略**:

| 场景 | 策略 |
|------|------|
| 单个攻击超时 | 记录错误，继续其他攻击 |
| 批量执行异常 | 回退到逐个执行 |
| 远程数据集加载失败 | 跳过，继续本地数据 |
| Markdown 渲染失败 | 回退到简单格式 |
| 原生 output 失败 | `logger.warning`，不中断 |

**示例**:
```python
# ✅ 正确: 分层降级
try:
    result = await asyncio.wait_for(
        self._execute_single_plan(plan, ...),
        timeout=effective_timeout,
    )
except asyncio.TimeoutError:
    result.errors.append({"plan_id": plan.plan_id, "error": f"Timeout"})
    logger.warning(f"Plan {plan.plan_id} timed out (non-fatal)")
except Exception as e:
    logger.warning(f"Plan {plan.plan_id} failed (non-fatal): {e}")
    if fail_fast:
        raise
```

### 1.6 代码组织原则

**规则**: 按功能模块组织，每个模块有清晰的 `__init__.py` 导出公共 API。

**目录组织**:

```
src/
├── core/           # 核心模型和配置加载
├── converters/     # Converter 链配置（80+）
├── scorers/        # Scorer 配置（52 API）
├── executor/       # 攻击执行子系统（五层架构）
├── payloads/       # 数据集五层架构
├── targets/        # 目标 Target 工厂（11 种）
├── recon/          # 侦察层
├── analysis/       # 分析层
├── reporting/      # 报告层 + 证据导出
└── exam/           # 考试专用功能
```

**模块 `__init__.py` 规范**:
- 每个模块的 `__init__.py` 必须包含模块级 docstring
- 导出公共 API 必须有 `__all__` 列表
- 内部实现不暴露

### 1.7 非PyRIT领域排除原则

**规则**: 非 PyRIT 优势领域不使用 PyRIT 实现，仅识别端点并推荐外部工具。

**实现方式**: `config.yaml` 的 `ai_type_detection` 段定义各类型的 `pyrit_attackable` 标志和 `external_tools` 推荐。

### 1.8 代码审查检查清单

每次代码提交前必须确认：

- [ ] 所有新代码使用 PyRIT 原生组件（原生优先）
- [ ] 所有可变参数从配置文件读取（避免硬编码）
- [ ] 层间数据使用 Pydantic 模型或原生对象传递（数据结构传递）
- [ ] 错误处理使用分层降级策略（错误处理）
- [ ] 新增模块有 `__init__.py` 和 `__all__`（代码组织）
- [ ] OWASP 映射已更新（如涉及新攻击类型）
- [ ] 单元测试已编写并通过（测试先行）
- [ ] 根据改动范围运行了对应层级的测试（§1.9 分层测试）
- [ ] 已运行 ruff check 并清理所有冗余/死代码（§1.10 死代码清理）
- [ ] 文档已同步更新

### 1.9 分层测试与回归原则

**规则**: 每次代码修改后必须根据改动范围运行对应层级的测试，确保改动不引入回归。

**分层测试策略**:

| 改动范围 | 测试层级 | 命令 | 说明 |
|----------|----------|------|------|
| 单个模块内代码改动 | 单元测试 | `pytest tests/unit/test_<module>.py -x -q` | 仅运行受影响模块的单元测试 |
| 模块间接口/数据流改动 | 集成测试 | `pytest tests/integration/ -x -q` | 运行集成测试验证模块间交互 |
| 多个模块同时改动 | 完整回归测试 | `pytest tests/ -x -q` | 运行全部测试确保无回归 |

**执行要求**:
- 模块内改动（如修改某个类的内部方法）：运行该模块对应的单元测试文件
- 模块间改动（如修改 `__init__.py` 导出、函数签名、数据模型字段）：运行集成测试
- 多模块改动（如跨模块重构、批量清理死代码、架构调整）：运行完整回归测试
- 测试失败时必须修复后才能继续后续工作，不允许跳过失败测试

### 1.10 死代码即时清理原则

**规则**: 每次代码改动后必须自动清理冗余代码和死代码，确保代码简洁。

**清理范围**:

| 类型 | 检测方式 | 工具 |
|------|----------|------|
| 未使用导入 (F401) | ruff check | `python -m ruff check --fix --select F401` |
| 未使用变量 (F841) | ruff check | `python -m ruff check --fix --select F841` |
| 无占位符 f-string (F541) | ruff check | `python -m ruff check --fix --select F541` |
| 重复字典键 (F601) | ruff check | `python -m ruff check --select F601` |
| 未使用的公共函数/类 | AST 交叉引用扫描 | 手动确认未被任何模块/测试导入后删除 |
| 死分支（不可达代码） | 代码审查 | 手动识别 `elif` 不可达分支、赋值后立即覆盖的变量 |
| 过时注释 | 代码审查 | 手动删除引用已删除代码的注释块 |

**执行要求**:
- 每次代码改动后运行 `python -m ruff check src/ pipeline.py --fix` 自动修复
- 删除函数/方法后，同步清理 `__init__.py` 中对应的导出
- 删除模块后，同步清理所有导入该模块的文件
- 清理后必须运行对应层级的测试验证（遵循 §1.9）

---

## 二、最佳实践原则

### 2.1 AttackExecutor Facade 模式

**原则**: 使用 Facade 模式封装 PyRIT 原生 AttackExecutor，提供统一执行入口。

**实现**: `NativeAttackExecutor` 作为 Facade：
- `execute_single_attack()`: 根据技术类型分派到 `SingleTurnExecutor` 或 `MultiTurnExecutor`
- `execute_batch_same_technique()`: 原生批量并行执行
- `execute_sequential_attack()`: 委托 `SequentialExecutor`

**关键不变量**: `one-objective → one-result`

### 2.2 五层+②.5数据驱动架构

**原则**: 数据源自由组合，非一次性打包；交互选择层在数据管理和攻击准备之间提供终端交互。

**五层架构**:
```
① 数据准备层 → DatasetManager.load_datasets()
② 数据管理层 → CentralMemory (add_seed_datasets_to_memory / get_seed_groups)
②.5 交互选择层 → SeedGroupSelector (build_catalog / filter / prompt_user)
③ 攻击准备层 → AttackPreparator (SeedGroup → AttackSeedGroup)
④ 攻击执行层 → ScenarioOrchestrator + NativeAttackExecutor
⑤ 评估与追踪层 → Scorer + PyRIT Memory 审计链
```

**关键设计约束**:
- 禁止直接构造 `PromptItem`（必须走五层流转）
- 禁止绕过选择层（pipeline 必须经过 `SeedGroupSelector`）
- 禁止修改 `SeedGroup` 对象（`source_seed_group` 保留原始引用）
- 条件分派逻辑不可变（`prepended_conversation` → `crescendo`，`next_message` → `prompt_sending`，无 → `red_teaming`）

### 2.3 TargetParams 三级配置

**原则**: Target 构造参数支持三级配置优先级。

**优先级**: 显式参数 > 环境变量 > `config.yaml`

**TargetParams 48 字段覆盖**:
- 推理参数: `temperature` / `top_p` / `max_completion_tokens` / `max_output_tokens` / `frequency_penalty` / `presence_penalty` / `seed`
- Responses API 专用: `reasoning_effort` / `reasoning_summary`（o1/o3 推理模型）
- 通用透传: `extra_body_parameters` / `underlying_model`
- HTTP 客户端: `httpx_client_kwargs`（timeout / verify / proxy / http2）
- 能力探测: `discover_capabilities` / `apply` / `per_probe_timeout_s`
- 速率限制: `max_requests_per_minute`
- JSON 输出: `force_json_output`
- Agentic: `custom_functions`

### 2.4 差异化超时策略

**原则**: 按攻击复杂度设定合理超时阈值，避免简单攻击等待过久、复杂攻击被误杀。

```yaml
batch_execution:
  timeout_overrides:
    single_turn: 90           # 单轮直接攻击（1次API调用+评分）
    converter_enhanced: 150   # 编码转换增强（额外转换链开销）
    multi_turn: 300           # 多轮渐进攻击（多轮对话+adversarial LLM迭代）
    sequential: 480           # 顺序组合攻击（异构技术链）
```

**超时解析**: `ScenarioOrchestrator._resolve_timeout()` 根据 `AttackPlan.prompt_item.attack_mode` 选择超时。

### 2.5 升级重试机制

**原则**: 攻击失败后自动升级到更强的攻击技术。

**三种升级策略**:
1. **单轮 → 多轮升级**: `single_turn_to_multi_turn`（如 `prompt_sending` → `crescendo`）
2. **基础多轮 → 高级多轮升级**: `multi_turn_upgrade`（如 `red_teaming` → `tap`）
3. **添加 Converter 链**: `add_converter`（如添加 `stealth_evasion` 链）

**实现**: `_generate_upgrade_plans()` 从 `payload_strategy_matrix.yaml` 的 `attack_upgrade_strategies` 段读取策略。

### 2.6 三级证据链

**原则**: 报告中的每个 Finding 关联其对应的具体 AttackResult 和完整对话历史。

```
第一级: OWASPFinding (漏洞发现 + OWASP 映射 + MITRE + 修复建议)
    ↓ 关联
第二级: AttackResult (攻击结果 + 评分 + 执行指标)
    ↓ 关联
第三级: Conversation (完整对话历史 + 逐消息 + 逐评分)
```

**实现**: `OWASPMapper.map_attacks_to_findings()` → `ReportGenerator._collect_attack_details()` → EvidenceExporter。

### 2.7 双通道输出

**原则**: 攻击结果同时输出到终端和文件，确保实时可见和完整记录。

| 通道 | 格式 | 用途 |
|------|------|------|
| 终端 | pretty | 实时进度可见 |
| 文件 | Markdown | 全量日志记录 |

**实现**: `OutputManager` 管理双通道输出，`TeeOutput` 将 stdout/stderr 同时写入终端和日志文件。

### 2.8 向后兼容

**原则**: 旧 API 和类型名保留向后兼容，不破坏现有代码。

**实现方式**:
- `_LEGACY_TYPE_ALIASES`: 旧 Target 类型名映射（含 `dalle` / `image_generation` → `openai_image`）
- `DirectAttackExecutor = NativeAttackExecutor`: 旧名称别名
- `AttackExecutionParams`: 废弃但保留过渡层
- `src/orchestrators/__init__.py`: 保留为兼容 shim
- Benchmark `run_async` 返回 dict（向后兼容），附带 `native_result` 字段
- Benchmark `run_native_async` 返回原生 `AttackResult`

### 2.9 每次运行独立数据库

**原则**: 每次运行使用独立的 SQLite 数据库路径，彻底避免旧数据残留和文件锁定问题。

```python
db_path = db_base_path.parent / f"{exam_id}.db"
```

### 2.10 Registry 命名空间

**原则**: PyRIT Registry 使用类名而非 snake_case 注册组件。

**实现**: `get_scorer_from_pyrit_registry` 同时支持两种命名（类名 + snake_case）。

---

## 三、项目开发实践原则

### 3.1 模块导出规范

每个模块的 `__init__.py` 必须遵循以下规范：

```python
"""
Module Name
===========
模块级 docstring，说明职责和架构对齐。
"""

# 导入顺序：标准库 → PyRIT 原生 → 项目内部
from src.module.file import ClassA, ClassB

__all__ = [
    "ClassA",
    "ClassB",
]
```

### 3.2 工厂函数模式

公共 API 以工厂函数形式暴露，隐藏内部实现：

```python
async def execute_batch_attacks(
    attack_plans, objective_target, judge_target, ...
) -> BatchAttackResult:
    """批量执行攻击计划（工厂函数）"""
    orchestrator = ScenarioOrchestrator()
    return await orchestrator.execute_batch(...)
```

### 3.3 单例模式

配置加载器使用全局单例：

```python
_global_config_loader: Optional[ConfigLoader] = None

def get_config_loader() -> ConfigLoader:
    global _global_config_loader
    if _global_config_loader is None:
        _global_config_loader = ConfigLoader()
    return _global_config_loader
```

### 3.4 条件分派逻辑不可变

`AttackPreparator.select_attack_technique()` 的分派逻辑不可变：

```python
# 有前置对话 → 多轮渐进攻击
if attack_group.prepended_conversation:
    return "crescendo"
# 有 next_message → 单轮直接发送
if attack_group.next_message is not None:
    return "prompt_sending"
# 无 next_message 且无 prepended → 目标导向多轮
return "red_teaming"
```

### 3.5 PyRIT 原生 API 优先

**禁止手工拼接 PyRIT 已原生支持的功能**:

| 禁止操作 | 原生替代 |
|---------|---------|
| 手工拼接对话 Markdown | `MarkdownConversationMemoryPrinter.render_async()` |
| 手工解析 YAML 数据集 | `SeedDataset.from_yaml_file()` |
| 手工实现攻击并行 | `AttackExecutor(max_concurrency=N)` |
| 手工实现证据导出 | `EvidenceExporter.export_all_evidence()` |
| 手工实现能力探测 | `discover_target_capabilities_async()` |

### 3.6 AttackScoringConfig 三层架构

评分配置遵循 PyRIT 1.0.0 三层评分架构：

```python
AttackScoringConfig(
    objective_scorer=...,      # TrueFalseScorer 类型
    refusal_scorer=...,        # TrueFalseScorer 类型（检测目标拒绝）
    auxiliary_scorers=[...],   # 辅助评分列表
    use_score_as_feedback=True, # 评分作为迭代反馈
)
```

**特殊处理**:
- TAP 家族使用 `TAPAttackScoringConfig`（自动检测）
- 单轮攻击和 `red_teaming` 不接受 `refusal_scorer`（`NO_REFUSAL_SCORER_ATTACKS` 常量集合自动剥离）

### 3.7 攻击技术常量集合

攻击技术按特征分组为 `frozenset` 常量：

```python
SINGLE_TURN_ATTACKS = frozenset({"prompt_sending", "multi_prompt_sending", ...})
MULTI_TURN_TECHNIQUES = frozenset({"red_teaming", "crescendo", "pair", "tap", ...})
TAP_FAMILY_ATTACKS = frozenset({"tap", "tree_of_attacks_pruned"})
NO_REFUSAL_SCORER_ATTACKS = frozenset({"prompt_sending", "red_teaming"})
MAX_TURNS_ATTACKS = frozenset({"red_teaming", "crescendo", "pair"})
TREE_DEPTH_ATTACKS = frozenset({"tap", "tree_of_attacks_pruned"})
```

### 3.8 文档同步原则

每次代码变更后，相关文档必须同步更新：

| 变更类型 | 需更新文档 |
|---------|------------|
| 新增/修改 Target 类型 | `docs/targets.md` + 双库 |
| 新增/修改 Attack 技术 | `docs/executor.md` + `config/payload_strategy_matrix.yaml` |
| 新增/修改数据集层 | `docs/datasets_architecture.md` |
| 架构变更 | `docs/architecture_design.md` + `docs/architecture_assessment.md` + 双库 |
| 开发规则变更 | 双库（`.assistant_pyrit/memory_bank.md` + `docs/development_guidelines.md`） |

### 3.8.1 新增数据源规则

新增数据源时：
1. 在 `DatasetManager` 中添加 `load_*_datasets()` 方法
2. 方法内部调用 `memory.add_seed_datasets_to_memory_async()` 存入 CentralMemory
3. 在 `load_datasets()` 统一入口中添加开关参数
4. 在 `config.yaml` 的 `dataset_manager` 中添加配置段
5. 确保数据格式为 PyRIT 原生 `SeedDataset`

### 3.8.2 新增种子组元数据规则

新增 YAML 种子时，metadata 字段应包含：
```yaml
metadata:
  owasp_id: "LLM01"           # 必填
  technique: "direct"          # 必填
  severity: "high"             # 必填
  attack_mode: "single_turn"   # 必填
  rationale: "..."             # 可选
```

### 3.8.3 选择层扩展规则

扩展选择层功能时：
1. 新增过滤维度: 在 `SeedGroupSelector` 中添加 `filter_by_*()` 静态方法
2. 新增展示维度: 在 `SeedGroupEntry` 中添加字段，在 `_build_entry()` 中提取
3. 不修改 `AttackPreparator` 的接口和逻辑

### 3.9 XPIA/RAG 攻击开发规范

**原则**: XPIA 工作流必须委托原生 `XPIAWorkflow`，使用 `MessagePiece` 新 API。

**必须遵循**:
- `XPIAWorkflowWrapper` 内部委托原生 `XPIAWorkflow`（不可自行实现工作流逻辑）
- 攻击内容使用 `MessagePiece` 新 API 构建（`Message(message_pieces=[MessagePiece(...)])`）
- Converter 链通过 `converter_config` 参数传入（`StrategyConverterConfig`）
- RAG 攻击使用 `RAGXPIAWorkflowWrapper`（专用 RAG 检索模拟）
- ProcessingCallback 使用 `ProcessingCallbackBuilder` 工厂方法构建

**ProcessingCallback 类型**:
| 类型 | 方法 | 场景 |
|------|------|------|
| Agent function calling | `agent_function_calling_callback` | OpenAI Responses API + Tool Calling |
| RAG 检索 | `rag_retrieval_callback` | RAG 检索+生成模拟 |
| 简单处理 | `simple_processing_callback` | 已有 PromptTarget 直接处理 |

### 3.10 多模态攻击开发规范

**原则**: 攻击前必须检查目标能力兼容性，不支持的模态自动降级。

**必须遵循**:
- 攻击前调用 `ModalityRouter.route_attack()` 检查兼容性
- 多模态种子使用 `ModalityRouter.build_multimodal_message()` 构建
- 不支持的模态降级到纯文本（不跳过攻击）
- `OpenAIImageTarget` 通过 `openai_image` 类型注册到 TargetFactory

**TargetCapabilities 预设**:
| 预设 | 用途 |
|------|------|
| `TEXT_ONLY_CAPABILITIES` | 纯文本目标（Ollama, vLLM） |
| `GPT4O_CAPABILITIES` | GPT-4o 多模态目标 |
| `IMAGE_GENERATION_CAPABILITIES` | DALL-E 图片生成目标 |
| `REASONING_MODEL_CAPABILITIES` | o1/o3 推理模型 |

### 3.11 GCG/AML 管道开发规范

**原则**: GCG 支持双路径（本地 torch + AML 管道），后缀可通过 Converter 集成。

**必须遵循**:
- 本地 torch 路径: `generate_async`（需要 torch + model + tokenizer）
- AML 管道路径: `generate_via_aml_async`（委托原生 `GCGGenerator`）
- 一站式方法: `generate_and_create_converter_async`（生成 + 创建 `SuffixAppendConverter`）
- 不满足条件时安全降级（返回空列表，不抛异常）

### 3.12 Benchmark 返回类型规范

**原则**: Benchmark 封装返回原生 `AttackResult`，同时保留 dict 向后兼容。

**方法对应**:
| 方法 | 返回类型 | 用途 |
|------|---------|------|
| `run_native_async` | `AttackResult` | 原生结果（L5 对齐） |
| `run_async` | `Dict[str, Any]` | 向后兼容（附带 `native_result` 字段） |
| `run_batch_native_async` | `Tuple[List[AttackResult], Dict]` | 批量原生结果 + 摘要 |
| `run_batch_async` | `Dict[str, Any]` | 批量向后兼容 |

**特殊方法**:
- `QuestionAnsweringWrapper.run_wmdp_async`: WMDP 危险知识代理测试（含风险评估）

---

## 四、编码风格

### 4.1 Python 风格

- 遵循 PEP 8
- 类型注解必选（`from typing import ...`）
- Docstring 必选（Google 风格）
- 模块级 docstring 说明架构对齐

### 4.2 导入顺序

```python
# 1. 标准库
import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# 2. 第三方库
from pydantic import BaseModel, Field

# 3. PyRIT 原生
from pyrit.executor.attack import AttackExecutor, AttackScoringConfig
from pyrit.memory import CentralMemory
from pyrit.models import AttackSeedGroup, SeedGroup

# 4. 项目内部
from src.core.config_loader import get_config_loader
from src.payloads.models import AttackPlan
```

### 4.3 日志规范

```python
import logging
logger = logging.getLogger(__name__)

# ✅ 正确: 使用 logger
logger.info(f"Loaded {len(datasets)} datasets")
logger.warning(f"Failed to load dataset {yaml_file}: {e}")

# ❌ 错误: 使用 print（除非是 pipeline.py 的进度输出）
print("something")  # 禁止在 src/ 中使用！
```

**例外**: `pipeline.py` 使用 `print()` 作为用户可见的进度输出，`src/` 内部使用 `logger`。

### 4.4 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 类 | PascalCase | `NativeAttackExecutor` |
| 函数/方法 | snake_case | `execute_single_attack` |
| 常量 | UPPER_SNAKE | `SINGLE_TURN_ATTACKS` |
| 私有方法 | `_` 前缀 | `_create_scoring_config` |
| 模块文件 | snake_case | `native_executor.py` |

---

## 五、验证与测试

### 5.1 分层测试命令

| 改动范围 | 命令 | 说明 |
|----------|------|------|
| 模块内改动 | `pytest tests/unit/test_<module>.py -x -q` | 单元测试 |
| 模块间改动 | `pytest tests/integration/ -x -q` | 集成测试 |
| 多模块改动 | `pytest tests/ -x -q` | 完整回归测试 |

### 5.2 死代码清理命令

```bash
# 自动修复（未使用导入/变量/f-string）
python -m ruff check src/ pipeline.py --fix

# 检查残留（含重复字典键、导入位置等）
python -m ruff check src/ pipeline.py --output-format=concise
```

### 5.3 测试目录

```
tests/
├── conftest.py          # pytest 配置
├── unit/                # 单元测试
└── integration/         # 集成测试
```

### 5.4 测试要求

- 每次代码修改后必须根据改动范围运行对应层级测试（§1.9）
- 每次代码修改后必须清理冗余/死代码（§1.10）
- 新增功能必须编写单元测试
- 集成测试覆盖端到端流程
- 测试失败必须修复，不允许跳过

---

## 六、Git 提交规范

### 6.1 提交信息

```
<type>(<scope>): <subject>

<body>
```

**type**: `feat` / `fix` / `docs` / `refactor` / `test` / `chore`  
**scope**: 模块名（如 `executor` / `targets` / `scorers`）

### 6.2 分支策略

- `main`: 稳定分支
- `feature/*`: 功能分支
- `fix/*`: 修复分支
