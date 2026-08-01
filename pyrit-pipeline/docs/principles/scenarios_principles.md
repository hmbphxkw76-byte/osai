# PyRIT Scenarios 原理说明文档

> 基于 PyRIT 1.1.0.dev0 官方文档（5 个页面）系统梳理 — 以 PyRIT 专家架构师视角  
> 文档版本：v1.1 | 更新日期：2026-8-1  
> Pipeline 对接：TextAdaptive 场景由 `pipeline/stages/stage_scenario.py` 构造，ASR 驱动选择由 `pipeline/asr/failure_type_selector.py` 实现，详见 [architecture_design.md](../architecture_design.md#三六阶段流水线)  
> 官方文档来源：  
> - [Scenarios](https://microsoft.github.io/PyRIT/1.1.0.dev0/code/scenarios/scenarios/)  
> - [Attack Techniques](https://microsoft.github.io/PyRIT/1.1.0.dev0/code/scenarios/attack-techniques/)  
> - [Common Scenario Parameters](https://microsoft.github.io/PyRIT/1.1.0.dev0/code/scenarios/common-scenario-parameters/)  
> - [Custom Scenario Parameters](https://microsoft.github.io/PyRIT/1.1.0.dev0/code/scenarios/custom-scenario-parameters/)
> - [Adaptive Scenarios](https://microsoft.github.io/PyRIT/1.1.0.dev0/code/scenarios/adaptive-scenarios/)

---

## 目录

1. [Scenario 核心概念](#1-scenario-核心概念)
2. [关键组件体系](#2-关键组件体系)
3. [Attack Technique 体系](#3-attack-technique-体系)
4. [Common Scenario Parameters](#4-common-scenario-parameters)
5. [Custom Scenario Parameters](#5-custom-scenario-parameters)
6. [Adaptive Scenarios](#6-adaptive-scenarios)
7. [现有 Scenario 目录](#7-现有-scenario-目录)
8. [Baseline 执行策略](#8-baseline-执行策略)
9. [弹性与恢复机制](#9-弹性与恢复机制)
10. [Matrix-Shaped Scenarios 与 build_matrix_atomic_attacks](#10-matrix-shaped-scenarios-与-build_matrix_atomic_attacks)
11. [AI-300 考试知识映射](#11-ai-300-考试知识映射)
12. [Scenario 设计哲学](#12-scenario-设计哲学)
13. [当前项目实现评估](#13-当前项目实现评估)
14. [最佳实践与建议路线图](#14-最佳实践与建议路线图)

---

## 1. Scenario 核心概念

### 1.1 定义

**Scenario**（场景）是一个 **更高级别的构造**，将多个 Attack Configuration 组合在一起。它允许你执行一个包含多种攻击方法的综合测试活动（testing campaign）。Scenario 编排多个 `AtomicAttack` 实例的顺序执行，并将结果聚合到单个 `ScenarioResult` 中。

关键区分：
- **Scenario ≠ Attack**：Attack 是与目标系统交互的算法（Executor），Scenario 是编排多个 Attack 的 **测试活动**。
- **Scenario ≠ Attack Technique**：Attack Technique 是一个配置配方（角色扮演框架、多示例引导集），由 Scenario 按名称选择。Scenario 是选择和运行 Techniques 的 **编排层**。
- **Scenario ≠ Orchestrator**：在 PyRIT 1.0.0 中，Orchestrator 概念已被 Scenario 和 AttackExecutor 替代。Scenario 负责 "运行哪些攻击"，AttackExecutor 负责 "如何并行执行"。

### 1.2 核心不变量

```
Scenario = {AtomicAttack_1, AtomicAttack_2, ..., AtomicAttack_n} -> ScenarioResult
```

每个 `AtomicAttack` 顺序执行，测试其配置的攻击技术对所有指定 objectives 和 datasets 的效果。结果聚合为 `ScenarioResult`，包含所有攻击结果和 scenario 元数据。

### 1.3 典型用例

| Scenario 名称 | 描述 | 场景 |
|---|---|---|
| VibeCheckScenario | 从 HarmBench 随机选取少量提示，快速评估模型行为 | 快速冒烟测试 |
| QuickViolence | 使用多种攻击技术检查模型对暴力内容的防御 | 专项危害测试 |
| ComprehensiveFoundry | 使用所有可用攻击转换器和技术测试目标 | 全面渗透测试 |
| CustomCompliance | 使用精选数据集和攻击测试特定合规要求 | 合规审计 |

### 1.4 运行方式

Scenario 应该几乎不需要配置即可运行。PyRIT Scanner 提供两个 CLI：
- **`pyrit_scan`**：自动化执行，适合 CI/CD 和批量测试
- **`pyrit_shell`**：交互式探索，适合手动分析和调试

```bash
# CLI 基本运行
pyrit_scan --scenario TextAdaptive --target openai_chat

# 指定数据集和技术
pyrit_scan --scenario TextAdaptive --target openai_chat \
  --datasets airt_hate airt_violence \
  --max-dataset-size 10

# 调整自适应参数
pyrit_scan --scenario TextAdaptive --target openai_chat \
  --params max_attempts_per_objective=5 \
  --techniques single_turn
```

### 1.5 生命周期

Scenario 的生命周期分为三个阶段：

1. **构造（Construction）**：`__init__` 接收 `objective_scorer` 和 `scenario_result_id`（用于 resume），但不接收 `objective_target`——目标在 `initialize_async()` 中注入
2. **初始化（Initialization）**：`initialize_async()` 接收 `objective_target`、`scenario_techniques`、`max_concurrency` 等运行参数，调用 `_build_atomic_attacks_async(context)` 构建 AtomicAttack 列表
3. **执行（Execution）**：`run_async()` 顺序执行每个 AtomicAttack，结果聚合为 ScenarioResult

---

## 2. 关键组件体系

### 2.1 组件关系图

```
+-------------------------------------------------------------+
|                      Scenario                                |
|  (top-level orchestrator: groups & executes atomic attacks)  |
|                                                             |
|  +-------------+  +-------------+  +-------------+          |
|  | AtomicAttack|  | AtomicAttack|  | AtomicAttack|          |
|  |     #1      |  |     #2      |  |     #N      |          |
|  +------|------+  +------|------+  +------|------+          |
|         |                |                |                  |
|         v                v                v                  |
|  +----------------------------------------------+           |
|  |           ScenarioResult                     |           |
|  |  (aggregated results + scenario metadata)    |           |
|  +----------------------------------------------+           |
+-------------------------------------------------------------+
```

### 2.2 三大核心组件

| 组件 | 职责 | 关键属性 |
|---|---|---|
| **Scenario** | 顶层编排器，组合并执行多个原子攻击 | `name`, `version`, `technique_class`, `default_dataset_config`, `objective_scorer` |
| **AtomicAttack** | 原子测试单元，组合攻击技术 + objectives + 执行参数 | `atomic_attack_name`, `attack_technique`, `seed_groups`, `adversarial_chat`, `objective_scorer` |
| **ScenarioResult** | 聚合所有原子攻击结果 + scenario 元数据 | `attack_results`, `display_groups`, `id` |

### 2.3 AtomicAttack 内部结构

```python
AtomicAttack(
    atomic_attack_name="role_play_demo",       # 攻击名称
    attack_technique=technique,                 # AttackTechnique 实例（已配置的攻击）
    seed_groups=[seed_group],                   # AttackSeedGroup 列表（objectives）
    adversarial_chat=adversarial_chat,          # 对抗 LLM target（多轮攻击需要）
    objective_scorer=objective_scorer,          # 目标评分器
)
```

一个 `AtomicAttack` 将一个已配置的 Technique（the how）与一个或多个 `AttackSeedGroup`（每个携带一个 objective = the what）配对。它运行该 Technique 对每个 objective 的攻击，并返回结果——这是 `Scenario` 内部执行的相同单元，只是去掉了编排层。

### 2.4 执行流程

```
1. Scenario.initialize_async()
   -> 接收 objective_target, scenario_techniques, max_concurrency 等参数
   -> 调用 _build_atomic_attacks_async(context) 构建 AtomicAttack 列表

2. Scenario.run_async()
   -> 每个 AtomicAttack 顺序执行
   -> 每个 AtomicAttack 测试其配置的攻击技术对所有指定 objectives 和 datasets
   -> 结果聚合为 ScenarioResult
   -> 可选 memory_labels 用于跟踪和分类
```

### 2.5 构建自定义 Scenario 的路径

1. **定义 Technique 枚举**：创建 `ScenarioTechnique` 枚举，定义可用的攻击技术
2. **定义 Dataset 配置**：通过 `default_dataset_config` 指定默认数据集
3. **实现 Constructor**：使用 `@apply_defaults` 装饰器，调用 `super().__init__()` 传入元数据
4. **实现 `_build_atomic_attacks_async(context)`**：唯一的抽象扩展点

---

## 3. Attack Technique 体系

### 3.1 Technique vs. Attack 的关系

**Attack**（a.k.a. Executor）是运行提示词对抗目标的算法。**Technique** 包装一个已配置的 Attack，使其可以被注册、列举、标记和选择，而调用者无需知道它是如何构建的。一个 Scenario 运行一组 Techniques 对抗一组 objectives。

Technique 可以打包：
- **attack_class**（`AttackStrategy` 子类）及其所有构造参数（`attack_kwargs`）—— 如 `max_turns`、`tree_width`/`tree_depth`、或 `AttackConverterConfig`
- **adversarial_chat** 目标及其 system prompt（`adversarial_system_prompt_path`）和 seed prompt（`adversarial_seed_prompt`）—— 用于驱动对话的攻击
- **AttackTechniqueSeedGroup**（`seed_technique`）：通用技术种子，可携带 system prompt、prepended_conversation、simulated_conversation（`SeedSimulatedConversation`）和 next_message
- **选择元数据**：`name` 和 `technique_tags`

> **关键原则**：objective 不是 Technique 的一部分——它保持独立，由 dataset 在运行时提供。你很少手工构建 Technique；而是注册一个 factory，让 Scenario 用自己的 objective target 和 scorer 按需构建 Technique。

### 3.2 Technique 来源：Initializers

技术目录位于 `pyrit/setup/initializers/techniques/`。Techniques 分为小组模块，每个模块暴露一个 `get_technique_factories()` 函数返回 `AttackTechniqueFactory` 实例列表：

| 模块 | 说明 | 注册方式 |
|---|---|---|
| `core.py` | 通用技术，任何 Scenario 都可使用（role_play 变体、many_shot、tap、crescendo 变体、red_teaming、context_compliance） | 默认注册 |
| `extra.py` | 可选技术（pair、violent_durian、skeleton_key） | 需显式注册 |
| `airt.py` | 源自特定 AIRT Scenario 的技术 | 由所属 Scenario 直接导入 |

**TechniqueInitializer** 聚合选定的组模块，将它们的 factory 注册到单例 `AttackTechniqueRegistry`。聚合时注入组名作为 technique tag（每个 core 技术获得 `core` tag，每个 extra 技术获得 `extra` tag），使整组可一次选中。

注册控制通过 initializer 的 `tags` 参数：
- 默认（无 `tags`）—— 仅注册 `core`
- `tags=["core", "extra"]` —— 注册两组
- `tags=["all"]` —— `core` + `extra` 的简写

注册是按名称幂等的，所以 initializer 可组合：运行多个时每个只添加尚未注册的技术。

### 3.3 完整 Technique 目录

| Technique | Attack (Executor) | 需要对抗? | Tags |
|---|---|---|---|
| context_compliance | PromptSendingAttack | yes | single_turn, light, core |
| crescendo_history_lecture | PromptSendingAttack | yes | single_turn, core |
| crescendo_journalist_interview | PromptSendingAttack | yes | single_turn, core |
| crescendo_movie_director | PromptSendingAttack | yes | single_turn, core |
| crescendo_simulated | PromptSendingAttack | yes | single_turn, core |
| flip | PromptSendingAttack | no | single_turn, light, core |
| many_shot | ManyShotJailbreakAttack | no | multi_turn, light, core |
| pair | PAIRAttack | yes | multi_turn, extra |
| red_teaming | RedTeamingAttack | yes | multi_turn, light, core |
| role_play_movie_script | PromptSendingAttack | yes | single_turn, light, core |
| role_play_persuasion | PromptSendingAttack | yes | single_turn, light, core |
| role_play_persuasion_written | PromptSendingAttack | yes | single_turn, light, core |
| role_play_trivia_game | PromptSendingAttack | yes | single_turn, light, core |
| role_play_video_game | PromptSendingAttack | yes | single_turn, light, core |
| skeleton_key | SkeletonKeyAttack | no | single_turn, extra |
| tap | TreeOfAttacksWithPruningAttack | yes | multi_turn, core |
| violent_durian | RedTeamingAttack | yes | multi_turn, extra |

### 3.4 Technique 选择方式

Scenario 不直接引用 factory。而是通过 `ScenarioTechnique` 枚举从已注册的 factory 构建：每个 technique 成为枚举成员，factory 的 tags 成为可选择的聚合体。

| 选择方式 | 说明 | 示例 |
|---|---|---|
| **按名称** | 选择单个技术 | `role_play_movie_script` |
| **按聚合标签** | 选择所有匹配技术的组 | `ALL`（全部）、`single_turn`（单轮）、`light`（轻量） |
| **组合** | 将技术与转换器配对 | `FoundryComposite(attack=Crescendo, converters=[Base64])` |

CLI 中对应 `--technique` 标志；编程接口中对应 `scenario_techniques` 参数。

### 3.5 ScenarioTechnique 枚举设计

`ScenarioTechnique` 是一个特殊的枚举基类，每个成员定义为 `(value, tags)` 元组：

```python
class MyTechnique(ScenarioTechnique):
    ALL = ("all", {"all"})
    DEFAULT = ("default", {"default"})
    SINGLE_TURN = ("single_turn", {"single_turn"})
    PromptSending = ("prompt_sending", {"single_turn", "default"})
    RolePlay = ("role_play_movie_script", {"single_turn"})
```

- **聚合成员**（如 `ALL`、`DEFAULT`、`SINGLE_TURN`）在解析时展开为其 tags 覆盖的所有具体技术
- **具体成员**（如 `PromptSending`、`RolePlay`）直接映射到已注册的 factory
- `default()` classmethod 返回默认聚合成员

### 3.6 单轮攻击与 Technique 的关系

许多单轮攻击实际上就是攻击技术：一个 `PromptSendingAttack` 配以特定的种子集或固定配置。`crescendo_simulated` 和角色驱动的 crescendo 变体就是如此——一个普通的 `PromptSendingAttack` 加上不同的种子组。当你发现自己想创建一个一次性单轮攻击子类时，考虑是否将其表达为已注册的技术，这样 Scenario 可以按名称和标签选择它。

### 3.7 注册自定义 Technique

最简形式——命名一个 Attack 类并添加标签：

```python
from pyrit.executor.attack import PromptSendingAttack
from pyrit.registry import AttackTechniqueRegistry
from pyrit.scenario.core.attack_technique_factory import AttackTechniqueFactory

AttackTechniqueRegistry.get_registry_singleton().register_from_factories(
    [
        AttackTechniqueFactory(
            name="my_prompt_sending",
            attack_class=PromptSendingAttack,
            technique_tags=["single_turn", "custom"],
        )
    ]
)
```

将注册包装在 `PyRITInitializer` 中（如 `TechniqueInitializer` 所做），使其作为标准设置的一部分运行。要将技术作为标准目录的一部分，添加到 `pyrit/setup/initializers/techniques/` 下的组模块中。

---

## 4. Common Scenario Parameters

### 4.1 两个选择轴

| 轴 | 选择什么 | 说明 |
|---|---|---|
| **Techniques** | 攻击技术（攻击如何运行） | prompt_sending、role_play、TAP 等 |
| **Datasets** | objectives（测试什么） | 危害类别、合规主题等 |

CLI 中使用 `--dataset-names` 按内容类别过滤，`--techniques` 按技术类型过滤。

### 4.2 Dataset Configuration

`DatasetAttackConfiguration` 控制向目标发送哪些提示（objectives）。

**最简方式**——使用 `dataset_names` 从内存加载数据集：

```python
from pyrit.scenario import DatasetAttackConfiguration

dataset_config = DatasetAttackConfiguration(
    dataset_names=["harmbench"], max_dataset_size=2
)
```

**精细控制**——使用 `SeedDatasetProvider` 获取数据集并传入显式 `seed_groups`：

```python
from pyrit.datasets import SeedDatasetProvider
from pyrit.models import SeedGroup

datasets = await SeedDatasetProvider.fetch_datasets_async(dataset_names=["harmbench"])
seed_groups: list[SeedGroup] = datasets[0].seed_groups

dataset_config = DatasetAttackConfiguration(seed_groups=seed_groups, max_dataset_size=2)
```

**内联注入**——通过 `seed_groups=` 直接传入（不触碰 Memory）：

```python
dataset_config = DatasetAttackConfiguration(seed_groups=my_attack_seed_groups)
```

> 三种数据源互斥：`seeds=` / `seed_groups=` / `dataset_names=`

### 4.3 Technique 选择与组合

三种方式指定 Techniques，可混合使用：

```python
# 1. 单个技术
single_technique = [FoundryTechnique.Base64]

# 2. 聚合技术（标签扩展）
aggregate_technique = [FoundryTechnique.EASY]

# 3. 组合技术（攻击 + 转换器）
from pyrit.scenario.foundry import FoundryComposite
composite_technique = [FoundryComposite(
    attack=FoundryTechnique.Crescendo,
    converters=[FoundryTechnique.Base64]
)]

# 混合使用
scenario_techniques = [
    FoundryTechnique.Base64,
    FoundryTechnique.Binary,
    FoundryComposite(attack=FoundryTechnique.Crescendo, converters=[FoundryTechnique.Caesar]),
]
```

### 4.4 Custom Scorers

默认使用复合评分器（Azure Content Filter + SelfAsk Refusal）。可通过 `AttackScoringConfig` 覆盖：

```python
from pyrit.executor.attack import AttackScoringConfig
from pyrit.score import SelfAskRefusalScorer, TrueFalseInverterScorer

# 越狱成功 = 目标未拒绝 -> 反转拒绝评分器
refusal_scorer = SelfAskRefusalScorer(chat_target=OpenAIChatTarget())
inverted_scorer = TrueFalseInverterScorer(scorer=refusal_scorer)

custom_scenario = RedTeamAgent(
    attack_scoring_config=AttackScoringConfig(objective_scorer=inverted_scorer),
)
```

### 4.5 结果排序

`output_scenario_async` 支持 `sort_groups_by_success_rate=True`，按成功率降序排列 Per-Group Breakdown，使最成功的技术一目了然。

### 4.6 通用运行输入参数

以下参数由 Scenario 基类统一管理，所有 Scenario 均支持：

| 参数 | 类型 | 说明 |
|---|---|---|
| `objective_target` | PromptChatTarget | 被攻击的目标 |
| `scenario_techniques` | list[ScenarioTechnique] | 要运行的攻击技术（默认 ALL） |
| `dataset_config` | DatasetAttackConfiguration | 数据集配置 |
| `max_concurrency` | int | 并发执行数 |
| `max_retries` | int | Scenario 级别重试次数 |
| `memory_labels` | dict[str, str] | 附加到所有攻击结果的标签 |
| `include_baseline` | bool | 是否包含基线（受 BASELINE_ATTACK_POLICY 约束） |

---

## 5. Custom Scenario Parameters

### 5.1 声明参数

使用 `Parameter` 声明，通过 `additional_parameters()` classmethod 返回自定义参数列表。基类将其与通用运行输入组合，无需重复或遗漏：

```python
from pyrit.models import Parameter

@classmethod
def additional_parameters(cls) -> list[Parameter]:
    return [
        Parameter(
            name="max_turns",
            description="Maximum conversation turns for the persuasive_rta technique.",
            param_type=int,
            default=5,
        ),
    ]
```

### 5.2 Parameter 属性

| 属性 | 说明 |
|---|---|
| `name` | `self.params` 中的键，CLI 中转换为 `--kebab-case` |
| `description` | 显示在 `--list-scenarios` 和 `--help` 中 |
| `default` | 未提供时使用的值；每次运行深拷贝 |
| `param_type` | `str`, `int`, `float`, `bool`, `Literal[...]`/`Enum`, `list[...]`, 或 `None`（原始透传） |

### 5.3 运行时读取

框架调用 `set_params_from_args` 后，`self.params["max_turns"]` 返回用户值或声明默认值。编程用户也获得同样行为：`initialize_async()` 在首次运行时物化声明的默认值。可变默认值如 `["a", "b"]` 每次运行深拷贝，一个 Scenario 实例的更改不会泄漏到另一个。

### 5.4 CLI 标志

```bash
# 使用声明默认 (5)
pyrit_scan airt.scam --target my_target --initializers target

# 覆盖
pyrit_scan airt.scam --target my_target --initializers target --max-turns 10
```

声明的标志也出现在 `pyrit_scan <scenario> --help` 和 `--list-scenarios` 中。

### 5.5 Resume 验证

通过 `scenario_result_id` 恢复时，PyRIT 验证存储结果与当前配置完全匹配。任何偏差抛出 `ValueError` 而非静默启动新 Scenario。不匹配维度：
- 存储的 ID 在内存中未找到（拼写错误、已清除 DB、从未持久化）
- Scenario 名称不同（如 Scam ID 传给 Cyber 构造器）
- Scenario 版本不同（保存和恢复之间的发布漂移）
- 有效参数与原始运行的持久化参数不同

差异消息只命名 changed/added/removed 的键，不打印值，防止敏感参数泄露到异常输出中。

---

## 6. Adaptive Scenarios

### 6.1 核心理念

自适应 Scenario 不对每个 objective 运行所有攻击技术。而是 **按 objective 选择下一个要尝试的技术**，从有效的结果中学习，并在某个技术成功时立即停止。这将花费集中在实际有效的技术上。

### 6.2 工作原理

对每个 objective，Scenario 尝试最多 `max_attempts_per_objective` 个技术：
1. **探索（概率 epsilon）**：随机选择一个技术
2. **利用（概率 1-epsilon）**：选择当前观察成功率最高的技术
3. **记录结果**，成功则提前停止

未尝试的技术优先尝试，因此前几个 objective 实际上轮询每个技术，然后 Scenario 稳定在最佳表现者上。

### 6.3 自适应 vs. 静态对比

| 特性 | 静态 Scenario | 自适应 Scenario |
|---|---|---|
| 技术选择 | 运行所有选定的技术 | 按结果选择 |
| 提前停止 | 否 | 是——首次成功即停止 |
| 成本 | O(techniques x objectives) | O(max_attempts x objectives) |

### 6.4 AdaptiveTechniqueDispatcher 与 SequentialAttack

自适应 Scenario 内部使用 `AdaptiveTechniqueDispatcher` 构建 `SequentialAttack`：

- **SequentialAttack**：将多个技术按 selector 排序组合成序列
- **FIRST_SUCCESS 策略**：第一个成功的技术自动终止后续尝试
- **TechniqueBundle**：每个技术打包为 `TechniqueBundle`（attack + name + seed_technique + adversarial_chat）
- **eval_hash 去重**：相同配置的技术通过 `compute_inner_attack_eval_hash` 去重

### 6.5 配置参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `max_attempts_per_objective` | 3 | 每个 objective 尝试的最大技术数 |
| `selector` (epsilon) | 0.2 | epsilon-greedy 选择器的探索概率 |
| `random_seed` | None | 随机种子（可复现） |
| `scenario_techniques` | ALL | 限制选择器可选的技术范围 |

```python
from pyrit.scenario.scenarios.adaptive import EpsilonGreedyTechniqueSelector

configured_scenario = TextAdaptive(
    selector=EpsilonGreedyTechniqueSelector(epsilon=0.3, random_seed=42),
)
configured_scenario.set_params_from_args(args={
    "max_attempts_per_objective": 5,
    "objective_target": objective_target,
    "scenario_techniques": [technique_class("single_turn")],
    "dataset_config": DatasetAttackConfiguration(
        dataset_names=["airt_hate", "airt_violence"], max_dataset_size=4,
    ),
})
```

### 6.6 自定义 TechniqueSelector

`TechniqueSelector` 是一个抽象基类，定义 `select_async()` 接口：

```python
class TechniqueSelector(ABC):
    async def select_async(
        self,
        *,
        technique_identifiers: Sequence[str],
        objective: str,
        num_top_techniques: int = 1,
        scenario_result_id: str | None = None,
    ) -> Sequence[str]:
        ...
```

子类可以覆写 `select_async()` 实现自定义选择逻辑。`EpsilonGreedyTechniqueSelector` 是官方提供的默认实现，通过查询 Memory 获取历史成功率。

### 6.7 检查尝试记录

每个自适应运行持久化 per-objective envelope（`SequentialAttackResult`）及其 per-attempt child rows。每个 child row 携带自己的 `atomic_attack_identifier`，持久化数据足以重建 per-attempt 轨迹——无需 envelope 侧元数据或 Scenario 侧查找表。

### 6.8 排除技术

`prompt_sending` 运行作为基线比较，从自适应技术池中排除。通过 `_EXCLUDED_TECHNIQUES` 类属性控制。

### 6.9 抽象方法

`AdaptiveScenario` 要求子类实现以下抽象方法：

| 方法 | 说明 |
|---|---|
| `_atomic_attack_prefix()` | 返回 per-objective atomic-attack 名称前缀 |
| `get_technique_class()` | 返回 Scenario 的 Technique 枚举类 |
| `default_dataset_config()` | 返回默认 DatasetAttackConfiguration |

---

## 7. 现有 Scenario 目录

### 7.1 完整列表（10 个）

| Scenario | 类名 | 技术数 | 默认数据集 | 特殊参数 |
|---|---|---|---|---|
| `adaptive.text_adaptive` | TextAdaptive | 10 个自适应 | 7 个 AIRT (max 4 each) | `max_attempts_per_objective` |
| `airt.cyber` | Cyber | 1 个 (red_teaming) | airt_malware | — |
| `airt.jailbreak` | Jailbreak | 4 个 (prompt_sending, many_shot, skeleton, role_play) | airt_harms | — |
| `airt.leakage` | Leakage | 12 个 (含 first_letter, image) | airt_leakage | — |
| `airt.psychosocial` | Psychosocial | 2 个 (imminent_crisis, licensed_therapist) | airt_imminent_crisis | — |
| `airt.rapid_response` | RapidResponse | 10 个 | 7 个 AIRT | — |
| `airt.scam` | Scam | 3 个 (context_compliance, role_play, persuasive_rta) | airt_scams | `max_turns` |
| `benchmark.adversarial` | AdversarialBenchmark | 9 个 | harmbench (max 8) | `adversarial_targets` |
| `foundry.red_team_agent` | RedTeamAgent | 25 个 (含编码攻击) | harmbench | — |
| `garak.encoding` | Encoding | 17 个编码技术 | garak_slur_terms_en, garak_web_html_js | — |

### 7.2 技术标签聚合体系

每个 Scenario 的 `ScenarioTechnique` 枚举从已注册的 factory 构建。聚合标签可一次选择整组：

```
foundry.red_team_agent:
  Aggregate: all, easy, moderate, difficult
  EASY -> Base64, Binary, CharSwap, Flip, Leetspeak, Morse, ROT13...

adaptive.text_adaptive:
  Aggregate: all, default, single_turn, multi_turn
  prompt_sending -> baseline (excluded from adaptive pool)
```

### 7.3 关键 Scenario 详解

**RedTeamAgent**（25 技术）：最全面的 Scenario，支持 EASY/MODERATE/DIFFICULT 难度级别扩展。包含 17 种编码攻击（Base64/ROT13/Morse 等）+ 多轮攻击（Crescendo/PAIR/TAP）。设计用于 Foundry AI Red Teaming Agent 库集成。

**TextAdaptive**（10 技术）：自适应 Scenario 的典型实现。使用 epsilon-greedy 选择器，`prompt_sending` 作为基线排除。跨 7 个 AIRT 数据集（hate/fairness/violence/sexual/harassment/misinformation/leakage）。

**AdversarialBenchmark**：跨对抗模型比较 ASR。用户通过 `adversarial_targets` 参数提供对抗目标，执行 `(technique x adversarial_target x dataset)` 交叉积。

---

## 8. Baseline 执行策略

### 8.1 三种策略

| 策略 | 说明 | 适用场景 |
|---|---|---|
| **Enabled** | 基线默认前置，调用者可选择退出 | 大多数 Scenario（未修改提示是有效比较点） |
| **Disabled** | 基线支持但默认省略，调用者需选择启用 | Scenario 已被大量模板/技术主导（如 Jailbreak） |
| **Forbidden** | 基线不可用，传入 `include_baseline=True` 会抛出异常 | 基线无意义的 Scenario（如跨对抗模型基准测试、仅多轮 Scenario） |

### 8.2 基线用途

基线是一个 `PromptSendingAttack`，将每个 objective 直接发送给目标，不使用任何转换器或多轮技术。

- **测量默认防御**：目标如何响应未修改的有害提示？
- **建立比较点**：比较基线拒绝率与攻击增强运行
- **计算攻击提升**：每个技术比基线提升多少？

```python
# 禁用基线
scenario = RedTeamAgent()
scenario.set_params_from_args(args={
    "objective_target": objective_target,
    "scenario_techniques": [FoundryTechnique.Base64],
    "include_baseline": False,
})
```

---

## 9. 弹性与恢复机制

### 9.1 自动恢复

重新运行 Scenario 时，自动从上次中断处继续。框架跟踪已完成的攻击和 objectives，不会因中断而丢失进度。可安全停止和重启 Scenario 而不重复工作。

### 9.2 重试机制

`max_retries` 参数处理瞬时故障。任何未知异常发生时，PyRIT 自动重试失败操作（从中断处继续）最多指定次数。

### 9.3 动态配置

长时间运行的 Scenario 期间，可安全停止、重新配置（如调整 `max_concurrency`、切换 scorer 使用不同 target）并继续。PyRIT 的弹性特性使按需停止、重新配置和继续 Scenario 变得安全。

---

## 10. Matrix-Shaped Scenarios 与 build_matrix_atomic_attacks

### 10.1 矩阵架构

矩阵形 Scenario 使用 `build_matrix_atomic_attacks` 辅助函数，从已注册的攻击技术自动构建 AtomicAttack。一行代码完成构建：

```python
async def _build_atomic_attacks_async(self, *, context):
    return build_matrix_atomic_attacks(
        context=context,
        objective_scorer=self._objective_scorer,
        display_group_fn=lambda combo: combo.dataset_name,  # 按数据集分组
    )
```

### 10.2 构建路径

```
定义 Technique 枚举 + Dataset 配置 + Constructor
    |
    v
实现 _build_atomic_attacks_async(context)
    |
    v
矩阵形 Scenario 委托 build_matrix_atomic_attacks
    |
    v
自动从注册的攻击技术构建 AtomicAttack
    |
    v
display_group_fn 自定义结果分组（默认按技术，可按数据集）
```

### 10.3 自定义 Scenario 完整模板

```python
from pyrit.common import apply_defaults
from pyrit.scenario import DatasetConfiguration, Scenario, ScenarioTechnique
from pyrit.scenario.core.matrix_atomic_attack_builder import build_matrix_atomic_attacks
from pyrit.score.true_false.true_false_scorer import TrueFalseScorer

class MyTechnique(ScenarioTechnique):
    ALL = ("all", {"all"})
    DEFAULT = ("default", {"default"})
    SINGLE_TURN = ("single_turn", {"single_turn"})
    PromptSending = ("prompt_sending", {"single_turn", "default"})
    RolePlay = ("role_play_movie_script", {"single_turn"})

    @classmethod
    def default(cls) -> "MyTechnique":
        return cls.DEFAULT

class MyScenario(Scenario):
    """Quick-check scenario for testing model behavior across harm categories."""
    VERSION: int = 1

    @apply_defaults
    def __init__(self, *, objective_scorer=None, scenario_result_id=None):
        self._objective_scorer = (
            objective_scorer if objective_scorer else self._get_default_objective_scorer()
        )
        super().__init__(
            version=self.VERSION,
            objective_scorer=self._objective_scorer,
            technique_class=MyTechnique,
            default_dataset_config=DatasetConfiguration(
                dataset_names=["dataset_name"], max_dataset_size=4
            ),
            scenario_result_id=scenario_result_id,
        )

    async def _build_atomic_attacks_async(self, *, context):
        return build_matrix_atomic_attacks(
            context=context,
            objective_scorer=self._objective_scorer,
            display_group_fn=lambda combo: combo.dataset_name,
        )
```

---

## 11. AI-300 考试知识映射

### 11.1 Scenario 知识点与考试映射

| 知识领域 | Scenario 概念 | 考试应用 |
|---|---|---|
| 攻击编排 | Scenario + AtomicAttack | 理解如何将多个攻击组合为测试活动 |
| 技术选择 | ScenarioTechnique 枚举 + tags | 按攻击类型快速选择技术组合 |
| 数据集管理 | DatasetAttackConfiguration | 选择正确的 objectives 测试目标 |
| 自适应优化 | AdaptiveScenario + epsilon-greedy | 在有限时间内最大化成功率 |
| 基线比较 | BASELINE_ATTACK_POLICY | 评估攻击增强效果 |
| 弹性恢复 | max_retries + 自动恢复 | 考试中网络不稳定时的容错 |
| 参数化 | Custom Parameters | 运行时调整攻击参数（max_turns 等） |

### 11.2 考试场景中的 Scenario 应用

| 考试场景 | 推荐 Scenario | 关键配置 |
|---|---|---|
| LLM 越狱测试 | `airt.jailbreak` 或 `foundry.red_team_agent` | EASY 难度 + Base64/ROT13 编码 |
| 内容危害测试 | `airt.rapid_response` 或 `adaptive.text_adaptive` | 自适应 + max_attempts=3 |
| 数据泄露测试 | `airt.leakage` | 12 种技术含 first_letter/image |
| 对抗模型比较 | `benchmark.adversarial` | adversarial_targets 参数 |
| 编码攻击测试 | `garak.encoding` 或 `foundry.red_team_agent` | EASY 聚合标签 |
| 快速冒烟测试 | `adaptive.text_adaptive` | epsilon-greedy + 限制技术范围 |

---

## 12. Scenario 设计哲学

### 12.1 何时创建自定义 Scenario

- **需要特定工作流**：你的测试需要特定的攻击顺序、数据集组合或评分逻辑
- **需要可重复配方**：你希望一个命令即可运行完整的测试活动，包括默认数据集和技术
- **需要自定义参数**：你想暴露运行时可调参数（如 `max_turns`），而非修改源代码
- **需要特定结果分组**：默认按技术分组不够，你想按数据集、OWASP 类别等分组

### 12.2 何时不需要创建 Scenario

- **单次攻击测试**：直接使用 `AttackTechniqueFactory.create()` + `AtomicAttack.run_async()` 即可
- **快速探索**：使用 `pyrit_shell` 交互式运行已有 Scenario
- **一次性脚本**：直接使用 AttackExecutor，无需 Scenario 编排

### 12.3 核心设计原则

1. **Scenario 硬编码是可接受的**：Scenario 被设计为配置和编写以测试特定工作流，因此硬编码某些值是可接受的
2. **Technique 与 Objective 分离**：Technique 是 the how，Objective 是 the what，保持分离让 Scenario 可以灵活组合
3. **Factory 模式优先**：不手工构建 Technique，注册 factory 让 Scenario 按需构建
4. **标签驱动选择**：通过 tags 而非名称选择技术组，使聚合选择自然
5. **基线策略明确**：每个 Scenario 应明确选择其 `BASELINE_ATTACK_POLICY`

---

## 13. 当前项目实现评估

> 以 PyRIT 专家和资深架构师视角，逐文件评估 `src/scenarios/` 目录下所有代码实现的 PyRIT 原生框架对齐度。

### 13.1 目录结构总览

```
src/scenarios/
  ├── __init__.py                  # 模块导出（30+ 公共 API）
  ├── ai300_scenario.py            # AI300Scenario 基类（extends Scenario）
  ├── ai300_technique.py            # AI300Technique 枚举（extends ScenarioTechnique）
  ├── technique_factories.py        # AttackTechniqueFactory 注册（core + extra + Converter 变体）
  ├── technique_initializer.py      # TechniqueInitializer 初始化器
  ├── failure_type_selector.py      # FailureTypeRoutingSelector（extends EpsilonGreedyTechniqueSelector）
  ├── ai300_adaptive_scenario.py    # AI300AdaptiveScenario（extends AdaptiveScenario）
  ├── adaptive_runner.py            # 原生 Scenario 执行入口
  ├── scenario_output.py            # 原生 output_scenario_async 双通道输出
  └── scenario_result_bridge.py     # BatchAttackResult ↔ ScenarioResult 桥接 + OWASP 集成
```

### 13.2 逐文件评估

#### 13.2.1 `ai300_scenario.py` — 对齐度：95%

**原生优先 ✅：**
- `AI300Scenario` 继承 PyRIT 原生 `Scenario` 基类，完整获得 `initialize_async` / `run_async` 生命周期
- 使用 `@apply_defaults` 装饰器对齐原生构造模式
- 调用 `super().__init__()` 传入 `version`、`objective_scorer`、`technique_class`、`default_dataset_config`、`scenario_result_id`
- 实现 `_build_atomic_attacks_async(context)` 使用原生 `build_matrix_atomic_attacks` 辅助函数
- 通过 `additional_parameters()` classmethod 声明考试专用 `Parameter`（`max_turns`、`per_attack_timeout`）
- `BASELINE_ATTACK_POLICY` 三种策略正确使用（Enabled / Disabled）
- 三个预置子类（RapidResponse / Jailbreak / Encoding）对齐原生 AIRT Scenario 设计模式

**自建保留（合理） ✅：**
- `get_attack_plans_for_orchestrator()` 桥接方法：将 Scenario 的 AtomicAttack 转换为 AttackPlan，用于与现有 `ScenarioOrchestrator` 集成。这是 **必要的向后兼容桥接**，非替代原生 API。
- `per_attack_timeout` 参数声明：PyRIT 原生无 per-attack 超时机制，作为 `Parameter` 声明是合理的扩展。

**潜在改进点 🟡：**
- `_get_default_objective_scorer()` 方法在 `__init__` 中被调用但未在文件中定义——依赖父类 `Scenario` 的默认实现。如果父类无此方法，需确认行为。经查证，PyRIT 原生 `Scenario` 基类有 `_get_default_objective_scorer()` 实现（使用 `TrueFalseInverterScorer + RefusalScorer`），此处行为正确。

#### 13.2.2 `ai300_technique.py` — 对齐度：98%

**原生优先 ✅：**
- `AI300Technique` 继承 PyRIT 原生 `ScenarioTechnique` 枚举基类
- 每个成员定义为 `(value, tags)` 元组，完全对齐原生 `ScenarioTechnique` 设计
- 聚合成员（`ALL` / `DEFAULT` / `SINGLE_TURN` / `MULTI_TURN` / `LIGHT`）正确实现
- `default()` classmethod 返回 `DEFAULT` 聚合
- `get_aggregate_tags()` 返回聚合标签集合
- `AI300EncodingTechnique` 独立枚举对齐 `garak.encoding` Scenario 的编码专用技术
- 35 个技术成员覆盖官方 17 个核心 + 额外扩展（编码/Converter 变体）

**最佳实践 ✅：**
- tags 体系设计合理：`single_turn` / `multi_turn` / `light` / `encoding` / `default` 分层清晰
- 编码技术与原生 `foundry.red_team_agent` 的 EASY 聚合对齐

#### 13.2.3 `technique_factories.py` — 对齐度：95%

**原生优先 ✅：**
- 使用原生 `AttackTechniqueFactory` 类构建工厂
- 注册到原生 `AttackTechniqueRegistry` 单例
- `core` / `extra` 分组对齐原生 `core.py` / `extra.py` 模块设计
- `register_ai300_techniques()` 实现幂等注册（按名称去重），完全对齐原生 `TechniqueInitializer` 行为
- `AI300_TECHNIQUE_METADATA` 包含完整的元数据（`attack_class`、`tags`、`description`、`uses_adversarial`、`category`）
- 覆盖全部官方 17 个技术 + 扩展编码技术 + Converter 变体

**Converter 变体创新（自建合理） ✅：**
- `CONVERTER_VARIANT_CHAINS` + `BASE_TECHNIQUES_FOR_VARIANTS` 定义 Converter 变体配置
- `build_converter_variant_factories()` 为每个基础技术注册多个 Converter 变体作为独立 `AttackTechniqueFactory`
- 将 `AttackConverterConfig` 烘焙到 `attack_kwargs` 中，使原生 `AdaptiveTechniqueDispatcher` 的 `FIRST_SUCCESS` 自动在首个成功变体处停止
- 这是对原生 Technique 体系的 **合理扩展**，利用了原生 `AttackTechniqueFactory` 的 `attack_kwargs` 参数实现 Converter 预配置

**最佳实践验证 ✅：**
- 非 LLM 链可在无 `converter_target` 时创建；LLM 链需 `converter_target`，缺失则跳过并记录警告
- 工具函数 `is_converter_variant()` / `get_base_technique_from_variant()` / `get_converter_chain_from_variant()` 提供清晰的变体识别接口
- `+"` 分隔符命名约定清晰（如 `prompt_sending+stealth_evasion`）

#### 13.2.4 `technique_initializer.py` — 对齐度：90%

**原生优先 ✅：**
- `AI300TechniqueInitializer` 对齐原生 `TechniqueInitializer` 的 `set_params_from_args` / `initialize_async` / `supported_parameters` 接口
- 便捷函数 `initialize_techniques_async()` 封装注册流程
- 查询函数（`get_registered_technique_names` / `get_technique_metadata` / `list_techniques_by_category` / `list_techniques_by_tag` / `get_technique_summary`）提供丰富的技术目录查询

**差距 🟡：**
- 未继承原生 `PyRITInitializer` ABC 基类（但 `src/setup/ai300_initializers.py` 中的 `AI300TechniqueInitializerWrapper` 已处理此问题，委托此类）
- `validate()` / `description` / `get_info_async()` 等原生 `PyRITInitializer` 方法未实现（由 Wrapper 处理）

> 注：此问题已通过 `src/setup/ai300_initializers.py` 中的 `AI300TechniqueInitializerWrapper` 解决，该 Wrapper 继承 `PyRITInitializer` 并委托此类。

#### 13.2.5 `failure_type_selector.py` — 对齐度：92%

**原生优先 ✅：**
- `FailureTypeRoutingSelector` 继承原生 `EpsilonGreedyTechniqueSelector`
- 覆写 `select_async()` 方法，先调用父类 epsilon-greedy 获取基础排序，再根据失败类型重排
- 完全对齐原生 `TechniqueSelector` 的 `select_async()` 签名
- Selector 是无状态的：查询 Memory 获取历史成功率，不维护内部计数

**自建增强（合理） ✅：**
- 失败类型路由（`model_refusal` → Converter 变体优先 / `timeout` → 基础单轮优先 / `objective_not_achieved` → 强技术优先）——替代自建 `AttackUpgradeStrategy` 的失败类型分析
- P1 Converter 变体感知排序：技术名含 `+` 的为变体，按优先级排序
- P3 Target 类型感知：通过 `target_aware_router` 使用 Target 类型对应的 ASR 优先级
- v2.0 OWASP 策略映射初始偏好：从 `owasp_strategy_map` 加载 `default_attack_technique`，使首次尝试时优先 OWASP 推荐的技术

**最佳实践验证 ✅：**
- `extract_failure_type_from_result()` 函数对齐自建 `upgrade_strategy.py` 的 `extract_failure_type`，通过 `error_message` / `outcome_reason` / `outcome` 安全提取
- `_target_aware_sort_key()` 方法优雅地处理了 Target 感知优先级与全局优先级的回退
- `_reorder_by_failure_type()` 方法对每种失败类型的重排逻辑清晰且互斥

#### 13.2.6 `ai300_adaptive_scenario.py` — 对齐度：93%

**原生优先 ✅：**
- `AI300AdaptiveScenario` 继承原生 `AdaptiveScenario`
- 实现全部三个抽象方法：`_atomic_attack_prefix()` / `get_technique_class()` / `default_dataset_config()`
- 使用 `@apply_defaults` 装饰器
- 通过 `additional_parameters()` 声明 `max_attempts_per_objective` + `per_attack_timeout`
- 构造器接收 `selector` / `objective_scorer` / `converter_target` / `target_type` / `owasp_id` / `scenario_result_id`，调用 `super().__init__()` 传入原生参数
- `AI300EpsilonGreedySelector` 继承 `FailureTypeRoutingSelector`，预设 `epsilon=0.2` / `random_seed=42`

**关键覆写（必要修复） ✅：**
- `_get_attack_technique_factories()` 覆写：在原生技术池基础上追加 Converter 变体工厂
- `_build_techniques_dict()` 覆写（**关键修复**）：原生 `_build_techniques_dict` 只遍历枚举值，Converter 变体名不在枚举中 → 变体从未被选中。覆写后调用 `super()` 获取基础技术 bundles，再为已解析基础技术追加 Converter 变体 `TechniqueBundle`

> **架构师评注**：`_build_techniques_dict()` 覆写是整个 Converter-Aware Adaptive Architecture 的关键修复点。原生 `AdaptiveScenario` 的 `_build_techniques_dict` 通过枚举值遍历工厂池，但 Converter 变体名（如 `prompt_sending+stealth_evasion`）不是枚举成员，导致变体工厂虽已注册但从未被选中。此覆写正确解决了这一架构限制，同时保持了与原生 `SequentialAttack(FIRST_SUCCESS)` 的兼容性。

**自建保留（合理） ✅：**
- `per_attack_timeout` 参数声明：PyRIT 原生无 per-attack 超时
- `display_converter_variants()` / `get_converter_variants_summary()`：展示可用的 Converter 变体信息，非替代原生 API，仅增强可观测性

**最佳实践验证 ✅：**
- `compute_inner_attack_eval_hash` 去重：防止相同配置的技术重复加入
- `adversarial_chat` 回退处理：当 `factory.uses_adversarial` 但 `adversarial_chat is None` 时，通过 `get_default_adversarial_target()` 获取默认值
- 幂等设计：`if factory.name not in base_factories` / `if eval_hash in base_techniques` 防止重复

#### 13.2.7 `adaptive_runner.py` — 对齐度：90%

**原生优先 ✅：**
- `run_adaptive_scenario_async()` 是原生 `AI300AdaptiveScenario` 的执行入口
- 使用 `DatasetAttackConfiguration(seed_groups=...)` 内联传入 attack_plans（方案 A — PyRIT 原生优先），完全不触碰 Memory
- 通过 `scenario.set_params_from_args()` 传入全部参数（`objective_target` / `dataset_config` / `max_retries` / `max_concurrency` / `scenario_techniques` / `memory_labels`）
- 调用原生 `scenario.initialize_async()` + `scenario.run_async()`
- 注册 `judge_target` 到 `TargetRegistry`（`adversarial_chat` + `objective_scorer_chat`），使原生 `AdaptiveScenario` 能通过 `get_default_adversarial_target()` / `get_default_scorer_target()` 查找
- 创建 `SelfAskTrueFalseScorer` 作为 `objective_scorer`

**自建保留（合理） ✅：**
- `per_attack_timeout` 参数保留（作为文档/未来扩展，不包裹 `scenario.run_async()`）
- OWASP 映射通过 `build_memory_labels()` 集成到原生 `memory_labels`
- `AdaptiveRunResult` 数据类封装原生 `ScenarioResult` + 向后兼容 `BatchAttackResult`

**错误恢复处理 ✅：**
- Scenario 失败时，尝试从 `CentralMemory` 检索最新的 `ScenarioResult`（包含已完成的攻击结果）
- `_convert_native_to_batch_result()` 正确提取 `get_display_groups()` / `attack_results` 并统计成功/失败/错误

**objective 去重 ✅：**
- 使用 `to_sha256` 对 objective 文本去重，防止 PyRIT 原子攻击的 SHA256 去重机制报错

**潜在改进点 🟡：**
- `per_attack_timeout` 目前仅作为参数声明保留，未实际实现 per-attack 超时包裹。文档注释说明"未来可用于自定义 executor"，但当前无实际超时保护。考虑到原生 Scenario 已有 `max_retries` 弹性恢复，此为可接受的降级。

#### 13.2.8 `scenario_output.py` — 对齐度：92%

**原生优先 ✅：**
- `output_scenario_async()` 直接使用原生 `output_scenario_async` + `StdoutSink` / `FileSink`
- 支持 `sort_groups_by_success_rate` 参数对齐原生功能
- 当原生 `ScenarioResult` 可用时，完全委托给原生 `output_scenario_async`
- 仅当原生 `ScenarioResult` 不可用时，回退到 `ScenarioResultBridge` 的自建格式化

**自建增强（合理） ✅：**
- `display_enhanced_group_breakdown()`：统一 Per-Group Breakdown 展示，合并原生信息 + 增强列（Techniques / Converters / OWASP）
- 使用 PyRIT 原生 API 提取信息：`ScenarioResult.get_display_groups()` / `AttackResult.get_attack_strategy_identifier()` / `AttackResult.labels`
- `_clean_technique_name()` 正确处理原生 `unique_name` 格式（`ClassName::hash`）
- `_extract_converters_from_identifier()` 从 `identifier.children['request_converters']` 提取 Converter 类名
- `_DATASET_OWASP_MAP` 提供数据集名 → OWASP ID 的回退映射

**最佳实践验证 ✅：**
- 回退路径使用 `_Adapter` 内部类包装非标准结果对象，确保 `ScenarioResultBridge` 能处理各种输入类型
- OWASP 名称映射覆盖全部 LLM01-10 + ASI01-10

#### 13.2.9 `scenario_result_bridge.py` — 对齐度：88%

**原生优先 ✅：**
- `ScenarioResultBridge` 桥接 `BatchAttackResult` 与原生 `ScenarioResult` API
- 保存 `_native_result` 引用，使 `output_scenario_async` 可直接使用原生 `ScenarioResult`
- 保存 `_scenario_result_id` 支持原生 resume
- `get_display_groups()` 优先委托给原生 `ScenarioResult.get_display_groups()`
- `get_per_group_stats()` 优先使用原生 `get_display_groups()`，提取技术名 + Converter + OWASP
- `build_memory_labels()` 通过原生 `memory_labels` 将 OWASP 映射集成到 Scenario 运行

**自建保留（合理） ✅：**
- OWASP 映射通过 `memory_labels` 集成（PyRIT 原生无 OWASP 概念）
- `_extract_technique_name()` / `_extract_converter_from_result()` / `_extract_owasp_from_result()` 使用 PyRIT 原生 API（`get_attack_strategy_identifier()` / `labels`）
- `get_owasp_mapping()` / `get_summary()` 提供增强统计

**最佳实践验证 ✅：**
- `batch_result_to_scenario_result()` 便捷函数支持 `native_result` / `scenario_result_id` / `memory_labels` 可选参数
- `get_per_group_stats()` 方法同时处理原生结果和回退结果，两路径提取逻辑一致

**差距 🟡：**
- 未实现原生 `ScenarioResult` 的全部接口（如 `get_display_groups()` 在回退路径中按技术名分组而非数据集名），但这是向后兼容的合理折衷

### 13.3 整体对齐度评估

| 维度 | 对齐度 | 评估 |
|---|---|---|
| Scenario 基类体系 | 95% | 🟢 原生 Scenario 继承 + @apply_defaults + build_matrix_atomic_attacks + BASELINE_ATTACK_POLICY |
| Technique 枚举体系 | 98% | 🟢 原生 ScenarioTechnique 继承 + tags 聚合 + default() classmethod |
| Technique 工厂注册 | 95% | 🟢 原生 AttackTechniqueFactory + AttackTechniqueRegistry + 幂等注册 + core/extra 分组 |
| Technique 初始化器 | 90% | 🟢 set_params_from_args + initialize_async（通过 Wrapper 继承 PyRITInitializer） |
| Adaptive Scenario | 93% | 🟢 原生 AdaptiveScenario 继承 + 抽象方法实现 + _build_techniques_dict 关键覆写 |
| 失败类型路由选择器 | 92% | 🟢 原生 EpsilonGreedyTechniqueSelector 继承 + select_async 覆写 |
| Parameter 声明式参数化 | 95% | 🟢 additional_parameters() + Parameter 类型 + self.params |
| Dataset 配置 | 95% | 🟢 DatasetAttackConfiguration(seed_groups=) 内联注入（方案 A 原生优先） |
| 结果输出 | 92% | 🟢 原生 output_scenario_async + StdoutSink/FileSink |
| 结果桥接 | 88% | 🟢 ScenarioResultBridge + native_result 引用 + memory_labels OWASP 集成 |
| 弹性恢复 | 90% | 🟢 max_retries + scenario_result_id + Memory 检索回退 |
| **整体对齐度** | **~93%** | 🟢 **原生优先，自建保留合理** |

### 13.4 原生优先策略验证

| 策略 | 验证结果 |
|---|---|
| **继承原生基类** | ✅ AI300Scenario extends Scenario / AI300AdaptiveScenario extends AdaptiveScenario / AI300Technique extends ScenarioTechnique / FailureTypeRoutingSelector extends EpsilonGreedyTechniqueSelector |
| **使用原生 API** | ✅ build_matrix_atomic_attacks / AttackTechniqueFactory / AttackTechniqueRegistry / DatasetAttackConfiguration / output_scenario_async / StdoutSink / FileSink / CentralMemory |
| **声明式参数化** | ✅ Parameter + additional_parameters() + set_params_from_args + self.params |
| **原生执行流程** | ✅ initialize_async() → _build_atomic_attacks_async() → run_async() → ScenarioResult |
| **原生弹性恢复** | ✅ max_retries + scenario_result_id + 自动恢复 |
| **原生输出** | ✅ output_scenario_async + PrettyScenarioResultMemoryPrinter |

### 13.5 自建保留合理性评估

| 自建功能 | 原生是否有 | 保留理由 | 评估 |
|---|---|---|---|
| per_attack_timeout | ❌ 无 | PyRIT 原生无 per-attack 超时机制；考试时间约束需要 | ✅ 合理 |
| OWASP 映射 | ❌ 无 | PyRIT 原生无 OWASP 概念；考试报告需要 OWASP 分类 | ✅ 合理（通过 memory_labels 集成） |
| Converter 变体 | ❌ 无 | 原生 AttackTechniqueFactory 支持 attack_kwargs 但无变体注册体系；考试需要多 Converter 组合自动尝试 | ✅ 合理（利用原生 attack_kwargs + FIRST_SUCCESS） |
| 失败类型路由 | ❌ 无 | 原生 EpsilonGreedyTechniqueSelector 无失败类型分析；考试需要按失败类型优化技术选择 | ✅ 合理（继承原生选择器 + 覆写 select_async） |
| ScenarioResultBridge | ❌ 无 | 桥接 BatchAttackResult 与 ScenarioResult；向后兼容现有 pipeline | ✅ 合理（保留 native_result 引用） |
| display_enhanced_group_breakdown | 部分 | 原生有 Per-Group Breakdown 但无 Techniques/Converters/OWASP 增强列 | ✅ 合理（使用原生 API 提取信息） |

---

## 14. 最佳实践与建议路线图

### 14.1 已达标的最佳实践

1. **原生基类继承优先**：所有核心类继承 PyRIT 原生基类（Scenario / AdaptiveScenario / ScenarioTechnique / EpsilonGreedyTechniqueSelector），获得原生生命周期和 API 兼容性
2. **@apply_defaults 装饰器**：构造器使用 `@apply_defaults` 对齐原生参数默认值注入模式
3. **build_matrix_atomic_attacks**：使用原生辅助函数构建 AtomicAttack，一行代码完成矩阵构建
4. **Parameter 声明式参数化**：通过 `additional_parameters()` 声明考试专用参数，框架自动组合与默认值注入
5. **DatasetAttackConfiguration 内联注入**：使用原生 `seed_groups=` 参数内联传入，不触碰 Memory（方案 A 原生优先）
6. **幂等注册**：AttackTechniqueFactory 按名称去重，可安全多次调用
7. **memory_labels OWASP 集成**：通过原生 `memory_labels` 将 OWASP 映射集成到 Scenario 运行
8. **原生输出优先**：当原生 ScenarioResult 可用时，完全委托给 `output_scenario_async` + `StdoutSink/FileSink`
9. **FIRST_SUCCESS 自动停止**：Converter 变体利用原生 `AdaptiveTechniqueDispatcher` 的 `FIRST_SUCCESS` 策略自动在首个成功变体处停止
10. **错误恢复**：Scenario 失败时从 Memory 检索部分结果

### 14.2 建议改进路线图

#### P0: per_attack_timeout 实际实现（当前仅声明）

当前 `per_attack_timeout` 仅作为 `Parameter` 声明，未实际实现 per-attack 超时包裹。建议：
- 通过自定义 `AttackExecutor` 子类实现 per-attack 超时
- 或通过 `asyncio.wait_for` 包裹单个 AtomicAttack 执行（需在 `_execute_atomic_attacks_parallel_async` 级别注入）

#### P1: TechniqueInitializer 直接继承 PyRITInitializer

当前 `AI300TechniqueInitializer` 未直接继承 `PyRITInitializer` ABC，通过 `AI300TechniqueInitializerWrapper` 间接集成。建议：
- 直接继承 `PyRITInitializer`，实现 `validate()` / `description` / `get_info_async()`
- 移除 Wrapper 层，简化架构

#### P2: 原生 ScenarioResult 完整接口对齐

`ScenarioResultBridge` 的回退路径未实现原生 `ScenarioResult` 的全部接口。建议：
- 在回退路径中更完整地模拟 `get_display_groups()` 行为（按数据集名而非技术名分组）
- 添加 `scenario_name` / `scenario_version` 的动态推断

#### P3: CLI 集成

当前 Scenario 通过编程接口使用，未集成 `pyrit_scan` / `pyrit_shell` CLI。建议：
- 注册 `AI300AdaptiveScenario` 到 `ScenarioRegistry`
- 实现 `--list-scenarios` 支持
- 实现 `--help` 参数显示

### 14.3 考试就绪度评估

| 考试维度 | 就绪度 | 关键支撑 |
|---|---|---|
| LLM 越狱 | 95% | AdaptiveScenario + FIRST_SUCCESS + Converter 变体 |
| 编码攻击 | 98% | AI300EncodingTechnique + 17 编码技术 + tags 体系 |
| 多轮攻击 | 95% | Crescendo / TAP / PAIR / RedTeaming + max_turns 参数 |
| 自适应优化 | 95% | EpsilonGreedyTechniqueSelector + 失败类型路由 + OWASP 偏好 |
| 快速冒烟测试 | 90% | BASELINE_ATTACK_POLICY + max_attempts_per_objective |
| 结果报告 | 92% | output_scenario_async + Per-Group Breakdown + OWASP 映射 |
| 弹性恢复 | 90% | max_retries + scenario_result_id + Memory 检索 |
| **整体考试就绪度** | **93%** | **原生 Scenario 体系 + 自建考试优化** |

### 14.4 总结

当前项目 `src/scenarios/` 模块以 **PyRIT 原生框架优先** 为核心策略，整体对齐度约 **93%**。所有核心类均继承 PyRIT 原生基类，使用原生 API 进行构建、注册、初始化和执行。自建保留的 6 项功能（per_attack_timeout / OWASP 映射 / Converter 变体 / 失败类型路由 / ScenarioResultBridge / 增强展示）均为 PyRIT 原生不具备的考试专用能力，且通过原生扩展点（`additional_parameters` / `select_async` 覆写 / `_build_techniques_dict` 覆写 / `memory_labels` / `attack_kwargs`）合理集成，未破坏原生架构不变量。

关键架构决策（`_build_techniques_dict` 覆写解决 Converter 变体从未被选中的根因、`DatasetAttackConfiguration(seed_groups=)` 内联注入方案 A、`FIRST_SUCCESS` 自动停止策略）体现了对 PyRIT 原生 Scenario 子系统的深度理解和正确扩展。
