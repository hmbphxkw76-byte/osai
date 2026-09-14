# 57 — 攻击技术蓝图与扩展注册表（Technique Blueprint & Extension Registry）

> **父索引**：`docs/specs/README.md` [sid:readme-ch1]（文档地图）/ `55-ATTACK-GAP-CLOSURE.md` [sid:55-ch1]（缺口登记处，本设计为"技术组合层"增强，非攻击面缺口）。
> **文档层级**：配套（**设计提案，非规约**）。本文件只描述设计与落点，不定义任何规则；规则以 `40-GUARDRAILS.md`、蓝图 `10-ARCHITECTURE.md` 为准。
> **版本**：v1.0（2026-09-14 新建；本文件为"统一最优组合选择器 + 插件式扩展注册表"的设计规格）
> **版本史**：`git log -- docs/specs/57-TECHNIQUE-BLUEPRINT.md`
> **作者**：AI Red Team
> **状态**：⚡ 实施中（REQ-172 已登记；registry + blueprint 已落地，各对象 `converter_presets` 补齐中）；实现前须在 `20-REQUIREMENTS.md` 登记对应 REQ（见 [sid:57-scope]）。

> **本文件解决的问题**：pyrit-mini 已是"PyRIT 原生底层 + 对象轴定制"的分层架构，但 **seeds / converters / strike / scores 四个轴的选择逻辑分散在四套独立硬编码机制中**，`config/components/*.yaml` 的 `converter_vectors` 字段当前**未被消费**，且新增 converter / strike 策略 / scorer 都必须改散落各处的硬编码表。本设计给出：① 统一最优组合选择器（消费组件 YAML 为四轴单源真值，按实测 ASR 重排）；② 插件式扩展注册表（`@register_*` 装饰器，新增 primitive 即插即用）。

---

## 1. 背景与目标 [sid:57-ch1]

### 1.1 现状（已具备）

| 层 | 现有实现 | 证据 |
|----|----------|------|
| PyRIT 原生底层 | converters 全封装 `pyrit` 原生 `Converter`；strike 策略映射到 `pyrit.executor.attack.*` | `arm/converter_chains.py`、`strike/common/progressive_strike.py` 的 `STRATEGY_CLASS_MAP` |
| 对象轴定制（声明 SSOT） | 每对象一份 `config/components/<obj>.yaml`，集中声明 `seed_sets` / `preferred_attack_class` / `strike_modules` / `assess.t0_check` | `config/components/mcp.yaml`、`core/registry.py` 的 `ComponentRegistry` |
| 运行时调度 | `ComponentRegistry` 加载 YAML，运行时查表、静态 `validate_wiring` 反向校验 | `core/registry.py` |

### 1.2 目标

1. **四轴单源真值**：让 `config/components/<obj>.yaml` 成为该对象 "seeds + converters + strike + scorers" 默认最优组合的**唯一声明处**；选择器不再各自硬编码。
2. **默认优先高成功率组合**：组合按"最佳实践候选集 + 实测 ASR 重排"产出（宪法 C2 ASR 至上）。
3. **插件式扩展**：新增 seed / converter / strike 策略 / scorer 走"一处声明即生效"，不再改散落硬编码表。

### 1.3 非目标（明确边界）

- 不改 PyRIT 原生 attack/converter 的底层实现（R-NATIVE-1）。
- 不重写 `progressive_strike` 的渐进升级状态机，只在 dispatch 层接注册表。
- 不在此文档内实现代码（仅设计 + 落点）；代码实现见后续任务。

---

## 2. 现状差距分析 [sid:57-ch2]

| 轴 | 当前选择机制 | 问题 |
|----|--------------|------|
| seeds | `core/seed_loader.py` 按 `COMPONENT_SEED_DIRS` / legacy map 加载 | 与组件 YAML 的 `seed_sets` 是**两套**目录声明，未统一消费 YAML |
| converters | `arm/converter_presets.py` 的 `l5_optimal` 按 `target_type` 硬编码候选列表；`arm/<obj>/preset.py` 仅 pin `target_type` | 组件 YAML 的 `converter_vectors` **从不消费**；新增 converter 须改 `converter_chains.py` + `converter_presets.py` + `preset.py` |
| strike | `strike/_strategies.yaml` 的 `TARGET_STRATEGY_MAP`（已按 target 声明，较好） | 新增策略须改 `progressive_strike.py` 的 `_execute_phase` if/elif 链 |
| scores | `assess/component_scorers.py` 的 `_COMPONENT_T0_FUNCTIONS` 硬编码列表 | 新增 scorer 须改此列表 + facade 导入 |

**核心缺口**：四轴无统一"组合"概念；`converter_vectors` 死键；扩展点分散。

---

## 3. 设计 A：统一最优组合选择器 [sid:57-blueprint]

### 3.1 新增模块 `core/technique_blueprint.py`

职责：给定对象键 + 目标指纹，产出该对象的 **`TechniqueBlueprint`**（四轴已按 ASR 重排的最优组合）。只读查表 + 重排，**不含任何攻击执行逻辑**（对齐 `core/registry.py` 的"零攻击逻辑"原则）。

```python
# core/technique_blueprint.py（设计骨架，非实现）

@dataclass
class TechniqueBlueprint:
    object_key: str
    seed_files: list[Path]          # 已按 ASR 重排（若有实测）
    converters: list[Any]           # 已 ASR-prune + 重排
    strike_strategies: list[tuple[int, str, int]]  # 来自 TARGET_STRATEGY_MAP
    t0_scorer: Callable | None      # 来自 spec.assess.t0_check（经 SCORER_REGISTRY 解析）

def build_optimal_blueprint(object_key: str, *, fingerprint: dict | None = None) -> TechniqueBlueprint:
    """消费 core.registry.ComponentRegistry 声明 + 实测 ASR 数据，产出最优组合。"""
    spec = get_registry().spec(object_key) or get_registry().spec(component_for_object(object_key))
    # 1. seeds: 从 spec.seed_sets 解析目录 -> 文件列表；若有 seed 级 ASR 则重排
    # 2. converters: 从 spec.converter_presets（见 §3.2）解析 -> 经 CONVERTER_REGISTRY 实例化
    #    -> 复用 converter_selector._prune_low_asr_converters 做 ASR prune/rerank
    #    空列表时回退 l5_optimal(target_type=...)（W0 零回归）
    # 3. strike: get_strategies_for_target(object_key)（现有逻辑，不变）
    # 4. scores: SCORER_REGISTRY[spec.assess.t0_check 的 component_type]（见 §4.3）
```

### 3.2 组件 YAML 新增字段 `converter_presets`

在 `config/components/<obj>.yaml` 增加**高成功率 converter 组合**的显式声明（真实 PyRIT converter 类名），作为该对象的"最佳实践默认组合"：

```yaml
# config/components/mcp.yaml（增量，非重写）
converter_presets:                # 高成功率组合（按优先级降序；空 -> 回退 l5_optimal）
  - DecompositionConverter        # ASR 40-60%（arXiv:2402.14266）
  - PolicyPuppetryConverter        # ASR 30-40%
  - CodeChameleonConverter         # ASR 35-45%
  - PersuasionConverter:authority_endorsement  # ASR 38.4%（arXiv:2402.19181）
converter_vectors:                # 保留为高层语义标签（描述性，不驱动选择）
  - mcp_tool_registration
  - mcp_message_injection
  - mcp_schema_poisoning
```

- `converter_presets` 缺省/为空 → 选择器回退到现有 `l5_optimal` 行为（**零回归**，对齐 W0）。
- 解析：`converter_presets` 中每个名字经 `CONVERTER_REGISTRY`（§4.1）解析为实例；名字须与注册表 key 一致，未知名 → 日志 WARNING 并跳过（IA-6，不崩溃）。

### 3.3 ASR 重排来源（不变复用）

- converter 级 ASR：`arm/converter_selector.py` 已有的 `_prune_low_asr_converters` / `asr_history.json` 的 `converter_asr` —— 直接复用，不新建。
- strike 级：沿用 `TARGET_STRATEGY_MAP`（已按对象声明 + `priority`）。
- seed 级：本期先用 YAML 声明顺序；后续在 `asr_history.json` 增加 `seed_asr`（按 `suitable_for`/目录）做重排，列为后续项（§9）。

---

## 4. 设计 B：插件式扩展注册表 [sid:57-registry]

### 4.1 新增模块 `core/technique_registry.py`

集中持有三类注册表与装饰器，**替代**散落各处的硬编码列表。该模块零攻击逻辑，仅反射查表（对齐 `core/registry.py`）。

```python
# core/technique_registry.py（设计骨架，非实现）

CONVERTER_REGISTRY: dict[str, Callable] = {}     # name -> 构造器(converter_target)->Converter
STRATEGY_REGISTRY: dict[str, type] = {}          # strategy_name -> PyRIT attack class
SCORER_REGISTRY: dict[str, Callable] = {}        # component_type -> t0 checker

def register_converter(name: str):
    def _(fn): CONVERTER_REGISTRY[name] = fn; return fn
    return _

def register_strategy(name: str, attack_cls: type):
    def _(cls): STRATEGY_REGISTRY[name] = attack_cls; return cls
    return _

def register_scorer(component_type: str):
    def _(fn): SCORER_REGISTRY[component_type] = fn; return fn
    return _
```

### 4.2 converter 自注册

`arm/converter_chains.py` 各构造器加 `@register_converter("DecompositionConverter")`；`arm/<obj>/preset.py` 的 `build_converters` 改为：优先读取 `spec.converter_presets` → 经 `CONVERTER_REGISTRY` 实例化（取代硬编码 `candidates.extend(...)`）。新增 converter = 一个 `@register_converter` + 组件 YAML 一行 `converter_presets`。

### 4.3 strike 策略自注册

`progressive_strike.py` 的 `_execute_phase` 改为经 `STRATEGY_REGISTRY` 派发（`name -> PyRIT class`），移除 `_execute_phase` 的 if/elif 长链；`STRATEGY_CLASS_MAP` 保持不变作为注册表的初始化种子。新增策略 = `@register_strategy("tap", TAPAttack)` + `_strategies.yaml` 一行 `phases`（无需改派发代码）。

### 4.4 scorer 自注册

`assess/<obj>/t0.py` 的 checker 加 `@register_scorer("mcp_tool_poisoning")`；`assess/component_scorers.py` 的 `get_t0_checker` 改为优先查 `SCORER_REGISTRY`，回退现有 `_COMPONENT_T0_FUNCTIONS`（W0 零回归）。新增 scorer = 新 `assess/<obj>/t0.py` + 一个装饰器。

### 4.5 seed 扩展（已灵活，无需改动）

新增 seed = 在 `data/seeds/<obj>/` 放 `.prompt` 文件即可（`core/seed_loader.py` 已按目录加载）；如需纳入默认组合，在组件 YAML 的 `seed_sets` 加一行目录。本期**不引入** seed 注册表（避免过度设计）。

---

## 5. 落点（文件变更清单） [sid:57-landing]

### 5.1 新增文件

| 文件 | 职责 | 规模上限（R-TOOLS-2） |
|------|------|----------------------|
| `core/technique_blueprint.py` | 统一最优组合选择器（只读查表 + ASR 重排） | ≤ 200 行 |
| `core/technique_registry.py` | 三类 `@register_*` 注册表 | ≤ 120 行 |
| `tests/test_technique_blueprint.py` | 蓝图产出 + 回退行为 | — |
| `tests/test_technique_registry.py` | 注册/派发/未知名降级 | — |

### 5.2 修改文件（均为定点替换，C5 最小变更）

| 文件 | 变更 |
|------|------|
| `config/components/mcp.yaml`（及后续 a2a/rag/...） | 增量加 `converter_presets` 字段 |
| `arm/converter_chains.py` | 各构造器加 `@register_converter` |
| `arm/converter_presets.py` | `l5_optimal` / `build_converter_map` 兼容 `converter_presets` 优先解析（空则原行为） |
| `arm/converter_selector.py` | `select_converters` / `_build_converter_config` 接 `build_optimal_blueprint` 的 converter 产出 |
| `arm/mcp/preset.py` | `build_converters` 改读组件 YAML `converter_presets` → `CONVERTER_REGISTRY` |
| `strike/common/progressive_strike.py` | `STRATEGY_CLASS_MAP` 初始化 `STRATEGY_REGISTRY`；`_execute_phase` 经注册表派发 |
| `assess/component_scorers.py` | `get_t0_checker` 优先查 `SCORER_REGISTRY` |
| `assess/mcp/t0.py`（及同类） | checker 加 `@register_scorer` |

### 5.3 接线校验扩展（可选）

`core/registry.py` 的 `validate_wiring` 可增量加 `converter_presets` 名字存在性校验（经 `CONVERTER_REGISTRY`），沿用现有 `WiringError` 模式；不强制本期内完成。

---

## 6. ASR 影响分析 [sid:57-asr]

**裁决问题：这个决定让 ASR 变高还是变低？**（README [sid:readme-ch0] 终极问题）

- **不降低 ASR**：所有选择器保留回退路径（W0 零回归）——`converter_presets` 为空回退 `l5_optimal`；`STRATEGY_REGISTRY` 未注册时回退 `STRATEGY_CLASS_MAP`；`SCORER_REGISTRY` 未命中回退现有硬编码表。默认行为与原实现逐字节等价。
- **倾向提升 ASR**：默认组合由组件 YAML 的 `converter_presets`（最佳实践候选集）显式声明 + 实测 `converter_asr` 重排，优先高成功率组合（C2 ASR 至上）；消除"全局 `_CONVERTER_PRIORITY_MAP` 对所有对象一刀切"的信息损失（此前 MCP 与 model 共用同一优先级表，未利用 MCP 专属高 ASR 组合）。
- **可验证**：实现后由 `tests/test_technique_blueprint.py` 断言"mcp 蓝图产出的 converter 集合 ⊆ l5_optimal(target_type=mcp_agent) 且按 ASR 降序"，并提供 dry-run 证据（门禁 `dry-run` 步，0 token）。

**结论**：ASR 不变或提升；无沉默降级（R-H1：无静默 fallback，回退路径显式可观测）。

---

## 7. 宪法 / 护栏合规 [sid:57-compliance]

| 条款 | 落点 |
|------|------|
| C3（SSOT） | 四轴默认组合唯一声明处收敛到 `config/components/<obj>.yaml`；编排层不再硬编码组件名（对齐 `core/registry.py` ADR-007） |
| C1 / R-NATIVE-1 | 底层仍 100% 用 PyRIT 原生 `Converter` / `Attack` 类，注册表只做查表不重写实现 |
| C2（ASR 至上） | 默认组合按实测 ASR 重排优先高成功率 |
| C5（最小变更） | 全部为定点替换 + 新增两个只读模块；回退路径保证零回归 |
| R-H3 / R-H1 | 无第二套 ASR 口径；回退显式可观测，不假装策略已运行 |
| D1 / D8（文档纪律） | 本文件章节锚点见 [sid:57-ch1]–[sid:57-scope]；规则不复制，只引用 `40`/`10` |
| 80（组件化规则） | 新增组件只需在其 YAML 加 `converter_presets` + 一个 `@register_*`；目录/命名遵循 `80-COMPONENT-ARCHITECTURE-RULES.md` |

---

## 8. 验收标准与测试 [sid:57-accept]

- [ ] `core/technique_blueprint.build_optimal_blueprint("mcp")` 产出非空 `converters` 且为 `l5_optimal(target_type="mcp_agent")` 的子集，按 `converter_asr` 降序（若有历史）。
- [ ] `config/components/mcp.yaml` 无 `converter_presets` 时，`build_optimal_blueprint` 回退到 `l5_optimal` 行为，结果与原实现一致（W0）。
- [ ] 新增一个 `@register_converter("DummyX")` + 在 `mcp.yaml` 加 `converter_presets: [DummyX]`，蓝图即包含该 converter，无需改 `converter_presets.py` / `preset.py`。
- [ ] `@register_strategy("tap", TAPAttack)` 后，`progressive_strike` 经注册表派发，无需改 `_execute_phase`。
- [ ] `@register_scorer("mcp_tool_poisoning")` 后，`get_t0_checker` 命中注册表。
- [ ] `python -m tools.gate --stage commit` 全绿（含 spec-lint / guard / architecture / ruff / dry-run）。
- [ ] `pytest tests/test_technique_blueprint.py tests/test_technique_registry.py` 通过。
- [ ] 未知 converter 名 / 未注册策略 → 显式 WARNING 降级，不崩溃（IA-6）。

---

## 9. 范围与后续 [sid:57-scope]

- **实现前置**：编码前须在 `20-REQUIREMENTS.md` 登记对应 REQ（如 `REQ-<n>`：统一技术组合选择器 + 扩展注册表），并在 `30-TASKS.md` 落任务规格（八步协议）。
- **后续项（非本期）**：
  1. `asr_history.json` 增加 `seed_asr`（按 `suitable_for`），让 seed 轴也参与 ASR 重排。
  2. 将 a2a / rag / session / model / web / embedding / agent / multimodal_upload 的 `converter_presets` 补齐（用户会话 2026-09-14 已落齐；memory 由 session 组件覆盖，gateway/web_api 复用同一组件键）。
  3. `validate_wiring` 增量校验 `converter_presets` 名字存在性（§5.3）。
- **跨模型审查**：本设计为"配套（非规约）"设计提案，不直接改动 L0–L4 规约；但其实现会改 `core/` 与 `arm/` 等代码，按 `60-CROSS-MODEL-VERIFICATION.md` 在合入前走 review-only 协议。
