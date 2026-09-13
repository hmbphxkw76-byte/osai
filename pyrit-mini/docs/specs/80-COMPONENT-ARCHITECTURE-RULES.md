# 80 — 组件化架构规则（Component Architecture Rules）

> **文档层级**：L1（架构规则补充）
> **效力**：定义组件化架构的目录组织、命名、注册与归属规则。任何涉及组件的代码变更必须能在本文件"落点"。
> **版本**：v2.0（2026-09-12 REV-02：与 `config/components/*.yaml` 严格对齐——引入双命名空间规则、修正组件状态登记表、新增组件 Checkpoint 改为注册表驱动）
> **版本史**：`git log -- docs/specs/80-COMPONENT-ARCHITECTURE-RULES.md`
> **读者**：新增/修改组件时**必读**；评审涉及组件的 diff 时**必读**。

---

## 第一章：设计哲学 [sid:80-ch1]

**Hub-and-Spoke（中心辐射）**：

```
              ┌──────────────────────────────┐
              │  框架层（Hub）                │
              │  core/ arm/ assess/ report/  │
              │  + core/registry.py（SSOT）   │
              └───────────────┬──────────────┘
                              │ 注册表驱动，禁止硬编码组件名
        ┌─────────┬───────────┼───────────┬──────────┐
        ▼         ▼           ▼           ▼          ▼
    mcp/      a2a/        rag/       session/    web_api/   ...（Spoke）
```

| 原则 | 含义 |
|------|------|
| 框架层稳定 | `core/ arm/ assess/ report/` 提供通用调度，**不随组件增加而膨胀** |
| 组件层独立 | 每个组件拥有独立的 `strike/<id>/` 与 `recon/<id>/` 实现目录 |
| 注册式扩展 | 新组件通过 `config/components/*.yaml` 声明接入，**不改框架层代码**（开放-封闭，IA-7） |
| 数据流隔离 | 组件间只经 `PipelineContext` + 事件流交接，禁止直接 import（蓝图 2.2） |

> **反模式**：在 `core/phases/`、`strike/common/dispatcher.py` 中 `if component == "mcp": ...`。
> 这是 ADR-007 / R-EVENT-1 / REQ-153 明令禁止的硬编码组件名（guard BLOCKING）。

---

## 第二章：双命名空间（`id` vs `component_key`）—— 必读 [sid:80-ch2]

`core/registry.py` 同时维护两个键空间，**混用会导致运行时查不到组件**。这是本项目最容易踩的坑。

| 键 | 定义 | 消费 API | 约束 |
|----|------|---------|------|
| **`id`** | **文件/目录标识**。`mcp.yaml` → `mcp`；用于定位 `strike/<id>/`、`recon/<id>/` | `get(id)`、`names()`、`by_label()`、`for_seed_component()` | **必须等于 YAML 文件名 stem** |
| **`component_key`** | **语义键**（运行时调度主键）。形如 `mcp_tool_poisoning`，与种子 `suitable_for`、评分 rubric 名、报告章节对齐 | `keys()`、`spec(key)`、`specs()`、`by_neighbor(key)`、`validate_wiring()` | **全局唯一**，与 `labels` 至少有一个交集 |

### 2.1 当前实际映射（2026-09-12 快照）

| YAML 文件 | `id` | `component_key` | `id == stem`? |
|-----------|------|-----------------|---------------|
| `a2a.yaml` | `a2a` | `a2a_agent_integrity` | ✅ |
| `audit.yaml` | `audit` | `audit_evasion` | ✅ |
| `embedding.yaml` | `embedding` | `embedding` | ✅ |
| `gateway.yaml` | `gateway` | `llm_gateway` | ✅ |
| `mcp.yaml` | `mcp` | `mcp_tool_poisoning` | ✅ |
| `model.yaml` | `model` | `model_behavior_shift` | ✅ |
| `rag.yaml` | `rag` | `rag_pipeline` | ✅ |
| `session.yaml` | `memory_session_tenant` | `session_memory` | ❌ **漂移**（stem 为 `session`） |
| `supply_chain.yaml` | `supply_chain` | `supply_chain` | ✅ |
| `web_api.yaml` | `web_infra` | `web_api` | ❌ **漂移**（stem 为 `web_api`） |

> ⚠️ `session.yaml` / `web_api.yaml` 的 `id` 不等于文件名 stem，违反 2.1 约束。已登记 backlog（BL-024）。
> **修正前禁止**编写依赖 `id == stem` 的代码；需要用目录标识时显式读 `spec.id`。

### 2.2 权威读取方式（禁止从文档抄写清单）

```bash
# component_key 列表（运行时调度主键）
python -c "from core.registry import get_registry; print(get_registry().keys())"
# id 列表（文件/目录标识）
python -c "from core.registry import get_registry; print(get_registry().names())"
# 接线完整性（recon/seeds/assess/report 落点是否真实存在）
python -c "from core.registry import get_registry; print(get_registry().validate_wiring() or 'OK')"
```

---

## 第三章：目录组织规则 [sid:80-ch3]

### 3.1 攻击实现（Spoke）

```
strike/
├── <id>/            # 组件专属攻击实现（mcp/ a2a/ rag/ session/ web_api/ ...）
│   ├── __init__.py  # 必须声明 __all__
│   └── ...
├── injection/       # 跨组件的注入类实现
├── evasion/         # 跨组件的绕过类实现
└── common/          # 组件间共享工具（唯一允许的共享代码位）
```

**S-DIR-1**：`strike/` 根目录**禁止**放置攻击实现代码。
**S-DIR-2**：每个组件子目录必须含 `__init__.py` 并声明 `__all__`。
**S-DIR-3**：`recon/` 适用同规则（`recon/<id>/`）；框架层侦察（`fingerprint.py`、`stealth_timing.py`、`common/`）留在 `recon/` 根。

### 3.2 框架层（Hub）

**F-DIR-1**：框架层通过 `_REGISTRY` 字典 + `register_*()` / `get_*()` 支持组件扩展。
**F-DIR-2**：框架层**禁止**直接 `import` 组件实现，必须运行时注册动态加载。

| 框架层调度器 | 职责 |
|-------------|------|
| `core/seed_router.py` | 按 `attack_vector` + `suitable_for` 路由种子到 Converter 链 |
| `assess/component_router.py` | 按组件归属路由评分逻辑 |
| `assess/component_scorers.py` | 组件 T0 零 token 启发式 + rubric 选择 |
| `report/component_reports.py` | 组件专属报告章节 |
| `report/component_poc.py` | 组件专属 PoC 生成 |

### 3.3 种子库

```
data/seeds/
├── _core/                       # 通用核心种子
├── _attack_surface/
│   └── T{ID}_{COMPONENT}_{DESCRIPTOR}/    # 组件种子集
├── _encoding_evasion/ _experimental/ _multilingual/
```

**D-DIR-1**：组件种子集目录命名 `T{ID}_{COMPONENT}_{DESCRIPTOR}/`（如 `T1_ASI02_mcp_full_surface/`）。
**D-DIR-2**：种子文件扩展名 `.prompt`，frontmatter 声明归属：

```markdown
---
attack_vector: mcp_tool_registration
suitable_for: [mcp_tool_poisoning, a2a_agent_integrity]   # 必须是 component_key，不是 id
category: mcp
owasp_id: ASI02
---

{ATTACK_PROMPT_CONTENT}
```

> **C-NAME-2**：`suitable_for` 的取值必须等于 **`component_key`**（不是 `id`）。`for_seed_component()` 按此匹配。

---

## 第四章：命名规范 [sid:80-ch4]

| 场景 | 规则 | 示例 |
|------|------|------|
| 组件专用攻击文件 | `{action}_{id}.py` | `attack_mcp.py` |
| 组件编排器 | `{id}_orchestrator.py` | `web_orchestrator.py` |
| 组件侦察实现 | `{id}_scanner.py` | `mcp_scanner.py` |
| 框架层调度器 | `component_{capability}.py` | `component_scorers.py` |
| 桥梁模块 | `_{capability}_bridge.py` | `_component_bridge.py` |
| 组件测试 | `test_{id}_*.py` | `test_mcp_attack.py` |

**C-NAME-1（修订）**：`component_key` 与 `strike/<id>/`、`recon/<id>/` **语义一致**；`id` 与目录名**字面一致**。

---

## 第五章：组件归属与传递 [sid:80-ch5]

### 5.1 归属写入（CB-1）

`core/phases/_component_bridge.py` 是 `component_type` / 组件归属的**唯一写者**，在攻击结果上盖章：

```python
attack_result.setdefault("metadata", {})["component_type"] = component_key
```

**CB-1**：禁止其他模块直接写该字段。
**CB-2**：下游消费者统一读 `metadata.get("component_type")`。

> **历史缺陷（已修）**：`VulnerabilityEvidence` 曾缺 `metadata` 字段，导致 `getattr(ev, "metadata", {})` 恒空 → 组件专属报告永不生成。新增任何证据结构时，必须自测 `metadata` 端到端可读。

### 5.2 多组件归属（IC-1，v4.0）

企业目标是**组合体**，单一标签不足表达：

- 目标态：归属为 `component_labels: list[str]` + `label_confidence: dict[str, float]`
- 迁移期：单值 `component_type` 保留为**兼容派生视图**，W5 删除
- **IC-3**：一个 finding 允许归属多个组件

迁移未完成前，新增代码**必须**同时能读单值与多值（用 `getattr` + 兜底），不得假设只有一种形态。

---

## 第六章：新增组件 Checklist [sid:80-ch6]

> **顺序不可颠倒**：声明先行（YAML），实现其后。没有 YAML 声明的组件 = 不存在。

### 6.1 声明（SSOT，必做）

- [ ] 新建 `config/components/<id>.yaml`，`<id>` 与文件名 stem 一致
- [ ] 填写新契约字段：`labels` / `detect.signals` / `detect.min_confidence` / `recon` / `seeds` / `scorer` / `cleanup`（字段定义见 `config/components/README.md`）
- [ ] `component_key` 全局唯一，与 `labels` 有交集
- [ ] **不写** W0 遗留字段（`component_key` 除外）：`seed_sets` / `converter_vectors` / `strike_modules` / `report_builder` 等为兼容层，**只减不增**

### 6.2 实现

- [ ] `strike/<id>/` + `recon/<id>/` 建立，含 `__init__.py` 与 `__all__`
- [ ] 种子集落在 `data/seeds/_attack_surface/T{ID}_{COMPONENT}_{DESC}/`，frontmatter `suitable_for` 用 `component_key`
- [ ] `assess/component_scorers.py` 注册 T0 检测函数 + rubric
- [ ] `report/component_reports.py` 注册章节构建器；`report/component_poc.py` 注册 PoC 模板

### 6.3 验证（缺一不可）

```bash
python -c "from core.registry import get_registry; r=get_registry(); print(r.spec('<component_key>')); print(r.validate_wiring() or 'wiring OK')"
python -m tools.guard
python tools/architecture_validator.py full
python -m pytest tests/ -q
python main.py --dry-run --max-seeds 1
```

- [ ] 上述命令全部通过；`validate_wiring()` 无 blocking 错误
- [ ] 未改动任何框架层调度逻辑（IA-7）
- [ ] 测试 `tests/test_<id>_*.py` 存在且通过

> 完整门禁见 `specs/README.md` §2。

---

## 第七章：架构不变量 [sid:80-ch7]

| # | 不变量 | 依据 |
|---|--------|------|
| IA-1 | `strike/` 根目录不含攻击实现（仅 `__init__.py` 与文档） | S-DIR-1 |
| IA-2 | 框架层不含组件专属攻击实现 | F-DIR-1 |
| IA-3 | 组件类型键由 `core/registry.py` 统一管理，**禁止任何第二处硬编码映射** | C-NAME-1 / ADR-007 |
| IA-4 | 组件归属由 `_component_bridge` 统一写入 | CB-1 |
| IA-5 | 种子 `suitable_for` 取值必须等于 `component_key` | C-NAME-2 |
| IA-6 | 未知组件返回 `None` / 默认实现，**禁止崩溃** | 调度器兜底 |
| IA-7 | 新组件经注册扩展，**不改框架层调度逻辑**（开放-封闭） | 第四章 / 第六章 |
| IA-8 | `id` 必须等于 YAML 文件名 stem | 第二章 |

---

## 第八章：组件接线状态（读代码，不读表） [sid:80-ch8]

> 状态随时变化。**禁止**在本文件手工维护状态表（文档纪律 D4）。

```bash
python -c "from core.registry import get_registry; r=get_registry(); [print(f'{s.component_key:<28} id={s.id:<20} recon={len(s.recon_modules)} seeds={len(s.seeds)} rubric={s.rubric}') for s in r.specs()]"
python -c "from core.registry import get_registry; print(get_registry().validate_wiring() or 'ALL WIRING OK')"
```

**判定**：`validate_wiring()` 返回空 = 全部组件接线完整。非空则按 `layer` 字段定位缺失落点（recon / seeds / assess / report / schema）。

> **注**：`supply_chain` 为侦察级组件，不计入 ASR 分母（蓝图 13.4 横切说明）。
