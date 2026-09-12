# 80 — 组件化架构规则：目录组织与命名规范（Component Architecture Rules）

> **文档层级**：L1 / 五层规约金字塔第二层（架构规则补充）
> **效力**：定义 PyRIT-Mini 组件化架构的目录组织规则、文件命名规范、组件注册流程。任何涉及新组件或目录变更的代码必须在本文档"落点"。
> **读者**：实施组件化开发的 AI（必读）、评审 diff 的人工/AI。
> **版本**：v1.0（2026-09-11 REV-01：首次发布，固化组件化架构优化经验）

---

## 第一章：组件化架构概述

### 1.1 设计哲学

PyRIT-Mini 采用 **Hub-and-Spoke（中心辐射）** 组件化架构：

```
                    ┌──────────────────┐
                    │   Framework      │
                    │   (框架层)        │
                    │                  │
                    │  core/           │
                    │  assess/         │
                    │  report/         │
                    │  arm/            │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │   MCP    │  │   A2A    │  │  Model   │
        │ (spoke)  │  │ (spoke)  │  │ (spoke)  │
        └──────────┘  └──────────┘  └──────────┘
              │              │              │
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │   RAG    │  │ Session  │  │   Web    │
        │ (spoke)  │  │ (spoke)  │  │ (spoke)  │
        └──────────┘  └──────────┘  └──────────┘
```

**核心原则**：
1. **框架层稳定**：`core/`/`assess/`/`report/`/`arm/` 提供通用调度能力，不随组件增加而膨胀
2. **组件层独立**：每个 AI 核心组件（MCP/A2A/Model/RAG/Session/Web）拥有独立的攻击实现目录
3. **注册式扩展**：新组件通过注册机制接入框架，无需修改框架层代码（开放-封闭原则）
4. **数据流隔离**：组件间通过 `PipelineContext` 和 `component_type` 元数据交接，禁止直接 import

### 1.2 组件分类

| 组件类别 | 组件类型键 | 目录位置 | 职责 |
|---------|-----------|---------|------|
| MCP Server | `mcp_tool_poisoning` | `strike/mcp/`, `recon/mcp/` | 工具注册操纵、消息注入、Schema 投毒 |
| A2A Protocol | `a2a_agent_integrity` | `strike/a2a/`, `recon/a2a/` | 跨代理注入、身份伪造、生命周期攻击 |
| Model Output | `model_behavior_shift` | `strike/injection/`, `strike/evasion/` | 提示注入、越狱、后门触发、过滤绕过 |
| RAG Pipeline | `rag_pipeline` | `strike/rag/`（预留） | 检索污染、上下文注入、向量库投毒 |
| Session/Memory | `session_memory` | `strike/session/`（预留） | 上下文泄漏、记忆投毒、会话边界违反 |
| Web/API | `web_api` | `strike/web/` | 认证绕过、限速规避、请求走私、网关绕过 |

---

## 第二章：目录组织规则

### 2.1 攻击实现目录（Component-Specific）

攻击实现代码必须按组件拆分到独立子目录：

```
strike/
├── mcp/              # MCP Server 组件攻击
│   ├── __init__.py
│   ├── attacks.py    # MCP 专用攻击实现
│   └── ...
├── a2a/              # Agent-to-Agent 组件攻击
│   ├── __init__.py
│   ├── attacks.py
│   └── ...
├── injection/        # 模型注入攻击
├── evasion/          # 绕过/逃逸攻击
├── rag/              # RAG Pipeline 攻击（预留）
├── session/          # Session/Memory 攻击（预留）
├── web/              # Web/API 攻击
│   ├── orchestrator.py
│   ├── attacks.py
│   └── ...
└── common/           # 组件间共享工具
```

**规则 S-DIR-1**：`strike/` 根目录禁止放置攻击实现代码。所有攻击实现必须放入对应组件子目录，或放入 `strike/common/`（仅限跨组件共享工具）。

**规则 S-DIR-2**：每个组件子目录必须包含 `__init__.py`，并在其中声明 `__all__` 导出公共 API。

**规则 S-DIR-3**：`recon/` 目录遵循相同规则，侦察实现按组件拆分子目录：

```
recon/
├── mcp/              # MCP 侦察
├── a2a/              # A2A 侦察
├── rag/              # RAG 侦察（预留）
├── session/          # Session 侦察（预留）
├── web/              # Web 侦察
├── fingerprint.py    # 通用指纹构建（框架层）
├── stealth_timing.py # 通用时序控制（框架层）
└── common/           # 侦察共享工具
```

### 2.2 框架层目录（Framework Layer）

框架层目录提供通用调度能力，**不按组件拆分**：

```
core/
├── seed_router.py       # 种子→转换器智能路由（dispatcher）
├── seed_loader.py       # 组件化种子加载
├── orchestrator.py      # 流水线编排
├── context.py           # PipelineContext
├── phases/
│   ├── _component_bridge.py  # 组件类型元数据盖章
│   └── ...
└── ...

assess/
├── component_scorers.py # 组件感知评分器（dispatcher）
├── component_router.py  # 组件感知评估路由
├── judge_manager.py     # LLM Judge 管理
└── ...

report/
├── component_reports.py # 组件感知报告构建器（dispatcher）
├── component_poc.py     # 组件感知 PoC 生成器（dispatcher）
└── ...

arm/
├── converter_selector.py # 转换器选择
├── seed_ranker.py        # 种子排序
└── ...
```

**规则 F-DIR-1**：框架层模块通过注册-调度模式支持组件扩展，内部使用 `_REGISTRY` / `_TEMPLATES` 字典映射组件类型到具体实现。

**规则 F-DIR-2**：框架层模块**禁止**直接 import 组件实现，必须通过运行时注册机制动态加载。

### 2.3 种子库目录

种子库按组件组织，使用 `_attack_surface/` 前缀标记组件种子集：

```
data/seeds/
├── _core/                      # 通用核心种子
├── _attack_surface/
│   ├── T1_ASI02_mcp_full_surface/      # MCP 组件种子集
│   ├── T1_ASI06-09_multi_agent/        # A2A 组件种子集
│   ├── T1_LLM08_rag_full_surface/      # RAG 组件种子集
│   └── T1_MEMORY/                      # Memory 组件种子集
├── _encoding_evasion/          # 编码逃逸种子
├── _experimental/              # 实验性种子
└── _multilingual/              # 多语言种子
```

**规则 D-DIR-1**：组件种子集目录命名格式：`T{ID}_{COMPONENT}_{DESCRIPTOR}/`，如 `T1_ASI02_mcp_full_surface/`。

**规则 D-DIR-2**：种子文件使用 `.prompt` 扩展名，元数据通过 frontmatter 声明组件类型：

```markdown
---
attack_vector: mcp_tool_registration
suitable_for: [mcp_tool_poisoning, a2a_agent_integrity]
category: mcp
owasp_id: ASI02
---

{ATTACK_PROMPT_CONTENT}
```

---

## 第三章：文件命名规范

### 3.1 组件实现文件命名

| 场景 | 命名规则 | 示例 |
|------|---------|------|
| 组件专用攻击文件 | `{action}_{component}.py` | `attack_mcp.py`, `attack_a2a.py` |
| 组件编排器 | `{component}_orchestrator.py` | `web_orchestrator.py`, `a2a_orchestrator.py` |
| 组件侦察实现 | `{component}_scanner.py` | `mcp_scanner.py`, `a2a_scanner.py` |
| 组件配置文件 | `{component}_config.py` | `mcp_config.py` |

### 3.2 框架层文件命名

| 场景 | 命名规则 | 示例 |
|------|---------|------|
| 组件感知调度器 | `component_{capability}.py` | `component_scorers.py`, `component_reports.py` |
| 桥梁模块（桥接） | `_{capability}_bridge.py` | `_component_bridge.py` |
| 注册中心 | `{capability}_registry.py` | `initializer_registry.py` |

### 3.3 测试文件命名

| 场景 | 命名规则 | 示例 |
|------|---------|------|
| 组件测试 | `test_{component}_*.py` | `test_mcp_attack.py`, `test_a2a_orchestrator.py` |
| 集成测试 | `test_pipeline_integration.py` | 端到端流水线测试 |
| 框架测试 | `test_{framework_module}.py` | `test_seed_router.py`, `test_component_scorers.py` |

---

## 第四章：组件注册框架规范

### 4.1 注册模式

所有组件感知的调度器必须使用统一的注册模式：

```python
# 1. 声明注册表
_MY_REGISTRY: dict[str, Any] = {}


# 2. 注册函数
def register_my_capability(component_type: str, impl: Any) -> None:
    """Register an implementation for a component type."""
    _MY_REGISTRY[component_type] = impl


# 3. 获取函数
def get_my_capability(component_type: str) -> Any | None:
    """Get the implementation for a component type."""
    return _MY_REGISTRY.get(component_type)


# 4. 默认注册函数
def _register_defaults() -> None:
    """Register built-in implementations."""
    register_my_capability("mcp_tool_poisoning", _mcp_impl)
    register_my_capability("a2a_agent_integrity", _a2a_impl)
    # ...新组件注册于此


# 5. 模块导入时自动注册
_register_defaults()
```

### 4.2 组件类型键命名

组件类型键使用 **snake_case**，格式：`{category}` 或 `{category}_{subcategory}`

**规则 C-NAME-1**：组件类型键与目录名保持语义一致
- `mcp_tool_poisoning` → `strike/mcp/`
- `a2a_agent_integrity` → `strike/a2a/`
- `rag_pipeline` → `strike/rag/`
- `session_memory` → `strike/session/`
- `web_api` → `strike/web/`

**规则 C-NAME-2**：种子 frontmatter 中 `suitable_for` 字段的值必须与注册表中的组件类型键完全匹配。

### 4.3 Component Bridge 规范

`core/phases/_component_bridge.py` 负责在攻击结果上盖章 `component_type` 元数据：

```python
def stamp_component_metadata(attack_result: dict, component_type: str) -> dict:
    """Stamp component_type metadata on attack result for downstream use.
    
    Called by strike executor after attack completion.
    Downstream consumers: assess/component_router, report/component_reports, report/component_poc
    """
    attack_result.setdefault("metadata", {})["component_type"] = component_type
    return attack_result
```

**规则 CB-1**：`component_type` 元数据由 `_component_bridge.stamp()` 写入，禁止其他模块直接写入此字段。

**规则 CB-2**：下游消费者读取 `component_type` 通过 `metadata.get("component_type")` 获取。

---

## 第五章：Dispatcher 模式实现规范

### 5.1 三级调度架构

```
                    ┌─────────────────┐
                    │   Entry Point   │
                    │ (Public API)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   Dispatcher    │  ← 根据 component_type 路由
                    │ (Registry Lookup)│
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
    │  MCP    │        │  A2A    │        │  ...    │  ← 组件特定实现
    │ Handler │        │ Handler │        │ Handler │
    └─────────┘        └─────────┘        └─────────┘
```

### 5.2 框架层调度器职责分配

| 调度器 | 文件 | 职责 |
|--------|------|------|
| 种子路由器 | `core/seed_router.py` | 根据 `attack_vector` 和 `suitable_for` 路由种子到最优转换器链 |
| 评分路由器 | `assess/component_router.py` | 根据 `component_type` 路由评分逻辑 |
| T0 评分器 | `assess/component_scorers.py` | 组件特定零令牌启发式检测 + 评分 rubric 选择 |
| 报告构建器 | `report/component_reports.py` | 组件特定报告章节生成 |
| PoC 生成器 | `report/component_poc.py` | 组件特定 PoC 脚本生成 |

### 5.3 调度器实现模板

```python
"""component_xxx - Component-specific XXX dispatcher for AI core components."""

from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger(__name__)

# =============================================================================
# Registry
# =============================================================================
_XXX_REGISTRY: dict[str, Any] = {}

def register_xxx(component_type: str, impl_fn: Any) -> None:
    """Register a XXX implementation for a component type."""
    _XXX_REGISTRY[component_type] = impl_fn

def get_xxx(component_type: str) -> Any | None:
    """Get the XXX implementation for a component type."""
    return _XXX_REGISTRY.get(component_type)

# =============================================================================
# MCP Component XXX
# =============================================================================
def _mcp_xxx_impl(...):
    """MCP-specific XXX implementation."""
    ...

# =============================================================================
# A2A Component XXX
# =============================================================================
def _a2a_xxx_impl(...):
    """A2A-specific XXX implementation."""
    ...

# =============================================================================
# Public API
# =============================================================================
def dispatch_xxx(evidence: dict[str, Any]) -> Any:
    """Dispatch to appropriate XXX implementation based on component_type."""
    metadata = evidence.get("metadata", {}) or {}
    component_type = metadata.get("component_type")
    
    if not component_type:
        # Infer from category
        cat = metadata.get("category", "")
        cat_lower = cat.lower()
        if "mcp_" in cat_lower:
            component_type = "mcp_tool_poisoning"
        # ... other inference rules
    
    if not component_type:
        return None
    
    impl_fn = get_xxx(component_type)
    if impl_fn:
        try:
            return impl_fn(evidence)
        except Exception as e:
            logger.warning("XXX dispatch failed for %s: %s", component_type, e)
            return None
    return None

# =============================================================================
# Module Init
# =============================================================================
def _register_defaults() -> None:
    register_xxx("mcp_tool_poisoning", _mcp_xxx_impl)
    register_xxx("a2a_agent_integrity", _a2a_xxx_impl)

_register_defaults()
```

---

## 第六章：新增组件开发 Checklist

完成以下全部步骤后，方可认为新组件开发完毕：

### 6.1 目录与文件

- [ ] 在 `strike/` 下创建组件子目录（如 `strike/new_component/`）
- [ ] 在子目录中创建 `__init__.py`，声明 `__all__`
- [ ] 创建组件特定攻击实现文件（如 `attacks.py`、`orchestrator.py`）
- [ ] 在 `recon/` 下创建对应侦察子目录（如适用）

### 6.2 攻击向量注册

- [ ] 在 `core/seed_router.py` 的 `_ATTACK_VECTOR_CONVERTER_MAP` 中添加组件攻击向量映射
- [ ] 在 `data/seeds/_attack_surface/` 下创建组件种子集目录
- [ ] 种子文件 frontmatter 中 `suitable_for` 包含新组件类型键

### 6.3 评分扩展

- [ ] 在 `assess/component_scorers.py` 中添加组件 T0 启发式检测函数
- [ ] 在 `_COMPONENT_RUBRIC_MAP` 中注册组件 rubric 路径
- [ ] 在 `_COMPONENT_T0_FUNCTIONS` 中注册 T0 检测函数
- [ ] 在 `assess/component_router.py` 中更新 T0 路由器（如适用）

### 6.4 报告扩展

- [ ] 在 `report/component_reports.py` 中添加组件报告构建器函数
- [ ] 在 `_assess_replay_complexity` 中添加组件 replay 复杂度逻辑
- [ ] 在 `register_component_builder()` 中注册新构建器
- [ ] 更新 dominant 组件检测逻辑（识别新组件 category 前缀）

### 6.5 PoC 扩展

- [ ] 在 `report/component_poc.py` 中添加组件 PoC 生成器函数
- [ ] 在 `_register_default_templates()` 中注册新模板
- [ ] 在 `generate_component_poc()` 的推断逻辑中添加组件前缀识别

### 6.6 测试

- [ ] 编写组件专用测试 `test/test_{component}_*.py`
- [ ] 运行 `pytest tests/ -x` 确保全绿
- [ ] 运行 `ruff check strike/ tests/` 确保无 lint 错误

### 6.7 文档

- [ ] 更新 `docs/specs/80-COMPONENT-ARCHITECTURE-RULES.md` 中的组件登记表
- [ ] 在组件子目录中添加 `README.md` 或模块 docstring 说明

---

## 第七章：架构不变量（Invariants）

以下不变量任何变更不得破坏：

| # | 不变量 | 依据 |
|---|--------|------|
| IA-1 | `strike/` 根目录不含攻击实现代码（仅 `__init__.py` 和 README） | S-DIR-1 |
| IA-2 | 框架层模块（core/assess/report/arm）不含组件特定攻击实现 | F-DIR-1 |
| IA-3 | 组件类型键由注册中心统一管理，禁止重复注册 | C-NAME-1 |
| IA-4 | `component_type` 元数据由 `_component_bridge` 统一写入 | CB-1 |
| IA-5 | 种子 frontmatter 中 `suitable_for` 必须匹配注册中心组件类型键 | C-NAME-2 |
| IA-6 | 调度器回退机制：未知组件类型必须返回 None 或默认实现，禁止崩溃 | 5.3 dispatch_xxx |
| IA-7 | 新组件通过注册扩展，无需修改框架层模块的调度逻辑（开放-封闭原则） | 第四章总体 |

---

## 第八章：组件状态登记表

> 跟踪当前支持的组件及其实现状态。

| 组件类型键 | 状态 | strike 目录 | recon 目录 | seed 集 | 评分 | 报告 | PoC |
|-----------|------|------------|-----------|---------|------|------|-----|
| `mcp_tool_poisoning` | ✅ 已实现 | `strike/mcp/` | `recon/mcp/` | T1_ASI02 | ✅ | ✅ | ✅ |
| `a2a_agent_integrity` | ✅ 已实现 | `strike/a2a/` | `recon/a2a/` | T1_ASI06-09 | ✅ | ✅ | ✅ |
| `model_behavior_shift` | ✅ 已实现 | `strike/injection/`, `strike/evasion/` | — | T1_LLM01-07 | ✅ | ✅ | ✅ |
| `rag_pipeline` | 🟡 框架已扩展 | `strike/rag/`（预留） | — | T1_LLM08 | ✅ | ✅ | ✅ |
| `session_memory` | 🟡 框架已扩展 | `strike/session/`（预留） | — | T1_MEMORY | ✅ | ✅ | ✅ |
| `web_api` | ✅ 已实现 | `strike/web/` | — | T1_WEB | ✅ | ✅ | ✅ |

**图例**：✅ 已实现 | 🟡 框架已扩展（待组件实现） | ❌ 未实现

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-11 | 初版：目录组织规则、命名规范、组件注册模板、开发 Checklist、架构不变量 IA-1~IA-7 | 当前会话 |
