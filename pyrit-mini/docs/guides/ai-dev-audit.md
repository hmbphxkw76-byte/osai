# AI 编程 L5 专家审查水准 — 审计通用指南模板

> **文档定位**：跨项目可复用的 AI 编程审计框架，适用于任何使用 AI 进行软件开发的项目。
> **核心理念**通过**六大审计维度** + **三级门禁机制** + **跨模型规约审查**，实现 L5 专家生产标准的自动化质量保障。
> **适用范围**：个人项目、团队协作、企业级系统、开源基础设施、跨模型协作——任何使用 AI 进行软件开发的场景。
> **合规标准**：对齐 L5 专家水准 + 跨模型一致性协议 + 生产级工具链。
> **版本**：v1.0（2026-09-11）— 基于 pyrit-mini 实践经验提炼的通用审计模板

---

## ⚡ 快捷触发词速查（跨模型通用）

> **使用说明**：在任何 AI 编程助手（CatPaw / Cursor / Claude / GPT 等）中输入以下触发词，即可启动对应审计流程。

| 触发词 | 审计类型 | 核心检查项 | 类比理解 |
|--------|---------|-----------|---------|
| **架构审计** | Architecture Audit | 阶段边界契约 / 组件传播 / 模块路由 / 元数据连续性 | 相当于"房屋结构安全检测" |
| **组件审计** | Component Audit | 基线扫描 / 纯净度 / T0覆盖 / Scorer覆盖 / 种子清单 / 验证门禁 | 相当于"房间功能完整性检查" |
| **依赖审计** | Dependency Audit | 导入合规 / 跨层禁止 / 版本锁定 / 废弃API检测 | 相当于"水电管线合规检查" |
| **数据审计** | Data Audit | 全链路数据流 / 字段契约 / 阶段间传递 / 证据链完整 | 相当于"物流追踪链审计" |
| **漂移审计** | Drift Audit | 规范-代码同步 / 版本漂移 / 契约消费 / 原生优先 | 相当于"GPS偏离路线检测" |
| **开发全审** | Dev Full Audit | A→H 全流水线（Guard + Lint + Test + DryRun + DataFlow + Drift + QuickCheck） | 相当于"年度全面体检" |
| **纯净审计** | Purity Audit | AST分析 / 跨组件污染 / 必需技术覆盖 / 高ASR覆盖 | 相当于"食材纯度检测" |
| **门禁检查** | Gate Check | R-SIZE / R-CONV / R-IMPORT / R-TOOLS / R-DATA 静态规则 | 相当于"安检门" |

---

## 文档导览

### 按角色阅读路径

| 角色 | 阅读路径 | 预计时间 |
|------|---------|---------|
| **完全新手** | Part 1 → Part 2 → Part 3 快速上手 | 30 分钟 |
| **日常开发者** | 快捷触发词 → Part 3 工作流 → Part 4 工具链 | 45 分钟 |
| **团队 Lead** | 全文 + Part 5 跨模型 + Part 6 门禁设计 | 2 小时 |
| **专家/审计** | Part 1 + Part 4 + Part 5 + Part 7 框架设计 | 1.5 小时 |
| **跨模型协作** | Part 5 + 附录 A + 附录 C | 1 小时 |

### 按场景快速导航

| 场景 | 导航位置 |
|------|---------|
| 新项目启动 | Part 2 快速上手 + Part 3.1 基线建立 |
| 日常开发 | Part 3.2 提交前检查 + 快捷触发词 |
| 代码评审 | Part 4 工具链 + Part 6 门禁机制 |
| 跨模型一致性 | Part 5 跨模型规约 + 附录 A |
| 规范演进 | Part 8 FAQ + 附录 D |
| 出了问题 | Part 8 FAQ + 附录 B 排错 + 附录 E 失败案例库 |

---

## 目录

1. [第一部分：审计框架总览](#第一部分审计框架总览)
2. [第二部分：5 分钟快速上手](#第二部分5-分钟快速上手)
3. [第三部分：审计工作流](#第三部分审计工作流)
3. [第四部分：六大审计维度详解](#第四部分六大审计维度详解)
5. [第五部分：跨模型规约审查](#第五部分跨模型规约审查)
6. [第六部分：三级门禁机制](#第六部分三级门禁机制)
7. [第七部分：框架适配指南](#第七部分框架适配指南)
8. [第八部分：FAQ](#第八部分faq)
9. [附录 A：跨模型 Prompt 模板库](#附录-a跨模型-prompt-模板库)
10. [附录 B：排错速查](#附录-b排错速查)
11. [附录 C：触发词完整映射表](#附录-c触发词完整映射表)
12. [附录 D：规范 CHANGELOG](#附录-d规范-changelog)
13. [附录 E：失败案例库](#附录-e失败案例库)

---

## 第一部分：审计框架总览

### 1.1 什么是"L5 专家审查水准"？

```
┌─────────────────────────────────────────────────────────────────┐
│                    L5 专家审查水准金字塔                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                        ▲                                        │
│                       /  \                                      │
│                      / L5 \        ← 专家审查 (Expert Audit)    │
│                     /______\          全维度 + 跨模型 + 自动化   │
│                    /   L4    \      ← 生产级 (Production)       │
│                   /____________\      门禁全绿 + 全量测试        │
│                  /     L3      \    ← 集成级 (Integration)      │
│                 /________________\    数据流 + 漂移检测          │
│                /       L2        \  ← 组件级 (Component)        │
│               /____________________\  纯净度 + 覆盖度            │
│              /         L1          \ ← 基础级 (Foundation)      │
│             /________________________\  Lint + 单测 + 静态规则  │
│            /           L0           \ ← 入门级 (Starter)        │
│           /__________________________\  代码风格 + 文件结构     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**L5 专家审查的核心特征**：
- **全维度覆盖**：架构、组件、依赖、数据、漂移、纯净度六大维度
- **跨模型一致性**：同一规约在不同 AI 模型上产生一致结果
- **自动化门禁**：BLOCKING/WARNING/INFO 三级，失败即停
- **可复用模板**：适配任何 AI 编程项目，无需重写规则

### 1.2 六大审计维度

| 维度 | 核心问题 | 检测方法 | 输出 |
|------|---------|---------|------|
| **架构审计** | 模块边界是否清晰？阶段契约是否满足？ | 静态分析 + 运行时追踪 + 契约检查 | PASS/WARNING/BLOCKING |
| **组件审计** | 组件目录是否完整？覆盖是否充分？ | 基线扫描 + T0覆盖 + Scorer覆盖 + 种子清单 | 缺失项列表 |
| **依赖审计** | 导入是否合规？版本是否锁定？ | 正则匹配 + import 解析 + 版本对比 | 违规项 + 修复建议 |
| **数据审计** | 数据流是否完整？字段契约是否满足？ | 全链路追踪 + 字段存在性验证 | 断点位置 |
| **漂移审计** | 规范与代码是否同步？版本是否偏离？ | 规范表格-代码交叉验证 + 版本锁定检测 | 漂移维度 + 修复提示 |
| **纯净审计** | 组件是否被污染？必需技术是否覆盖？ | AST 分析 + 正则扫描 + 基线对比 | 纯净度分数 + 覆盖度分数 |

### 1.3 三级门禁机制

```
┌──────────────────────────────────────────────────────────────┐
│                    三级门禁决策树                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  审计结果                                                     │
│     │                                                        │
│     ├── BLOCKING (阻断) ──→ 立即修复 ──→ 禁止提交/合并       │
│     │                                                        │
│     ├── WARNING (警告) ──→ 建议修复 ──→ 可提交但记录         │
│     │                                                        │
│     └── INFO (信息) ──→ 知会即可 ──→ 无需修复                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**门禁阈值定义**：

| 级别 | 含义 | 处理方式 | 类比 |
|------|------|---------|------|
| **BLOCKING** | 架构违规 / 数据断裂 / 安全漏洞 | 立即修复，禁止通过 | 红灯 — 停止 |
| **WARNING** | 潜在风险 / 规范偏离 / 性能隐患 | 建议修复，可人工豁免 | 黄灯 — 注意 |
| **INFO** | 最佳实践提醒 / 改进建议 | 知会即可，无需阻断 | 绿灯 — 通行 |

---

## 第二部分：5 分钟快速上手

### 2.1 三步启动审计

```bash
# Step 1: 安装依赖（首次）
pip install -e ".[dev]"

# Step 2: 运行开发全审（最全面的审计）
py -m tools.dev_audit_full

# Step 3: 查看结果
# 全绿 = Ready for commit
# 有红 = Fix before commit
```

### 2.2 常用一键命令

```bash
# 架构审计（最快，30秒）
py -m tools.guard

# 组件审计（全维度，约60秒）
py -m tools.component_audit

# 纯净度检查（AST分析，约30秒）
py -m tools.guard --component-purity

# 漂移检测（规范同步，约20秒）
py -m tools.drift_detector --full

# 架构合规验证（静态+契约，约20秒）
python tools/architecture_validator.py full
```

### 2.3 首次接入新项目清单

- [ ] **Step 1**：确认项目根目录结构（`core/`, `tools/`, `tests/` 等）
- [ ] **Step 2**：建立组件目录基线（`strike/<component>/`, `recon/<component>/` 等）
- [ ] **Step 3**：配置门禁规则（R-SIZE 阈值、白名单、跨层禁止）
- [ ] **Step 4**：运行首次全审，记录基线结果
- [ ] **Step 5**：将审计命令集成到 CI/CD 或 pre-commit hook

---

## 第三部分：审计工作流

### 3.1 基线建立（新项目/大重构后）

```
┌─────────────────────────────────────────────────────────────────┐
│                    基线建立流程                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 运行组件审计 → 记录组件目录清单                              │
│  2. 运行架构审计 → 记录阶段契约基线                              │
│  3. 运行依赖审计 → 记录合规导入清单                              │
│  4. 运行数据审计 → 记录字段契约链                                │
│  5. 运行漂移审计 → 记录规范-代码同步状态                         │
│  6. 运行纯净审计 → 记录各组件纯净度分数                          │
│                                                                 │
│  输出: baseline.json（基线快照，用于后续对比）                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 提交前检查（日常开发）

```bash
# 快速检查（推荐每次提交前运行）
py -m tools.guard --quick-all

# 完整检查（合并前/发布前运行）
py -m tools.dev_audit_full

# 仅检查修改的文件（最快）
py -m tools.guard --quick path/to/modified_file.py
```

### 3.3 持续集成集成

```yaml
# .github/workflows/audit.yml 示例
name: L5 Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e ".[dev]"
      - run: py -m tools.guard
      - run: py -m tools.component_audit
      - run: py -m tools.drift_detector --full
```

---

## 第四部分：六大审计维度详解

### 4.1 架构审计（Architecture Audit）

#### 4.1.1 核心验证维度

| 维度 | 验证内容 | 方法 |
|------|---------|------|
| **阶段边界契约** | 各阶段是否正确输出到上下文 | 静态正则匹配 `ctx.{attr}` 赋值 |
| **组件类型传播** | component_type 是否全链路一致 | 桥接函数存在性检查 |
| **模块路由完整性** | 组件子模块是否被正确调用 | 文件存在性 + 函数存在性 |
| **元数据连续性** | metadata 是否在阶段间保持 | 读取链追踪 |
| **桥接集成** | 组件桥接是否在正确位置被调用 | 调用点检测 |

#### 4.1.2 架构审计执行流程

```
Phase 1: Static Analysis (静态分析)
  ├── 阶段边界契约验证
  ├── 组件类型传播验证
  ├── 模块路由完整性验证
  ├── 元数据连续性验证
  └── 桥接集成验证

Phase 2: Contract Check (契约检查)
  ├── Recon → ARM 契约
  ├── ARM → Strike 契约
  ├── Strike → Assess 契约
  ├── Assess → Report 契约
  └── 横切关注点检查

Phase 3: Runtime Trace (运行时追踪, 可选)
  ├── 阶段输出快照
  └── 组件类型传播率验证
```

#### 4.1.3 输出格式示例

```
======================================================================
Architecture Compliance Validation Report
======================================================================
  PASS: 79 | WARNING: 6 | BLOCKING: 0

[PHASE_BOUNDARY]
  [PASS] Phase 'recon' outputs ctx.service_profile
  [PASS] Phase 'strike' outputs ctx.attack_results
  [WARN] Phase 'assess' may not output ctx.dual_judge_stats

[COMPONENT_PROPAGATION]
  [PASS] Component bridge has stamp function
  [PASS] Component router has classification function

[MODULE_ROUTING]
  [PASS] Recon module exists for mcp_tool_poisoning: recon.mcp.schema_extractor
  [PASS] Strike module exists for a2a_agent_integrity: strike.a2a.card_spoofer
```

### 4.2 组件审计（Component Audit）

#### 4.2.1 六阶段组件审计流程

| Phase | 名称 | 核心检查 | 耗时 |
|-------|------|---------|------|
| 1 | Baseline Scan | 全模块组件目录清单扫描 | ~5s |
| 2 | Purity Validation | AST+正则验证组件纯净度 | ~15s |
| 3 | T0 Coverage | 分类模式 + T0 检查器覆盖 | ~5s |
| 4 | Scorer/Report Coverage | Scorer + Report 组件感知章节覆盖 | ~5s |
| 5 | Seed Inventory | 种子文件数量与组件类型匹配 | ~5s |
| 6 | Validation Gate | pytest + guard + architecture_validator 三重验证 | ~30s |

#### 4.2.2 组件纯净度验证规则

```
纯净度(Purity) = 1.0 - (违规数 / 总行数)
覆盖度(Coverage) = 已发现技术数 / 必需技术数

阈值:
  - 纯净度 >= 90% 为合格
  - 覆盖度 >= 60% 为合格
```

#### 4.2.3 组件审计输出示例

```
======================================================================
  Component Audit Pipeline (Phase 1→6)
======================================================================

[Phase 1] Baseline Scan
  [OK] strike/mcp/ (4 files)
  [OK] strike/a2a/ (3 files)
  [OK] strike/rag/ (5 files)
  [MISS] strike/web/ (required)

[Phase 2] Purity Validation
  [PASS] a2a - Purity Score: 98.5%
  [PASS] mcp - Purity Score: 97.2%
  [WARN] rag - Purity Score: 85.3% (cross-component import detected)

[Phase 6] Validation Gate
  [PASS] 31 purity tests passed
  [INFO] Guard: BLOCKING=0, WARNING=7
  [PASS] ArchCheck: PASS=79, WARNING=6, BLOCKING=0

======================================================================
  ALL PHASES PASSED — 组件审计全绿
======================================================================
```

### 4.3 依赖审计（Dependency Audit）

#### 4.3.1 核心规则

| 规则 | 说明 | 级别 |
|------|------|------|
| R-IMPORT-1 | 禁止使用的第三方库（如 requests → httpx） | WARNING |
| R-IMPORT-2 | 跨层导入禁止（如 report 导入 strike） | BLOCKING |
| R-IMPORT-3 | 循环依赖检测 | BLOCKING |
| R-IMPORT-4 | __all__ / __getattr__ 导出完整性 | WARNING |
| R-IMPORT-5 | 废弃 API 检测 | WARNING |
| R-IMPORT-6 | 版本锁定验证 | BLOCKING |

#### 4.3.2 跨层导入禁止矩阵

```
_FROM_  →  _TO_   | strike | recon | assess | report | utils
------------------|--------|-------|--------|--------|------
strike             |   ✓    |   ✗   |   ✗    |   ✗    |   ✗
recon              |   ✗    |   ✓   |   ✗    |   ✗    |   ✗
assess             |   ✗    |   ✗   |   ✓    |   ✗    |   ✗
report             |   ✗    |   ✗   |   ✗    |   ✓    |   ✗
utils              |   ✗    |   ✗   |   ✗    |   ✗    |   ✓
```

> **规则**：高层模块（report）不得导入低层模块（strike/recon），保证依赖方向单向。

### 4.4 数据审计（Data Audit）

#### 4.4.1 全链路数据流验证

```
Recon ──→ ARM ──→ Strike ──→ Assess ──→ Report/Evidence
  │         │         │          │           │
  ▼         ▼         ▼          ▼           ▼
service_  seeds     attack_    asr_per_    report
profile   techniques results   technique   evidence
          converter_           overall_asr
          map                  dual_judge_
                               stats
```

#### 4.4.2 字段契约验证点

| 阶段 | 输出字段 | 消费阶段 | 验证方法 |
|------|---------|---------|---------|
| recon | service_profile | arm | `ctx.service_profile` 读取检测 |
| recon | mcpsec_surface | arm | `ctx.mcpsec_surface` 读取检测 |
| arm | seeds | strike | `ctx.seeds` 读取检测 |
| arm | techniques | strike | `ctx.techniques` 读取检测 |
| strike | attack_results | assess | `ctx.attack_results` 读取检测 |
| assess | overall_asr | report | `ctx.overall_asr` 读取检测 |
| assess | asr_per_technique | report | `ctx.asr_per_technique` 读取检测 |

### 4.5 漂移审计（Drift Audit）

#### 4.5.1 检测维度

| 规则 | 维度 | 说明 |
|------|------|------|
| R-DRIFT-1 | api_sync | 规范引用的原生 API 是否真实可解析 |
| R-DRIFT-2 | spec_table | 规范表格引用的代码模块是否仍存在 |
| R-DRIFT-3 | version_lock | 依赖版本是否偏离锁定版本 |
| R-DRIFT-4 | contract_drift | PipelineContext 字段是否被实际消费 |
| R-NATIVE-* | native_first | 是否存在自研替代原生实现 |

#### 4.5.2 漂移检测输出示例

```
======================================================================
  Spec-Code Drift Detector v1.0
======================================================================

  Timestamp: 2026-09-11T10:30:00
  PyRIT Version: 1.0.1

  [API_SYNC] 1 finding(s):
    [W] R-DRIFT-1 WARNING: PyRIT 原生类不在预期位置: pyrit.executor.attack.multi_turn.XPIAAttack
       Fix: 检查 XPIAAttack 是否已改名或移动位置

  Summary: 0 BLOCKING / 1 WARNING / 2 INFO
======================================================================
```

### 4.6 开发全审（Dev Full Audit）

#### 4.6.1 核心问题
> **代码是否达到提交/合并标准？开发全审是最全面的审计，串联所有关键检查维度。**

#### 4.6.2 A→H 八阶段流水线

| Phase | 名称 | 核心检查 | 耗时 | 可跳过 |
|-------|------|---------|------|--------|
| A | Spec Impact | 手动阅读规范文档（提示开发者） | 手动 | 是 |
| B | Architecture Guard | R-SIZE/CONV/IMPORT/TOOLS/DATA 静态架构检查 | ~15s | 否 |
| B2 | ArchCheck | 组件感知流水线架构合规验证 | ~10s | 否 |
| C | Lint (Ruff) | 代码风格检查 (E/F/W/I 规则集) | ~10s | 否 |
| D | Unit Test | pytest tests/ 全量单元测试 | ~60s | 否 |
| E | Runtime Dry-Run | main.py 6 阶段流水线运行时验证 | ~30s | 是 |
| F | Data Flow | Recon→ARM→Strike→Assess→Report 全链路验证 | ~20s | 是 |
| G | Drift Detection | 规约-代码漂移检测 (R-DRIFT-1~4) | ~15s | 是 |
| H | Final Quick Check | R-DELIVERY 规则快速扫描 | ~10s | 是 |

#### 4.6.3 执行引擎设计

```python
@dataclass
class Phase:
    """单阶段配置"""
    id: str           # a, b, c, ...
    name: str         # 显示名称
    description: str  # 说明
    command: list[str]  # 执行命令
    required: bool = True  # 是否必须通过
    timeout: int = 300     # 超时秒数

# 全审流程定义
AUDIT_PHASES: list[Phase] = [
    Phase(id="b", name="Architecture Guard",
          command=[sys.executable, "-m", "tools.guard"]),
    Phase(id="b2", name="ArchCheck",
          command=[sys.executable, "tools/architecture_validator.py", "full"]),
    Phase(id="c", name="Lint (Ruff)",
          command=[sys.executable, "-m", "ruff", "check", "."]),
    Phase(id="d", name="Unit Test",
          command=[sys.executable, "-m", "pytest", "tests/", "-v"]),
    Phase(id="e", name="Runtime Dry-Run",
          command=[sys.executable, "main.py", "--dry-run", "--max-seeds", "1"]),
    Phase(id="f", name="Data Flow",
          command=[sys.executable, "-m", "pytest", "tests/test_data_flow_integrity.py", "-v"]),
    Phase(id="g", name="Drift Detection",
          command=[sys.executable, "-m", "tools.drift_detector", "--full"]),
    Phase(id="h", name="Final Quick Check",
          command=[sys.executable, "-m", "tools.quick_check", "--all"]),
]

def run_audit(skip=None, only=None, fail_fast=True):
    """运行完整开发全审流程 — fail-fast 机制"""
    for phase in phases_to_run:
        passed, output, duration = run_phase(phase)
        if not passed and fail_fast and phase.required:
            break  # [FAIL-FAST] 立即停止
    return 0 if all_passed else 1
```

#### 4.6.4 Fail-Fast 机制

```
Fail-Fast 决策树:

审计触发
    │
    ▼
┌──────────────┐
│ 按顺序执行阶段 │
└──────┬───────┘
       │
       ▼
┌──────────────┐    失败    ┌──────────────┐
│ 阶段通过？    │──────────→│ required?    │
└──────┬───────┘           └──────┬───────┘
       │ 通过                     │
       ▼                    是 ↙   ↘ 否
┌──────────────┐         ┌──────┐ ┌──────┐
│ 下一阶段      │         │ 停止 │ │ 记录 │
└──────────────┘         │ 报错 │ │ 继续 │
                         └──────┘ └──────┘
```

#### 4.6.5 输出格式示例

```
======================================================================
 Development Audit Pipeline (A→H)
======================================================================
  Project: d:\文档\GitHub\osai\pyrit-mini
  Python:  3.11.9
  Time:    2026-09-11 10:30:00

[Phase B] Architecture Guard
  R-SIZE / R-CONV / R-IMPORT / R-TOOLS / R-DATA 静态架构检查
  Result: PASS (12.3s)

[Phase B2] ArchCheck
  组件感知流水线架构合规验证 (阶段边界/组件传播/模块路由/元数据连续性)
  Result: PASS (8.7s)

[Phase C] Lint (Ruff)
  代码风格检查 (E/F/W/I 规则集)
  Result: PASS (9.1s)

[Phase D] Unit Test
  pytest tests/ 全量单元测试
  Result: PASS (58.2s)

[Phase E] Runtime Dry-Run
  main.py 6 阶段流水线运行时验证 (跳过 API 调用)
  Result: PASS (28.5s)

[Phase F] Data Flow
  Recon→ARM→Strike→Assess→Report/Evidence 全链路数据流验证
  Result: PASS (18.3s)

[Phase G] Drift Detection
  规约-代码漂移检测 (R-DRIFT-1~4)
  Result: PASS (14.1s)

[Phase H] Final Quick Check
  R-DELIVERY 规则快速扫描 (文件大小/文档字符串/跨层导入)
  Result: PASS (7.8s)

======================================================================
 Development Audit Summary
======================================================================
  Total Phases: 8
  Passed:       8
  Failed:       0
  Total Time:   157.0s

  Phase    Name                      Result     Time
  -------- ------------------------- ---------- --------
  B        Architecture Guard        PASS       12.3s
  B2       ArchCheck                 PASS       8.7s
  C        Lint (Ruff)               PASS       9.1s
  D        Unit Test                 PASS       58.2s
  E        Runtime Dry-Run           PASS       28.5s
  F        Data Flow                 PASS       18.3s
  G        Drift Detection           PASS       14.1s
  H        Final Quick Check         PASS       7.8s

  ALL PHASES PASSED — Ready for commit
======================================================================
```

#### 4.6.6 CLI 命令参考

```bash
# 执行全审 B→H (A 为手动)
py -m tools.dev_audit_full

# 跳过 Dry-Run 和 Data Flow (加速)
py -m tools.dev_audit_full --skip e,f

# 仅执行指定阶段
py -m tools.dev_audit_full --phase b    # 仅 Architecture Guard
py -m tools.dev_audit_full --phase b2   # 仅 ArchCheck
py -m tools.dev_audit_full --phase d    # 仅单元测试

# 详细输出 (显示完整命令输出)
py -m tools.dev_audit_full -v

# 失败继续执行后续阶段 (不停止)
py -m tools.dev_audit_full --no-fail-fast
```

#### 4.6.7 各阶段依赖关系

```
A (Spec Impact)
  │ 手动确认
  ▼
B (Architecture Guard) ──→ B2 (ArchCheck)
  │                          │
  │ 静态通过                  │ 架构合规
  ▼                          ▼
C (Lint) ─────────────────→ D (Unit Test)
  │                          │
  │ 风格通过                  │ 测试通过
  ▼                          ▼
E (Dry-Run) ──────────────→ F (Data Flow)
  │                          │
  │ 运行时通过                │ 数据流通过
  ▼                          ▼
G (Drift Detection) ──────→ H (Quick Check)
                             │
                             │ 全部通过
                             ▼
                        Ready for commit
```

> **设计原则**：阶段间有隐式依赖——前一阶段通过后才能进入下一阶段。E/F/G/H 为非必需阶段（可跳过），B/B2/C/D 为必需阶段（失败即停）。

### 4.7 纯净审计（Purity Audit）

#### 4.7.1 AST 纯净度分析

```python
# 核心检测逻辑
class PurityAnalyzer(ast.NodeVisitor):
    def visit_Import(self, node):
        # 检测跨组件导入
        if is_cross_component_import(node.names):
            report_violation("cross_component_import")

    def visit_FunctionDef(self, node):
        # 检测禁止模式函数
        if matches_forbidden_pattern(node.name):
            report_violation("forbidden_function")

    def visit_ClassDef(self, node):
        # 检测禁止模式类
        if matches_forbidden_pattern(node.name):
            report_violation("forbidden_class")
```

#### 4.7.2 纯净度评分标准

| 分数段 | 等级 | 含义 | 处理建议 |
|--------|------|------|---------|
| 95-100% | A+ | 完全纯净 | 无需处理 |
| 90-94% | A | 基本纯净 | 可选优化 |
| 80-89% | B | 轻微污染 | 建议修复 |
| 70-79% | C | 中度污染 | 需要修复 |
| <70% | D | 严重污染 | 立即修复 |

---

## 第五部分：跨模型规约审查

### 5.1 为什么需要跨模型审查？

不同 AI 模型（GPT-4, Claude, Gemini, DeepSeek 等）对同一规约的理解可能存在差异。跨模型审查确保：

1. **一致性**：同一 prompt 在不同模型上产生结构一致的输出
2. **完整性**：不同模型不会遗漏关键检查维度
3. **可靠性**：审计结果不依赖单一模型的"幻觉"

### 5.2 跨模型审查协议

```
┌─────────────────────────────────────────────────────────────────┐
│                  跨模型审查协议 (Cross-Model Audit Protocol)     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Prompt 标准化                                               │
│     └── 使用结构化 prompt 模板（见附录 A）                       │
│                                                                 │
│  2. 多模型并行执行                                               │
│     └── 同一 prompt 输入 ≥2 个模型                              │
│                                                                 │
│  3. 结果对比                                                    │
│     └── 对比各模型输出的检查项覆盖度                             │
│                                                                 │
│  4. 差异分析                                                    │
│     └── 识别模型间差异，判断是"补充"还是"矛盾"                   │
│                                                                 │
│  5. 共识决策                                                    │
│     └── 取交集作为必选项，取并集作为推荐项                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 跨模型 Prompt 模板

#### 模板 A：架构审计 Prompt（跨模型通用）

```markdown
# 架构审计任务

## 角色
你是一位拥有 10 年经验的软件架构师，专精于 AI 编程项目的架构合规审查。

## 输入
- 项目根目录路径: {project_root}
- 架构规范文档: {architecture_spec}
- 组件类型列表: {component_types}

## 检查清单（按顺序执行）

### 1. 阶段边界契约
- [ ] 检查每个阶段文件是否存在
- [ ] 验证阶段输出字段是否赋值到 ctx
- [ ] 验证下游阶段是否正确读取 ctx 字段

### 2. 组件类型传播
- [ ] 检查组件桥接模块是否存在
- [ ] 验证桥接函数是否包含 stamp 逻辑
- [ ] 检查组件路由器是否存在分类函数

### 3. 模块路由完整性
- [ ] 验证每个组件类型是否有对应的 recon 模块
- [ ] 验证每个组件类型是否有对应的 strike 模块
- [ ] 验证每个组件类型是否有对应的 assess 评分函数
- [ ] 验证每个组件类型是否有对应的 report 构建函数

### 4. 元数据连续性
- [ ] 检查评分管道是否读取 component_type
- [ ] 检查证据收集器是否保留 metadata

## 输出格式
```
[阶段边界契约]
  [PASS/FAIL] 具体检查项描述

[组件类型传播]
  [PASS/FAIL] 具体检查项描述

[模块路由完整性]
  [PASS/FAIL] 具体检查项描述

[元数据连续性]
  [PASS/FAIL] 具体检查项描述

总结: PASS={数量} / WARNING={数量} / BLOCKING={数量}
```
```

#### 模板 B：组件审计 Prompt（跨模型通用）

```markdown
# 组件审计任务

## 角色
你是一位 AI 编程质量审计专家，负责验证组件化代码组织的完整性和纯净度。

## 输入
- 项目根目录路径: {project_root}
- 核心组件类型: {core_components}
- 扩展组件类型: {extended_components}
- 最小种子数/组件: {min_seeds}

## 检查清单

### Phase 1: 基线扫描
- [ ] 遍历所有模块（strike/recon/assess/report/tools/data）
- [ ] 列出每个模块下的组件子目录
- [ ] 统计每个组件目录的 .py 文件数
- [ ] 标记缺失的核心组件目录

### Phase 2: 纯净度验证
- [ ] 对每个组件目录执行 AST 分析
- [ ] 检测跨组件导入（如 a2a 模块导入 mcp 内容）
- [ ] 检测禁止模式（如 SQL 注入出现在 A2A 组件中）
- [ ] 计算纯净度分数

### Phase 3: T0 覆盖
- [ ] 检查 component_router.py 的分类模式覆盖
- [ ] 检查 T0 检查器函数覆盖
- [ ] 检查 __init__.py 导出完整性
- [ ] 检查强信号分类覆盖
- [ ] 检查元数据推断覆盖

### Phase 4: Scorer/Report 覆盖
- [ ] 检查 data/scorers/component_scorers/ 目录
- [ ] 检查 report/component_reports.py 章节构建器
- [ ] 检查 report/component_poc.py PoC 生成器
- [ ] 检查 core/phases/_component_bridge.py

### Phase 5: 种子清单
- [ ] 统计每个组件的种子文件数
- [ ] 标记种子不足的组件
- [ ] 统计扩展组件种子数

### Phase 6: 验证门禁
- [ ] 运行 pytest 测试
- [ ] 运行 guard 检查
- [ ] 运行 architecture_validator

## 输出格式
按 Phase 1→6 顺序输出，每个 Phase 包含:
- 检查项列表（[PASS]/[FAIL]/[WARN]）
- 问题汇总
- 修复建议
```

### 5.4 跨模型结果对比表

| 检查维度 | GPT-4 | Claude | Gemini | DeepSeek | 共识 |
|---------|-------|--------|--------|----------|------|
| 阶段边界契约 | ✓ | ✓ | ✓ | ✓ | **必选** |
| 组件类型传播 | ✓ | ✓ | ✗ | ✓ | **必选** |
| 模块路由完整性 | ✓ | ✓ | ✓ | ✓ | **必选** |
| 元数据连续性 | ✓ | ✗ | ✓ | ✗ | 推荐 |
| 桥接集成 | ✓ | ✓ | ✓ | ✓ | **必选** |

> **决策规则**：≥3 个模型覆盖 → 必选；2 个模型覆盖 → 推荐；≤1 个模型覆盖 → 可选

---

## 第六部分：三级门禁机制

### 6.1 门禁规则体系

```
┌─────────────────────────────────────────────────────────────────┐
│                     门禁规则体系 (Guard Rules)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  R-SIZE   ─ 文件大小控制 (God Object 检测)                       │
│  R-CONV   ─ Converter 串联限制                                   │
│  R-IMPORT ─ 依赖导入合规                                         │
│  R-TOOLS  ─ CLI 工具位置规范                                     │
│  R-DATA   ─ 数据流完整性                                         │
│  R-PIPE   ─ 流水线模块注册                                       │
│  R-REDTEAM─ 红队最佳实践                                         │
│  R-EVID   ─ 证据收集完整性                                       │
│  R-REPORT ─ 报告生成完整性                                       │
│  R-DELIVERY ─ 交付规范 (文件/文档/跨层)                          │
│  R-DRIFT  ─ 规范漂移检测                                         │
│  R-NATIVE ─ 原生优先原则                                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 门禁决策流程

```
审计触发
    │
    ▼
┌──────────────┐
│ 运行全量检查  │
└──────┬───────┘
       │
       ▼
┌──────────────┐    是    ┌──────────────┐
│ BLOCKING > 0 │────────→│ 立即修复     │
└──────┬───────┘         │ 禁止提交     │
       │ 否              └──────────────┘
       ▼
┌──────────────┐    是    ┌──────────────┐
│ WARNING > N  │────────→│ 建议修复     │
└──────┬───────┘         │ 记录豁免     │
       │ 否              └──────────────┘
       ▼
┌──────────────┐
│ 通过 ✓       │
│ 允许提交     │
└──────────────┘
```

### 6.3 门禁豁免机制

当 WARNING 无法立即修复时，可申请豁免：

```python
# 豁免配置示例 (audit_exemptions.yaml)
exemptions:
  - rule: "R-SIZE"
    file: "arm/converter_chains.py"
    reason: "稳定运行的转换器链，单一职责，含完整测试覆盖"
    approved_by: "tech_lead"
    expires: "2026-12-31"

  - rule: "R-DELIVERY-1"
    file: "recon/_target_router_helpers.py"
    reason: "858行，路由辅助函数集合，拆分风险高于收益"
    approved_by: "architect"
    expires: "2026-12-31"
```

---

## 第七部分：框架适配指南

### 7.1 适配新项目步骤

#### Step 1: 目录结构映射

```yaml
# audit_config.yaml - 项目适配配置
project:
  name: "your-project"
  root: "."

# 模块映射（根据实际项目调整）
modules:
  core: "core"           # 核心逻辑
  attack: "strike"       # 攻击/执行模块
  recon: "recon"         # 侦察/分析模块
  assess: "assess"       # 评估/评分模块
  report: "report"       # 报告模块
  tools: "tools"         # 工具脚本
  data: "data"           # 数据目录

# 组件类型定义
components:
  core: ["mcp", "a2a", "model", "rag", "session", "web"]
  extended: ["memory", "evasion", "injection"]

# 门禁阈值
thresholds:
  file_size_warning: 850
  file_size_blocking: 1500
  min_purity: 0.90
  min_coverage: 0.60
  min_seeds_per_component: 3
```

#### Step 2: 规则定制

```python
# 根据项目特点定制规则
CUSTOM_RULES = {
    "R-SIZE": {
        "warning": 850,
        "blocking": 1500,
        "whitelist": [
            "core/orchestrator.py",
            "tools/guard.py",
        ],
    },
    "R-IMPORT": {
        "forbidden": [
            (r"import\s+requests", "使用 httpx 替代"),
        ]
    },
    "R-CROSS-LAYER": {
        "forbidden": {
            "report": ["strike"],
            "utils": ["strike", "recon", "assess", "report"],
        }
    },
}
```

#### Step 3: 集成 CI/CD

```yaml
# .github/workflows/l5-audit.yml
name: L5 Expert Audit
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Architecture Guard
        run: py -m tools.guard

      - name: Component Audit
        run: py -m tools.component_audit

      - name: Drift Detection
        run: py -m tools.drift_detector --full

      - name: Upload audit report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: audit-report
          path: outputs/audit/
```

### 7.2 不同规模项目的适配策略

| 项目规模 | 推荐审计策略 | 频率 | 工具链 |
|---------|-------------|------|--------|
| **个人项目** | 快速检查（guard --quick-all） | 每次提交 | ruff + guard |
| **小团队** | 标准审计（guard + component_audit） | PR 时 | ruff + guard + pytest |
| **企业级** | 全量审计（dev_audit_full） | 每次 push | 完整工具链 + CI |
| **开源项目** | 全量 + 跨模型审查 | Release 时 | 完整 + 多模型对比 |

### 7.3 常见项目类型适配

#### Web 后端项目

```yaml
# Web 后端项目适配
modules:
  core: "app"
  attack: "services"      # 业务逻辑层
  recon: "middleware"      # 中间件层
  assess: "validators"     # 验证层
  report: "serializers"    # 序列化层

components:
  core: ["auth", "api", "db", "cache", "queue"]
```

#### 数据科学项目

```yaml
# 数据科学项目适配
modules:
  core: "src"
  attack: "models"         # 模型定义
  recon: "features"        # 特征工程
  assess: "evaluation"     # 评估指标
  report: "visualization"  # 可视化

components:
  core: ["classification", "regression", "clustering", "nlp", "cv"]
```

#### CLI 工具项目

```yaml
# CLI 工具项目适配
modules:
  core: "cli"
  attack: "commands"       # 子命令
  recon: "parsers"         # 输入解析
  assess: "formatters"     # 输出格式化
  report: "output"         # 输出渲染

components:
  core: ["init", "run", "config", "plugin", "auth"]
```

---

## 第八部分：FAQ

### Q1: 审计失败怎么办？

**A**: 按以下优先级处理：

1. **BLOCKING** → 立即修复，禁止提交
2. **WARNING** → 评估影响，建议修复
3. **INFO** → 知会即可，可延后处理

```bash
# 查看具体失败项
py -m tools.guard -v

# 查看修复建议
py -m tools.guard --quick path/to/file.py
```

### Q2: 如何豁免某个 WARNING？

**A**: 在豁免配置文件中添加条目：

```yaml
# audit_exemptions.yaml
exemptions:
  - rule: "R-SIZE"
    file: "path/to/file.py"
    reason: "详细说明豁免原因"
    approved_by: "审批人"
    expires: "过期日期"
```

### Q3: 新组件如何加入审计？

**A**: 三步添加：

1. 在 `audit_config.yaml` 的 `components.core` 中添加组件名
2. 创建对应的组件目录（`strike/<component>/`, `recon/<component>/`）
3. 在 `component_purity_config.py` 中添加基线定义

### Q4: 跨模型审查需要多少模型？

**A**: 建议至少 2 个模型进行对比，3-4 个模型可获得更可靠的共识。

- **2 模型**：取交集作为必选项
- **3 模型**：≥2 模型覆盖即为必选
- **4+ 模型**：≥3 模型覆盖为必选，2 模型覆盖为推荐

### Q5: 审计耗时太长怎么办？

**A**: 使用增量检查策略：

```bash
# 仅检查修改的文件
py -m tools.guard --quick path/to/modified.py

# 仅运行快速检查
py -m tools.guard --quick-all

# 跳过耗时阶段
py -m tools.dev_audit_full --skip e,f  # 跳过 DryRun 和 DataFlow
```

### Q6: 如何在 monorepo 中应用？

**A**: 为每个子包配置独立审计：

```yaml
# monorepo 配置
packages:
  - name: "core"
    path: "packages/core"
    components: ["auth", "api", "db"]

  - name: "plugins"
    path: "packages/plugins"
    components: ["mcp", "a2a", "rag"]
```

---

## 附录 A：跨模型 Prompt 模板库

### A.1 架构审计 Prompt（完整版）

```markdown
# 架构审计专家 Prompt

## 系统角色
你是一位资深软件架构师，专精于 AI 编程项目的架构合规审查。你的任务是验证代码是否完全遵循架构规范。

## 审计范围
- 项目路径: {project_root}
- 架构规范: {architecture_spec_path}
- 组件类型: {component_types}

## 检查维度（必须全部覆盖）

### 1. 阶段边界契约 (Phase Boundary Contracts)
对每个阶段 (recon/arm/strike/assess/report):
1. 检查阶段文件是否存在: core/phases/{phase}.py
2. 读取阶段文件内容
3. 验证是否正确输出到 ctx（匹配 ctx.{attr} = ... 模式）
4. 验证下游阶段是否正确读取

### 2. 组件类型传播 (Component Type Propagation)
1. 检查 core/phases/_component_bridge.py 是否存在
2. 验证桥接函数是否包含 stamp 逻辑
3. 检查 assess/component_router.py 是否存在分类函数

### 3. 模块路由完整性 (Module Routing)
对每个组件类型:
1. 检查 recon/{component}/ 目录是否存在
2. 检查 strike/{component}/ 目录是否存在
3. 检查对应的 T0 评分函数是否存在
4. 检查对应的报告构建函数是否存在

### 4. 元数据连续性 (Metadata Continuity)
1. 检查评分管道是否读取 component_type
2. 检查证据收集器是否保留 metadata

## 输出要求
- 按维度分组输出
- 每个检查项标记 [PASS]/[FAIL]/[WARN]
- 最终汇总: PASS={n} / WARNING={n} / BLOCKING={n}
- 如有 FAIL/BLOCKING，提供具体修复建议
```

### A.2 组件审计 Prompt（完整版）

```markdown
# 组件审计专家 Prompt

## 系统角色
你是一位 AI 编程质量审计专家，负责验证组件化代码组织的完整性和纯净度。

## 审计范围
- 项目路径: {project_root}
- 核心组件: {core_components}
- 扩展组件: {extended_components}

## 检查维度

### Phase 1: 基线扫描
遍历所有模块，列出组件子目录清单。

### Phase 2: 纯净度验证
对每个组件目录:
1. 读取所有 .py 文件
2. AST 分析检测跨组件导入
3. 正则扫描检测禁止模式
4. 计算纯净度分数

### Phase 3: T0 覆盖
1. 检查 component_router.py 分类模式
2. 检查 T0 检查器函数
3. 检查 __init__.py 导出

### Phase 4: Scorer/Report 覆盖
1. 检查 data/scorers/component_scorers/
2. 检查 report/component_reports.py
3. 检查 report/component_poc.py

### Phase 5: 种子清单
统计每个组件的种子文件数，标记不足项。

### Phase 6: 验证门禁
运行 pytest + guard + architecture_validator。

## 输出要求
按 Phase 1→6 顺序输出，每 Phase 包含检查项和结果标记。
```

### A.3 依赖审计 Prompt

```markdown
# 依赖审计专家 Prompt

## 检查清单

### 1. 导入合规
- [ ] 扫描所有 .py 文件的 import 语句
- [ ] 检测禁止使用的第三方库
- [ ] 检测跨层导入（高→低）

### 2. 版本锁定
- [ ] 读取 pyproject.toml / requirements.txt
- [ ] 对比实际安装版本
- [ ] 标记版本偏离项

### 3. 循环依赖
- [ ] 构建模块依赖图
- [ ] 检测循环引用
- [ ] 标记循环依赖链

### 4. 废弃 API
- [ ] 扫描已知废弃 API 使用
- [ ] 提供替代方案建议
```

---

## 附录 B：排错速查

### B.1 常见 BLOCKING 问题

| 问题 | 原因 | 修复方法 |
|------|------|---------|
| R-SIZE BLOCKING | 文件超过 1500 行 | 拆分为子模块 |
| R-IMPORT BLOCKING | 跨层导入 | 重构为单向依赖 |
| R-TOOLS BLOCKING | CLI 入口位置错误 | 迁移到 tools/ 目录 |
| R-DATA BLOCKING | 数据流断裂 | 补充 ctx 字段赋值 |

### B.2 常见 WARNING 问题

| 问题 | 原因 | 修复方法 |
|------|------|---------|
| R-SIZE WARNING | 文件 850-1500 行 | 评估是否需要拆分 |
| R-IMPORT WARNING | 使用不推荐的库 | 替换为推荐库 |
| R-DRIFT WARNING | 规范-代码不同步 | 更新规范或代码 |
| Purity WARNING | 组件被污染 | 移除跨组件代码 |

### B.3 性能问题

| 问题 | 原因 | 修复方法 |
|------|------|---------|
| 审计超时 | 文件过多/网络调用 | 增加超时、跳过网络阶段 |
| 内存不足 | 大文件 AST 分析 | 分批处理、增加内存 |
| CI 耗时过长 | 全量检查 | 增量检查、并行执行 |

---

## 附录 C：触发词完整映射表

### C.1 中文触发词

| 触发词 | 英文对应 | 执行命令 | 适用场景 |
|--------|---------|---------|---------|
| 架构审计 | Architecture Audit | `py -m tools.guard` + `python tools/architecture_validator.py full` | 模块边界/阶段契约检查 |
| 组件审计 | Component Audit | `py -m tools.component_audit` | 组件完整性/覆盖度检查 |
| 依赖审计 | Dependency Audit | `py -m tools.guard` (R-IMPORT 规则) | 导入合规/版本锁定 |
| 数据审计 | Data Audit | `py -m pytest tests/test_data_flow_integrity.py` | 全链路数据流验证 |
| 漂移审计 | Drift Audit | `py -m tools.drift_detector --full` | 规范-代码同步检测 |
| 开发全审 | Dev Full Audit | `py -m tools.dev_audit_full` | A→H 全流水线检查 |
| 纯净审计 | Purity Audit | `py -m tools.guard --component-purity` | 组件纯净度/覆盖度 |
| 门禁检查 | Gate Check | `py -m tools.guard` | 静态规则快速检查 |
| 快速检查 | Quick Check | `py -m tools.guard --quick-all` | 提交前快速验证 |
| 单文件检查 | Single File Check | `py -m tools.guard --quick file.py` | 单文件合规检查 |
| 实时监视 | Watch Mode | `py -m tools.guard --watch` | 开发时实时检查 |

### C.2 英文触发词

| 触发词 | 对应中文 | 执行命令 |
|--------|---------|---------|
| "audit architecture" | 架构审计 | Architecture Guard + ArchCheck |
| "audit components" | 组件审计 | Component Audit Pipeline |
| "audit dependencies" | 依赖审计 | Guard R-IMPORT rules |
| "audit data flow" | 数据审计 | Data Flow Integrity Test |
| "audit drift" | 漂移审计 | Drift Detector |
| "full audit" | 开发全审 | Dev Audit Full (A→H) |
| "purity check" | 纯净审计 | Component Purity Validation |
| "gate check" | 门禁检查 | Architecture Guard |
| "quick check" | 快速检查 | Quick Check All |

---

## 附录 D：规范 CHANGELOG

### v1.0 (2026-09-11)
- **初始版本**：基于 pyrit-mini 实践经验提炼
- **核心内容**：
  - 六大审计维度定义（架构/组件/依赖/数据/漂移/纯净）
  - 三级门禁机制（BLOCKING/WARNING/INFO）
  - 跨模型审查协议
  - 快捷触发词体系
  - 跨模型 Prompt 模板库
- **设计原则**：
  - 跨项目可复用
  - 跨模型通用
  - L5 专家水准
  - 自动化优先

---

## 附录 E：失败案例库

### E.1 架构审计失败案例

**案例 1：阶段边界契约断裂**
- **现象**：assess 阶段未读取 ctx.attack_results
- **根因**：重构时遗漏了字段传递
- **修复**：在 assess.py 中添加 `ctx.attack_results` 读取逻辑
- **教训**：重构后必须运行架构审计

**案例 2：组件类型传播失败**
- **现象**：attack_results 中 80% 缺少 component_type
- **根因**：_component_bridge.stamp_component_metadata 未被调用
- **修复**：在 strike.py 输出阶段调用桥接函数
- **教训**：新增攻击模块时必须集成桥接

### E.2 组件审计失败案例

**案例 3：组件纯净度污染**
- **现象**：strike/a2a/ 中检测到 SQL 注入代码
- **根因**：AI 生成代码时混入了不相关技术
- **修复**：移除 SQL 注入代码，迁移到正确的组件
- **教训**：AI 生成代码后必须运行纯净度检查

**案例 4：T0 覆盖缺失**
- **现象**：新增 web 组件但 component_router.py 未更新
- **根因**：添加组件时忘记更新路由器
- **修复**：在 component_router.py 添加 web_api 分类模式
- **教训**：新增组件必须同步更新路由器

### E.3 依赖审计失败案例

**案例 5：跨层导入**
- **现象**：report/generator.py 导入了 strike/executor.py
- **根因**：AI 生成代码时违反了依赖方向
- **修复**：重构为通过 ctx 传递数据，移除直接导入
- **教训**：高→低层依赖必须通过中间层（ctx）传递

**案例 6：版本漂移**
- **现象**：pyrit 版本从 1.0.* 漂移到 1.1.0
- **根因**：pip install 时未锁定版本
- **修复**：回滚到锁定版本，更新 pyproject.toml
- **教训**：依赖版本必须锁定并定期检测

---

> **文档维护**：本模板为活文档，随项目实践持续更新。建议每次重大审计后发现新规则时，同步更新本指南。
> 
> **反馈渠道**：如发现模板不足或需要新增审计维度，请提交 Issue 或 PR。
