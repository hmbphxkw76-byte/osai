# 开发规范

> **版本**: v2.4
> **日期**: 2026-8-4
> **更新记录**:
>   v2.4 — 新增 R-022: PyRIT 原生框架优先与自研增强最佳实践; R-023: 端到端验证待办自动写入记忆库与后续自动对齐
>   v2.3 — 新增 R-021: 代码改动默认全量测试 + L5 差距分析 + 端到端运行需用户确认
>   v2.2 — 新增 R-013: Makefile 自动维护约定
>   v2.1 — 新增 R-010: 流水线阶段原生框架优先与混合增强准则
>   v2.0 — 全面增强：新增原生 API 优先级、代码规范、测试规范、模块创建指南、文档规范
>   v1.0 — 初始版本，包含 R-008 运行前后清理规则、R-009 优化后L5差距分析报告规则

---

## 目录

1. [R-007: 研究资料调研优先级](#1-r-007-研究资料调研优先级)
2. [R-008: 运行前后自动清理 Python 临时文件](#2-r-008-运行前后自动清理-python-临时文件)
3. [R-009: 优化后自动生成 L5 差距分析报告](#3-r-009-优化后自动生成-l5-差距分析报告)
4. [R-010: 流水线阶段原生框架优先与混合增强准则](#4-r-010-流水线阶段原生框架优先与混合增强准则)
5. [R-013: Makefile 自动维护约定](#5-r-013-makefile-自动维护约定)
6. [R-021: 代码改动默认全量测试 + L5 差距分析 + 端到端运行需用户确认](#6-r-021-代码改动默认全量测试--l5-差距分析--端到端运行需用户确认)
7. [R-022: PyRIT 原生框架优先与自研增强最佳实践](#7-r-022-pyrit-原生框架优先与自研增强最佳实践)
8. [R-023: 端到端验证待办自动写入记忆库与后续自动对齐](#8-r-023-端到端验证待办自动写入记忆库与后续自动对齐)
9. [原生 API 优先级原则](#9-原生-api-优先级原则)
10. [代码规范](#10-代码规范)
11. [测试规范](#11-测试规范)
12. [模块创建指南](#12-模块创建指南)
13. [文档规范](#13-文档规范)
14. [Git 提交规范](#14-git-提交规范)

---

## 1. R-007: 研究资料调研优先级

### 规则

研究新技术/方法/概念时资料调研须按优先级顺序进行，不得跳级：

1. **首选**: 阅读 arxiv.org 学术文献确保有理论基础，引用时标注 arXiv 编号与标题
2. **其次**: 参考 GitHub 上 star 数高、issue 活跃、官方或知名机构维护的源码库（如 PyRIT、garak、Microsoft AI Red Team），关注实现与论文的对应关系
3. **仅当上述两层均无法找到时**: 方使用搜索引擎自行检索，且须交叉验证来源可信度

### 原因

AI 安全红队评估高度依赖前沿研究，凭直觉或碎片化博客易脱离学术共识，导致攻击链路缺理论支撑、ASR 数据不可信。

### 核心学术文献

| 主题 | 文献 | 贡献 |
|------|------|------|
| PyRIT 框架 | [[arXiv:2407.01232v1]](https://arxiv.org/abs/2407.01232) | 原生框架设计基准 |
| JailbreakBench | [[arXiv:2402.01135]](https://arxiv.org/abs/2402.01135) | ASR 基线数据 |
| HarmBench | [[arXiv:2402.04249]](https://arxiv.org/abs/2402.04249) | 标准化红队评估 |
| Wei et al. "Jailbroken" | [[arXiv:2307.15043]](https://arxiv.org/abs/2307.15043) | 攻击范式三分法 |
| Crescendo | [[arXiv:2404.01833]](https://arxiv.org/abs/2404.01833) | 多轮递进攻击 |
| TAP | [[arXiv:2312.02191]](https://arxiv.org/abs/2312.02191) | 树搜索攻击优化 |
| PAIR | [[arXiv:2310.08437]](https://arxiv.org/abs/2310.08437) | 对抗迭代优化 |
| Russinovich et al. | [[arXiv:2402.12109]](https://arxiv.org/abs/2402.12109) | Crescendo + encoding 协同 |
| Zeng et al. | [[arXiv:2402.19181]](https://arxiv.org/abs/2402.19181) | 说服策略 ASR |
| StrongREJECT | [[arXiv:2402.10260]](https://arxiv.org/abs/2402.10260) | 拒绝评估 |

---

## 2. R-008: 运行前后自动清理 Python 临时文件

### 规则

每次运行流水线（`python main.py`）前和运行后，**必须自动清理**项目中的 Python 临时文件（`__pycache__` 目录、`.pyc`、`.pyo` 文件和 `.pytest_cache` 目录）。

### 原因

- `__pycache__` 等字节码缓存在环境变更（依赖更新、代码重构）后可能过期失效，导致难以调试的问题。
- 自动清理确保每次运行从干净的字节码缓存开始，运行后不残留临时文件。
- 报告文件保留在 `output/` 目录中供人工审查，不受清理影响。

### 实现

- **代码位置**: `pipeline/utils/cleaner.py` → `clean_temp_files()` 函数
- **调用时机**:
  - 运行前: Stage 1 (`stage_init`) 之前
  - 运行后: Stage 6 (`stage_output`) 之后
- **清理范围**:
  - `__pycache__` 目录
  - `.pytest_cache` 目录
  - `*.pyc` 文件
  - `*.pyo` 文件
- **不清理**: `output/` 目录（报告保留供用户查看）

### 使用方式

```bash
# 默认: 运行前后自动清理临时文件 (报告保留)
python main.py
```

### 相关文件

| 文件 | 作用 |
|---|---|
| `pipeline/utils/cleaner.py` | 清理逻辑实现 |
| `main.py` | 清理调用入口 |

---

## 3. R-009: 优化后自动生成 L5 差距分析报告

### 规则

每次方案进行优化和调整后，**必须自动给出**优化后的方案和L5专家水平的差距分析报告，并给出对齐100%的L5专家水平的完整优化解决方案，**待用户确认后再执行代码修改**。

### 流程

1. **输出优化后的方案概述** — 简述本次优化的目标、范围和预期效果
2. **输出L5差距分析报告** — 包含：
   - 优化前后对比表（维度、优化前、优化后、提升幅度）
   - 剩余差距的根因分析
   - 学术依据引用（遵循 R-007 规则，优先 arXiv 文献）
3. **给出完整的100%对齐优化解决方案** — 针对每个剩余差距：
   - 消除方案的技术路径
   - 学术理论依据
   - 实施步骤
   - 预期效果
4. **等待用户确认** — 不得跳过此步骤直接改代码
5. **用户确认后执行代码修改** — 按确认的方案实施

### 原因

- 避免在未对齐目标的情况下盲目修改代码，减少返工
- 确保每次优化都有学术理论支撑，符合 R-007 规则
- 让用户对优化方向和影响有完整认知后再决策
- 差距分析报告作为优化决策的可追溯文档

### 相关文件

| 文件 | 作用 |
|---|---|
| `docs/l5_gap_analysis.md` | L5 差距分析报告（每次优化后更新） |
| `docs/development_guidelines.md` | 本开发规范 |

---

## 4. R-010: 流水线阶段原生框架优先与混合增强准则

### 规则

流水线的主要阶段全部都是 **PyRIT 原生框架优先**。必要增强的部分，只有当 PyRIT 原生框架无法实现该功能时，才自研代码来进行增强和实现；在自研时，也优先使用 **混合 PyRIT 框架和自研代码** 的方案来实施（如继承原生类、包装原生对象、组合原生组件），而非完全脱离原生框架的纯自研。

### 决策优先级

| 优先级 | 方案 | 说明 | 示例 |
|--------|------|------|------|
| 1 | PyRIT 原生 API 直接使用 | 原生已支持的功能，直接调用，不自造轮子 | `TextAdaptive`, `AttackExecutor`, `CentralMemory` |
| 2 | 混合方案优先 | 原生不完全支持时，优先继承/包装/组合原生组件进行增强 | `FailureTypeRoutingSelector(EpsilonGreedyTechniqueSelector)` |
| 3 | 纯自研为最后兜底 | 仅当原生框架完全无法实现该功能时，方可纯自研模块 | `EvidenceCollector`, ASR 先验数据 |

### 适用范围

- 流水线全部六个阶段（`stage_init` → `stage_scenario` → `stage_initialize` → `stage_execute` → `stage_post_analysis` → `stage_output`）
- 新增功能开发、功能增强、功能重构

### 禁止事项

| 禁止 | 说明 |
|------|------|
| **禁止原生可用时自研** | 原生框架已支持的功能不得自研替代 |
| **禁止完全脱离原生** | 自研模块必须至少组合或依赖一个原生组件 |
| **禁止覆盖原生生命周期** | 不覆盖 `scenario.run_async()` 等核心方法（与 R-003 一致） |

### 原因

PyRIT 原生框架经过学术验证和工程实践检验，直接使用可确保攻击链路的可信度和可维护性。混合方案在保留原生框架优势的同时实现定制化增强，避免完全自研导致的维护负担和与上游脱节风险。

---

## 5. R-013: Makefile 自动维护约定

### 规则

项目根目录的 `Makefile` 和 `make.ps1` 是自动化命令行入口，须与项目脚本保持同步。具体约定：

1. **自动发现兜底**: 任何放入 `scripts/` 目录的 `.py` 文件，均可通过 `make script-<name>` 直接调用，无需手动注册
2. **高频脚本注册**: 高频使用的脚本须在 `Makefile` 中注册独立 target（如 `download-datasets`、`env-check`），并在 `help` 中添加说明
3. **新增脚本时同步**: 每次新增 `scripts/*.py` 脚本时，须同步更新 `Makefile`（注册 target 或确认已通过通配符覆盖）
4. **定期检查**: 运行 `make scripts-check` 检测 `scripts/` 下未注册的脚本，按需补充独立 target
5. **make.ps1 同步**: `make.ps1` 是 Windows PowerShell 包装器，无需同步 target 列表（它自动委托给 `make` 或 WSL `make`）

### 维护流程

```
新增 scripts/my_script.py
  ├── 自动可用: make script-my_script
  ├── 运行检查: make scripts-check
  └── 高频? → 在 Makefile 注册独立 target + help 条目
```

### Makefile 结构约定

| 区块 | 内容 |
|------|------|
| 帮助 | `help` target，分类列出所有命令 |
| 环境安装 | `install` / `install-dev` / `install-all` 等 |
| 环境配置 | `env-setup` / `env-check` / `pre-commit` |
| 流水线运行 | `run` / `run-small` / `run-custom` 等 |
| 测试 | `test` / `test-pipeline` / `test-cov` 等 |
| 代码质量 | `lint` / `format` / `typecheck` / `check` |
| 数据管理 | `download-*` / `sync-asr` |
| 清理 | `clean` / `clean-output` / `clean-all` |
| Docker | `docker-build` / `docker-run` |
| 文档 & 基准 | `docs` / `benchmark` |
| 验证 | `verify-integration` / `verify-all` |
| 脚本自动发现 | `script-%` / `scripts-list` / `scripts-check` |

### 相关文件

| 文件 | 作用 |
|---|---|
| `Makefile` | 自动化命令行入口（主文件） |
| `make.ps1` | Windows PowerShell 包装器（通过 WSL 调用 make） |

---

## 6. R-021: 代码改动默认全量测试 + L5 差距分析 + 端到端运行需用户确认

> 新增于 2026-8-4
> 覆盖（取代）R-011 中的「每次代码修改后必须执行完整流水线运行测试」要求
> 合并吸收 R-015 的全量代码级测试要求
> 扩展 R-009 的 L5 差距分析要求至「代码改动后」

### 规则

每次代码改动后，默认执行以下四步流程：

#### 6.1 全量代码级测试（默认自动执行）

代码改动后立即执行：

- **ruff check** 全量检查：`pipeline/` `scripts/` `tests/` `conftest.py`（不得使用 `ruff check .` 全局扫描）
- **pytest** 全量测试：`pytest tests/ -v --tb=short`，所有测试必须通过（0 failed）
- **快捷命令**: `make check-full` 一键执行 ruff + pytest 全量检查
- 确保程序运行正常：零 ruff 违规 + 0 failed tests

#### 6.2 PyRIT 版本一致性

当前 PyRIT 版本为 **1.0.1**，所有代码改动必须：

- 保持与 PyRIT 1.0.1 原生 API 的一致性和一贯性
- 不引入与 1.0.1 不兼容的 API 调用
- 新增功能优先检查 PyRIT 1.0.1 原生是否已支持（遵循 R-010）
- PyRIT 源码位于 `../src/PyRIT-1.0.1/`（只读，不可修改）

#### 6.3 L5 差距分析（默认自动执行）

代码改动完成后，**主动**给出与 L5 专家水平 100% 的差距分析：

- 改动前后的 L5 维度对比表
- 剩余差距的根因分析
- 达到 100% L5 水平的完整优化解决方案
- 差距分析报告更新到 `docs/l5_gap_analysis.md`

#### 6.4 端到端流水线运行（⚠️ 需用户确认）

**不得主动运行端到端流水线**（`python main.py`）：

- **除非**: 用户明确确认执行
- **除非**: 必须运行端到端才能验证达到 100% L5 水平（此时仍需告知用户并等待确认）
- 代码级测试（ruff + pytest）已足以验证代码正确性
- 端到端运行消耗 API 额度和时间，仅在必要时执行
- 如需运行端到端流水线，须向用户说明理由并等待确认

### 流程图

```
代码改动完成
  │
  ├─→ 1. make check-full（ruff + pytest）  ← 默认自动执行
  │
  ├─→ 2. PyRIT 1.0.1 API 一致性检查         ← 默认自动执行
  │
  ├─→ 3. L5 差距分析报告                     ← 默认自动执行
  │
  └─→ 4. 端到端流水线运行 (python main.py)   ← ⚠️ 需用户确认
```

### 与既有规则的关系

| 既有规则 | 关系 | 说明 |
|---------|------|------|
| R-009 | 扩展 | R-009 管「方案确认前」的 L5 差距分析；R-021 管「代码改动后」的 L5 差距分析 |
| R-011 | 部分取代 | R-011 要求每次代码修改后执行完整流水线运行测试；R-021 取消此要求，改为需用户确认 |
| R-015 | 合并吸收 | R-015 的全量代码级测试要求合并到 R-021 中，成为默认行为 |

### 原因

- 代码级测试（ruff + pytest）已能充分验证代码正确性和无回归
- 端到端流水线运行消耗 API 额度和时间，不宜每次代码改动都执行
- L5 差距分析确保每次改动都有明确的质量定位和改进路径
- PyRIT 1.0.1 版本一致性确保代码与原生框架的兼容性

### 相关文件

| 文件 | 作用 |
|---|---|
| `.assistant_pyrit/rules.md` | 项目专项规则（R-001 ~ R-021） |
| `docs/development_guidelines.md` | 本开发规范 |
| `docs/l5_gap_analysis.md` | L5 差距分析报告（每次代码改动后更新） |
| `Makefile` | `make check-full` 一键执行 ruff + pytest |

---

## 7. R-022: PyRIT 原生框架优先与自研增强最佳实践

> 新增于 2026-8-4
> 统领 R-003（PyRIT 原生框架优先）和 R-010（流水线阶段原生框架优先与混合增强准则），适用于三库全部代码

### 规则

**PyRIT 原生框架优先，自研代码是 PyRIT 原生框架的增强，符合 PyRIT 最佳实践原则。**

所有代码（不限于流水线阶段）必须遵循以下原则：

1. **原生框架优先** — PyRIT 原生组件是首选，不自造轮子
2. **自研即增强** — 自研代码的存在意义是增强 PyRIT 原生框架，而非替代或绕过；自研代码必须至少组合或依赖一个原生组件
3. **最佳实践对齐** — 所有代码必须符合 PyRIT 最佳实践：
   - async 后缀命名规范
   - keyword-only 参数风格
   - 完整类型注解
   - 原生注册表机制
   - 原生配置机制（`.pyrit_conf` + `.env`）
   - 原生生命周期（不覆盖核心方法）

### 适用范围

- 三库全部代码（pyrit-pipeline / garak-pipeline / 未来的其他 pipeline 项目）
- 不限于流水线阶段，包括 scripts/、tests/、web_redteam/ 等所有模块

### 与 R-003 / R-010 的关系

| 规则 | 范围 | 侧重 |
|------|------|------|
| R-003 | 原生组件使用 | 不自造轮子，自研作为扩展层 |
| R-010 | 流水线阶段 | 混合增强准则（继承/包装/组合） |
| **R-022** | **全部代码** | **统领 R-003/R-010，强调自研即增强 + 最佳实践对齐** |

### 原因

PyRIT 原生框架经过学术验证和工程实践检验，自研代码的价值在于增强而非替代。只有自研代码与原生框架保持最佳实践一致，才能确保代码的可维护性、可追溯性和与上游的兼容性。

### 相关文件

| 文件 | 作用 |
|---|---|
| `.assistant_pyrit/rules.md` | 项目专项规则（R-001 ~ R-023） |
| `docs/development_guidelines.md` | 本开发规范 |

---

## 8. R-023: 端到端验证待办自动写入记忆库与后续自动对齐

> 新增于 2026-8-4
> 补充 R-021 端到端验证的自动化追踪机制

### 规则

当 L5 差距分析发现 **必须通过端到端流水线运行才能验证 100% 对齐 L5 专家水平** 的差距项时，执行以下自动化流程：

### 自动化流程

```
L5 差距分析 → 发现端到端验证型差距
  │
  ├─→ 1. 自动写入记忆库  ← 将待验证项写入记忆，标注触发条件
  │
  ├─→ 2. 等待用户确认端到端运行  ← R-021 要求用户确认
  │
  ├─→ 3. 端到端运行完成后 → 自动对齐 L5 差距分析  ← 验证待办项，更新差距状态
  │
  └─→ 4. 继续给出后续优化解决方案  ← 如有新差距，给出完整解决方案
```

### 详细步骤

#### 步骤 1: 自动写入记忆库

当 L5 差距分析中发现端到端验证型差距时，**立即**将以下信息写入记忆库：

- **差距描述** — 具体哪个 L5 维度需要端到端验证
- **触发条件** — 什么运行命令/参数组合可以验证此差距
- **预期验证结果** — 运行后应观察什么日志/数据来确认对齐
- **当前差距百分比** — 该差距项占 L5 100% 的权重
- **关联规则** — R-021（端到端需用户确认）

#### 步骤 2: 等待用户确认

- 向用户说明需要端到端运行的理由
- 列出待验证项清单
- 等待用户明确确认后才执行（遵循 R-021 步骤 4）

#### 步骤 3: 端到端运行后自动对齐

端到端流水线运行完成后，**自动**执行：

- 逐项验证记忆库中的待验证项
- 检查运行日志/数据是否满足预期验证结果
- 更新每项差距的状态：✅ 已对齐 / ⚠️ 部分对齐 / ❌ 未对齐
- 更新 `docs/l5_gap_analysis.md` 差距分析报告
- 更新记忆库中的验证结果

#### 步骤 4: 继续给出后续优化解决方案

如有新发现的差距或未完全对齐的项：

- 给出完整的 L5 100% 对齐优化解决方案
- 包含技术路径、学术依据、实施步骤
- 遵循 R-009 流程（待用户确认后再改代码）

### 与 R-021 的关系

| 规则 | 管什么 | 关系 |
|------|--------|------|
| R-021 | 端到端运行需用户确认 | 定义「不能主动运行」的约束 |
| **R-023** | **端到端验证的自动化追踪** | **补充 R-021，定义「需要端到端验证时」的完整自动化流程** |

### 原因

端到端流水线运行不是每次代码改动都执行的常规步骤，但当 L5 差距分析发现有必须端到端才能验证的差距时，不能让这些差距项丢失。R-023 确保这些待验证项被自动记录、追踪、并在运行后自动对齐，形成完整闭环。

### 相关文件

| 文件 | 作用 |
|---|---|
| `.assistant_pyrit/rules.md` | 项目专项规则（R-001 ~ R-023） |
| `docs/development_guidelines.md` | 本开发规范 |
| `docs/l5_gap_analysis.md` | L5 差距分析报告（端到端运行后更新） |

---

## 9. 原生 API 优先级原则

### 9.1 核心原则

> **PyRIT 原生框架优先，自研代码以 ASR 驱动，攻击为王，报告证据齐全为原则，其余的内容都可以忽略。**

### 9.2 API 使用优先级

| 优先级 | API 来源 | 使用场景 | 示例 |
|--------|---------|---------|------|
| 1 | PyRIT 原生 API | 核心攻击/评分/输出/内存 | `TextAdaptive`, `AttackExecutor`, `CentralMemory` |
| 2 | 原生 API 子类继承 | 选择器增强 | `FailureTypeRoutingSelector(EpsilonGreedyTechniqueSelector)` |
| 3 | 原生 API 包装 | 目标增强 | `RateLimitedTarget(PromptTarget)` |
| 4 | 原生 API 扩展 | 数据层增强 | `RichMetadataLoader(SeedDataset)` |
| 5 | 纯自研 | 数据/分析/报告 | `EvidenceCollector`, `ASROptimizer` |

### 9.3 禁止事项

| 禁止 | 说明 |
|------|------|
| **禁止覆盖原生生命周期** | 不覆盖 `scenario.run_async()` 等核心方法 |
| **禁止重新实现原生功能** | 不自建评分器/攻击执行器/内存系统 |
| **禁止绕过原生注册表** | 通过 `TargetRegistry`/`ScorerRegistry`/`AttackTechniqueRegistry` 获取实例 |
| **禁止硬编码 API 调用** | 通过 `.pyrit_conf` + `.env` 配置，不硬编码 endpoint/key |

### 9.4 自研模块准则

自研模块必须满足以下条件之一：
1. **数据层增强**: 提供原生 API 不支持的数据 (如 ASR 先验)
2. **选择层路由**: 增强原生选择器的决策能力 (如失败类型路由)
3. **分析层扩展**: 从原生结果提取结构化信息 (如证据收集)
4. **包装层增强**: 包装原生对象增加功能 (如限速包装)

---

## 10. 代码规范

### 10.1 代码风格

- **格式化工具**: `ruff` (配置在 `pyproject.toml`)
- **行长度**: 120 字符
- **Import 顺序**: stdlib → third-party → pyrit → pipeline → local
- **类型注解**: 所有公共函数必须有类型注解
- **Docstring**: 所有公共函数/类必须有 docstring

### 10.2 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 模块 | snake_case | `failure_type_selector.py` |
| 类 | PascalCase | `FailureTypeRoutingSelector` |
| 函数 | snake_case | `select_async()` |
| 常量 | UPPER_SNAKE | `DEFAULT_EPSILON` |
| 私有 | _prefix | `_build_warm_start_asr()` |
| 环境变量 | UPPER_SNAKE | `OPENAI_CHAT_ENDPOINT` |

### 10.3 异步规范

- 所有 I/O 操作使用 `async/await`
- 不在异步函数中使用 `time.sleep()`，使用 `asyncio.sleep()`
- 并发使用 `asyncio.Semaphore` 控制并发度

### 10.4 错误处理

```python
# 三级 fallback 模式 (评分器获取示例)
try:
    scorer = registry.get_by_tag("default_objective_scorer")
except:
    try:
        scorer = registry.get_by_name("objective_scorer_chat")
    except:
        scorer = registry.get_by_tag("scorer")
```

### 10.5 日志规范

- 使用原生 `pyrit.logging` 或 Python `logging`
- 噪音日志重定向到文件 (R-008 配套: `pipeline/utils/noise_redirector.py`)
- 终端输出仅显示关键信息

---

## 11. 测试规范

### 11.1 测试结构

```
tests/
├── unit/                   # 单元测试
│   ├── test_asr/          # ASR 模块测试
│   ├── test_converters/   # Converter 模块测试
│   ├── test_analysis/     # 分析模块测试
│   └── test_reporting/    # 报告模块测试
├── integration/           # 集成测试
│   └── test_pipeline.py   # 端到端测试
└── conftest.py            # pytest 配置
```

### 11.2 测试准则

| 准则 | 说明 |
|------|------|
| **原生 API mock** | 测试中 mock 原生 API 调用，不依赖真实 API |
| **ASR 数据 mock** | 使用固定 ASR 数据，不依赖历史运行 |
| **独立运行** | 每个测试可独立运行，不依赖其他测试的副作用 |
| **覆盖率** | 自研模块测试覆盖率目标 ≥ 80% |
| **命名** | `test_<模块>_<函数>_<场景>()` |

### 11.3 运行测试

```bash
# 运行所有测试
python -m pytest tests/ -v

# 运行特定模块测试
python -m pytest tests/unit/test_asr/ -v

# 生成覆盖率报告
python -m pytest tests/ --cov=pipeline --cov-report=html
```

---

## 12. 模块创建指南

### 12.1 何时创建新模块

```
需要新模块吗？

├── 原生 API 是否已支持该功能？
│   └── YES → 使用原生 API，不创建新模块
│   └── NO → 继续
│
├── 是否是数据层增强？
│   └── YES → 创建 pipeline/asr/ 或 pipeline/converters/ 模块
│
├── 是否是分析层扩展？
│   └── YES → 创建 pipeline/analysis/ 模块
│
├── 是否是报告层扩展？
│   └── YES → 创建 pipeline/reporting/ 模块
│
├── 是否是目标层增强？
│   └── YES → 创建 pipeline/targets/ 模块
│
└── 是否是新的攻击行为？
    └── YES → 这不是 pipeline 模块，应该在 PyRIT 上游实现
```

### 12.2 模块结构模板

```python
# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""模块简述。

详细说明模块的职责、设计决策和原生 API 依赖。
"""

from __future__ import annotations

# stdlib imports
import ...

# third-party imports
import ...

# pyrit imports
from pyrit... import ...

# pipeline imports
from pipeline... import ...


class ModuleName:
    """类简述。

    Attributes:
        attr1: 属性说明
    """

    def __init__(self, param1: str, param2: int = 3) -> None:
        """初始化。

        Args:
            param1: 参数说明
            param2: 参数说明
        """
        ...

    async def method_async(self, param: str) -> Any:
        """方法说明。

        Args:
            param: 参数说明

        Returns:
            返回值说明
        """
        ...
```

### 12.3 模块注册

新模块需要在以下位置注册：
- `pipeline/__init__.py` — 公共接口导出
- `docs/asr_driven_e2e_architecture.md` — 自研模块清单
- `docs/architecture_design.md` — 模块依赖关系

---

## 13. 文档规范

### 13.1 文档结构

| 文档 | 说明 | 位置 |
|------|------|------|
| `asr_driven_e2e_architecture.md` | ASR 驱动端到端架构 (主文档) | `docs/` |
| `architecture_design.md` | 核心架构设计 | `docs/` |
| `end_to_end_architecture.md` | 端到端攻击流程 | `docs/` |
| `l5_gap_analysis.md` | L5 差距分析报告 | `docs/` |
| `targets.md` | 目标层设计 | `docs/` |
| `development_guidelines.md` | 开发规范 (本文档) | `docs/` |
| `principles/*.md` | PyRIT 组件原理文档 | `docs/principles/` |

### 13.2 文档准则

| 准则 | 说明 |
|------|------|
| **代码-文档一致** | 文档反映真实代码架构，不描述不存在的功能 |
| **版本标记** | 每个文档标注版本号、日期、PyRIT 版本 |
| **学术引用** | 遵循 R-007，优先引用 arXiv 文献 |
| **中文优先** | 文档以中文撰写，代码注释以英文撰写 |
| **表格优先** | 复杂信息优先使用表格呈现 |
| **更新记录** | 文档头部标注更新记录 |

### 13.3 文档更新时机

- 新增模块时
- 修改阶段逻辑时
- 新增 CLI 参数时
- 优化方案确认后 (R-009)
- 依赖版本升级时

---

## 14. Git 提交规范

### 14.1 提交信息格式

```
<type>: <简述>

<详细说明>
```

### 14.2 类型

| 类型 | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | 修复 |
| `docs` | 文档更新 |
| `refactor` | 重构 |
| `test` | 测试 |
| `chore` | 构建/工具 |

### 14.3 示例

```
feat: 新增 FailureTypeRoutingSelector 失败类型路由选择器

继承原生 EpsilonGreedyTechniqueSelector，增加:
- 学术 ASR 先验 warm-start
- 失败类型路由策略
- 动态 Alpha 计算
```

---

*文档结束*
