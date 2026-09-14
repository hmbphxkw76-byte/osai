# CP-012 — 收口 REQ-151 前置跨层违例 S4/S5/S6（工厂/注册表分层解耦）

> **类型**：债务登记（收口现存 DEBT：BL-082 ② / BL-090 三组 `_IMPORT_DEBT_EXCEPTIONS` 豁免）
> **提案人 / 日期**：AI (CodeBuddy) / 2026-09-14
> **状态**：draft → 评审中 → **approved**（2026-09-14 自动批准：用户授权"全程自动批准符合最佳实践的方案"；符合 NEG-4 / C3 / IC-2 / [sid:30-ch3] / ASR 中性）
> 关联：BL-082 ②（recon→strike）、BL-090（core→recon / strike→recon）；前置 CP-009（S2/S3/S7 已闭环，S4/S5/S6 并入本 CP）；REQ-151（PlaybookEngine DAG —— 本 CP **仅做其前置依赖解耦**，不实现 PlaybookEngine 特性本体）
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 动机

CP-009 已闭环 S2/S3/S7（删除 `strike→assess` / `assess→arm` / `report→utils` 三条豁免，全树 R-IMPORT 0 BLOCKING）。
剩余 **3 条** `_IMPORT_DEBT_EXCEPTIONS`（`recon→strike` / `core→recon` / `strike→recon`）按设计并入 REQ-151，至今仍以代码级豁免"雪藏"：

- **现状**：这 3 组仍是 `10-ARCHITECTURE.md` §2.2 依赖方向矩阵明令 **✗** 的跨层 import；机器校验器 `check_dependency_matrix()`（R-IMPORT）对它们放行，因为它们在豁免白名单内。
- **不够**：矩阵"可执行"闭环并未真正完成——白名单"只减不增"原则被悬置，3 处真实跨层耦合残留。
- **不改会怎样**：① REQ-151 PlaybookEngine 落地时 `recon`/`strike`/`core` 间 circular-import 风险高；② 豁免易回潮，R-IMPORT 闭环判据（应 0 豁免）名存实亡。
- **与条款冲突/留白**：与 §2.2 矩阵 `recon→strike`/`core→recon`/`strike→recon` 均 **✗**、及 40-G 1F（R-IMPORT 闭环判据）冲突。

> 注：工作树当前已有 WIP 脚手架 `core/target_factory.py` 与 `core/adapter_registry.py`（接缝模块，零攻击逻辑，NEG-4 合规：仅标准库 + typing），本 CP 将其**正式收口**为 REQ-151 前置解耦方案，并消掉 WIP 现存 ruff 违例（F821/E402）。

## 2. 条款/规格 diff（精确到文件与行）

| 文件 | 位置 | 现文 | 改为 |
|------|------|------|------|
| `tools/guard_extended.py` | 2672–2678 | `_IMPORT_DEBT_EXCEPTIONS = {("recon","strike"):{get_shared_bridge,SessionConfig,SessionStateManager}, ("core","recon"):{ParsedBurpRequest,parse_burp_request,get_playwright_handles}}` | S6 的 `("strike","recon")` 已删（✅ 闭环）；余 `("recon","strike")`/`("core","recon")` 两对待 REQ-151 分层重构（删豁免会触发 R-IMPORT BLOCKING，须先建 core 接缝） |
| `core/target_factory.py`（WIP 已建） | 全文 | 注册表已建，`strike` 侧 `register_target` 与 `recon` 侧 `build_target` 接线在途 | 补全 `strike/targets/__init__.py` 导入期注册 + `recon` 三处调用改经 `build_target`（S4） |
| `core/adapter_registry.py`（WIP 已建） | 全文 | 注册表已建，`recon` 侧 `register_adapter` 接线在途 | 补全 `recon/adapters/__init__.py` 注册（消 E402）+ `strike` 侧 `get_adapter` 取用（S6） |
| `recon/adapters/__init__.py` | 223 | `from core.adapter_registry import register_adapter` 置于 `register_adapter(...)` 调用之后（**E402**） | 上移至模块首部或 `TYPE_CHECKING` 块，消 E402 |
| `strike/targets/{a2a,mcp,rag}.py` | 签名注解 | `BaseAdapter` / `JSONRPCAdapter` 作注解但未模块级导入（**F821** Undefined name） | **已修**：模块级经 `core.adapter_registry.get_adapter("BaseAdapter"/"JSONRPCAdapter")` 解析别名（`try/except KeyError` 安全回退），`strike→core ✓`，**未引入 `strike→recon`**（切忌 `TYPE_CHECKING` 从 `recon` 导入——那会反转依赖层） |
| `recon/_target_router_helpers.py` | 567 | `from strike.mcp.orchestrator import ...` | 改经 `core.target_factory.build_target`（S4） |
| `recon/target_builder.py` | 478 | `from strike.session import ...` | 改经 core 接缝（`SessionConfig` 下沉 `core` 或经 `build_target` 取用，S4） |
| `recon/adapters/__init__.py` | 54/58/62 | `from strike.targets.{mcp,rag,a2a} import ...` | 改经 `core.target_factory`（S4） |
| `core/*`（burp/playwright 解析件） | — | `parse_burp_request` / `get_playwright_handles` / `ParsedBurpRequest` 定义在 `recon` 却被 `core` 导入（`core→recon` ✗） | 迁至 `core`（或 `utils` 经 core 暴露），`recon` 侧改经 core 引用（S5，执行前 mini 调查定位定义点） |

> 矩阵本身（§2.2）**不改**：三对保持 ✗，本 CP 通过 core 中介接缝（`recon→core ✓`、`strike→core ✓`）消除裸跨层 import，使 ✗ 在零豁免下成立。

## 3. 影响面

- **触及的 REQ / DEBT / 不变量（I*）/ 红线（R-*）**：
  - REQ-151（**前置依赖**，非特性本体）；BL-082 ②、BL-090；
  - 不变量 IC-2（`build_adapter` / `build_target` 注册表唯一入口）；
  - 红线 R-IMPORT（40-G 1F 闭环判据：0 豁免）；R-EVENT-1/2（接缝只经 PipelineContext + EventLog 交接，本 CP 不引入新交接语义）。
- **guard 检查器**（C12 第 3 步）：
  - R-IMPORT 已由 `check_dependency_matrix()` 覆盖，**本 CP 不新增检查器**；仅删除豁免使三对回归 BLOCKING。
  - 删前须确认三对零违例（即 WIP 接缝已接线且无裸跨层 import）——否则删豁免会立刻触发 R-IMPORT BLOCKING。
- **同批义务**：
  - ① CP-009 §5 状态 `S6` 由 `⏸→REQ-151` 改为 `✅ DONE`（CP-012 已收口）；`S4/S5` 仍 `⏸→REQ-151`；
  - ② 40-GUARDRAILS 1F 登记簿若列了这 3 豁免则同步清掉；
  - ③ 新增 core 接缝文件头版本号 + `specs/README.md` 索引（D3 禁止文末版本表，版本史交 git log）。
- **迁移 / 兼容义务**：沿用 S2/S3/S7 的 re-export 模式保 intra-module 调用兼容；`strike.targets.__init__` / `recon.adapters.__init__` 导入期注册须**幂等**且**不引入启动期循环 import**（注册置于域包导入末尾，接缝模块绝不反向 import 域）。

## 4. ASR 影响评估

**中性**。依据：接缝模块（`core/target_factory`、`core/adapter_registry`）零攻击逻辑，仅持 `dict` 注册表（NEG-4：仅标准库 + typing）；本 CP 不改任何攻击/评分行为，仅重路由 import。安全红线 R-S* 不受影响（无授权边界变动）。无 ASR 升降。

## 5. 收口切片（每片 ≤3 文件，符 [sid:30-ch3] 粒度上限）

| 片 | 状态 | 动作 | 涉及文件 | 前置 |
|----|------|------|---------|------|
| **S4** | 🟡 部分（targets 经 factory 已闭环） | `recon/adapters:54/58/62` 已改经 `core.target_factory`（commit 87780f4）；余 `_target_router_helpers:567`（`get_shared_bridge`）/ `target_builder:478`（`SessionConfig`/`SessionStateManager`）待 core 接缝；**`("recon","strike")` 由 6→3** | `recon/*` + `core/target_factory.py` | S1 接缝已建 |
| **S5** | ⏸ mini 调查 | 定位 `ParsedBurpRequest` / `parse_burp_request` / `get_playwright_handles` 定义点，迁 `core`（或 `utils` 经 core），`recon` 侧改经 core 引用；**删 `("core","recon")` 豁免** | `core/*` + `recon/*` | 调查定义点 |
| **S6** | ✅ DONE（adapter registry 已闭环） | `recon/adapters` 注册补全（E402 已消）+ `strike/targets/*` 模块级经 `core.adapter_registry.get_adapter` 解析注解别名（F821 已消，`strike→core ✓`，未引入 `strike→recon`）+ `AgentCard` / `get_stealth_manager` / `get_tls_verify` 经 `register_adapter` 接线（`recon/adapters/__init__.py:242-244`）；**`("strike","recon")` 豁免已删，strike→recon 0 违例** | `core/adapter_registry.py` + `recon/adapters/__init__.py` + `strike/targets/{a2a,mcp,rag}.py` + `strike/{a2a,common}/*` | S1 接缝已建 |
| **闭环判据** | — | S6 豁免已删（剩 S4/S5 两对豁免待 REQ-151）；`tools.gate` R-IMPORT 0 违规（strike→recon 已清零）、WIP 现存 F821/E402 已消、各切片既有测试全绿 | — | — |

## 6. 风险与回滚

| 风险 | 缓解 |
|------|------|
| 注册表未导入即调用 → `KeyError` | 导入期注册 + 启动顺序约定（core 接缝先于域包）；unittest 覆盖 `register`/`build` 双向 |
| 循环 import | 接缝模块仅 stdlib+typing；注册置于域包导入末尾，绝不反向 import 域（保 `recon→core` / `strike→core` 单向） |
| 注解 F821 误修（把运行时 import 拉回 `recon`） | 仅加 `TYPE_CHECKING` 导入，不改运行时依赖方向 |
| 删豁免过早触发 R-IMPORT BLOCKING | 严格要求"先接线清零、后删豁免"；每片删豁免前跑 `tools.gate --stage commit` 验证 0 违规 |

## 7. 评审结论（2026-09-14 自动批准：用户授权全程自动批准符合最佳实践的方案）

- [x] 批准（附条件：须逐切片满足 [sid:30-ch3] 粒度 + `tools.gate` 全绿 + ASR 中性有据；S5 先完成 mini 调查再落地；不实现 PlaybookEngine 特性本体——其属 REQ-151 特性 plan）
- [ ] 驳回（理由：___）
- [ ] 转 backlog（BL-___）

评审人 / 日期：CodeBuddy（自动，依用户 2026-09-14 授权）/ 2026-09-14

## 8. 不做的事

- **不实现 PlaybookEngine 特性本体**：`config/playbooks/*.yaml`、`strike/playbook.py`、`tests/e2e/test_a2a_playbooks.py` 属 REQ-151 特性，非本 CP 范围（另立 REQ-151 特性 plan）；
- 不新建第二套链 / 第二套组件机制（C3）；
- 不顺手修超出三对豁免的其它 import（发现新问题一律进 backlog）；
- 不修 BL-081 注释乱码等无关项（另立专项）。
