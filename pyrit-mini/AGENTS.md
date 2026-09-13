# AGENTS.md — AI 编码代理唯一入口（跨 IDE / 跨模型）

> **本文件是入口，不是规则源。**
> 规则本体的唯一权威在 `docs/specs/` 规约金字塔（裁决序见 `docs/specs/00-CONSTITUTION.md` 第二章）。
> 本文件只做三件事：**① 指向冷启动入口 ② 约束"编辑规约的动作方式（how）" ③ 定义跨模型协作角色**。
> 任何冲突以规约金字塔为准（宪法 C3）；本文件不复制任何规则、命令、阈值与清单（文档纪律 D1）。
> **版本**：v1.1（2026-09-13 REV-1：① 冷启动顺序加 sid 稳定锚点并声明唯一定义处；② 新增 S7 机器校验纪律与 §4 锚点门禁；③ 版本史外置）
> **版本史**：`git log -- AGENTS.md`（文档纪律 D3，正文不维护）

---

## 1. 会话冷启动阅读顺序（必读，按顺序） [sid:agents-ch1]

> **本节是冷启动顺序的唯一定义处**：任何规约文档（含 `90-AI-DEV-ARCHITECTURE.md`）如需描述阅读顺序，
> 一律引用本节 sid，**不得另立一份顺序表**（D1；由 `python -m tools.spec_lint` 的 AI 入口唯一性检查守护）。

1. `docs/specs/README.md` [sid:readme-ch1] —— 规约金字塔唯一入口 + 门禁唯一表（[sid:readme-ch2]）
2. `docs/specs/90-AI-DEV-ARCHITECTURE.md` [sid:90-ch2] —— 产品契约 → 架构落点导航（[sid:90-ch3] 走流程）
3. `docs/specs/00-CONSTITUTION.md` [sid:00-ch0] —— 使命 + 裁决序 [sid:00-ch2] + C1–C14（Step 1 宪法自检）
4. `docs/specs/30-TASKS.md` [sid:30-ch4] —— 八步协议 / 粒度上限 [sid:30-ch3] / STOP-REPORT [sid:30-ch5] / 三栏汇报 [sid:30-ch6]
5. `docs/specs/10-ARCHITECTURE.md` 与 `docs/specs/20-REQUIREMENTS.md` 的相关章节（Step 2 落点 / Step 3 验收标准）

> **只加载与当前任务相关的文件，禁止"全读一遍"**（README [sid:readme-ch1] 规则）。

---

## 2. 编辑 `docs/specs/` 的硬纪律（本文件唯一新定义：AI 执行侧的 how） [sid:agents-ch2]

> **规则本体**：宪法 C4（最小变更）/ C5（先读后写）/ C11（停止权）+ README [sid:readme-ch5] 文档纪律 D1–D8 + [sid:readme-ch8] 边界说明。
> 本节**不复述**上述规则，只规定编辑动作本身。违反任一条 = STOP-REPORT（格式见 `docs/specs/30-TASKS.md` 第五章）。

| # | 纪律 | 判定（命中即违例） |
|---|------|------------------|
| S1 | **先读后写**：编辑任何规约文件前必须完整读取该文件（C5） | 编辑操作无对应前置读取记录 |
| S2 | **增量编辑**：一律定点替换（replace / patch）；**禁止整文件覆盖重写** | 一次编辑替换掉整个文件内容 |
| S3 | **禁止重排章节号**：不得为"编号连续"而对既有章节重编号；新增小节追加到所属章节末尾（如 `§4.4`），不位移既有编号 | diff 中出现全篇章节号位移 |
| S4 | **最小同步面**：只同步本次变更真正受影响的条目（文件头版本号 / README 索引行 / 检查器登记簿行）；禁止顺手重写无关段落 | diff 含与本次变更无关的段落改写 |
| S5 | **无占位符**：不留 `TASK-___` / `[CMD]` / `TODO` / `待填`（D7） | 文档出现未填实占位符 |
| S6 | **规模自检**：改动行数须与任务规模匹配；若发现自己正在重写整节 → 停止并输出 STOP-REPORT | 单文件 diff 远超任务所需（对照 30-TASKS [sid:30-ch3] 粒度上限） |
| S7 | **锚点不可破坏**：新增章节必须分配新 sid；禁止重排/回收既有 sid；禁止生成嵌套或粘连的 sid 锚点字面（一个 sid 括号里再嵌一个 sid 括号，或把文档正文吃进锚点） | `python -m tools.spec_lint` 出现 BLOCKING |

---

## 3. 跨模型协作：review-only 协议（C14 落地） [sid:agents-ch3]

> **触发条件与审查级别**：`docs/specs/60-CROSS-MODEL-VERIFICATION.md` [sid:60-ch3]（角色与落笔权见其 §4.4）
> **κ 阈值与动作**：`docs/specs/30-TASKS.md` [sid:30-ch10]
> **护栏强制力**：`docs/specs/40-GUARDRAILS.md` 1I-CROSS（R-CROSS-1~5）
>
> **协作三基石**（本项目的跨模型适配结论）：**稳定锚点**（sid，永不重排）/ **机器校验**（`tools.spec_lint` +
> `tools.gate`，规则可 `--describe` 自证）/ **统一 AI 入口**（本文件，跨 IDE 自动加载）。任一基石缺失，
> 换模型即重写整篇规约的概率显著上升。

| 角色 | 权限 | 产物 |
|------|------|------|
| **Author（落笔模型）** | 唯一允许编辑 `docs/specs/` 的角色；产出 patch | 文档/代码 diff + 修复回写 |
| **Reviewer（评审模型）** | **只读**；禁止编辑任何文件；只输出 findings JSON | `outputs/cross_model_review/{YYYYMMDD}-{change_id}/raw/{model}.json`（目录约定见 60 §6.1，Schema 见 60 §5.1） |
| **Human（人工）** | 终审、仲裁与合并裁决 | `adjudication/decision.json` + `summary.md` |

**硬规则**：

1. **禁止两个模型对同一份规约文件同时落笔** —— 互相覆盖是"换个模型就大幅重写"的主要来源。
2. **合并权只在 Author + 人工**：Reviewer 的 confirmed findings 由 Author 逐条修复，并回写到同一次 review 记录；Reviewer 不得直接改文件。
3. **降级**：可用模型 < 2 时按 R-CROSS-1 降级条款转**人工审查模式**，标记 `needs-cross-model-pending` 并登记 `docs/backlog.md`，不阻断合入。
4. **工具链现状**：`tools/cross_model_review.py` 已实施（5 检查器 R-CROSS-1~5，BL-042 已闭环）；当前为**人工编排模式**（审查记录由人工落地），存 `outputs/cross_model_review/`（入库例外 `!outputs/cross_model_review/`，满足 R-CROSS-3「永久保留」，BL-072 已闭环）。R-CROSS-1 在人工编排期降级为 WARNING、不阻断，标记 `needs-cross-model-pending`（与工具实现一致）。

---

## 4. 门禁（每次变更后强制，顺序固定） [sid:agents-ch4]

**命令唯一表见 README [sid:readme-ch2]**（本文件不抄写命令，D1）。统一入口：`python -m tools.gate`（commit 阶段）/ `python -m tools.gate --stage push`（pre-push / CI）；步骤清单以 `python -m tools.gate --describe` 为准。

**纪律**："改动很小"不豁免任何一步；guard 通过 ≠ 代码可用；门禁失败禁止标记任务完成（C10）。

**规约自检（0 `spec-lint` 步，本机可单跑）**：`python -m tools.spec_lint` 守护 sid 锚点完整性与改动规模；
`python -m tools.spec_lint --describe` 输出其全部规则。改 `docs/specs/` 后先跑它，再跑统一门禁。

---

## 5. 熔断（STOP-REPORT） [sid:agents-ch5]

出现规格含糊 / 未登记变更 / 超受影响文件清单 / 超粒度上限 / 红线风险 / 对"ASR 变高还是变低"无有据答案 —— 立即停止编码并输出 STOP-REPORT（格式见 `docs/specs/30-TASKS.md` [sid:30-ch5]）。

**猜着做 = 违宪；停下来问 = 合宪。**
