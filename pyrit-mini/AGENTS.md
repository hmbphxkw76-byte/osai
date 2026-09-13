# AGENTS.md — AI 编码代理唯一入口（跨 IDE / 跨模型）

> **本文件是入口，不是规则源。**
> 规则本体的唯一权威在 `docs/specs/` 规约金字塔（裁决序见 `docs/specs/00-CONSTITUTION.md` 第二章）。
> 本文件只做三件事：**① 指向冷启动入口 ② 约束"编辑规约的动作方式（how）" ③ 定义跨模型协作角色**。
> 任何冲突以规约金字塔为准（宪法 C3）；本文件不复制任何规则、命令、阈值与清单（文档纪律 D1）。
> **版本**：v1.0（2026-09-12 初版：入口指向 / S1–S6 编辑纪律 / review-only 协议）
> **版本史**：`git log -- AGENTS.md`（文档纪律 D3，正文不维护）

---

## 1. 会话冷启动阅读顺序（必读，按顺序）

1. `docs/specs/README.md` —— 规约金字塔唯一入口 + 门禁唯一表（§2）
2. `docs/specs/90-AI-DEV-ARCHITECTURE.md` —— 产品契约 → 架构落点导航（第三章走流程）
3. `docs/specs/00-CONSTITUTION.md` —— 使命 + 裁决序 + C1–C14（Step 1 宪法自检）
4. `docs/specs/30-TASKS.md` —— 八步协议 / 粒度上限 / STOP-REPORT / 三栏汇报
5. `docs/specs/10-ARCHITECTURE.md` 与 `docs/specs/20-REQUIREMENTS.md` 的相关章节（Step 2 落点 / Step 3 验收标准）

> **只加载与当前任务相关的文件，禁止"全读一遍"**（`docs/specs/README.md` §1 规则）。

---

## 2. 编辑 `docs/specs/` 的硬纪律（本文件唯一新定义：AI 执行侧的 how）

> **规则本体**：宪法 C4（最小变更）/ C5（先读后写）/ C11（停止权）+ `docs/specs/README.md` §5 文档纪律 D1–D7 + §8 边界说明。
> 本节**不复述**上述规则，只规定编辑动作本身。违反任一条 = STOP-REPORT（格式见 `docs/specs/30-TASKS.md` 第五章）。

| # | 纪律 | 判定（命中即违例） |
|---|------|------------------|
| S1 | **先读后写**：编辑任何规约文件前必须完整读取该文件（C5） | 编辑操作无对应前置读取记录 |
| S2 | **增量编辑**：一律定点替换（replace / patch）；**禁止整文件覆盖重写** | 一次编辑替换掉整个文件内容 |
| S3 | **禁止重排章节号**：不得为"编号连续"而对既有章节重编号；新增小节追加到所属章节末尾（如 `§4.4`），不位移既有编号 | diff 中出现全篇章节号位移 |
| S4 | **最小同步面**：只同步本次变更真正受影响的条目（文件头版本号 / README 索引行 / 检查器登记簿行）；禁止顺手重写无关段落 | diff 含与本次变更无关的段落改写 |
| S5 | **无占位符**：不留 `TASK-___` / `[CMD]` / `TODO` / `待填`（D7） | 文档出现未填实占位符 |
| S6 | **规模自检**：改动行数须与任务规模匹配；若发现自己正在重写整节 → 停止并输出 STOP-REPORT | 单文件 diff 远超任务所需（对照 30-TASKS 第三章粒度上限） |

---

## 3. 跨模型协作：review-only 协议（C14 落地）

> **触发条件与审查级别**：`docs/specs/60-CROSS-MODEL-VERIFICATION.md` §3.1（新增 §4.4 角色与落笔权）
> **κ 阈值与动作**：`docs/specs/30-TASKS.md` 第十章
> **护栏强制力**：`docs/specs/40-GUARDRAILS.md` 1I-CROSS（R-CROSS-1~5）

| 角色 | 权限 | 产物 |
|------|------|------|
| **Author（落笔模型）** | 唯一允许编辑 `docs/specs/` 的角色；产出 patch | 文档/代码 diff + 修复回写 |
| **Reviewer（评审模型）** | **只读**；禁止编辑任何文件；只输出 findings JSON | `outputs/cross_model_review/{YYYYMMDD}-{change_id}/raw/{model}.json`（目录约定见 60 §6.1，Schema 见 60 §5.1） |
| **Human（人工）** | 终审、仲裁与合并裁决 | `adjudication/decision.json` + `summary.md` |

**硬规则**：

1. **禁止两个模型对同一份规约文件同时落笔** —— 互相覆盖是"换个模型就大幅重写"的主要来源。
2. **合并权只在 Author + 人工**：Reviewer 的 confirmed findings 由 Author 逐条修复，并回写到同一次 review 记录；Reviewer 不得直接改文件。
3. **降级**：可用模型 < 2 时按 R-CROSS-1 降级条款转**人工审查模式**，标记 `needs-cross-model-pending` 并登记 `docs/backlog.md`，不阻断合入。
4. **工具链现状（勿按已落地引用）**：`tools/cross_model_review.py` 尚未实施，当前为**人工编排模式**；`outputs/` 被 `.gitignore` 忽略，审查记录不入库，与 R-CROSS-3「永久保留」存在冲突（已登记 BL-072）。

---

## 4. 门禁（每次变更后强制，顺序固定）

**命令唯一表见 `docs/specs/README.md` §2**（本文件不抄写命令，D1）。统一入口：`python -m tools.gate`（commit 阶段）/ `python -m tools.gate --stage push`（pre-push / CI）。

**纪律**："改动很小"不豁免任何一步；guard 通过 ≠ 代码可用；门禁失败禁止标记任务完成（C10）。

---

## 5. 熔断（STOP-REPORT）

出现规格含糊 / 未登记变更 / 超受影响文件清单 / 超粒度上限 / 红线风险 / 对"ASR 变高还是变低"无有据答案 —— 立即停止编码并输出 STOP-REPORT（格式见 `docs/specs/30-TASKS.md` 第五章）。

**猜着做 = 违宪；停下来问 = 合宪。**
