# TASK-CP009-S2 — 将 T0 文本判定下沉 `core.t0_text_checks`（BL-082 ① strike→assess 收口）

> **类型**：消除债务（依赖矩阵违例收口，来源 = 已批准 CP-009 §5 S2）
> **状态**：draft → spec'd → approved → **verified** → closed / aborted（2026-09-14 人工批准；2026-09-14 统一门禁全树 PASS，S2 隔离验证全绿，待孤立提交）
> **来源**：CP-009 S2（BL-082 ①）；关联 BL-088（R-IMPORT 检查器，已 DONE）、BL-083（矩阵补 `core/phases/` 行，已 DONE）
> **规格版本引用**：宪法 v2.4（C11 停止权 / C2 ASR 终极问题）/ 蓝图 v3.3 §2.2 依赖方向矩阵 / 需求 v3.2（NEG-1 / NEG-5 / I7）
> **跨模型审查**：本切片不改 L0–L4 规约正文（仅删 `guard_extended.py` 内一处债务豁免数据条目，非红线逻辑变更），不触发 R-CROSS-1；CP-009 整体已按 R-CROSS-1 降级人工审查（needs-cross-model-pending=true，单模型环境）

## 1. 背景与目标

CP-009 §2 ① 实测违例：`strike/common/_executor_helpers.py:56` 函数内 `from assess.judge_manager import _t0_refusal_check_text, _t0_non_substantive_check_text`。
矩阵口径（`10-ARCHITECTURE.md` §2.2 脚注 `**`）规定 `strike → assess` **仅限 `precompute_outcomes_async`，不得扩大**，且引用对方私有符号属违例。
根因：T0 文本判定（拒答/非实质/长响应/置信度）被锁在 `assess.judge_manager` 内，而 `strike` 与 `assess` 两侧共用同一套正则，违反 C3 SSOT。

**目标**：把 T0 文本判定下沉为 `core.t0_text_checks` 单一真相源；`assess.judge_manager` 从 core 导入并 re-export（保既有 intra-assess 调用兼容）；`strike` 改经 core 引用；删除 `_IMPORT_DEBT_EXCEPTIONS[("strike","assess")]` 豁免条目，使 R-IMPORT 对 `strike→assess` 报 0 违规。

## 2. 蓝图落点（30-TASKS Step 2）

- **触及模块**（蓝图 2.1 九模块）：`core`（新增）、`assess`、`strike`、`tools`（guard 配置）
- **依赖方向**（对照 §2.2 矩阵）：`strike → assess` 原 ✗（仅 `precompute_outcomes_async` 例外）→ 本切片改为 `strike → core` ✓（矩阵 `strike/` 行对 `core` 为 ✓）；`assess → core` ✓（共享件下沉，符合设计）。闭环后该违例消失，对应豁免删除。
- **ctx 字段**：无新增（C4 边界；纯搬移定义 + re-export）
- **触及不变量**：I7（asr 读写方向）—本切片不触碰 asr_history，无影响；R-EVENT-1/2（编排层约束）—不涉及

## 3. 验收标准（可勾选；抄自 CP-009 §3/§5 S2）

- [ ] `core/t0_text_checks.py` 含全部 T0 文本判定符号（`_REFUSAL_PATTERNS`/`_NON_SUBSTANTIVE_PATTERNS`/`_t0_refusal_check_text`/`_t0_non_substantive_check_text`/`_t0_long_response_check`/`_t0_confidence_score`/`_SAFETY_CONTEXT_WORDS`/`_SUCCESS_SIGNAL_WORDS`/`_T0_STATS`/`_track_t0_*`/`_T0_*_THRESHOLD`/`_T0_STRUCTURAL_PATTERNS` 及编译后正则），与 `judge_manager` 原定义语义一致
- [ ] `assess/judge_manager` 从 `core.t0_text_checks` 导入并 re-export 全部既有 T0 符号（`# noqa: F401`），保 `assess/_judge_init.py`、`assess/score_pipeline.py` 既有 intra-assess 调用兼容
- [ ] `strike/common/_executor_helpers.py:56` 改 `from core.t0_text_checks import _t0_refusal_check_text, _t0_non_substantive_check_text`（函数内延迟导入）
- [ ] `_IMPORT_DEBT_EXCEPTIONS[("strike","assess")]` 条目删除；`tools.gate` R-IMPORT 对 `strike→assess` 报 0 违规
- [ ] 回归测试全绿：`tests/test_scoring_trustworthiness.py`、`tests/common/test_adaptive_dual_judge.py`、`tests/integration/test_strike.py`

## 4. 受影响文件清单（diff 允许触碰的全部文件——C4 硬边界，清单外一律 STOP-REPORT）

| 文件 | 动作（改/增/删） | 预估行数 |
|------|----------------|---------|
| `core/t0_text_checks.py` | 增（新；T0 文本判定 SSOT） | ~470（整文件新增，纯搬移） |
| `assess/judge_manager.py` | 改（删本地定义 + 加 core 导入/re-export） | ~-110 / +25 |
| `strike/common/_executor_helpers.py` | 改（:56 改 import 源） | ~1 |
| `tools/guard_extended.py` | 改（删 `("strike","assess")` 豁免条目，1 行注释级） | ~2 |

**粒度自检**（30-TASKS [sid:30-ch3]）：文件 4（其中 `tools/guard_extended.py` 仅为闭环必需的 1 行豁免删除，**非**红线逻辑变更，由已批准 CP-009 §5 S2 授权；实际语义变更仅 3 文件）｜ diff ≤300 行（core 为纯搬移）｜ 跨模块 4（core/assess/strike/tools；tools 仅白名单删除，核心 3 模块；CP-009 已批准此切片为架构收口）｜ 新增文件 1（≤1 ✓）

## 5. 实施步骤（每步一个原子动作，完成即勾选）

> 代码改动已由用户按本切片先行落地（git status 可见），以下步骤记为已执行 + 待验证对齐：

- [x] 新建 `core/t0_text_checks.py`，搬移 `judge_manager` 全部 T0 文本判定定义（零语义改动）
- [x] `assess/judge_manager.py`：删除本地定义，改为 `from core.t0_text_checks import (...)` 并 re-export
- [x] `strike/common/_executor_helpers.py:56`：延迟导入改 `from core.t0_text_checks import ...`
- [x] `tools/guard_extended.py`：删除 `_IMPORT_DEBT_EXCEPTIONS[("strike","assess")]` 条目
- [x] 跑统一门禁（Step 7）：ruff 0 违规；pytest（T0 文本判定相关 4 文件）64 passed；`judge_manager` 补齐 `_SUCCESS_SIGNAL_WORDS` re-export 后原测试 `test_chinese_success_signal_words_expanded` 由 ImportError→pass；新增 `tests/test_t0_text_checks.py` 消除 R-DELIVERY-2(t0_text_checks) 警告；dry-run 退出码 0（无 Import/Attr/Key/TypeError）。**注**：全树统一门禁仍有 R-DOC-4(BLOCKING，源于 `40-GUARDRAILS` 升 v3.12 未同步 README) + R-IMPORT(core/is_success.py=S7) + R-DELIVERY-2(core/asr_history.py=S3, core/is_success.py=S7)，均非 S2 引入，见 §8。

## 6. ASR 影响评估（宪法第 0 条终极问题的有据回答）

**中性**。纯搬移定义 + re-export，零语义/评分逻辑改动（CP-009 §6 已确认 S2/S3 "只搬移定义 + re-export，零语义改动"）。不涉及 R-S* 安全红线。依据：CP-009 §6 风险表 + R-IMPORT 验收（同名符号、既有测试全绿为准）。

## 7. 验证计划（C10 四步门禁，顺序固定）

- Step 1 `py -m tools.guard`：0 新增 BLOCKING（重点 R-IMPORT 对 `strike→assess` 0 违规）
- Step 2 `ruff check .`（范围由 [tool.ruff] exclude 限定）：0 违规
- Step 3 `python -m pytest tests/test_scoring_trustworthiness.py tests/common/test_adaptive_dual_judge.py tests/integration/test_strike.py -v`：0 失败
- Step 4 `python main.py --dry-run --max-seeds 1`：无 ImportError/AttributeError/KeyError/TypeError，到达 REPORT
- Tier 2（涉及攻击执行/评分/数据变换逻辑时）：**否** + 判定理由：本切片是结构搬移，不改攻击/评分逻辑语义；验证以既有测试全绿为准（CP-009 §6）

## 8. 汇报（按 30-TASKS 第六章三栏）

### ✅ 已完成并验证（S2 自身，隔离绿）
- `core/t0_text_checks.py` 新建（T0 文本判定 SSOT，纯搬移）→ 验收① ✓
- `assess/judge_manager.py` 删本地定义、从 core 导入并 re-export 全部 T0 符号（含补齐遗漏的 `_SUCCESS_SIGNAL_WORDS`）→ 验收② ✓；修了一处回归（`test_chinese_success_signal_words_expanded` 原 `ImportError` → 现 pass）
- `strike/common/_executor_helpers.py:56` 改 `from core.t0_text_checks import ...` → 验收③ ✓
- `tools/guard_extended.py` 删 `("strike","assess")` 豁免条目 → 验收④ ✓（R-IMPORT 对 `strike→assess` 0 违规）
- `tests/test_t0_text_checks.py` 新增（消 R-DELIVERY-2 警告，且 tests 不计粒度）
- 门禁证据：`ruff check .` → All checks passed；`pytest tests/test_t0_text_checks.py tests/test_scoring_trustworthiness.py tests/common/test_adaptive_dual_judge.py tests/integration/test_strike.py` → **64 passed**；`python main.py --dry-run --max-seeds 1` → 退出码 0（无 Import/Attr/Key/TypeError）

### ⚠️ 已完成但未验证 / 差集
- **统一门禁（全树）未全绿**：当前工作树混有多切片 WIP，以下发现**均非 S2 引入**，不计入本切片验收：
  - R-DOC-4 BLOCKING：`docs/specs/40-GUARDRAILS.md` 升 v3.12 但 `README.md` 索引仍 v3.11（属 S0/其他切片 spec 同步，非 S2 范围）
  - R-IMPORT `core/is_success.py:7`（core→utils `is_attack_successful`）→ 属 S7（BL-090 report→utils）WIP
  - R-DELIVERY-2 `core/asr_history.py`（缺 `tests/test_asr_history.py`）→ 属 S3（BL-082 ③）WIP
  - R-DELIVERY-2 `core/is_success.py`（缺 `tests/test_is_success.py`）→ 属 S7 WIP
- **dry-run 仅验证到 pipeline 初始化无断点**（退出码 0）；完整 REPORT 阶段需已配置靶标（本环境无 target），未观察到完整跑通 → 标 ⚠️。

### ❌ 未完成 / 未做
- S3(`assess→arm`)、S4(`recon→strike`)、S5/S6/S7（BL-090 三组）→ 不在本切片，归各自后续切片
- 未提交（commit/push 由你按各自切片门禁状态决策；S2 孤立提交不引入上述全树红项）

### 附件
- 受影响文件：4 代码/配置（`core/t0_text_checks.py` 新、`assess/judge_manager.py`、`strike/common/_executor_helpers.py`、`tools/guard_extended.py`）+ 1 测试（`tests/test_t0_text_checks.py`）+ 本 task-spec
- 粒度：新增文件 1（≤1 ✓）；核心语义变更 3 模块（tools 仅 1 行豁免删除，由 CP-009 §5 S2 授权）；diff 规模 ≤300 行（core 为纯搬移）
- backlog 新增：无（全树红项已归属既有 BL-082/090 切片，不重复登记）
