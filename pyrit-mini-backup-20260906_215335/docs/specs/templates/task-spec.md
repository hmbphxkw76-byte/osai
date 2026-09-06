# 任务规格：TASK-___（标题：一句话、动词开头，如"为 REQ-002 增加 XX 探针"）

> **类型**：标准任务 / **考试快速任务**（Exam Quick Task — OffSec AI-300 考试变体，使用 30-TASKS 第九章协议）
> **状态**：draft → spec'd → approved → in-progress → verified → closed / aborted
> **来源**：REQ-___ / DEBT-___ / bug 现象（描述）/ **考试模板（TPL-LLM/AGENT/MULTI/RAG/MCP/EMB）** / 其他（须先走 20-REQUIREMENTS 第五章登记，否则 STOP）
> **规格版本引用**：宪法 v___ 相关条款 / 蓝图 v___ 相关章节 / 需求 v___ 对应条目

**考试快速任务变体说明**（当类型 = 考试快速任务时填写）：
- **模板 ID**：TPL-___（对应 30-TASKS 9B 模板清单）
- **目标类型**：___（LLM/Agent/Multi-Agent/RAG/MCP/Embedding）
- **预计耗时**：___min（按 50-ROADMAP 8C Playbook 时间盒）
- **简化门禁**：跳过 Step 1（guard 静态检查），保留 Step 4（dry-run）+ Tier 2（真实攻击验证）

## 1. 背景与目标

（为什么做、要解决什么，3-5 句；bug 修复须含复现方式）

## 2. 蓝图落点（30-TASKS Step 2）

- **触及模块**（蓝图 2.1 九模块）：
- **依赖方向**（对照蓝图 2.2 矩阵，声明本次依赖是否合法）：
- **ctx 字段**（复用哪些；若新增，须先登记蓝图第四章表格）：
- **触及不变量**：I___ ——如何保证不破坏：

## 3. 验收标准（可勾选；抄自 20-REQUIREMENTS 对应 REQ；bug 修复自拟等价标准）

- [ ]
- [ ]

## 4. 受影响文件清单（diff 允许触碰的全部文件——C4 硬边界，清单外一律 STOP-REPORT）

| 文件 | 动作（改/增/删） | 预估行数 |
|------|----------------|---------|

**粒度自检**（30-TASKS 第三章，超任一即先拆分）：文件 ≤3 ｜ diff ≤300 行 ｜ 跨模块 ≤2 ｜ 新增文件 ≤1

## 5. 实施步骤（每步一个原子动作，完成即勾选）

- [ ]
- [ ]

## 6. ASR 影响评估（宪法第 0 条终极问题的有据回答）

（本变更让对 Burp 目标的 ASR 变高 / 变低 / 中性？依据是什么？涉及安全红线须标注 R-S* 编号）

## 7. 验证计划（C10 四步门禁，顺序固定）

- Step 1 `python core/architecture_guard.py --fix-hints`：0 新增 BLOCKING（基线：outputs/guard_baseline.json）
- Step 2 `ruff check core/ recon/ arm/ strike/ assess/ report/ targets/ utils/ main.py`：0 违规
- Step 3 `python -m pytest tests/ -v --tb=long`：0 失败
- Step 4 `python main.py --dry-run --max-seeds 1`：无 ImportError/AttributeError/KeyError/TypeError，到达 REPORT
- Tier 2（涉及攻击执行/评分/数据变换逻辑时）：**是 / 否** + 判定理由

## 8. 汇报（完成后按 30-TASKS 第六章三栏格式填写）

- ✅ 已完成并验证：（改动点 → 门禁证据；验收标准逐条勾选）
- ⚠️ 已完成但未验证：（差集及理由）
- ❌ 未完成 / 未做：（显式列出及原因）
- 附件：diff 统计（N 文件 / +A -B 行）；backlog 新增（BL-___）
