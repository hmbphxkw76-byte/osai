# backlog — 唯一待办池

> **规则**（30-TASKS 第八章 / 宪法 C4 豁免通道）：一行一条；登记时**不动代码**；AI 发现的任何非本任务问题一律进此处。
> **状态**：open / converted（转为 REQ / DEBT / 任务规格）/ discarded

| ID | 登记日期 | 内容 | 来源 |
|----|---------|------|------|
| BL-001 | 2026-09-05 | **外部锚点核对（最高优先，进入代码会话第一件事）**：REV-02 已完成文件级审计（@0b8e28c，仓库与六阶段结构吻合），剩余：① guard 18 项检查器逐一对锚（BL-003）；② SKILL.md（57KB）与 specs 的冲突条款清单；③ REQ-001~108/NFR-1~6 逐条运行时核验并回填 20-REQUIREMENTS 第七章状态表 | REV-01 评审 §五 → REV-02 更新 |
| BL-002 | 2026-09-05 | NFR-6 Python ≥3.13 与 PyRIT 1.0.1 官方支持矩阵核对；若 3.13 超出支持区间，按 NFR-6 硬边界以 PyRIT 区间为准并修订登记 | REV-01 P2-4 |
| BL-003 | 2026-09-05 | Guard 检查器登记簿锚定（40-GUARDRAILS 1D）：补齐 16→18 的差额 2 项，回填全部"待锚定"级别 | REV-01 P1-4 |
| BL-004 | 2026-09-05 | SKILL.md frontmatter 指向宪法（降位为 ⑤ 细则后收口） | 宪法第五章遗留迁移项 |
| BL-005 | 2026-09-05 | docs/implementation_checklist.md 并入 specs/templates/task-spec.md 后转存档 | 宪法第五章遗留迁移项 |
| BL-006 | 2026-09-05 | D-09 文档收敛：SKILL.md / docs/ 与 specs/ 职责重叠，按蓝图第八章消除方向执行 | 蓝图第八章 |
| BL-007 | 2026-09-05 | escalation.py vs escalation_chain.py 孪生 diff 确认（两文件仅差 9 字节）→ 执行 D-10 合并任务 | REV-02 审计 D-10 |
| BL-008 | 2026-09-05 | report/output.py docstring mojibake（UTF-8/GBK 混写）修复，随 D-16 工具链任务 | REV-02 审计 D-16 |
| BL-009 | 2026-09-05 | pyproject.toml：移除 ruff `exclude = [... "pipeline"]`、依赖钉 `pyrit==1.0.*`，随 D-16 工具链任务（路线图 T0-3） | REV-02 审计 D-16 |
| BL-010 | 2026-09-05 | data/seeds/asr_history.json 运行时产物迁出 git（→ outputs/），.gitignore 补齐（NEG-7），随 D-16 任务 | REV-02 审计 D-16 |
| BL-011 | 2026-09-05 | SKILL.md 本体收敛：实测 57KB/1400+ 行（宪法引用的 810 行为历史值），超出任何单会话可审计范围，须分章拆解迁移 | REV-02 审计 |
| BL-012 | 2026-09-05 | ~~Best-of-N stub 缺口~~ → 已升格为 REQ-004 内标注的 P0 缺口 + 路线图 T0-1 任务（保留此行作转化记录） | REV-02 审计 → converted |
