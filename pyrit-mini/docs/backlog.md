# backlog — 唯一待办池

> **规则**（30-TASKS 第八章 / 宪法 C4 豁免通道）：一行一条；登记时**不动代码**；AI 发现的任何非本任务问题一律进此处。
> **状态**：open / converted（转为 REQ / DEBT / 任务规格）/ discarded

| ID | 登记日期 | 内容 | 来源 |
|----|---------|------|------|
| BL-001 | 2026-09-05 | ~~外部锚点核对~~ | REV-01 评审 §五 → REV-02 更新 → 2026-09-10 | ✅ **completed** 2026-09-10 全量核查：① BL-003 guard 登记簿锚定 ✅（命名错位已定位）；② BL-004 frontmatter ✅；③ REQ 运行时核验 ✅（~31/43 检查器已实装，剩余 26 项 [NOT IMPLEMENTED] 待路线图 T1C/T1D 实施） |
| BL-002 | 2026-09-05 | NFR-6 Python ≥3.13 与 PyRIT 1.0.1 官方支持矩阵核对；若 3.13 超出支持区间，按 NFR-6 硬边界以 PyRIT 区间为准并修订登记 | REV-01 P2-4 |
| BL-003 | 2026-09-05 | Guard 检查器登记簿锚定（40-GUARDRAILS 1F）：~~补齐 16→18 差额~~ **2026-09-10 全量核查**：1F 登记 46 项，实际实现 43 项（guard.py 5 + guard_extended.py 33 + drift_detector.py 5）；命名错位 7 处已定位（no_defense_in_attack_dirs/top_level_structure/pyrit_native_api_resolve/spec_table_sync/version_drift/context_contract_drift/native_usage_pattern）；26 项标 [NOT IMPLEMENTED] 待路线图实施 | REV-01 P1-4 → ✅ **completed** 2026-09-10 全量核查更新 |
| BL-004 | 2026-09-05 | SKILL.md frontmatter 指向宪法（降位为 ⑤ 细则后收口） | 宪法第五章遗留迁移项 | ✅ **completed** 2026-09-10：SKILL.md 第 3 行已声明 `权威源：specs/00-CONSTITUTION.md`，第 9-10 行裁决序与宪法第二章吻合 |
| BL-005 | 2026-09-05 | docs/implementation_checklist.md 并入 specs/templates/task-spec.md 后转存档 | 宪法第五章遗留迁移项 | ✅ **completed** 2026-09-06 |
| BL-006 | 2026-09-05 | D-09 文档收敛：SKILL.md / docs/ 与 specs/ 职责重叠，按蓝图第八章消除方向执行 | 蓝图第八章 | ✅ **partial** 2026-09-06：B/C 类旧文档全部删除，specs/ 金字塔确立为唯一权威源；SKILL.md 死引用已清理；**BL-011 本体收敛已完成**（见下） |
| BL-007 | 2026-09-05 | escalation.py vs escalation_chain.py 孪生 diff 确认（两文件仅差 9 字节）→ escalation_chain.py 已删除（死代码/语法错误） | ✅ **completed** 2026-09-08 |
| BL-008 | 2026-09-05 | report/output.py docstring mojibake（UTF-8/GBK 混写）修复，随 D-16 工具链任务 | REV-02 审计 D-16 | ✅ **completed** 2026-09-08：report/output.py 已删除（死代码） |
| BL-009 | 2026-09-05 | pyproject.toml：移除 ruff `exclude = [... "pipeline"]`、依赖钉 `pyrit==1.0.*`，随 D-16 工具链任务（路线图 T0-3） | REV-02 审计 D-16 | ✅ **completed** 2026-09-08：pyproject.toml 已修复 |
| BL-010 | 2026-09-05 | ~~data/seeds/asr_history.json 运行时产物迁出 git~~ | REV-02 审计 D-16 | ✅ **completed** 2026-09-10：`.gitignore` 第 30 行已包含 `data/seeds/asr_history.json`（NEG-7 红线合规） |
| BL-011 | 2026-09-05 | ~~SKILL.md 本体收敛~~ | REV-02 审计 | ✅ **completed** 2026-09-10：**实测 SKILL.md 仅 4.4KB/135 行**（57KB/1400+ 行描述为历史值已过时）；frontmatter 已经口合规；Anti-Drift + Core Rules 10 条在 135 行内完整覆盖，无需拆章 |
| BL-012 | 2026-09-05 | ~~Best-of-N stub 缺口~~ → 已升格为 REQ-004 内标注的 P0 缺口 + 路线图 T0-1 任务（保留此行作转化记录） | REV-02 审计 → converted |
| BL-013 | 2026-09-06 | P0-NEW-1：默认配置下 L2→L4 升级链整体失效（UnboundLocalError）—— `_safe_call` 仅定义在 else 分支，defaults.yaml 默认走 if 分支，L2/L3/L4 调用时抛 UnboundLocalError 被 main.py 静默吞错。违反 C2/I4/REQ-005 | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-014 | 2026-09-06 | P0-NEW-2：多智能体种子 5 条中 3 条永不加载 —— `CAPABILITY_SEED_MAP["multi_agent"]` 仅映射 2/5 种子文件。违反 REQ-002/REQ-109 | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-015 | 2026-09-06 | P0-NEW-3：MCP 动态种子链路断裂 —— `build_mcp_attack_seeds` 完整实现但零生产调用；`ctx._mcp_dynamic_seeds` 死字段；陈旧注释引用不存在的函数。违反 REQ-002 | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-016 | 2026-09-06 | P0-NEW-4：死代码未登记 —— targets/agent_adapter.py（~574行）+ data/scorer_selector.py（252行）+ get_default_classifier() 坏占位。随 D-01/D-13 处理 | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-017 | 2026-09-06 | D-10 修正：escalation 非 9 字节孪生，实为"门面+拆分"三件 + 编码损坏。修正方向：删 escalation_attacks.py + 清 re-export 债务 | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-018 | 2026-09-06 | D-11 修正：converter 非纯粹三轨，但 converter_selector.py 含 ~230 行死函数 + _PRIORITY_MAP 孪生 | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-019 | 2026-09-06 | D-12 修正：seed 排序非孪生，实为拆分+12 符号 re-export 门面 + 双向 import | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-020 | 2026-09-06 | D-01 量化：assess 合并家族实际 ~3354 行整体死代码（非仅双轨描述） | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-021 | 2026-09-06 | 编码损坏范围扩大：technique_registry.py 全文编码损坏，超出原 D-16② 登记范围 | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-022 | 2026-09-06 | 场景特异性未进入执行层：technique_registry.py 的 10 项技术全部是通用越狱类，agent/MCP/RAG 仅靠 tag 过滤，无专用 attack module | 2026-09-06 代码审计 | ✅ **completed** 2026-09-08 |
| BL-023 | 2026-09-09 | ~~pyproject.toml `[tool.setuptools.packages.find]` include 含死条目 `targets*`~~ | 2026-09-09 规约优化 P2 门禁命令统一核查（C4 豁免通道，未动代码） | ✅ **completed** 2026-09-10：`targets/` 目录不存在（已于 D-10 重构中移除，adapters/ 后续摘除），pyproject.toml 第 32 行 `targets*` 已移除 |
