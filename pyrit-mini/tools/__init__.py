"""
tools/ - CLI 开发/运维工具目录

存放所有带 `if __name__ == "__main__"` 的脚本/工具入口。
这些工具不属于攻击流水线运行时，而是面向开发者/红队操作员的辅助工具。

架构原则 (R-TOOLS-1):
    - `tools/` 集中管理所有 CLI 入口（宪法守卫、hooks 安装、场景列表、PoC 生成）
    - `core/` 禁止存放带 `__main__` 的脚本（纯业务逻辑）
    - `utils/` 禁止存放带 `__main__` 的脚本（纯运行时工具函数）

================================================================================
【三元组开发规范】— 最精简记忆方案，3 个词覆盖开发全生命周期
================================================================================

  触发词（三选一）：
    "开发规范" = "开发必看"  → 开发前：查看 宪法/蓝图/需求/红线，了解规则
    "开发验证" = "开发必跑"  → 开发中：跑 6 步检查 + 自动修复
    "开发交付" = "开发必验"  → 开发后：跑交付标准验收清单

  同义词：
    "完整验证" / "规范对齐" = "开发验证" = "开发必跑"
    "开发规范" = "开发必看"
    "开发交付" = "开发必验"

▌开发规范覆盖的文档（开发前必看）：
    00-CONSTITUTION  → AI 行为宪法、裁决序、C1-C12 条款
    10-ARCHITECTURE  → 分层依赖、ctx 契约、不变量、数据流完整性
    20-REQUIREMENTS  → P0/P1/P2 需求、NFR、NEG 状态
    30-TASKS         → 任务生命周期、八步协议
    40-GUARDRAILS    → 红线清单、四步门禁、三层防线
    50-ROADMAP       → 任务序列、会话模型
    55-ATTACK-GAP    → 攻击缺口闭环状态

▌开发验证覆盖的工具（开发中必跑）：
    tools/guard.py              → 架构守卫（静态检查）
    tools/drift_detector.py     → 规范漂移检测
    tools/dataflow/              → 数据流完整性子包
    ruff check .                → 代码风格
    pytest tests/               → 全量测试
    python main.py --dry-run    → 运行时验证

▌开发交付覆盖的标准（开发后必验）：
    40-GUARDRAILS 第七章        → 交付验证清单格式
    templates/task-spec.md      → 任务验收标准
    backlog.md                  → 待办闭环

▸ 核心操作（必记）
    "组件审计"              → 执行 Phase 1→6 全流程组件审计 (py -m tools.component_audit)
    "架构审计" / "架构体检" → 执行架构合规验证 (python tools/architecture_validator.py full)
    "开发全审" / "全审"     → 执行 A→L 开发全审 (py -m tools.dev_audit_full)
    "完整验证" / "规范对齐" → 执行 6 步全流程验证 + 修复所有问题
    "门禁"                  → 执行四步质量门禁 (guard/ruff/pytest/dry-run)
    "守卫"                  → 运行架构守卫静态检查 (py -m tools.guard)
    "漂移"                  → 运行规范漂移检测 (py -m tools.drift_detector)
    "数据流"                → 运行数据流完整性验证
    "交付标准"              → 按 40-GUARDRAILS 第七章格式生成验收清单

▸ 开发流程
    "领任务"                → 从 50-ROADMAP 查看下一个任务
    "任务规格"              → 生成 TASK-xxx 规格文件
    "宪法"                  → 查看 00-CONSTITUTION 核心条款
    "蓝图"                  → 查看 10-ARCHITECTURE 架构设计
    "需求"                  → 查看 20-REQUIREMENTS 需求状态
    "红线"                  → 查看 40-GUARDRAILS 红线清单

▸ 快速检查
    "lint"                  → ruff check . 代码风格检查
    "dry-run"               → python main.py --dry-run 运行时验证
    "测试"                  → pytest tests/ 运行测试
    "backlog"               → 查看/登记待办池
    "hooks"                 → 安装/检查 git hooks

▸ 考试场景
    "考试模式"              → 切换为 OffSec AI-300 考试流程
    "考试合规"              → 运行 7D 定期自检
    "模板"                  → 查看攻击模板速查表 (TPL-*)

================================================================================

【完整验证详细流程】— "完整验证" / "规范对齐" 触发:

    1. py -m tools.guard                    — 架构守卫静态检查 (0 BLOCKING)
    2. ruff check .                         — 代码风格检查 (0 errors)
    3. pytest tests/ -v --tb=short          — 全量测试 (0 failed)
    4. python main.py --dry-run --max-seeds 1 — 运行时数据流验证
    5. py -m tools.drift_detector --full    — 规范漂移检测 (0 BLOCKING)
    6. pytest tests/test_data_flow_integrity.py -v — 数据流完整性验证

自动修复策略:
    - ruff 可修复问题 → 自动 ruff check --fix
    - BLOCKING 违规 → 分析并修复代码
    - 测试失败 → 区分预存问题 vs 新引入问题
    - 漂移检测 → 同步文档/代码引用

================================================================================

调用方式:
    py -m tools.component_audit     # 组件审计 Phase 1→6 (全组件纯净度/覆盖度/种子验证)
    py -m tools.dev_audit_full     # 开发全审 A→H (同 架构审计 / 架构体检)
    py -m tools.guard              # 宪法守卫 (含 quick_check + watch_guard 功能)
    py -m tools.guard --quick file.py  # 单文件快速检查
    py -m tools.guard --watch      # 实时文件监视
    py -m tools.hooks              # Git hooks 安装 (含 --local 模式)
    py -m tools.scenarios          # 场景列表 (原 py -m core.scenario_router)
    py -m tools.poc                # PoC 生成器 (CLI 模式)
    py -m tools.dataflow.validator  # ARM→Strike→Assess 数据流完整性验证
    py -m tools.drift_detector     # 规范漂移检测器 (v2.1 新增)

对应 entry_points (pyproject.toml):
    pyrit-component-audit = "tools.component_audit:main"
    pyrit-dev-audit = "tools.dev_audit_full:main"
    pyrit-guard = "tools.guard:main"
    pyrit-hooks = "tools.hooks:main"
    pyrit-scenarios = "tools.scenarios:main"
    pyrit-poc = "tools.poc:main"
    pyrit-dataflow = "tools.dataflow.validator:main"
    pyrit-drift = "tools.drift_detector:main"

快捷词组映射 (AI Code 触发词):
    "组件审计"              → py -m tools.component_audit
    "架构审计" / "架构体检" → py -m tools.dev_audit_full
    "开发全审" / "全审"     → py -m tools.dev_audit_full
"""
