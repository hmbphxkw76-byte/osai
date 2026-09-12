# 开发全审快速参考卡（Dev Triad Checklist）

> **核心原则**：每次开发任务必须执行 **开发必看 → 开发必跑 → 开发必验** 完整流程，确保代码达到生产水准。

---

## 🔍 开发必看（开发前，5 分钟）

执行以下检查后再开始编码：

```markdown
□ 阅读相关 specs/ 文档（00-CONSTITUTION / 10-ARCHITECTURE / 20-REQUIREMENTS / 40-GUARDRAILS）
□ 确认任务涉及的宪法条款（C1~C15）
□ 确认任务涉及的护栏红线（R-L1~L8 / R-H1~H3 / R-NATIVE~R-CROSS）
□ 确认任务涉及的架构不变量（I1~I8）
□ 确认是否需要跨模型审查（P0/P1 任务需要）
```

**快速命令**：
```bash
# 查看宪法条款
py -c "from tools.guard import get_constitution_summary; print(get_constitution_summary())"

# 查看红线清单
py -m tools.guard --list-redlines
```

---

## 🏃 开发必跑（开发中，10 分钟）

每完成一个功能点，执行以下 7 步验证：

| 步 | 命令 | 通过标准 | 说明 |
|----|------|---------|------|
| 1 | `py -m tools.guard` | 0 BLOCKING | 架构守卫 |
| 1.5 | `python tools/architecture_validator.py full` | 0 BLOCKING | 架构体检 (组件感知流水线合规) |
| 2 | `ruff check .` | 0 errors | 代码风格 |
| 3 | `pytest tests/ -v --tb=short` | 0 failed | 单元测试 |
| 4 | `python main.py --dry-run --max-seeds 1` | 无异常 | 运行时验证 |
| 5 | `py -m tools.drift_detector --full` | 0 BLOCKING | 规范漂移 |
| 6 | `pytest tests/test_data_flow_integrity.py -v` | 全部通过 | 数据流完整性 |

**一键执行**：
```bash
# 保存为 scripts/dev_check_all.py 或手动顺序执行
py -m tools.guard && python tools/architecture_validator.py full && ruff check . && pytest tests/ -v --tb=short && python main.py --dry-run --max-seeds 1 && py -m tools.drift_detector --full && pytest tests/test_data_flow_integrity.py -v
```

**仅执行架构体检**：
```bash
# 方式1: 通过全审入口
py -m tools.dev_audit_full --phase b2

# 方式2: 直接运行
python tools/architecture_validator.py full
```

---

## ✅ 开发必验（开发后，5 分钟）

提交前逐项打勾：

### 代码质量
```markdown
□ 新增/修改文件 ≤ 800 行（R-SIZE）
□ 单一职责（R-H3）
□ 无 __main__ 块（R-TOOLS-1，仅 tools/tests/ 根目录允许）
□ 类型标注完整
□ 文档字符串完整
□ arXiv 引用（如涉及学术方法）
```

### 红线合规
```markdown
□ C1 PyRIT 原生优先（无自研替代）
□ C2 ASR 至上（无攻击端过滤）
□ C3 SSOT（无重复定义）
□ R-L1 攻击端无安全护栏
□ R-L2 无自定义 Executor/Target/Scorer
□ R-L3 无 Converter 串联堆叠
□ R-H1 无 stub/空实现
□ R-H2 无静默吞错
□ R-H3 无双轨新增
```

### 跨模型一致性（P0/P1 任务）
```markdown
□ C14 跨模型等价（输出相关性 r ≥ 0.85）
□ C15 多模型协议优先（分歧走三级仲裁）
□ R-CROSS-1 跨模型审查已执行
□ R-CROSS-2 分歧已仲裁
□ R-CROSS-3 一致性 ≥ 阈值
□ R-CROSS-4 报告已归档
□ R-CROSS-5 已知偏差已处理
```

### 测试覆盖
```markdown
□ 新增模块有对应测试文件
□ 测试覆盖核心功能路径
□ 所有测试通过
```

---

## 🚀 跨模型审查（可选，P0/P1 任务）

当任务需要跨模型一致性保证时：

```bash
# Step 1: 独立审查（在不同模型执行同一任务）
[CROSSMODEL_CMD] --task TASK-___ --model model_a
[CROSSMODEL_CMD] --task TASK-___ --model model_b

# Step 2: 差异比对
[CROSSMODEL_CMD] --diff results_a.json results_b.json

# Step 3: 计算一致性
[CROSSMODEL_CMD] --kappa results.json

# Step 4: 生成报告
[CROSSMODEL_CMD] --report REVIEW-___
```

**三级仲裁**：
- **Tier 1**：κ ≥ 0.6 → 自动合并
- **Tier 2**：κ < 0.6 → 升级第三方模型
- **Tier 3**：κ < 0.4 → 人工仲裁

---

## 📋 验收报告模板

```markdown
# 开发全审报告：TASK-___

## 开发必看
- [ ] 已阅读相关 specs/ 文档
- [ ] 已确认宪法条款和红线
- [ ] 已确认是否需要跨模型审查

## 开发必跑
- [ ] Step 1: py -m tools.guard → 0 BLOCKING
- [ ] Step 2: ruff check . → 0 errors
- [ ] Step 3: pytest tests/ → 0 failed
- [ ] Step 4: python main.py --dry-run → 无异常
- [ ] Step 5: py -m tools.drift_detector → 0 BLOCKING
- [ ] Step 6: pytest tests/test_data_flow_integrity.py → 全部通过

## 开发必验
- [ ] 代码质量 6 项全部通过
- [ ] 红线合规 9 项全部通过
- [ ] 跨模型一致性（如适用）7 项全部通过
- [ ] 测试覆盖完整

## 最终结论
- [ ] PASS — 达到生产水准，可合入
- [ ] FAIL — 需修复后重新验证
```

---

## 🔧 工具链速查

| 工具 | 命令 | 用途 |
|------|------|------|
| 架构守卫 | `py -m tools.guard` | 检查架构规则和红线 |
| 架构体检 | `python tools/architecture_validator.py full` | 组件感知流水线架构合规验证 |
| 代码风格 | `ruff check .` | 检查代码风格违规 |
| 单元测试 | `pytest tests/ -v` | 运行所有测试 |
| 运行时验证 | `python main.py --dry-run --max-seeds 1` | 验证无运行时异常 |
| 规范漂移 | `py -m tools.drift_detector --full` | 检查规约-代码一致性 |
| 数据流完整性 | `pytest tests/test_data_flow_integrity.py -v` | 验证端到端数据流 |
| Hooks 安装 | `py -m tools.install_hooks_local` | 安装 Git hooks |
| 开发全审 | `py -m tools.dev_audit_full` | 一键执行 B→B2→C→D→E→F→G→H 全审流程 |

---

## 📌 关键阈值

| 指标 | 阈值 | 说明 |
|------|------|------|
| BLOCKING | 0 | 架构守卫零容忍 |
| WARNING | ≤ 预存数量 | 不新增 WARNING |
| 测试失败 | 0 | 零容忍 |
| Cohen's Kappa | ≥ 0.6 | 跨模型一致性 |
| Pearson r | ≥ 0.85 | 跨模型相关性 |
| 文件行数 | ≤ 800 | R-SIZE 建议 |
| diff 行数 | ≤ 300 | 单次变更建议 |

---

*本参考卡自包含，可打印张贴或保存为 IDE 快捷方式。*
*版本：v1.0 | 更新：2026-09-09 | 维护者：pyrit-mini 红队团队*
