# PyRIT-Strike 实施前检查清单模板

> **文档定位**: 每次代码变更前必须填写此清单，确保变更不偏离架构目标
> **使用方式**: 复制此模板，填写所有字段，在对话中展示后再开始编码
> **强制级别**: MANDATORY — 未填写清单即开始编码 = 架构违规
> **最后更新**: 2026-08-31

---

## 使用说明

1. **每次代码变更前**复制此模板到对话中
2. 填写所有 `[待填]` 字段 — 不允许留空
3. 在对话中展示完整清单
4. 获得确认后再开始编码
5. 编码过程中逐项勾选 `[x]`
6. 编码后运行 `architecture_guard.py` 验证

---

## 检查清单模板

### 变更目标

- **变更描述**: [待填 — 一句话描述要做什么]
- **主要指标**: [待填 — ASR / 攻击延迟 / 种子覆盖 / 升级效率 / 架构合规]
- **预期影响**: [待填 — 如 "+15% ASR on OWASP LLM01-10" 或 "修复 R10 串联堆叠违规"]
- **关联需求**: [待填 — 对应 RTM 矩阵的哪一行]

### 受影响文件 (必须列出所有文件)

- [ ] `strike/xxx.py` — [变更内容: 如 "修复 ConverterConfiguration 串联堆叠"]
- [ ] `arm/xxx.py` — [变更内容: 如 "新增 Converter 路径定义"]
- [ ] `config/defaults.yaml` — [变更内容: 如 "新增参数"]
- [ ] `tests/test_xxx.py` — [变更内容: 如 "新增对应测试"]
- [ ] (列出所有文件，不允许遗漏)

### 实施步骤 (编号，粒度细到每步可独立验证)

1. [ ] Step 1: [具体动作 — 如 "将 `converters=[conv1, conv2]` 改为两个独立的 `converters=[conv1]` + `converters=[conv2]`"]
2. [ ] Step 2: [具体动作 — 如 "在 `technique_registry.py` 中添加 `from pyrit.executor.attack import SkeletonKeyAttack`"]
3. [ ] Step 3: [具体动作]
4. [ ] (继续 — 必须覆盖所有变更)

### 规则合规预检 (编码前必须验证)

- [ ] **R1**: 此变更提升 ASR 或攻击效率 (攻击者视角)
- [ ] **R2**: 使用 PyRIT 原生组件 (不自研替换) — 或 enhancement wrapper 包装原生
- [ ] **R2**: 已搜索 PyRIT 源码确认无等价原生组件
- [ ] **R2 §2.1**: 终端展示优先调用 `output_scenario_async` / `output_attack_async` + `StdoutSink` (原生优先, 自研卡片为增强)
- [ ] **R2 §2.1**: 不手动提取 prompt/response 文本替代原生 output 渲染
- [ ] **R3**: 所有参数对齐 L5 基线 (`config/defaults.yaml`)
- [ ] **R5**: 新技术/参数有 arXiv 引用
- [ ] **R6 §6.1**: 每个 `ConverterConfiguration` 包含恰好 1 个 converter (禁止串联)
- [ ] **R6 §6.2**: 攻击执行路径中使用 0-token 评分器 (SubStringScorer + Inverter)
- [ ] **R6 §6.4**: 使用 PyRIT 原生攻击策略 (不自研 Executor)
- [ ] **R6 §6.4a**: 每个攻击类已实例化 (不只是导入)
- [ ] **R6 §6.4b**: 攻击参数从 `config/defaults.yaml` 读取 (不硬编码)
- [ ] **R7**: 效率参数 (中间退出阈值、级联跳过) 在 `defaults.yaml` 中定义, 不硬编码
- [ ] **R7**: 中间退出检查点存在于 L1→L2 和 L2→L3 边界
- [ ] **R8 §8.1**: 多 endpoint 模式下 `--stage` 退出点使用 `exclude_shared=True`
- [ ] **R8 §8.2**: 异常处理有 fallback (partial results 保留, 不中断流水线)
- [ ] **R8 §8.3**: 全局变量有 `_reset_*()` 函数, 多 endpoint 循环开始时调用
- [ ] **R8 §8.4**: 空输入边界条件防御 (seeds/attack_results/endpoint 列表)
- [ ] **R8 §8.5**: 编排日志覆盖所有 6 阶段 (recon+arm+strike+escalate+assess+report)
- [ ] **R8 §8.6**: 并发数从 `get_effective_concurrency(ctx)` SSOT 读取, 不硬编码
- [ ] **R9 §9.1**: 所有效率参数通过 `getattr(ctx.args, ...)` 读取 (不直接赋值)
- [ ] **R9 §9.2**: 需要配置的函数有 `ctx` 参数 (不硬编码 fallback)
- [ ] **R9 §9.3**: 日志/报告描述引用运行时 `ctx.args` 值 (不硬编码数字)
- [ ] **R10**: 变更后运行 `python main.py --dry-run --max-seeds 1` 验证流水线完整性
- [ ] **R10**: 如攻击/评分逻辑变更, 运行 `python main.py --max-seeds 1` 真实验证
- **变更后的 `architecture_guard.py` 不会新增 BLOCKING 违规

### 架构守护脚本预检

```bash
# 编码前运行，记录当前违规基线
python core/architecture_guard.py --json > architecture_baseline.json
```

- 当前 BLOCKING 违规数: [待填]
- 当前 WARNING 违规数: [待填]
- 变更后预期 BLOCKING 违规数: [待填 — 必须 ≤ 当前]
- 变更后预期 WARNING 违规数: [待填 — 必须 ≤ 当前]

### 风险评估

- **可能破坏什么**: [待填 — 如 "现有 converter 链测试可能需要更新"]
- **缓解措施**: [待填 — 如 "Step 2 后立即运行全量测试"]
- **回退方案**: [待填 — 如 "git stash + 恢复 arm/converter_selector.py 原始逻辑"]

### 变更后验证 (编码完成后执行)

```bash
# Step 1: 架构守护脚本 (必须 0 新增 BLOCKING)
python core/architecture_guard.py --fix-hints

# Step 2: ruff 检查
ruff check core/ recon/ arm/ strike/ assess/ report/ targets/ utils/ main.py

# Step 3: pytest 全量测试 (如果 tests/ 存在)
python -m pytest tests/ -v --tb=long

# Step 4: 临时文件清理
# PowerShell:
# Get-ChildItem -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
# Get-ChildItem -Recurse -Directory -Filter ".pytest_cache" | Remove-Item -Recurse -Force
# Get-ChildItem -Recurse -Directory -Filter ".ruff_cache" | Remove-Item -Recurse -Force
```

- [ ] `architecture_guard.py` 无新增 BLOCKING 违规
- [ ] `ruff check` 零违规
- [ ] `pytest` 零失败
- [ ] `__pycache__` 已清理

---

## 示例：已填写的检查清单

> 以下是一个实际示例，展示如何填写此模板。

### 变更目标

- **变更描述**: 修复 `arm/converter_selector.py:411` 的 Converter 串联堆叠违规
- **主要指标**: 架构合规 (R10 BLOCKING → 0)
- **预期影响**: 消除 architecture_guard 的 BLOCKING 违规
- **关联需求**: RTM 矩阵 Section 4, 路径 "违规" 行

### 受影响文件

- [ ] `arm/converter_selector.py` — 将 `converters=[conv1, conv2]` 拆分为两个独立 `ConverterConfiguration`
- [ ] `docs/requirement_traceability_matrix.md` — 更新 Section 4 状态从 FAIL → PASS

### 实施步骤

1. [ ] Step 1: 读取 `arm/converter_selector.py` 第 400-440 行
2. [ ] Step 2: 将 `ConverterConfiguration(converters=[best_converter, unique_converters[1]])` 改为两个独立的 `ConverterConfiguration`
3. [ ] Step 3: 更新日志输出，反映两个独立路径而非串联
4. [ ] Step 4: 运行 `python core/architecture_guard.py --rule R10` 验证违规消除

### 规则合规预检

- [x] **R1**: 修复串联堆叠恢复 ASR (12%→4% 问题消除)
- [x] **R2**: 使用 PyRIT 原生 `ConverterConfiguration`
- [x] **R3**: 不涉及参数变更
- [x] **R7**: arXiv:2307.15043 — 串联 >2 层 ASR 降级
- [x] **R8**: 不新增文件
- [x] **R10**: 变更后每个 `ConverterConfiguration` 包含恰好 1 个 converter
- [x] **R10**: 不涉及评分器
- [x] **R10**: 使用 PyRIT 原生 `PromptSendingAttack`

### 风险评估

- **可能破坏什么**: 链式 SelectiveText 编码可能失去选择性叠加效果
- **缓解措施**: 将第二个 SelectiveText 作为独立路径运行，FIRST_SUCCESS 会尝试两条路径
- **回退方案**: `git diff` + `git checkout` 恢复

---

## 检查清单存档规则

- 每次代码变更的检查清单应保存在对话历史中
- 重大变更 (涉及 3+ 文件) 的检查清单应复制到 `docs/archive/` 目录
- 检查清单的填写质量直接影响项目成功率 — 不填写 = 项目失败的根因
