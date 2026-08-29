# PyRIT-Strike 需求映射追踪矩阵 (RTM)

> **文档定位**: 确保 6 步攻击链路的每一步都映射到 PyRIT 原生组件，且每次代码变更都可追溯
> **核心目标**: 消除"偏离预期目标"的根因 —— 每个需求 → 原生组件 → 代码位置 → 验证检查 → 状态
> **最后更新**: 2026-08-29

---

## 1. 6 步攻击链路 → PyRIT 原生组件映射

| 步骤 | 需求描述 | PyRIT 原生组件 | 自研代码 (仅限 glue/enhancement/output) | 验证检查 | 当前状态 |
|------|----------|---------------|---------------------------------------|---------|---------|
| ① Burp 拦截 | 读取 Burp HTTP 请求，解析占位符 | N/A (数据输入层) | `recon/burp_parser.py` (glue: 解析→注入) | architecture_guard R8 | PASS |
| ② 侦察 | 目标能力指纹探测，构建 HTTPTarget | `HTTPTarget`, `OpenAIChatTarget`, `TargetRequirements` | `recon/target_router.py` (glue: 连接 Burp→HTTPTarget), `targets/rate_limited.py` (enhancement: 包装原生 Target) | architecture_guard R2 | PASS |
| ③ 种子选取 | 从 YAML 加载种子，按 ASR 排序 | `SeedPrompt` YAML format, `AttackSeedGroup`, `SeedObjective` | `arm/seed_ranker.py` (enhancement: ASR 排序+能力映射) | architecture_guard R2 | PASS |
| ④ Converter | 构建 L5 多路径 Converter 链 | `ConverterConfiguration`, `pyrit.converter.*` (全部原生) | `arm/converter_presets.py` (glue: 链定义→实例化), `arm/converter_chains.py` (glue: 链构建函数) | **architecture_guard R10 (BLOCKING)** | **FAIL** — `arm/converter_selector.py:411` 串联堆叠 |
| ⑤ 攻击发送 | 多路径独立执行 + FIRST_SUCCESS + 多轮升级 | `PromptSendingAttack`, `CrescendoAttack`, `TAPAttack`, `PAIRAttack`, `SequentialAttack`, `RedTeamingAttack`, `SkeletonKeyAttack`, `AttackExecutor`, `AttackScoringConfig`, `AttackConverterConfig` | `strike/executor.py` (glue: 编排 SequentialAttack), `strike/escalation*.py` (glue: 升级链编排), `strike/adaptive_executor.py` (glue: Best-of-N) | **architecture_guard R10 (WARNING)** | **PARTIAL** — 缺 `RedTeamingAttack` + `SkeletonKeyAttack` 导入 |
| ⑥ 评分判定 | T0→J1→J2→J3 级联评分 + ASR 统计 | `SubStringScorer`, `TrueFalseInverterScorer`, `SelfAskTrueFalseScorer`, `SelfAskRefusalScorer`, `TrueFalseCompositeScorer`, `ConversationScorer`, `CentralMemory`, `DuckDBMemory` | `assess/scorer.py` (glue: 评分器注册), `assess/adaptive_dual_judge.py` (enhancement: 自适应双 Judge), `assess/asr_tracker.py` (output: ASR 统计) | architecture_guard R10 | PASS (post-hoc 评分正确) |

---

## 2. 架构契约规则 → 代码检查映射

| 规则 | 规则描述 | 自动检查器 | 当前违规数 | 违规文件 | 修复优先级 |
|------|---------|-----------|-----------|---------|-----------|
| R2 | PyRIT 原生优先，禁止自研替换 | `architecture_guard.check_forbidden_custom_classes()` | 0 | — | — |
| R3 | L5 参数 100% 对齐 | 手动审计 `config/defaults.yaml` | 0 | — | — |
| R5 | ruff + pytest 验证 (HARD GATE) | `architecture_guard.check_test_coverage()` | **1 (BLOCKING)** | tests/ 目录不存在 | P0 — 创建测试 |
| R8 | 目录组织规范 | `architecture_guard.check_root_directory()` | 0 | — | — |
| R10 | AI 红队就绪对齐 (HARD GATE) | `architecture_guard.check_serial_stacking()` + `check_native_attack_usage()` + `check_llm_scorer_in_attack()` | **1 BLOCKING + 5 WARNING** | `arm/converter_selector.py:411` (串联堆叠), 缺 `SkeletonKeyAttack`/`RedTeamingAttack`, escalation 路径使用 LLM scorer | P0 — 修复串联堆叠; P1 — 导入缺失攻击类 |
| R11 | ASR-token-time 平衡优化 | 手动审计 (规则在 `defaults.yaml` 参数中) | 0 | — | — |

---

## 3. PyRIT 原生攻击策略使用追踪

| 攻击策略 | PyRIT 模块 | 导入位置 | 使用位置 | 状态 |
|----------|-----------|---------|---------|------|
| `PromptSendingAttack` | `pyrit.executor.attack` | `strike/executor.py:73` | `strike/executor.py`, `strike/escalation_attacks.py` | PASS |
| `CrescendoAttack` | `pyrit.executor.attack` | `strike/technique_registry.py:73` | `strike/escalation_attacks.py` | PASS |
| `TAPAttack` | `pyrit.executor.attack` | `strike/technique_registry.py:62` | `strike/escalation_attacks.py` | PASS |
| `PAIRAttack` | `pyrit.executor.attack` | `strike/technique_registry.py:62` | `strike/escalation_attacks.py` | PASS |
| `SequentialAttack` | `pyrit.executor.attack.compound.sequential_attack` | `strike/executor.py:294` | `strike/executor.py:_try_native_sequential_attack()` | PASS |
| `RedTeamingAttack` | `pyrit.executor.attack` | **缺失** | **未使用** | **FAIL — 需导入并在升级链中使用** |
| `SkeletonKeyAttack` | `pyrit.executor.attack` | **缺失** (仅手动构建 prepended_conversation) | **未使用原生类** | **FAIL — 需导入并替换手动 SkeletonKey 逻辑** |

---

## 4. Converter 独立路径映射 (Rule 10 强制)

| 路径 | Converter | ASR | 代码位置 | ConverterConfiguration | 状态 |
|------|----------|-----|---------|----------------------|------|
| 1 | `DecompositionConverter` | 40-60% | `arm/converter_chains.py:decomposition()` | `converters=[single]` | PASS |
| 2 | `PersuasionConverter(authority)` | 38.4% | `arm/converter_presets.py:l5_optimal()` | `converters=[single]` | PASS |
| 3 | `VariationConverter` | 20-30% | `arm/converter_chains.py:variation()` | `converters=[single]` | PASS |
| 4 | `CodeChameleonConverter` | 35-45% | `arm/converter_chains.py:code_chameleon()` | `converters=[single]` | PASS |
| 5 | `PolicyPuppetryConverter` | 30-40% | `arm/converter_chains.py:policy_puppetry()` | `converters=[single]` | PASS |
| 6 | `SelectiveEncoding (Base64 30%)` | 25-35% | `arm/converter_chains.py:selective_encoding()` | `converters=[single]` | PASS |
| 7 | `ROT13Converter` | 30-40% | `arm/converter_presets.py:l5_optimal()` | `converters=[single]` | PASS |
| **违规** | `SelectiveText + SelectiveText` | — | `arm/converter_selector.py:411` | **`converters=[conv1, conv2]`** | **FAIL — 串联堆叠** |

---

## 5. 评分级联映射 (Rule 11)

| 级别 | 评分器 | Token 成本 | 代码位置 | 用途 | 状态 |
|------|--------|-----------|---------|------|------|
| T0 | `_MultiKeywordRefusalScorer` (继承 `SubStringScorer`) | 0 | `strike/executor.py:_MultiKeywordRefusalScorer` | 拒绝关键词正则匹配 | PASS |
| T0 | `TrueFalseInverterScorer` | 0 | `strike/executor.py:_build_first_success_scoring_config()` | 反转 T0 结果 (非拒绝=成功) | PASS |
| J1 | `SelfAskTrueFalseScorer` (calibrated, lenient) | ~800 | `assess/scorer.py:create_objective_scorer()` | 宽松 Judge (post-hoc) | PASS |
| J2 | `TrueFalseInverterScorer(SelfAskRefusalScorer, strict)` | ~800 | `assess/adaptive_dual_judge.py` | 严格 Judge (post-hoc) | PASS |
| J3 | `SelfAskTrueFalseScorer` (arbiter, different model) | ~800 | `assess/adaptive_dual_judge.py` | 仲裁 Judge (仅 J1≠J2) | PASS |

---

## 6. 工程保障机制

### 6.1 架构守护脚本 (`core/architecture_guard.py`)

**运行方式**:
```bash
# 每次代码变更前/后运行
python core/architecture_guard.py --fix-hints

# CI 集成 (JSON 输出)
python core/architecture_guard.py --json

# 只检查特定规则
python core/architecture_guard.py --rule R10
```

**检查项**:
1. Converter 串联堆叠 (R10 BLOCKING)
2. PyRIT 原生攻击策略使用 (R10 WARNING)
3. 自定义 Executor/Target/Scorer (R2 BLOCKING)
4. 根目录文件混乱 (R8 BLOCKING/WARNING)
5. 测试覆盖率 (R5 BLOCKING)
6. LLM 评分器在攻击路径中使用 (R10 WARNING)

### 6.2 强制执行流程 (每次代码变更)

```
代码变更请求
    │
    ▼
Phase 0: 架构守护脚本 ──→ BLOCKING? ──→ YES: STOP, 修复后重试
    │                                     NO: 继续
    ▼
Phase 1: 实施前检查清单 (见 docs/implementation_checklist.md)
    │  (列出所有受影响文件 + 步骤 + 规则预检)
    ▼
Phase 2: 代码实现
    │
    ▼
Phase 3: 架构守护脚本 (再次运行) ──→ BLOCKING? ──→ YES: STOP, 修复后重试
    │                                     NO: 继续
    ▼
Phase 4: ruff check + pytest
    │
    ▼
Phase 5: L5 Gap 分析 (Rule 9 Phase 4)
    │
    ▼
Phase 6: 下一步优化建议 (Rule 9 Phase 5)
```

### 6.3 追踪矩阵维护规则

- **每次代码变更后**必须更新此矩阵
- 新增模块时在 Section 1 添加行
- 新增 Converter 路径时在 Section 4 添加行
- 修复违规时将状态从 FAIL → PASS
- `architecture_guard.py` 的输出应与此矩阵一致
