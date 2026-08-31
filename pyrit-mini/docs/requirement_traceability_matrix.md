# PyRIT-Strike 需求映射追踪矩阵 (RTM)

> **文档定位**: 确保 6 步攻击链路的每一步都映射到 PyRIT 原生组件，且每次代码变更都可追溯
> **核心目标**: 消除"偏离预期目标"的根因 —— 每个需求 → 原生组件 → 代码位置 → 验证检查 → 状态
> **最后更新**: 2026-08-31

---

## 1. 6 步攻击链路 → PyRIT 原生组件映射

| 步骤 | 需求描述 | PyRIT 原生组件 | 自研代码 (仅限 glue/enhancement/output) | 验证检查 | 当前状态 |
|------|----------|---------------|---------------------------------------|---------|---------|
| ① Burp 拦截 | 读取 Burp HTTP 请求，解析占位符 | N/A (数据输入层) | `recon/burp_parser.py` (glue: 解析→注入) | architecture_guard R8 | PASS |
| ② 侦察 | 目标能力指纹探测，构建 HTTPTarget | `HTTPTarget`, `OpenAIChatTarget`, `TargetRequirements` | `recon/target_router.py` (glue: 连接 Burp→HTTPTarget), `targets/rate_limited.py` (enhancement: 包装原生 Target) | architecture_guard R2 | PASS |
| ③ 种子选取 | 从 YAML 加载种子，按 ASR 排序 | `SeedPrompt` YAML format, `AttackSeedGroup`, `SeedObjective` | `arm/seed_ranker.py` (enhancement: ASR 排序+能力映射) | architecture_guard R2 | PASS |
| ④ Converter | 构建 L5 多路径 Converter 链 | `ConverterConfiguration`, `pyrit.converter.*` (全部原生) | `arm/converter_presets.py` (glue: 链定义→实例化), `arm/converter_chains.py` (glue: 链构建函数) | architecture_guard R6 | PASS — 串联堆叠已修复 |
| ⑤ 攻击发送 | 多路径独立执行 + FIRST_SUCCESS + 多轮升级 | `PromptSendingAttack`, `CrescendoAttack`, `TAPAttack`, `PAIRAttack`, `SequentialAttack`, `RedTeamingAttack`, `SkeletonKeyAttack`, `ManyShotJailbreakAttack`, `MultiPromptSendingAttack`, `ChunkedRequestAttack`, `AttackExecutor`, `AttackScoringConfig`, `AttackConverterConfig` | `strike/executor.py` (glue: 编排 SequentialAttack), `strike/escalation*.py` (glue: 升级链编排), `strike/adaptive_executor.py` (glue: Best-of-N), `strike/native_attacks.py` (glue: 原生攻击策略), `strike/technique_registry.py` (glue: 技术注册) | architecture_guard R6 | PASS — 10 种原生攻击策略全部导入并实例化 |
| ⑥ 评分判定 | T0→J1→J2→J3 级联评分 + ASR 统计 | `SubStringScorer`, `TrueFalseInverterScorer`, `SelfAskTrueFalseScorer`, `SelfAskRefusalScorer`, `TrueFalseCompositeScorer`, `ConversationScorer`, `CentralMemory`, `DuckDBMemory` | `assess/scorer.py` (glue: 评分器注册), `assess/adaptive_dual_judge.py` (enhancement: 自适应双 Judge), `assess/asr_tracker.py` (output: ASR 统计) | architecture_guard R10 | PASS (post-hoc 评分正确) |

---

## 2. 架构契约规则 → 代码检查映射

| 规则 | 规则描述 | 自动检查器 | 当前违规数 | 违规文件 | 修复优先级 |
|------|---------|-----------|-----------|---------|-----------|
| R2 | PyRIT 原生优先，禁止自研替换 | `architecture_guard.check_forbidden_custom_classes()` + `check_pyrit_native_output()` | 0 | — | — |
| R3 | ruff + pytest + guard (HARD GATE) | `architecture_guard.check_root_directory()` + `check_test_coverage()` | 0 | — | — |
| R4 | L5 参数基线对齐 | `architecture_guard.check_l5_params()` | 0 | — | — |
| R5 | arXiv 引用优先 | `architecture_guard.check_arxiv_citations()` | 0 | — | — |
| R6 | AI 红队就绪对齐 (HARD GATE) | `architecture_guard.check_serial_stacking()` + `check_native_attack_usage()` + `check_native_attack_instantiation()` + `check_native_params_from_config()` + `check_llm_scorer_in_attack()` + `check_cascade_order()` | 0 | — | — |
| R7 | ASR-token-time 平衡优化 | `architecture_guard.check_hardcoded_params()` + `check_intermediate_exit()` + `check_precision_targeting()` | 0 | — | — |
| R8 | 生产级工程实践 | 手动审计 (8 个实践领域) | 0 | — | — |
| R9 | 配置数据流一致性 | `architecture_guard.check_config_data_flow()` | 0 | — | — |
| R10 | 变更后流水线验证 (HARD GATE) | `architecture_guard.check_dry_run_available()` | 0 | — | — |

---

## 3. PyRIT 原生攻击策略使用追踪

| 攻击策略 | PyRIT 模块 | 导入位置 | 使用位置 | 状态 |
|----------|-----------|---------|---------|------|
| `PromptSendingAttack` | `pyrit.executor.attack` | `strike/executor.py:73` | `strike/executor.py`, `strike/escalation_attacks.py` | PASS |
| `CrescendoAttack` | `pyrit.executor.attack` | `strike/technique_registry.py:73` | `strike/escalation_attacks.py` | PASS |
| `TAPAttack` | `pyrit.executor.attack` | `strike/technique_registry.py:62` | `strike/escalation_attacks.py` | PASS |
| `PAIRAttack` | `pyrit.executor.attack` | `strike/technique_registry.py:62` | `strike/escalation_attacks.py` | PASS |
| `SequentialAttack` | `pyrit.executor.attack.compound.sequential_attack` | `strike/executor.py:294` | `strike/executor.py:_try_native_sequential_attack()` | PASS |
| `RedTeamingAttack` | `pyrit.executor.attack` | `strike/technique_registry.py` | `strike/escalation_level1.py` | PASS |
| `SkeletonKeyAttack` | `pyrit.executor.attack` | `strike/technique_registry.py` | `strike/escalation_level3.py` | PASS |
| `ManyShotJailbreakAttack` | `pyrit.executor.attack` | `strike/native_attacks.py` | `strike/escalation_level3.py` | PASS |
| `MultiPromptSendingAttack` | `pyrit.executor.attack` | `strike/multi_prompt_attack.py` | `strike/multi_prompt_attack.py` | PASS |
| `ChunkedRequestAttack` | `pyrit.executor.attack` | `strike/chunked_attack.py` | `strike/chunked_attack.py` | PASS |

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

**检查项 (17 个检查器)**:
1. Converter 串联堆叠 (R6 BLOCKING)
2. PyRIT 原生攻击策略使用 (R6 WARNING)
3. 原生攻击实例化 (R6 §6.4a WARNING)
4. 原生攻击参数来源 (R6 §6.4b WARNING)
5. 自定义 Executor/Target/Scorer (R2 BLOCKING)
6. 根目录文件混乱 (R3 BLOCKING/WARNING)
7. 测试覆盖率 (R3 BLOCKING)
8. L5 参数基线 (R4 BLOCKING/WARNING)
9. 硬编码效率参数 (R7 WARNING)
10. 中间退出检查点 (R7 BLOCKING)
11. arXiv 引用 (R5 WARNING)
12. 安全护栏 (R1 BLOCKING)
13. LLM 评分器在攻击路径中使用 (R6 WARNING)
14. 级联评分顺序 (R6 §6.2 WARNING)
15. PyRIT 原生 output 使用 (R2 BLOCKING)
16. 配置数据流一致性 (R9 WARNING/INFO)
17. --dry-run 可用性 (R10 BLOCKING/WARNING)
18. 精准投放四大机制完整性 (R1/R7 WARNING)

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
