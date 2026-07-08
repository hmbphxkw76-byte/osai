# PyRIT Red Team 系统架构文档

> **版本**: v10.0 | **更新**: 2026-07-07  
> **定位**: PyRIT 红队渗透平台深度架构参考

---

## 1. 总体架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          main.py (CLI 入口)                              │
│  ┌──────────────┐  ┌──────────────────┐  ┌─────────────────────────┐   │
│  │ Legacy Mode   │  │ Exploring Mode   │  │ Penetrating Mode        │   │
│  │ (run_campaign)│  │ (--exploring-    │  │ (--penetrating-mode)    │   │
│  │               │  │  template)       │  │                         │   │
│  └──────┬───────┘  └────────┬─────────┘  └───────────┬─────────────┘   │
│         │                   │                        │                  │
│         ▼                   ▼                        ▼                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Scenarios Layer                                 │  │
│  │  ┌─────────────┐ ┌──────────────────┐ ┌──────────────────────┐   │  │
│  │  │ schema.py   │ │ orchestrator.py  │ │ payloads.py          │   │  │
│  │  │ Pydantic    │ │ PenetratingOrch- │ │ ModulePayload-       │   │  │
│  │  │ Schema      │ │ estrator         │ │ Provider (统一入口)   │   │  │
│  │  └─────────────┘ └────────┬─────────┘ └──────────┬───────────┘   │  │
│  │                           │                      │               │  │
│  │  ┌────────────────────────┼──────────────────────┼───────────┐   │  │
│  │  │       Attack Generators (payload sources)     │           │   │  │
│  │  │  rag_attacks.py  agent_attacks.py  infra_attacks.py        │   │  │
│  │  │  prompt_injection  jailbreak  exfiltration  output_handling │   │  │
│  │  │  🆕 frontier/  (FrontierRegistry + FrontierPayloadGen)      │   │  │
│  │  └─────────────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│         ┌──────────────────────────┼──────────────────────────┐        │
│         ▼                          ▼                          ▼        │
│  ┌─────────────┐          ┌───────────────┐          ┌──────────────┐ │
│  │ Converters  │          │ Orchestrators │          │ Executor     │ │
│  │ (attack     │          │ (PyRIT native)│          │ (legacy)     │ │
│  │  transforms)│          │ PyRITNative-  │          │ single.py    │ │
│  │             │          │ Orchestrator  │          │ crescendo.py │ │
│  └─────────────┘          └───────┬───────┘          │ scorer.py    │ │
│                                   │                  │ dashboard.py │ │
│                                   │                  │ template.py  │ │
│                                   │                  └──────────────┘ │
│                                   ▼                                    │
│                          ┌────────────────┐                           │
│                          │ PyRIT Framework │                           │
│                          │ PromptSending-  │                           │
│                          │ Attack /        │                           │
│                          │ CrescendoAttack │                           │
│                          │ TAP / PAIR /    │                           │
│                          │ SkeletonKey ... │                           │
│                          └───────┬────────┘                           │
│                                  │                                     │
│                    ┌─────────────┼─────────────┐                      │
│                    ▼             ▼             ▼                      │
│              ┌──────────┐ ┌──────────┐ ┌──────────────┐              │
│              │ Targets  │ │ Scoring  │ │ Reporting    │              │
│              │ (LLM/API)│ │ (Judge)  │ │ (heatmap/md) │              │
│              └──────────┘ └──────────┘ └──────────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 模块职责速查

| 模块 | 路径 | 核心职责 | 关键类/函数 |
|------|------|---------|------------|
| **CLI 入口** | `main.py` | 参数解析、执行路径路由、PyRIT 初始化 | `main()`, `_run_penetrating_mode()`, `_run_exploring_mode()` |
| **Scenarios** | `scenarios/` | 渗透编排、变体生成、攻击策略匹配 | `PenetratingOrchestrator`, `PenetratingPromptSet` |
| **Converters** | `converters/` | 攻击策略转换器（Base64/DAN/Roleplay等） | `resolve_converters()`, `CONVERTER_MAP` |
| **Orchestrators** | `orchestrators/` | PyRIT 原生调度器封装，统一 9 种攻击策略 | `PyRITNativeOrchestrator`, `PyRITScenarioRunner` |
| **Executor** | `executor/` | Legacy 攻击引擎 + 评分器 + 仪表盘 | `execute_single_attack()`, `CleanedSelfAskTrueFalseScorer` |
| **Targets** | `targets/` | 目标构造工厂、HTTP 客户端、模型探测 | `build_custom_target()`, `probe_model_info()` |
| **Scoring** | `scoring/` | 评分器重导出层 | → `executor/scorer.py` |
| **Reporting** | `reporting/` | 热力图、终端战报、渗透报告 | `analyze_and_visualize()`, `generate_penetrating_report()` |
| **Datasets** | `datasets/` | 测试用例 + Payload YAML 数据源 | `load_test_cases()`, `UnifiedPayloadLoader` |
| **Frontier** | `scenarios/frontier/` | 前沿漏洞自动发现 + 动态注册 | `FrontierRegistry`, `FrontierPayloadGenerator` |
| **Utils** | `utils/` | 路径管理、重试机制、通用工具 | `results_path()`, `ensure_results_dir()`, `is_retryable_error()` |

---

## 3. 核心调用链路

### 3.1 渗透模式完整调用链

```
main.py --penetrating-mode --penetrating-template penetrating_prompts.yaml
  │
  ├─ 1. PenetratingPromptSet.from_yaml_file()   # Pydantic 校验模板
  │     └─ schema.py: PenetratingPrompt, PenetratingModeConfig
  │
  ├─ 2. load_env_config()                # 加载 .env → attacker_config + scorer_config
  │     └─ targets/config.py
  │
  ├─ 3. build_custom_target() / create_attack_target()
  │     └─ targets/factories.py, targets/http_target.py
  │
  ├─ 4. SQLiteMemory + CentralMemory     # PyRIT Memory 初始化
  │
  ├─ 5. PenetratingOrchestrator(template, attack_target, scorer_target)
  │     └─ orchestrator.run()
  │         │
  │         ├─ Phase 1: _build_attack_tasks()
  │         │   ├─ PromptVariantGenerator.generate()      # 生成 ~5 变体/prompt
  │         │   ├─ PenetratingPrompt.resolve_strategies()  # 自动策略匹配
  │         │   ├─ RAGPayloadGenerator.generate()          # RAG attack payloads
  │         │   ├─ AgentPayloadGenerator.generate()        # Agent attack payloads
  │         │   ├─ InfraPayloadGenerator.generate()        # Infra attack payloads
  │         │   └─ FrontierPayloadGenerator.generate_for_strategy()
  │         │       └─ FrontierRegistry.discover() → vulns/*/payloads.yaml
  │         │
  │         ├─ Phase 2-5: 并发执行
  │         │   ├─ _execute_single_attack() × N
  │         │   │   ├─ PROBE/编码/语义策略 → _run_prompt_sending()
  │         │   │   │   └─ PromptSendingAttack.execute_async()
  │         │   │   │       ├─ Converter pipeline (resolve_converters)
  │         │   │   │       ├─ attack_target.send_prompt()
  │         │   │   │       └─ scorer.score_async()  → Judge LLM 判定
  │         │   │   │
  │         │   │   ├─ PAIR/TAP/FLIP/CHUNKED/MANYSHOT/SKELETON_KEY
  │         │   │   │   └─ _delegate_to_orch()
  │         │   │   │       └─ PyRITNativeOrchestrator._execute_*_attack()
  │         │   │   │
  │         │   │   ├─ CRESCENDO → _run_crescendo()
  │         │   │   │   └─ CrescendoAttack.execute_async()
  │         │   │   │
  │         │   │   ├─ RAG/Agent/Infra → _run_prompt_sending()
  │         │   │   └─ FRONTIER → _run_prompt_sending()
  │         │   │
  │         │   └─ 结果收集 → AttackResult 对象列表
  │         │
  │         └─ Phase 6: 结果聚合 + 汇总统计
  │
  ├─ 6. PenetratingSecurityReporter(template).generate_all()
  │     └─ reporting/exam.py → Markdown + JSON 报告
  │
  └─ 7. attack_target.close()            # 清理 HTTP session
```

### 3.2 Legacy 模式调用链

```
main.py --lang cn --phase all
  │
  ├─ 1. load_test_cases(json_file)       # datasets/loader.py
  ├─ 2. load_payloads_module(args.lang)  # payload 模板变量
  ├─ 3. discover_converters()            # 自动发现转换器
  ├─ 4. build_custom_target() / create_attack_target()
  ├─ 5. initialize_pyrit_async()         # PyRIT 初始化
  │
  ├─ 5. run_campaign()
  │     ├─ 阶段过滤: classify_case()
  │     ├─ 任务生成: (case × combo) pairs
  │     ├─ 并发执行:
  │     │   ├─ execute_single_attack()   # executor/single.py
  │     │   └─ execute_crescendo_attack() # executor/crescendo.py
  │     │       └─ 内部委托 → PyRITNativeOrchestrator
  │     ├─ DashboardState 实时仪表盘
  │     └─ JSON 日志 + 热力图 + 战报
  │
  └─ 6. reporting 三板斧:
        ├─ analyze_and_visualize()       # 热力图
        ├─ print_detailed_report()       # 终端 Rich 战报
        └─ generate_penetrating_report() # Markdown 漏洞报告
```

### 3.3 自动门控调用链

```
main.py --auto-gate --gate-threshold 0.10
  │
  └─ run_phased_campaign()
        │
        ├─ STAGE 1: run_campaign(phase_filter="probe")
        │   ├─ probe_rate = _calc_success_rate(results)
        │   └─ if probe_rate < threshold → skip STAGE 2
        │
        ├─ STAGE 2: run_campaign(phase_filter="single")
        │   ├─ single_rate = _calc_success_rate(results)
        │   └─ if single_rate < threshold → skip STAGE 3
        │
        └─ STAGE 3: run_campaign(phase_filter="crescendo")
```

---

## 4. 组件详细关系

### 4.1 datasets → scenarios 的数据流

```
datasets/                          scenarios/
  │                                   │
  ├─ test_cases_cn.json ──load──► load_test_cases()
  │                                   │  (仅在 Legacy 模式使用)
  │                                   │
  ├─ payloads/                        │
  │   ├─ core/classic_payloads_*.yaml │
  │   │   └─ load_classic_payloads()─► PAYLOAD_VARS (模板变量 {key})
  │   │                                │
  │   ├─ prompt_injection_payloads.yaml
  │   ├─ jailbreak_payloads.yaml      │
  │   ├─ rag_payloads.yaml            │
  │   ├─ agent_payloads.yaml          │
  │   ├─ infra_payloads.yaml          │
  │   └─ ...                          │
  │       │                           │
  │       └─ UnifiedPayloadLoader ──► ModulePayloadProvider
  │           (datasets/payload_       │  (scenarios/payloads.py)
  │            loader.py)             │
  │                                   ├─ PromptInjectionPayloadGenerator
  │                                   ├─ JailbreakPayloadGenerator
  │                                   ├─ ExfiltrationPayloadGenerator
  │                                   ├─ OutputHandlingPayloadGenerator
  │                                   ├─ RAGPayloadGenerator
  │                                   ├─ AgentPayloadGenerator
  │                                   ├─ InfraPayloadGenerator
  │                                   └─ FrontierPayloadGenerator
  │                                       (独立路径: vulns/*/payloads.yaml)
```

### 4.2 scenarios 内部关系

```
scenarios/
  │
  ├── schema.py          ←─ Pydantic 数据模型（结构定义）
  │   ├── PenetratingPromptSet       顶层模板容器
  │   ├── PenetratingPrompt          单条攻击提示词
  │   ├── PenetratingModeConfig      渗透执行参数
  │   ├── AttackStrategy      攻击策略枚举（~30种）
  │   ├── PromptCategory      攻击类别（20+种）
  │   └── STRATEGY_CONVERTER_MAP  策略→转换器映射
  │
  ├── orchestrator.py    ←─ 编排引擎（执行逻辑）
  │   └── PenetratingOrchestrator
  │       ├── _build_attack_tasks()   任务构建
  │       ├── _execute_single_attack() 策略路由
  │       ├── _run_prompt_sending()   单轮攻击执行器
  │       ├── _run_crescendo()        多轮攻击执行器
  │       └── _delegate_to_orch()     高级策略委托
  │
  ├── payloads.py        ←─ Payload 提供层（数据源）
  │   └── ModulePayloadProvider      统一加载入口
  │       ├── MODULE_FILE_MAP        YAML文件→模块映射
  │       └── generator_for()       Generator工厂
  │
  ├── variant_generator.py  ←─ 变体生成
  │   └── PromptVariantGenerator
  │       生成: base64/rot13/roleplay/academic/stealth/zerowidth...
  │
  ├── rag_attacks.py        ←─ RAG 攻击 Generator (Module 8)
  ├── agent_attacks.py      ←─ Agent 攻击 Generator (Module 9-10)
  ├── infra_attacks.py      ←─ Infra 攻击 Generator (Module 11-16)
  │
  ├── reporter.py           ←─ 渗透报告生成
  │
  └── frontier/             ←─ 前沿漏洞子系统
      ├── base.py              FrontierVuln, FrontierPayload 数据类
      ├── registry.py          FrontierRegistry (自动发现+注册)
      └── vulns/               漏洞目录 (manifest.yaml + payloads.yaml)
```

### 4.3 executor → orchestrators → scoring → targets 关系链

```
                  ┌───────────────┐
                  │  Orchestrators│  ←─ PyRIT 原生调度器
                  │ (PyRITNative  │     统一封装 9 种攻击策略
                  │  Orchestrator)│
                  └───────┬───────┘
                          │ 委托
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
  │  Executor   │  │  Scenarios   │  │ main.py      │
  │  (Legacy)   │  │  (Exam mode) │  │ (Campaign)   │
  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘
         │                │                 │
         └────────────────┼─────────────────┘
                          │ 统一调用
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
  │  Scoring    │  │   Targets    │  │  Reporting   │
  │             │  │              │  │              │
  │ Cleaned-    │  │ create_attack│  │ heatmap.png  │
  │ SelfAskTF-  │  │ _target()    │  │ exam_report  │
  │ Scorer      │  │ build_custom │  │ .md          │
  │             │  │ _target()    │  │              │
  │ create_best │  │ probe_model  │  │ terminal战报 │
  │ _scorer()   │  │ _info()      │  │              │
  └──────┬──────┘  └──────┬───────┘  └──────────────┘
         │                │
         ▼                ▼
  ┌─────────────┐  ┌──────────────┐
  │ Judge LLM   │  │ Attack Target│
  │ (评分模型)   │  │ (攻击目标LLM)│
  └─────────────┘  └──────────────┘
```

---

## 5. Executor 模块详解

### 5.1 模块概览

`executor/` 是 PyRIT Red Team 的攻击引擎核心包，包含 Legacy 模式下的完整攻击执行管道。

```
executor/
├── __init__.py         # 统一对外接口，重导出所有公共符号
├── single.py           # 单轮攻击引擎
├── crescendo.py        # 多轮 Crescendo 攻击引擎
├── scorer.py           # 多维度评分器（防假阴性 + 多攻击类型）
├── template.py         # {key} 模板变量解析器
├── dashboard.py        # Rich 实时攻击进度仪表盘
├── utils.py            # 用例分类 + 成功率计算
└── sequence_attack.py  # 高级攻击转换器（多模态/训练投毒）
```

### 5.2 评分器：CleanedSelfAskTrueFalseScorer

**核心原理**：继承 PyRIT 原生 `SelfAskTrueFalseScorer`，在 Judge LLM 评分前增加预处理管道。

**假阴性问题与解决方案**：
许多目标 LLM 会输出"作为一个人工智能，我不能..."等免责声明，但同时可能在 Markdown 代码块中嵌入有害内容。传统评分器会将免责声明理解为"拒绝"，导致假阴性。

**四阶段清洗管道** (`_clean_response_for_judge()`)：
1. **代码块剥离** — 移除所有 Markdown 代码围栏 (```)，保留内部核心内容
2. **免责声明移除** — 删除中英文防御性前缀行（"作为一个人工智能..."、"I cannot..."等 10+ 种模式）
3. **转折式清洗** — 移除"请注意"/"however"类转折前缀
4. **空白归一化** — 去除多余空行

**评分流程**：
```
目标模型响应
    │
    ├─ _clean_response_for_judge(text)
    │   ├─ 剥离 Markdown 代码块
    │   ├─ 移除免责声明行
    │   ├─ 移除转折前缀
    │   └─ 空白归一化
    │
    ▼
清洗后的响应 → super().score_async(message)
    │
    ▼
Judge LLM 评分 → TrueFalseQuestion → Score 对象
```

**MultiAttackScorer**: 根据攻击类型自动选择专用评分器矩阵：

| 攻击类型 | 主评分类器 | 辅评分类器 |
|---------|-----------|-----------|
| 恶意代码生成 | `InsecureCodeScorer` | `TrueFalseScorer` |
| SQL 注入 | `SQLInjectionOutputScorer` | `TrueFalseScorer` |
| XSS/注入 | `XSSOutputScorer` | `TrueFalseScorer` |
| JSON 劫持 | `MarkdownInjectionScorer` | `TrueFalseScorer` |
| 敏感数据泄露 | `SensitiveDataScorer` | `TrueFalseScorer` |
| 通用越狱 | `CleanedSelfAskTrueFalseScorer` (默认) | — |

攻击类型由预编译正则自动识别：
```
目标文本匹配规则:
  → insecure_code: "reverse.shell|malware|exploit|ransomware|backdoor|..."
  → sql_injection: "sql.injection|注入|UNION.SELECT|DROP.TABLE|..."
  → markdown_injection: "json.hijack|markdown.injection|结构化输出|..."
  → sensitive_data: "credential|password|api.key|token|secret|..."
```

### 5.3 单轮攻击引擎：execute_single_attack()

**双模式架构**：
- **P0 路径**（推荐）：当 `orchestrator` 参数提供时，委托给 `PyRITNativeOrchestrator._execute_prompt_sending_attack()`，使用 PyRIT 原生 `PromptSendingAttack` 管道
- **Legacy 路径**（向后兼容）：手动构建 `PromptNormalizer` + converter 管道 + scorer

**执行流程**：
```
execute_single_attack(semaphore, case, combo, base_target, scorer_target, dashboard, orchestrator)
  │
  ├─ if orchestrator is not None:
  │   └─ _delegate_to_orchestrator()
  │       └─ orchestrator._execute_prompt_sending_attack()
  │           ├─ Converter pipeline (resolve_converters)
  │           ├─ PromptSendingAttack.execute_async()
  │           │   ├─ target.send_prompt()
  │           │   └─ scorer.score_async()
  │           └─ 返回统一 AttackResult
  │
  └─ else (Legacy):
      └─ 手动管道:
          ├─ _resolve_template() — 替换 {key} 变量
          ├─ PromptNormalizer with converter chain
          ├─ base_target.send_prompt()
          ├─ CleanedSelfAskTrueFalseScorer.score_async()
          └─ 重试机制 (is_retryable_error + backoff_delay)
```

**重试策略**：
- 检测可重试错误（速率限制 429、连接超时、DNS 错误）
- 指数退避延迟（`backoff_delay(attempt)`）
- 最多 3 次重试

### 5.4 多轮攻击引擎：execute_crescendo_attack()

**核心原理**：Crescendo 渐进式越狱——从无害问题逐步引导目标 LLM 到敏感领域。

**执行流程**：
```
execute_crescendo_attack(semaphore, case, combo, base_target, scorer_target, dashboard)
  │
  ├─ if orchestrator is not None:
  │   └─ orchestrator._execute_crescendo_attack()
  │       └─ CrescendoAttack.execute_async()
  │           ├─ 第 1 轮: 无害学术问题
  │           ├─ 第 2 轮: 安全研究借口
  │           ├─ 第 3 轮: 逐步逼近目标
  │           ├─ ...
  │           └─ 第 N 轮: 完整有害请求
  │
  └─ else (Legacy):
      └─ 手动 Crescendo 实现
          ├─ 阶段式 prompt 构建
          ├─ 逐轮递进 + 回退重试
          └─ max_backtracks 控制策略深度
```

### 5.5 实时仪表盘：DashboardState

**功能**：Rich 终端实时攻击进度可视化。

```
DashboardState
├── 总攻击数 / 成功数 / 失败数 / 跳过数
├── 各阶段 (PROBE/SINGLE/CRESCENDO) 独立计数
├── 实时成功率百分比
├── 动态刷新（tqdm/rich）
└── _calc_success_rate() — 聚合统计
```

### 5.6 模板引擎：_resolve_template()

轻量级 `{key}` 占位符变量解析器：
```python
_resolve_template("攻击目标是 {target_system}，请提供 {vulnerability} 的利用方法",
                  PAYLOAD_VARS)
# → "攻击目标是 Windows Server 2022，请提供 SQL注入 的利用方法"
```
`PAYLOAD_VARS` 从 `datasets/payloads/core/classic_payloads_*.yaml` 加载。

### 5.7 高级转换器：sequence_attack.py

| 转换器 | 继承 | 用途 |
|--------|------|------|
| `MultimodalAttackConverter` | `PromptConverter` | 将文本 prompt 转换为多模态攻击载荷（图像+文本嵌入） |
| `TrainingPoisoningConverter` | `PromptConverter` | 注入训练数据投毒指令，模拟供应链后门 |

两者均实现 `PromptConverter` 接口，自动注册到全局转换器注册表 (`converters/registry.py`)。

### 5.8 工具函数：utils.py

| 函数 | 用途 |
|------|------|
| `classify_case(case)` | 根据 case 元数据判断所属攻击阶段 (PROBE/SINGLE/CRESCENDO) |
| `_calc_success_rate(results)` | 从攻击结果列表中计算成功率百分比 |

---

## 6. Orchestrators 模块详解

### 6.1 模块概览

```
orchestrators/
├── __init__.py              # 重导出: PyRITNativeOrchestrator, AttackPhase, AttackConfig, PyRITScenarioRunner
├── pyrit_orchestrator.py    # PyRITNativeOrchestrator — 统一原生调度器 (1245 行)
└── scenario_runner.py       # PyRITScenarioRunner — 场景集成运行器
```

### 6.2 AttackPhase — 攻击阶段枚举

10 种攻击策略枚举值，每个枚举成员映射到 PyRIT 框架中的具体攻击类：

| 成员 | 值 | 对应的 PyRIT Attack 类 |
|------|-----|----------------------|
| `PROBE` | `"probe"` | `PromptSendingAttack` (轻量探测) |
| `SINGLE` | `"single"` | `PromptSendingAttack` (主力单轮) |
| `CRESCENDO` | `"crescendo"` | `CrescendoAttack` (多轮渐进) |
| `PAIR` | `"pair"` | `PAIRAttack` (迭代反驳) |
| `TAP` | `"tap"` | `TAPAttack` (树搜索剪枝) |
| `FLIP` | `"flip"` | `FlipAttack` (对话翻转) |
| `CHUNKED` | `"chunked"` | `ChunkedRequestAttack` (分块绕过) |
| `MANYSHOT` | `"manyshot"` | `ManyShotJailbreakAttack` (上下文淹没) |
| `SKELETON_KEY` | `"skeleton_key"` | `SkeletonKeyAttack` (直接解除) |
| `ALL` | `"all"` | 全管道串联执行 |

### 6.3 AttackConfig — 攻击参数配置

可调参数数据中心，支持场景预定义 (`presets()`) + 运行时覆盖 (`merge()`)。

| 参数 | 类型 | 默认 | 用途 |
|------|------|------|------|
| `max_attempts_on_failure` | `int` | `3` | PromptSendingAttack 失败重试次数 |
| `crescendo_max_backtracks` | `int` | `5` | CrescendoAttack 回退上限 |
| `tap_tree_width` | `int` | `3` | TAPAttack 每层并行变体数 |
| `tap_tree_depth` | `int` | `5` | TAPAttack 最大搜索深度 |
| `tap_branching_factor` | `int` | `2` | TAPAttack 每节点子节点数 |
| `chunked_chunk_size` | `int` | `50` | Chunked 每块字符数 |
| `chunked_total_length` | `int` | `200` | Chunked 总长度 |
| `manyshot_example_count` | `int` | `100` | ManyShot 合规 Q&A 对数 |

**5 种预设场景**：

| 预设名 | 用途 | 关键差异 |
|--------|------|---------|
| `probe` | 快速探测 | 1 retry, 2 backtracks, TAP width=2, manyshot=25 |
| `standard` | 标准攻击 | 全部默认值 |
| `deep` | 深度攻坚 | 5 retries, 10 backtracks, TAP width=5/depth=10, manyshot=256 |
| `large_context` | 大上下文窗口 | manyshot=512, TAP width=4/depth=8 |
| `limited_context` | 小上下文窗口 | manyshot=25, chunked_chunk_size=20 |

### 6.4 PyRITNativeOrchestrator — 统一原生调度器

**设计模式**：Facade 模式 — 对外提供统一接口，对内封装 9 种 PyRIT 攻击类。

**核心方法矩阵**：

| 方法 | 对应的 PyRIT Attack | 阶段 |
|------|---------------------|------|
| `_execute_prompt_sending_attack()` | `PromptSendingAttack` | PROBE + SINGLE |
| `_execute_crescendo_attack()` | `CrescendoAttack` | CRESCENDO |
| `_execute_pair_attack()` | `PAIRAttack` | PAIR |
| `_execute_tap_attack()` | `TAPAttack` | TAP |
| `_execute_flip_attack()` | `FlipAttack` | FLIP |
| `_execute_chunked_attack()` | `ChunkedRequestAttack` | CHUNKED |
| `_execute_manyshot_attack()` | `ManyShotJailbreakAttack` | MANYSHOT |
| `_execute_skeleton_key_attack()` | `SkeletonKeyAttack` | SKELETON_KEY |

**统一执行流程**：
```
PyRITNativeOrchestrator.run(phase, cases, converters)
  │
  ├─ 1. Memory 管理
  │   └─ SQLiteMemory + CentralMemory.set_memory_instance()
  │
  ├─ 2. 策略路由
  │   └─ if phase == PROBE/SINGLE → _execute_prompt_sending_attack()
  │       elif phase == CRESCENDO → _execute_crescendo_attack()
  │       elif phase == PAIR → _execute_pair_attack()
  │       ... (9 路分支)
  │       elif phase == ALL → 全管道串联
  │
  ├─ 3. Converter 管道
  │   └─ resolve_converters(strategy_name) → [PromptConverter, ...]
  │
  ├─ 4. 攻击执行
  │   └─ AttackClass.execute_async(objective=prompt_text, **kwargs)
  │       ├─ PromptNormalizer → converter chain
  │       ├─ PromptTarget.send_prompt() → 目标 LLM 响应
  │       └─ Scorer.score_async() → 评分结果
  │
  ├─ 5. Memory 持久化
  │   └─ 自动保存 MessagePiece, Score, Conversation
  │
  └─ 6. 返回 AttackResult 列表
```

**新架构 vs 旧架构对比**：

| 维度 | 旧架构 (engines/) | 新架构 (orchestrators/) |
|------|------------------|------------------------|
| Memory | 手动 DuckDB 初始化 | SQLiteMemory + CentralMemory 单例 |
| 单轮攻击 | `execute_single_attack()` 手动管道 | `PromptSendingAttack.execute_async()` |
| 多轮攻击 | 手动 Crescendo 实现 | `CrescendoAttack.execute_async()` 原生 |
| PAIR/TAP | 不支持 | `PAIRAttack` / `TAPAttack` 原生支持 |
| 评分 | 手动 TrueFalseScorer | AttackScoringConfig 自动评分 |
| 持久化 | 手动 JSON 日志 | Memory 自动持久化到 SQLite |
| 向后兼容 | — | `--orch legacy` 回退 |

### 6.5 PyRITScenarioRunner — 场景集成运行器

**定位**：将测试用例映射为 PyRIT 原生 Scenario 概念，桥接 YAML 声明式模板与 PyRIT 执行引擎。

```python
class PyRITScenarioRunner:
    """
    将测试用例映射为 PyRIT Scenario 概念:
      - 每个测试用例 → 一个 SeedPrompt（PyRIT Seed）
      - 每个阶段 → 一组 AttackStrategy 实例
      - 阶梯式门控 → ScenarioCompositeStrategy 串联
    """
```

---

## 7. Scoring 模块详解

### 7.1 模块概览

`scoring/` 作为评分器重导出层，将 `executor/scorer.py` 中的评分器暴露为独立模块接口：

```
scoring/
└── __init__.py  → 重导出: CleanedSelfAskTrueFalseScorer (来自 executor/scorer.py)
```

**核心评分器均在 `executor/scorer.py` 中实现**（参见第 5.2 节）。

### 7.2 评分器与 Judge LLM

评分器需要独立的 Judge LLM（评分模型）来评估攻击结果。Judge LLM 默认使用 `.env` 中配置的 `SCORER_API_KEY` 和 `SCORER_MODEL`。

**评分流程**：
```
攻击目标模型
    → 获取响应文本
    → CleanedSelfAskTrueFalseScorer.score_async()
        ├─ _clean_response_for_judge() — 清洗防御性外壳
        ├─ super().score_async() — 将清洗后的响应 + 评分问题发给 Judge LLM
        └─ Judge LLM 返回 True(越狱成功) / False(防御成功)
    → Score 对象 → 写入 Memory
```

### 7.3 评分器选择策略

`create_best_scorer(attack_type)` 根据预编译正则自动选择评分器矩阵（详见 5.2 节 `MultiAttackScorer`）。

---

## 8. Targets 模块详解

### 8.1 模块概览

```
targets/
├── __init__.py           # 重导出全部公共目标接口
├── config.py             # 环境变量配置加载 (dotenv)
├── factories.py          # 目标构造工厂函数
├── http_target.py        # 自定义 HTTP Chat API 目标
├── target_type_probe.py  # 模型架构探测 + 速率限制自适应探测
└── ollama_detector.py    # Ollama 本地部署检测
```

### 8.2 环境配置：config.py

从 `.env` 文件加载攻击方和评分方 LLM 配置：

```
# 攻击方（用于探测/对比，非目标）
ATTACKER_API_KEY=sk-xxx
ATTACKER_MODEL=gpt-4
ATTACKER_BASE_URL=https://api.openai.com/v1

# 评分方 (Judge LLM)
SCORER_API_KEY=sk-xxx
SCORER_MODEL=gpt-4o-mini
SCORER_BASE_URL=https://api.openai.com/v1
```

**`load_env_config()`** 返回两个 tuple：
- `attacker_config` — (api_key, model, base_url)
- `scorer_config` — (api_key, model, base_url)

### 8.3 目标工厂：factories.py

**`create_attack_target(env_config)`** — 从环境变量创建 PyRIT 原生的 `OpenAIChatTarget`：
```python
target = OpenAIChatTarget(
    endpoint=base_url,
    api_key=api_key,
    model_name=model
)
```

**`build_custom_target(target_url, api_key, model, api_format, **kwargs)`** — 攻击自定义 HTTP API 端点的统一工厂函数。支持多种 API 格式：

| `api_format` | 适配器 | 适用场景 |
|-------------|--------|---------|
| `openai` | `OpenAIChatTarget` | OpenAI 兼容 API |
| `raw` | `CustomHttpChatTarget` | 通用 HTTP Chat API |
| `gemini` | Gemini 适配器 | Google Gemini API |
| `claude` | Claude 适配器 | Anthropic Claude API |

### 8.4 HTTP 目标：http_target.py

**`CustomHttpChatTarget`** — 自定义 HTTP Chat API 客户端的 PyRIT 适配器。

**支持的认证方式**：
- Cookie/Session 认证
- 自定义请求头 (X-API-Key, X-CSRF-Token 等)
- Bearer Token 认证
- 自定义请求/响应格式映射

**关键特性**：
- SSL 证书验证可选关闭（内网自签证书场景）
- 可配置的连接超时
- 支持流式/非流式响应
- 自动 session 复用（`close()` 清理）

### 8.5 模型探测：target_type_probe.py

**`probe_model_info(target_url, target_api_key, target_model, ...)`** — 自动化目标模型架构探测。

**探测能力**：
1. **模型类型探测** — 发送轻量测试请求识别目标模型名称和版本
2. **API 格式检测** — 自动识别 OpenAI/Gemini/Claude/原始格式
3. **速率限制自适应探测** — 渐进式增加并发数，观察 429 响应或延迟飙升
4. **架构指纹识别** — 识别 Ollama 本地部署 (`ollama_detector.py`)
5. **安全配置评估** — 检测目标 API 的安全防护措施

**速率限制自适应算法**：
```
并发数: 1 → 成功 → 并发数: 2 → 成功 → 并发数: 4 → 成功 → 并发数: 8
                                                    ↓ 429/超时
                                          推荐并发数: 4
```

**⚠️ Ollama 特例**：Ollama 是本地单 GPU 串行推理，无内置速率限制，高并发不会返回 429 而是直接导致 GPU OOM。`ollama_detector.py` 自动识别 Ollama 实例并强制设置 `concurrent=1`。

### 8.6 目标重试与容错

所有目标交互通过 `utils/retry.py` 的统一重试机制：
```python
retry_if(is_retryable_error, max_tries=3, delay_fn=backoff_delay)
```

**可重试错误**：
- HTTP 429 (Rate Limited)
- HTTP 502/503/504 (服务器临时故障)
- 连接超时 (ConnectionError, TimeoutError)
- DNS 解析失败
- SSL 握手失败（可选重试）

---

## 9. PyRIT 集成层次

```
Level 3: PyRITNativeOrchestrator     PyRIT Red Team 统一调度器 (orchestrators/)
         Facade 封装 PyRIT 原生攻击类

Level 2: PyRIT Executor             攻击执行 (pyrit.executor.attack)
         PromptSendingAttack    — 单轮攻击
         CrescendoAttack        — 多轮渐进式
         PAIRAttack             — 迭代反驳式
         TAPAttack              — 树搜索
         ManyShotJailbreakAttack— Many-shot 淹没
         FlipAttack             — 对话翻转
         ChunkedRequestAttack   — 分块绕过
         SkeletonKeyAttack      — Skeleton Key

Level 1: PyRIT Core                PyRIT 基础组件
         OpenAIChatTarget       — LLM 目标抽象
         SQLiteMemory           — 持久化存储
         CentralMemory          — 全局 Memory 单例
         SelfAskTrueFalseScorer — Judge LLM 评分器
         PromptConverterConfiguration — 转换器配置
```

---

## 10. 策略路由决策树

渗透模式下 `_execute_single_attack()` 的策略路由逻辑：

```
strategy in AttackStrategy
  │
  ├─ PROBE ─────────────────────┐
  ├─ BASE64/ROT13 ──────────────┤
  ├─ ROLEPLAY/ACADEMIC/STEALTH ─┤
  ├─ BRUTEFORCE/TRANSLATION ────┤
  ├─ ENCODING/FEWSHOT ──────────┤
  ├─ DEEPINCEPTION/JSON_HIJACK ─┤
  ├─ RAG_POISON_DOC/... ────────┤
  ├─ CROSS_AGENT_INJECT/... ────┤
  ├─ API_FUZZ/... ──────────────┤
  ├─ FRONTIER ──────────────────┤
  │   └──> _run_prompt_sending()
  │         └──> PromptSendingAttack.execute_async()
  │               ├── Converter pipeline
  │               ├── Target.send_prompt()
  │               └── Scorer.score_async()
  │
  ├─ PAIR ─────> _delegate_to_orch("pair")    → PyRITNativeOrchestrator._execute_pair_attack()
  ├─ TAP ──────> _delegate_to_orch("tap")     → PyRITNativeOrchestrator._execute_tap_attack()
  ├─ FLIP ─────> _delegate_to_orch("flip")    → PyRITNativeOrchestrator._execute_flip_attack()
  ├─ CHUNKED ──> _delegate_to_orch("chunked") → PyRITNativeOrchestrator._execute_chunked_attack()
  ├─ MANYSHOT ─> _delegate_to_orch("manyshot")→ PyRITNativeOrchestrator._execute_manyshot_attack()
  ├─ SKELETON_KEY → _delegate_to_orch("skeleton_key") → PyRITNativeOrchestrator._execute_skeleton_key_attack()
  │
  └─ CRESCENDO → _run_crescendo()
                   └──> CrescendoAttack.execute_async()
```

---

## 11. 三条执行路径对比

| 维度 | Legacy 模式 | 渗透模式 | 探索模板模式 |
|------|-----------|---------|------------|
| **入口** | `main.py --lang cn` | `main.py --penetrating-mode` | `main.py --exploring-template` |
| **数据源** | `datasets/test_cases_*.json` | `scenarios/templates/*.yaml` | `scenarios/templates/*.yaml` |
| **Payload** | `datasets/payloads/core/*.yaml` | `datasets/payloads/*.yaml` + `frontier/vulns/*/` | Converter 链 |
| **调度器** | `PyRITNativeOrchestrator` / Legacy | `PenetratingOrchestrator` | 内联 asyncio |
| **攻击策略** | 67 组攻击组合 | ~30 种策略自动匹配 | 用户指定 Converter 链 |
| **报告** | 热力图 + 战报 + 渗透报告 | 综合安全评估报告 | Converter 有效性排名 |
| **适用场景** | 日常红队操作 | PyRIT Red Team 渗透 | 快速测试 Converter 效果 |

---

## 12. 渗透时的数据流动

```
渗透时仅修改 → scenarios/templates/penetrating_prompts.yaml


      penetrating_prompts.yaml                        系统自动完成
      ═══════════════════                     ═══════════════
      metadata:                               ✅ Pydantic 校验
      config:                                 ✅ 变体生成（~5/prompt）
        max_concurrent: 3                     ✅ 策略自动匹配
        enable_advanced: true                 ✅ Converter 管道
      prompts:                                ✅ 目标交互
        - id: P001                            ✅ Judge LLM 评分
          objective: "..."                    ✅ Memory 持久化
          criterion: "..."                    ✅ Markdown 报告
          category: jailbreak                 ✅ 前沿漏洞自动注入
          difficulty: medium
```

**渗透期间只需关注 `prompts` 数组的内容编写，其余全部由系统预固化。**
