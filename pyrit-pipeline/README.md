# PyRIT Pipeline — ASR 数据驱动的端到端 AI Red Team 流水线

> 基于 PyRIT 1.0.1 原生框架扩展。核心攻击/评分/输出 100% 使用原生 API，
> ASR 驱动选择器与报告增强为自研模块 (8 个, 不干扰原生生命周期)。

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 15:40 — 新建 README.md, 补充入口文档
>   2026-8-1 18:00 — v5.0: 全量原生功能接入 (GCG/Fuzzer/多模态/XPIA/AIRT/Garak/Benchmark/Foundry/HTTP Target/限速/HTML报告)
>   2026-8-1 19:40 — 优化6: 更正声明, 明确区分原生核心与自研增强模块
>   2026-8-1 22:00 — R-008 更新: 不再清理 output/ 目录，改为仅清理 __pycache__ 等临时文件

---

## 快速开始

### 1. 环境配置

```bash
# 克隆项目
git clone <repo-url>
cd pyrit-pipeline

# 安装依赖 (使用 uv)
uv sync

# 复制环境配置模板
cp config/.env.example config/.env
# 编辑 config/.env, 填入 API Key 和 Endpoint

# 创建 PyRIT 配置
cp config/.pyrit_conf  # 已包含在项目中
```

### 2. 运行流水线

```bash
# 基础运行 (默认配置: harmbench + jbb_behaviors + strong_reject)
python main.py

# 自定义数据集 + 限制采样数
python main.py --datasets harmbench jbb_behaviors --max-dataset-size 10

# 指定技术
python main.py --techniques many_shot tap crescendo_simulated

# 启用 Converter (ASR 驱动差异化路由)
python main.py --converters rot13 base64

# 断点续跑
python main.py --resume <scenario_result_id>
```

### 3. 高级功能

```bash
# GCG 对抗后缀生成 (需要 torch + GPU)
python main.py --gcg-model meta-llama/Llama-2-7b-chat-hf --gcg-steps 100

# Fuzzer MCTS 载荷变异
python main.py --fuzzer-iterations 50

# 多模态攻击 (自动检测目标模态)
python main.py --multimodal

# XPIA 跨域提示注入工作流
python main.py --xpia --xpia-attack-content "Ignore all previous instructions..."

# 多场景选择
python main.py --scenario airt_jailbreak
python main.py --scenario garak_encoding
python main.py --scenario benchmark_adversarial
python main.py --scenario foundry_red_team

# HTTP Target (Burp 请求文件)
python main.py --http-target data/burp/request.txt

# 限速包装 (并发信号量 + 退避重试)
python main.py --rate-limit 3 --rate-limit-retries 5

# EXHAUSTIVE 全技术评估模式
python main.py --exhaustive

# HTML/PDF 报告
python main.py --html-report --pdf-report
```

### 4. Web Red Team (浏览器自动化红队)

```bash
# 安装 web-redteam 依赖
uv sync --extra web-redteam

# 使用 YAML Profile
python -m web_bridge.run --target-profile web_bridge/targets/same_domain/example_portal.yaml

# 快速 URL 模式
python -m web_bridge.run --target-url https://example.com/chat --attack-type prompt_sending
```

### 5. 运行测试

```bash
# 全部测试
python -m pytest -v

# 带覆盖率
python -m pytest --cov=pipeline --cov=web_bridge --cov-report=term-missing

# 仅 pipeline 测试
python -m pytest pipeline/tests/ -v

# 仅 web_bridge 测试
python -m pytest web_bridge/tests/ -v
```

---

## 目录结构

```
pyrit-pipeline/
├── pipeline/               # 五阶段流水线 (ASR 驱动)
│   ├── __init__.py         # 公共接口
│   ├── context.py          # PipelineContext 状态容器
│   ├── config.py           # 命令行参数 (含 GCG/Fuzzer/多模态/XPIA/场景选择)
│   ├── asr_optimizer.py    # ASR 驱动优化器 (历史查询 + 同次运行反馈)
│   ├── converter_factory.py # Converter 工厂 (ASR 驱动差异化路由)
│   ├── stage_init.py       # Stage 1: 原生初始化 + GCG/Fuzzer/多模态/限速/HTTP Target
│   ├── stage_scenario.py   # Stage 2: 场景配置 (多场景 + ASR 驱动)
│   ├── stage_initialize.py # Stage 3: 场景初始化 + ASR 反馈闭环
│   ├── stage_execute.py    # Stage 4: 场景执行 + ASR 分析
│   ├── stage_output.py      # Stage 5: 结果输出 + HTML/PDF 报告
│   ├── promptgen/           # P0: GCG + Fuzzer 生成器集成
│   │   ├── __init__.py
│   │   ├── gcg_integration.py     # GCG 对抗后缀 (原生 pyrit.executor.promptgen.gcg)
│   │   └── fuzzer_integration.py  # Fuzzer MCTS 变异 (原生 pyrit.executor.promptgen.fuzzer)
│   ├── multimodal/          # P0: 多模态攻击支持
│   │   └── __init__.py      # 原生 ModalityRouter + 图像 Converter
│   ├── scenarios/           # P1: 多场景注册表
│   │   └── __init__.py      # AIRT/Garak/Benchmark/Foundry 场景选择
│   ├── workflows/           # P1: XPIA 工作流集成
│   │   └── __init__.py      # 原生 pyrit.executor.workflow.xpia
│   ├── rate_limited_target.py  # P2: 限速 Target 包装器 (自研)
│   ├── reporting/              # P3: HTML/PDF 报告生成 (format_converter + Jinja2)
│   ├── rich_metadata_loader.py     # 富元数据加载器
│   ├── rich_metadata_migration.py  # 富元数据 → 原生 SeedDataset 迁移
│   └── tests/              # 单元测试
├── web_bridge/            # Playwright Web 红队框架
├── config/                # 用户认证配置 (.env, .pyrit_conf)
├── data/                   # 种子数据集 + 系统配置
├── docs/                   # 架构文档
├── scripts/               # 工具脚本
├── output/                # 运行时报告输出
├── pyproject.toml          # 依赖管理
└── main.py                 # 流水线入口
```

---

## 五阶段流水线数据流

```
┌─────────────────────────────────────────────────────────────────────┐
│                        main.py (薄入口)                              │
│  ctx = PipelineContext(args=parse_args())                           │
└─────────┬───────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────┐
│  Stage 1: Init       │  ConfigurationLoader.load_with_overrides()
│  pipeline/stage_init  │  → config/.env + config/.pyrit_conf
│                      │  → CentralMemory(SQLite) + 全部 Registry
│  产出: ctx.config     │  → TargetRegistry / ScorerRegistry / TechniqueRegistry
└─────────┬────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 2: Scenario    pipeline/stage_scenario.py                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ASR 驱动载荷优先级                                          │   │
│  │ → query_historical_asr_by_category()                        │   │
│  │ → sort_datasets_by_asr() (Laplace 平滑)                     │   │
│  │ → get_technique_asr_summary() (ASR 排行榜)                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ASR 驱动 Converter 路由 (per-technique 差异化)              │   │
│  │ → query_historical_asr_by_technique()                       │   │
│  │ → build_technique_converter_map(asr_by_technique=...)      │   │
│  │   高 ASR 技术 → 全部 converters                              │   │
│  │   低 ASR 技术 → converter 子集                                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  → TextAdaptive(selector=EpsilonGreedyTechniqueSelector)           │
│  → CompoundDatasetAttackConfiguration.per_dataset()                │
│  → scenario.set_params_from_args(params)                            │
│  产出: ctx.scenario, ctx.objective_scorer                          │
└─────────┬───────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 3: Initialize  pipeline/stage_initialize.py                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ★ 同次运行 ASR 反馈闭环 (Stage 3 → Stage 2/4)              │   │
│  │ → query_current_run_asr_by_technique(scenario_result_id)    │   │
│  │ → ctx.metadata["current_run_asr"] = asr_map                │   │
│  │ → ASR 趋势分析 (当前运行 vs 历史)                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ASR 智能调度 (执行顺序优化)                                  │   │
│  │ → 合并当前运行 ASR + 历史 ASR                               │   │
│  │ → 按 ASR 降序重排 _atomic_attacks                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  → scenario.initialize_async()                                     │
│  产出: ctx.metadata["current_run_asr"]                             │
└─────────┬───────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 4: Execute     pipeline/stage_execute.py                    │
│  → scenario.run_async()                                             │
│    → AttackExecutor(max_concurrency=5) + asyncio.Queue              │
│    → EpsilonGreedyTechniqueSelector.select_async()                  │
│      (current_run scope: 读取同次运行 ASR 动态调参)                │
│    → SequentialAttack(FIRST_SUCCESS)                               │
│    → AttackResult 持久化到 CentralMemory                            │
│  → result.get_display_groups() (按技术聚合)                         │
│  → result.objective_achieved_rate() (总体 ASR)                      │
│  产出: ctx.result, ctx.asr_per_technique, ctx.overall_asr          │
└─────────┬───────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 5: Output      pipeline/stage_output.py                     │
│  → output_scenario_async(sort_groups_by_success_rate=True)         │
│  → output_scorer_async(scorer_identifier=...)                      │
│  → output_attack_async(format="markdown", sink=FileSink)            │
│  → ASR 排行榜展示                                                   │
│  产出: ctx.output_dir                                              │
└───────────────────────────────────────────────────────────────────┘
```

---

## ASR 数据驱动架构

### 核心闭环

```
                    ┌───────────────────────┐
                    │    CentralMemory      │
                    │    (SQLite)           │
                    └───────┬───────────────┘
                            │
                 ┌──────────┴──────────┐
                 │                      │
                 ▼                      ▼
    ┌────────────────────┐   ┌────────────────────┐
    │  历史查询           │   │  同次运行反馈      │
    │  (跨运行学习)       │   │  (动态调参)        │
    │                    │   │                    │
    │  query_historical  │   │  query_current_   │
    │  _asr_by_category  │   │  run_asr_by_      │
    │  _asr_by_technique │   │  technique        │
    └────────┬───────────┘   └────────┬───────────┘
             │                         │
             ▼                         ▼
    ┌─────────────────────────────────────────────┐
    │           ASR 驱动决策                        │
    │                                             │
    │  Stage 2: 数据集排序 + 技术选择 + Converter  │
    │           路由 (per-technique 差异化)         │
    │  Stage 3: ASR 反馈闭环 + 智能调度            │
    │  Stage 4: EpsilonGreedy 动态调参             │
    └─────────────────────────────────────────────┘
```

### ASR 驱动的关键设计

| 设计 | 实现 | 原生 API |
|------|------|----------|
| 历史 ASR 查询 | `query_historical_asr_by_category()` | `memory.get_attack_results()` |
| 数据集优先级 | `sort_datasets_by_asr()` (Laplace 平滑) | 自定义排序 |
| 技术选择 | `EpsilonGreedyTechniqueSelector` | 原生 selector |
| 同次运行反馈 | `query_current_run_asr_by_technique()` | `memory.get_attack_results()` |
| Converter 路由 | `build_technique_converter_map()` | `technique_converters` 参数 |
| 智能调度 | `_reorder_attacks_by_asr()` | 重排 `_atomic_attacks` |
| ASR 展示 | `get_asr_summary()` / `get_technique_asr_summary()` | 日志输出 |

---

## 原生 API 对齐

所有攻击、评分、输出均 100% 调用 PyRIT 原生 API：

| 组件 | 原生 API | 用途 |
|------|----------|------|
| 配置加载 | `ConfigurationLoader` | 加载 config/.env + config/.pyrit_conf |
| 内存管理 | `CentralMemory` | SQLite 持久化 |
| 目标注册 | `TargetRegistry` | 目标模型注册 |
| 评分器注册 | `ScorerRegistry` | 评分器注册 |
| 技术注册 | `AttackTechniqueRegistry` | 攻击技术注册 |
| 场景 | `TextAdaptive` | 自适应场景 |
| 选择器 | `EpsilonGreedyTechniqueSelector` | ASR 驱动技术选择 |
| 数据集 | `CompoundDatasetAttackConfiguration` | per-dataset 独立预算 |
| Converter | `ROT13Converter` / `Base64Converter` / ... | 载荷变换 |
| 执行 | `scenario.run_async()` | AttackExecutor 并发 |
| 输出 | `output_scenario_async` / `output_attack_async` | Markdown 报告 |
| Web 目标 | `PlaywrightTarget` | 浏览器自动化 |
| 攻击 | `PromptSendingAttack` / `RedTeamingAttack` / `CrescendoAttack` / `TAPAttack` | 攻击策略 |
| **GCG** | `pyrit.executor.promptgen.gcg.GCG` | 对抗后缀生成 (arXiv:2307.15043) |
| **Fuzzer** | `pyrit.executor.promptgen.fuzzer.Fuzzer` | MCTS 载荷变异 (arXiv:2309.11453) |
| **多模态** | `ModalityRouter` + `AddImageTextConverter` 等 | 图像/音频/视频攻击 |
| **XPIA** | `pyrit.executor.workflow.xpia.XpiaWorkflow` | 跨域提示注入 |
| **AIRT** | `pyrit.scenario.scenarios.airt.*` | AIRT 标准化场景集 |
| **Garak** | `pyrit.scenario.scenarios.garak.*` | Garak 探测场景 |
| **Benchmark** | `pyrit.scenario.scenarios.benchmark.AdversarialBenchmark` | 对抗基准 |
| **Foundry** | `pyrit.scenario.scenarios.foundry.RedTeamAgentScenario` | Azure AI Foundry |
| **HTTP Target** | `pyrit.prompt_target.HTTPTarget` | Burp 请求文件 |

### 自研模块 (PyRIT 原生不提供)

| 模块 | 用途 | 学术依据 |
|------|------|----------|
| `RateLimitedTarget` | 并发信号量 + 退避重试 | Circuit Breaker Pattern |
| `format_converter.py` | Markdown → HTML/PDF 转换 | OWASP 报告格式最佳实践 |
| `rich_metadata_migration.py` | 富元数据 → 原生 SeedDataset | HarmBench 元数据标准 |
| `FailureTypeRoutingSelector` | 失败类型路由技术选择 | arXiv:2310.04451 (PAIR) |
| `asr_prior_registry.py` | 学术 ASR 先验数据 | JailbreakBench (arXiv:2402.01135) |
| `evidence_collector.py` | 结构化漏洞证据收集 | OWASP Top 10 for LLM |
| `diversity_analyzer.py` | 攻击多样性分析 | Shannon 熵 + 覆盖度 |

---

## CLI 参数完整参考

### 数据集
| 参数 | 默认 | 说明 |
|------|------|------|
| `--datasets` | harmbench jbb_behaviors strong_reject | 数据集名称列表 |
| `--max-dataset-size` | 10 | 每个数据集最大采样数 |
| `--local-datasets` | None | 本地 .prompt 文件路径列表 |

### 技术选择
| 参数 | 默认 | 说明 |
|------|------|------|
| `--techniques` | None (DEFAULT) | 技术名称列表 (ALL/core/extra/具体名称) |
| `--max-attempts` | 3 | 每 objective 最多尝试技术数 |
| `--exhaustive` | False | 全技术评估模式 (不提前停止) |

### 场景
| 参数 | 默认 | 说明 |
|------|------|------|
| `--scenario` | text_adaptive | 场景类型 (airt_*/garak_*/benchmark_*/foundry_*) |

### ASR 驱动
| 参数 | 默认 | 说明 |
|------|------|------|
| `--epsilon` | 0.1 | Epsilon-greedy 探索概率 |
| `--selector-scope` | all_runs | ASR 查询范围 |

### GCG
| 参数 | 默认 | 说明 |
|------|------|------|
| `--gcg-model` | None | HuggingFace 模型名 |
| `--gcg-steps` | 100 | 优化步数 |
| `--gcg-batch-size` | 128 | 每步候选数 |

### Fuzzer
| 参数 | 默认 | 说明 |
|------|------|------|
| `--fuzzer-iterations` | None | MCTS 迭代次数 |

### 多模态
| 参数 | 默认 | 说明 |
|------|------|------|
| `--multimodal` | False | 启用多模态攻击 |
| `--multimodal-converters` | None | 多模态 Converter 预设名称 |

### XPIA
| 参数 | 默认 | 说明 |
|------|------|------|
| `--xpia` | False | 启用 XPIA 工作流 |
| `--xpia-attack-content` | None | XPIA 攻击内容 |

### HTTP Target
| 参数 | 默认 | 说明 |
|------|------|------|
| `--http-target` | None | Burp 请求文件路径 |

### 限速
| 参数 | 默认 | 说明 |
|------|------|------|
| `--rate-limit` | None | 最大并发数 |
| `--rate-limit-retries` | 5 | 重试次数 |

### 报告
| 参数 | 默认 | 说明 |
|------|------|------|
| `--html-report` | False | 生成 HTML 报告 |
| `--pdf-report` | False | 生成 PDF 报告 |
| `--output-dir` | None | 报告输出目录 |

### 执行控制
| 参数 | 默认 | 说明 |
|------|------|------|
| `--max-concurrency` | 5 | 最大并发 AtomicAttack 数 |
| `--max-retries` | 3 | 失败重试次数 |
| `--resume` | None | 断点续跑 ID |
| `--no-baseline` | False | 禁用 baseline |
| `--converters` | None | Converter 名称列表 |
| `--config-file` | config/.pyrit_conf | 配置文件路径 |

---

## 开发指南

### 添加新阶段

1. 在 `pipeline/` 下创建 `stage_<name>.py`
2. 定义 `async def run(ctx: PipelineContext) -> None`
3. 在 `PipelineContext` 中新增字段
4. 在 `main.py` 中串联

### 添加新数据集

1. 在 `data/` 下创建 `.prompt` 文件 (YAML 格式)
2. 使用 `--local-datasets data/path/to/file.prompt` 加载

### 添加新 Converter

1. 在 `converter_factory.py` 的 `_CONVERTER_REGISTRY` 中注册
2. 使用 `--converters <name>` 启用

### 提交前检查

```bash
# 安装 pre-commit
pip install pre-commit
pre-commit install

# 手动检查
pre-commit run --all-files
```
