# 端到端攻击流程文档

> **版本**: v1.0
> **日期**: 2026-8-1
> **PyRIT 版本**: 1.0.1
> **学术依据**: PyRIT [[arXiv:2407.01232v1]](https://arxiv.org/abs/2407.01232), JailbreakBench [[arXiv:2402.01135]](https://arxiv.org/abs/2402.01135)

---

## 目录

1. [端到端流程概览](#一端到端流程概览)
2. [Stage 1: 原生初始化](#二stage-1-原生初始化)
3. [Stage 2: ASR 驱动场景配置](#三stage-2-asr-驱动场景配置)
4. [Stage 3: 场景初始化](#四stage-3-场景初始化)
5. [Stage 4: 场景执行](#五stage-4-场景执行)
6. [Stage 5: 执行后分析](#六stage-5-执行后分析)
7. [Stage 6: 结果输出](#七stage-6-结果输出)
8. [完整执行示例](#八完整执行示例)

---

## 一、端到端流程概览

```
用户执行: python main.py --datasets harmbench jbb_behaviors strong_reject --load-local-datasets

Stage 1: 原生初始化
  ├── ConfigurationLoader.load_with_overrides(.pyrit_conf)
  ├── config.initialize_pyrit_async()
  │   ├── TargetInitializer → TargetRegistry (3个目标)
  │   ├── ScorerInitializer → ScorerRegistry (评分器)
  │   ├── TechniqueInitializer → AttackTechniqueRegistry (17个工厂)
  │   └── LoadDefaultDatasets → CentralMemory
  ├── 加载本地 .prompt 数据集 (RichMetadataLoader)
  ├── [可选] GCG 对抗后缀生成
  ├── [可选] Fuzzer MCTS 载荷变异
  ├── [可选] 多模态能力检测
  ├── [可选] RateLimitedTarget 包装
  └── [可选] HTTPTarget 配置

Stage 2: ASR 驱动场景配置
  ├── 查询历史 ASR (by category + by technique)
  ├── 按 ASR 排序数据集 (sort_datasets_by_asr)
  ├── 获取评分器 (三级 fallback)
  ├── 构建 warm-start ASR (学术先验 + 经验融合)
  ├── 构建 GroupFallbackExecutor 降级链
  ├── [可选] TieredSelectionWizard 技术选择
  ├── 构造 FailureTypeRoutingSelector
  ├── 构造 TextAdaptive (零覆盖, 原生)
  ├── 构建 CompoundDatasetAttackConfiguration (per-dataset 预算)
  ├── Converter 双路由 (CLI + Target 感知)
  └── scenario.set_params_from_args(params)

Stage 3: 场景初始化
  ├── scenario.initialize_async()
  │   ├── _resolve_objective_target("openai_chat")
  │   ├── DatasetAttackConfiguration.get_attack_groups_by_dataset_async()
  │   ├── _build_techniques_dict() (工厂创建技术实例)
  │   └── _build_atomic_attacks_async()
  ├── ASR 智能调度 (重排 AtomicAttack 执行顺序)
  └── [可选] 同次运行 ASR 反馈 (resume 场景)

Stage 4: 场景执行
  ├── scenario.run_async()
  │   ├── _get_remaining_atomic_attacks_async() (过滤已完成)
  │   └── _execute_atomic_attacks_parallel_async()
  │       └── AttackExecutor(max_concurrency=5)
  │           └── 每个 AtomicAttack.run_async():
  │               └── SequentialAttack(FIRST_SUCCESS):
  │                   ├── Child 1: 发送 prompt → 评分 → 成功/失败
  │                   ├── 成功 → 停止
  │                   └── 失败 → Child 2 → ... → 最多 3 个
  ├── 后处理扫描 (FailureTypeEventHandler)
  ├── ASR 分析 (get_display_groups + objective_achieved_rate)
  └── 经验 ASR 保存

Stage 5: 执行后分析
  ├── 执行成果概要
  ├── 实测 ASR vs 先验对比表
  ├── Converter 韧性分析
  ├── ASR 经验闭环 (经验写回 Top-N)
  └── 成果回溯 + 下次运行建议

Stage 6: 结果输出
  ├── output_scenario_async() (场景结果汇总)
  ├── output_scorer_async() (评分器指标)
  ├── output_attack_async(format="markdown") (攻击 Markdown 报告)
  ├── EvidenceCollector (结构化漏洞证据)
  ├── GroupFallbackExecutor (降级链报告)
  ├── [可选] DiversityAnalyzer / ConverterLogCollector / TieredSelectionWizard
  └── [可选] HTML/PDF 报告生成
```

---

## 二、Stage 1: 原生初始化

### 2.1 配置加载

```python
# 原生 API
config = ConfigurationLoader.load_with_overrides(config_file=config_path)
config.silent = True
await config.initialize_pyrit_async()
```

初始化器执行链：
```
TargetInitializer → TargetRegistry: openai_chat, objective_scorer_chat, adversarial_chat
ScorerInitializer → ScorerRegistry: refusal/scale/ACS/task_achieved + DEFAULT_OBJECTIVE_SCORER
TechniqueInitializer(tags=[core, extra]) → AttackTechniqueRegistry: 17 个工厂
LoadDefaultDatasets → CentralMemory: airt_hate, airt_fairness, ...
```

### 2.2 数据集加载

```python
# 自研: RichMetadataLoader (扩展原生 SeedDataset)
from pipeline.targets.rich_metadata_loader import load_rich_prompt_as_native

dataset = load_rich_prompt_as_native(file_path="data/seed_datasets/owasp/llm01_prompt_injection.prompt")
await memory.add_seed_datasets_to_memory_async(datasets=[dataset], added_by="pipeline.stages.stage_init")
```

支持的数据集类型：
- **预下载数据集**: `data/seed_datasets/benchmarks/{name}.prompt` (harmbench, jbb_behaviors, strong_reject)
- **OWASP 本地数据集**: `data/seed_datasets/owasp/*.prompt` (LLM01-LLM10, ASI01-ASI10)
- **CVE 数据集**: `data/seed_datasets/cve/*.prompt`
- **自定义数据集**: `data/seed_datasets/custom/*.prompt`

### 2.3 可选增强

| 功能 | CLI 参数 | 原生 API | 说明 |
|------|---------|---------|------|
| GCG 对抗后缀 | `--gcg-model` | `pyrit.executor.promptgen.gcg` | 生成对抗后缀注入数据集 |
| Fuzzer 变异 | `--fuzzer-iterations` | `pyrit.executor.promptgen.fuzzer` | MCTS 载荷变异 |
| 多模态检测 | `--multimodal` | `discover_target_capabilities_async` | 运行时能力探测 |
| 限速包装 | `--rate-limit N` | 自研 RateLimitedTarget | 并发信号量 + 指数退避 |
| HTTP Target | `--http-target FILE` | `HTTPTarget` | Burp 请求文件 |

---

## 三、Stage 2: ASR 驱动场景配置

### 3.1 ASR 查询与排序

```python
# 自研: ASR 驱动数据集排序
asr_by_category = query_historical_asr_by_category()
sorted_datasets = sort_datasets_by_asr(args.datasets, asr_by_category=asr_by_category)
```

### 3.2 Warm-start ASR 构建

```python
# 自研: 学术 ASR 先验 + 经验 ASR 融合
warm_start_asr = _build_warm_start_asr(model_name, model_tier, owasp_id)
warm_start_asr = merge_empirical_with_priors(warm_start_asr)  # 经验覆盖先验
```

数据源：
- **学术先验**: `data/setting/asr_priors.yaml` (JailbreakBench ASR 基线数据)
- **经验数据**: `output/empirical_asr/{model_name}.json` (历史运行写回)

### 3.3 FailureTypeRoutingSelector 构造

```python
# 自研: 继承原生 EpsilonGreedyTechniqueSelector
selector = FailureTypeRoutingSelector(
    epsilon=args.epsilon,           # 探索概率 (默认 0.1)
    scope=selector_scope,           # all_runs / current_run
    strategy_mode="academic",       # 策略模式
    model_name=model_name,          # 目标模型名
    model_tier=model_tier,          # 模型安全过滤等级
    owasp_id=owasp_id,             # OWASP 分类 ID
    warm_start_asr=warm_start_asr,  # warm-start ASR 字典
)
```

### 3.4 TextAdaptive 场景构造 (零覆盖)

```python
# 原生 API: 直接使用原生 TextAdaptive, 不覆盖任何方法
scenario = TextAdaptive(
    objective_scorer=objective_scorer,
    selector=selector,
    scenario_result_id=args.resume,
)
```

### 3.5 参数注入

```python
# 原生 API: 单次 set_params_from_args 调用
params = {
    "objective_target": "openai_chat",
    "dataset_config": dataset_config,
    "max_retries": args.max_retries,
    "max_concurrency": args.max_concurrency,
    "max_attempts_per_objective": max_attempts,
    "include_baseline": not args.no_baseline,
    "memory_labels": {...},
    # 可选: scenario_techniques, technique_converters
}
scenario.set_params_from_args(args=params)
```

### 3.6 停止策略

| 策略 | 条件 | max_attempts |
|------|------|-------------|
| FIRST_SUCCESS (默认) | 首成功即停 | 3 (可配置) |
| EXHAUSTIVE | 全技术尝试 | 999 |
| 全局首停 | `STOP_ON_FIRST_SUCCESS=true` | 1 |

---

## 四、Stage 3: 场景初始化

### 4.1 原生初始化

```python
# 原生 API
await ctx.scenario.initialize_async()
```

内部执行：
1. `_resolve_objective_target("openai_chat")` → OpenAIChatTarget
2. `DatasetAttackConfiguration.get_attack_groups_by_dataset_async()` → AttackSeedGroup 列表
3. `_build_techniques_dict()` → 技术实例 + eval_hash
4. `_build_atomic_attacks_async()` → AtomicAttack 列表 (含 SequentialAttack)

### 4.2 ASR 智能调度

```python
# 自研: 按 ASR 优先级重排 AtomicAttack 执行顺序
# 优先级: GroupFallbackExecutor 降级链 > 当前运行 ASR > 历史 ASR > 0.5 (Laplace)
scenario._atomic_attacks = sorted(atomic_attacks, key=_attack_priority, reverse=True)
```

---

## 五、Stage 4: 场景执行

### 5.1 原生执行

```python
# 原生 API
result = await ctx.scenario.run_async()
```

内部执行：
1. `_get_remaining_atomic_attacks_async()` — 过滤已完成 (resume 场景)
2. `_execute_atomic_attacks_parallel_async()` — AttackExecutor 并发执行
3. 每个 AtomicAttack 执行 SequentialAttack(FIRST_SUCCESS)
4. AttackResult 自动持久化到 CentralMemory

### 5.2 后处理扫描

```python
# 自研: 非侵入式 post-execution scan
for _attack_id, attack_results in result.attack_results.items():
    for ar in attack_results:
        handler.on_attack_result(ar)  # 失败类型反馈到 selector
        # 扫描 SequentialAttack 子结果
        for child in getattr(ar, "child_attack_results", []) or []:
            handler.on_attack_result(child)
```

### 5.3 ASR 分析

```python
# 原生 API
groups = result.get_display_groups()  # 按技术聚合
for group_name, attack_results in groups.items():
    successes = sum(1 for r in attack_results if r.outcome == AttackOutcome.SUCCESS)
    asr = (successes / total) * 100

# 原生 API: 总体 ASR
ctx.overall_asr = result.objective_achieved_rate()
```

---

## 六、Stage 5: 执行后分析

### 6.1 ASR 实测 vs 先验对比

```
┌─ 实测 ASR vs 先验 ─────────────────────────────────────────┐
│ 技术                              实测     先验     差异    样本
│ ──────────────────────────────── ─────── ─────── ─────── ────
│ crescendo_simulated                82.0%   82.0%   +0.0%   10 ↑
│ tap                                62.0%   62.0%   +0.0%   10 ↑
│ pair                               53.0%   53.0%   +0.0%   10 ↑
└────────────────────────────────────────────────────────────┘
```

### 6.2 经验写回

```python
# 自研: 经验 ASR 自动写回
save_empirical_asr(ctx.asr_per_technique)
```

### 6.3 下次运行建议

根据 ASR 水平和失败模式自动生成建议：
- ASR < 10%: 启用多轮攻击策略
- ASR < 30%: 增加 Converter 变体池
- timeout 频繁: 降低 max_concurrency
- objective_not_achieved: 升级到更高 ASR 技术

---

## 七、Stage 6: 结果输出

### 7.1 原生输出

```python
# 原生 API
await output_scenario_async(result, sort_groups_by_success_rate=True)
await output_scorer_async(scorer_identifier=ctx.objective_scorer.get_identifier())
await output_attack_async(ar, format="markdown", sink=FileSink(path=md_path))
```

### 7.2 证据收集

```python
# 自研: EvidenceCollector
collector = EvidenceCollector(target_model=model_name, model_tier=model_tier)
collection = collector.collect(
    attack_results=result.attack_results,
    scenario_result_id=result.id,
    asr_per_technique=ctx.asr_per_technique,
    overall_asr=ctx.overall_asr,
    owasp_id=owasp_id,
)
collector.save_json(collection, output_dir=output_dir)
collector.save_markdown(collection, output_dir=output_dir)
```

### 7.3 L5 报告生成 (ReportGenerator + EvidenceExporter)

```python
# L5: 优先使用 ReportGenerator (三级证据链 + OWASP 矩阵 + ZIP 证据包)
from pipeline.reporting.report_generator import ReportGenerator

generator = ReportGenerator()
report_result = await generator.generate_report(
    scenario_result=result,
    output_dir=report_output_dir,
    evidence_dir=evidence_dir,
    generate_html=args.html_report,
    generate_pdf=args.pdf_report,
)
# 回退: 自研 format_converter (Markdown → HTML/PDF)
# convert_report_formats(markdown_content, ...)
```

报告内容：
1. 报告概述 (ASR、攻击总数、成功数、证据数)
2. ASR 矩阵 (技术 × ASR + 可视化条)
3. OWASP 分类映射
4. 完整攻击证据 (攻击链路 + Converter 日志 + 载荷)
5. 失败分析
6. ASR 趋势
7. [可选] 多样性分析 / Converter 路由统计 / 降级链报告

---

## 八、完整执行示例

### 8.1 基本运行

```bash
# 默认运行
python main.py

# 指定数据集 + OWASP
python main.py --datasets harmbench jbb_behaviors strong_reject --load-local-datasets

# 快速评估 (Tier 1)
python main.py --load-local-datasets --tier-layer 1

# 深度评估 (Tier 3)
python main.py --load-local-datasets --tier-layer 3
```

### 8.2 高级运行

```bash
# 全技术尝试 + HTML 报告
python main.py --techniques ALL --exhaustive --html-report

# 启用 Converter 路由
python main.py --converters rot13 base64 leetspeak

# 启用 GCG + Fuzzer + 多模态
python main.py --gcg-model meta-llama/Llama-2-7b-chat-hf --fuzzer-iterations 50 --multimodal

# HTTP Target + 限速
python main.py --http-target data/burp/request.txt --rate-limit 3

# 断点续跑
python main.py --resume <scenario_result_id>
```

### 8.3 输出结构

```
output/
├── db/                                    # SQLite 数据库
├── empirical_asr/                         # 经验 ASR
│   └── {model_name}.json
├── evidence/
│   └── redteam_YYYYMMDD_HHMMSS/
│       ├── attacks/                       # Markdown 攻击报告
│       ├── conversations/                 # 对话记录
│       ├── scores/                        # 评分记录
│       ├── blurred/                       # 模糊图像
│       ├── evidence.json                  # 结构化证据 JSON
│       ├── evidence_report.md             # 证据 Markdown 报告
│       └── group_fallback.json            # 降级链报告
├── logs/
│   ├── pipeline-YYYYMMDD_HHMMSS.noise.log # 噪音日志
├── reports/                               # HTML/PDF 报告
│   ├── report.md
│   ├── report.html
│   └── report.pdf
└── empirical_asr.json                     # 经验 ASR (全局)
```

---

## 九、Web Bridge: 侦察 → 认证 → AI 端点 → 主流水线

### 9.1 架构概览

Web Bridge 是 `web_redteam` 框架与 `pyrit-pipeline` 主流水线的桥接层，
实现从 **侦察** → **认证** → **到达 AI 端点** → **主流水线 6 阶段深入攻击** 的完整闭环。

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Web Bridge 完整链路                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 侦察 (Recon)                                                        │
│     ├─ recon-pipeline 扫描目标 → ReconReport                           │
│     ├─ 端点发现 + 能力推断 + 认证检测                                    │
│     └─ 产出: recon_result.json (可序列化复用)                           │
│                                                                         │
│  2. 认证 (Auth)                                                         │
│     ├─ --auth-state-file 复用 → 跳过重复认证 (G2)                      │
│     ├─ 浏览器认证 (Playwright) → cookies + storage_state              │
│     ├─ API 认证 (header/token) → auth_headers                          │
│     └─ 产出: AuthState (可导出/导入)                                    │
│                                                                         │
│  3. 到达 AI 端点 (Target)                                               │
│     ├─ PlaywrightTarget (Web App 模式) — G1: page 保持活跃             │
│     ├─ HTTPTarget (API 模式) — G3: callback_function 提取响应          │
│     ├─ RateLimitedTarget 包装 — 限速+并发控制                           │
│     └─ G4: recon_http_target 不注册 default tag, 避免冲突              │
│                                                                         │
│  4. 主流水线 6 阶段                                                     │
│     ├─ Stage 1: 初始化 + recon_result 加载                             │
│     ├─ Stage 2: 场景配置 — G6: recon 推荐始终显示                      │
│     ├─ Stage 3: 场景初始化 — Target 就绪                                │
│     ├─ Stage 4: 执行攻击 — Converter 链 + Scorer                        │
│     ├─ Stage 5: 后分析 — ASR 实测 vs 先验                               │
│     └─ Stage 6: 输出 — 证据收集 + L5 报告                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.2 关键修复 (G1-G6)

| 修复 | 文件 | 问题描述 | 解决方案 | 学术依据 |
|------|------|----------|----------|----------|
| G1 | `web_bridge.py` | `_browser_auth` 关闭浏览器后 `PlaywrightTarget` 无 page | 移除 `session.close()`, page 保持活跃, 由 `main.py` finally 清理 | OWASP ASVS V2.4 |
| G2 | `stage_target_classify.py` | 无认证状态复用, 每次重复认证 | `try_reuse_auth_state()` + storage_state 恢复 + `export_auth_state()` 导出 | NIST SP 800-63B |
| G3 | `recon_target_bridge.py` | `HTTPTarget` 缺 `callback_function`, 响应无法解析 | 添加 `get_http_target_json_response_callback_function` | PyRIT (arXiv:2407.01232) |
| G4 | `recon_target_bridge.py` | recon target 注册 `default` tag, 与 `stage_target_classify` 冲突 | 移除 `default` tag, 仅保留 `scorer` tag | PyRIT Registry 设计 |
| G5 | `web_bridge.py` | `ssl=False` 硬编码, 企业内网自签证书场景不兼容 | `WEB_BRIDGE_SSL_VERIFY` 环境变量可配置 | OWASP ASVS V9.2 |
| G6 | `main.py` | `--scenario` 指定时 recon 推荐完全跳过 | 始终显示推荐, 仅 `--scenario` 未指定时自动选择 | MITRE ATT&CK T1592 |

### 9.3 使用方式

```bash
# 完整链路: recon → auth → pipeline
python main.py --target-url https://chat.example.com --web-bridge --load-local-datasets

# 复用认证状态 (跳过重复认证)
python main.py --target-url https://api.example.com/v1/chat --web-bridge --auth-state-file outputs/auth_state/auth_state.json --load-local-datasets

# 从 recon JSON 加载 (跳过侦察步骤)
python main.py --recon-json outputs/recon/recon_result.json --load-local-datasets

# 企业内网 (自签证书)
$env:WEB_BRIDGE_SSL_VERIFY = "true"
python main.py --target-url https://internal-llm.corp.local --web-bridge --load-local-datasets
```

---

*文档结束*
