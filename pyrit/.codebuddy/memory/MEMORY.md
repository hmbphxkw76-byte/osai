# AI-300 Framework - Long-Term Memory

## 项目概述
基于 PyRIT 0.14.0 的 OffSec AI-300 (OSAI+) 考试全覆盖红队评估框架。
目标：修改 YAML 配置和攻击载荷后，全流程自动化执行并生成专业报告。

## 关键规则

### Windows 编码（强制）
- 所有 Python 脚本必须在入口处强制 UTF-8（sys.stdout.reconfigure + PYTHONIOENCODING）
- Rich Console 在 Windows 默认使用 GBK，不设置会报 `UnicodeEncodeError`

### PyRIT 组件使用
- `ROT13Converter`（非 Rot13Converter）
- `SearchReplaceConverter(pattern=, replace=)`（非 old_value/new_value）
- YAML 含多文档分隔符 `---` 时用 `yaml.safe_load_all()`

### 死代码清理（强制）
- 每次代码调整/优化后，必须清除所有死代码和未调用代码
- **默认检查工具：`ruff`**
  - `ruff check pyrit_ai300/ --select F,I,E,W` — 未使用导入/变量 + 风格
  - `ruff check pyrit_ai300/ --select F401,F841` — 仅死代码检测
  - `ruff check pyrit_ai300/ --fix` — 自动修复可修复项

### 架构设计原则
- **调度器 + 格式转换器原则（ARCH-001）**：框架只做调度器+格式转换器，不重复造轮子
- **数据与代码分离**：`data/`（载荷库）+ `config/`（配置）在根目录，`pyrit_ai300/` 为纯代码
- **组件映射集中管理**：`component_registry.py` 的 CONVERTER_MAP / SCORER_MAP
- **攻击注册表集中管理**：`attack_registry.py` 的 ATTACK_REGISTRY
- **v3.0 执行层原则**：SmartMatcher 只负责选择 PyRIT 攻击策略，执行全部交给 PyRIT 原生攻击
- **模块独立原则**：reconnaissance/ 不 import attack/，通过 TargetProfile JSON 通信

## 评分器配置（2026-07-17 简化）

### 目录模式
- **配置目录**：`config/scores/`（每个后端一个 YAML 文件）
- **现有文件**：`ollama.yaml`（默认）、`zhipu.yaml`（智谱模板）
- **已删除**：旧 `config/scores/`（6 个文件）+ `config/scorers.yaml`（旧格式）+ `config/scores.yaml`（中间态单文件）

### ASI 自动选择评分器类型
- `AttackOrchestrator._ASI_SCORER_MAP`：ASI 类别 → 评分器类型映射
  - ASI01/06/09, LLM01/02/09 → `refusal`（拒绝检测）
  - ASI02/04/07, LLM03/06/10 → `true_false`（真假判断）
  - ASI03/08/10, LLM05/08 → `category`（分类评分）
  - ASI05, LLM04/07 → `substring`（子串匹配）

### 外部 LLM 评分器配置
- **CLI 参数**：`--scorer-url` / `--scorer-key` / `--scorer-model`
- **优先级**：CLI 参数 > 环境变量 > 配置文件 > 默认 local_ollama
- **环境变量**：`SCORER_BASE_URL` / `SCORER_API_KEY` / `SCORER_MODEL_NAME`
- **默认后端**：local_ollama（qwen3:0.6b @ http://localhost:11434/v1）

### 代码入口
- `AttackOrchestrator.__init__(scorer_url=, scorer_key=, scorer_model=)`
- `AttackOrchestrator._load_scorer_config()` — 目录扫描加载（`config/scores/*.yaml`）+ CLI 覆盖
- `AttackOrchestrator.build_scorers(asi_category=)` — ASI 自动选择
- `AI300Engine.__init__(scorer_url=, scorer_key=, scorer_model=)` — 传递给 Orchestrator

## 占位符系统（Placeholder System）
- **三级分类**：
  - Tier 1：`{goal}` / `{objective}` — 用 `--objective` 参数
  - Tier 2：编码变体（14 种）— 从 objective 自动编码
  - Tier 3：领域参数（50+ 种）— 用 `--placeholders key=value`
- **CLI 参数**：`--experiment` > `--objective` > `auto_discover` > `--placeholder-file` > interactive
- **实验模式**：`load_experiment_config(path)` 加载 `config/placeholders/{path}.yaml`
- **中文界面**：`PLACEHOLDER_LABELS_CN` 字典映射 50+ 占位符到中文名

## 目录结构（简化）
```
data/                 # 数据层
  ├── owasp/          #   唯一真相源（LLM01-10 + ASI01-10 + expericing/）
  └── recon_templates/#   侦察探测模板
config/               # 配置层
  ├── placeholders/   #   占位符配置（llm01-llm10/ + expericing/）
  ├── recon/          #   侦察配置
  ├── scores/         #   评分器 LLM 后端（每后端一个 YAML）
  └── targets/        #   目标配置
pyrit_ai300/          # 代码层
  ├── reconnaissance/ #   侦察引擎（独立）
  ├── attack/         #   攻击引擎扩展
  ├── orchestrators/  #   编排器（attack_orchestrator/smart_matcher/component_registry）
  ├── payloads/       #   载荷管理
  ├── pipeline/       #   流水线追踪
  ├── reporting/      #   报告生成
  └── tests/          #   单元测试
```

## 数据架构规则（DATA-001）
- **OWASP 为唯一真相源** — 所有载荷仅存储在 `data/owasp/`
- **OWASP ID 隐含攻击面** — 不存储 `surfaces` 和 `ai300_chapters`
- **surfaces 由侦察动态生成** — TargetProfile.surfaces 来自 ReconEngine
- **AI-300 章节动态推导** — `reporting/chapter_mapper.py`
- **多级子目录扫描** — `load_data_dir()` 使用 `rglob` 递归
- **顶层文件跳过规则** — 有子目录时顶层 YAML 不加载
- **ref_path 格式** — `owasp:llm:llm01:jailbreak:aim`

## 已删除的死代码/冗余（2026-07-17）
- `config/scores/` 旧目录（6 个文件）→ 简化为 `config/scores/` 新目录（每后端一个 YAML）
- `config/scorers.yaml`（旧格式含 scorer_definitions/best_scorer_by_scenario）
- `config/catalog/` 目录 + `build_attack_list()` 方法
- `PayloadManager.get_payloads_by_surface()` / `get_payloads_by_chapter()`
- `AI300Engine.MODULES` / `_run_module()` / `_run_all_modules()`
- `ReportGenerator._extract_surfaces()`
- `cli.py` 的 `run` 子命令
- 所有 YAML 的 `surfaces` 和 `ai300_chapters` 字段
- 52 个过时载荷（DAN/STAN/GCG 后缀/glitch token 等）

## 已删除的死代码（2026-07-17 二次清理）
- `AttackOrchestrator._execute_with_fallback()` 同步版本（约52行）
- `AttackOrchestrator._execute_single_attack()` 同步版本（约101行）
- `SmartMatcher.AttackMemory` 类（约100行，从未被调用）
- `SmartMatcher.AdaptiveExplorationManager` 类（约62行，从未被调用）
- `SmartMatcher._build_exploration_fallback()` / `record_attack_result()` / `get_memory_summary()` / `get_exploration_summary()` 方法
- `PayloadManager.get_payloads()` / `get_all_modules()` / `get_attacks_for_module()` / `add_payload()` / `get_metadata()` 5个 legacy 兼容方法
- `orchestrators/__init__.py` 中未使用的 `RULE_BASED_SCORERS` 导出
- 对应测试（6个）从 174 减少到 168

## 已删除的死代码（2026-07-16）
- `converters/`, `scorers/`, `attacks/` 整个目录（空壳）
- `text_jailbreak_integration.py`（模板已转 YAML）
- `display/` 目录（拆分为 pipeline/ + reporting/）
- `strategy_optimizer.py`, `scenario_runner.py`, `attack_factory.py` 等

## 覆盖进度
- AI-300 Module: 11/11 | OWASP LLM: 10/10 | OWASP Agentic: 10/10
- 载荷库: 590 个有效载荷（LLM 537 + Agentic 105）
- Jailbreak 模板: 165 个（统一 YAML 格式）
- 侦察工具: 2 个（Garak + DeepTeam）✅
- 测试: 168 passed, 1 skipped

## Garak 独立 venv 架构
- **原因**：garak 0.15.1 与 pyrit 0.14.0 的 datasets 版本冲突
- **方案**：独立 venv `.garak/` + subprocess 调用
- **安装**：`make setup-garak`
