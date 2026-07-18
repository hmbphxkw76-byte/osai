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

## 占位符系统（Placeholder System v2.0，2026-07-18）
- **三级分类**：
  - Tier 1：`{goal}` / `{objective}` — scope 级，定义在 `data/owasp/llm/{scope}/_goals.yaml`
  - Tier 2：编码变体（39 种 PyRIT 转换器）— 智能选择（见下方）
  - Tier 3：领域参数（50+ 种）— 模板级，声明在模板 `placeholders:` 段
- **自动发现**：框架扫描模板 `placeholders:` 段提取默认值
- **用户覆盖**：`config/placeholders/{scope}/_goals.yaml`（merge_strategy: append/prepend/replace）
- **CLI 参数**：`--experiment` > `--objective` > `auto_discover` > `--placeholder-file` > interactive
- **实验模式**：`load_experiment_config(path)` 加载 `data/owasp/expericing/{path}/experiment.yaml`
- **加载函数**：`load_scope_goals(scope)` — 合并框架默认 + 用户自定义
- **中文界面**：`PLACEHOLDER_LABELS_CN` 字典映射 50+ 占位符到中文名

## 智能编码选择器（Encoding Selector v1.0，2026-07-18）
- **问题**：当前 Tier 2 是固定列表暴力枚举（每个 payload 试全部编码），请求量大
- **方案**：三级过滤 — OWASP 类别静态过滤 → 语言兼容性过滤 → 目标自适应探测
- **核心模块**：`pyrit_ai300/orchestrators/encoding_selector.py`
- **静态映射**：`CONVERTER_OWASP_COMPATIBILITY`（39 转换器 × OWASP 类别）
- **语言过滤**：`LANGUAGE_INCOMPATIBLE_CONVERTERS`（CJK 排除 rot13/leetspeak 等拉丁编码）
- **目标画像**：`TargetProfile` — 运行时探测编码通过率
- **选择逻辑**：`select_encodings_for_payload()` — 综合三级过滤选最优编码
- **集成点**：`build_attack_list_from_refs()` 使用智能选择器替代静态配置
- **扩展转换器**：component_registry.py 从 17 增到 39 个 PyRIT 转换器
- **Pipeline 追踪**：4 个日志方法 + show_encoding_summary() 集成到 PipelineTracker
- **追踪阶段**：encoding_filter_owasp → encoding_filter_language → encoding_probe → encoding_selection
- **测试**：35 个新测试（27 选择器 + 8 Pipeline），221 total passed

## 目录结构（简化，v2.0）
```
data/                 # 数据层
  ├── owasp/          #   唯一真相源
  │   ├── llm/        #   LLM01-10（每 scope 含 _goals.yaml + 模板 YAML）
  │   ├── agentic/    #   ASI01-10
  │   └── expericing/ #   实验数据（含 experiment.yaml）
  └── recon_templates/#   侦察探测模板
config/               # 配置层（用户覆盖）
  ├── attack/         #   攻击策略配置（defaults.yaml + patterns.yaml）
  ├── placeholders/   #   用户自定义覆盖（每 scope 可选 _goals.yaml）
  ├── recon/          #   侦察配置
  ├── scores/         #   评分器 LLM 后端（每后端一个 YAML）
  ├── headers/        #   认证头文件
  ├── output/         #   输出报告配置
  └── targets/        #   目标配置
pyrit_ai300/          # 代码层（纯执行引擎）
  ├── reconnaissance/ #   侦察引擎（独立，3 个适配器：Garak + DeepTeam + ProtocolFingerprint）
  ├── attack/         #   攻击引擎扩展
  ├── orchestrators/  #   编排器（attack_orchestrator/smart_matcher/component_registry）
  ├── payloads/       #   载荷管理
  ├── pipeline/       #   流水线追踪
  ├── reporting/      #   报告生成
  └── tests/          #   单元测试（168 tests）
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

## 配置迁移（2026-07-17 三次清理）
- **目标**：config 目录成为唯一配置源，代码中不再硬编码策略配置
- **新建文件**：`config/attack/defaults.yaml`（3个配置块）
  - `default_converters`：20 个 OWASP ID → 转换器列表
  - `default_scorers`：20 个 OWASP ID → 评分器列表
  - `asi_scorer_map`：20 个 ASI/LLM 类别 → 评分器类型
- **删除硬编码**：
  - `AttackOrchestrator._DEFAULT_CONVERTERS`（~22行）
  - `AttackOrchestrator._DEFAULT_SCORERS`（~22行）
  - `AttackOrchestrator._ASI_SCORER_MAP`（~22行类属性）
- **新增方法**：`AttackOrchestrator._load_attack_defaults()`（类级别缓存加载）
- **修改方法**：`build_attack_list_from_refs` / `build_scorers` / `cli.py` 信息展示
- **净减代码**：约 50 行硬编码 → 1 个 YAML 文件 + 5 行加载逻辑
- **测试**：168 passed, 1 skipped（无回归）

## 已删除的死代码（2026-07-18 Placeholder 重构）
- `config/placeholders/` 下 37 个文件：
  - 10 个 `*_tier1_goal.yaml` → 迁移为 `data/owasp/llm/{scope}/_goals.yaml`（3 个 scope 使用 {goal}）
  - 20 个 Tier 3 占位符配置 → 内联到模板 `placeholders:` 段
  - 10 个 `manifest.yaml` → 删除（占位符自声明）
  - 1 个 `expericing/tier1_goal.yaml` → 迁移到 `data/owasp/expericing/tier1_goal/experiment.yaml`
- `load_scope_manifest()` 函数 → 删除（不再需要）
- `discover_scopes()` → 重写（扫描 data/owasp/llm/）
- `auto_discover_placeholders()` → 重写（从模板 placeholders 段读取）
- `validate_placeholders()` → 重写（从模板 placeholders 段读取）
- 向导步骤 3 → 简化（不再基于 manifest）

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

## CLI 命令（v3.0）

```
ai300 owasp <scope>     # OWASP 标准攻击（llm01/asi01/llm/agentic/all/ref_path）
  --target-file <yaml>   # 目标配置文件
  --target-dir <dir>     # 多目标批量（目录下所有 YAML）
  --target-url <url>     # 直接 URL
  --profile <json>       # 侦察生成的 TargetProfile
  --objective <text>     # 攻击目标（替换 {goal} 占位符）
  --placeholders k=v     # 自定义占位符
  --experiment <path>    # 实验配置（config/placeholders/{path}.yaml）
  --auto-recon           # 先侦察再攻击
  --scorer-url/key/model # 外部 LLM 评分器
  --format md|html       # 报告格式
  --list-placeholders    # 列出占位符
  --no-prompt            # 禁用交互式提示

ai300 recon -t <target>  # 侦察目标
ai300 list <component>   # 列出组件（attacks/converters/scorers/owasp）
ai300 report -r <json>   # 生成报告
```

## 覆盖进度
- AI-300 Module: 11/11 | OWASP LLM: 10/10 | OWASP Agentic: 10/10
- 载荷库: 590 个有效载荷（LLM 537 + Agentic 105）
- Jailbreak 模板: 165 个（统一 YAML 格式）
- 侦察工具: 3 个（Garak + DeepTeam + ProtocolFingerprint）✅
- 占位符系统: v2.0（模板自包含 + _goals.yaml）✅
- 智能编码选择器: v1.0（OWASP 过滤 + 语言感知 + 目标自适应）✅
- 测试: 220 passed, 1 skipped

## ProtocolFingerprintAdapter（2026-07-18）
- **来源**：BishopFox/aimap 的指纹探测逻辑（无 Shodan 依赖）
- **功能**：协议识别（MCP/Ollama/vLLM/LangServe/Gradio/Streamlit/OpenWebUI/TGI）、模型提取、认证检测、系统提示泄露、MCP 工具枚举
- **依赖**：零外部依赖（复用 http_client.py，stdlib urllib）
- **注册**：ReconEngine.ADAPTER_MAP["protocol_fingerprint"]
- **配置**：config/recon/recon.yaml → tools.protocol_fingerprint

## 流式侦察优化（Streaming Recon，2026-07-18）
- **原策略**：3 适配器并行，等全部完成后一次性合并（最慢工具决定总耗时）
- **新策略**：每个适配器完成后立即 yield 部分画像
  - ProtocolFingerprint（~30s）→ 部分画像可驱动攻击准备
  - Garak/DeepTeam（1-5min）→ 补充漏洞发现
- **新增方法**：
  - `ReconEngine.run_streaming()` — 生成器，yield `(tool_name, partial_profile, is_complete)`
  - `ProfileMerger.merge_incremental()` — 增量合并新结果到现有 TargetProfile
- **CLI**：`--auto-recon` 使用流式模式，打印每个工具完成进度
- **测试**：220 passed, 1 skipped（新增 10 个测试）

## AIMAP→Garak 顺序侦察整合（2026-07-18）
- **原问题**：wizard 中手动执行 AIMAP → 提取端点 → 配置 Garak → 再调用 `engine.run()`（AIMAP 执行两次，桥接未追踪）
- **新方案**：AIMAP→Garak 顺序侦察整合到 `ReconEngine.run()` 和 `run_streaming()` 内部
- **流程**：
  1. AIMAP 优先执行（协议识别）
  2. `extract_garak_endpoints()` → 提取可探测端点
  3. 配置 Garak（model_type/model_name/endpoint）
  4. `log_recon_aimap_garak_bridge()` → 记录到 PipelineTracker
  5. 执行剩余工具（Garak + DeepTeam）
  6. 合并结果 → TargetProfile
- **新增方法**：
  - `ReconEngine._run_single_adapter()` — 内部方法，统一处理单个适配器执行 + tracker 记录
  - `PipelineTracker.log_recon_aimap_garak_bridge()` — 记录 AIMAP→Garak 端点桥接步骤
- **wizard 简化**：`_run_wizard_recon()` 从三步简化为两步（目标选择 → 确认执行）
- **测试**：224 passed, 1 skipped（无回归）

## Garak 独立 venv 架构
- **原因**：garak 0.15.1 与 pyrit 0.14.0 的 datasets 版本冲突
- **方案**：独立 venv `.garak/` + subprocess 调用
- **安装**：`make setup-garak`
