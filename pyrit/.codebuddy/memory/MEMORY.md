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
- **默认检查工具：`ruff`**（替代 pyflakes/vulture）
  - `ruff check pyrit_ai300/ --select F,I,E,W` — 未使用导入/变量 + 风格
  - `ruff check pyrit_ai300/ --select F401,F841` — 仅死代码检测
  - `ruff check pyrit_ai300/ --fix` — 自动修复可修复项
  - 全量扫描：`ruff check pyrit_ai300/`（含 200+ 规则）
- vulture 作为补充：`vulture pyrit_ai300/ --min-confidence 80`（需人工复核）

### 架构设计原则
- **调度器 + 格式转换器原则（ARCH-001）**：本框架只做调度器+格式转换器，不重复造轮子。侦察/攻击能力全部来自开源工具，本框架只做调度编排+格式转换
- 直接复用 PyRIT 组件，不重复造轮子
- **数据与代码分离**：`data/`（载荷库）+ `config/`（配置）在根目录（数据层），`pyrit_ai300/` 为纯代码（引擎层）
- **组件映射集中管理**：所有 PyRIT 组件统一通过 `component_registry.py` 的 CONVERTER_MAP / SCORER_MAP 引用
- **攻击注册表集中管理**：所有攻击元数据通过 `attack_registry.py` 的 ATTACK_REGISTRY 管理
- **v3.0 执行层原则**：SmartMatcher 只负责选择 PyRIT 攻击策略，执行全部交给 PyRIT 原生攻击
- **大文件拆分原则**：多职责大文件拆分为独立模块 + 主类文件；高内聚模块保持现状
- **模块独立原则**：reconnaissance/ 不 import attack/，两者通过 TargetProfile JSON 文件通信

## TextJailBreak 模板迁移（2026-07-16）
- **统一格式方案**：165 个模板从 PyRIT 包目录转为统一 YAML 格式，存入 `data/owasp/llm/llm01/jailbreak/`
- **删除** `text_jailbreak_integration.py`（254 行）和对应测试类（约 130 行）
- **渲染方式**：`{goal}` 字符串替换，无需 PyRIT Jinja2 依赖
- **模板选择**：`text_jailbreak:aim` / `text_jailbreak:random` / `text_jailbreak:all`
- **data/ 唯一真相源**：所有 YAML 载荷（OWASP + TextJailBreak）集中管理

## Smart Match 引擎（v3.0 核心）
- 决策流程：payload → normalize_payload() → analyze_payload() → PayloadProfile(五维+置信度) → 两层策略选择 → PyRIT 原生攻击
- 攻击探针族：DIRECT_SINGLE / PROGRESSIVE / TREE_SEARCH / ITERATIVE / EXPLORATORY / MULTI_PRESET
- Fallback 链：Crescendo → TAP → PAIR → PromptSending
- 动态参数：`max_turns = 5 + complexity_score + token_factor`

## 目录结构（pyrit/ 根目录）
```
data/                 # 数据层：载荷库
  ├── owasp/          #   唯一真相源
  │   ├── llm/        #     LLM01-LLM10
  │   │   ├── llm01/  #       技术组文件 + jailbreak/ 模板目录
  │   │   └── ...
  │   └── agentic/    #     ASI01-ASI10
  ├── surfaces/       #   攻击面分析文档（仅引用，不存储载荷）
  └── recon_templates/#   侦察探测模板（system_prompt/capability/boundary）
config/               # 配置层：catalog/ targets/ output/ scorers.yaml
  └── recon/          #   侦察配置（recon.yaml）
tools/                # 外部工具目录（当前为空，所有工具均为 Python 原生）
  └── README.md       #   工具清单 + 安装方式

pyrit_ai300/          # 代码层：纯框架引擎
  ├── reconnaissance/ #   侦察引擎（完全独立，不 import attack/）✅ 已实现
  │   ├── recon_engine.py       #   统一调度入口
  │   ├── target_profile.py     #   TargetProfile 数据模型（唯一接口契约）
  │   ├── profile_merger.py     #   多工具结果合并
  │   ├── adapters/             #   薄壳适配器（每个 ≤100 行）
  │   │   ├── base_adapter.py   #   抽象基类
  │   │   ├── llmmap_adapter.py #   → import LLMmap
  │   │   ├── garak_adapter.py  #   → import garak
  │   │   └── deepteam_adapter.py # → import deepteam
  │   └── utils/
  │       ├── http_client.py    #   HTTP 客户端
  │       └── result_parser.py  #   结果解析器
  ├── attack/         #   攻击引擎扩展 ✅ 已实现
  │   ├── profile_loader.py     #   读 TargetProfile → SmartMatcher 参数
  │   └── __init__.py
  ├── orchestrators/  #   编排器（已有）
  ├── payloads/       #   载荷管理（已有）
  ├── pipeline/       #   流水线追踪（已有）
  ├── reporting/      #   报告生成（已有）
  │   ├── chapter_mapper.py     #   OWASP ID → AI-300 章节映射
  ├── tests/          #   单元测试（已有）
  │   └── test_recon/           #   侦察测试 ✅ 46 tests
  ├── utils/          #   工具函数（已有）
  ├── __init__.py     #   AI300Engine 入口
  └── cli.py          #   命令行接口（薄壳路由，owasp/recon/list/report 四个子命令）
```

## 数据架构规则（2026-07-17 更新）
- **规则编号**: DATA-001（详见 `.codebuddy/rules/data-architecture.md`）
- **OWASP 为唯一真相源** — 所有载荷仅存储在 `data/owasp/`，禁止在其他目录重复存储
- **OWASP ID 隐含攻击面** — 载荷 YAML 不存储 `surfaces` 和 `ai300_chapters`，由 OWASP ID 隐含
- **surfaces 由侦察阶段动态生成** — TargetProfile.surfaces 来自 ReconEngine 检测，与载荷元数据解耦
- **AI-300 章节动态推导** — `reporting/chapter_mapper.py` 从 OWASP ID 推导考试章节
- **新增载荷流程**：确定 OWASP 类别 → 创建 YAML → CLI 自动可用（零映射维护）
- **PayloadManager 扩展**:
  - `get_scope_refs(scope)` — 解析 scope 为 ref 列表（单个 ID/分组/全部）
  - `get_payloads_by_owasp(owasp_id)` — 按 OWASP ID 获取载荷
  - `resolve_refs()` 支持 dict 类型载荷去重
  - `_resolve_text_jailbreak()` — 从 payload_store 读取模板，`{goal}` 替换渲染
- **多级子目录扫描** — `load_data_dir()` 使用 `rglob` 递归扫描 `llm01/jailbreak/*.yaml` 等嵌套目录
- **顶层文件跳过规则** — 有对应子目录时，顶层 YAML 不加载到 payload store（子目录是唯一真相源）
  - `llm/llm01.yaml` + `llm/llm01/` 子目录 → 跳过顶层，只加载子目录
  - `agentic/asi01.yaml`（无子目录）→ 正常加载
- **已删除顶层 llmXX.yaml** — `llm01-llm10.yaml` 纯元数据无载荷，代码零引用，已删除
  - 载荷全部来自子目录，`agentic/asiXX.yaml` 保留（扁平结构）
- **YAML 三要素规范（强制）** — 所有载荷 YAML 必须包含 `id`（OWASP ID）+ `name`（类别名）+ `description`（描述）
  - `id` 为 OWASP 分类标识（如 `LLM01`），不参与 ref_path 构建
  - `name` 为人类可读类别名（如 `Prompt Injection`）
  - `description` 描述该技术组的攻击原理和范围
  - 241/241 文件已覆盖（含特殊文件 `_registry.core.yaml` 和 `_template.yaml`）
- **ref_path 格式** — 嵌套子目录使用 `owasp:llm:llm01:jailbreak:aim`
- **双格式兼容** — 支持字符串列表（旧格式）和字典列表（新格式）两种载荷存储方式

## 已删除的死代码（2026-07-17）
- `PayloadManager.get_payloads_by_surface()` / `get_payloads_by_chapter()` — 由 `get_scope_refs()` 替代
- `AI300Engine.MODULES` — 由 `OWASP_SCOPES` 替代
- `AI300Engine._run_module()` / `_run_all_modules()` — 由 `_run_scope()` 替代
- `ReportGenerator._extract_surfaces()` — surfaces 不再存储，无需提取
- `cli.py` 的 `run` 子命令 — 由 `owasp` 子命令替代
- 所有 YAML 的 `surfaces` 和 `ai300_chapters` 字段 — 由 OWASP ID 隐含

## 已删除的过时载荷（2026-07-17）
- `llm01/jailbreak.yaml` — 删除 24 个 DAN/STAN/DUDE/AntiDAN/Developer Mode 等经典越狱（对当前模型完全无效）
- `llm01/adversarial_suffix.yaml` — 删除 6 个预计算 GCG 后缀（针对旧版开源模型，已被修复）
- `llm01/glitch_token.yaml` — 删除 12 个已知异常 token（SolidGoldMagikarp/覚醒/SpaceEngineers 等，已被修复）
- `llm01/many_shot_jailbreak.yaml` — 删除 1 个 25-shot 显式有害 Q&A（被内容过滤器拦截）
- `llm01/encoding_bypass.yaml` — 删除 9 种编码技术（Braille/Morse/Atbash/Leet/NATO/Base2048/Ecoji/UUEncode/MIME）
- 总计删除 52 个载荷，从 589 减少到 537，仅保留对当前模型有效的技术

## 已删除的死代码（2026-07-16）
- `converters/converter_chain.py`, `scorers/scorer_factory.py`, `payloads/dataset_loader.py`
- `orchestrators/strategy_optimizer.py`, `scenarios/`, `reporting/templates.py`
- `utils/validators.py`, `utils/config_loader.py`, `targets/`
- `orchestrators/scenario_runner.py`, `attacks/attack_factory.py`
- `converters/`, `scorers/`, `attacks/` 整个目录（空壳）
- `display/` 整个目录（终端展示与报告生成职责混合，拆分为 `pipeline/` + `reporting/`）
- `payloads/text_jailbreak_integration.py` — TextJailBreak 包装类（模板已转统一 YAML 格式）

## 术语约定

- **写入三库**：指同时写入以下三处，是本项目规则沉淀的标准流程
  1. **开发规范** — `docs/DEVELOPMENT.md`（面向开发者的可读文档）
  2. **规则库** — `.codebuddy/rules/*.md`（带编号的强制规则，如 DATA-001）
  3. **记忆库** — `.codebuddy/memory/MEMORY.md`（长期记忆，供 AI 跨会话引用）

## 载荷跟踪与添加规则（2026-07-17 生效）
- **规则编号**: DATA-002（详见 `.codebuddy/rules/payload-tracking.md`）
- **跟踪清单模板**: `data/owasp/_tracking.template.yaml`
- **跟踪目录**: `data/owasp/_tracking/`（存放进行中的跟踪清单）
- **来源优先级**: CVE（P0）→ 论文（P1）→ 博客/PoC（P2）→ 工具更新（P3）→ 实战发现（P4）
- **状态流转**: pending → researching → writing → testing → done / rejected
- **新增流程**: 创建跟踪清单 → 评估有效性 → 编写 YAML → 更新注册表 → 测试验证
- **定期审计**: 每周 CVE 监控 → 每月论文检查 → 每季度载荷清理

## 研究资料搜索规则（2026-07-17 生效）

- **规则编号**: RES-001（详见 `.codebuddy/rules/research-sources.md`）
- **搜索优先级**: arxiv.org（学术论文）→ github.com（开源代码）→ 自行查询（兜底）
- **适用范围**: 所有 AI 红队相关技术资料搜索活动

## 测试策略（2026-07-16 生效）
- **规则编号**: TEST-001（详见 `.codebuddy/rules/testing-strategy.md`）
- **单元测试即回归测试**：65 个测试覆盖核心模块，每次修改后必须跑 `make test`
- **分层策略**：每次修改 → `make test`；提交前 → `make ci`；发布前 → `make test-cov`
- **集成测试**：仅考试前用真实目标验证端到端，日常开发不跑

## 侦察工具组合（ARCH-001 配套）
- **核心（Python 原生）**：Garak（扫描）+ DeepTeam（OWASP 红队）
- **外部独立使用**：LLMmap（指纹识别，需预训练模型权重，用户自行通过 CLI 使用）
- **集成方式**：Adapter 薄壳，每个 ≤100 行，零重复造轮子
- **接口契约**：TargetProfile JSON（侦察 → 攻击的唯一通信方式）

## Garak 独立 venv 架构（2026-07-17）
- **原因**：garak 0.15.1 要求 `datasets>=3.0.0,<4.0`，与 pyrit 0.14.0 的 `datasets>=4.8.0` 冲突
- **方案**：garak 安装在独立 venv `.garak/`，主程序通过 subprocess 调用
- **文件**：`garak-requirements.txt`（固定版本：garak==0.15.1, datasets>=3.0.0,<4.0, litellm>=1.84.0,<1.91.0）
- **适配器**：`garak_adapter.py` 重写为 subprocess 模式，`_get_garak_python()` 自动检测路径
- **安装**：`make setup-garak`（Windows）/ `make setup-garak-unix`（Linux/Mac）
- **环境变量**：`GARAK_PYTHON` 可覆盖自动检测路径
- **pyproject.toml**：garak 从 `recon` optional-dependencies 移除，仅保留 deepteam

## 侦察驱动攻击数据流（v3.1 新增）
- **目标配置三级优先级**：CLI `--target-url` > 侦察 `target_endpoint` > `target_config.yaml`
- **策略参数注入**：ProfileLoader 输出 `preferred_probe_families` + `aggression_level` → SmartMatcher
- **SmartMatcher 侦察约束**：`_precise_model_match()` 中侦察推荐优先级高于 ASI 约束
- **Garak 直接 URL 支持**：`--endpoint` 参数 + `OPENAI_BASE_URL` 环境变量
- **DeepTeam 直接 URL 支持**：`_build_model_callback()` HTTP POST 到 target URL
- **CLI `--target-url`**：跳过 YAML 配置，直接指定目标 URL 进行攻击

## 覆盖进度
- AI-300 Module: 11/11 | OWASP LLM: 10/10 | OWASP Agentic: 10/10
- PyRIT 转换器: 16/55 已映射 | PyRIT 评分器: 14/40+ 已映射
- Jailbreak 模板: 165 个（统一 YAML 格式，data/owasp/llm/llm01/jailbreak/）
- 侦察工具: 2 个（Garak + DeepTeam）✅ 适配器已实现（LLMmap 需预训练权重，改为外部独立使用）
- 侦察引擎: ✅ 完成（TargetProfile + ReconEngine + 3 Adapters + ProfileMerger + ProfileLoader）
- 测试: 174 passed, 1 skipped（含 ProfileMerger 26 + 适配器更新 6 个新测试）
- 载荷库: 537 个有效载荷（2026-07-17 清理了 52 个对当前模型无效的过时载荷）
