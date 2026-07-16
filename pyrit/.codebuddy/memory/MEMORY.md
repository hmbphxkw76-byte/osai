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
- 直接复用 PyRIT 组件，不重复造轮子
- **数据与代码分离**：`data/`（载荷库）+ `config/`（配置）在根目录（数据层），`pyrit_ai300/` 为纯代码（引擎层）
- **组件映射集中管理**：所有 PyRIT 组件统一通过 `component_registry.py` 的 CONVERTER_MAP / SCORER_MAP 引用
- **攻击注册表集中管理**：所有攻击元数据通过 `attack_registry.py` 的 ATTACK_REGISTRY 管理
- **v3.0 执行层原则**：SmartMatcher 只负责选择 PyRIT 攻击策略，执行全部交给 PyRIT 原生攻击
- **大文件拆分原则**：多职责大文件拆分为独立模块 + 主类文件；高内聚模块保持现状

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
  └── surfaces/       #   攻击面分析文档（仅引用，不存储载荷）
config/               # 配置层：catalog/ targets/ output/ scorers.yaml
pyrit_ai300/          # 代码层：纯框架引擎
  ├── pipeline/       #   攻击流水线追踪 (payload→分类→策略选择→执行)
  ├── orchestrators/  #   编排器
  │   ├── component_registry.py  #   PyRIT 组件映射（转换器 + 评分器）
  │   ├── attack_registry.py     #   PyRIT 攻击注册表 + 静态查询
  │   ├── attack_orchestrator.py #   攻击编排器主类
  │   └── smart_matcher.py       #   智能匹配引擎（策略选择）
  ├── payloads/       #   载荷管理 + 分类
  │   ├── models.py          #   数据模型（ThreatModel, PayloadProfile）
  │   ├── patterns.py        #   检测模式定义 + YAML 加载
  │   ├── normalizer.py      #   归一化预处理
  │   ├── payload_classifier.py  #   核心分析函数
  │   └── payload_manager.py     #   载荷管理器
  ├── reporting/      #   报告生成
  ├── tests/          #   单元测试 (65 tests)
  ├── utils/          #   工具函数
  ├── __init__.py     #   AI300Engine 入口
  └── cli.py          #   命令行接口
```

## 数据架构规则（2026-07-16 生效）
- **规则编号**: DATA-001（详见 `.codebuddy/rules/data-architecture.md`）
- **OWASP 为唯一真相源** — 所有载荷仅存储在 `data/owasp/`，禁止在其他目录重复存储
- **攻击面通过元数据交叉引用** — 每个 payload YAML 必须包含 `surfaces` 和 `ai300_chapters` 字段
- **surfaces/ 目录可选** — 纯分析文档，可安全删除
- **新增载荷流程**：确定 OWASP 类别 → 创建 YAML → 填写元数据 → catalog 引用（不改代码）
- **删除** `data/by_surface/` — 载荷重复，维护负担大
- **新增** `data/surfaces/` — 攻击面分析文档（README.md, rag.md, mcp.md, agent.md, embedding.md）
- **PayloadManager 扩展**:
  - `get_payloads_by_surface(surface)` — 按攻击面筛选
  - `get_payloads_by_chapter(chapter)` — 按 AI-300 章节筛选
  - `resolve_refs()` 支持 dict 类型载荷去重
  - `_resolve_text_jailbreak()` — 从 payload_store 读取模板，`{goal}` 替换渲染
- **多级子目录扫描** — `load_data_dir()` 使用 `rglob` 递归扫描 `llm01/jailbreak/*.yaml` 等嵌套目录
- **ref_path 格式** — 嵌套子目录使用 `owasp:llm:llm01:jailbreak:aim`
- **双格式兼容** — 支持字符串列表（旧格式）和字典列表（新格式）两种载荷存储方式

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

## 测试策略（2026-07-16 生效）
- **规则编号**: TEST-001（详见 `.codebuddy/rules/testing-strategy.md`）
- **单元测试即回归测试**：65 个测试覆盖核心模块，每次修改后必须跑 `make test`
- **分层策略**：每次修改 → `make test`；提交前 → `make ci`；发布前 → `make test-cov`
- **集成测试**：仅考试前用真实目标验证端到端，日常开发不跑

## 覆盖进度
- AI-300 Module: 11/11 | OWASP LLM: 10/10 | OWASP Agentic: 10/10
- PyRIT 转换器: 16/55 已映射 | PyRIT 评分器: 14/40+ 已映射
- Jailbreak 模板: 165 个（统一 YAML 格式，data/owasp/llm/llm01/jailbreak/）
- 测试: 65 tests passed
