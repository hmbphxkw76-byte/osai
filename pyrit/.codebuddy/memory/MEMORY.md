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
- 检查工具：`vulture pyrit_ai300/ --min-confidence 80`

### 架构设计原则
- 直接复用 PyRIT 组件，不重复造轮子
- **数据与代码分离**：`data/`（载荷库）+ `config/`（配置）在根目录（数据层），`pyrit_ai300/` 为纯代码（引擎层）
- **组件映射集中管理**：所有 PyRIT 组件统一通过 `AttackOrchestrator` 的 CONVERTER_MAP / SCORER_MAP / build_target() 引用
- **v3.0 执行层原则**：SmartMatcher 只负责选择 PyRIT 攻击策略，执行全部交给 PyRIT 原生攻击

## TextJailBreak 集成（2026-07-16 新增）
- **模块**：`pyrit_ai300/payloads/text_jailbreak_integration.py`
- **功能**：封装 PyRIT 的 `TextJailBreak` 类，90 个本地 YAML 越狱模板（无需联网）
- **PayloadManager 扩展**：`resolve_refs()` 支持 `text_jailbreak:` 前缀
  - `text_jailbreak:aim` → 用指定模板渲染
  - `text_jailbreak:random` → 随机模板渲染
  - `text_jailbreak:all` → 全部模板渲染（穷举）
- **API**：`TextJailBreakIntegration` 类提供 `list_templates()`, `render_template()`, `render_random()`, `render_all()`, `render_with_string_template()`, `get_template_info()`, `get_templates_by_category()`

## Smart Match 引擎（v3.0 核心）
- 决策流程：payload → normalize_payload() → analyze_payload() → PayloadProfile(五维+置信度) → 两层策略选择 → PyRIT 原生攻击
- 攻击探针族：DIRECT_SINGLE / PROGRESSIVE / TREE_SEARCH / ITERATIVE / EXPLORATORY / MULTI_PRESET
- Fallback 链：Crescendo → TAP → PAIR → PromptSending
- 动态参数：`max_turns = 5 + complexity_score + token_factor`

## 目录结构（pyrit/ 根目录）
```
data/                 # 数据层：载荷库（owasp/llm, owasp/agentic, by_surface）
config/               # 配置层：catalog/ targets/ output/ scorers.yaml
pyrit_ai300/          # 代码层：纯框架引擎
  ├── display/        #   终端展示 (Rich 格式化)
  ├── orchestrators/  #   编排器 (AttackOrchestrator, SmartMatcher) + 组件映射
  ├── payloads/       #   载荷管理 + 分类 + TextJailBreak 集成
  ├── reporting/      #   报告生成
  ├── tests/          #   单元测试 (78 tests)
  ├── utils/          #   工具函数
  ├── __init__.py     #   AI300Engine 入口
  └── cli.py          #   命令行接口
```

## 已删除的死代码（2026-07-16）
- `converters/converter_chain.py`, `scorers/scorer_factory.py`, `payloads/dataset_loader.py`
- `orchestrators/strategy_optimizer.py`, `scenarios/`, `reporting/templates.py`
- `utils/validators.py`, `utils/config_loader.py`, `targets/`
- `orchestrators/scenario_runner.py`, `attacks/attack_factory.py`
- `converters/`, `scorers/`, `attacks/` 整个目录（空壳）

## 覆盖进度
- AI-300 Module: 11/11 | OWASP LLM: 10/10 | OWASP Agentic: 10/10
- PyRIT 转换器: 16/55 已映射 | PyRIT 评分器: 14/40+ 已映射
- TextJailBreak 模板: 90 个本地模板已集成
- 测试: 78 tests passed
