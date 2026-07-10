# RedTeam_AI 开发实践规范标准

> **定位**: 本文档是 RedTeam_AI 项目所有开发活动的唯一权威标准。
> 所有新代码、新模块、新功能必须严格遵循本文档规范。
> 本文档优先级高于任何个人偏好或历史遗留代码。

---

## 一、核心理念

### 1.1 YAML 是唯一真实来源

所有可变化的数据（Prompt、Payload、场景定义、攻击组合）存储在 YAML 文件中。
Python 代码是执行引擎，不包含业务数据。修改攻击行为时只改 YAML 不改代码。

```
promptfoo/templates/           → Prompt 载荷（核心提示词 + 测试用例 + YAML 模板）
```

- 新增载荷：在 `promptfoo/templates/` 新建 YAML 文件。
- 新载荷必须在 `promptfoo/templates/manifest.yaml` 中注册。

### 1.2 配置分离，关注点独立

```
pyrit/.env                    → 选择器 + 通用参数（TARGET_PRESET= / PLATFORM_SELECTOR=）
pyrit/configs/platforms.env   → 平台模型定义 [OPENAI]/[OLLAMA]/[CUSTOM]...
pyrit/configs/targets.env     → 目标场景预设 [TARGET_DEMO_CHAT]/[TARGET_DUAL_AUTH]...
```

- `.env` 只管"选什么"，不管"怎么定义"。
- `configs/` 只管"定义"，不管"选择"。
- 新增配置类型时优先考虑独立文件，避免 `.env` 膨胀。

### 1.3 模块化部署，职责单一

每个包的职责边界清晰，不跨层引用：

| 包 | 职责 | 依赖方向 |
|---|---|---|
| `entrypoint/` | CLI 入口（解析 → 回显 → 引导 → 路由） | → targets, promptfoo, converters |
| `orchestrators/` | 攻击工作流编排（Facade） | → executor, converters, reporting |
| `executor/` | 攻击执行引擎 | → targets, promptfoo |
| `converters/` | 攻击策略转换器 | → 外部 PyRIT 框架 |
| `targets/` | 目标封装 + 工厂 + 配置加载 | → 外部 API |
| `scoring/` | 评分引擎 | → executor |
| `reporting/` | 结果分析 + 报告生成 | → executor |
| `scenario/` | 多Agent攻击场景 | → executor, converters |
| `storage/` | 持久化存储（Neo4j） | → executor, reporting |
| `utils/` | 工具函数 | 可跨层（只读） |

- 只能从上层引用下层，禁止反向依赖。
- `__init__.py` 定义包的公开 API（`__all__`），包内部细节不对外暴露。

### 1.4 最小化改动原则

- 新增功能优先在 YAML 层实现，不修改 Python 代码。
- 修改现有行为时，确保向后兼容。
- 重构时优先提取而非重写：旧代码注释标记而非删除。
- CLI 参数新增时提供合理默认值，不破坏已有脚本。

---

## 二、六阶段管道约束

RedTeam_AI 的核心流程为 **六阶段全生命周期管道**，由 `pipeline.py` 统一编排：

```
L0: recon/       前置侦察 — Web指纹 / 密钥提取 / API发现 / 模型探测
L1: garak/       AI 安全侦查 — 基线/深度扫描 / 安全画像
L2: bridge/      桥接映射 — Garak JSONL → Seeds / OWASP 标注
L3: promptfoo/   提示词模板 — YAML 管理 / 载荷分发
L4: pyrit/       深度攻击 — 注入/越狱/XPIA/RAG/Agent/提取
L5: 统一报告     — ASR + 证据 + 断言 → OffSec 报告
```

**强制规则**：
- 新增攻击能力必须在 L4 落地；新增评估能力在 L2 落地；新增侦察能力在 L0 落地
- 阶段间数据通过标准化 JSON Schema 传递
- 每个阶段完成后必须输出专家指导建议
- 不得跳过阶段：L0 → L1 → L2 → L3 → L4 → L5 顺序执行

---

## 三、代码组织规范

### 3.1 入口模式

`main.py` 严格保持精简（<100 行），只做 4 件事：

```python
# 1. 解析 → 2. 回显 → 3. 引导 → 4. 路由
args = build_parser().parse_args()
print_cli_args(args)
ctx = await bootstrap_environment(args)
await route_command(args, ctx)
```

所有复杂逻辑下沉到 `entrypoint/` 子模块。

### 3.2 Bootstrap Context 模式

环境初始化结果通过 `@dataclass` 统一传递：

```python
@dataclass
class BootstrapContext:
    attack_target: PromptTarget | None = None
    scorer_target: PromptTarget | None = None
    attacker_config: dict = field(default_factory=dict)
    scorer_config: dict = field(default_factory=dict)
    # ... 所有初始化产物都在这里
```

### 3.3 工厂模式创建目标

```python
# targets/factories.py 统一创建入口
create_scorer_target(config)     → AzureOpenAIChatTarget / OpenAIChatTarget
create_attack_target(config)     → OpenAIChatTarget / OpenAICompatibleTarget / GeminiTarget / ClaudeTarget
build_custom_target(endpoint, ..) → OpenAICompatibleTarget / GeminiTarget / ClaudeTarget / CustomHttpChatTarget
```

**Target SDK 选型标准（SDK 优先，不重复造轮子）：**

| API 类型 | Target 类 | SDK | 说明 |
|---|---|---|---|
| OpenAI / Ollama / vLLM 等 | `OpenAICompatibleTarget` | `openai` | `/v1/chat/completions` 兼容端点 |
| Google Gemini | `GeminiTarget` | `google-genai` | Gemini API（generateContent） |
| Anthropic Claude | `ClaudeTarget` | `anthropic` | Claude Messages API |
| 非标准 Web Chat API | `CustomHttpChatTarget` | `httpx` | 兜底方案，禁止扩展 |

**选型规则**：
1. 所有主流 LLM API 必须使用对应官方 SDK 实现
2. `CustomHttpChatTarget` 仅作为非标准 API 兜底，禁止向其添加新格式支持
3. 新增 API 接入时，优先使用已有 SDK；若无对应 SDK，在本规范中补充理由

### 3.4 Router 分发模式

```python
# entrypoint/router.py — 所有执行模式的分发入口
async def route_command(args, ctx):
    if args.penetrating_mode:
        await _route_penetrating_mode(args, ctx)
    elif args.exploring_template:
        await _route_exploring_mode(args, ctx)
    elif args.orch == "legacy":
        await _route_legacy_mode(args, ctx)
    else:
        await _route_native_mode(args, ctx)
```

---

## 四、命名规范

### 4.1 模块命名：全称单词，禁用缩写

| ✅ 正确 | ❌ 错误 | 说明 |
|---------|---------|------|
| `entrypoint/` | `cli/`, `entry/` | 全称 |
| `converters/` | `conv/` | 全称 |
| `executor/` | `exec/` | 全称 |
| `orchestrators/` | `orch/`, `orchestration/` | 复数 |
| `scoring/` | `score/` | 动名词 |
| `reporting/` | `report/` | 动名词 |
| `storage/` | `db/`, `store/` | 全称 |

### 4.2 文件命名：小写 + 下划线，语义优先

| ✅ 正确 | ❌ 错误 |
|---------|---------|
| `http_target.py` | `http.py`, `target.py` |
| `model_probe.py` | `probe.py` |
| `pyrit_orchestrator.py` | `orch.py`, `native.py` |
| `scenario_runner.py` | `runner.py` |

### 4.3 函数/类/常量命名

| 类型 | 规范 | 正确示例 | 错误示例 |
|------|------|---------|---------|
| 函数名 | `verb_noun` | `build_report()`, `run_baseline()`, `filter_by_risk()` | `report()`, `baseline()` |
| 私有函数 | `_verb_noun` | `_resolve_config()`, `_clean_value()` | `resolveConfig()` |
| 类名 | PascalCase | `FullPipeline`, `AttackSurfaceReport` | `fullPipeline` |
| 常量 | UPPER_SNAKE | `MAX_TOKENS`, `GARAK_PROBE_CATEGORIES` | `maxTokens` |

- 异步函数：`async def`，调用方统一 `await`

---

## 五、配置优先级链

所有可配置值遵循统一优先级：

```
CLI 显式参数  >  预设选择器  >  系统默认值
    ↑               ↑
  --target-url   TARGET_PRESET / PLATFORM_SELECTOR
```

实现模式（在 bootstrap 中使用 `_resolve` 合并）：

```python
def _resolve(key: str, default=None):
    cli_val = getattr(args, key, None)
    if cli_val and cli_val_is_not_default(cli_val, key):
        return cli_val
    return target_preset.get(key, default)
```

---

## 六、YAML 设计规范

### 6.1 清单文件结构

```yaml
metadata:
  version: "1.0"
  description: "..."

config:           # 执行配置（并发、超时、策略）
  max_concurrent: 3
  converter_presets: [...]

payloads:         # 或 prompts: / cases: — 核心攻击数据
  - id: "..."     # 全局唯一 ID
    objective: "..."  # 攻击目标描述
    criterion: "..."  # 判定标准
```

### 6.2 索引驱动

- 新模块必须在 `promptfoo/templates/manifest.yaml` 注册。
- 索引即文档：通过索引找到目标 YAML，不需要看代码。

### 6.3 Front Matter 注释

每个 YAML 文件开头必须包含标准注释块：

```yaml
# ===============================================================================
# 文件用途描述
# ===============================================================================
# 使用方式：命令行示例
# 维护者：维护说明
# ===============================================================================
```

---

## 七、Python 代码规范

### 7.1 Import 规范

```python
# 1. 标准库
import os
from dataclasses import dataclass

# 2. 第三方库
from rich.console import Console
from pyrit.memory import SQLiteMemory

# 3. 项目内部
from targets import load_env_config
from entrypoint.parser import build_parser
```

使用 `from targets import X` 而非 `from targets.config import X`，由 `__init__.py` 控制公开 API。

### 7.2 类型注解

- 所有公开函数必须包含类型注解。
- 使用 `| None` 而非 `Optional[X]`（Python 3.10+）。
- dataclass 字段使用 `field(default_factory=...)` 处理可变默认值。

### 7.3 文档字符串

- 每个公开函数包含中英文混合 docstring。
- 模块开头包含标准分隔注释块：

```python
"""
===============================================================================
模块名称 — 一句话职责描述
===============================================================================
职责:
  - 职责 1
  - 职责 2

使用方式:
  from module import Class

架构位置: LX — 层级描述
依赖方向: → downstream (下行依赖)
===============================================================================
"""
```

### 7.4 控制台输出

- 统一使用 `rich.console.Console`。
- 状态行格式：`[emoji] [状态] [标签] 详情`
  - `✅ 攻击者 [OLLAMA] qwen3:0.6b @ http://...`
  - `🔍 评分器 [CUSTOM_SCORER] (独立平台) deepseek-v4-flash`
  - `❌ 错误: 具体原因`
  - `⚠️ 警告: 具体原因`

### 7.5 文件编码规范

**所有项目文本文件必须遵循统一的编码标准：**

| 规范项 | 要求 | 说明 |
|--------|------|------|
| **字符编码** | UTF-8 without BOM | 禁止 UTF-8 with BOM、UTF-16、GBK 等 |
| **换行符** | LF (`\n`) | 统一 Unix 风格，禁止 CRLF 混用 |
| **缩进** | 空格（4 空格） | 禁止 Tab 字符 |
| **行尾空格** | 无 | 每行末尾不允许存在空白字符 |
| **文件末尾** | 单个空行结尾 | 最后一行后恰好一个换行符 |

**编码适用文件范围**：

| 文件类型 | 示例 | 关键约束 |
|----------|------|----------|
| Python 源码 | `*.py` | 字符串字面量使用标准 ASCII + UTF-8 多字节序列 |
| YAML 配置 | `*.yaml`, `*.yml` | 中文注释使用 UTF-8 编码 |
| 环境变量 | `.env`, `*.env` | 纯 ASCII，不包含非 ASCII 注释 |
| 依赖清单 | `requirements.txt` | 纯 ASCII |
| Markdown 文档 | `*.md` | UTF-8 without BOM |

**反例警示**：

| ❌ 禁止 | 后果 |
|---------|------|
| 文件包含 BOM (0xEF 0xBB 0xBF) | pip/解析器将 BOM 视为有效字符，导致语法错误 |
| 全角 ASCII 运算符（如 `＞＝` 代替 `>=`） | pip 等工具无法识别，报 `Invalid requirement` |
| CRLF 与 LF 混用 | Git diff 显示全文件变更 |
| Tab 与空格混用 | Python 解释器报 `IndentationError` |
| 非 UTF-8 编码（GBK/Shift-JIS） | 跨平台打开乱码 |

---

## 八、依赖管理

### 8.1 版本约束

所有依赖必须锁定上下限版本：

```
pyrit>=0.14.0,<1.0.0          # 主框架
httpx>=0.27,<1.0               # HTTP 客户端
openai>=1.0,<3.0               # OpenAI SDK
google-genai>=1.0,<2.0          # Google Gemini SDK
anthropic>=0.40,<1.0           # Anthropic Claude SDK
python-dotenv>=1.0,<2.0       # 环境变量
pyyaml>=6.0,<7.0               # YAML 解析
pydantic>=2.0,<3.0             # 数据验证
rich>=13.0,<15.0               # 终端 UI
```

### 8.2 Target SDK 依赖（核心依赖）

项目使用以下官方 SDK 对接各大 LLM API，**禁止手工构造 HTTP 请求替代**：

| 依赖 | 版本 | 对接 API | 文件 |
|---|---|---|---|
| `openai` | `>=1.0,<3.0` | OpenAI / Ollama / vLLM / ZHIPU / DeepSeek 等 | `pyrit/targets/openai_sdk_target.py` |
| `google-genai` | `>=1.0,<2.0` | Google Gemini | `pyrit/targets/gemini_target.py` |
| `anthropic` | `>=0.40,<1.0` | Anthropic Claude | `pyrit/targets/claude_target.py` |
| `httpx` | `>=0.27,<1.0` | 非标准 API 兜底 | `pyrit/targets/http_target.py` |

### 8.3 新增依赖审批

新增依赖前必须说明：
1. 功能必要性（为什么现有依赖无法实现）
2. 是否纯 Python（C 扩展需要跨平台编译）
3. 许可证是否兼容

---

## 九、集成规范

### 9.1 外部工具集成标准

所有外部工具都必须有降级回退机制 — 不可用时不能阻塞主流程：

| 工具 | 集成方式 | 位置 | 降级策略 |
|------|---------|------|---------|
| Garak | subprocess CLI | `garak/scanner.py` | 返回空 SecurityProfile |
| Promptfoo | subprocess CLI (npx) | `promptfoo/manager.py` | 使用默认载荷 |
| Neo4j | Python SDK (`neo4j`) | `pyrit/storage/` | 回退 JSON 存储 |

### 9.2 Promptfoo 提示词管理流程

```
选择风险等级 → 筛选提示词 → 导出 YAML 配置
    ↓
执行 promptfoo eval (可选)
    ↓
PyRIT 消费提示词载荷 → 执行攻击
```

**筛选优先级**:
1. 按 OWASP 分类匹配提示词
2. 按风险等级匹配提示词
3. 按攻击类别匹配提示词
4. 无匹配 → 使用内置默认载荷

---

## 十、数据流强制规范

### 10.1 阶段间数据传递

所有阶段间数据必须使用标准化 JSON Schema，不得使用 pickle 或自定义二进制格式：

| 阶段 | 输出 | Schema 定义位置 |
|------|------|----------------|
| L0 → L1 | `target_profile.json` | `recon/schema.py` (TargetProfile) |
| L1 → L2 | `security_profile.json` | `garak/schema.py` (SecurityProfile) |
| L2 → L3 | `attack_seeds.json` | `bridge/mapper.py` |
| L3 → L4 | 提示词载荷 | `promptfoo/schema.py` |
| L4 → L5 | 攻击结果 | `pyrit/schemas/` |
| L5 输出 | 统一报告 | `pyrit/reporting/` |

### 10.2 Neo4j 图数据库 Schema

```
节点标签:
  Target        — 目标系统 (url, target_type, platform)
  ReconResult   — 侦察结果 (profile_path, auth_type, model_name)
  AIScenario    — AI 场景 (type: rag/agent/multi_agent/basic_llm)
  Vulnerability — 漏洞发现 (vuln_id, owasp_category, risk_level, cvss_score)
  AttackResult  — 攻击结果 (attack_id, attack_type, success, asr_score)
  OWASP_Category — OWASP 分类 (name)

关系:
  (Target)-[:HAS_RECON]->(ReconResult)
  (Target)-[:HAS_SCENARIO]->(AIScenario)
  (AIScenario)-[:HAS_VULN]->(Vulnerability)
  (Vulnerability)-[:MAPPED_TO]->(OWASP_Category)
  (Vulnerability)-[:EXPLOITED_BY]->(AttackResult)
```

---

## 十一、执行期专家指导规范

### 11.1 三阶段指导模型

```
Stage 1: 探测后 (Pre-Execution)     → 目标类型识别 + 策略推荐
Stage 2: 执行中 (In-Execution)      → 实时仪表盘 + 动态建议
Stage 3: 执行后 (Post-Execution)    → 报告引擎 + 终端输出
```

### 11.2 六阶段指导标准

每个阶段完成后必须输出专家指导：

| 阶段 | 指导内容 | 必须包含 |
|------|---------|---------|
| L0 侦察 | 认证信息提取结果、下一步入口 | 可直接执行的 CLI 命令 |
| L1 AI 探测 | 架构判定、Garak 扫描摘要 | 推荐攻击策略 |
| L2 桥接 | 风险分类、OWASP 映射 | 高风险项列表 |
| L3 模板 | 匹配结果、载荷分组 | 并行执行建议 |
| L4 攻击 | ASR、成功/失败统计 | 下一步建议 |
| L5 报告 | 产物路径、归档建议 | 查看和重新生成命令 |

### 11.3 指导输出格式

每条指导必须包含：
1. **阶段总结** — 关键发现和指标
2. **专家建议** — 文字形式操作建议（2-5 条）
3. **推荐命令** — 可直接复制粘贴执行的 CLI 命令
4. **注意事项** — 风险警告和注意点
5. **下一步** — 推荐的下一个阶段

详细参见: `execution-guidance.md`

---

## 十二、测试与质量门禁

### 12.1 提交前检查清单

- [ ] 文件编码: UTF-8 without BOM, LF 换行
- [ ] 类型注解: 所有公开函数有完整类型注解
- [ ] Docstring: 模块和公开函数有中英文文档字符串
- [ ] 命名规范: 遵循本文档命名强制规范
- [ ] YAML 注册: 新载荷在 manifest.yaml 中注册
- [ ] 降级策略: 外部工具集成有 fallback
- [ ] 阶段指导: 新增功能在对应阶段有专家指导输出
- [ ] 无硬编码: 所有配置通过 .env 或 YAML 注入

### 12.2 禁止事项

| ❌ 禁止 | 说明 |
|---------|------|
| 直接修改核心文件不加注释 | 所有修改必须有变更说明 |
| 跨层引用（如 executor 引用 orchestrators） | 只能上层引用下层 |
| 在 Python 代码中硬编码攻击载荷 | 载荷必须在 YAML 文件中 |
| 使用缩写命名（包/文件/函数） | 全称单词 |
| stdout 直接 print | 必须使用 `rich.console.Console` |
| 忽略外部工具不可用 | 必须有降级回退 |
| 跳过专家指导输出 | 每个阶段必须输出指导 |
| 在顶层新增目录（除 `docs/` 外） | 破坏项目结构约束 |
| 文件包含 BOM 头 | 导致解析错误 |
| CRLF 与 LF 混用 | Git diff 全文件变更 |

---

## 十三、变更管理

### 13.1 版本号规范

遵循 `MAJOR.MINOR.PATCH`：
- MAJOR: 新阶段/新目录/架构级变更
- MINOR: 新攻击模块/新集成/新 YAML 载荷
- PATCH: Bug 修复/文档更新/格式调整

### 13.2 向后兼容

- 现有 CLI 参数不能移除（可新增，不可删除）
- 现有 YAML 字段不能移除（可新增 optional 字段）
- 现有 JSON Schema 不能破坏已有字段
- Legacy 路径保留至少一个 MINOR 版本

---

## 十四、参考资料

详细模式说明和示例参见同目录下的专题规范：
- `architecture-design.md` — 架构分层与数据流详解
- `7-layer-architecture.md` — 七层攻击架构设计
- `config-patterns.md` — 配置管理模式与实战示例
- `yaml-patterns.md` — YAML 驱动开发完整模式
- `execution-guidance.md` — 执行期专家指导规范

---

> **最后更新**: 2026-07-10
> **维护者**: RedTeam_AI 团队
> **适用范围**: 本项目所有开发活动
