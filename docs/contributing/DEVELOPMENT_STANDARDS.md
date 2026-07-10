# RedTeam_AI 开发实践规范标准

> **定位**: 本文档是 RedTeam_AI 项目所有开发活动的唯一权威标准。
> 所有新代码、新模块、新功能必须严格遵循本文档规范。
> 本文档优先级高于任何个人偏好或历史遗留代码。

---

## 一、项目架构强制约束

### 1.1 六阶段管道为主流程

RedTeam_AI 的核心流程为 **六阶段全生命周期管道**，任何功能新增必须在对应阶段落位：

```
Stage 0: 前置侦察 (L0)  → recon/ + Web UI
Stage 1: AI 场景探测 (L1) → Garak 基线/深度扫描
Stage 2: 攻击面分析 (L2) → OWASP 双映射 + 风险评级
Stage 3: 风险筛选 (L3) → 高/中风险路由
Stage 4: 攻击执行 (L4) → Promptfoo 提示词管理 + PyRIT 攻击
Stage 5: 数据入库 + 报告 (L5) → Neo4j + OffSec 报告
```

**强制规则**：
- 新增攻击能力必须在 L4 落地，新增评估能力在 L2 落地
- 阶段间数据通过标准化 JSON Schema 传递（profile → surface → risks → results）
- 每个阶段完成后必须输出专家指导建议（使用 `utils/stage_guidance.py`）

### 1.2 目录结构强制约束

```
RedTeam_AI/
├── README.md                    # 项目总览
├── Makefile                     # 统一命令入口
├── CONTRIBUTING.md              # 贡献指南（指向规范）
├── docs/                        # 项目级文档
│   ├── architecture.md          #   架构文档
│   └── contributing/            # 📋 开发规范标准（项目级唯一权威）
│       ├── README.md            #   核心研发规范
│       ├── DEVELOPMENT_STANDARDS.md  #   本文档
│       └── ...                  #   专题规范
│
├── recon/                       # L0 前置侦察引擎（独立项目）
│   ├── main.py                  # CLI 入口
│   ├── recon/                   # 侦察引擎核心
│   │   ├── scanners/            #   Web 扫描器（browser/dict/spa/traffic/waf/cred）
│   │   ├── probes/              #   AI 探针（model/prompt/rag）
│   │   ├── auth/                #   认证自动化（login）
│   │   └── analysis/            #   行为分析（behavior/giskard/endpoint/profile）
│   ├── web/                     # Web UI（Flask）
│   ├── templates/               # 前端模板
│   ├── wordlists/               # 扫描字典
│   ├── outputs/                 # 侦察结果
│   └── requirements.txt
│
└── pyrit/                       # L1-L5 AI 攻击框架（主项目）
    ├── main.py                  # CLI 入口
    ├── pipeline.py              # 三层管道
    ├── recon_adapter.py         # recon → PyRIT 桥接
    │
    ├── entrypoint/              # CLI 入口层（解析→回显→引导→路由）
    ├── orchestrators/           # 🆕 编排层（full_pipeline.py + pyrit_orchestrator.py）
    ├── executor/                # 执行器层（含 Garak/Promptfoo/RAG/Agent）
    ├── converters/              # 载荷变形器
    ├── targets/                 # 目标适配器
    ├── scoring/                 # 评分层（含 OWASP 映射）
    ├── reporting/               # 报告生成
    ├── storage/                 # 🆕 图数据库存储（Neo4j）
    ├── datasets/                # 数据层（payloads + YAML）
    ├── configs/                 # 配置层
    ├── scenarios/               # 场景模板
    ├── schemas/                 # 数据模型
    ├── scripts/                 # 工具脚本
    ├── utils/                   # 通用工具（含 stage_guidance）
    ├── guides/                  # 用户指南
    │   └── user/                #   使用文档
    └── outputs/                 # 攻击结果
```

**强制规则**：
- 不得在顶层新增目录（除 `docs/` 外）
- `recon/recon/` 新增模块必须按职责归入 `scanners/`、`probes/`、`auth/`、`analysis/` 之一
- 新增 Python 包必须遵循现有命名规范（全称、复数、动名词，参见 `docs/contributing/README.md` 第 3.1 节）
- 所有新模块必须在对应包的 `__init__.py` 中声明 `__all__`
- 开发规范统一存放于顶层 `docs/contributing/`，`pyrit/` 和 `recon/` 开发者共同遵循

---

## 二、数据流强制规范

### 2.1 阶段间数据传递格式

所有阶段间数据必须使用标准化 JSON Schema，不得使用 pickle 或自定义二进制格式：

| 阶段输出 | 文件 | Schema 位置 |
|---------|------|------------|
| L0 → L1 | `target_profile.json` | `recon/recon/schema.py` |
| L1 → L2 | `security_profile.json` | `executor/garak_scanner.py` (SecurityProfile) |
| L2 → L3 | `attack_surface.json` | `scoring/owasp_mapper.py` (AttackSurfaceReport) |
| L3 → L4 | `selected_risks.json` | `orchestrators/full_pipeline.py` (selected_findings) |
| L4 → L5 | `pipeline_state.json` | `orchestrators/full_pipeline.py` (PipelineState) |
| L5 输出 | `attack_graph.json` | `storage/neo4j_client.py` |

### 2.2 Neo4j 图数据库 Schema

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

## 三、编码强制规范

### 3.1 文件编码

| 规范项 | 要求 |
|--------|------|
| 字符编码 | UTF-8 without BOM |
| 换行符 | LF (`\n`) |
| 缩进 | 空格（4 空格），禁止 Tab |
| 行尾空格 | 无 |
| 文件末尾 | 单个空行结尾 |
| 行宽 | 建议 ≤120 字符 |

### 3.2 Python 代码规范

```python
# 1. 导入顺序：标准库 → 第三方 → 项目内部
import os
from dataclasses import dataclass

from rich.console import Console

from targets import load_env_config
```

```python
# 2. 类型注解：所有公开函数必须有
async def run_pipeline(target_url: str, stage: str = "auto") -> PipelineState:
    ...

# 3. 使用 | None 而非 Optional[X]
def get_profile(path: str | None = None) -> dict:
    ...

# 4. dataclass 可变默认值使用 field(default_factory=...)
@dataclass
class Result:
    items: list = field(default_factory=list)
```

```python
# 5. 模块文档字符串格式
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

# 6. 公开函数中英文 docstring
async def attack(target: Target) -> AttackResult:
    """执行对目标的一次攻击。
    
    Execute a single attack against the target.

    Args:
        target: 目标系统封装

    Returns:
        AttackResult: 包含成功率、响应内容、风险评级的攻击结果
    
    Raises:
        ConnectionError: 目标不可达时抛出
    """
```

### 3.3 终端输出规范

```python
# 统一使用 rich.console.Console
from rich.console import Console
console = Console()

# 状态行格式
console.print("[green]✅ 状态: 详情[/green]")
console.print("[red]❌ 错误: 原因[/red]")
console.print("[yellow]⚠️ 警告: 提示[/yellow]")
console.print("[cyan]📊 信息: 数据[/cyan]")
```

### 3.4 命名强制规范

| 类型 | 规范 | 正确示例 | 错误示例 |
|------|------|---------|---------|
| 包名 | 全称、复数/动名词 | `executor/`, `orchestrators/`, `scoring/`, `reporting/` | `exec/`, `orch/`, `score/` |
| 文件名 | 小写+下划线 | `full_pipeline.py`, `neo4j_client.py`, `stage_guidance.py` | `pipeline.py`, `Neo4j.py` |
| 函数名 | verb_noun | `build_report()`, `run_baseline()`, `filter_by_risk()` | `report()`, `baseline()` |
| 私有函数 | `_verb_noun` | `_resolve_config()`, `_clean_value()` | `resolveConfig()` |
| 类名 | PascalCase | `FullPipeline`, `Neo4jClient`, `AttackSurfaceReport` | `fullPipeline`, `neo4J_Client` |
| 常量 | UPPER_SNAKE | `MAX_TOKENS`, `GARAK_PROBE_CATEGORIES` | `maxTokens` |

---

## 四、YAML 驱动开发规范

### 4.1 YAML 是唯一真实来源

```
datasets/payloads/         ← 提示词载荷（核心攻击数据）
datasets/payloads/manifest.yaml ← 模块→文件索引，新模块在此注册
scenarios/templates/       ← 攻击场景模板（声明式阶段+策略）
scenarios/frontier/        ← 前沿漏洞（index.yaml + vulns/*/manifest.yaml）
```

### 4.2 新模块注册流程

```yaml
# 1. 创建载荷文件: datasets/payloads/xxx_payloads.yaml
# 2. 在 manifest.yaml 中注册:
- module_id: "20"
  title: "新模块名称"
  key: "module_key"
  file: "xxx_payloads.yaml"
  loader: "UnifiedPayloadLoader.get_module('module_key')"
  description: "模块描述"
```

### 4.3 YAML 文件标准格式

```yaml
# ===============================================================================
# 文件用途描述
# ===============================================================================
# 使用方式: 命令行示例
# 维护者: 维护说明
# ===============================================================================

metadata:
  version: "1.0"
  description: "..."

payloads:
  - id: "unique-id"
    objective: "攻击目标描述"
    criterion: "判定标准"
    content: |
      攻击载荷内容
```

---

## 五、集成规范

### 5.1 外部工具集成标准

| 工具 | 集成方式 | 位置 | 降级策略 |
|------|---------|------|---------|
| Garak | subprocess CLI | `executor/garak_scanner.py` | 返回空 SecurityProfile |
| Promptfoo | subprocess CLI (npx) | `executor/promptfoo_manager.py` | 使用默认载荷 |
| Neo4j | Python SDK (`neo4j`) | `storage/neo4j_client.py` | 回退 JSON 存储 |

**强制规则**：
- 所有外部工具都必须有降级回退机制 — 不可用时不能阻塞主流程
- 集成前在 `requirements.txt` 中添加可选依赖（注释标记 `# optional: xxx`）

### 5.2 Promptfoo 提示词管理流程

```
选择风险等级 → PromptfooManager 筛选提示词 → 导出 YAML 配置
    ↓
执行 promptfoo eval (可选)
    ↓
PyRIT 消费优化后的提示词载荷 → 执行攻击
```

**筛选优先级**:
1. 按 OWASP 分类匹配提示词
2. 按风险等级匹配提示词
3. 按攻击类别匹配提示词
4. 无匹配 → 使用内置默认载荷

---

## 六、专家指导规范

### 6.1 六阶段指导标准

每个阶段完成后必须调用 `utils/stage_guidance.generate_guidance()` 输出指导：

| 阶段 | 指导内容 | 必须包含 |
|------|---------|---------|
| L0 侦察 | 认证信息提取结果、下一步入口 | 可直接执行的 CLI 命令 |
| L1 AI 探测 | 架构判定、Garak 扫描摘要 | 推荐攻击策略 |
| L2 攻击面 | OWASP 映射、风险统计 | 高风险漏洞列表 |
| L3 风险筛选 | 分组结果（Promptfoo vs 直接攻击） | 并行执行建议 |
| L4 攻击 | ASR、成功/失败统计 | Neo4j 入库命令 |
| L5 报告 | 产物路径、归档建议 | 查看和重新生成命令 |

### 6.2 指导输出格式

每条指导必须包含：
1. **阶段总结** — 关键发现和指标
2. **专家建议** — 文字形式操作建议（2-5 条）
3. **推荐命令** — 可直接复制粘贴执行的 CLI 命令
4. **注意事项** — 风险警告和注意点
5. **下一步** — 推荐的下一个阶段

---

## 七、测试与质量门禁

### 7.1 提交前检查清单

- [ ] 文件编码: UTF-8 without BOM, LF 换行
- [ ] 类型注解: 所有公开函数有完整类型注解
- [ ] Docstring: 模块和公开函数有中英文文档字符串
- [ ] 命名规范: 遵循本文档命名强制规范
- [ ] YAML 注册: 新载荷在 manifest.yaml 中注册
- [ ] 降级策略: 外部工具集成有 fallback
- [ ] 阶段指导: 新增功能在对应阶段有专家指导输出
- [ ] 无硬编码: 所有配置通过 .env 或 YAML 注入

### 7.2 禁止事项

| ❌ 禁止 | 说明 |
|---------|------|
| 直接修改 `recon/` 和 `pyrit/` 核心文件不加注释 | 所有修改必须有变更说明 |
| 跨层引用（如 executor 引用 orchestrators） | 只能上层引用下层 |
| 在 Python 代码中硬编码攻击载荷 | 载荷必须在 YAML 文件中 |
| 使用缩写命名（包/文件/函数） | 全称单词 |
| stdout 直接 print | 必须使用 `rich.console.Console` |
| 忽略外部工具不可用 | 必须有降级回退 |
| 跳过专家指导输出 | 每个阶段必须输出指导 |

---

## 八、变更管理

### 8.1 版本号规范

遵循 `MAJOR.MINOR.PATCH`：
- MAJOR: 新阶段/新目录/架构级变更
- MINOR: 新攻击模块/新集成/新 YAML 载荷
- PATCH: Bug 修复/文档更新/格式调整

### 8.2 向后兼容

- 现有 CLI 参数不能移除（可新增，不可删除）
- 现有 YAML 字段不能移除（可新增 optional 字段）
- 现有 JSON Schema 不能破坏已有字段
- Legacy 路径保留至少一个 MINOR 版本

---

## 九、快速参考

### 全流程启动命令

```bash
# Web UI 侦察
cd recon/ && python web_app.py

# 全流程管道
cd pyrit/
python -m orchestrators.full_pipeline --target-url https://target.com --auto

# 从指定阶段执行
python -m orchestrators.full_pipeline --stage attack_surface --profile target_profile.json

# 仅攻击 (HIGH+ 风险)
python -m orchestrators.full_pipeline --stage attack --min-risk high

# 生成报告
python -m orchestrators.full_pipeline --stage report

# 恢复执行
python -m orchestrators.full_pipeline --resume-from outputs/pipeline_state.json
```

### 关键文件速查

| 需求 | 文件 |
|------|------|
| 架构设计 | `docs/architecture.md` |
| 管道编排 | `pyrit/orchestrators/full_pipeline.py` |
| OWASP 映射 | `pyrit/scoring/owasp_mapper.py` |
| Neo4j 存储 | `pyrit/storage/neo4j_client.py` |
| Promptfoo 管理 | `pyrit/executor/promptfoo_manager.py` |
| 阶段指导 | `pyrit/utils/stage_guidance.py` |
| Garak 集成 | `pyrit/executor/garak_scanner.py` |
| 载荷注册 | `pyrit/datasets/payloads/manifest.yaml` |
| 环境配置 | `pyrit/.env.example` |
| 原有规范 | `pyrit/contributing/README.md` |

---

> **最后更新**: 2026-07-10
> **维护者**: RedTeam_AI 团队
> **适用范围**: 本项目所有开发活动
