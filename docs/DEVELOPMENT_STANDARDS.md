# RedTeam-AI 开发标准 v2.1

> **符合最佳实践原则优先**

> 基于 OffSec AI-300 (OSAI) 课程大纲 + 当前代码实现梳理
> 最后更新：2026-07-12

---

## 一、项目定位

RedTeam-AI 是一个 **AI 红队攻击模拟工具**，覆盖 OffSec AI-300 课程的全部 11 个章节对应的攻击面。目标用户是在 Kali Linux 环境中备考 AI-300 或执行实际 AI 红队评估的安全专业人员。

**核心原则：Library-First。**

---

## 二、架构规范

### 2.1 管道阶段模型

```
Phase 1: Reconnaissance (AI-300 Ch2)
Phase 2: Guardrail Profiling (AI-300 Ch1/Ch2)
Phase 3: Prompt Injection (AI-300 Ch3)
Phase 4: MCP & Tool Surface Attack (AI-300 Ch7)
Phase 5: RAG Pipeline Exploit (AI-300 Ch5)
Phase 6: Embedding Attack (AI-300 Ch6)
Phase 7: Supply Chain Attack (AI-300 Ch8)
Phase 8: Infrastructure Attack (AI-300 Ch9)
Phase 9: Multi-Agent/A2A Attack (AI-300 Ch4)
Phase 10: Threat Modeling (AI-300 Ch10)
Phase 11: Report Generation (AI-300 Ch11)
```

- 每个阶段独立可执行（checkpoint/resume 模式）
- 阶段间通过 JSON 文件传递中间结果（`reports/{run_id}/`）
- 失败不阻断下游，但记录状态

### 2.2 模块职责边界

| 模块 | 职责 | 对应 AI-300 章节 |
|------|------|-----------------|
| `redteam/recon/ai_surface.py` | AI 服务发现、被动/主动侦察、端点枚举 | Ch2 |
| `redteam/recon/auth_parse.py` | 浏览器 F12 请求头解析为 AuthContext | Ch2 |
| `redteam/attack/prompt_inject.py` | 直接/间接提示注入、护栏绕过 | Ch3 |
| `redteam/attack/infra_attack.py` | 云配置错误、供应链风险、MCP 端点分析 | Ch7, Ch8, Ch9 |
| `redteam/attack/pyrit_runner.py` | PyRIT 框架集成（可选双通道执行） | Ch3~Ch7 |
| `redteam/core/models.py` | 所有数据模型、枚举定义 | 全章节 |
| `redteam/core/tools.py` | 工具路径解析、功能开关 | 基础设施 |
| `redteam/core/store.py` | JSON 持久化层 | 基础设施 |
| `redteam/pipeline.py` | 管道编排主逻辑 | 全章节 |
| `redteam/cli.py` | CLI 入口 | 基础设施 |

### 2.3 不允许的模块依赖

- **禁止依赖外部小众 CLI 工具**（如 AIMap、mcp-scan、snyk-agent-scan）
- **禁止依赖非 Kali 标准源的工具**
- 如确实需要外部工具，需满足以下任一条件：
  - Kali 官方仓库预装（如 nmap、curl、sqlmap）
  - Python 标准库已包含
  - 可通过 `pip install` 从 PyPI 在离线环境预装（必须在文档中注明）

---

## 三、数据模型规范

### 3.1 模型定义规则

1. **所有数据结构使用 Pydantic BaseModel**，统一在 `redteam/core/models.py` 中定义
2. **禁止使用 dict 传递复杂数据**：API 边界处必须使用强类型模型
3. **枚举优先于字符串常量**：AI 协议、漏洞分类、攻击阶段均使用 Enum
4. **每个 Finding 必须绑定 `OWASPLlm` + `MITREATLASTactic`**

### 3.2 枚举必须覆盖

| 枚举 | 说明 |
|------|------|
| `OWASPLlm` | OWASP Top 10 for LLMs (LLM01~LLM10) |
| `MITREATLASTactic` | MITRE ATLAS 战术 (Recon ~ Impact) |
| `AIStackLayer` | AI 五层栈 (UI, API, Orchestration, Model, Infrastructure) |
| `AIProtocol` | AI 协议/框架指纹 (MCP, Ollama, vLLM, A2A, ...) |
| `GuardrailType` | 护栏类型 (OpenAI Moderation, Llama Guard, NeMo, ...) |
| `ContentCategory` | 内容类别 (harmful, system, jailbreak, pii, code_exec) |

### 3.3 新增 Finding 的规范

```python
Finding(
    source="url_or_component",
    category="prompt_injection | infra_misconfig | rag_poisoning | ...",
    severity="CRITICAL | HIGH | MEDIUM | LOW | INFO",
    title="Human-readable title",
    description="Detailed description with evidence",
    owasp_llm=OWASPLlm.LLM01,    # 必须
    mitre_atlas_tactic=MITREATLASTactic.Recon,  # 必须
    cve_refs=["CVE-XXXX-YYYY"],   # 可选
)
```

---

## 四、攻击方法学规范

### 4.1 Enumerate-Attack-Detect-Evade 循环

源自 AI-300 Ch3 的核心方法论，**每个攻击模块必须实现这四个步骤**：

1. **Enumerate（枚举）**：了解目标能力和边界
   - 健康检查端点 (`/health`, `/api/health`)
   - 工具发现（系统提示提取、OpenAPI 架构）
   - 权限边界探测（拒绝 vs. 无信息 的区分）
   
2. **Attack Naive（天真攻击）**：直接用已知技术
   - 用于确认攻击向量有效
   - 目的是生成可检测信号

3. **Detect（检测分析）**：查看检测规则触发情况
   - 了解被什么规则捕获
   - 了解检测盲点

4. **Evade（规避）**：修改攻击以绕过特定检测
   - 编码绕过关键词过滤器（字符间隔、ROT13、Base64）
   - 分步 crescendo（跨多轮消息）
   - CSS 隐藏文本绕过内容扫描器
   - 交叉文档拆分绕过单文件扫描
   - 导入解析攻击（非注入代码触发文件读取）

### 4.2 攻击技术选择优先级

1. **首选**：纯 Python 库实现（httpx, pypdf, beautifulsoup4）
2. **次选**：Kali 标准工具 subprocess 调用（nmap, curl, sqlmap）
3. **末选**：专用 Python 框架（PyRIT，已作为可选双通道实现）
4. **禁用**：非 Kali 标准的外部 CLI 工具

### 4.3 报告输出规范

- 所有输出使用 `Finding` 模型
- 严重性评级：
  - **CRITICAL**: 直接导致凭据泄露、远程代码执行、数据外泄
  - **HIGH**: 护栏绕过、提示注入成功、权限提升
  - **MEDIUM**: 信息泄露、配置不当（可被利用）
  - **LOW**: 指纹识别成功、端点发现、低影响信息暴露
  - **INFO**: 侦查结果、无害探测

### 4.4 Agent 核心组件 (AI-300 Ch3.1)

单 Agent 由五个核心组件构成，每个都有独立攻击面：

| 组件 | 说明 | 攻击面 |
|------|------|--------|
| **LLM Core** | 推理引擎，处理所有 token | 缺乏信任边界，所有输入混在一起处理 |
| **System Prompt** | 隐藏指令，定义代理身份、规则、工具、行为边界 | 常含敏感信息（内部URL、数据库凭据、API密钥、过滤关键字列表） |
| **Tools** | 文件读取、数据库查询、网页抓取、API调用等能力 | 工具权限继承，可被劫持执行未授权操作 |
| **Memory** | 短期记忆（会话内）和长期记忆（跨会话） | 记忆投毒，跨会话持久化攻击 |
| **Guardrails** | 输入过滤器、输出扫描器、内容扫描器、行为监控器 | 模式匹配器存在盲点，可被规避 |

### 4.5 多 Agent 协调模式 (AI-300 Ch4.1)

- **Orchestrator Pattern（中心辐射式）**：中央代理管理子代理，单点故障风险，攻击者可通过控制编排器控制整个系统
- **Inter-Agent Trust Boundaries**：代理间网络请求暴露认证缺口、序列化漏洞，可被利用进行横向移动

### 4.6 RAG 架构攻击面 (AI-300 Ch5)

**检索过程**：查询 → 嵌入 → 向量搜索 → 上下文注入 → LLM生成

**摄入过程**：文档加载 → 切分 → 嵌入 → 向量化存储

**关键攻击面**：
- **检索器**：查询操纵、结果劫持、访问控制绕过
- **知识库**：数据投毒、恶意文档插入、过期信息利用
- **访问控制配置**：权限边界、数据隔离、敏感数据访问

### 4.7 Embedding 攻击类型 (AI-300 Ch6)

| 攻击类型 | 说明 | 复杂度 |
|----------|------|--------|
| **嵌入反演 (Embedding Inversion)** | 从数值向量重建原始文本 | 高（需模型知识/权重/计算资源） |
| **成员推断 (Membership Inference)** | 判断特定信息是否存在于知识库 | 低（仅确认存在性） |
| **属性推断 (Attribute Inference)** | 从向量预测文档元数据（情感、分类） | 中（用于快速筛选高价值目标） |

### 4.8 供应链攻击面 (AI-300 Ch8)

**代码执行攻击**：
- Pickle 反序列化 RCE
- Joblib 序列化风险
- 依赖混淆攻击

**模型/数据篡改攻击**：
- 恶意模型投毒（Pickle 反向 Shell）
- 数据集污染
- Hugging Face 命名空间复用攻击

**MCP 供应链**：
- MCP 服务器源码仓库后门植入
- 跨部门共享 MCP 工具链攻击

### 4.9 威胁建模方法论 (AI-300 Ch10)

- **假设登记册**：追踪观察、假设、置信度、验证状态
- **信任区域界定**：定义边界，追踪升级路径，应用参与规则作为硬约束
- **攻击情报简报**：基于当前知识决定下一个攻击目标，在时间压力下优先排序

---

## 五、代码风格规范

### 5.1 Python 标准
- Python >= 3.10
- 类型提示（Type Hints）**必须**
- Pydantic v2 风格模型定义
- Ruff 作为 linter/formatter（配置在 pyproject.toml）
- 异步函数统一使用 `async/await` + `httpx.AsyncClient`

### 5.2 文件命名
- 模块文件：`snake_case.py`
- 测试文件：`test_*.py`，放在 `tests/` 目录
- 配置：`config/*.yaml`
- 词表：`config/wordlists/*.txt`（符合最佳实践原则优先）

### 5.3 文档字符串
- 每个公开函数必须有 docstring
- 格式：Google style（Args/Returns/Raises）
- 模块顶部的 `"""..."""` 必须说明：用途、覆盖的 AI-300 章节、依赖

### 5.4 导入规范
```python
# 标准库
from __future__ import annotations
from typing import Any

# 第三方库
import httpx
from pydantic import BaseModel

# 项目内部
from redteam.core.models import Finding, OWASPLlm
```

---

## 六、测试规范

### 6.1 测试结构
```
tests/
├── test_ai_surface.py      # 侦察模块
├── test_infra_attack.py    # 基础设施攻击
├── test_prompt_inject.py   # 提示注入
├── test_pipeline.py        # 管道集成
├── test_models.py          # 数据模型
├── test_tools.py           # 工具解析
├── test_cli.py             # CLI
└── conftest.py             # 共享 fixtures（如有）
```

### 6.2 测试要求
- pytest 框架
- 每个 attack 模块至少覆盖：正常路径 + 边界情况 + 空输入
- mock 外部调用（httpx、subprocess）
- 测试数据使用**合成数据**，严禁真实 API 密钥或凭据
- 每新增一个模块，测试文件同步新增

### 6.3 临时文件清理规则

**AI 会话产生的临时文件必须在任务完成后立即删除，不得残留在工作区。**

临时文件命名规范（均已在 `.gitignore` 中忽略）：

| 模式 | 示例 | 说明 |
|------|------|------|
| `_*.py` | `_fix_yaml_colons.py`, `_validate_scenarios.py` | 临时调试/修复/验证脚本 |
| `.temp_*.py` | `.temp_extract.py` | AI 会话数据提取脚本 |
| `.temp_*.txt` | `.temp_Ch3.txt`, `.temp_exam_all.txt` | 临时章节课件/考试资料提取 |
| `pytest_*.txt` | `pytest_output.txt`, `pytest_yaml_final.txt` | 临时 pytest 输出 |
| `validate_*.txt` | `validate_real.txt` | 临时验证输出 |
| `tmp_*.txt` / `tmp_*.log` | — | 通用临时输出文件 |

**规则：**
- AI 助手在会话结束时**必须主动删除**自己创建的临时文件
- 确认删除前检查文件是否为 AI 会话产生的临时产物
- 有用的临时脚本应移至 `scripts/` 目录并提交版本控制

### 6.4 Makefile 命令行手册同步规则

**每次修改 Makefile（新增/删除/重命名目标），必须同步更新 `docs/COMMAND_REFERENCE.md`。**

| 操作 | 要求 |
|------|------|
| 新增目标 | 在手册中按类别添加对应的命令条目，含用法示例和实际执行命令 |
| 删除目标 | 从手册中移除对应条目 |
| 修改目标 | 更新手册中的用法说明、变量引用 |
| 变量变更 | 同步更新手册顶部的变量速查表 |
| 考试速查 | 手册末尾"考试常用命令速查"保持与当前最佳实践一致 |

手册按 Makefile 注释分组对应 12 个类别：环境安装与构建、代码质量与测试、YAML 预检验证、场景驱动攻击、提示注入攻击、快速测试、报告生成、前沿漏洞攻击、统一攻击流水线、Git 仓库侦察、传统运行模式、其他。

**手册路径**：`docs/COMMAND_REFERENCE.md`

---

## 七、配置文件规范

### 7.1 settings.yaml 结构
```yaml
recon:
  concurrency: 3
  timeout: 10
  rate_limit_ms: 800        # 500-1000ms 模拟人工浏览绕过WAF
  ai_wordlist: config/wordlists/ai_paths.txt
  proxy: ""

store:
  dir: reports

report:
  out_dir: reports
```

### 7.2 配置添加规则
- 功能开关使用三态：`true`（启用）/ `false`（禁用）/ `auto`（自动检测）
- 工具路径使用绝对路径或 `$PATH` 可解析的名称
- 禁止在配置文件中存储凭据（API 密钥等通过环境变量获取）

### 7.3 YAML 引号规范（重要）

**中文引号必须使用 Unicode 全角引号，禁止 ASCII 双引号：**

```yaml
# 正确: description 字段使用中文全角引号 \u201c \u201d
description: "使模型在\u201c虚假证据\u201d上编造"     # ✅ YAML 解析通过

# 错误: ASCII 双引号 0x22 与外层 YAML 双引号冲突
description: "使模型在"虚假证据"上编造"               # ❌ YAML 解析失败！
```

**问题根因：** 当 YAML 字符串用双引号 `"..."` 包裹时，内部出现的 ASCII `"` (0x22) 会被解析器视为字符串终止符，导致后续内容解析失败。

**规则：**
- 在 YAML `description` 或其他双引号字符串字段中，中文引号使用 `\u201c`（左）和 `\u201d`（右）
- 或在编辑器中直接输入中文全角引号 `""`（U+201C/U+201D），而非 ASCII `""` (U+0022)
- 同理适用于 `'...'` 单引号字符串中的中文单引号，应使用 `''`（U+2018/U+2019）

**检查方法：**
```python
# 检测 YAML 描述中的 ASCII 引号冲突
python -c "
with open('file.yaml', 'r', encoding='utf-8') as f:
    for i, line in enumerate(f, 1):
        if 'description:' in line and line.count(chr(0x22)) > 2:
            print(f'Line {i}: QUOTE CONFLICT')
"
```

---

## 八、安全注意事项

1. **所有攻击代码仅用于授权测试**，项目文档必须包含合法使用声明
2. **输出脱敏**：报告中自动遮蔽凭据（`mask()` 方法）
3. **测试数据隔离**：合成数据，不使用真实目标
4. **速率限制**：默认启用 800ms 请求间隔，避免对目标造成 DoS
5. **WAF 规避**：低并发 + 模拟人工浏览模式
6. **Honeypot 识别**：警告用户检查凭据中的明显标记（如 HONEYPOT 字样）

---

## 九、版本与兼容性

| 组件 | 版本要求 |
|------|---------|
| Python | >= 3.10 |
| Kali Linux | 2024.x+ |
| httpx | >= 0.27 |
| pydantic | >= 2.0 |
| pytest | >= 8.0 |
| PyRIT（可选） | >= 0.5 |

---

## 十、后续开发路线图（按 AI-300 章节优先级）

| 优先级 | 章节 | 模块 | 当前状态 | 待开发 |
|--------|------|------|---------|--------|
| P0 | Ch2 | 侦察 | 已实现 | HTTP 头被动分析、JS 配置枚举 |
| P0 | Ch3 | 单 Agent 攻击 | 已实现 | 护栏绕过技术、输出过滤规避 |
| P1 | Ch5 | RAG 管道攻击 | 部分实现 | 知识库投毒、检索劫持 |
| P1 | Ch7 | MCP 工具攻击 | 已重构 | 工具描述投毒、权限滥用 |
| P1 | Ch8 | 供应链攻击 | 部分实现 | 数据集投毒、模型权重后门 |
| P1 | Ch9 | 基础设施攻击 | 已实现 | 容器逃逸、K8s 利用 |
| P2 | Ch4 | 多 Agent/A2A 攻击 | 待开发 | Agent Card 欺骗、信任边界 |
| P2 | Ch6 | Embedding 攻击 | 待开发 | Embedding 反转、信息提取 |
| P2 | Ch10 | 威胁建模 | 待开发 | 假设登记表、信任区域映射 |
| P2 | Ch11 | 综合报告 | 部分实现 | 攻击链可视化、影响评估 |
