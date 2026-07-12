# RedTeam-AI 开发标准 v2.1

> 基于 OffSec AI-300 (OSAI) 课程大纲 + 当前代码实现梳理
> 最后更新：2026-07-12

---

## 一、项目定位

RedTeam-AI 是一个 **AI 红队攻击模拟工具**，覆盖 OffSec AI-300 课程的全部 11 个章节对应的攻击面。目标用户是在 Kali Linux 环境中备考 AI-300 或执行实际 AI 红队评估的安全专业人员。

**核心原则：Library-First，零外部小众工具依赖。**

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
- **禁止依赖非 Kali 标准源的工具**（考试环境无 pip install）
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
- 词表：`config/wordlists/*.txt`

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
