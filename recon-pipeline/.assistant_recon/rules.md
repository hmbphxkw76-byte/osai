# Recon-Pipeline 项目规则

> AI 助手在操作本项目时必须遵守以下规则。违反任何一条需在代码审查中标注。

> **继承**: 本项目同时受全局规则约束，详见 [`.assistant/rules.md`](../../.assistant/rules.md)（G-001 ~ G-125）。
> 全局规则涵盖：架构原则、代码质量、分级测试、改动流程、Git 规范、依赖管理、API 设计、性能、安全、代码审查、废弃策略、ruff/pytest 工具链规范、侦察原则、实施前检查清单（G-125）。
> 以下为 Recon-Pipeline 项目专项规则（R-100 ~ R-120 + R-018），是全局规则的补充细化，不得与全局规则冲突。

---

## 学术基础

以下论文构成本项目侦察方法论的理论基石：

### 核心引用

| # | 论文 | arXiv | 核心贡献 | 映射到本模块 |
|---|------|-------|---------|------------|
| 1 | Greshake et al. "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" | [2302.12173](https://arxiv.org/abs/2302.12173) | 首次系统展示间接提示注入攻击面：攻击者通过网页/文档等外部数据源注入恶意指令，操控 LLM 集成应用。定义了 Agent 工具调用是间接注入的关键入口。 | `endpoint_classifier.py` 的 AGENT_TOOL_API 分类规则；`attack_recommender.py` 的 xpia_workflow 推荐 |
| 2 | Zou et al. "PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models" | [2402.07867](https://arxiv.org/abs/2402.07867) | USENIX Security 2025。证明仅需注入 5 条恶意文本即可达到 90% 攻击成功率。将向量数据库定位为 RAG 系统的关键攻击面。 | `vector_db_fingerprinter.py` 的未授权访问检测；`rag_probe.py` 的知识库投毒入口发现 |
| 3 | Hou et al. "Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions" | [2503.23278](https://arxiv.org/abs/2503.23278) | MCP 安全威胁系统性研究。定义 MCP 全生命周期攻击面（Creation/Deployment/Operation/Maintenance），识别 16 种威胁场景，涵盖 tool poisoning、tool shadowing、supply chain 等。 | `mcp_probe.py` 的工具枚举和 tool shadowing 检测；`endpoint_classifier.py` 的 MCP_SERVER 分类规则 |
| 4 | Debenedetti et al. "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents" | [2406.13352](https://arxiv.org/abs/2406.13352) | Agent 场景下 prompt injection 攻击的系统评估基准。定义了工具调用场景中的攻击面分类法。 | `agent_probe.py` 的过度代理风险评估；`tool_permission_matrix.py` 的风险等级体系 |

### OWASP 对齐

本项目所有侦察结果映射到 **OWASP Top 10 for LLM Applications 2025**：

| OWASP ID | 类别 | 侦察目标 | 探针 |
|----------|------|---------|------|
| LLM01 | Prompt Injection | 聊天输入框、Model API 端点、系统提示词提取 | LLMProbe, DOMProbe |
| LLM02 | Sensitive Information Disclosure | 模型指纹泄露、系统提示词泄露 | LLMProbe |
| LLM04 | Data Poisoning | 文件上传端点、知识库导入接口 | RAGProbe, DOMProbe |
| LLM06 | Excessive Agency | Agent 工具权限矩阵、MCP 工具枚举 | AgentProbe, MCPProbe |
| LLM07 | System Prompt Leakage | 系统提示词提取、MCP 配置信息泄露 | LLMProbe, MCPProbe |
| LLM08 | Vector and Embedding Weaknesses | 向量数据库指纹、嵌入端点、未授权访问 | RAGProbe, EmbeddingProbe |
| LLM10 | Unbounded Consumption | Model API 端点（无速率限制） | LLMProbe |

---

## 开源实践参考

以下开源项目提供了侦察/红队测试的实现参考：

### 直接相关

| # | 项目 | 仓库 | 核心能力 | 对本模块的参考价值 |
|---|------|------|---------|-----------------|
| 1 | **AIMap** (Bishop Fox) | [github.com/BishopFox/aimap](https://github.com/BishopFox/aimap) | 互联网级 AI Agent 基础设施发现与安全测试。32+ Shodan 查询发现端点 → Nuclei 模板指纹识别 → 风险评分(0-10)。支持 MCP/Ollama/vLLM/LangChain/Streamlit 等多框架检测。 | 端点指纹识别方法论：URL 模式 + 响应体关键词 + 响应头 + favicon hash 多维度组合检测。与本模块 `EndpointClassifier` + `VectorDBFingerprinter` 架构对齐。 |
| 2 | **Garak** (NVIDIA) | [github.com/NVIDIA/garak](https://github.com/NVIDIA/garak) | LLM 漏洞扫描器，probes → detectors → evaluators 三层架构。40+ 探针覆盖 jailbreak/数据泄露/提示注入/幻觉等。模块化插件设计，每探针指定 primary_detector。 | 探针-检测器分离架构；`probewise` harness 模式（每探针独立运行，结果聚合）；与本模块 `ReconProbe` ABC + `ReconPipeline` 编排对齐。 |
| 3 | **VulnerableMCP** | [vulnerablemcp.info](https://vulnerablemcp.info) | MCP 漏洞数据库：50 漏洞 / 13 Critical / 32 研究人员。分类：Prompt Injection(13)、Input Validation(17)、Auth Failures(5) 等。攻击向量：RCE、SSRF、DNS Rebinding、Tool Poisoning、Tool Shadowing。 | 为本模块 MCP 侦察提供漏洞分类参考。`MCPProbe` 的 tool shadowing 检测和风险等级评估直接参考其攻击向量分类。 |

### 间接相关

| # | 项目 | 仓库 | 核心能力 |
|---|------|------|---------|
| 4 | **PyRIT** (Microsoft) | [github.com/Azure/PyRIT](https://github.com/Azure/PyRIT) | AI 红队测试框架，提供 orchestrator/converter/scorer/target 抽象。`PlaywrightTarget` 支持浏览器自动化攻击。 | 为本模块 `stage_recon.py` 提供下游集成参考（ReconReport → PyRITExporter → pipeline_ctx.metadata）。 |

---

## 侦察设计原则

### R-100 · 侦察先行原则

侦察（Recon）必须在攻击（Attack）之前执行。侦察结果驱动攻击策略选择：
- `ReconReport.recommendations` 必须由 `AttackRecommender` 根据实际发现的端点和注入面生成
- 不允许跳过侦察直接硬编码攻击策略
- 侦察发现为空的场景需显式记录（`ReconReport.endpoints == []`）

**学术依据**: MITRE ATT&CK TA0043 (Reconnaissance) — 攻击前必须完成目标环境测绘。

### R-101 · 认证后侦察原则

侦察应在认证完成后执行，利用已认证的浏览器会话发现完整攻击面：
- 认证后侦察产出是未认证的 3-5 倍（内部 API 端点 + 完整 DOM 注入面）
- 无认证目标（auth_type=none）同样适用：AuthProbe 直接返回，侦察在目标页面执行
- 一次浏览器会话贯穿全流程（认证 → 侦察 → 攻击），不重复启动

**学术依据**: MITRE ATT&CK T1078 (Valid Accounts) — 认证态复用最大化信息收集效率。

### R-102 · 探针分层原则

六类探针按依赖关系分层执行：

```
Layer 0 (基础设施): NetworkInterceptor → 发现 API 端点（必须先运行）
Layer 1 (分类分析): LLMProbe, RAGProbe, AgentProbe, MCPProbe, EmbeddingProbe → 分析已发现端点
Layer 2 (DOM 分析):  DOMProbe → 扫描页面注入面（可与 Layer 1 并行）
Layer 3 (推荐生成): AttackRecommender → 综合所有发现生成攻击推荐
```

- Layer 1 的探针依赖 Layer 0 的产出（`session.report.endpoints`）
- Layer 2 可与 Layer 1 并行（仅依赖 browser_page）
- Layer 3 依赖 Layer 0+1+2 的完整产出

### R-103 · 主动探测补充原则

探针不应仅被动解析已拦截的响应，还应主动发起探测请求获取更多信息：
- MCPProbe 应对发现的 MCP 端点主动发送 `tools/list`、`resources/list`、`prompts/list` JSON-RPC 请求
- LLMProbe 应发送标准探测 prompt 提取模型信息（非攻击性探测）
- EmbeddingProbe 应发送已知文本的嵌入请求以验证维度

**学术依据**: Hou et al. (2503.23278) — MCP 安全评估需要主动枚举工具列表和权限边界。

### R-104 · 攻击面映射原则

所有侦察发现必须映射到 OWASP LLM Top 10 2025 类别：
- 端点 → `EndpointClassifier.get_owasp_mapping()`
- 注入面 → `InjectionSurface.owasp_ids`
- 攻击推荐 → `AttackRecommendation.owasp_id`
- 新增端点类型必须同步更新 `get_owasp_mapping()`

**学术依据**: OWASP Top 10 for LLM Applications 2025 — 行业标准攻击面分类法。

### R-008 · 运行前后自动清理 Python 临时文件

> 新增于 2026-8-3 — 三库统一标准 (pyrit-pipeline / garak-pipeline / recon-pipeline)

每次运行流水线（`python recon-main.py`）前和运行后，必须自动递归清理项目中的所有 Python 临时文件：

- **`__pycache__` 目录** — Python 字节码缓存目录
- **`.pyc` / `.pyo` 文件** — 编译后的字节码文件
- **`.pytest_cache` 目录** — pytest 测试缓存目录

### 三库统一实现

| 库 | 实现位置 | 调用时机 |
|:--|:--|:--|
| **pyrit-pipeline** | `pipeline/utils/cleaner.py` → `clean_temp_files(phase)` | `main.py` Stage 1 之前 + Stage 5 之后 (finally 块) |
| **garak-pipeline** | `pipeline/utils.py` → `clean_pycache(project_root)` | `main.py` 执行前 + 执行后 (finally 块) |
| **recon-pipeline** | `recon-main.py` → `clean_temp_files(phase)` | `recon-main.py` 阶段发现前 + 执行后 + KeyboardInterrupt |

### 规则要求

- **运行前清理**：移除过期的字节码缓存，确保干净起点，避免旧缓存导致难以调试的问题。
- **运行后清理**：移除本次运行生成的临时缓存，保持环境整洁。
- **异常退出清理**：KeyboardInterrupt / SIGTERM 等异常退出路径也必须执行清理。
- 报告文件保留在 `outputs/` 目录中供人工审查，不受清理影响。
- 清理过程静默执行，不输出到 stdout（避免干扰流水线输出）。

**理由**：`__pycache__` 等字节码缓存在环境变更后可能过期失效（如参数变更后旧 `.pyc` 仍被加载导致 `TypeError: got an unexpected keyword argument`），自动清理确保每次运行从干净的字节码缓存开始。三库统一标准确保跨项目一致性和可维护性。

---

## 代码规范

### R-110 · 探针接口一致性

所有探针必须是 `ReconProbe` 子类，实现以下接口：
- `name: str` — 唯一探针名称
- `requires_browser: bool` — 是否需要浏览器（默认 False）
- `requires_auth: bool` — 是否需要认证（默认 True）
- `probe(session: ReconSession) -> dict[str, Any]` — 执行探针

基础设施类（`NetworkInterceptor`, `EndpointClassifier`, `AttackRecommender` 等）可保持独立类，但应通过 ReconProbe 子类包装供 pipeline 使用。

### R-111 · 数据模型单一来源

所有数据模型定义在 `core/models/recon_report.py`（唯一来源）：
- `core/probes/recon_result.py` 仅为向后兼容 shim
- 新代码必须 `from core.models.recon_report import ...`
- 新增字段/类型先在 `models/recon_report.py` 定义，再通过 shim 导出

### R-112 · 结果去重原则

探针产出的端点/指纹/工具信息在 `ReconReport.merge()` 中自动合并，但各探针内部需自行去重：
- `LLMProbe`: 按 `model_name` 去重
- `MCPProbe`: 按 `tool_name` + `server_url` 去重
- `VectorDBFingerprinter`: 按 `endpoint_url` 去重

### R-113 · 版本号一致

修改模块后必须同步更新以下位置的版本号：
- `core/__init__.py` — `__version__`
- `pyproject.toml` — `[project] version`
- `docs/DESIGN.md` — 顶部版本标注

---

## 测试规范

### R-120 · 探针测试覆盖

每新增一个 ReconProbe 子类，必须包含以下测试：
1. 接口合规测试（继承 ReconProbe，有 name，requires_browser/requires_auth 正确）
2. 空输入测试（session.report 为空时返回空结果）
3. 核心逻辑测试（指纹识别/风险分析/工具枚举的正确性）
4. 边界条件测试（无效 JSON、超大响应体、特殊字符）
