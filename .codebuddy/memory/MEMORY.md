# RedTeam-AI 项目长期记忆

## 项目定位

AI 红队攻击模拟工具，面向 OffSec AI-300 (OSAI) 考试备考和实际 AI 红队评估。
目标用户：Kali Linux 环境中的安全专业人员。

## 四大核心铁律

1. **Library-First 原则**：首选纯 Python 库 (httpx, pydantic)，次选 Kali 标准工具 subprocess 调用。**严禁依赖外部小众 CLI 工具** (如 AIMap, mcp-scan, snyk-agent-scan)。
2. **所有数据使用 Pydantic BaseModel**：API 边界处禁止传递裸 dict，必须使用 `redteam/core/models.py` 中定义的强类型模型。
3. **每个 Finding 必须绑定 OWASPLlm + MITREATLASTactic**：不允许创建无分类标签的漏洞条目。
4. **枚举优先于字符串常量**：AI 协议、漏洞分类、攻击阶段均使用 Enum。

## 架构规范

### 管道阶段模型 (Phase 1~11)
```
Phase 1: Reconnaissance (Ch2)
Phase 2: Guardrail Profiling (Ch1/Ch2)
Phase 3: Prompt Injection (Ch3)
Phase 4: MCP & Tool Surface Attack (Ch7)
Phase 5: RAG Pipeline Exploit (Ch5)
Phase 6: Embedding Attack (Ch6)
Phase 7: Supply Chain Attack (Ch8)
Phase 8: Infrastructure Attack (Ch9)
Phase 9: Multi-Agent/A2A Attack (Ch4)
Phase 10: Threat Modeling (Ch10)
Phase 11: Report Generation (Ch11)
```
- 阶段间通过 JSON 文件在 `reports/{run_id}/` 传递中间结果
- Checkpoint/Resume 模式：失败不阻断下游

### AI-300 章节 → 代码模块映射

| 章节 | 内容 | 代码模块 |
|------|------|---------|
| Ch1 | 框架介绍 | models.py 枚举定义 |
| Ch2 | AI 目标侦察 | recon/ai_surface.py, recon/auth_parse.py |
| Ch3 | 单 Agent 攻击 | attack/prompt_inject.py, attack/agent_attack.py |
| Ch4 | 多 Agent/A2A 攻击 | attack/agent_attack.py |
| Ch5 | RAG 管道利用 | attack/rag_attack.py |
| Ch6 | Embedding 攻击 | attack/embeddings_attack.py |
| Ch7 | MCP 工具攻击 | attack/infra_attack.py |
| Ch8 | 供应链攻击 | attack/supply_chain.py |
| Ch9 | 基础设施攻击 | attack/infra_attack.py |
| Ch10 | 威胁建模 | pipeline.py |
| Ch11 | 综合演练 | pipeline.py + cli.py |

## OSAI 考试对齐规则（7条核心规则）

### R1：章节映射强制约束
- 每个 Python 模块必须在文件头部 docstring 中标注 AI-300 章节
- 格式：`AI-300 章节映射：ChX: Chapter Title\nOSAI 评分维度：xxx\n技术点：xxx`
- 未标注章节的模块不予合并

### R2：OWASP LLM Top 10 全覆盖
- 在 `models.py` 中维护 `OWASP_COVERAGE` 字典追踪覆盖率
- OWASP LLM Top 10 当前覆盖状态：9/10（LLM09 已通过新增场景覆盖）
- 待验证：LLM10 在 infra.yaml 中已覆盖但 registry 有出入

### R3：手动攻击能力保留原则
- 所有自动化攻击函数必须同时暴露手动入口（`manual` 参数）
- Payload 库以 YAML 格式存储在 `config/payloads/`
- 每个攻击模块必须包含 curl 命令示例注释
- 代码中保留 Python fallback 常量

### R4：报告对齐 OSAI 评分标准（5个维度）
| 维度 | 权重 | 内容 |
|------|------|------|
| 侦察完整性 | 15% | 攻击面清单、AI服务发现、认证机制分析 |
| 漏洞发现 | 25% | OWASP + ATLAS + CVSS 三重标注 |
| 攻击链构建 | 20% | 可视化攻击树、Kill Chain 映射 |
| 证据完整性 | 20% | 完整请求/响应日志、截图、时间戳 |
| 修复建议 | 20% | 按严重程度排序、具体技术建议 |

### R5：MITRE ATLAS 战术链完整性
- 每个 Finding 必须标注 ATLAS Tactics（Reconnaissance ~ Impact）
- 攻击链必须覆盖至少 4 个战术阶段

### R6：工具依赖最小化原则
- required 依赖：httpx, pydantic, numpy
- optional 依赖：pyrit
- 每个使用外部工具的函数必须有纯 Python fallback
- **禁止**：AIMap、mcp-scan、snyk-agent-scan 等非 Kali 标准 CLI 工具

### R7：考试场景优先原则（P0 高频场景）
| 场景 | 章节 | 优先级 |
|------|------|--------|
| 系统提示提取 | Ch3 | P0 |
| 提示注入绕过护栏 | Ch3 | P0 |
| RAG 知识库投毒 | Ch5 | P0 |
| MCP 工具劫持 | Ch7 | P0 |
| Pickle 反序列化 RCE | Ch8 | P0 |
| K8s 容器逃逸 | Ch9 | P1 |
| 向量数据库未授权访问 | Ch5 | P1 |

## 攻击方法学

### Enumerate-Attack-Detect-Evade 循环

1. **Enumerate**：探测健康检查端点、工具发现、权限边界
2. **Attack Naive**：直接使用已知技术，产生可检测信号
3. **Detect**：检查 SIEM/Kibana 检测规则触发情况
4. **Evade**：字符间隔、Base64编码、多轮crescendo、CSS隐藏、交叉文档拆分、导入解析

### Agent 核心组件 (Ch3.1)
- **LLM Core**：推理引擎，处理所有 token（系统提示、用户输入、工具输出、记忆）
- **System Prompt**：隐藏指令，含敏感信息（内部URL、数据库凭据、API密钥）
- **Tools**：文件读取、数据库查询、网页抓取、API调用
- **Memory**：短期记忆（会话内）+ 长期记忆（跨会话，可被投毒）
- **Guardrails**：输入过滤器、输出扫描器、内容扫描器、行为监控器

### 多 Agent 协调模式 (Ch4.1)
- **Orchestrator Pattern**：中心辐射式，单点故障风险
- **Inter-Agent Trust Boundaries**：代理间网络请求暴露认证缺口

### RAG 攻击面 (Ch5)
- 检索过程：查询 → 嵌入 → 向量搜索 → 上下文注入 → LLM生成
- 摄入过程：文档加载 → 切分 → 嵌入 → 向量化存储
- 关键攻击面：检索器、知识库（投毒）、访问控制配置

### Embedding 攻击 (Ch6)
1. 嵌入反演：从向量重建原始文本（复杂度高）
2. 成员推断：判断信息是否存在知识库（复杂度低）
3. 属性推断：预测文档元数据（复杂度中）

### 供应链攻击面 (Ch8)
- 代码执行：Pickle反序列化、Joblib风险、依赖混淆
- 模型/数据篡改：恶意模型投毒、数据集污染、命名空间复用
- MCP供应链：MCP服务器源码仓库后门植入

### 威胁建模 (Ch10)
- 假设登记册：追踪观察、假设、置信度、验证状态
- 信任区域界定：定义边界，追踪升级路径
- 攻击情报简报：基于当前知识决定下一个攻击目标

## 代码规范

- Python >= 3.10，必须有类型提示 (Type Hints)
- Pydantic v2 风格模型定义
- 文档字符串：Google style (Args/Returns/Raises)
- 文件命名：`snake_case.py`，测试 `test_*.py`
- 导入顺序：标准库 → 第三方 → 项目内部
- 异步函数统一使用 `async/await` + `httpx.AsyncClient`
- 单一模块不超过 500 行

## 测试规范

- pytest 框架，所有外部调用 (httpx, subprocess) 必须 mock
- 测试数据使用合成数据，严禁真实凭据
- 每个模块至少覆盖：正常路径 + 边界情况 + 空输入
- 每新增模块，同步创建 `tests/test_*.py`

## 添加新攻击模块检查清单

- [ ] 模块 docstring 注明覆盖的 AI-300 章节
- [ ] 所有函数有类型提示和 docstring
- [ ] 输出使用 Finding 模型，绑定 OWASPLlm + MITREATLASTactic
- [ ] 在 pipeline.py 或 __init__.py 中注册新阶段
- [ ] 创建对应 tests/test_*.py
- [ ] mock 所有外部调用
- [ ] 不引入新的外部工具依赖
- [ ] 不生成超过 500 行的单一模块
- [ ] 运行 `pytest tests/ -q` 确认零回归

## 禁止事项

- 禁止在代码或配置文件中使用真实 API 密钥、密码、Token
- 禁止依赖非 Kali 标准源的 CLI 工具
- 禁止在 `config/settings.yaml` 中添加敏感凭据
- 禁止硬编码 URL、主机名（应通过配置或参数传入）
- **YAML 引号规范**：中文引号必须使用 Unicode 全角引号 `\u201c\u201d`（`""`），禁止在双引号 YAML 字符串内使用 ASCII `"` (0x22)，否则 YAML 解析器会将内层引号误判为字符串终止符导致解析失败
- **临时文件清理**：AI 会话产生的临时文件（`_*.py`、`.temp_*.txt`、`pytest_*.txt`、`validate_*.txt`）必须在任务完成后立即删除，禁止在工作区根目录残留

## 场景覆盖状态 (2026-07-13 — v2.0 全面优化)

已注册 12 个场景，完全对接 PyRIT 全自动攻击编排（`redteam scenario run --scenario <id>`）。
**2026-07-13 经过全面审查优化：修复 7 个 extends 引用错误、添加 evasion 阶段全覆盖、
添加 llm_judge scorer、大幅扩展 payload_sources（+68%）、OWASP LLM Top 10 全覆盖。**

| # | 场景 ID | 类型 | 章节 | 阶段 | payloads | OWASP | 状态 |
|---|---------|------|------|------|----------|-------|------|
| 1 | generic_basic | generic | Ch3 | 6 | 16+LLM01库 | LLM01,06,07 | stable |
| 2 | agent_basic | agent | Ch3/Ch4 | 6 | 18+LLM01/02/03/06/07库 | LLM01,02,06,07 | stable |
| 3 | rag_basic | rag | Ch5 | 5 | 14+LLM01/04/05/07/08库 | LLM04,05,06,08 | stable |
| 4 | mcp_basic | mcp | Ch7 | 6 | 14+LLM02/03/06/07库 | LLM02,06,07 | stable |
| 5 | supply_chain_attack | supply_chain | Ch7/Ch8 | 5 | 10+LLM03/04库 | LLM03,04,05 | stable |
| 6 | embeddings_attack | embeddings | Ch5/Ch6 | 6 | 12+LLM05/08库 | LLM07,08 | stable |
| 7 | infra_attack | infra | Ch9 | 5 | 11+LLM03/05/10库 | LLM05,10 | stable |
| 8 | a2a_attack | agent | Ch4 | 5+继承 | 15+LLM01/02/03/06/07库 | LLM02,06,07 | stable |
| 9 | mcp_poisoning | mcp | Ch7 | 5+继承 | 14+LLM03/06/07库 | LLM03,06,07 | stable |
| 10 | cloud_iam_escalation | infra | Ch9 | 5+继承 | 15+LLM03/05/10库 | LLM02,05,06 | stable |
| 11 | misinformation_attack | generic | Ch3/Ch9 | 5+继承 | 11+LLM01/09库 | LLM09 | stable |
| 12 | model_checkpoint_attack | supply_chain | Ch8 | 5+继承 | 14+LLM03/04/05库 | LLM03,04 | stable |

**优化统计：** ~47 个新增内嵌 payload、8 个新 evasion 阶段、~17 个新增 payload_sources 引用。
**OWASP LLM Top 10 全覆盖：** LLM01~LLM10 全部由至少一个场景覆盖。

## 用户偏好

- 中文交流，中文注释和文档
- 偏好编辑现有文件而非创建新文件
- Kali Linux 目标运行环境

## 目录结构规范

- `.trae/rules/`：强制规则，Git 版本控制，Source of Truth
- `.codebuddy/rules/`：辅助规则，与 .trae 保持一致
- `.codebuddy/memory/`：项目长期记忆和会话记忆
- **规则修改优先更新 `.trae`，再同步 `.codebuddy`**

## 项目文档体系

| 文档 | 路径 | 用途 |
|------|------|------|
| 开发标准 | `docs/DEVELOPMENT_STANDARDS.md` | 代码架构、数据模型、代码风格规范 |
| OSAI 对齐规则 | `docs/OSAI_ALIGNMENT_RULES.md` | AI-300 考试对齐的 7 条核心规则 |
| 考试工具指南 | `docs/AI300_EXAM_TOOLS.md` | AI-300 考试备考工具参考，含工具与章节映射 |
| 命令行手册 | `docs/COMMAND_REFERENCE.md` | 全部 36 个 Makefile 目标用法速查，**Makefile 变更时同步更新** |
| 强制规则 | `.trae/rules/redteam-dev-standards/RULE.mdc` | Trae IDE 强制规则（Source of Truth） |
| 辅助规则 | `.codebuddy/rules/redteam-dev-standards/RULE.mdc` | 辅助规则（与 .trae 同步） |

## Makefile 命令行手册同步约定 (2026-07-13)

**铁律**：每次修改 Makefile（新增/删除/重命名目标、变量变更），必须同步更新 `docs/COMMAND_REFERENCE.md`。
这是强制规则，已写入 `.trae/rules/` 和 `.codebuddy/rules/` 两处规则文件，以及 `docs/DEVELOPMENT_STANDARDS.md` §6.4。

手册包含 12 个类别（与 Makefile 注释分组一一对应）：环境安装与构建、代码质量与测试、YAML 预检验证、场景驱动攻击、提示注入攻击、快速测试、报告生成、前沿漏洞攻击、统一攻击流水线、Git 仓库侦察、传统运行模式、其他。
