# RedTeam-AI 项目长期记忆

## 项目定位

AI 红队攻击模拟工具，面向 OffSec AI-300 (OSAI) 考试备考和实际 AI 红队评估。目标用户：Kali Linux 环境中的安全专业人员。

## 架构设计哲学

本项目采用 **YAML 数据驱动端到端自动化攻击** 架构，**纯原生（v2.4 Native-Only）**，零框架依赖。

**六大核心设计原则：**

1. **YAML 数据驱动**：载荷/场景/参数全部通过 YAML 定义（`config/payloads/` + `config/scenarios/`），实现「配置即攻击」。YAML 缺失时自动回退 Python fallback 常量。
2. **AI 红队专家风格**：每阶段以专业安全分析师视角呈现 — 侦察情报简报、攻击策略推荐（动态成功率）、风险指标推导。
3. **纯原生（Native-Only）**：所有攻击模块使用 `NativeAttackRunner`（纯 httpx），零框架依赖，考试环境 100% 可跑。
4. **多轮编排原生化**：Crescendo/TAP/PAIR 全部由 `MultiTurnOrchestrator` 纯原生实现，支持可选 attacker LLM 动态生成。
5. **全局统筹**：Phase 1~11 完整攻击链，侦察结果自动驱动后续阶段目标选择；每个阶段输出严重等级分解和实时进度。
6. **阶段提示**：统一双线边框横幅（72 字符 + AI-300 章节标注 + ⏳/⚔️/✓ 状态图标）+ 严重等级分解条 + 全局风险仪表盘。

**攻击执行策略矩阵：**

| 能力域 | 执行策略 | 引擎 |
|--------|---------|------|
| 单轮注入/编码绕过 | 永远原生 | NativeAttackRunner (httpx) |
| 规则评分 | 永远原生 | HybridScorer/FastGrayscaleScorer |
| 侦察/RAG/Embedding/供应链/K8s/报告 | 永远原生 | 自研模块 |
| 多轮 Crescendo/TAP/PAIR | 永远原生 | multi_turn_orchestrator.py |

**CLI 向导核心工作流：**

```
目标输入 → 认证 → 连通性验证
    ↓
Phase 1: 侦察 → 情报简报（攻击面全景）
    ↓
侦察→攻击决策衔接：
  ├─ 攻击策略推荐（按协议族动态成功率）
  ├─ 目标确认 [y/N]
  └─ Phase 2 参数配置（多轮攻击/attacker LLM/judge）
    ↓
Phase 2: 提示注入（原生引擎）
    ↓
Phase 3~8: 统一横幅 + 严重等级分解 + 结果摘要
    ↓
Phase 9: 威胁建模 → 综合报告 → 全局风险仪表盘
```

## 四大核心铁律

1. **Library-First 原则**：首选纯 Python 库 (httpx, pydantic)，次选 Kali 标准工具 subprocess 调用。**严禁依赖外部小众 CLI 工具**。
2. **所有数据使用 Pydantic BaseModel**：API 边界处禁止传递裸 dict。
3. **每个 Finding 必须绑定 OWASPLlm + MITREATLASTactic**：不允许创建无分类标签的漏洞条目。
4. **枚举优先于字符串常量**：AI 协议、漏洞分类、攻击阶段均使用 Enum。

## 管道阶段模型

```
Phase 1: Reconnaissance (Ch2)          Phase 7: Supply Chain Attack (Ch8)
Phase 2: Guardrail Profiling (Ch1/Ch2) Phase 8: Infrastructure Attack (Ch9)
Phase 3: Prompt Injection (Ch3)        Phase 9: Multi-Agent/A2A Attack (Ch4)
Phase 4: MCP & Tool Surface (Ch7)      Phase 10: Threat Modeling (Ch10)
Phase 5: RAG Pipeline Exploit (Ch5)    Phase 11: Report Generation (Ch11)
Phase 6: Embedding Attack (Ch6)
```

- 阶段间通过 JSON 文件 (`reports/{run_id}/`) 传递中间结果，Checkpoint/Resume 模式，失败不阻断下游。

## OSAI 考试对齐规则（7 条）

| 规则 | 要点 |
|------|------|
| R1 章节映射 | 每个 Python 模块 docstring 标注 AI-300 章节 |
| R2 OWASP 全覆盖 | `models.py` 中维护 `OWASP_COVERAGE` 字典，OWASP LLM Top 10 已完成全覆盖 |
| R3 手动能力保留 | 所有攻击函数暴露 `manual` 参数，Payload 库 YAML 存储，保留 Python fallback |
| R4 报告 5 维度 | 侦察 15% + 漏洞发现 25% + 攻击链 20% + 证据 20% + 修复建议 20% |
| R5 ATLAS 链 | 每个 Finding 标注 ATLAS Tactics，攻击链覆盖 ≥4 战术阶段 |
| R6 工具最小化 | required: httpx/pydantic/numpy, 零外部框架依赖, 禁止小众 CLI 工具 |
| R7 考试优先 | P0: 系统提示提取/注入绕过/RAG投毒/MCP劫持/Pickle RCE |

## 攻击方法学要点

- **Enumerate-Attack-Detect-Evade 循环**：4 阶段递进
- **Agent 核心组件**：LLM Core, System Prompt, Tools, Memory, Guardrails
- **多 Agent 模式**：Orchestrator Pattern (中心辐射), Inter-Agent Trust Boundaries
- **RAG 攻击面**：检索过程 + 摄入过程，关键面 = 检索器/知识库/访问控制
- **Embedding 弱点**：嵌入反演 (高), 成员推断 (低), 属性推断 (中)
- **供应链风险**：Pickle 反序列化, Joblib, 依赖混淆, 模型投毒, MCP 后门
- **威胁建模方法**：假设登记册, 信任区域界定, 攻击情报简报

## 代码规范

- Python >= 3.10 + Type Hints, Pydantic v2, Google style docstring
- snake_case.py, test_*.py, 导入: 标准库→第三方→项目内部
- 单一模块 ≤500 行, 异步统一 async/await + httpx.AsyncClient

## 测试规范

- pytest, 所有外部调用 mock, 合成数据, 禁止真实凭据
- 每模块: 正常路径 + 边界 + 空输入, 新模块同步创建 test

## 场景覆盖

12 个场景 (generic/agent/rag/mcp/supply_chain/embeddings/infra/a2a/mcp_poisoning/cloud_iam/misinformation/model_checkpoint)，OWASP LLM Top 10 全覆盖，纯原生引擎 (NativeAttackRunner) 执行。

## 禁止事项

- 禁止真实凭据, 非 Kali CLI 工具, settings.yaml 硬编码凭据, 硬编码 URL
- YAML 中文引号使用 Unicode `\u201c\u201d`（`""`），禁止 ASCII `"` 在双引号 YAML 内
- 临时文件 (`_*.py`, `.temp_*.txt` 等) 任务完成后立即删除

## 用户偏好

- 中文交流，中文注释和文档；偏好编辑现有文件；Kali Linux 目标环境

## 目录与文档结构

- `.trae/rules/` = 强制规则 (Git, Source of Truth)；`.codebuddy/rules/` = 辅助规则（同步自 .trae）
- `.codebuddy/` ↔ `.trae/` 双向自动同步：任一目变更须同步更新另一目录（见开发规范）
- `docs/`: DEVELOPMENT_STANDARDS.md, OSAI_ALIGNMENT_RULES.md, AI300_EXAM_TOOLS.md, COMMAND_REFERENCE.md
- Makefile 变更 → 必须同步更新 `docs/COMMAND_REFERENCE.md`

## CLI 错误处理规范

- `main()` 使用 `try/except typer.Exit` 包装，抑制 Python 完整 traceback
- 连通性测试失败等预期错误只显示友好错误消息，不打印调用栈
