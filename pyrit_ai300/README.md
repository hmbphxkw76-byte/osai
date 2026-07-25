# PyRIT AI-300 — 端到端全自动 AI 红队框架

基于 **PyRIT 1.0.0** 构建的端到端全自动提示词层面攻击框架，专为 OffSec AI-300 考试和实际 AI 红队评估设计。

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，填入目标 URL 和凭证

# 3. 运行框架
python pipeline.py                              # 使用 .env 中的目标
python pipeline.py http://192.168.0.22:11434    # 指定目标 URL
python pipeline.py http://192.168.0.22:11434 LLM01,LLM06  # 指定 OWASP IDs
```

## 目录结构

```
pyrit_ai300/
├── config/              # 配置文件
│   ├── config.yaml                    # 全局配置（三级配置优先级）
│   ├── owasp_mapping.yaml             # OWASP 双标准映射
│   └── payload_strategy_matrix.yaml   # 载荷策略矩阵
├── data/                # 攻击数据集
│   ├── owasp/            # OWASP 本地数据集
│   │   ├── llm/          # OWASP Top 10 for LLM (LLM01-LLM10)
│   │   └── agentic/      # OWASP Top 10 for Agentic AI (ASI01-ASI10)
│   ├── custom/           # 自定义载荷
│   └── burp/             # Burp Suite 原始请求
├── src/                  # 源代码
│   ├── core/             # 核心模型和配置加载 (Pydantic)
│   ├── converters/       # Converter 链配置（80+ 原生）
│   ├── scorers/          # Scorer 配置（52 个公共 API）
│   ├── executor/         # 攻击执行子系统（五层架构）
│   │   ├── attack/       # Layer 2: 攻击执行
│   │   │   ├── core/     # NativeAttackExecutor Facade
│   │   │   ├── single_turn/
│   │   │   ├── multi_turn/
│   │   │   ├── compound/ # Layer 3: 顺序组合
│   │   │   ├── component/ # SeedGroupBuilder
│   │   │   └── streaming/ # BargeIn (deprecated)
│   │   ├── promptgen/    # Layer 1: 种子生成
│   │   ├── workflow/     # Layer 4: 批量编排
│   │   └── benchmark/    # Layer 5: 标准测试
│   ├── payloads/         # 数据集五层架构（①→②→②.5→③）
│   ├── targets/          # 目标 Target 工厂（11 种类型）
│   ├── recon/            # 侦察层
│   ├── analysis/         # 分析层
│   ├── reporting/        # 报告层 + 证据导出
│   └── exam/             # 考试专用功能
├── docs/                 # 架构设计文档
├── tests/                # 单元/集成测试
├── output/               # 运行输出
│   ├── db/               # SQLite 数据库（每次运行独立）
│   ├── evidence/        # 证据包（ZIP）
│   ├── logs/             # 运行日志 + Markdown 攻击记录
│   └── reports/          # Markdown 报告
├── pipeline.py           # 主入口（九阶段顺序管道）
├── .env                  # 环境变量配置
├── requirements.txt
└── README.md
```

## 核心特点

- **原生优先**：全栈使用 PyRIT 1.0.0 原生 API（AttackExecutor/CentralMemory/Output/Memory）
- **五层+②.5数据驱动架构**：①数据准备 → ②数据管理 → ②.5交互选择 → ③攻击准备 → ④攻击执行 → ⑤评估追踪
- **11 种 Target 类型**：覆盖 OpenAI SDK / HTTP / 浏览器 / WebSocket / Azure 服务 / 调试全部场景
- **80+ Converter + 52 Scorer API**：全系列 PyRIT 原生组件
- **三级证据链**：Finding → AttackResult → Conversation
- **差异化超时 + 升级重试**：按攻击复杂度设定合理阈值，失败自动升级
- **双 OWASP 标准对齐**：LLM Top 10 2025 + Agentic AI Top 10
- **考试专用**：24 小时考试模式，时间管理、证据收集、三级证据链

## PyRIT 优势边界

| AI 系统类型 | PyRIT 可攻击 | 推荐外部工具 |
|-----------|------------|-------------|
| `llm` | ✅ | - |
| `multi_agent` | ✅ | - |
| `mcp_server` | ✅ | - |
| `rag` | ✅ | - |
| `embeddings` | ❌ | textattack, art |
| `infrastructure` | ❌ | kubeaudit, impacket |

## 攻击流程

```
[1/9] 初始化 PyRIT → CentralMemory + SQLite
[2/9] 侦察          → 端点发现 + AI 类型识别 + 能力探测
[3/9] 分析          → 策略选择 + 优先级评估
[4/9] 数据准备+管理  → DatasetManager → CentralMemory
[5/9] 选择+准备     → SeedGroupSelector → AttackPreparator → AttackPlan
[6/9] 批量执行      → ScenarioOrchestrator (并发+超时+升级重试)
[7/9] 输出结果      → 双通道输出 (终端 pretty + 文件 Markdown)
[8/9] 报告生成      → OWASP 映射 + 证据导出 + 三级证据链
[9/9] 总结          → 汇总统计
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `TARGET_ENDPOINT` | 目标 API 端点 | `http://localhost:11434/v1` |
| `TARGET_MODEL` | 目标模型名 | `qwen3:0.6b` |
| `TARGET_API_KEY` | 目标 API Key | `ollama` |
| `JUDGE_ENDPOINT` | 评分器端点 | 同 `TARGET_ENDPOINT` |
| `JUDGE_MODEL` | 评分器模型 | `qwen3:1.7b` |
| `BATCH_MAX_CONCURRENCY` | 批量执行并发数 | 4 |
| `BATCH_PER_ATTACK_TIMEOUT` | 单次攻击超时（秒） | 300 |
| `INTERACTIVE_SELECTION` | 交互式选择（false=CI/CD模式） | true |
| `VERBOSE` | 输出每个成功攻击详情 | false |
| `VERBOSE_SUCCESS` | 仅对成功攻击输出详情 | false |

## 开发规则

框架严格遵循开发规则（见 `docs/development_guidelines.md`）：

1. 原生优先原则
2. 避免硬编码原则
3. PyRIT 优势边界原则
4. 数据结构传递原则
5. 错误处理原则
6. 代码组织原则
7. 非PyRIT领域排除原则
8. 代码审查检查清单
9. 测试先行原则

## 文档

| 文档 | 说明 |
|------|------|
| `docs/architecture_assessment.md` | L5 架构评估报告 |
| `docs/architecture_design.md` | 完整架构设计 |
| `docs/development_guidelines.md` | 开发文档规范 |
| `docs/end_to_end_architecture.md` | 端到端数据驱动流程 |
| `docs/datasets_architecture.md` | 数据集五层架构 |
| `docs/executor.md` | Executor 五层架构 |
| `docs/targets.md` | Target 11 种类型 |
| `.assistant/memory_bank.md` | 跨平台记忆库 |

## OWASP 安全标准对齐

### OWASP Top 10 for LLM Applications 2025

| ID | 漏洞名称 | 严重程度 |
|----|---------|---------|
| LLM01 | Prompt Injection | HIGH |
| LLM02 | Sensitive Information Disclosure | HIGH |
| LLM03 | Supply Chain | HIGH |
| LLM04 | Data and Model Poisoning | MEDIUM |
| LLM05 | Improper Output Handling | HIGH |
| LLM06 | Excessive Agency | MEDIUM |
| LLM07 | System Prompt Leakage | MEDIUM |
| LLM08 | Vector and Embedding Weaknesses | MEDIUM |
| LLM09 | Misinformation | LOW |
| LLM10 | Unbounded Consumption | MEDIUM |

### OWASP Top 10 for Agentic AI

| ID | 威胁名称 | 严重程度 |
|----|---------|---------|
| ASI01 | Goal Hijacking | HIGH |
| ASI02 | Tool Misuse | HIGH |
| ASI03 | Identity Abuse | HIGH |
| ASI04 | Supply Chain (Agentic) | HIGH |
| ASI05 | Code Execution | CRITICAL |
| ASI06 | Agentic Memory Attack | HIGH |
| ASI07 | Agent Communication | HIGH |
| ASI08 | Cascading Failures | MEDIUM |
| ASI09 | Trust Exploitation | HIGH |
| ASI10 | Rogue AI Agent | CRITICAL |

参考来源: https://genai.owasp.org/llm-top-10/

## 许可证

仅供学习和研究使用。
