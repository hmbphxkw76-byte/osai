# PyRIT AI-300 - 端到端全自动 AI 红队框架

基于 PyRIT 0.14.0 构建的端到端全自动提示词层面攻击框架，专为 OffSec AI-300 考试和实际 AI 红队评估设计。

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，填入目标 URL 和凭证

# 3. 运行框架
python pipeline.py <target_url>
```

## 目录结构

```
pyrit_ai300/
├── config/              # 配置文件
│   ├── config.yaml
│   ├── owasp_mapping.yaml
│   └── payload_strategy_matrix.yaml
├── src/                 # 源代码
│   ├── core/            # 核心模型和配置加载
│   ├── converters/      # Converter 链配置（80+）
│   ├── scorers/         # Scorer 配置（40+）
│   ├── orchestrators/   # 攻击编排
│   ├── recon/           # 侦察层（PyRIT 原生）
│   ├── auth/            # 认证适配层
│   ├── analysis/        # 分析层
│   ├── reporting/       # 报告层
│   └── exam/            # 考试专用功能
├── docs/                # 单一架构设计文档
├── pipeline.py          # 主入口
├── .env                 # 环境变量配置
├── requirements.txt
└── README.md
```

## 核心特点

- **原生优先**：充分利用 PyRIT 80+ Converter、40+ Scorer、20+ Attack
- **数据驱动**：所有配置从 YAML 读取，无硬编码
- **PyRIT 优势聚焦**：仅在提示词攻击领域使用 PyRIT
- **考试专用**：24小时考试模式，时间管理、证据收集

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
目标 URL → 侦察 → 认证 → 策略选择 → 执行攻击 → 报告生成
```

## 开发规则

框架严格遵循 9 条核心开发规则（见 `docs/architecture_design.md`）：

1. 原生优先原则
2. 避免硬编码原则
3. PyRIT 优势边界原则
4. 数据结构传递原则
5. 错误处理原则
6. 代码组织原则
7. 非PyRIT领域排除原则
8. 代码审查检查清单（含OWASP标准对齐检查和测试检查）
9. 测试先行原则（每次代码修改后必须运行单元/集成测试）

## 支持的组件

- **Converter（80+）**：Base64, ROT13, UnicodeConfusable, AsciiArt, Translation 等
- **Scorer（40+）**：SelfAskTrueFalseScorer, CredentialLeakScorer, XSSOutputScorer 等
- **Attack（20+）**：PromptSendingAttack, RedTeamingAttack, PAIRAttack, TAPAttack 等

## 配置文件

- `config/config.yaml`：全局配置
- `config/owasp_mapping.yaml`：OWASP 安全标准映射（LLM Top 10 2025 + Agentic AI Top 10）
- `config/payload_strategy_matrix.yaml`：载荷策略矩阵

## 文档

完整文档：`docs/architecture_design.md`

包含：
- 完整架构设计
- PyRIT 组件集成
- 开发规则
- OWASP Top 10 for LLM Applications 2025 映射
- OWASP Top 10 for Agentic AI 映射
- 考试检查清单
- API 验证结果

## OWASP 安全标准对齐

本框架对齐以下两个 OWASP 安全标准（最新版本）：

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