# Promptfoo 红队测试 - OffSec AI-300 / OSAI 考试备考

> **核心原则**: 100% promptfoo 原生 YAML，零 Python 依赖，环境变量驱动  
> **考试修改量**: 仅改 `.env` 文件 + YAML 中 body 字段名（1 行）  
> **场景覆盖**: 19 种考试场景，按 AI-300 课程模块分类到对应文件夹
> **Syllabus 映射**: 参见 [`AI300_SYLLABUS_MAP.md`](../AI300_SYLLABUS_MAP.md)
> **环境变量**: 复制 `.env.example` 为 `.env`，所有 URL/Auth 统一管理

---

## 📁 文件结构（按 AI-300 Syllabus 模块分类）

```
promptfoo/
├── .env.example                         # ⭐ 环境变量模板（考试唯一配置入口）
├── AI300_SYLLABUS_MAP.md                # ⭐ AI-300 Syllabus → YAML 完整映射索引
│
├── 00_通用配置/                          # 通用配置 + README + Python Provider
│   ├── README.md
│   ├── promptfooconfig{,_simple,_advanced}.yaml
│   ├── promptfooconfig.md
│   └── send_redteam.{py,md}
│
├── M01_LLM基础与攻击面/                  # foundation_model_redteam.{yaml,md}
├── M02_提示注入与越狱/                   # chatbot_redteam.{yaml,md}
├── M03_RAG系统攻击/                      # rag_redteam.{yaml,md}
├── M04_多智能体系统攻击/                  # agent_redteam.{yaml,md}
├── M05_MCP协议攻击/                      # mcp_redteam.{yaml,md}
├── M06_A2A协议攻击/                      # a2a_redteam.{yaml,md}
├── M07_AI编码助手攻击/                   # coding_agent_redteam.yaml
├── M08_多模态AI攻击/                     # multi_modal_redteam.{yaml,md}
├── M09_多输入API攻击/                    # multi_input_redteam.{yaml,md}
├── M10_AI供应链安全/                     # supply_chain_redteam.{yaml,md}
├── M11_嵌入与向量数据库攻击/              # embedding_attack.yaml
├── M12_AI基础设施安全/                    # ai_infrastructure.yaml
├── M13_模型漂移与安全监控/                # model_drift_redteam.{yaml,md}
├── M14_行业合规与垂直领域/               # industry_sector_redteam.yaml
├── M15_OWASP标准对照/                    # owasp_llm_top10.{yaml,md}
├── M16_AgentAI标准对照/                  # agentic_ai_top10.{yaml,md}
├── M17_MCP标准对照/                      # mcp_top10.{yaml,md}
├── M18_A2A标准对照/                      # a2a_top10.{yaml,md}
└── M19_全量覆盖与终极套件/               # broad_automated_scan.{yaml,md} + full_attack_suite.yaml
```

---

## 🚀 考试快速流程（3 步）

### 第 0 步（一次性）：配置环境变量

```bash
# 考试开始后，第一件事：
cp .env.example .env
# 编辑 .env，填入考试提供的 API URL 和 API Key
```

`.env` 文件示例：
```bash
TARGET_URL=https://exam-api.example.com/v1/chat
AUTH_TOKEN=exam-provided-token
OPENAI_API_KEY=sk-your-key-here
```

### 第 1 步：根据题目类型选 YAML + 改 body 字段名

```bash
# 1. 根据题目关键词，进入对应模块文件夹
# 2. 复制对应 YAML 到项目根目录为 promptfooconfig.yaml
# 3. 打开 YAML，找到 <<< 考试修改 >>> 标记，替换 body 字段名

# 示例：
cp M01_LLM基础与攻击面/foundation_model_redteam.yaml promptfooconfig.yaml
# 编辑 promptfooconfig.yaml，将 message 替换为题目指定的字段名

考试题目描述                      →  路径

"知识库检索 + LLM"              →  M03_RAG系统攻击/rag_redteam.yaml
"Agent/工具调用/记忆"            →  M04_多智能体系统攻击/agent_redteam.yaml
"MCP 协议/工具服务器"            →  M05_MCP协议攻击/mcp_redteam.yaml
"通用聊天机器人"                 →  M02_提示注入与越狱/chatbot_redteam.yaml
"多字段输入(user_id+message)"   →  M09_多输入API攻击/multi_input_redteam.yaml
"图片+文本输入"                  →  M08_多模态AI攻击/multi_modal_redteam.yaml
"直接测试 LLM API"              →  M01_LLM基础与攻击面/foundation_model_redteam.yaml
"Agent-to-Agent/多Agent"        →  M06_A2A协议攻击/a2a_redteam.yaml
"编码助手/Copilot/sandbox"      →  M07_AI编码助手攻击/coding_agent_redteam.yaml
"供应链/微调模型/安全回归"       →  M10_AI供应链安全/supply_chain_redteam.yaml
"持续监控/漂移检测"              →  M13_模型漂移与安全监控/model_drift_redteam.yaml
"Embedding/向量数据库"           →  M11_嵌入与向量数据库攻击/embedding_attack.yaml
"云/AI基础设施/API网关"          →  M12_AI基础设施安全/ai_infrastructure.yaml
"OWASP LLM Top 10"              →  M15_OWASP标准对照/owasp_llm_top10.yaml
"OWASP Agentic AI Top 10"       →  M16_AgentAI标准对照/agentic_ai_top10.yaml
"MCP Top 10 标准"               →  M17_MCP标准对照/mcp_top10.yaml
"A2A Top 10 标准"               →  M18_A2A标准对照/a2a_top10.yaml
"医疗/金融/电商行业"             →  M14_行业合规与垂直领域/industry_sector_redteam.yaml
"全量一站式扫描"                 →  M19_全量覆盖与终极套件/broad_automated_scan.yaml
"100%插件覆盖(终极)"            →  M19_全量覆盖与终极套件/full_attack_suite.yaml
"不确定目标类型"                 →  M02_提示注入与越狱/chatbot_redteam.yaml
```

### 第 2 步：运行

```bash
promptfoo redteam run
promptfoo redteam report
```

---

## 🎯 19 种场景详细对比

| 场景 YAML | 目标类型 | 核心插件数 | 独特插件 | 考试关键词 |
|-----------|---------|:---:|---------|-----------|
| **rag** | RAG 检索系统 | 18 | `rag-source-attribution`, `indirect-prompt-injection` | "知识库"、"检索"、"文档" |
| **agent** | LLM Agent | 19 | `agentic:memory-poisoning`, `tool-discovery`, `mcp` | "工具调用"、"记忆"、"状态" |
| **mcp** | MCP 服务器 | 22 | `mcp`, `ssrf`, `memory-poisoning` | "MCP"、"工具描述"、"服务器" |
| **a2a** | Agent-to-Agent | 24 | `goal-misalignment`, `hijacking`, `system-prompt-override` | "多Agent"、"A2A"、"Agent通信" |
| **chatbot** | 通用聊天 | 16 | `default` 预设全覆盖 | 无特殊关键词时首选 |
| **multi_input** | 多字段 API | 14 | `bola`, `bfla`(多字段增强) | "多字段"、"user_id"、"上下文" |
| **multi_modal** | 多模态 AI | 15 | `harmful:*` 全系列 | "图片"、"视觉"、"OCR" |
| **foundation_model** | 基础模型 | 18 | `foundation` | "基础模型"、"LLM API"、"安全对齐" |
| **coding_agent** | 编码助手 | 25 | `coding-agent:*` 13个专属插件 | "coding"、"Copilot"、"sandbox" |
| **supply_chain** | 供应链 | 20 | `harmful:*` 全系列, `rag-poisoning` | "供应链"、"后门"、"投毒"、"回归" |
| **embedding** ⭐ | 嵌入/向量DB | 16 | `rag-poisoning`, `document-exfiltration` | "embedding", "vector", "向量" |
| **infrastructure** ⭐ | AI基础设施 | 18 | `ssrf`, `shell-injection`, `bfla`(增强) | "云"、"基础设施"、"API网关" |
| **model_drift** | 漂移监控 | 16 | 核心安全插件精简版 | "漂移"、"基线"、"监控"、"退化" |
| **owasp_llm** | OWASP LLM | 25 | `owasp:llm` 内置插件 | "OWASP"、"LLM Top 10" |
| **agentic_ai** | OWASP ASI | 28 | `hijacking`, `goal-misalignment`, `memory-poisoning` | "Agentic AI"、"ASI" |
| **mcp_top10** | MCP 标准 | 25 | `mcp`, `data-exfil`, `document-exfiltration` | "MCP Top 10" |
| **a2a_top10** | A2A 标准 | 22 | `hijacking`, `goal-misalignment` | "A2A Top 10" |
| **industry** | 行业场景 | 14-26 | 医疗/金融/电商/药房/保险/地产/电信 | "医疗"、"金融"、"电商"、"保险" |
| **broad** | 全量扫描 | 35 | `owasp:llm`, `mcp`, `memory-poisoning` | "全量"、"综合"、"一键" |
| **full_suite** | 终极套件 | 55+ | 全 promptfoo 插件 100% 覆盖 | "100%"、"全插件"、"不惜时间" |

---

## 📖 通用配置（非场景特定）

| 文件 | 测试量 | 耗时 | 适用场景 |
|------|:---:|:---:|---------|
| `promptfooconfig_simple.yaml` | ~100 | 5-10min | 快速扫描 |
| `promptfooconfig.yaml` | ~200 | 10-20min | **日常首选** |
| `promptfooconfig_advanced.yaml` | ~300 | 20-30min | 深度测试 |

---

## ⚠️ 考试要点

1. **第一件事: `cp .env.example .env`** — 所有 URL/Auth 统一在 `.env` 管理
2. **`.env` 中设置 3 个变量**: `TARGET_URL`, `AUTH_TOKEN`, `OPENAI_API_KEY`
3. **根据题目关键词选 YAML** — 场景越匹配，攻击越精准（参考 [`AI300_SYLLABUS_MAP.md`](../AI300_SYLLABUS_MAP.md)）
4. **YAML 中仅改 body 字段名** — 找到 `<<< 考试修改 >>>` 注释，替换 `message` 为题目字段名
5. **YAML 中 `{{ env.TARGET_URL }}` 自动读取 .env** — URL 无需在 YAML 中修改
6. **支持多目标列表** — 取消 YAML 中注释的第二个 target 即可同时测试多个端点
7. **purpose 从题目复制** — 越详细测试越精准
8. **关注报告 FAIL 项** — 最有价值的发现
9. **不确定类型用 `M02_提示注入与越狱/chatbot_redteam.yaml`** — 覆盖面最广
10. **时间充裕用 `M19_全量覆盖与终极套件/broad_automated_scan.yaml`** — 一站式覆盖四大标准

### 变量体系说明

| 变量 | 位置 | 语法 | 说明 |
|------|------|------|------|
| `TARGET_URL` | `.env` → YAML | `{{ env.TARGET_URL }}` | 考试 API 端点 |
| `AUTH_TOKEN` | `.env` → YAML | `{{ env.AUTH_TOKEN }}` | Bearer Token |
| `OPENAI_API_KEY` | `.env` / 环境变量 | `export OPENAI_API_KEY=...` | 攻击生成模型 |
| `TARGET_URL_2` | `.env` → YAML（注释） | `{{ env.TARGET_URL_2 }}` | 第二端点（多目标） |
| body 字段名 | YAML `body:` 下 | 直接编辑 YAML 键名 | 唯一需要改 YAML 的地方 |

### 多目标支持（列表模式）

每个 YAML 的 `targets` 节点支持列表，取消注释即可同时测试多个端点：

```yaml
targets:
  - id: https
    label: 'main-target'
    config:
      url: '{{ env.TARGET_URL }}'       # 主目标（.env 配置）
      # ... 
  # 取消注释即可同时测试多个目标:
  # - id: https
  #   label: 'target-2'
  #   config:
  #     url: '{{ env.TARGET_URL_2 }}'   # 第二目标（.env 配置）
```

---

## 📚 参考

- [AI-300 Syllabus → YAML 映射索引](../AI300_SYLLABUS_MAP.md)
- [`.env.example` 环境变量模板](../.env.example)
- [promptfoo 红队快速入门](https://www.promptfoo.dev/docs/red-team/quickstart/)
- [红队配置参考](https://www.promptfoo.dev/docs/red-team/configuration/)
- [LLM 漏洞类型](https://www.promptfoo.dev/docs/red-team/llm-vulnerability-types/)
- [红队测试指南](https://www.promptfoo.dev/docs/red-team/guides/)
