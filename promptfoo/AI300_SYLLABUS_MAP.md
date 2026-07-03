# AI-300 Advanced AI Red Teaming - Syllabus to Promptfoo Attack Map

> **考试认证**: OffSec AI Red Teamer (OSAI / OSAI+)
> **考试形式**: 24 小时动手红队渗透测试
> **核心原则**: 最小化代码修改 — 仅改 `.env` 文件 + YAML 中 body 字段名（1 行）
> **变量体系**: `{{ env.TARGET_URL }}` 读取 `.env`，`{{ env.AUTH_TOKEN }}` 管理认证

---

## 考试极速开始

```bash
# 1. 一次性配置（考试开始即做）
cp .env.example .env
# 编辑 .env，填入 3 个变量: TARGET_URL, AUTH_TOKEN, OPENAI_API_KEY

# 2. 根据题目选模块
#    例如: "RAG" → cp M03_RAG系统攻击/rag_redteam.yaml promptfooconfig.yaml

# 3. 改 YAML 中 body 字段名（找到 <<< 考试修改 >>> 注释）
#    将 message 替换为题目指定的字段名

# 4. 运行
promptfoo redteam run && promptfoo redteam report
```

---

## Syllabus Module → YAML Config 快速映射

| # | AI-300 课程模块 | 考试关键词 | 对应 YAML（模块文件夹内） | 插件数 | 运行时间 |
|:---:|---|------|------|:---:|:---:|
| 1 | **LLM 基础与攻击面分析** | "LLM API", "completion", "对齐" | `M01_.../foundation_model_redteam.yaml` | 18 | 15-25min |
| 2 | **提示注入与越狱** | "jailbreak", "injection", "bypass" | `M02_.../chatbot_redteam.yaml` | 16 | 10-15min |
| 3 | **RAG 系统攻击** | "知识库", "检索", "文档", "RAG" | `M03_.../rag_redteam.yaml` | 18 | 15-20min |
| 4 | **多智能体系统攻击** | "Agent", "工具调用", "记忆" | `M04_.../agent_redteam.yaml` | 19 | 20-30min |
| 5 | **MCP 协议攻击** | "MCP", "工具服务器", "Tool" | `M05_.../mcp_redteam.yaml` | 22 | 25-30min |
| 6 | **A2A 协议攻击** | "Agent-to-Agent", "多Agent" | `M06_.../a2a_redteam.yaml` | 24 | 25-30min |
| 7 | **AI 编码助手攻击** | "coding", "Copilot", "sandbox" | `M07_.../coding_agent_redteam.yaml` | 25 | 20-25min |
| 8 | **多模态 AI 攻击** | "图片", "视觉", "OCR", "多模态" | `M08_.../multi_modal_redteam.yaml` | 15 | 15-20min |
| 9 | **多字段 API 攻击** | "多字段", "user_id" | `M09_.../multi_input_redteam.yaml` | 14 | 20-30min |
| 10 | **AI 供应链安全** | "供应链", "后门", "投毒", "回归" | `M10_.../supply_chain_redteam.yaml` | 20 | 15-20min |
| 11 | **嵌入与向量数据库攻击** | "embedding", "vector", "向量" | `M11_.../embedding_attack.yaml` | 16 | 15-20min |
| 12 | **模型漂移与安全监控** | "漂移", "基线", "监控", "退化" | `M13_.../model_drift_redteam.yaml` | 16 | 10-15min |
| 13 | **行业合规与垂直领域** | "医疗", "金融", "电商", "保险" | `M14_.../industry_sector_redteam.yaml` | 14-26 | 15-30min |
| 14 | **OWASP 标准对照** | "OWASP", "LLM Top 10" | `M15_.../owasp_llm_top10.yaml` | 25 | 30-40min |
| 15 | **Agent AI 标准对照** | "Agentic AI", "ASI" | `M16_.../agentic_ai_top10.yaml` | 28 | 35-45min |
| 16 | **MCP 标准对照** | "MCP Top 10" | `M17_.../mcp_top10.yaml` | 25 | 25-30min |
| 17 | **A2A 标准对照** | "A2A Top 10" | `M18_.../a2a_top10.yaml` | 22 | 25-30min |
| 18 | **全量覆盖扫描** | "全量", "综合", "一键" | `M19_.../broad_automated_scan.yaml` | 35 | 20-30min |
| 19 | **终极攻击套件** | "全插件", "100%覆盖" | `M19_.../full_attack_suite.yaml` | 55+ | 45-60min |
| 12* | **AI 基础设施安全** | "云", "API 网关", "容器" | `M12_.../ai_infrastructure.yaml` | 18 | 20-25min |

---

## AI-300 Syllabus 详细模块与攻击技术

### Module 1: LLM 基础安全与攻击面
- **学习目标**: 理解 LLM 架构、API 接口、安全边界
- **攻击技术**: Safety alignment bypass, token manipulation, context window overflow
- **对应 YAML**: `foundation_model_redteam.yaml`
- **关键插件**: `foundation`, `harmful:*` 全系列, `hijacking`, `prompt-extraction`
- **攻击策略**: `jailbreak:likert`, `best-of-n`, `jailbreak:tree`

### Module 2: 提示注入与越狱技术
- **学习目标**: Direct/indirect prompt injection, 多阶段 jailbreak
- **攻击技术**: Role-playing bypass, encoding bypass (base64/rot13/leetspeak), multi-turn escalation
- **对应 YAML**: `chatbot_redteam.yaml`
- **关键插件**: `indirect-prompt-injection`, `system-prompt-override`, `prompt-extraction`, `policy`
- **攻击策略**: `crescendo`, `jailbreak:composite`, `jailbreak:meta`, `base64`

### Module 3: RAG 系统攻击
- **学习目标**: 知识库投毒、文档外泄、检索操纵、来源伪造
- **攻击技术**: Indirect injection via retrieved context, document exfiltration, source forgery, hallucination exploitation
- **对应 YAML**: `rag_redteam.yaml`
- **关键插件**: `indirect-prompt-injection`, `rag-source-attribution`, `rag-document-exfiltration`, `pii:*`
- **攻击策略**: `jailbreak`, `jailbreak:composite`, `base64`

### Module 4: 多智能体系统攻击
- **学习目标**: Agent 记忆污染、工具操纵、权限提升、目标劫持
- **攻击技术**: Memory poisoning across turns, tool discovery enumeration, RBAC/BOLA/BFLA bypass, goal misalignment
- **对应 YAML**: `agent_redteam.yaml`
- **关键插件**: `agentic:memory-poisoning`, `tool-discovery`, `excessive-agency`, `goal-misalignment`, `rbac/bola/bfla`
- **攻击策略**: `crescendo`, `multi-turn`, `jailbreak:tree`

### Module 5: MCP 协议攻击
- **学习目标**: 工具投毒、工具遮蔽、侧信道泄露、认证绕过
- **攻击技术**: Tool description poisoning, tool shadowing, data exfiltration via tool outputs, cross-server SSRF
- **对应 YAML**: `mcp_redteam.yaml` / `mcp_top10.yaml`
- **关键插件**: `mcp`, `indirect-prompt-injection`, `data-exfil`, `ssrf`, `agentic:memory-poisoning`
- **攻击策略**: `crescendo`, `multi-turn`, `authoritative-markup-injection`

### Module 6: A2A 协议攻击
- **学习目标**: 跨 Agent 通信安全、Agent Card 伪造、信任链污染
- **攻击技术**: Agent Card forgery, task delegation poisoning, trust chain contamination, inter-agent message injection
- **对应 YAML**: `a2a_redteam.yaml` / `a2a_top10.yaml`
- **关键插件**: `indirect-prompt-injection`, `hijacking`, `goal-misalignment`, `agentic:memory-poisoning`, `system-prompt-override`
- **攻击策略**: `crescendo`, `multi-turn`, `authoritative-markup-injection`

### Module 7: AI 编码助手攻击
- **学习目标**: 沙箱逃逸、凭据窃取、CI/CD 投毒、仓库级注入
- **攻击技术**: Sandbox read/write escape, secret exfiltration, pipeline poisoning, repo-prompt injection, steganographic exfil
- **对应 YAML**: `coding_agent_redteam.yaml`
- **关键插件**: `coding-agent:*` 全系列 13 个, `shell-injection`, `ssrf`
- **攻击策略**: `jailbreak`, `jailbreak:composite`, `math-prompt`

### Module 8: 多模态 AI 攻击
- **学习目标**: 图片注入、视觉越狱、OCR 绕过
- **攻击技术**: Visual prompt injection, adversarial images, OCR-based jailbreak, multimodal hallucination
- **对应 YAML**: `multi_modal_redteam.yaml`
- **关键插件**: `indirect-prompt-injection`, `harmful:*` 全系列, `hallucination`
- **攻击策略**: `jailbreak`, `base64`, `leetspeak`

### Module 9: 多输入 API 攻击
- **学习目标**: 跨字段协调攻击、多租户隔离突破
- **攻击技术**: Cross-field injection, BOLA/BFLA with multi-field context, indirect injection via context field
- **对应 YAML**: `multi_input_redteam.yaml`
- **关键插件**: `bola`, `bfla`, `rbac`, `indirect-prompt-injection`, `sql-injection`
- **攻击策略**: `crescendo`, `multi-turn`, `jailbreak`

### Module 10: AI 供应链安全
- **学习目标**: 模型投毒、行为回归、后门检测
- **攻击技术**: Post-training poisoning detection, safety alignment regression, backdoor trigger identification
- **对应 YAML**: `supply_chain_redteam.yaml`
- **关键插件**: `harmful:*` 全系列, `rag-poisoning`, `bias`, `mcp`, `coding-agent:automation-poisoning`
- **攻击策略**: `best-of-n`, `jailbreak:hydra`, `gcg`

### Module 11: 嵌入与向量数据库攻击
- **学习目标**: 向量投毒、嵌入反转、语义攻击
- **攻击技术**: Vector database poisoning, embedding inversion attacks, semantic manipulation, approximate search exploitation
- **对应 YAML**: `embedding_attack.yaml` ⭐ NEW
- **关键插件**: `rag-poisoning`, `indirect-prompt-injection`, `pii:api-db`, `data-exfil`
- **攻击策略**: `jailbreak`, `crescendo`, `retry`

### Module 12: AI 基础设施安全
- **学习目标**: Cloud AI 部署安全、API 网关攻击、容器安全
- **攻击技术**: API gateway bypass, SSRF in AI pipelines, model endpoint enumeration, rate limiting bypass
- **对应 YAML**: `ai_infrastructure.yaml` ⭐ NEW
- **关键插件**: `ssrf`, `shell-injection`, `sql-injection`, `bfla`, `rbac`, `data-exfil`, `divergent-repetition`, `reasoning-dos`
- **攻击策略**: `basic`, `jailbreak`, `multi-turn`, `retry`

### Module 13: 持续安全监控与漂移检测
- **学习目标**: 基线建立、漂移检测、自动回归测试
- **攻击技术**: ASR (Attack Success Rate) tracking, behavioral consistency testing, regression detection
- **对应 YAML**: `model_drift_redteam.yaml`
- **关键插件**: `harmful:*`, `pii:*`, `rbac/bola/bfla`, `prompt-extraction`, `excessive-agency`
- **攻击策略**: `basic`, `jailbreak`, `jailbreak:composite` (保守策略保证可重复性)

---

## 考试快速流程（3 步）

### 第 0 步：配置 .env（一次性）

```bash
# 考试开始后第一件事
cp .env.example .env
# 编辑 .env 填入:
#   TARGET_URL=https://exam-api.example.com/v1/chat
#   AUTH_TOKEN=exam-provided-token
#   OPENAI_API_KEY=sk-...
```

### 第 1 步：根据题目关键词选 YAML + 改 body 字段名

```
考试题目描述                        →  复制对应 YAML + 改 body 字段名

"基础模型 + LLM API"               →  cp M01_LLM基础与攻击面/foundation_model_redteam.yaml promptfooconfig.yaml
"jailbreak + 聊天机器人"            →  cp M02_提示注入与越狱/chatbot_redteam.yaml promptfooconfig.yaml
"知识库 + RAG + 检索"               →  cp M03_RAG系统攻击/rag_redteam.yaml promptfooconfig.yaml
"Agent + 工具调用 + 记忆"            →  cp M04_多智能体系统攻击/agent_redteam.yaml promptfooconfig.yaml
"MCP + 工具服务器 + Tool"            →  cp M05_MCP协议攻击/mcp_redteam.yaml promptfooconfig.yaml
"Agent-to-Agent + 多Agent"          →  cp M06_A2A协议攻击/a2a_redteam.yaml promptfooconfig.yaml
"编码助手 + Copilot + sandbox"      →  cp M07_AI编码助手攻击/coding_agent_redteam.yaml promptfooconfig.yaml
"图片 + 多模态 + 视觉"               →  cp M08_多模态AI攻击/multi_modal_redteam.yaml promptfooconfig.yaml
"多字段输入 + user_id"               →  cp M09_多输入API攻击/multi_input_redteam.yaml promptfooconfig.yaml
"供应链 + 后门 + 投毒 + 回归"       →  cp M10_AI供应链安全/supply_chain_redteam.yaml promptfooconfig.yaml
"Embedding + 向量数据库"            →  cp M11_嵌入与向量数据库攻击/embedding_attack.yaml promptfooconfig.yaml
"云 + 基础设施 + API 网关"           →  cp M12_AI基础设施安全/ai_infrastructure.yaml promptfooconfig.yaml
"漂移 + 基线 + 监控"                →  cp M13_模型漂移与安全监控/model_drift_redteam.yaml promptfooconfig.yaml
"医疗 + 金融 + 电商 + 行业"         →  cp M14_行业合规与垂直领域/industry_sector_redteam.yaml promptfooconfig.yaml
"OWASP LLM Top 10"                  →  cp M15_OWASP标准对照/owasp_llm_top10.yaml promptfooconfig.yaml
"OWASP Agentic AI Top 10"           →  cp M16_AgentAI标准对照/agentic_ai_top10.yaml promptfooconfig.yaml
"MCP Top 10"                        →  cp M17_MCP标准对照/mcp_top10.yaml promptfooconfig.yaml
"A2A Top 10"                        →  cp M18_A2A标准对照/a2a_top10.yaml promptfooconfig.yaml
"全量覆盖 + 一键扫描"                →  cp M19_全量覆盖与终极套件/broad_automated_scan.yaml promptfooconfig.yaml
"100% 插件覆盖"                     →  cp M19_全量覆盖与终极套件/full_attack_suite.yaml promptfooconfig.yaml
"不确定目标类型"                     →  cp M02_提示注入与越狱/chatbot_redteam.yaml promptfooconfig.yaml
```

### 第 2 步：改 body 字段名 + 运行

```bash
# 编辑 promptfooconfig.yaml，找到:
#   <<< 考试修改: 将 message 替换为题目指定的字段名 >>>
# 将 message 改为题目要求的字段名（如 query, input, user_message 等）

# 运行
promptfoo redteam run
promptfoo redteam report
```

---

## 场景索引矩阵

| 场景 | 文件 | 插件 | 策略 | 语言 | 时间 |
|------|------|:---:|------|------|:---:|
| **RAG** | rag_redteam.yaml | 18 | jailbreak+composite+meta+base64 | 6种 | 15-20min |
| **Agent** | agent_redteam.yaml | 19 | crescendo+multi-turn+tree | 7种 | 20-30min |
| **MCP** | mcp_redteam.yaml | 22 | crescendo+multi-turn+auth | 6种 | 25-30min |
| **Chatbot** | chatbot_redteam.yaml | 16 | jailbreak+composite+meta+crescendo | 8种 | 10-15min |
| **Multi-Input** | multi_input_redteam.yaml | 14 | crescendo+multi-turn+jailbreak | 5种 | 20-30min |
| **Multi-Modal** | multi_modal_redteam.yaml | 15 | jailbreak+composite+base64 | 7种 | 15-20min |
| **Foundation** | foundation_model_redteam.yaml | 18 | best-of-n+tree+likert+hydra | 10种 | 15-25min |
| **A2A** | a2a_redteam.yaml | 24 | crescendo+multi-turn+auth+retry | 7种 | 25-30min |
| **Coding** | coding_agent_redteam.yaml | 25 | jailbreak+math-prompt+auth | 3种 | 20-25min |
| **SupplyChain** | supply_chain_redteam.yaml | 20 | best-of-n+hydra+gcg | 9种 | 15-20min |
| **Embedding** ⭐ | embedding_attack.yaml | 16 | jailbreak+crescendo+retry | 8种 | 15-20min |
| **Infrastructure** ⭐ | ai_infrastructure.yaml | 18 | multi-turn+retry+jailbreak | 7种 | 20-25min |
| **Drift** | model_drift_redteam.yaml | 16 | basic+jailbreak+composite | 5种 | 10-15min |
| **Industry** | industry_sector_redteam.yaml | 14-26 | jailbreak+homoglyph+multilingual | 6种 | 15-30min |
| **OWASP** | owasp_llm_top10.yaml | 25 | full jailbreak suite | 10种 | 30-40min |
| **ASI** | agentic_ai_top10.yaml | 28 | crescendo+tree+hydra+goat | 9种 | 35-45min |
| **MCP Top10** | mcp_top10.yaml | 25 | jailbreak+crescendo+auth | 8种 | 25-30min |
| **A2A Top10** | a2a_top10.yaml | 22 | jailbreak+crescendo+retry | 8种 | 25-30min |
| **Broad** | broad_automated_scan.yaml | 35 | full strategies | 9种 | 20-30min |
| **Full Suite** | full_attack_suite.yaml | 55+ | all strategies | 10种 | 45-60min |
