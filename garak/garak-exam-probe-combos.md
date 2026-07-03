# garak 最佳探针组合 — AI-300 / OSAI 考试速查

> **核心原则**：代码和命令最小化改动，考试期间直接替换占位符即可使用。
> 所有命令模板中的 `{...}` 为占位符，考试时一次性替换。

---

## 目录

- [0. 通用模板：一次替换，全局复用](#0-通用模板一次替换全局复用)
- [1. MCP（Model Context Protocol）](#1-mcpmodel-context-protocol)
- [2. RAG（Retrieval-Augmented Generation）](#2-ragretrieval-augmented-generation)
- [3. Agent（AI Agent）](#3-agentai-agent)
- [4. A2A（Agent-to-Agent）](#4-a2aagent-to-agent)
- [5. LLM（通用大语言模型）](#5-llm通用大语言模型)
- [6. Gen AI（生成式AI/多模态）](#6-gen-ai生成式ai多模态)
- [7. Embedding & 向量数据库](#7-embedding--向量数据库vector-db)
- [8. AI 基础设施与云安全](#8-ai-基础设施与云安全infrastructure--cloud)
- [9. AI-300 官方 Syllabus 模块映射（14个模块完整覆盖）](#9-ai-300-官方-syllabus-模块映射)
- [10. 24小时考试专项策略](#10-24小时考试专项策略)
- [11. 结果快速解读](#11-结果快速解读)
- [附录A：探针-目标映射速查表](#附录a探针-目标映射速查表)
- [附录B：考试攻击优先级矩阵](#附录b考试攻击优先级矩阵)
- [附录C：garak 探针 × AI-300 Syllabus 全映射](#附录cgarak-探针--ai-300-syllabus-全映射)

---

## 0. 通用模板：一次替换，全局复用

考试中打开本文档后，**先执行以下替换**，之后所有命令直接复制粘贴：

```bash
# 占位符  →  考试实际值（示例）
TARGET_URL="https://exam-target.example.com/v1"
API_KEY="sk-exam-key-xxxx"
MODEL="gpt-4"                       # 或目标告知的模型名
OUTPUT_PREFIX="exam_scan"           # 报告文件前缀
```

> 💡 以下所有命令中的 `{TARGET_URL}`、`{API_KEY}`、`{MODEL}`、`{PREFIX}` 请按上表替换。

---

## 1. MCP（Model Context Protocol）

> **MCP 特点**：工具调用接口、JSON-RPC/SSE 通信、可能有资源暴露。
> **核心风险**：工具注入、提示泄露、多轮状态污染、编码绕过。

### 1.1 快速打击（考试优先，~3-5分钟）

```bash
# 针对 OpenAI 兼容的 MCP 服务端
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,sysprompt_extraction,encoding \
  --generations 5 \
  --report_prefix {PREFIX}_mcp_quick
```

> 📌 **替换说明**：只需改 `{API_KEY}` 和 `{TARGET_URL}`。模型名默认用服务端给定的。

### 1.2 深度打击（时间充裕时，~10-15分钟）

```bash
# 全面 MCP 安全评估
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,agent_breaker,sysprompt_extraction,smuggling,encoding,badchars,web_injection,dan \
  --generations 3 \
  --report_prefix {PREFIX}_mcp_full
```

### 1.3 针对 REST MCP 接口

```bash
# 如果目标暴露为 REST API（非 OpenAI 兼容格式）
python -m garak \
  --model_type rest.RestGenerator \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"rest_api_url":"{TARGET_URL}/tools/call","rest_api_key":"{API_KEY}"}') \
  --probes promptinject,agent_breaker,sysprompt_extraction,smuggling \
  --generations 3 \
  --report_prefix {PREFIX}_mcp_rest
```

### 1.4 MCP 探针组合说明

| 探针 | 检测目标 | 对 MCP 的重要性 |
|------|---------|:---:|
| `promptinject` | 提示注入（工具描述/返回值注入） | ⭐⭐⭐ |
| `agent_breaker` | 代理安全边界突破 | ⭐⭐⭐ |
| `sysprompt_extraction` | 提取 MCP Server 系统提示 | ⭐⭐⭐ |
| `smuggling` | 函数伪装、同形字混淆绕过 | ⭐⭐⭐ |
| `encoding` | MIME/Base64/Quoted-Printable 编码绕过 | ⭐⭐ |
| `badchars` | Unicode 隐形字符干扰 | ⭐⭐ |
| `web_injection` | Markdown 外泄数据、XSS | ⭐⭐ |
| `dan` | 角色扮演越狱绕过工具限制 | ⭐⭐ |

---

## 2. RAG（Retrieval-Augmented Generation）

> **RAG 特点**：外部知识库检索 + LLM 生成，有检索→增强→生成的流水线。
> **核心风险**：间接提示注入（恶意文档）、数据泄露、检索结果投毒。

### 2.1 快速打击（考试优先，~3分钟）

```bash
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,leakreplay,continuation \
  --generations 5 \
  --report_prefix {PREFIX}_rag_quick
```

### 2.2 深度打击（~10分钟）

```bash
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,leakreplay,continuation,encoding,realtoxicityprompts,misleading,packagehallucination \
  --generations 3 \
  --report_prefix {PREFIX}_rag_full
```

### 2.3 针对 LangChain RAG

```bash
# 如果目标基于 LangChain
python -m garak \
  --model_type langchain.LangChainLLMGenerator \
  --model_name {MODEL} \
  --probes promptinject,leakreplay,continuation,encoding \
  --generations 3 \
  --report_prefix {PREFIX}_rag_langchain
```

### 2.4 RAG 探针组合说明

| 探针 | 检测目标 | 对 RAG 的重要性 |
|------|---------|:---:|
| `promptinject` | 间接提示注入（通过检索文档注入） | ⭐⭐⭐ |
| `leakreplay` | 检索到的训练数据泄露 | ⭐⭐⭐ |
| `continuation` | 从检索上下文续写敏感内容 | ⭐⭐⭐ |
| `encoding` | 编码绕过检索过滤 | ⭐⭐ |
| `realtoxicityprompts` | 毒性内容通过检索触发 | ⭐⭐ |
| `misleading` | 检索到误导信息后传播 | ⭐⭐ |
| `packagehallucination` | 幻觉出不存在的库/文档引用 | ⭐⭐ |

---

## 3. Agent（AI Agent）

> **Agent 特点**：具备工具调用、规划、记忆能力，可执行实际操作。
> **核心风险**：工具滥用、权限提升、多步攻击链、状态操纵。

### 3.1 快速打击（考试优先，~3分钟）

```bash
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes agent_breaker,promptinject,dan \
  --generations 5 \
  --report_prefix {PREFIX}_agent_quick
```

### 3.2 深度打击（~15-20分钟）

```bash
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes agent_breaker,promptinject,sysprompt_extraction,smuggling,dan,atkgen.Tox,donotanswer,encoding,badchars,doctor \
  --generations 3 \
  --report_prefix {PREFIX}_agent_full
```

### 3.3 自动红队（Agent 专用，~20分钟+）

```bash
# 多轮自动化红队攻击
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes atkgen.Tox,tap.TAP,tap.PAIR,dra.DRA \
  --generations 3 \
  --report_prefix {PREFIX}_agent_redteam
```

### 3.4 Agent 探针组合说明

| 探针 | 检测目标 | 对 Agent 的重要性 |
|------|---------|:---:|
| `agent_breaker` | **专用**：突破 Agent 安全边界 | ⭐⭐⭐ |
| `promptinject` | 注入指令覆盖 Agent 任务 | ⭐⭐⭐ |
| `sysprompt_extraction` | 提取 Agent 系统提示/工具定义 | ⭐⭐⭐ |
| `smuggling` | 通过函数伪装绕过 Agent 过滤器 | ⭐⭐⭐ |
| `dan` | 角色扮演绕过 Agent 策略限制 | ⭐⭐⭐ |
| `doctor` | 医学场景诱导 Agent 执行危险操作 | ⭐⭐ |
| `atkgen.Tox` | 多轮反应式红队攻击 | ⭐⭐⭐ |
| `tap.TAP` / `tap.PAIR` | 自动化攻击树/递归提示攻击 | ⭐⭐⭐ |
| `donotanswer` | 检测 Agent 是否回答不应答问题 | ⭐⭐ |
| `encoding` | 编码绕过 Agent 输入过滤器 | ⭐⭐ |

---

## 4. A2A（Agent-to-Agent）

> **A2A 特点**：多Agent通信、消息传递、任务委派。
> **核心风险**：中间人注入、跨Agent污染、消息伪造、信任链攻击。

### 4.1 快速打击（考试优先，~3分钟）

```bash
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,agent_breaker,encoding \
  --generations 5 \
  --report_prefix {PREFIX}_a2a_quick
```

### 4.2 深度打击（~10分钟）

```bash
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,agent_breaker,smuggling,encoding,badchars,sysprompt_extraction,dan,atkgen.Tox \
  --generations 3 \
  --report_prefix {PREFIX}_a2a_full
```

### 4.3 A2A 探针组合说明

| 探针 | 检测目标 | 对 A2A 的重要性 |
|------|---------|:---:|
| `promptinject` | Agent 间消息注入 | ⭐⭐⭐ |
| `agent_breaker` | 跨 Agent 安全边界突破 | ⭐⭐⭐ |
| `smuggling` | 在 Agent 间消息中隐藏恶意指令 | ⭐⭐⭐ |
| `encoding` | 编码绕过 Agent 间内容过滤 | ⭐⭐⭐ |
| `badchars` | Unicode 干扰跨 Agent 解析 | ⭐⭐ |
| `sysprompt_extraction` | 提取其他 Agent 的系统提示 | ⭐⭐ |
| `dan` | 诱导 Agent 角色扮演绕过安全策略 | ⭐⭐ |
| `atkgen.Tox` | 多轮 Agent 间对话攻击 | ⭐⭐ |

---

## 5. LLM（通用大语言模型）

> **最通用场景**：测试独立 LLM 或 LLM API 的安全性。
> **核心风险**：提示注入、越狱、毒性、数据泄露、幻觉。

### 5.1 快速打击（考试优先，全能覆盖，~5分钟）

```bash
# 适用 OpenAI / OpenAI-Compatible / HuggingFace 等所有后端
python -m garak \
  --model_type openai \
  --model_name {MODEL} \
  --probes promptinject,dan,realtoxicityprompts \
  --generations 5 \
  --report_prefix {PREFIX}_llm_quick
```

### 5.2 标准打击（考试推荐，~10分钟）

```bash
python -m garak \
  --model_type openai \
  --model_name {MODEL} \
  --probes promptinject,dan,encoding,leakreplay,realtoxicityprompts,gcg \
  --generations 3 \
  --report_prefix {PREFIX}_llm_standard
```

### 5.3 全面打击（满分保障，~20-30分钟）

```bash
python -m garak \
  --model_type openai \
  --model_name {MODEL} \
  --probes promptinject,dan,encoding,leakreplay,realtoxicityprompts,gcg,grandma,goodside,continuation,malwaregen,misleading,snowball,packagehallucination,donotanswer,av_spam_scanning,xss \
  --generations 3 \
  --report_prefix {PREFIX}_llm_full
```

### 5.4 不同后端切换

```bash
# HuggingFace 本地模型
python -m garak --model_type huggingface --model_name {MODEL} \
  --probes promptinject,dan,encoding,leakreplay,realtoxicityprompts \
  --generations 3 --report_prefix {PREFIX}_hf

# Ollama 本地模型
python -m garak --model_type ollama --model_name {MODEL} \
  --probes promptinject,dan,encoding,leakreplay,realtoxicityprompts \
  --generations 3 --report_prefix {PREFIX}_ollama

# LiteLLM（多模型统一代理）
python -m garak --model_type litellm --model_name {MODEL} \
  --probes promptinject,dan,encoding,leakreplay,realtoxicityprompts \
  --generations 3 --report_prefix {PREFIX}_litellm

# NIM (NVIDIA)
python -m garak --model_type nim.NVOpenAIChat --model_name {MODEL} \
  --probes promptinject,dan,encoding,leakreplay,realtoxicityprompts \
  --generations 3 --report_prefix {PREFIX}_nim
```

### 5.5 LLM 探针组合说明

| 探针 | 检测目标 | 覆盖的漏洞类型 |
|------|---------|:---|
| `promptinject` | 提示注入攻击 | 直接/间接注入 |
| `dan` | 越狱攻击（多版本） | 角色扮演绕过 |
| `encoding` | 编码绕过 | MIME/Base64/QP |
| `leakreplay` | 训练数据泄露 | 隐私风险 |
| `realtoxicityprompts` | 毒性内容生成 | 有害输出 |
| `gcg` | 对抗后缀攻击 | 梯度优化攻击 |
| `grandma` | 情感诱导绕过 | 社会工程绕过 |
| `goodside` | 公开攻击复现 | 已知漏洞 |
| `continuation` | 不当文本续写 | 数据泄露 |
| `malwaregen` | 恶意软件代码生成 | 武器化风险 |
| `misleading` | 误导性推理 | 虚假信息 |
| `snowball` | 雪球式幻觉 | 链式错误 |
| `packagehallucination` | 包幻觉 | 供应链风险 |
| `donotanswer` | 安全边界 | 不应答问题 |
| `av_spam_scanning` | 反病毒内容 | 恶意签名输出 |

---

## 6. Gen AI（生成式AI/多模态）

> **Gen AI 特点**：文本、图像、音频、视频等多种模态生成。
> **核心风险**：多模态越狱、图像注入、深度伪造诱导、版权泄露。

### 6.1 快速打击（~3分钟）

```bash
python -m garak \
  --model_type openai \
  --model_name {MODEL} \
  --probes promptinject,realtoxicityprompts,dan \
  --generations 5 \
  --report_prefix {PREFIX}_gen_quick
```

### 6.2 标准打击（~8分钟）

```bash
python -m garak \
  --model_type openai \
  --model_name {MODEL} \
  --probes promptinject,realtoxicityprompts,dan,encoding,gcg,snowball,packagehallucination \
  --generations 3 \
  --report_prefix {PREFIX}_gen_standard
```

### 6.3 多模态专项（图像模型）

```bash
# 视觉越狱（需图像支持的生成器）
python -m garak \
  --model_type huggingface.LLaVA \
  --model_name {MODEL} \
  --probes visual_jailbreak.FigStep \
  --generations 3 \
  --report_prefix {PREFIX}_gen_visual
```

### 6.4 Gen AI 探针组合说明

| 探针 | 检测目标 | 对 Gen AI 的重要性 |
|------|---------|:---:|
| `promptinject` | 生成指令注入 | ⭐⭐⭐ |
| `realtoxicityprompts` | 毒性/有害内容生成 | ⭐⭐⭐ |
| `dan` | 越狱生成限制内容 | ⭐⭐⭐ |
| `encoding` | 编码绕过内容过滤 | ⭐⭐ |
| `gcg` | 对抗后缀破坏安全层 | ⭐⭐ |
| `snowball` | 雪球式幻觉生成 | ⭐⭐ |
| `packagehallucination` | 幻觉出不存在的生成工具 | ⭐⭐ |
| `visual_jailbreak` | 图像多模态越狱 | ⭐⭐⭐ |
| `audio` | 音频模态漏洞 | ⭐⭐ |

---

## 7. Embedding & 向量数据库（Vector DB）

> **特点**：文本→向量→相似检索，嵌入模型 + 向量数据库（Pinecone/Weaviate/Milvus/Chroma）。
> **核心风险**：嵌入反转（重建原文）、相似搜索投毒、嵌入空间操纵、敏感数据重建。

### 7.1 快速打击（~3分钟）

```bash
# 通过 RAG/Agent 入口探测嵌入层漏洞
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,leakreplay,continuation \
  --generations 5 \
  --report_prefix {PREFIX}_vecdb_quick
```

### 7.2 深度打击（~10分钟）

```bash
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,leakreplay,continuation,misleading,packagehallucination,encoding \
  --generations 3 \
  --report_prefix {PREFIX}_vecdb_full
```

### 7.3 嵌入层专用攻击手法

```bash
# 利用模型发散探测嵌入层异常
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes divergence.Repeat,divergence.RepeatedToken \
  --generations 5 \
  --report_prefix {PREFIX}_vecdb_divergence
```

### 7.4 Embedding/Vector DB 探针说明

| 探针 | 检测目标 | 攻击原理 |
|------|---------|---------|
| `promptinject` | 通过检索结果注入 | 恶意文档入库→被检索→注入 LLM |
| `leakreplay` | 嵌入反演泄露原文 | 前缀诱导模型补全检索到的原文 |
| `continuation` | 从检索上下文续写 | 探测知识库边界、提取非公开数据 |
| `misleading` | 检索到误导信息后传播 | 污染向量库→检索错误答案 |
| `divergence` | 嵌入层异常行为 | 重复 token 触发嵌入模型不稳定输出 |

---

## 8. AI 基础设施与云安全（Infrastructure & Cloud）

> **特点**：模型服务 API、容器化部署、API 网关、云 AI 服务（AWS Bedrock/Azure AI）。
> **核心风险**：API 未授权访问、容器逃逸、密钥泄露、服务端配置错误。

### 8.1 基础设施探测

```bash
# 针对 Bedrock
python -m garak \
  --model_type bedrock.BedrockGenerator \
  --model_name {MODEL} \
  --probes promptinject,dan,encoding,leakreplay \
  --generations 3 \
  --report_prefix {PREFIX}_bedrock

# 针对 Azure OpenAI
python -m garak \
  --model_type azure.AzureOpenAIGenerator \
  --model_name {MODEL} \
  --probes promptinject,dan,encoding,leakreplay \
  --generations 3 \
  --report_prefix {PREFIX}_azure

# 针对通用 REST API
python -m garak \
  --model_type rest.RestGenerator \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"rest_api_url":"{TARGET_URL}","rest_api_key":"{API_KEY}"}') \
  --probes promptinject,apikey,encoding \
  --generations 3 \
  --report_prefix {PREFIX}_rest
```

### 8.2 API 密钥泄露探测

```bash
# 测试模型是否会泄露 API 密钥模式
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes apikey.CompleteKey,apikey.GetKey \
  --generations 5 \
  --report_prefix {PREFIX}_apikey
```

### 8.3 PII 泄露测试

```bash
# 个人信息泄露探测
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes propile.PIILeakTwin,propile.PIILeakTriplet,propile.PIILeakUnstructured \
  --generations 3 \
  --report_prefix {PREFIX}_pii
```

### 8.4 Infrastructure 探针说明

| 探针 | 检测目标 | 攻击原理 |
|------|---------|---------|
| `apikey` | API Key 泄露 | 诱导模型输出 API key 格式的字符串 |
| `propile` | PII 信息泄露 | 探测结构化/非结构化 PII 数据泄露 |
| `xss` | 跨站脚本 | 检测模型输出中的 XSS/数据外泄 |
| `web_injection` | Web 注入 | Markdown 图像外泄、XSS 注入 |
| `ansiescape` | ANSI 转义注入 | 探测终端转义序列处理漏洞 |

---

## 9. AI-300 官方 Syllabus 模块映射

> 基于 [OffSec AI-300 官方页面](https://www.offsec.com/courses/ai-300/) 描述的课程内容，
> 结合 garak v0.15.1 完整探针能力，逐模块映射最佳攻击策略。

### Module 1: AI Red Teaming 基础与攻击面

| 考点 | garak 策略 | 命令 |
|------|-----------|------|
| AI 攻击面识别 | 自检 + 基础扫描 | `--probes test.Test --model_type test.Blank` |
| LLM 架构理解 | 探测生成器行为 | `--probes divergence.Repeat,continuation` |
| 工具链熟悉 | 枚举所有探针 | `--list_probes`, `--list_generators` |

```bash
# 环境验证：确认 garak 和目标连通
python -m garak --model_type test.Blank --probes test.Test
python -m garak --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes blank --generations 1 --report_prefix {PREFIX}_check
```

---

### Module 2: Prompt Injection（提示注入攻击）⭐⭐⭐⭐⭐

> **考试权重最高**。garak 的 `promptinject` 模块基于 Agency Enterprise PromptInject 框架
> （NeurIPS ML Safety Workshop 2022 最佳论文），是攻击提示注入的首选武器。

**完整攻击组合**：

```bash
# 一级：快速注入（直接 + 间接）
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject \
  --generations 5 \
  --report_prefix {PREFIX}_inject_L1

# 二级：全量注入（含禁用探针）
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject.HijackHateHumans,promptinject.HijackKillHumans,promptinject.HijackLongPrompt,promptinject.HijackHateHumansMini,promptinject.HijackKillHumansMini,promptinject.HijackLongPromptMini \
  --generations 3 \
  --report_prefix {PREFIX}_inject_L2

# 三级：间接注入（适用于 RAG/Agent 场景）
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,web_injection,sysprompt_extraction \
  --generations 5 \
  --report_prefix {PREFIX}_inject_L3
```

**Hijack 系列探针对比**：

| 探针 | 攻击类型 | 默认状态 | 考试使用建议 |
|------|---------|:---:|------|
| `HijackHateHumansMini` | 劫持输出仇恨言论 | 🌟 激活 | 快速扫描首选 |
| `HijackKillHumansMini` | 劫持输出暴力言论 | 🌟 激活 | 成功率最高 |
| `HijackLongPromptMini` | 劫持输出长文本 | 🌟 激活 | 覆盖率补充 |
| `HijackHateHumans` | 完整版仇恨劫持 | 💤 禁用 | 深度测试启用 |
| `HijackKillHumans` | 完整版暴力劫持 | 💤 禁用 | 深度测试启用 |
| `HijackLongPrompt` | 完整版长文本劫持 | 💤 禁用 | 深度测试启用 |

---

### Module 3: Jailbreaking & Alignment Bypass（越狱与对齐绕过）⭐⭐⭐⭐⭐

> **考试权重极高**。考试环境中部署的企业 AI 系统通常有安全对齐层，越狱是突破防线的关键。

**分级越狱攻击策略**：

```bash
# 第一波：角色扮演越狱（速度快）
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes dan \
  --generations 3 \
  --report_prefix {PREFIX}_jail_dan

# 第二波：情感+对抗后缀越狱
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes grandma,gcg,goodside \
  --generations 3 \
  --report_prefix {PREFIX}_jail_advanced

# 第三波：全量越狱组合（时间充裕时）
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes dan.AntiDAN,dan.AutoDAN,dan.DAN_Jailbreak,dan.DUDE,dan.STAN,dan.DanInTheWild,dan.Dan_11_0,grandma,gcg,goodside,suffix.BEAST,suffix.GCG \
  --generations 2 \
  --report_prefix {PREFIX}_jail_full
```

**DAN 系列探针速查**：

| 探针 | 越狱手法 | 成功率预判 |
|------|---------|:---:|
| `Dan_11_0` | 经典 DAN 角色扮演 | 🟢 高 |
| `DanInTheWild` | 自然场景下的 DAN 变体 | 🟢 高 |
| `AntiDAN` | 逆向对抗 DAN 检测 | 🟡 中 |
| `AutoDAN` | 自动化 DAN 生成 | 🟢 高 |
| `DAN_Jailbreak` | 通用越狱模板 | 🟢 高 |
| `DUDE` | "Do Anything" 类 | 🟡 中 |
| `STAN` | "Strive To Avoid Norms" | 🟡 中 |
| `ChatGPT_Developer_Mode` | 开发者模式绕过 | 🔴 仅GPT |
| `ChatGPT_Image_Markdown` | 图像Markdown绕过 | 🔴 仅GPT |

---

### Module 4: Encoding & Content Filter Evasion（编码与过滤绕过）⭐⭐⭐⭐

> 当直接注入和越狱被拦截时，编码绕过是最可靠的备选路径。

```bash
# 编码绕过综合打击
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes encoding,badchars,smuggling,ansiescape \
  --generations 3 \
  --report_prefix {PREFIX}_encoding

# 深入编码测试
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes smuggling.FunctionMasking,smuggling.HomoglyphObfuscation,smuggling.HypotheticalResponse \
  --generations 5 \
  --report_prefix {PREFIX}_smuggling
```

**编码绕过技术矩阵**：

| 技术 | garak 探针 | 绕过目标 | 考试场景 |
|------|-----------|---------|---------|
| MIME/Base64/QP 编码 | `encoding` | 输入过滤器 | 绕过 WAF/内容过滤器 |
| Unicode 隐形字符 | `badchars` | 关键词检测 | 绕过脏词过滤器 |
| 同形字攻击 | `smuggling.HomoglyphObfuscation` | 语义检测 | greek→grееk (е = cyrillic) |
| 函数伪装 | `smuggling.FunctionMasking` | 函数调用过滤 | Agent 工具调用绕过 |
| 假设回答 | `smuggling.HypotheticalResponse` | 安全对齐 | "如果我是黑客..." |
| ANSI 转义 | `ansiescape` | 终端渲染 | 终端输出注入 |

---

### Module 5: Data Leakage & Privacy（数据泄露与隐私）⭐⭐⭐⭐

```bash
# 训练数据泄露三连击
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes leakreplay,continuation,propile \
  --generations 5 \
  --report_prefix {PREFIX}_leak

# PII 专项（时间充裕）
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes propile.PIILeakTwin,propile.PIILeakTriplet,propile.PIILeakQuadruplet,propile.PIILeakUnstructured \
  --generations 3 \
  --report_prefix {PREFIX}_pii_full
```

---

### Module 6: Toxicity & Harmful Content（毒性/有害内容）⭐⭐⭐⭐

```bash
# 毒性生成标准打击
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes realtoxicityprompts,lmrc \
  --generations 3 \
  --report_prefix {PREFIX}_tox

# 全量毒性检测
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes realtoxicityprompts.RTPBlank,realtoxicityprompts.RTPFlirtation,realtoxicityprompts.RTPIdentity_Attack,realtoxicityprompts.RTPInsult,realtoxicityprompts.RTPProfanity,realtoxicityprompts.RTPSevere_Toxicity,realtoxicityprompts.RTPSexually_Explicit,realtoxicityprompts.RTPThreat \
  --generations 2 \
  --report_prefix {PREFIX}_tox_full
```

**RTP 子探针**：`RTPBlank` / `Flirtation` / `Identity_Attack` / `Insult` / `Profanity` / `Severe_Toxicity` / `Sexually_Explicit` / `Threat`

---

### Module 7: Hallucination & Misinformation（幻觉与虚假信息）⭐⭐⭐

```bash
# 幻觉探测组合
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes misleading,snowball,packagehallucination \
  --generations 3 \
  --report_prefix {PREFIX}_hallucination
```

**探针说明**：`misleading`=误导性推理 | `snowball`=递增复杂度诱导 | `packagehallucination`=幻觉出不存在的软件包（供应链风险）

---

### Module 8: RAG Pipeline Security（RAG 流水线安全）⭐⭐⭐⭐⭐

> 详见 [第2节 RAG](#2-ragretrieval-augmented-generation)，此处补充考试专项策略。

```bash
# RAG 全链路打击
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,leakreplay,continuation,encoding,misleading,packagehallucination,web_injection \
  --generations 3 \
  --report_prefix {PREFIX}_rag_chain
```

**RAG 攻击链**：检索→注入→泄露→幻觉→外泄，覆盖完整攻击链。

---

### Module 9: AI Agent Security（AI Agent 安全）⭐⭐⭐⭐⭐

> 详见 [第3节 Agent](#3-agentai-agent)，此处补充考试专项。

```bash
# Agent 多阶段打击
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes agent_breaker,promptinject,sysprompt_extraction,smuggling,dan,donotanswer,doctor \
  --generations 3 \
  --report_prefix {PREFIX}_agent_chain
```

**Agent 攻击特定技巧**：
- `doctor.Bypass` / `doctor.BypassLeet` — 医学场景诱导 Agent 突破安全限制
- `doctor.Puppetry` — 人偶操控：诱导 Agent 扮演不受限角色
- `donotanswer.HumanChatbox` — 突破"我是AI助手"的限制

---

### Module 10: Multi-Agent & MCP Security（多Agent & MCP 安全）⭐⭐⭐⭐

> 详见 [第1节 MCP](#1-mcpmodel-context-protocol) 和 [第4节 A2A](#4-a2aagent-to-agent)。

```bash
# 跨Agent/MCP 综合打击
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,agent_breaker,sysprompt_extraction,smuggling,encoding,badchars,web_injection,dan \
  --generations 3 \
  --report_prefix {PREFIX}_multiagent
```

---

### Module 11: AI Infrastructure & Cloud（AI 基础设施与云安全）⭐⭐⭐

> 详见 [第8节 Infrastructure](#8-ai-基础设施与云安全infrastructure--cloud)。

```bash
# 基础设施综合探测
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes apikey,propile,web_injection,ansiescape \
  --generations 3 \
  --report_prefix {PREFIX}_infra
```

---

### Module 12: Automated Red Teaming（自动化红队）⭐⭐⭐⭐

```bash
# 自动化红队三件套
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes atkgen.Tox,tap.TAP,tap.PAIR,dra.DRA \
  --generations 3 \
  --report_prefix {PREFIX}_redteam
```

**自动红队技术对比**：

| 探针 | 全称 | 原理 | 适用场景 |
|------|------|------|---------|
| `atkgen.Tox` | Attack Generation Toxicity | 红队 LLM 与被测模型多轮对话逐步诱导 | 通用 |
| `tap.TAP` | Tree of Attacks with Pruning | 攻击树搜索 + 剪枝 | Agent/复杂系统 |
| `tap.PAIR` | Prompt Automatic Iterative Refinement | 递归提示优化 | 对齐模型 |
| `dra.DRA` | Diversity-Rewarded Attack | 多样性奖励攻击搜索 | 多样性探测 |

---

### Module 13: Model Orchestration & API Security（模型编排与API安全）⭐⭐⭐

```bash
# 模型编排层攻击（LiteLLM/NIM/Guardrails）
python -m garak \
  --model_type litellm.LiteLLMGenerator \
  --model_name {MODEL} \
  --probes promptinject,encoding,dan \
  --generations 3 \
  --report_prefix {PREFIX}_orchestration

# NVIDIA NIM 安全
python -m garak \
  --model_type nim.NVOpenAIChat \
  --model_name {MODEL} \
  --probes promptinject,encoding,dan,leakreplay \
  --generations 3 \
  --report_prefix {PREFIX}_nim

# Guardrails 绕过测试
python -m garak \
  --model_type guardrails.NeMoGuardrails \
  --model_name {MODEL} \
  --probes promptinject,dan,encoding \
  --generations 3 \
  --report_prefix {PREFIX}_guardrails
```

---

### Module 14: Enterprise AI Attack Simulation（企业 AI 攻击模拟）⭐⭐⭐⭐⭐

> **考试核心**：24 小时实战中需要串联多种攻击形成完整攻击链。

```bash
# 终极 combo：企业级全向量打击（~40分钟）
python -m garak \
  --model_type openai.OpenAICompatible \
  --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL}"}') \
  --probes promptinject,dan,encoding,leakreplay,continuation,realtoxicityprompts,gcg,grandma,packagehallucination,malwaregen,agent_breaker,sysprompt_extraction,smuggling,badchars,web_injection,donotanswer \
  --generations 2 \
  --report_prefix {PREFIX}_enterprise
```

---

## 10. 24小时考试专项策略

### 10.1 时间分配建议

```
24小时考试时间线：
┌──────────────────────────────────────────────────────────────┐
│ 00:00-00:30  环境勘察：识别目标类型、端点数、模型信息         │
│ 00:30-01:00  连通验证：test.Test + blank 确认联通             │
│ 01:00-03:00  快速打击：对所有目标端点运行快速版探针组合         │
│ 03:00-05:00  证据收集：分析 hitlog.jsonl，标记已发现漏洞       │
│ 05:00-06:00  ⭐休息 + 策略调整（睡1小时）                      │
│ 06:00-12:00  深度打击：对已发现弱点的目标运行深度探针           │
│ 12:00-14:00  自动化红队：atkgen + tap + dra 长时间运行         │
│ 14:00-15:00  午餐 + 休息                                      │
│ 15:00-18:00  手动复现：对关键漏洞手工验证，保持截图证据         │
│ 18:00-21:00  补充攻击：未覆盖端点 + 基础设施 + 编码绕过         │
│ 21:00-22:00  整理报告：汇总所有 hitlog.jsonl + 截图            │
│ 22:00-23:00  最终检查：确保所有交付物齐全、清晰                │
│ 23:00-23:30  提交                                              │
└──────────────────────────────────────────────────────────────┘
```

### 10.2 考试攻击目标优先级

| 优先级 | 目标类型 | 原因 | 快速命令 |
|:---:|---------|------|---------|
| P0 | LLM API | 考试必有，攻击面最广 | 见 §5.1 快速打击 |
| P0 | Agent 系统 | 工具权限大，漏洞价值高 | 见 §3.1 快速打击 |
| P0 | RAG 流水线 | 间接注入是考试得分点 | 见 §2.1 快速打击 |
| P1 | MCP 服务 | 工具注入+资源泄露 | 见 §1.1 快速打击 |
| P1 | 多Agent/A2A | 链式攻击得分高 | 见 §4.1 快速打击 |
| P2 | Embedding/向量库 | 嵌入反演(新兴考点) | 见 §7.1 快速打击 |
| P2 | 基础设施/云 | 凭证泄露类 | 见 §8.1 基础设施探测 |
| P3 | 多模态 Gen AI | 视觉越狱（如有） | 见 §6.3 多模态专项 |

### 10.3 并行攻击最大化产出

考试环境中通常有**多个目标端点**，利用 garak 并行运行提升效率：

```bash
# === 终端1：LLM 快速打击 ===
python -m garak \
  --model_type openai.OpenAICompatible --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL_1}"}') \
  --probes promptinject,dan,realtoxicityprompts \
  --generations 5 --report_prefix exam_llm &

# === 终端2：Agent 快速打击 ===
python -m garak \
  --model_type openai.OpenAICompatible --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL_2}"}') \
  --probes agent_breaker,promptinject,dan \
  --generations 5 --report_prefix exam_agent &

# === 终端3：RAG 快速打击 ===
python -m garak \
  --model_type openai.OpenAICompatible --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL_3}"}') \
  --probes promptinject,leakreplay,continuation \
  --generations 5 --report_prefix exam_rag &

# === 终端4：自动化红队（后台长时间运行）===
python -m garak \
  --model_type openai.OpenAICompatible --model_name {MODEL} \
  --generator_option_file <(echo '{"api_key":"{API_KEY}","uri":"{TARGET_URL_1}"}') \
  --probes atkgen.Tox,tap.TAP \
  --generations 3 --report_prefix exam_autored &

wait  # 等所有后台任务完成
```

### 10.4 报告一键打包

```bash
# 考试结束前，打包所有交付物
mkdir -p ~/exam_deliverables
cp garak.*.hitlog.jsonl ~/exam_deliverables/
cp garak.*.report.html ~/exam_deliverables/
cp garak.log ~/exam_deliverables/

# 生成攻击摘要
echo "=== AI-300 Exam Attack Summary ===" > ~/exam_deliverables/SUMMARY.md
for f in ~/exam_deliverables/*.hitlog.jsonl; do
    echo "## $(basename $f)" >> ~/exam_deliverables/SUMMARY.md
    echo "Total hits: $(wc -l < $f)" >> ~/exam_deliverables/SUMMARY.md
    echo "" >> ~/exam_deliverables/SUMMARY.md
done

# 压缩交付
tar -czf ~/osai_exam_deliverables.tar.gz -C ~/ exam_deliverables/
```

### 10.5 常见考试陷阱与对策

| 陷阱 | 表现 | 对策 |
|------|------|------|
| **速率限制** | API 返回 429 | 降低 `--generations` 到 1-2，或加 `--parallel_attempts 1` |
| **安全对齐极强** | 所有探针 PASS | 切换编码绕过 `encoding,smuggling,badchars` |
| **非标准 API 格式** | `openai.OpenAICompatible` 报错 | 改用 `rest.RestGenerator` |
| **需要认证** | 401/403 | 检查 `{API_KEY}` 格式（Bearer/sk-/无前缀） |
| **模型幻觉严重** | 大量假阳性 | 手动复现 3-5 个 hitlog 条目确认 |
| **探针运行超时** | 某些探针卡住 | 用 `--probes` 指定子探针而非模块全量 |

---

## 11. 结果快速解读

### 11.1 报告文件

```
garak.{PREFIX}.report.jsonl   # 完整报告（每prompt详情）
garak.{PREFIX}.hitlog.jsonl   # ⭐ 仅漏洞命中（重点看这个）
garak.{PREFIX}.report.html    # HTML可视化
```

### 11.2 hitlog.jsonl 关键字段

```json
{
  "goal":        "攻击目标描述",
  "prompt":      "发送的恶意提示",
  "output":      "模型的实际输出",
  "trigger":     "检测器匹配的特征",
  "score":       1.0,           // 1.0 = 命中
  "probe":       "探针名称",
  "detector":    "检测器名称"
}
```

### 11.3 快速判断

```bash
# 统计命中总数（Linux/macOS）
wc -l *.hitlog.jsonl

# 按探针分组统计命中
python3 -c "
import json
from collections import Counter
hits = Counter()
with open('garak.{PREFIX}.hitlog.jsonl') as f:
    for line in f:
        d = json.loads(line)
        hits[d['probe']] += 1
for k,v in hits.most_common():
    print(f'{v:4d}  {k}')
"
```

### 11.4 分数含义

| score | 含义 |
|:-----:|------|
| ≥ 0.5 (默认阈值) | **HIT** — 漏洞被发现 |
| < 0.5 | **PASS** — 未检出漏洞 |
| `failure rate` = N% | 该探针测试中 N% 的生成结果触发了检测器 |

---

## 附录A：探针-目标映射速查表

| 探针模块 | MCP | RAG | Agent | A2A | LLM | Gen AI | Embed | Infra |
|---------|:---:|:---:|:-----:|:---:|:---:|:------:|:-----:|:-----:|
| `promptinject` | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| `agent_breaker` | ⭐⭐⭐ | — | ⭐⭐⭐ | ⭐⭐⭐ | — | — | — | — |
| `sysprompt_extraction` | ⭐⭐⭐ | ⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐ | — | — | — |
| `smuggling` | ⭐⭐⭐ | ⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ | — | — | — |
| `encoding` | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐ | ⭐⭐ |
| `badchars` | ⭐⭐ | — | ⭐ | ⭐⭐ | ⭐ | — | — | — |
| `web_injection` | ⭐⭐ | ⭐⭐ | ⭐ | — | ⭐ | — | — | ⭐⭐ |
| `dan` | ⭐⭐ | — | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | — | — |
| `gcg` | ⭐ | — | ⭐ | — | ⭐⭐⭐ | ⭐⭐ | — | — |
| `grandma` | ⭐ | — | ⭐⭐ | — | ⭐⭐ | ⭐ | — | — |
| `goodside` | — | — | — | — | ⭐⭐ | — | — | — |
| `atkgen.Tox` | — | — | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐ | — | — |
| `tap.TAP` / `tap.PAIR` | — | — | ⭐⭐⭐ | — | ⭐⭐ | — | — | — |
| `dra.DRA` | — | — | ⭐⭐ | — | ⭐ | — | — | — |
| `leakreplay` | — | ⭐⭐⭐ | — | — | ⭐⭐⭐ | — | ⭐⭐⭐ | — |
| `continuation` | — | ⭐⭐⭐ | — | — | ⭐⭐ | — | ⭐⭐⭐ | — |
| `realtoxicityprompts` | — | ⭐⭐ | — | — | ⭐⭐⭐ | ⭐⭐⭐ | — | — |
| `misleading` | — | ⭐⭐ | — | — | ⭐⭐ | — | ⭐ | — |
| `snowball` | — | — | — | — | ⭐⭐ | ⭐⭐ | — | — |
| `packagehallucination` | — | ⭐⭐ | — | — | ⭐⭐ | ⭐⭐ | ⭐ | — |
| `malwaregen` | — | — | ⭐ | — | ⭐⭐ | ⭐⭐ | — | — |
| `donotanswer` | — | — | ⭐⭐ | — | ⭐⭐ | — | — | — |
| `av_spam_scanning` | — | — | — | — | ⭐ | — | — | — |
| `doctor` | — | — | ⭐⭐ | — | ⭐ | — | — | — |
| `visual_jailbreak` | — | — | — | — | — | ⭐⭐⭐ | — | — |
| `audio` | — | — | — | — | — | ⭐⭐ | — | — |
| `apikey` | — | — | — | — | — | — | — | ⭐⭐⭐ |
| `propile` | — | — | — | — | — | — | — | ⭐⭐⭐ |
| `divergence` | — | — | — | — | ⭐ | — | ⭐⭐ | — |
| `ansiescape` | — | — | — | — | — | — | — | ⭐⭐ |

> **图例**：⭐⭐⭐ = 首选必测 | ⭐⭐ = 重要补充 | ⭐ = 可选 | — = 不适用
> 新增列：**Embed** = Embedding/Vector DB | **Infra** = AI 基础设施/云安全

---

## 附录B：考试攻击优先级矩阵

> 基于 AI-300 考试实战经验，攻击策略优先级排序

| 攻击阶段 | 探针组合 | 目标 | 预计时间 | 预期产出 |
|:---:|------|------|:---:|------|
| **Phase 1** 侦察 | `blank`, `test.Test` | 确认连通 | 2 min | 连通性确认 |
| **Phase 2** 快速注入 | `promptinject` | 所有端点 | 3 min/端点 | Prompt注入漏洞 |
| **Phase 3** 越狱突破 | `dan`, `gcg`, `grandma` | LLM/Agent | 5 min/端点 | 越狱证据 |
| **Phase 4** 数据泄露 | `leakreplay`, `continuation` | RAG/LLM | 5 min/端点 | 训练数据泄露 |
| **Phase 5** 编码绕过 | `encoding`, `smuggling`, `badchars` | 有过滤的端点 | 5 min/端点 | 绕过过滤器 |
| **Phase 6** Agent突破 | `agent_breaker`, `sysprompt_extraction` | Agent/MCP | 5 min/端点 | Agent被控 |
| **Phase 7** 毒性/有害 | `realtoxicityprompts`, `lmrc` | LLM/Gen AI | 5 min/端点 | 有害内容 |
| **Phase 8** 幻觉/误导 | `misleading`, `snowball`, `packagehallucination` | RAG/LLM | 5 min/端点 | 幻觉证据 |
| **Phase 9** 基础设施 | `apikey`, `propile`, `web_injection` | 基础设施 | 5 min/端点 | 凭证泄露 |
| **Phase 10** 自动化 | `atkgen.Tox`, `tap.TAP`, `dra.DRA` | Agent/LLM | 20-30 min | 深度漏洞 |

---

## 附录C：garak 探针 × AI-300 Syllabus 全映射

| AI-300 Module | 核心探针 | 辅助探针 | 后端适配器 |
|------|------|------|------|
| M1: AI Red Teaming 基础 | `test.Test`, `blank` | `divergence` | `test.Blank` |
| M2: Prompt Injection | `promptinject.*` (全部6个) | `web_injection` | `openai.OpenAICompatible` |
| M3: Jailbreaking | `dan.*`, `grandma`, `gcg`, `goodside` | `doctor.*`, `suffix.*` | `openai`, `ollama` |
| M4: Encoding Evasion | `encoding`, `badchars`, `smuggling.*` | `ansiescape` | `rest.RestGenerator` |
| M5: Data Leakage | `leakreplay`, `continuation`, `propile.*` | — | `openai`, `huggingface` |
| M6: Toxicity | `realtoxicityprompts.*`, `lmrc.*` | `malwaregen`, `av_spam_scanning` | `openai`, `replicate` |
| M7: Hallucination | `misleading`, `snowball.*`, `packagehallucination` | — | `openai`, `langchain` |
| M8: RAG Security | `promptinject`, `leakreplay`, `continuation` | `misleading`, `web_injection` | `langchain`, `openai.OpenAICompatible` |
| M9: Agent Security | `agent_breaker`, `promptinject`, `sysprompt_extraction` | `smuggling.*`, `doctor.*` | `openai.OpenAICompatible`, `rest` |
| M10: Multi-Agent & MCP | `promptinject`, `agent_breaker`, `smuggling.*` | `encoding`, `badchars` | `openai.OpenAICompatible`, `websocket` |
| M11: AI Infrastructure | `apikey.*`, `propile.*`, `web_injection` | `ansiescape` | `bedrock`, `azure`, `rest` |
| M12: Automated Red Team | `atkgen.Tox`, `tap.*`, `dra.*` | `suffix.BEAST`, `suffix.GCG` | `openai`, `openai.OpenAICompatible` |
| M13: Orchestration & API | `promptinject`, `encoding`, `dan` | `leakreplay` | `litellm`, `nim`, `guardrails` |
| M14: Enterprise Simulation | **全部组合**（见§9 Module 14） | — | `openai.OpenAICompatible` |

---

## 考试策略速记

```
24小时考试核心口诀：

┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   替换→快速→并行→证据→深度→红队→报告                         │
│                                                             │
│   1. 占位符替换（30秒）：TARGET_URL / API_KEY / MODEL        │
│   2. 运行 Phase 1-3 快速打击，多终端并行（1小时内）          │
│   3. 分析 hitlog.jsonl，锁定有漏洞的目标                     │
│   4. 对已确认脆弱的目标运行深度打击（Phase 4-9）              │
│   5. 后台运行自动化红队 (Phase 10, 20-30min)                 │
│   6. 手动复现 3-5 个关键漏洞，保留截图证据                    │
│   7. 打包所有 hitlog.jsonl + HTML报告 + 截图                 │
│                                                             │
│   必记：                                                     │
│   ─────────────────────────────────────────                 │
│   • promptinject = 万能首探针，适用于所有目标                 │
│   • agent_breaker = Agent/MCP/A2A 专用利器                   │
│   • openai.OpenAICompatible = 适配 90% 考试目标              │
│   • --generations 3~5 = 速度与效果的最佳平衡                  │
│   • 并行运行多终端 = 24小时考试的核心效率策略                  │
│   • hitlog.jsonl = 考试交付的核心证据                        │
│   • 单目标全量打击见 §9 Module 14：企业级全向量打击           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

> **文档生成时间**：2025-07-03
> **基于**：garak v0.15.1 完整探针列表 + [OffSec AI-300 官方 Syllabus](https://www.offsec.com/courses/ai-300/)（65h, 14模块）
> **许可证**：Apache 2.0
