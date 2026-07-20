# AI-300 全链路编排文档

> **最后更新**: 2026-07-20 / 版本: v1.1 / 关联模块: pyrit_ai300/pipeline/ + spa_chat/ / 状态: 已完成

## 1. 概述

全链路编排器 (`PipelineOrchestrator`) 实现 AI 红队评估的一键执行：
**凭据检查 → 侦察 → 攻击 → 报告**

### 1.1 核心特性

| 特性 | 说明 |
|------|------|
| 凭据优先复用 | 从 `config/targets/credentials/` 自动发现有效凭据（JWT 过期检查） |
| 凭据自动注入 | Garak（环境变量）/ DeepTeam（请求头）/ PyRIT（api_key） |
| 侦察驱动攻击 | 侦察画像自动驱动 REV-1 载荷过滤 + REV-2 ASR 排序 |
| 结果突出显示 | 每个阶段的关键指标用 Rich 格式清晰展示 |
| 错误隔离 | 单个阶段失败可配置为跳过或终止 |

### 1.2 架构位置

```
CLI (ai300 pipeline)
  └── PipelineOrchestrator
        ├── CredentialManager    → 凭据发现/验证/注入
        ├── ReconEngine          → AIMAP/Garak/DeepTeam 并行侦察
        ├── AI300Engine          → PyRIT 攻击执行
        └── ReportGenerator      → CVSS+ATLAS+Mermaid+ROI 报告
```

## 2. 凭据管理（CredentialManager）

### 2.1 设计原则

1. **域名隔离**：域名 A 只读取 A 的凭据文件，绝不交叉读取
2. **JWT 缓冲**：Token 预留 5 分钟缓冲，临界过期视为已过期
3. **优先复用**：有效凭据直接使用，避免重复登录
4. **自动导出**：认证成功后凭据自动导出到 `credentials/` 目录

### 2.2 凭据格式

凭据文件存储在 `config/targets/credentials/{domain}.txt`，格式为 HTTP Request Headers：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Cookie: SESSIONID=abc123; csrftoken=xyz789
User-Agent: Mozilla/5.0...
```

### 2.3 凭据注入策略

| 目标工具 | 注入方式 | 代码位置 |
|----------|----------|----------|
| Garak | `OPENAI_API_KEY` 环境变量 | `garak/adapter.py` |
| DeepTeam | `base_headers` 请求头 | `deepteam/adapter.py` |
| PyRIT OpenAIChatTarget | `api_key` 构造参数 | `target_builder.py` |
| PyRIT HTTPTarget | `Authorization` 头 | `target_builder.py` |
| PlaywrightTarget | `inject_auth()` 注入 | `playwright_injector.py` |

### 2.4 API

```python
from pyrit_ai300.pipeline import CredentialManager

mgr = CredentialManager()
resolution = mgr.resolve("https://student.syxy.ouchn.cn/#/home")

if resolution.has_credentials:
    # 凭据有效，直接使用
    garak_env = CredentialManager.for_garak(resolution)
    deepteam_headers = CredentialManager.for_deepteam(resolution)
    oai_kwargs = CredentialManager.for_openai_target(resolution)
else:
    # 凭据过期或缺失，需要重新认证
    ...
```

## 3. 全链路编排（PipelineOrchestrator）

### 3.1 执行阶段

| 阶段 | 名称 | 说明 | 可跳过 |
|------|------|------|--------|
| credential | 凭据检查 | 从 credentials/ 发现并验证凭据 | 是 |
| recon | 侦察 | AIMAP/Garak/DeepTeam 并行执行 | 是（`--profile`） |
| attack | 攻击 | PyRIT OWASP 标准攻击 | 是（`--recon-only`） |
| report | 报告 | CVSS+ATLAS+Mermaid+ROI | 是 |

### 3.2 CLI 使用

```bash
# 全链路执行（LLM API 目标）
ai300 pipeline --target-url http://localhost:11434 --scope all

# 全链路执行（SPA 智能助手目标，含认证）
ai300 pipeline --spa-config config/targets/spa_target.yaml --scope llm01

# 指定侦察深度 + HTML 报告
ai300 pipeline --target-url http://target.com --scope all -d deep --format html

# 仅执行侦察阶段
ai300 pipeline --target-url http://target.com --recon-only

# 跳过侦察，直接攻击（使用已有画像）
ai300 pipeline --target-url http://target.com --scope llm01 \
  --profile results/recon/profile.json

# 使用外部评分器
ai300 pipeline --target-url http://target.com --scope all \
  --scorer-url https://open.bigmodel.cn/api/paas/v4 \
  --scorer-key $ZHIPUAI_API_KEY --scorer-model glm-4-flash
```

### 3.3 Python API

```python
from pyrit_ai300.pipeline import PipelineOrchestrator

orchestrator = PipelineOrchestrator()
result = orchestrator.run(
    target_url="https://student.syxy.ouchn.cn/#/home",
    spa_config="config/targets/spa_target.yaml",
    scope="llm01",
    depth="standard",
)

# 查看结果
print(result.summary_table())
print(f"侦察成功: {result.recon_success}")
print(f"攻击成功: {result.attack_success}")
print(f"画像路径: {result.profile_path}")
print(f"报告路径: {result.report_path}")
```

### 3.4 便捷方法

```python
# 仅执行侦察
result = orchestrator.run_recon_only(
    target_url="http://target.com",
    depth="deep",
)

# 仅执行攻击（使用已有画像）
result = orchestrator.run_attack_only(
    target_url="http://target.com",
    scope="all",
    profile_path="results/recon/profile.json",
)
```

## 4. 文件清单

| 文件 | 行数 | 说明 |
|------|------|------|
| `pipeline/credential_manager.py` | 480 | 统一凭据管理器 |
| `pipeline/orchestrator.py` | 580 | 全链路编排器 |
| `pipeline/__init__.py` | 35 | 模块导出 |
| `cli.py` (pipeline 部分) | 120 | CLI 命令定义 + 执行函数 |

## 5. 最佳实践

### 5.1 凭据生命周期

```
首次使用 → 认证流程（SPA 侦察/手动登录）
         → 凭据导出到 credentials/{domain}.txt
         → 后续阶段直接复用（JWT 过期检查）
         → 过期时重新认证
```

### 5.2 侦察→攻击数据流

```
ReconEngine.run()
  → TargetProfile JSON（fingerprint + surfaces + vulnerabilities）
    → AI300Engine._build_target_config()
      → endpoint 覆盖（侦察发现的 LLM API 端点）
      → model 覆盖（侦察识别的模型名）
    → PayloadFilter (REV-1)：基于 surfaces 过滤不相关 OWASP 类别
    → ASRRanker (REV-2)：按目标模型 ASR 降序排序
    → AttackOrchestrator.execute_attack()
```

### 5.3 错误处理策略

| 场景 | 策略 |
|------|------|
| 凭据过期 | 标记为无效，继续执行（无凭据模式） |
| 侦察失败 | 记录错误，跳过攻击阶段（可配置） |
| 攻击失败 | 保存部分结果，生成报告 |
| 报告失败 | 打印错误，返回已有结果 |

## 6. 自适应侦察编排（v1.1 新增）

### 6.1 目标类型自动检测

编排器在侦察阶段开始前自动检测目标类型，选择最优侦察路径：

| 目标类型 | 检测条件 | 侦察路径 |
|----------|----------|----------|
| SPA | `--spa-config` 参数或 URL 含 `#` 片段 | SPA Recon → Garak + DeepTeam |
| API | URL 无 `#` 片段，指向 `/v1/chat/completions` 等端点 | AIMAP → Garak + DeepTeam |

### 6.2 SPA 路径流程

```
SPA 目标
  → CredentialManager 凭据检查/认证
  → SPAChatReconAdapter 全流程侦察
    → 认证（SSO/credentials/manual）
    → DOM 自动检测（选择器评分 + 降级链）
    → 网络流量捕获（LLM API 端点 + RAG 端点）
    → 探测消息发送（UI → API 降级重试）
    → 直接 API 探测（fetch 三重策略）
    → LLM 信息提取（模型名/提供商/参数）
  → SPA Recon 结果直接驱动 Garak + DeepTeam（跳过 AIMAP）
  → 凭据注入（Bearer Token → 环境变量/请求头）
```

### 6.3 API 路径流程

```
API 端点目标（Ollama / OpenAI 兼容 / 自定义端点）
  → AIMAP 协议识别 + 端点提取
  → Garak + DeepTeam 并行侦察（AIMAP 结果驱动）
  → 凭据注入（API Key → 环境变量/请求头）
```

## 7. 提供商推断（v2 全球覆盖）

### 7.1 双重策略推断

`_infer_provider(model_name, api_url)` 采用 **模型名称 + API 域名** 双重策略推断提供商：

1. **模型名称匹配**（优先）：直接反映底层模型，适用于自建代理平台
2. **API 域名匹配**（补充）：当模型名无法识别时，通过域名推断

### 7.2 覆盖范围

#### 中国厂商（模型名 + 域名）

| 提供商 | 模型名模式 | API 域名 |
|--------|-----------|----------|
| 火山引擎 | `deepseek-r1-*` | `volcengineapi.com` / `ark.volces.com` |
| DeepSeek | `deepseek` | `api.deepseek.com` |
| 阿里 | `qwen` / `通义` | `dashscope.aliyuncs.com` |
| 智谱 | `glm` / `chatglm` | `open.bigmodel.cn` |
| 百度 | `ernie` / `wenxin` | `qianfan.baidubce.com` |
| 月之暗面 | `moonshot` / `kimi` | `api.moonshot.cn` |
| MiniMax | `abab` / `minimax` | `api.minimax.chat` |
| 百川 | `baichuan` | — |
| 讯飞 | `spark` / `星火` | — |
| 腾讯 | `hunyuan` / `混元` | — |
| 零一 | `yi-*` | `api.01.ai` |
| 阶跃 | `step-*` | `api.stepfun.com` |

#### 欧美厂商（模型名 + 域名）

| 提供商 | 模型名模式 | API 域名 |
|--------|-----------|----------|
| OpenAI | `gpt` / `o1` / `o3` / `dall-e` / `whisper` / `tts-1` / `text-embedding` / `sora` | `api.openai.com` / `openai.azure.com` |
| Anthropic | `claude` | `api.anthropic.com` |
| Google | `gemini` / `gemma` / `palm` / `bard` | `generativelanguage.googleapis.com` / `aiplatform.googleapis.com` |
| Meta | `llama` | — |
| Mistral | `mistral` / `ministral` / `mixtral` / `codestral` / `pixtral` | `api.mistral.ai` |
| Microsoft | `phi-3` / `phi` | — |
| Cohere | `command` / `coral` | `api.cohere.ai` / `api.cohere.com` |
| Amazon | `nova` / `titan` | `bedrock-runtime.*.amazonaws.com` |
| IBM | `granite` / `merlinite` | `ml.cloud.ibm.com` |
| Perplexity | `pplx` / `sonar` | `api.perplexity.ai` |
| Stability | `stablelm` / `stablecode` | `api.stability.ai` |
| AI21 | `jamba` / `jurassic` | `api.ai21.com` / `api.ai21.ai` |
| Reka | `reka` | `api.reka.ai` |
| Databricks | `dbrx` | — |
| xAI | `grok` | `api.x.ai` |
| Together | — | `api.together.xyz` |
| Fireworks | — | `api.fireworks.ai` |
| Groq | — | `api.groq.com` |
| DeepInfra | — | `api.deepinfra.com` |
| Hugging Face | — | `api-inference.huggingface.co` |
| OpenRouter | — | `openrouter.ai` |

## 8. AI 响应容器选择器（v2 全面覆盖）

### 8.1 选择器覆盖范围

SPA 侦察的响应容器自动检测覆盖以下 AI 应用框架：

| 框架/风格 | 选择器示例 |
|-----------|-----------|
| 通用语义 | `[class*="answer"]` / `[class*="response"]` / `[class*="message"]` / `[class*="markdown"]` |
| ChatGPT / OpenAI | `[class*="markdown-body"]` / `[data-testid*="conversation"]` |
| Claude / Anthropic | `[class*="human-turn"]` / `[class*="assistant-turn"]` |
| 国产 AI 应用 | `[class*="answer-box"]` / `[class*="chat-msg"]` / `[class*="msg-content"]` / `[class*="bubble"]` |
| Vercel AI SDK | `[data-stream="true"]` / `[class*="ai-output"]` |
| LangChain / Gradio | `[class*="gradio"]` / `[class*="stMarkdown"]` / `[class*="langchain"]` |
| 推理/思维链 | `[class*="thinking"]` / `[class*="reasoning"]` / `[class*="reflection"]` |
| ARIA 语义角色 | `[role="log"]` / `[aria-live="polite"]` / `[role="article"]` |

### 8.2 降级链机制

```
配置选择器（YAML auto_detected）
  → 失败 → response_fallback_sels 列表依次尝试
    → 失败 → page.evaluate 批量扫描全部选择器
      → 按文本长度降序选择最佳元素
```
