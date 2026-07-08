# 二、攻击阶段：按认证场景选择策略

侦察完成后，系统已自动获取以下信息并注入攻击管线：

| 信息 | 来源 | 自动注入位置 |
|------|------|-------------|
| 模型名称 | 步骤② | `--target-model` |
| Chat 端点 | 步骤① | `--target-url` |
| 架构类型 | 步骤③ | attack strategy 选择 |
| 速率限制 | 步骤① | `--concurrent` 建议 |

攻击阶段的核心机制：无论有无 API Key，攻击都通过 `CustomHttpChatTarget` 对目标 URL 发 POST 请求来完成。唯一区别在于 HTTP 请求头中是否携带认证信息。

```
攻击管道架构：
  Converter 层（编码/角色扮演/翻译/...）
      │
      ▼
  CustomHttpChatTarget ──POST──→ 目标
      │                          
      │  POST Body: 根据 --target-api-format 构建
      │  - openai: {"model":"xxx","messages":[{"role":"user","content":"恶意提示词"}]}
      │  - raw:    {"message":"恶意提示词","conversation_id":""}
      │  - gemini: {"contents":[{"parts":[{"text":"恶意提示词"}]}],...}
      │  - claude: {"model":"xxx","messages":[{"role":"user","content":"恶意提示词"}]}
      │                          
      │  HTTP Headers: 根据认证方式组合
      │  - 无认证:     仅浏览器伪装头（User-Agent/Content-Type）
      │  - API Key:    Authorization: Bearer {key}
      │  - Cookie:     Cookie: {cookie_value}
      │  - JWT:        Authorization: Bearer {jwt}
      ▼
  Scorer 评分（独立 Judge LLM）→ Memory 持久化 → 报告生成
```

以下按三种认证场景分类，给出侦察完成后继续攻击的完整命令和策略。

---

**📖 手册导航**：[← 一、侦察阶段](reconnaissance-guide.md) | [三、攻击后研判 →](post-attack-analysis.md)

---

### 场景 1：无 API Key — 内网自部署 Web 应用（无认证目标）

**典型目标**：vLLM / Ollama / TGI / LocalAI / text-generation-webui / Open-WebUI 等在内网裸跑的服务，无认证防护。

**本质**：POST 请求不携带 `Authorization` 头，仅发送浏览器伪装头 + JSON body。

> 代码依据 — `targets/http_target.py:171-185`：`effective_key` 为空时 `if effective_key:` 为 False，不添加 `Authorization` 或 `x-api-key`。

#### 1.1 攻击流程总览

```
侦察完成（已知 model + endpoint）
    │
    ├─→ 2.1 单轮快速扫描   （30 秒判断是否有防线）
    ├─→ 2.2 多轮渐进越狱   （对付高防线模型）
    ├─→ 2.3 高级攻击策略   （按架构类型定向打击）
    └─→ 2.4 全自动门控     （一劳永逸，推荐）
```

#### 1.2 单轮快速扫描（首轮试探）

```bash
# 侦察输出为 OpenAI 兼容端点（vLLM/TGI 等）→ 使用默认 openai 格式
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase single

# 侦察输出为 raw 格式（非标准 Web Chat）→ 切换 raw 格式
python main.py --lang cn --target-url http://192.168.2.199:8501/api/chat --target-api-format raw --phase single

# 提高并发加速（使用侦察步骤①输出的推荐值）
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase single --concurrent 4
```

**此时 HTTP 行为（openai 格式）**：
```
POST /v1/chat/completions HTTP/1.1
User-Agent: Mozilla/5.0 ... Chrome/131.0 ...
Content-Type: application/json

{"model": "qwen2.5", "messages": [{"role": "user", "content": "越狱提示词..."}]}
```

**此时 HTTP 行为（raw 格式）**：
```
POST /api/chat HTTP/1.1
User-Agent: Mozilla/5.0 ... Chrome/131.0 ...
Content-Type: application/json

{"message": "越狱提示词...", "conversation_id": ""}
```

#### 1.3 多轮 Crescendo 渐进式越狱

对付单轮无法突破的高防线模型，Crescendo 会对同一目标发起多轮递增 POST，每轮基于上一轮响应调整策略：

```bash
# OpenAI 兼容端点
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase crescendo

# raw 格式端点
python main.py --lang cn --target-url http://192.168.2.199:8501/api/chat --target-api-format raw --phase crescendo
```

#### 1.4 按侦察架构类型定向攻击

根据侦察步骤③的架构判定，选择对应的高级攻击策略：

```bash
# 侦察判定为 AGENT 架构 → 工具调用劫持/跨代理注入
python main.py --lang cn --target-url http://192.168.2.199:8501/api/chat --target-api-format raw --phase agent_attack

# 侦察判定为 RAG 架构 → RAG 投毒/检索操纵/数据泄露
python main.py --lang cn --target-url http://192.168.2.199:8501/api/rag --target-api-format raw --phase rag_poison

# 侦察判定为 MCP 架构 → MCP 协议滥用/JSON 劫持/分块注入
python main.py --lang cn --target-url http://192.168.2.199:8501/jsonrpc --target-api-format raw --phase mcp_security

# 侦察判定为 MULTI_AGENT → 跨代理注入/工具劫持
python main.py --lang cn --target-url http://192.168.2.199:8501/api/agent --target-api-format raw --phase agent_attack

# 分块绕过 — 对付有 token/长度限制的目标
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase chunked

# ManyShot 洪水 — 超长上下文投喂攻击
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase manyshot

# Skeleton Key — 试图让模型"解除所有限制"
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase skeleton_key
```

#### 1.5 全自动门控（推荐，一劳永逸）

```bash
# 自动阶梯升级：PROBE → SINGLE → CRESCENDO
# 某阶段成功率低于阈值（默认 10%）自动跳过，避免无效攻击
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --auto-gate --gate-threshold 0.10
```

#### 1.6 高级控制参数

```bash
# 指定并发数
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase all --concurrent 4

# 指定载荷预设（stealth 隐匿 / bruteforce 暴力 / redteam 红队 / academic 学术 / minimal 精简）
python main.py --lang cn --target-url http://192.168.2.199:8501/api/chat --target-api-format raw --phase single --payload-preset stealth

# 命令行注入额外 payload 变量（最高优先级，覆盖其他所有来源）
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase single --payload-vars '{"target_lang":"en","bypass_hint":"roleplay"}'

# 仅攻击指定用例
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase single --case "CAP_001_social_eng_phishing,CAP_005_ransomware_cpp"

# 快捷用例别名
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --case all-single   # 等价 --phase single
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --case all-error    # 重跑失败用例

# 排除不适用用例
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase all --exclude-case "PROBE_01_roleplay_defense"
```

---

### 场景 2：获得 API Key 但目标不需要认证

**典型情况**：手上有 API Key，但目标端点实际不做认证校验（内网测试环境常见）。

**本质**：与场景 1 完全相同，Key 可传可不传。传了 Key 后 HTTP 请求头会携带 `Authorization: Bearer {key}`，但目标不校验。

> 代码依据 — `targets/http_target.py:178-184`：有 Key 时添加认证头，有 JWT 时 JWT 优先，均无时不添加。`entrypoint/bootstrap.py:274-277`：`api_key=effective_api_key or ""`，空字符串合法。

#### 2.1 验证目标是否需要认证

先用场景 1 方式试一轮（不传 Key）：

```bash
# 不传 Key
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase single
```

- 返回 HTTP 200 且正常内容 → **目标不需要认证** → 按场景 1 策略执行
- 返回 HTTP 401/403 → 进入场景 3

#### 2.2 命令（与场景 1 完全一致）

```bash
# 基础攻击（不传 Key）
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase single

# 全量门控
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --auto-gate

# 可选传入 Key（某些目标会对认证用户开放更高配额/限额，或用于身份伪装）
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --target-api-key sk-your-key --phase single
```

#### 2.3 策略要点

| 维度 | 说明 |
|------|------|
| 攻击策略 | 与场景 1 完全相同 |
| `--target-api-key` | 可选传入，不传也能正常攻击 |
| HTTP 行为 | 有 Key 时头带 `Authorization: Bearer`，无 Key 时不带 |
| 安全性 | 传入 Key 不影响攻击效果，目标不校验 |
| 适用目标 | 内网 dev/test 环境、未开启认证的 Ollama/vLLM 实例 |

---

### 场景 3：获得 API Key 且目标需要认证

**典型目标**：OpenAI API、Gemini API、Claude API、或内部部署但开启了认证的 LLM 服务。

**本质**：攻击时必须携带正确的认证信息（API Key / JWT / Cookie / 自定义头），否则目标返回 401/403。

> 代码依据 — `targets/http_target.py:171-185`：`_build_headers()` 中根据 `api_format` 选择认证策略：
> - `openai/raw` → `Authorization: Bearer {key}`
> - `claude` → `x-api-key: {key}` + `anthropic-version: 2023-06-01`
> - `gemini` → key 追加为 URL query parameter `?key={key}`

#### 3.1 认证方式一览

| 认证类型 | 核心参数 | 请求头发送格式 | 适用目标 |
|---------|---------|--------------|---------|
| Bearer Token | `--target-api-key sk-xxx` | `Authorization: Bearer sk-xxx` | OpenAI 兼容、大多数 API |
| Claude x-api-key | `--target-api-format claude --target-api-key sk-xxx` | `x-api-key: sk-xxx` | Anthropic Claude |
| Gemini URL Key | `--target-api-format gemini --target-api-key xxx` | `?key=xxx` 追加到 URL | Google Gemini |
| Cookie/Session | `--target-cookie "session=abc"` | `Cookie: session=abc` | 内网 Web 应用 |
| JWT Token | `--target-jwt "eyJ..."` | `Authorization: Bearer eyJ...` | RESTful API |
| 自定义头 | `--target-extra-headers '{"X-API-Key":"xxx"}'` | `X-API-Key: xxx` | 非标准认证 |
| Cookie+JWT 双重 | `--scenario cookie-jwt-dual --target-cookie --target-jwt` | Cookie + Bearer 同时 | 高安全内网应用 |

#### 3.2 OpenAI 兼容端点（最常见）

```bash
# 侦察（带 Key）
python main.py --lang cn --target-url https://api.internal.example.com/v1 --target-api-key sk-your-key --phase probe

# 单轮攻击
python main.py --lang cn --target-url https://api.internal.example.com/v1/chat/completions --target-api-key sk-your-key --phase single

# 跳过探测加速（手动指定模型）
python main.py --lang cn --target-url https://api.internal.example.com/v1/chat/completions --target-api-key sk-your-key --target-model gpt-4 --no-probe --phase single

# 全阶段攻击
python main.py --lang cn --target-url https://api.internal.example.com/v1/chat/completions --target-api-key sk-your-key --phase all

# 自动门控
python main.py --lang cn --target-url https://api.internal.example.com/v1/chat/completions --target-api-key sk-your-key --auto-gate --gate-threshold 0.10
```

**此时 HTTP 行为**：
```
POST /v1/chat/completions HTTP/1.1
Authorization: Bearer sk-your-key
Content-Type: application/json

{"model": "gpt-4", "messages": [{"role": "user", "content": "越狱提示词..."}]}
```

#### 3.3 Gemini API

```bash
# 侦察 + 单轮（一条命令完成）
python main.py --lang cn \
  --target-url https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent \
  --target-api-key YOUR_GEMINI_KEY \
  --target-api-format gemini \
  --phase probe

# 全量攻击
python main.py --lang cn \
  --target-url https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent \
  --target-api-key YOUR_GEMINI_KEY \
  --target-api-format gemini \
  --phase all
```

**此时 HTTP 行为**：
```
POST https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=YOUR_GEMINI_KEY
Content-Type: application/json

{"contents": [{"parts": [{"text": "越狱提示词..."}]}], "generationConfig": {...}}
```

#### 3.4 Claude API

```bash
# 侦察 + 单轮
python main.py --lang cn \
  --target-url https://api.anthropic.com/v1/messages \
  --target-api-key YOUR_CLAUDE_KEY \
  --target-api-format claude \
  --target-model claude-3-sonnet-20240229 \
  --phase probe

# 全量攻击
python main.py --lang cn \
  --target-url https://api.anthropic.com/v1/messages \
  --target-api-key YOUR_CLAUDE_KEY \
  --target-api-format claude \
  --target-model claude-3-sonnet-20240229 \
  --phase all
```

**此时 HTTP 行为**：
```
POST /v1/messages HTTP/1.1
x-api-key: YOUR_CLAUDE_KEY
anthropic-version: 2023-06-01
Content-Type: application/json

{"model": "claude-3-sonnet-20240229", "max_tokens": 4096, "messages": [{"role": "user", "content": "越狱提示词..."}]}
```

#### 3.5 内网 Web 应用（Cookie/JWT 认证）

```bash
# Cookie Session 认证
python main.py --lang cn \
  --target-url http://192.168.1.100/api/chat \
  --target-api-format raw \
  --target-cookie "session_id=abc123; auth_token=xyz" \
  --phase single

# 使用场景预设（一键组合认证+传输参数）
python main.py --lang cn \
  --target-url http://192.168.1.100/api/chat \
  --scenario cookie-ua-spoof \
  --target-cookie "session=abc" \
  --phase single

# JWT Token 认证
python main.py --lang cn \
  --target-url https://internal-api.example.com/v1/chat \
  --target-jwt "eyJhbGciOiJIUzI1NiIs..." \
  --phase single

# 使用场景预设
python main.py --lang cn \
  --target-url https://internal-api.example.com/v1/chat \
  --scenario jwt-bearer \
  --target-jwt "eyJ..." \
  --phase single

# Cookie + JWT 双重认证
python main.py --lang cn \
  --target-url https://high-security-app/api/chat \
  --scenario cookie-jwt-dual \
  --target-cookie "session=abc" \
  --target-jwt "eyJ..." \
  --phase single

# form-urlencoded POST + Cookie（传统 Web 表单类 Chat API）
python main.py --lang cn \
  --target-url http://192.168.1.100/chat \
  --scenario form-cookie \
  --target-cookie "PHPSESSID=abc123" \
  --phase single

# 自定义认证头（X-API-Key / X-CSRF-Token 等）
python main.py --lang cn \
  --target-url https://internal-app/api/v1/query \
  --target-extra-headers '{"X-API-Key":"sk-secret","X-CSRF-Token":"abc123"}' \
  --phase single

# 场景预设：HTTPS 自签证书 + 自定义认证头
python main.py --lang cn \
  --target-url https://192.168.12.22:8443/api/chat \
  --scenario https-selfsigned-custom-header \
  --target-extra-headers '{"X-API-Key":"sk-secret"}' \
  --phase single
```

#### 3.6 高级攻击策略（与场景 1 相同，带 Key）

```bash
# 架构定向（Agent/RAG/MCP）
python main.py --lang cn --target-url https://api.example.com/v1/chat --target-api-key sk-xxx --phase agent_attack
python main.py --lang cn --target-url https://api.example.com/v1/chat --target-api-key sk-xxx --phase rag_poison

# 分块/洪水/Skeleton Key
python main.py --lang cn --target-url https://api.example.com/v1/chat --target-api-key sk-xxx --phase chunked
python main.py --lang cn --target-url https://api.example.com/v1/chat --target-api-key sk-xxx --phase manyshot
python main.py --lang cn --target-url https://api.example.com/v1/chat --target-api-key sk-xxx --phase skeleton_key
```

#### 3.7 渗透模式（全自动编排，带 Key）

```bash
# 全自动渗透
python main.py --penetrating-mode --penetrating-template jailbreak_arsenal.yaml \
  --target-url https://api.example.com/v1/chat/completions --target-api-key sk-xxx

# 按架构选择模板
python main.py --penetrating-mode --penetrating-template rag_pipeline.yaml \
  --target-url https://api.example.com/v1/rag/chat --target-api-key sk-xxx

python main.py --penetrating-mode --penetrating-template agent_multi_agent.yaml \
  --target-url https://api.example.com/v1/agent/chat --target-api-key sk-xxx
```

**可用渗透模板**：`comprehensive.yaml` / `jailbreak_arsenal.yaml` / `prompt_injection.yaml` / `rag_pipeline.yaml` / `agent_multi_agent.yaml` / `encoding_bypass.yaml` / `data_exfiltration.yaml` / `output_handling.yaml` / `mcp_protocol.yaml` / `supply_chain.yaml` / `red_team_scenarios.yaml`

---

### 三场景对照速查

| 维度 | 场景 1：无 Key | 场景 2：有 Key 无需认证 | 场景 3：有 Key 需认证 |
|------|:---:|:---:|:---:|
| 目标特征 | 内网裸跑服务 | 内网 dev/test 环境 | OpenAI/Gemini/Claude/认证内网 |
| 侦察命令 | `--phase probe` | 同左（可选不传 Key） | `--phase probe --target-api-key xxx` |
| 攻击命令 | `--phase single/crescendo/all` | 同左 | 同左，**必须带**认证参数 |
| HTTP 认证头 | 无 | 可选 | **必带** |
| `--target-api-key` | 不需要 | 可选 | **必填** |
| `--target-api-format` | `openai` 或 `raw` | 同左 | 按目标选 `openai/claude/gemini/raw` |
| `--scenario` 预设 | 不需要 | 不需要 | `jwt-bearer`/`cookie-ua-spoof` 等 |
| `--auto-gate` | ✅ | ✅ | ✅ |
| 渗透模式 | ✅ 不需要 Key | ✅ 不需要 Key | ✅ 需要 Key |
| 场景预设 | 不适用 | 不适用 | `cookie-jwt-dual`/`form-cookie` 等 |

---

**📖 手册导航**：[← 一、侦察阶段](reconnaissance-guide.md) | [三、攻击后研判 →](post-attack-analysis.md)
