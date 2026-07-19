# SPA 智能助手侦察完整解决方案

> **最后更新**: 2026-07-19 / 版本: v1.2 / 关联模块: `pyrit_ai300/reconnaissance/adapters/spa_chat_recon_adapter.py`, `scripts/auto_spa_recon.py`, `config/targets/spa_target.yaml` / 状态: 已完成

## 1. 概述

本方案是针对**需要认证登录的 SPA 架构 AI 聊天应用**的端到端侦察解决方案。基于国开 `student.syxy.ouchn.cn` 实战经验提炼，覆盖从认证穿透到 LLM 端点发现的完整链路。

### 1.1 适用场景

| 场景特征 | 示例 |
|---------|------|
| SPA 架构（Vue/React/Angular） | URL 使用 hash 路由（如 `#/home`） |
| SSO/OIDC 隐式流认证 | token 在 URL fragment 或 localStorage |
| 简单账号密码认证 | 无 SSO，直接表单提交（无验证码时全自动） |
| 无需认证 | 公开聊天页面（`auth.mode: none`） |
| 浮动按钮式聊天入口 | 右下角 `div.show-chat-button` |
| 无独立发送按钮 | Enter 键发送或父容器点击 |
| 跨域 LLM API | 前端域名与 LLM 端点域名不同 |
| RAG 增强问答 | 带知识库引用的 LLM 响应 |
| WAF 防护 | HWWAFSESID 等 WAF cookie |

### 1.2 实战验证目标（2026-07-19）

| 项目 | 发现 |
|------|------|
| 目标 | `https://student.syxy.ouchn.cn/#/home` |
| 认证 | OIDC 隐式流，SSO 域名 `passport.syxy.ouchn.cn` |
| 聊天入口 | `div.show-chat-button`（右下角浮动按钮）|
| 输入框 | `textarea.send-box-default-text` |
| 发送方式 | Enter 键（无独立发送按钮）|
| 响应容器 | `.answer-box` / `.answer-text` |
| LLM 端点 | `POST https://appsharing-ai.ouchn.edu.cn/v0/chat/completions/with-knowledge` |
| 模型 | `deepseek-r1-250120`（DeepSeek R1，火山引擎）|
| 应用类型 | Chat + RAG（知识库增强）|
| 响应格式 | SSE 流式（`text/event-stream`）|

---

## 2. 解决方案架构

```
┌─────────────────────────────────────────────────────┐
│                  用户目标 URL                        │
│            (SPA + SSO + AI 聊天)                     │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │  scripts/auto_spa_recon │  ← 独立诊断脚本
          │  (通用 10 步流程)        │     （快速排查）
          └────────────┬────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  config/targets/            │  ← 配置层
        │  ├── spa_target.yaml       │     （极简 4 字段，侦察+攻击合一）
        │  └── credentials/域名.txt   │     （凭据自动导出/复用）
        └──────────────┬──────────────┘
                       │
     ┌─────────────────▼─────────────────┐
     │  SPAChatReconAdapter v1.4.1       │  ← 框架层
     │  ├── DEFAULT_CHAT_ENTRY_SELECTORS │     （900+ 选择器）
     │  │   (含 show-chat-button 等)     │
     │  ├── NetworkTrafficCapture        │     （LLM 端点识别）
     │  │   (含 with-knowledge 等 RAG)   │
     │  ├── _extract_dom_snapshot()      │     （DOM 批量提取）
     │  ├── _score_elements()            │     （多信号评分）
     │  └── _auto_detect_selectors()     │     （三层降级）
     └─────────────────┬─────────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  results/recon/             │  ← 输出层
        │  ├── auto_report_*.json     │     （诊断报告）
        │  ├── screenshots/           │     （4 阶段截图）
        │  └── storage_states/        │     （会话复用）
        └─────────────────────────────┘
```

---

## 3. 快速使用指南

### 3.0 极简配置工作流（推荐）

**第 1 步：填写极简配置（4 个字段）**

编辑 `config/targets/spa_target.yaml`：

```yaml
target:
  url: "https://example.com/#/home"
  username: "your_username"
  password: "your_password"
  auth_mode: "sso"          # sso / credentials / none
```

**第 2 步：运行侦察（选择器自动回写）**

```bash
python scripts/auto_spa_recon.py --config config/targets/spa_target.yaml
```

侦察完成后，选择器自动回写到文件底部 `auto_detected` 段：

```yaml
auto_detected:
  chat_entry: "div.show-chat-button"
  input: "textarea.send-box-default-text"
  response: ".answer-box"
  llm_endpoint: "POST https://appsharing-ai.ouchn.edu.cn/v0/chat/completions/with-knowledge"
  last_recon: "2026-07-19 21:03:17"
```

**第 3 步：运行攻击（自动复用选择器）**

```bash
ai300 owasp llm01 --target-file config/targets/spa_target.yaml
```

> **核心优势**：用户只需填 4 个字段，选择器由系统自动发现并回写，侦察+攻击共用一个文件。

### 3.1 方式一：独立诊断脚本（推荐首次使用）

```bash
cd d:\我的文档\GitHub\osai\pyrit

# 方式 A: 命令行参数
python scripts/auto_spa_recon.py --url https://xxx.com/#/home --user admin --pass PASSWORD

# 方式 B: YAML 配置（极简格式，推荐）
python scripts/auto_spa_recon.py --config config/targets/spa_target.yaml

# 方式 C: 交互式
python scripts/auto_spa_recon.py
```

**10 步全自动流程**：

| 步骤 | 动作 | 关键逻辑 |
|------|------|---------|
| 1 | 启动 Chromium | 非 headless（验证码需人工）|
| 2 | 导航到目标 | SSO 重定向超时是正常的 |
| 3 | 自动填写登录表单 | 8+ 种用户名/密码/提交选择器 |
| 4 | 等待人工验证码 | 180s 超时，排除 OIDC 回调中间页 |
| 5 | 检查认证状态 | localStorage token + Cookie |
| 6 | 扫描聊天入口 | 多信号评分 + 浮动按钮位置加分 |
| 7 | 查找输入框 | 8 种选择器降级 |
| 8 | 发送消息 | 三级降级：Enter → 发送按钮 → 父容器点击 |
| 9 | 获取 AI 响应 | 10 种响应容器选择器 |
| 10 | 保存结果 | storage_state + 诊断报告 + 选择器自动回写 YAML |

### 3.2 方式二：框架集成（批量攻击）

```bash
# 侦察阶段（选择器自动回写到 spa_target.yaml）
ai300 recon --target-file config/targets/spa_target.yaml

# 攻击阶段（自动读取回写的选择器）
ai300 owasp llm01 --target-file config/targets/spa_target.yaml
```

---

## 4. 核心技术要点

### 4.1 OIDC 隐式流认证穿透

**问题**：OIDC 隐式流在 URL fragment 传递 token（`#/signin-oidc#access_token=xxx`），容易被误判为登录页。

**解决方案**：

```python
# OIDC 回调特征（排除登录中间页）
OIDC_CALLBACK_PATTERNS = [
    "signin-oidc", "redirect_uri", "callback",
    "code=", "id_token=", "access_token=",
]

# 落地检测：目标域名 + 非 OIDC 回调
if target_domain in cur and not is_oidc_callback:
    print("✅ 已落地到目标域名")
```

**token 识别**：扫描 localStorage 中含 `token`/`access`/`auth`/`user` 的键。

### 4.2 WAF 假阳性规避

**问题**：华为云 WAF 的 `HWWAFSESID` cookie 会让 HTTP preflight 返回 200，导致框架误认为已认证。

**解决方案**：在 adapter 中，当 SSO 模式配置时，忽略仅有 cookie 的 preflight "成功"：

```python
# 如果是 SSO 模式且仅有 WAF cookie，跳过 preflight 判定
if login_mode in ("sso", "oidc") and not has_bearer_token:
    # 不信任 cookie-only 的 preflight，继续走浏览器自动化
    pass
```

### 4.3 浮动按钮式聊天入口发现

**问题**：聊天入口是 `div.show-chat-button`（无文本、无 ARIA 标签的右下角浮动 div），常规选择器无法命中。

**解决方案**：多信号评分 + 位置加分：

```javascript
// 关键词匹配加分
for (const kw of keywords) {
    if (combined.includes(kw)) { score += 10; signals.push(kw); }
}

// 浮动按钮位置加分（右下角 + 小尺寸）
if (rect.x > window.innerWidth * 0.7
    && rect.y > window.innerHeight * 0.5
    && rect.width < 100 && rect.height < 100) {
    score += 5; signals.push('fab-position');
}
```

同时在 adapter 的 `DEFAULT_CHAT_ENTRY_SELECTORS` 中新增：
- `.show-chat-button`, `.show-chat`, `.show-chat-btn`
- `.open-chat`, `.open-chat-button`, `.toggle-chat`

### 4.4 无发送按钮的三级降级发送

**问题**：目标站点无独立发送按钮，`send-box-default` 区域 `cursor:pointer`。

**解决方案**：

| 策略 | 方法 | 适用场景 |
|------|------|---------|
| 策略 1 | `page.press(input, "Enter")` | 大多数聊天应用 |
| 策略 2 | 查找 `button[class*='send']` 等 | 有发送按钮但未配置 |
| 策略 3 | 向上遍历父容器，`cursor:pointer` 时 `.click()` | div 容器点击型 |

### 4.5 跨域 LLM 端点识别

**问题**：前端域名 `student.syxy.ouchn.cn`，LLM API 在 `appsharing-ai.ouchn.edu.cn`（跨域）。

**解决方案**：在网络流量捕获中，不限定域名，按路径关键词 + body 字段 + content_type 综合判断：

```python
LLM_PATH_KEYWORDS = [
    "chat", "completions", "stream", "generate", "infer",
    # RAG / 知识库增强路径
    "with-knowledge", "knowledge-chat", "rag", "knowledge", "qa",
]

# 综合判断：路径匹配 + POST + body 字段 + SSE
is_llm = (path_match and method == "POST") or body_match or is_sse
```

### 4.6 RAG 知识库引用识别

**目标站点的 LLM 响应带知识库引用**（如 "魏公村-1-综办.xlsx"），需识别 RAG 特征：

```python
# RAG 端点检测
RAG_PATH_KEYWORDS = [
    "embed", "embedding", "vector", "retrieve", "retrieval",
    "knowledge", "citation", "reference", "document",
]

# 响应中包含引用记录 API
# GET /v0/chat/record/{id}/citationRecords → RAG 知识库
```

---

## 5. 配置文件模板

### 5.1 `spa_target.yaml`（推荐：侦察 + 攻击合一）

> v1.2 极简版：用户只需填 4 字段（url/username/password/auth_mode），选择器由侦察自动回写。
> v1.1 合并了 `sso_login.yaml` + `spa_chat_attack.yaml`，一个文件管整个生命周期。

```yaml
target:
  type: "spa_chat"                      # 统一类型（兼容 spa_chat_recon / playwright）
  connection:
    url: "https://目标域名/#/home"
    browser: "chromium"
    headless: false

  auth:
    # ── 6 种认证模式按场景选一种 ──
    mode: "sso"                         # sso / credentials / header_file / storage_state / manual / none
    username: "账号"
    password: "密码"
    target_domain: "目标域名"            # sso 模式需要
    header_file: "config/targets/credentials/域名.txt"  # header_file 模式需要

  spa:
    chat_entry:
      mode: "selector"
      selector: ".show-chat-button"      # 诊断确认后填入
    selectors:
      input: "textarea.send-box-default-text, ..."
      send_button: ""                    # 留空 = Enter 键发送
      response: ".answer-box, .answer-text, ..."

  probe:
    enabled: true
    save_storage_state: true             # 侦察后自动保存

  rate_control:
    max_concurrent: 1                    # 浏览器目标必须串行
```

**认证模式速查**：

| mode | 场景 | 人工干预 | 超时 |
|------|------|---------|------|
| `sso` | SSO/OIDC 跳转 + 验证码 | ✅ 需人工验证码 | 180s |
| `credentials` | 简单账号密码 | 检测到验证码才需人工 | 60s |
| `header_file` | 复用凭据文件 | ❌ 全自动 | - |
| `storage_state` | 复用浏览器状态 | ❌ 全自动 | - |
| `manual` | 完全手动 | ✅ 手动登录 | - |
| `none` | 无需认证 | ❌ 跳过登录 | - |

### 5.2 旧格式（向后兼容）

旧版 `sso_login.yaml` / `spa_chat_attack.yaml` 格式仍然有效，代码会自动识别。
但已删除这些文件，推荐使用 `spa_target.yaml` 极简格式。

### 5.3 `credentials/域名.txt`（凭据文件）

```
# 格式: 用户名:密码
2680201200754:PASSWORD
```

---

## 6. 诊断报告解读

`results/recon/auto_report_*.json` 关键字段：

```json
{
  "has_oidc_token": true,              // 认证是否成功
  "chat_input_found": true,            // 聊天输入框是否找到
  "input_selector": "textarea.send-box-default-text",  // 可复用的选择器
  "llm_api_calls": [                   // LLM API 请求列表
    {
      "url": "https://appsharing-ai.ouchn.edu.cn/v0/chat/completions/with-knowledge",
      "method": "POST",
      "status": 200,
      "content_type": "text/event-stream"  // SSE 流式
    }
  ],
  "response_containers": [             // AI 响应容器
    {
      "selector": "[class*='answer']",
      "class": "answer-box",           // 可复用的响应选择器
      "text": "你好呀😉！我是你的AI学习助手..."
    }
  ]
}
```

**关键指标**：
- `has_oidc_token: true` → 认证穿透成功
- `chat_input_found: true` → 聊天界面定位成功
- `llm_api_calls` 非空 → LLM 端点发现成功
- `response_containers` 非空 → AI 响应捕获成功

---

## 7. 新目标适配清单

对新的 SPA AI 聊天目标，按以下步骤适配：

### Step 1: 运行诊断脚本

```bash
python scripts/auto_spa_recon.py --url https://新目标.com --user 账号 --pass 密码
```

### Step 2: 检查诊断报告

重点看 4 个指标：
1. `has_oidc_token` → 认证是否穿透
2. `chat_input_found` → 聊天界面是否找到
3. `llm_api_calls` → LLM 端点是否捕获
4. `response_containers` → 响应容器是否识别

### Step 3: 提取选择器

从报告中提取 3 个关键选择器，填入配置文件：

| 报告字段 | 配置项 |
|---------|--------|
| `input_selector` | `selectors.input` |
| `response_containers[0].class` | `selectors.response` |
| 聊天入口（终端日志中 `✅ 点击成功` 的选择器） | `chat_entry.selector` |

### Step 4: 配置攻击

```bash
# 复用诊断出的 storage_state
cp results/recon/storage_states/auto_state_*.json results/recon/storage_states/新目标.json

# 编辑配置文件后运行攻击
ai300 owasp llm01 --target-file config/targets/spa_target.yaml
```

### Step 5: 常见问题排查

| 问题 | 可能原因 | 解决方案 |
|------|---------|---------|
| `has_oidc_token: false` | SSO 登录失败 / 验证码未完成 | 手动完成验证码后按 Enter |
| `chat_input_found: false` | 聊天入口未找到 | 查看截图，手动打开聊天界面后按 Enter |
| `llm_api_calls` 为空 | 发送方式不匹配 | 检查终端日志的三级降级输出 |
| `response_containers` 为空 | 响应容器选择器不匹配 | 查看截图，手动 F12 检查响应 DOM |

---

## 8. 与现有文档的关系

| 文档 | 用途 | 关系 |
|------|------|------|
| [spa_recon_guide.md](./spa_recon_guide.md) | adapter 详细使用手册 | 本方案是其快速入门版 |
| [recon_optimization_analysis.md](./recon_optimization_analysis.md) | 侦察优化分析（19 项）| 本方案已实施部分优化 |
| [payload_optimization_implementation.md](./payload_optimization_implementation.md) | 载荷优化实施报告 | 攻击阶段使用优化后的载荷 |

---

## 9. 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-07-19 | 初始版本，基于国开 syxy 实战经验提炼 |
| v1.1 | 2026-07-19 | 合并侦察+攻击为 `spa_target.yaml`，新增 `credentials`/`none` 认证模式，向后兼容旧格式 |
| v1.2 | 2026-07-19 | 极简配置优化：用户只需填 4 字段（url/username/password/auth_mode），侦察后选择器自动回写 `auto_detected` 段，配置从 155 行缩减到 20 行 |

---

## 附录 A: 诊断脚本选择器池

### A.1 聊天输入框选择器（8 种降级）

```python
CHAT_INPUT_SELECTORS = [
    "textarea.send-box-default-text",       # 国开专用
    "textarea[class*='send-box']",          # 模糊匹配
    "[placeholder='请输入文字或语音']",      # placeholder
    "textarea[class*='chat-input']",        # 通用 chat-input
    "textarea[class*='message']",           # 通用 message
    "textarea[class*='prompt']",            # AI prompt
    "[contenteditable='true'][class*='chat']",  # contenteditable
    "textarea",                             # 最终兜底
]
```

### A.2 聊天入口兜底选择器（18 种）

```python
CHAT_ENTRY_FALLBACK_SELECTORS = [
    ".show-chat-button", ".show-chat", ".show-chat-btn",
    ".open-chat", ".open-chat-button", ".toggle-chat",
    ".chat-fab", ".chat-widget", ".chat-trigger", ".chat-launcher",
    ".ai-assistant", ".ai-chat-btn", ".ai-trigger",
    ".floating-btn", ".fab", ".fab-btn",
    "[class*='show-chat']", "[class*='open-chat']",
    "[class*='chat-fab']", "[class*='ai-fab']",
    "[aria-label*='助手']", "[aria-label*='聊天']",
    "[aria-label*='AI']", "[aria-label*='Chat']",
    "[title*='助手']", "[title*='聊天']",
]
```

### A.3 LLM API 路径关键词（15 种）

```python
LLM_API_KEYWORDS = [
    "/api/", "/v0/", "/v1/", "/v2/",
    "chat", "completion", "llm", "stream", "message",
    "ask", "query", "generate", "infer",
    "with-knowledge", "rag", "knowledge",
]
```
