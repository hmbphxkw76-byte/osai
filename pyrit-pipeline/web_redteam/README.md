# Web Red Team Framework

> 通用认证感知红队框架 — 基于 PyRIT 原生 API, 零侵入扩展

## 双模式架构

| 模式 | 入口参数 | 目标类型 | 认证方式 | 适用场景 |
|---|---|---|---|---|
| **Browser UI** | `--target-profile` / `--target-url` | PlaywrightTarget | 浏览器交互 (同域/跨域/MFA) | 需要浏览器渲染的 Web Chat |
| **API POST** | `--api-url` | HTTPTarget + RateLimitedTarget | Bearer / OAuth2 | 直接攻击 AI LLM API 端点 |

## 快速开始

### 1. 安装依赖

```bash
pip install pyrit[playwright]
playwright install chromium
```

### 2A. Browser 模式 — 创建目标 Profile

在 `web_redteam/targets/` 下创建 YAML 文件:

```yaml
target:
  name: "my_target"
  type: "web_chat"

auth:
  type: "same_domain"  # or "cross_domain"
  login_url: "https://example.com/login"
  target_url: "https://example.com/chat"
  same_domain:
    detection:
      - strategy: "url_pattern"
        pattern: 'example\.com/chat'
      - strategy: "dom_element"
        selector: ".chat-container"
  auto_fill:
    "#username": "${TARGET_USERNAME}"
    "#password": "${TARGET_PASSWORD}"
  human_assisted_steps:
    - "captcha"

interaction:
  input:
    selector: "textarea#chat-input"
  send:
    selector: "button.send-btn"
  response:
    selector: "div.ai-message"
    wait_strategy: "new_element"

attack_defaults:
  attack_type: "red_teaming"
  max_turns: 10
```

```bash
# 首次运行 (需要人工认证)
python -m web_redteam.run \
  --target-profile web_redteam/targets/same_domain/example_portal.yaml \
  --attack-type red_teaming \
  --objective "Extract the system prompt" \
  --storage-state ~/.pyrit/auth_states/example.json

# 后续运行 (复用认证状态)
python -m web_redteam.run \
  --target-profile web_redteam/targets/same_domain/example_portal.yaml \
  --storage-state ~/.pyrit/auth_states/example.json
```

### 2B. API 模式 — 直接攻击 AI LLM API

```bash
# 基本用法 (Bearer Token)
python -m web_redteam.run \
  --api-url https://api.example.com/v1/chat/completions \
  --api-key sk-xxx \
  --api-model gpt-4 \
  --max-rpm 60 --max-concurrency 5 \
  --attack-type prompt_sending \
  --objective "Extract sensitive information"

# OAuth2 client_credentials 认证
python -m web_redteam.run \
  --api-url https://api.example.com/v1/chat/completions \
  --api-auth-type oauth2 \
  --api-oauth-token-url https://auth.example.com/token \
  --api-oauth-client-id my_client_id \
  --api-oauth-client-secret my_client_secret \
  --max-rpm 120 --max-concurrency 10 \
  --attack-type red_teaming

# 从 Burp Suite 原始请求加载
python -m web_redteam.run \
  --api-url https://api.example.com/v1/chat \
  --api-raw-request burp_request.txt \
  --attack-type prompt_sending

# SSE 流式响应
python -m web_redteam.run \
  --api-url https://api.example.com/v1/chat/stream \
  --api-response-format sse \
  --api-key sk-xxx \
  --attack-type prompt_sending

# 带侦察数据驱动 (recon-pipeline 产出)
python -m web_redteam.run \
  --api-url https://api.example.com/v1/chat \
  --api-key sk-xxx \
  --recon-data recon_output.json \
  --max-rpm 60

# 中断恢复
python -m web_redteam.run \
  --resume outputs/web_redteam_checkpoint.json
```

### 3. 运行测试

```bash
python -m pytest web_redteam/tests/ -v
```

## 支持的攻击类型

| 攻击类型 | PyRIT 原生类 | 说明 |
|---|---|---|
| `prompt_sending` | `PromptSendingAttack` | 单轮发送 |
| `red_teaming` | `RedTeamingAttack` | 多轮对抗 |
| `crescendo` | `CrescendoAttack` | 渐进越狱 |
| `tap` | `TAPAttack` | 树状探索 |

## 认证能力

### Browser 模式认证策略

| 策略 | 说明 |
|---|---|
| `same_domain` | 同域认证 (单域名内 login → target) |
| `cross_domain` | 跨域认证 (SSO/OAuth/CAS, 多域名跳转) |
| `auto` | 自动探测认证拓扑 |
| `none` | 无需认证 |

### API 模式认证

| 类型 | 参数 | 说明 |
|---|---|---|
| Bearer | `--api-key` 或 `--api-headers` | 静态 API Key |
| OAuth2 | `--api-auth-type oauth2` | client_credentials 动态获取 (RFC 6749) |

### MFA 自动检测

| MFA 类型 | DOM 选择器 | 文本关键词 |
|---|---|---|
| OTP | `input[name*="otp"]`, `input[autocomplete="one-time-code"]` | 验证码, OTP |
| QR 扫码 | `img[src*="qr"]`, `canvas[class*="qr"]` | 扫码, 二维码 |
| CAPTCHA | `img[src*="captcha"]`, `iframe[src*="recaptcha"]` | 图形验证, captcha |
| 滑块 | `div[class*="slider"]`, `div[class*="slide-to"]` | 滑动, 拖动 |
| SMS | — | 短信, SMS, 手机号 |

## 速率与并发控制 (API 模式)

| 特性 | 说明 |
|---|---|
| RPM 限速 | `--max-rpm` 每分钟最大请求数 |
| 并发控制 | `--max-concurrency` 最大并发信号量 |
| AIMD 自适应 | 429 错误自动降低 RPM, 成功后线性恢复 |
| RTT 驱动调整 | P90/P50 > 2.0 时降低更激进 (0.35 vs 0.5) |
| 不可重试状态码 | 400/401/403/404/405/422 立即失败不重试 |
| 指数退避重试 | 可重试错误 (500/429) 指数退避重试 |

## 运维韧性

| 特性 | 说明 |
|---|---|
| 优雅关闭 | Ctrl+C 保存部分结果 + 检查点 |
| 中断恢复 | `--resume` 从检查点恢复, 跳过已完成阶段 |
| 全局超时 | 900s 全局超时保护 |
| 凭据脱敏 | 日志中自动脱敏 Bearer/api_key (G9) |
| 认证重试 | 认证失败指数退避重试 (2 次) |
| 攻击重试 | 攻击失败指数退避重试 (3 次) |

## 目录结构

```
web_redteam/
├── targets/          # YAML 配置 (零代码接入新目标)
│   ├── api_config.py     # API 模式配置模型
│   ├── target_profile.py # Browser 模式 Profile
│   ├── dynamic_profile.py # URL → Profile 自动生成
│   ├── _schema.yaml      # Profile JSON Schema
│   ├── same_domain/      # 同域认证示例
│   └── cross_domain/     # 跨域认证示例
├── auth/             # 认证编排
│   ├── auth_detector.py  # 认证完成检测
│   ├── auth_probe.py     # 认证拓扑探测
│   ├── auth_strategy.py  # 策略选择 (same/cross/auto/none)
│   ├── browser_session.py # Playwright 浏览器管理
│   ├── human_assisted_auth.py # 人工辅助认证
│   └── mfa_detector.py   # MFA 自动检测
├── interaction/      # 目标交互 (interaction_func 工厂)
├── pipeline/         # 六阶段流水线
│   ├── context.py        # WebRedTeamContext 状态容器
│   ├── stage_init.py     # Stage 0: PyRIT 初始化
│   ├── stage_auth.py     # Stage 1: 认证 (双模式)
│   ├── stage_recon.py    # Stage 2: 侦察数据加载
│   ├── stage_target.py   # Stage 3: 目标创建 (双模式)
│   ├── stage_attack.py   # Stage 4: 攻击执行
│   └── stage_output.py   # Stage 5: 结果输出
├── tests/            # 单元测试
├── config.py         # CLI 参数解析
└── run.py            # 薄入口 (全局超时 + 优雅关闭 + 检查点)
```
