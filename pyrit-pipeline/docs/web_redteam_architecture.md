# Web Red Team Framework — 通用认证感知红队架构方案

> **对齐标准**: L5 专家水平 · PyRIT 原生框架优先 · 零侵入扩展 · 配置驱动
> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-2 00:00 — v2.0: 补充 AuthProbe 自动探测、DynamicProfile 快速模式、认证策略详解、交互层架构
>   2026-8-1 15:50 — 添加 R-006 时间标记; 更新文档头部

## 一、设计约束

| 约束 | 说明 |
|---|---|
| **不修改 PyRIT 任何原生代码** | 所有功能通过 `import pyrit.*` 调用公共 API |
| **原生 API 优先** | 优先使用 PyRIT 原生组件，自定义代码作为扩展层 |
| **通用化** | 不绑定任何特定目标 URL/域名，新目标仅需一个 YAML 文件 |
| **同域 + 跨域认证** | 两种认证拓扑均覆盖（SSO / OAuth / CAS） |
| **自动探测** | `auth.type = "auto"` 时自动判断认证拓扑（无需手动配置） |
| **人工配合** | 滑块/扫码/验证码/OTP 由人工完成，程序自动感知并接管后续流程 |
| **L5 专家水平** | 配置驱动、关注点分离、单一职责、可测试 |

## 二、原生 API 映射表

| 框架模块 | 依赖的原生 PyRIT API | 角色 |
|---|---|---|
| Browser Session | `playwright.async_api` + `connect_over_cdp` | 浏览器生命周期 |
| Auth Detector | `Page.url` / `Page.query_selector` / `Page.context.cookies` | 认证完成感知 |
| Auth Probe | `Page.url` / `Page.query_selector` / `Page.wait_for_url` | 自动认证拓扑探测 |
| Interaction Factory | `PlaywrightTarget(interaction_func=..., page=...)` | 目标创建 |
| Attack Orchestrator | `PromptSendingAttack` / `RedTeamingAttack` / `CrescendoAttack` / `TAPAttack` | 攻击执行 |
| Output | `pyrit.output.output_attack_async` / `output_scenario_async` | 结果输出 |
| Config | `pyrit.common.yaml_loadable.YamlLoadable` | YAML 配置加载 |
| Memory Init | `pyrit.setup.initialize_pyrit_async` | 框架初始化 |

## 三、目录结构

```
web_bridge/                              # 消费层根目录 (与 pipeline/ 平级, 不侵入 pyrit/)
│
├── targets/                               # 目标档案 (纯 YAML, 零代码)
│   ├── _schema.yaml                       # TargetProfile YAML Schema
│   ├── target_profile.py                  # TargetProfile 数据模型 (from YAML)
│   ├── dynamic_profile.py                 # 动态 Profile 生成器 (--target-url 快速模式)
│   ├── same_domain/                        # 同域认证目标
│   │   ├── example_portal.yaml             # 示例: 单域名内完成认证
│   │   ├── example_open_target.yaml        # 示例: 无需认证的开放目标
│   │   └── example_auto_detect.yaml        # 示例: auto 自动探测模式
│   └── cross_domain/                       # 跨域认证目标 (SSO / OAuth / CAS)
│       └── example_sso.yaml                # 示例: SSO 单点登录
│
├── auth/                                   # 认证编排层
│   ├── __init__.py
│   ├── auth_detector.py                    # 多策略认证完成检测器 (4 种策略)
│   ├── auth_probe.py                       # 自动认证探测器 (auto 模式)
│   ├── browser_session.py                  # 浏览器会话管理器 (CDP + storage_state)
│   ├── human_assisted_auth.py              # 人工辅助认证流程
│   └── auth_strategy.py                    # 认证策略选择器 (同域/跨域/auto)
│
├── interaction/                            # 目标交互层
│   ├── __init__.py
│   ├── interaction_factory.py              # interaction_func 工厂
│   └── generic_chat_interaction.py         # 通用聊天 UI 交互函数
│
├── pipeline/                               # 流水线层
│   ├── __init__.py
│   ├── context.py                          # WebBridgeContext (状态容器)
│   ├── stage_init.py                       # Stage 1: PyRIT 初始化
│   ├── stage_auth.py                       # Stage 2: 认证
│   ├── stage_target.py                     # Stage 3: 目标创建
│   ├── stage_attack.py                     # Stage 4: 攻击执行
│   └── stage_output.py                     # Stage 5: 结果输出
│
├── config.py                               # CLI 参数解析
├── run.py                                  # 薄入口
├── tests/                                  # 测试 (9 个测试文件)
│   ├── __init__.py
│   ├── test_auth_detector.py
│   ├── test_auth_probe.py
│   ├── test_auto_auth_strategy.py
│   ├── test_browser_session.py
│   ├── test_credential_auto_fill.py
│   ├── test_dynamic_profile.py
│   ├── test_interaction_factory.py
│   ├── test_pipeline.py
│   └── test_target_profile.py
└── README.md
```

## 四、核心数据流

```
run.py (薄入口)
  │
  ├── stage_init     → PyRIT 原生初始化
  ├── stage_auth     → 加载 Profile → 启动浏览器 → 人工辅助认证 → 检测完成 → 获取已认证 Page
  │                     (auto 模式: AuthProbe 自动探测拓扑 → 选择策略)
  ├── stage_target   → 从 Profile 生成 interaction_func → 创建 PlaywrightTarget
  ├── stage_attack   → 选择攻击策略 → 执行攻击 (带超时保护 + 自动重试)
  └── stage_output   → 输出 Markdown 报告
```

## 五、认证层架构

### 5.1 AuthDetector — 多策略认证完成检测

支持四种检测策略 (OR 逻辑, 任一满足即认为认证完成):

| 策略 | 类名 | 检测方式 | 原生对齐 |
|---|---|---|---|
| `url_pattern` | `URLPatternStrategy` | `page.url` 匹配正则 | `CopilotAuthenticator` URL 检测 |
| `dom_element` | `DOMElementStrategy` | `page.query_selector` 检测元素 | `PlaywrightCopilotTarget` 元素等待 |
| `cookie_presence` | `CookiePresenceStrategy` | `page.context.cookies()` 检测 Cookie | Playwright 原生 `context.cookies()` |
| `network_token` | `NetworkTokenStrategy` | `page.on("response", handler)` 拦截 Token | `CopilotAuthenticator.response_handler_async` |

`AuthDetector` 以轮询方式运行，`poll_interval_seconds` 控制检测频率，`timeout_seconds` 控制超时。

### 5.2 AuthProbe — 自动认证拓扑探测

当 `auth.type = "auto"` 时，`AuthProbe` 自动判断认证拓扑:

1. 导航到 `target_url`
2. 观察页面行为 (URL 变化 / DOM 特征 / HTTP 状态)
3. 判断结果:
   - **none**: 页面直接加载成功，无重定向到登录页 → 无需认证
   - **same_domain**: 同域名下出现 login/auth/signin → 同域认证
   - **cross_domain**: 重定向到不同域名的 IdP → 跨域认证

判断依据:
- URL 域名变化: `target_url` 域名 ≠ 最终页面域名 → `cross_domain`
- URL 路径变化但域名不变: 出现 `login/auth/signin` 关键词 → `same_domain`
- URL 无变化且页面正常加载 → `none`
- DOM 特征辅助: `<input type="password">` 存在 → 需要认证

### 5.3 AuthStrategy — 认证策略选择器

| `auth.type` | 策略类 | 行为 |
|---|---|---|
| `none` | `NoAuthStrategy` | 直接导航到 `target_url`，不执行认证 |
| `same_domain` | `SameDomainAuthStrategy` | 导航 → 自动填充 → 人工步骤 → 检测完成 |
| `cross_domain` | `CrossDomainAuthStrategy` | 导航 → 追踪重定向链 → IdP 认证 → 回调检测 |
| `auto` | `AutoAuthStrategy` | 调用 `AuthProbe` 探测 → 自动选择上述策略 |

### 5.4 BrowserSession — 浏览器会话管理

支持两种模式:
1. **`launch_with_debug_port()`**: 启动新浏览器，开启 CDP 调试端口 → 人工可在浏览器窗口中操作
2. **`connect_via_cdp()`**: 连接已有浏览器会话 (复用已登录状态)

认证状态持久化:
- **`save_storage_state()`**: 保存 cookies + localStorage 到 JSON
- **`restore_storage_state()`**: 从 JSON 恢复，跳过重复认证

### 5.5 HumanAssistedAuth — 人工辅助认证流程

职责分工:

| 操作 | 程序 | 人工 |
|---|---|---|
| 启动浏览器 + CDP | ✅ | |
| 导航到登录页 | ✅ | |
| 填充用户名/密码 | ✅ | |
| 图形验证码 | | ✅ |
| 滑块验证 | | ✅ |
| 扫码登录 | | ✅ |
| OTP 短信验证码 | | ✅ |
| 跨域重定向追踪 | ✅ | |
| 认证完成检测 | ✅ | |
| 跳转到聊天页 | ✅ | |
| 认证状态持久化 | ✅ | |

## 六、交互层架构

### 6.1 InteractionFactory

从 `TargetProfile.interaction` 配置生成符合 `PlaywrightTarget.InteractionFunction` Protocol 的异步函数:

```python
interaction_func = InteractionFactory.create(profile.interaction)
target = PlaywrightTarget(interaction_func=interaction_func, page=page)
```

### 6.2 GenericChatInteraction

通用聊天 UI 交互函数生成器，支持:

| 配置项 | 支持值 | 说明 |
|---|---|---|
| `input.type` | `textarea`, `contenteditable`, `input` | 输入框类型 |
| `send.selector` | CSS 选择器 | 发送按钮 |
| `send.shortcut` | `Enter`, `Ctrl+Enter` | 键盘快捷键发送 |
| `response.wait_strategy` | `new_element`, `text_stable`, `loading_gone` | 响应等待策略 |
| `response.stability_threshold_ms` | 整数 | 文本稳定阈值 |
| `response.loading_selector` | CSS 选择器 | Loading 指示器 |
| `extraction.text_selector` | CSS 选择器 | 响应文本提取选择器 |

交互流程 (对齐 `doc/code/targets/10_1_playwright_target.py`):
1. 记录当前 AI 消息数量
2. 填充输入框 (`page.fill` / `page.type` / `page.evaluate`)
3. 点击发送按钮 (`page.click`) 或发送快捷键 (`page.keyboard.press`)
4. 等待新消息出现 (`page.wait_for_selector` / `page.wait_for_function`)
5. 提取响应文本 (`element.text_content` / `page.evaluate`)

## 七、TargetProfile YAML Schema

```yaml
target:
  name: "example_portal"
  description: "示例平台 AI 助手"

auth:
  type: "same_domain"          # same_domain | cross_domain | auto | none
  login_url: "https://..."
  target_url: "https://..."

  same_domain:                  # 同域认证检测配置
    detection:
      - strategy: "url_pattern"
        pattern: "example\\.com/chat"
      - strategy: "dom_element"
        selector: ".chat-container"

  cross_domain:                 # 跨域认证配置
    redirect_chain:
      - domain: "app.example.com"
        auth_action: "redirect_to_idp"
      - domain: "sso.idp.com"
        auth_action: "login_form"
        human_steps: ["captcha"]
      - domain: "app.example.com"
        auth_action: "callback"
    detection:
      - strategy: "url_pattern"
        pattern: "app\\.example\\.com/chat"

  auto_fill:                    # 自动填充 (可选)
    "#username": "${TARGET_USERNAME}"
    "#password": "${TARGET_PASSWORD}"

  human_assisted_steps:         # 人工辅助步骤声明
    - "captcha"
    - "slider"
    - "qr_scan"
    - "otp"

interaction:
  input:
    selector: "textarea#chat-input"
    type: "textarea"            # textarea | contenteditable | input
  send:
    selector: "button.send-btn"
  response:
    selector: "div.ai-message"
    wait_strategy: "new_element"  # new_element | text_stable | loading_gone
    stability_threshold_ms: 2000
    loading_selector: ".typing-indicator"
  extraction:
    text_selector: "p.response-text"

attack_defaults:
  attack_type: "red_teaming"
  max_turns: 10
```

### 7.1 DynamicProfile — 快速模式

当用户通过 `--target-url` 快速模式运行时，`DynamicProfile` 从 URL 自动生成最小化 `TargetProfile`:

- `auth.type = "auto"` (自动探测认证)
- `auth.target_url` = 用户指定的 URL
- `interaction` = 通用默认选择器 (可被 CLI 覆盖)
- `attack_defaults` = 合理默认值 (可被 CLI 覆盖)

内置通用选择器覆盖常见前端框架:
- 用户名: `input[name="username"]`, `input[type="email"]`, `input[placeholder*="用户名"]` 等
- 密码: `input[name="password"]`, `input[type="password"]` 等
- 聊天输入: `textarea`, `[contenteditable]`, `input[type="text"]` 等
- 发送按钮: `button[type="submit"]`, `button[aria-label*="send"]` 等

## 八、认证流程

### 同域认证

```
程序启动浏览器 → 导航到 login_url → 自动填充账密 →
人工完成验证码/滑块/扫码/OTP → AuthDetector 检测 URL 变化 + DOM 元素 →
认证完成 → 跳转到 target_url → 保存 storage_state
```

### 跨域认证 (SSO/OAuth/CAS)

```
程序启动浏览器 → 导航到 login_url → 页面重定向到 IdP →
framenavigated 追踪域名跳转 → 在 IdP 上自动填充 →
人工完成验证码/扫码 → IdP 重定向回应用域名 →
AuthDetector 检测回到目标域名 + DOM 元素 → 认证完成
```

### Auto 自动探测

```
程序启动浏览器 → 导航到 target_url → AuthProbe 观察页面行为 →
判断拓扑 (none / same_domain / cross_domain) →
自动选择对应策略执行 (或直接跳过认证)
```

## 九、攻击执行

### Stage 4: AttackFactory

| `attack_type` | PyRIT 原生类 | 说明 |
|---|---|---|
| `prompt_sending` | `PromptSendingAttack` | 单轮发送 |
| `red_teaming` | `RedTeamingAttack` | 多轮对抗 |
| `crescendo` | `CrescendoAttack` | 渐进越狱 |
| `tap` | `TAPAttack` | 树状探索 |

安全机制:
- **超时保护**: `_ATTACK_TIMEOUT_SECONDS = 300` (5 分钟)
- **自动重试**: `_ATTACK_MAX_RETRIES = 3` (网络错误自动重试)

## 十、零侵入验证

所有模块仅通过 `import` + 调用 PyRIT 公共 API 工作，不修改任何原生文件。

验证清单:
- ✅ `auth/` — 仅使用 Playwright 原生 API (`Page`, `BrowserContext`)
- ✅ `interaction/` — 仅符合 `PlaywrightTarget.InteractionFunction` Protocol
- ✅ `pipeline/stage_attack.py` — 仅调用 `pyrit.executor.attack.*`
- ✅ `pipeline/stage_init.py` — 仅调用 `pyrit.setup.initialize_pyrit_async`
- ✅ `pipeline/stage_output.py` — 仅调用 `pyrit.output.output_attack_async`
- ✅ `targets/target_profile.py` — 继承 `pyrit.common.yaml_loadable.YamlLoadable`

## 十一、学术依据

| 论文 | 关联模块 | 要点 |
|---|---|---|
| PyRIT (arXiv:2407.01232) | 全局架构 | Python Risk Identification Toolkit 框架设计 |
| JailbreakBench (arXiv:2402.01135) | 攻击评估 | 标准化越狱评估基准 |
| Crescendo (arXiv:2404.01833) | CrescendoAttack | 渐进式多轮越狱策略 |
| TAP (arXiv:2312.02119) | TAPAttack | 树状结构自动越狱 |
