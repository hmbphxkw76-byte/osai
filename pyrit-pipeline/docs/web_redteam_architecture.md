# Web Red Team Framework — 通用认证感知红队架构方案

> **对齐标准**: L5 专家水平 · PyRIT 原生框架优先 · 零侵入扩展 · 配置驱动
> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 15:50 — 添加 R-006 时间标记; 更新文档头部

## 一、设计约束

| 约束 | 说明 |
|---|---|
| **不修改 PyRIT 任何原生代码** | 所有功能通过 `import pyrit.*` 调用公共 API |
| **原生 API 优先** | 优先使用 PyRIT 原生组件，自定义代码作为扩展层 |
| **通用化** | 不绑定任何特定目标 URL/域名，新目标仅需一个 YAML 文件 |
| **同域 + 跨域认证** | 两种认证拓扑均覆盖（SSO / OAuth / CAS） |
| **人工配合** | 滑块/扫码/验证码/OTP 由人工完成，程序自动感知并接管后续流程 |
| **L5 专家水平** | 配置驱动、关注点分离、单一职责、可测试 |

## 二、原生 API 映射表

| 框架模块 | 依赖的原生 PyRIT API | 角色 |
|---|---|---|
| Browser Session | `playwright.async_api` + `connect_over_cdp` | 浏览器生命周期 |
| Auth Detector | `Page.url` / `Page.query_selector` / `Page.context.cookies` | 认证完成感知 |
| Interaction Factory | `PlaywrightTarget(interaction_func=..., page=...)` | 目标创建 |
| Attack Orchestrator | `PromptSendingAttack` / `RedTeamingAttack` / `CrescendoAttack` / `TAPAttack` | 攻击执行 |
| Output | `pyrit.output.output_attack_async` / `output_scenario_async` | 结果输出 |
| Config | `pyrit.common.yaml_loadable.YamlLoadable` | YAML 配置加载 |
| Memory Init | `pyrit.setup.initialize_pyrit_async` | 框架初始化 |

## 三、目录结构

```
web_redteam/                              # 消费层根目录 (与 pipeline/ 平级, 不侵入 pyrit/)
│
├── targets/                               # 目标档案 (纯 YAML, 零代码)
│   ├── _schema.yaml                       # TargetProfile YAML Schema
│   ├── same_domain/                        # 同域认证目标
│   │   └── example_portal.yaml             # 示例: 单域名内完成认证
│   └── cross_domain/                       # 跨域认证目标 (SSO / OAuth / CAS)
│       └── example_sso.yaml                # 示例: SSO 单点登录
│
├── auth/                                   # 认证编排层
│   ├── __init__.py
│   ├── auth_detector.py                    # 多策略认证完成检测器
│   ├── browser_session.py                  # 浏览器会话管理器
│   ├── human_assisted_auth.py              # 人工辅助认证流程
│   └── auth_strategy.py                    # 认证策略选择器 (同域/跨域)
│
├── interaction/                            # 目标交互层
│   ├── __init__.py
│   ├── interaction_factory.py              # interaction_func 工厂
│   └── generic_chat_interaction.py         # 通用聊天 UI 交互函数
│
├── pipeline/                               # 流水线层
│   ├── __init__.py
│   ├── context.py                          # WebRedteamContext (状态容器)
│   ├── stage_init.py                       # Stage 1: PyRIT 初始化
│   ├── stage_auth.py                       # Stage 2: 认证
│   ├── stage_target.py                     # Stage 3: 目标创建
│   ├── stage_attack.py                     # Stage 4: 攻击执行
│   └── stage_output.py                     # Stage 5: 结果输出
│
├── config.py                               # CLI 参数解析
├── run.py                                  # 薄入口
├── tests/                                  # 测试
│   ├── __init__.py
│   ├── test_auth_detector.py
│   ├── test_browser_session.py
│   ├── test_interaction_factory.py
│   ├── test_target_profile.py
│   └── test_pipeline.py
└── README.md
```

## 四、核心数据流

```
run.py (薄入口)
  │
  ├── stage_init     → PyRIT 原生初始化
  ├── stage_auth     → 加载 Profile → 启动浏览器 → 人工辅助认证 → 检测完成 → 获取已认证 Page
  ├── stage_target   → 从 Profile 生成 interaction_func → 创建 PlaywrightTarget
  ├── stage_attack   → 选择攻击策略 → 执行攻击
  └── stage_output   → 输出 Markdown 报告
```

## 五、TargetProfile YAML Schema

```yaml
target:
  name: "example_portal"
  description: "示例平台 AI 助手"

auth:
  type: "same_domain"          # same_domain | cross_domain
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

## 六、认证流程

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

## 七、职责边界

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
| 填充 prompt + 发送 | ✅ | |
| 等待 AI 响应 | ✅ | |
| 攻击执行 | ✅ | |
| 结果输出 | ✅ | |

## 八、零侵入验证

所有模块仅通过 `import` + 调用 PyRIT 公共 API 工作，不修改任何原生文件。
