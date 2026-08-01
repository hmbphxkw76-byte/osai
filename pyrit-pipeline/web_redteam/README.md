# Web Red Team Framework

> 通用认证感知红队框架 — 基于 PyRIT 原生 API, 零侵入扩展

## 快速开始

### 1. 安装依赖

```bash
pip install pyrit[playwright]
playwright install chromium
```

### 2. 创建目标 Profile

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

### 3. 运行攻击

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

### 4. 运行测试

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

## 支持的认证检测策略

| 策略 | 说明 |
|---|---|
| `url_pattern` | URL 正则匹配 |
| `dom_element` | DOM 元素存在 |
| `cookie_presence` | Cookie 存在 |
| `network_token` | 网络响应 Token 拦截 |

## 目录结构

```
web_redteam/
├── targets/          # YAML 配置 (零代码接入新目标)
├── auth/             # 认证编排 (检测/浏览器/人工辅助/策略)
├── interaction/      # 目标交互 (interaction_func 工厂)
├── pipeline/         # 五阶段流水线
├── tests/            # 单元测试 (66 tests)
├── config.py         # CLI 参数解析
└── run.py            # 薄入口
```
