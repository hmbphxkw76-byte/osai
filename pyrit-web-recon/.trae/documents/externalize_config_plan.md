# pyrit-web-recon 配置外部化实施计划

## Context

用户要求：除最优默认参数值外，其余变量不应硬编码，而应通过 `.env` / YAML 配置 / CLI 参数等方式统一赋值。当前项目虽已具备 `config/recon.yaml`、`config/spa_chat.yaml` 和 `.env` 加载机制，但 `src/` 中大量数值、字符串、超时时间仍以硬编码形式存在，未从配置读取。

## Current State

- `main.py` 的 `_default_config()` 仅包含少量顶层默认值；`load_yaml_config()` 已可加载 YAML。
- `config/recon.yaml` 已定义 `browser_connection`、`network`、`api_probe` 等节点，但代码中多处未读取。
- `config/spa_chat.yaml` 已定义 `selector_timeout_ms`、`post_send_wait_ms`、`manual_login_*`、`screenshots` 等，但部分未被使用。
- `PipelineStage` 提供 `_config(context, key, default)` 和 `_spa_config(context, key, default)` 辅助方法。
- `.env.example` 按项目规则仅保留 `RECON_TARGET_URL` 与可选的 `RECON_USERNAME` / `RECON_PASSWORD`。

## Config Schema Design

### config/recon.yaml（浏览器、网络、API 探测）

在现有 `browser_connection` 基础上补充 `user_agent`；新增/明确 `network`、`api_probe` 节点。

```yaml
browser_connection:
  wait_until: domcontentloaded
  timeout: 30000
  ignore_https_errors: true
  post_load_wait: 2
  viewport:
    width: 1366
    height: 768
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

network:
  request_body_limit: 5000
  response_body_limit: 5000
  websocket_payload_limit: 2000
  text_length_limit: 5000

api_probe:
  force_api_probe: false
  ollama_model: "llama2"
  openai_model: "gpt-3.5-turbo"
  probe_prompt: "hi"
  response_body_limit: 5000
```

### config/spa_chat.yaml（DOM、聊天交互、截图）

在已有键基础上补充 DOM 等待、截断、响应超时等参数。

```yaml
selector_timeout_ms: 5000
entry_discovery_timeout_ms: 5000
send_probe_text: "你好，请介绍一下你自己。"
post_send_wait_ms: 3000
type_delay_ms: 500
send_strategy_wait_ms: 1500
click_timeout_ms: 3000
response_timeout_ms: 5000
response_text_limit: 1000
response_html_limit: 2000
max_retries: 2
```

### CLI / 环境变量

保持 `.env.example` 不变，不新增大量环境变量。高频参数已有 CLI 参数覆盖：

- `--headless`, `--type`, `--auth-mode`, `--probe`, `--no-send`
- `--manual-login`, `--manual-login-timeout`, `--manual-login-require-enter`
- `--login-url`, `--username`, `--password`

非高频参数通过修改 YAML 配置调整。

## File-by-File Refactoring Plan

### 1. src/browser_manager.py

`start()` / `navigate()` 已从 `connection` 读取 `viewport`、`ignore_https_errors`、`wait_until`、`timeout`、`post_load_wait`。**唯一需要外部化的是 `user_agent`**。

- 将硬编码 UA 改为从 `connection.get("user_agent", "<default>")` 读取。

### 2. src/pipeline/stages/navigation.py

将 `browser_connection` 配置传入 `BrowserManager`。

```python
connection = self._config(context, "browser_connection", {})
browser = BrowserManager(...)
await browser.start(url=context.target_url, connection=connection)
```

### 3. src/dom/detector.py

在 `__init__` 中读取 DOM 等待与截断参数，替换硬编码值：

- `selector_timeout_ms`：已读取，但部分位置仍写死 5000，统一使用 `self.selector_timeout_ms`
- `type_delay_ms` → 替换 `wait_for_timeout(500)`
- `send_strategy_wait_ms` → 替换三处 `wait_for_timeout(1500)`
- `click_timeout_ms` → 替换 `btn.click(timeout=3000)`
- `response_text_limit` → 替换响应文本 `[:1000]`
- `response_html_limit` → 替换响应 HTML `[:2000]`

### 4. src/dom/chat_entry.py

函数签名已支持 `timeout_ms`，调用方在 `entry_discovery.py` 中传入 `entry_discovery_timeout_ms`。

### 5. src/pipeline/stages/entry_discovery.py

- 调用 `discover_chat_entry` 时传入 `entry_discovery_timeout_ms`
- `_click_entry` 中硬编码的 5000ms/2000ms 等待改为 `click_timeout_ms` / `entry_click_wait_ms`

### 6. src/interaction/web_chat.py

- `post_send_wait_ms` 已读取
- `get_last_response()` 默认 `timeout_ms` 改为从 `self.config.get("response_timeout_ms", 5000)` 读取

### 7. src/pipeline/stages/probe_interaction.py

已通过 `_spa_config` 读取 `send_probe_text`、`post_send_wait_ms`、`max_retries`，无需额外改动。

### 8. src/pipeline/stages/api_probe.py

新增 `api_probe` 配置读取，替换硬编码：

- `force_api_probe`
- `ollama_model`, `openai_model`, `probe_prompt`
- `response_body_limit`（替换 `resp.text[:5000]`）
- `httpx_timeout`（替换 `httpx.AsyncClient(timeout=20.0)`）

### 9. src/auth/credential_extractor.py

- 构造函数接收 `config`
- UA 从 `config["browser_connection"]["user_agent"]` 读取
- body 长度限制从 `config["network"]["text_length_limit"]` 读取

在 `CredentialExtractionStage` 实例化时传入 `context.config`。

### 10. src/utils/login_waiter.py

已通过调用方参数化 `timeout_ms`、`poll_interval_ms`、`require_enter`。补充：

- `CAPTCHA_SELECTORS` 允许调用方通过 `captcha_selectors` 参数覆盖。

### 11. src/network/interceptor.py

在 `__init__` 中读取 `network` 配置：

- `request_body_limit` → 替换 `post_data[:5000]`
- `response_body_limit` → 替换响应体 `[:5000]`
- `websocket_payload_limit` → 替换 `payload[:2000]`

### 12. src/network/traffic_analyzer.py

构造函数接收 `config`，读取 `text_length_limit`，替换 `_extract_model_from_text` 中硬编码 5000。

使用处传入 `network` 配置：
- `src/network/interceptor.py`
- `src/pipeline/stages/api_probe.py`
- `src/pipeline/stages/analysis.py`

## Default Value Strategy

- **代码 fallback 为最终兜底**：每个 `.get(key, default)` 保留与当前硬编码相同的默认值，确保无配置文件也能运行。
- **YAML 为文档化默认值**：将相同默认值写入 `config/recon.yaml` 与 `config/spa_chat.yaml`，用户可直观覆盖。
- **避免与 `_default_config()` 重复**：`_default_config()` 仅保留顶层结构默认值，不再重复写入已由 YAML 承载的参数。
- **单一 UA 来源**：`browser_connection.user_agent` 为唯一 UA 来源，`credential_extractor.py` 通过 `context.config` 复用。

## Verification

1. 配置加载冒烟测试：
   ```bash
   python -c "from main import load_yaml_config; c=load_yaml_config('config/recon.yaml'); print(c['browser_connection']['viewport']); print(c['network']['response_body_limit'])"
   ```

2. CLI help 检查：
   ```bash
   python main.py --help
   ```

3. Mock LLM 完整流水线测试：
   ```bash
   # 终端 1
   python tests/mock_llm_server.py
   # 终端 2
   python main.py http://127.0.0.1:18080 --type spa --headless
   ```
   验证 `results/recon/profiles/` 与摘要正常生成。

4. 配置覆盖生效测试：临时修改 `config/spa_chat.yaml` 的 `post_send_wait_ms` 为 `5000`，重新执行 Mock 测试，确认无异常。

5. API 目标分支测试：
   ```bash
   python main.py http://127.0.0.1:18080/api/chat --type api
   ```

## Critical Files for Implementation

- `d:\文档\GitHub\osai\pyrit-web-recon\config\recon.yaml`
- `d:\文档\GitHub\osai\pyrit-web-recon\config\spa_chat.yaml`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\browser_manager.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\pipeline\stages\navigation.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\dom\detector.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\pipeline\stages\entry_discovery.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\interaction\web_chat.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\pipeline\stages\api_probe.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\auth\credential_extractor.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\pipeline\stages\credential_extraction.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\network\interceptor.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\network\traffic_analyzer.py`
- `d:\文档\GitHub\osai\pyrit-web-recon\src\utils\login_waiter.py`
