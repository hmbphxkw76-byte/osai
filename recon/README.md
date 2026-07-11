# Recon — L0 前置侦察引擎

> Playwright 驱动的 AI 目标侦察与画像生成，输出 `target_profile.json` → 流水线后续阶段消费。

## 快速开始

```bash
# 通过统一流水线（推荐）
make recon TARGET=https://target.com

# 或直接调用
python main.py --target https://target.com

# 完整 SPA 侦察 + 登录
python main.py --target https://target.com \
  --login-url https://target.com/login \
  --login-cred '{"username":"admin","password":"password"}'

# Cookie 注入模式（跳过登录）
python main.py --target https://target.com \
  --storage-state session.json
```

## 针对认证 AI 应用的四步工作流

针对需要登录认证的 AI Web 应用（如千问、Kimi、Dify、企业内网 AI 助手），推荐以下流程：

### 1. 获取 Cookie → 转换为 storageState

在浏览器中登录目标 AI 应用后，打开 DevTools (F12) → Network 标签，找到任一 API 请求，右键选择 **Copy as cURL (bash)**，然后使用工具转换：

```bash
python tools/cookie_to_authfile.py -o qianwen_auth.txt
# 交互式粘贴，支持 Copy as cURL / Copy request headers / 纯 Cookie 字符串三种格式自动识别
```

`--storage-state` 会自动识别三种格式：

- Playwright `storageState.json`（完整会话，含 cookies + localStorage + sessionStorage）
- 纯 Cookie 字符串，如 `session=abc123; token=xyz`
- Netscape `cookies.txt` 格式

### 2. L0 前置侦察（带 Cookie 认证）

```bash
python main.py --target https://www.qianwen.com \
  --storage-state qianwen_auth.txt \
  --har-output outputs/traffic.har
```

引擎将自动：① 浏览器渲染 SPA → ② 捕获 XHR/fetch 请求 → ③ 识别 Chat API 端点 → ④ 推断认证机制 → ⑤ 生成 `target_profile.json`。HAR 文件可用 Chrome DevTools / harviewer / haralyzer 离线分析。

> ⚠️ 如遇反爬（滑块/Cloudflare）：评估是否使用 `--stealth patchright` 或 `--stealth playwright_stealth`。商业 AI 平台通常有 Bot 检测，可能需要手动处理验证码后再导出 Cookie。

### 3. Cookie 过期处理 — 自动登录（可选）

如果 Cookie 频繁过期（通常 15-30 分钟），可填写登录凭据实现自动登录：

```bash
python main.py --target https://www.qianwen.com \
  --login-url https://www.qianwen.com/login \
  --login-cred '{"username":"your_account","password":"your_pwd"}'
```

引擎将在每次扫描前自动执行登录流程，无需手动刷新 Cookie。支持表单登录和 SSO 跳转识别。

### 4. L1-L4 全流程攻击（从侦察结果到深度对抗）

```bash
python pipeline.py --target https://www.qianwen.com --stage recon
python pipeline.py --target https://www.qianwen.com --stage garak
python pipeline.py --target https://www.qianwen.com --stage pyrit
```


## 输出格式

输出 `target_profile.json` 遵循标准 schema（见 `recon/schema.py`）：

```json
{
  "meta": { "version": "1.0", "target_url": "..." },
  "target": { "base_url": "...", "chat_api_url": "...", "..." },
  "auth": { "type": "cookie", "session_cookie": "...", "..." },
  "api_endpoints": [{ "path": "...", "method": "POST", "category": "chat", "..." }],
  "dynamic_routes": [{ "pattern": "...", "sample_value": "...", "..." }],
  "spa_info": { "is_spa": true, "framework": "react", "..." },
  "rate_limit": { "recommended_concurrency": 3, "..." }
}
```

## 目录结构

```
recon/
├── __init__.py          # 公开 API 导出
├── engine.py            # ReconEngine 核心编排
├── schema.py            # TargetProfile 数据模型
├── module_registry.py   # 模块注册表
├── main.py              # CLI 入口
├── analysis/            # 端点推断 + 行为映射 + 画像构建
├── auth/                # 登录自动化
├── probes/              # 模型探测 + Prompt 提取 + RAG 探测
├── scanners/            # 浏览器/字典/JS SDK/WAF/凭证/SPA/流量
├── web/                 # Flask Web 界面
├── templates/           # Web 模板
├── wordlists/           # 字典词表
└── outputs/             # 侦察输出
```

## CLI 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--target`, `-t` | 目标 URL | **必填** |
| `--output`, `-o` | 输出目录 | `outputs` |
| `--login-url` | 登录页面 URL | - |
| `--login-cred` | 登录凭据 JSON | - |
| `--storage-state` | 会话状态文件 (支持 storageState / Cookie 字符串 / Netscape cookies.txt) | - |
| `--auth-cookie` | 直接注入 Cookie 字符串 (临时) | - |
| `--auth-bearer` | Bearer Token | - |
| `--auth-header` | 自定义认证头，可多次使用 | - |
| `--no-spa` | 禁用浏览器渲染 | - |
| `--no-js-extract` | 禁用 JS 提取 | - |
| `--no-traffic` | 禁用流量捕获 | - |
| `--dict-scan` | 启用字典扫描 | - |
| `--headed` | 显示浏览器窗口 | - |
| `--stealth` | 反检测模式 (`auto`/`cloakbrowser`/`patchright`/`playwright_stealth`/`none`) | `auto` |
| `--chrome-path` | CloakBrowser / 系统 Chrome 可执行路径 | - |
| `--no-humanize` | 禁用人机行为模拟 | - |
| `--har-output` | HAR 流量录制文件路径 | - |
| `--concurrency` | 并发数 | `2` |
| `--timeout` | 请求超时秒数 | `30` |
| `--dump-har` | 导出 HAR 日志到 output_dir (旧参数，建议用 `--har-output`) | - |
| `--profile-only` | 仅输出 JSON Schema 定义到文件 | - |

## 常见问题

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| Cookie 太长命令行报错 | Windows CMD/PowerShell 长度上限 ~8191 字符 | 用 `--storage-state` 传入文件路径，避免在命令行粘贴长 Cookie |
| 侦察 401/403 | Cookie 过期，或缺少 CSRF / localStorage / sessionStorage | 使用 `--storage-state` 恢复完整浏览器状态；或用 `--manual-login` 完成 MFA 后自动保存 |
| storageState 加载失败 | 文件不存在、格式错误、Playwright 不兼容 | 确保文件为 storageState.json / 纯 Cookie / Netscape cookies.txt 之一；用 `--manual-login` 重新导出 |
| HAR 文件为空 | 禁用流量捕获，或页面未触发请求 | 不要加 `--no-traffic`；确保目标页面已加载并产生 XHR/fetch |
| 浏览器触发验证码 | 反爬/Bot 检测 | `--headed --manual-login` 手动验证；或 `--stealth patchright` |
| Chat API 未发现 | SPA 渲染或流量捕获未生效 | 去掉 `--no-spa`/`--no-traffic`；用 `--har-output` 录制后手动分析 |
| SSL 证书错误 | 内网自签名证书未信任 | 去掉 `--verify-ssl`，或上传企业 CA `.pem` |

> **Web UI 扫描完成后仍转圈？** 不属于预期行为。扫描完成（或失败）时前端应停止转圈并显示最终耗时。如果仍看到转圈，请刷新页面查看最新状态，并检查 `outputs/` 下是否已生成 `target_profile_*.json`。
