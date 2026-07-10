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
  --auth-cookie "lab_session=abc123def456"
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

## 与流水线桥接

```bash
# L0 侦察 → 后续阶段自动消费 profile
python pipeline.py --target https://target.com --stage recon
python pipeline.py --target https://target.com --stage garak    # 读取 profile
python pipeline.py --target https://target.com --stage pyrit    # 读取 profile
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
| `--auth-cookie` | 注入 Cookie | - |
| `--auth-bearer` | Bearer Token | - |
| `--auth-header` | 自定义认证头 | - |
| `--no-spa` | 禁用浏览器渲染 | - |
| `--no-js-extract` | 禁用 JS 提取 | - |
| `--dict-scan` | 启用字典扫描 | - |
| `--headed` | 显示浏览器窗口 | - |
| `--concurrency` | 并发数 | `5` |
| `--timeout` | 超时秒数 | `30` |
| `--dump-har` | 导出 HAR 日志 | - |
| `--profile-only` | 仅输出 Schema | - |
