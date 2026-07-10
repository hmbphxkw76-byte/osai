# AI Recon — AI 侦测引擎

> Phase 1: Playwright 驱动的 AI 目标侦察与画像生成。
> 输出 `target_profile.json` → PyRIT Phase 2 攻击框架消费。

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt
playwright install chromium

# 基础扫描（仅 HTTP）
python main.py --target https://192.168.0.20

# 完整 SPA 侦察 + 登录
python main.py --target https://192.168.0.20 \
  --login-url https://192.168.0.20/login \
  --login-cred '{"username":"admin","password":"password"}'

# Cookie 注入模式（跳过登录）
python main.py --target https://192.168.0.20 \
  --auth-cookie "lab_session=abc123def456"

# 仅输出 JSON Schema（不执行侦测）
python main.py --profile-only schema.json
```

## 输出格式

输出 `target_profile.json` 遵循标准 schema（见 [recon/schema.py](recon/schema.py)）：

```json
{
  "meta": { "version": "1.0", "target_url": "..." },
  "target": { "base_url": "...", "chat_api_url": "...", ... },
  "auth": { "type": "cookie", "session_cookie": "...", ... },
  "api_endpoints": [{ "path": "...", "method": "POST", "category": "chat", ... }],
  "dynamic_routes": [{ "pattern": "...", "sample_value": "...", ... }],
  "spa_info": { "is_spa": true, "framework": "react", ... },
  "rate_limit": { "recommended_concurrency": 3, ... }
}
```

## 与 PyRIT 桥接

```bash
# Step 1: AI 侦测
cd recon/
python main.py --target https://192.168.0.20 --output outputs/
# → 生成 outputs/target_profile_192.168.0.20.json

# Step 2: PyRIT 攻击（读取 profile）
cd ../pyrit/
python main.py --lang cn \
  --target-profile ../recon/outputs/target_profile_192.168.0.20.json \
  --phase all --auto-gate --gate-threshold 0.10
```

## 目录结构

```
recon/
├── main.py                     # 入口（CLI）
├── recon/
│   ├── __init__.py             # 包定义
│   ├── schema.py               # target_profile.json Schema 定义
│   ├── engine.py               # 核心引擎（流程编排）
│   ├── browser.py              # Playwright 浏览器管理
│   ├── login.py                # 认证流程自动化
│   ├── traffic_capture.py      # Network 流量捕获
│   ├── spa_router.py           # SPA 框架检测 + 路由提取
│   ├── endpoint_infer.py       # API 端点分类 + Chat 推断
│   ├── dict_scan.py            # 字典扫描
│   └── profile_builder.py      # Profile 组装清洗
├── wordlists/
│   ├── llm_paths.txt           # LLM API 路径词表
│   └── web_paths.txt           # Web 应用路径词表
├── outputs/                    # 侦察输出
├── requirements.txt
└── README.md
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
