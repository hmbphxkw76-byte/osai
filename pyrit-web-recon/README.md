# pyrit-web-recon

全面侦察基于 LLM 的 Web 应用目标：支持 SPA 浮动入口发现、三级发送降级、LLM API 流量识别、认证注入与标准化的 TargetProfile 输出。

## 核心能力

- **智能入口发现**：自动发现 AI 助手 / 客服 / Copilot / Agent 浮动按钮，支持 900+ 内置选择器 + 评分扫描兜底。
- **DOM 侦察**：评分机制识别输入框、发送按钮、响应区。
- **三级发送降级**：Enter 键 → 发送按钮点击 → 父容器点击，适配各类 LLM 聊天界面。
- **网络流量分析**：拦截 XHR/fetch/WebSocket，识别 OpenAI / Claude / Gemini / 文心 / 通义 / 星火 / Kimi / DeepSeek / Ollama 等 LLM API，解析 SSE / JSON 响应并提取模型名、通信协议（SSE / WebSocket / gRPC-Web）。
- **LLM 特征识别**：从流量中提取 API Key / Bearer Token 线索，识别 RAG（知识库 / 检索 / 向量）与 Agent / Copilot / MCP 组件特征。
- **认证注入**：从 `credentials/{domain}.txt` 解析 Headers，自动注入 Cookie / Bearer / 自定义头，支持 storage_state 复用。
- **人工登录等待**：检测到登录页时自动暂停，等待用户完成账号密码、验证码、拼图/滑块、OTP/扫码等登录步骤，完成后自动继续侦察。
- **凭据自动保存**：登录成功后自动从浏览器提取 Cookie / Token 并保存到 `credentials/{domain}.txt`，后续侦察可直接复用。
- **标准化输出**：生成 `TargetProfile` JSON/YAML，导出 Burp / Repeater 攻击模板。

## 项目结构

```text
pyrit-web-recon/
├── config/
│   ├── recon.yaml              # 全局侦察配置
│   ├── sites.yaml              # 已知站点选择器
│   └── spa_chat.yaml           # SPA 侦察配置
├── credentials/                # 按域名存放 Headers 凭据
├── src/
│   ├── auth/                   # 认证解析、注入与自动提取
│   │   ├── header_parser.py
│   │   ├── playwright_injector.py
│   │   └── credential_extractor.py
│   ├── browser_manager.py      # Playwright 生命周期
│   ├── credential_manager.py   # 凭据解析与适配
│   ├── dom/                    # DOM 侦察
│   │   ├── selector_pool.py
│   │   ├── chat_entry.py
│   │   └── detector.py
│   ├── network/                # 网络流量分析
│   │   ├── interceptor.py
│   │   └── traffic_analyzer.py
│   ├── utils/                  # 通用工具
│   │   └── login_waiter.py
│   ├── recon/                  # 侦察引擎
│   │   ├── engine.py
│   │   ├── spa_recon.py
│   │   └── target_profile.py
│   ├── interaction/            # Web 聊天交互
│   │   └── web_chat.py
│   └── export/                 # 结果导出
│       ├── template_exporter.py
│       └── profile_exporter.py
├── main.py                     # CLI 入口
└── requirements.txt
```

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
playwright install chromium
```

### 运行侦察

```bash
# 自动侦察
python main.py https://example.com/ai-chat

# 指定为 SPA
python main.py https://example.com/ai-chat --type spa

# 无头模式
python main.py https://example.com/ai-chat --headless

# 不发送探测消息
python main.py https://example.com/ai-chat --no-send

# 人工登录场景（京东/淘宝/企业门户等需先登录）
python main.py https://example.com/ai-chat --manual-login

# 人工登录，超时 10 分钟，自动检测完成后不按 Enter 确认
python main.py https://example.com/ai-chat --manual-login --manual-login-timeout 600 --manual-login-no-enter

# 跨域登录：起始页 www.jd.com，登录页 passport.jd.com，成功后跳转回 www.jd.com
python main.py https://www.jd.com --manual-login --login-url "https://passport.jd.com/new/login.aspx"
```

### 认证

从浏览器 F12 复制 Request Headers，保存到：

```text
credentials/example.com.txt
```

工具会自动按域名匹配并注入 Cookie / Authorization。

## 输出

- `results/recon/profiles/*.json`：标准化 TargetProfile
- `data/burp/*_api.txt`：API 攻击模板
- `data/burp/*_webui.txt`：Web UI 选择器模板
- `results/recon/screenshots/`：侦察截图
- `results/recon/storage_states/`：浏览器状态

## 完整架构流程图

见下方 Mermaid 图。

## 架构设计流程图

```mermaid
flowchart TD
    subgraph User["用户层"]
        CLI[python main.py &lt;URL&gt;]
    end

    subgraph Config["配置层"]
        RECON[config/recon.yaml]
        SITES[config/sites.yaml]
        SPA[config/spa_chat.yaml]
        CREDS[credentials/]
    end

    subgraph Core["核心引擎层"]
        ENGINE[ReconEngine<br/>目标类型推断 / 分发]
        CRED[CredentialManager<br/>凭据解析 / JWT 过期检查]
    end

    subgraph Browser["浏览器层"]
        BM[BrowserManager<br/>启动 / 导航 / storage_state]
        AUTH[auth/playwright_injector<br/>Cookie / Header 注入]
    end

    subgraph Recon["侦察执行层"]
        SPA_RECON[SPARecon]
        API_RECON[APIRecon]
    end

    subgraph DOM["DOM 侦察"]
        ENTRY[chat_entry.py<br/>浮动按钮 / Copilot / Agent 发现]
        DET[detector.py<br/>输入框 / 发送按钮 / 响应区]
        POOL[selector_pool.py<br/>900+ 选择器 + 评分]
    end

    subgraph Network["网络侦察"]
        INT[interceptor.py<br/>XHR/fetch/WebSocket 拦截]
        TA[traffic_analyzer.py<br/>LLM API / 模型名 / API Key / RAG / Agent / 协议识别]
    end

    subgraph Output["输出层"]
        PROF[ProfileExporter<br/>TargetProfile JSON/YAML]
        TMPL[TemplateExporter<br/>Burp / Repeater 模板]
        SHOT[screenshots/ + storage_states/]
        CREDS_OUT[credentials/*.txt 自动保存]
    end

    CLI --> ENGINE
    RECON --> ENGINE
    SITES --> ENGINE
    SPA --> ENGINE
    CREDS --> CRED
    CRED --> ENGINE

    ENGINE -->|auto/spa/web_ui| BM
    ENGINE -->|api| API_RECON
    BM --> AUTH
    AUTH --> SPA_RECON

    SPA_RECON --> ENTRY
    SPA_RECON --> DET
    DET --> POOL
    SPA_RECON --> INT
    INT --> TA

    SPA_RECON --> PROF
    API_RECON --> PROF
    SPA_RECON --> TMPL
    SPA_RECON --> SHOT
    SPA_RECON --> CREDS_OUT
    API_RECON --> TMPL

    PROF --> |results/recon/profiles/*.json| Attack["攻击阶段"]
    TMPL --> |data/burp/*.txt| Attack
    CREDS_OUT --> |credentials/*.txt| Attack
