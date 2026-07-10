# RedTeam_AI — AI 红队自动化攻击平台

> LLM / RAG / Multi-Agent 系统的全链路自动化红队测试平台。
> 覆盖侦察→攻击→评估→报告的六阶段攻防体系。

## 六阶段分层架构

```
┌──────────────────────────────────────────────────────────────────┐
│  L0: recon/         前置侦察                                    │
│  Web指纹 / 密钥提取 / API发现 / 模型探测 / WAF检测               │
├──────────────────────────────────────────────────────────────────┤
│  L1: garak/         AI 安全侦查                                 │
│  基线扫描 / 定向深度验证 / 漏洞指纹提取 / 安全画像生成            │
├──────────────────────────────────────────────────────────────────┤
│  L2: bridge/        桥接映射                                     │
│  Garak JSONL → Seeds JSON / 风险分类 / OWASP 标注               │
├──────────────────────────────────────────────────────────────────┤
│  L3: promptfoo/     提示词模板                                   │
│  YAML 模板管理 / 断言规则 / 变量插值 / 多场景配置                │
├──────────────────────────────────────────────────────────────────┤
│  L4: pyrit/         深度攻击核心                                 │
│  Crescendo多轮 / 编码绕过 / XPIA / RAG攻击 / Agent滥用 /        │
│  模型提取 / 多Agent攻击 / ASR量化                               │
├──────────────────────────────────────────────────────────────────┤
│  L5:                 统一报告                                    │
│  Garak ASR + PyRIT证据 + Promptfoo断言 → OffSec 规范报告         │
└──────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
RedTeam_AI/
├── README.md                     # 本文件
├── CONTRIBUTING.md               # 贡献指南
├── Makefile                      # 统一命令入口
├── pipeline.py                   # 六阶段统一编排入口
├── requirements.txt              # 统一依赖 (所有模块)
├── docs/                         # 项目级文档
│   ├── architecture.md
│   └── contributing/
│
├── recon/                        # L0 — 前置侦察引擎
│   ├── __init__.py               # 公开 API
│   ├── main.py                   # CLI 入口
│   ├── engine.py                 # ReconEngine 核心编排
│   ├── schema.py                 # TargetProfile 数据模型
│   ├── module_registry.py        # 模块注册表
│   ├── analysis/                 # 端点推断 + 行为映射 + 画像构建
│   ├── auth/                     # 登录自动化
│   ├── probes/                   # 模型探测 + Prompt提取 + RAG探测
│   ├── scanners/                 # 浏览器/字典/JS SDK/WAF/凭证/SPA/流量
│   ├── web/                      # Flask Web 界面
│   ├── templates/                # Web 模板
│   ├── wordlists/                # 扫描字典
│   └── outputs/                  # 侦察结果
│
├── garak/                        # L1 — AI 安全侦查
│   ├── __init__.py
│   ├── scanner.py                # Garak 扫描器
│   ├── schema.py                 # 安全画像数据模型
│   └── outputs/                  # 扫描输出
│
├── bridge/                       # L2 — 桥接映射
│   ├── mapper.py                 # JSONL → Seeds 转换
│   └── __init__.py
│
├── promptfoo/                    # L3 — 提示词模板 + 评估 + 报告
│   ├── __init__.py
│   ├── manager.py                # 提示词管理中心
│   ├── loader.py                 # 模板加载器
│   ├── payload_loader.py         # 载荷加载
│   ├── schema.py                 # 数据模型
│   ├── eval/                     # 评估引擎
│   └── reporting/                # 报告生成
│   └── templates/                # 提示词模板库 (19 YAML + JSON)
│
└── pyrit/                        # L4 — 深度攻击核心
    ├── __init__.py                # 平台入口 + 公开 API
    ├── .env / .env.example        # 环境配置
    ├── configs/                   # 环境预设 (shared / targets / platforms / recons)
    ├── schemas/                   # 跨层统一数据模型 (attack / target / multi_agent)
    ├── entrypoint/                # CLI 入口层 (解析 → 回显 → 引导 → 路由)
    ├── orchestrators/             # 攻击编排引擎 (PyRIT编排 / 路由 / 反馈 / 预算)
    ├── executor/                  # 攻击执行器 (注入/越狱/XPIA/RAG/Agent/提取/多Agent)
    ├── converters/                # 载荷变形器 (编码/自适应/越狱/GCG/多模态)
    ├── targets/                   # 目标抽象层 (OpenAI/Claude/Gemini/HTTP/桥接)
    ├── scoring/                   # 评分引擎 (混合评分 / OWASP / 统一评估)
    ├── reporting/                 # 报告生成器 (OffSec / 渗透测试 / 标准映射)
    ├── scenario/                  # 多Agent攻击场景
    ├── storage/                   # 持久化存储 (Neo4j 图数据库)
    └── utils/                     # 工具函数 (指导/HTTP传输/JS提取/密钥发现/令牌管理)
```

## 快速启动

```bash
# 安装依赖
make setup

# 六阶段全流程一键执行
make pipeline TARGET=https://192.168.0.20

# 或分阶段执行
make recon TARGET=https://192.168.0.20        # L0: 前置侦察
make garak TARGET=https://192.168.0.20        # L1: AI安全侦查
make bridge TARGET=https://192.168.0.20       # L2: 桥接映射
make promptfoo TARGET=https://192.168.0.20    # L3: 提示词模板
make attack TARGET=https://192.168.0.20       # L4: 深度攻击
make report                                   # L5: 统一报告
```

## 攻击能力覆盖

| 层级 | 攻击类别 | OWASP 映射 | 执行器 |
|------|---------|-----------|--------|
| L4 | 直接提示注入 | LLM01 | `pyrit/executor/direct_injection.py` |
| L4 | 越狱攻击 (Crescendo/PAIR/TAP) | LLM01 | `pyrit/executor/jailbreak.py` |
| L4 | XPIA 间接注入 (图片/文档/网页) | LLM02 | `pyrit/executor/indirect_injection.py` |
| L4 | RAG 检索注入 + 文档投毒 + 知识泄露 | LLM03/LLM06 | `pyrit/executor/rag_attack.py` |
| L4 | Agent 工具滥用 + 业务流程绕过 | LLM08 | `pyrit/executor/agent_abuse.py` |
| L4 | 模型提取 + 成员推理 | LLM10 | `pyrit/executor/model_extraction.py` |
| L4 | 多Agent攻击 (通信劫持/级联故障/记忆投毒) | LLM01/04/08 | `pyrit/executor/multi_agent_attack.py` |
| L3 | 提示词模板管理 + 载荷分发 | — | `promptfoo/` |
| L1 | AI 安全侦查 (6类探针) | — | `garak/` |
| L0 | 前置侦察 (Web指纹/API发现/模型探测) | — | `recon/` |

## 扩展指南

### 添加新的侦察模块 (L0)
在 `recon/scanners/`、`recon/probes/`、`recon/auth/` 或 `recon/analysis/` 下新增模块，
在 `recon/module_registry.py` 中注册即可。

### 添加新的 Garak 探针 (L1)
在 `garak/scanner.py` 的 `GARAK_PROBE_CATEGORIES` 字典中添加新类别。

### 添加新的攻击执行器 (L4)
在 `pyrit/executor/` 下新增执行器，遵循现有模块的接口约定。

### 添加新的载荷变形器 (L4)
在 `pyrit/converters/` 下新增转换器，通过 `registry.py` 注册。

### 添加新的提示词模板 (L3)
在 `promptfoo/templates/` 下添加 YAML 模板文件。

## 环境要求

- Python 3.10+
- Playwright (Chromium)
- Garak (可选, L1): `pip install garak`
- Promptfoo (可选, L3): `npm install -g promptfoo`

## 许可

本项目仅供授权的安全测试和研究使用。未经授权对他人系统进行测试可能违法。
