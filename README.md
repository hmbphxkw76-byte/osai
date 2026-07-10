# RedTeam_AI — AI 红队自动化攻击平台

> LLM / RAG / Multi-Agent 系统的全链路自动化红队测试平台。
> 覆盖侦察→攻击→评估→报告的六层攻防体系。

## 六层分层架构

```
┌──────────────────────────────────────────────────────────────────────┐
│  L0: recon/    前置侦察                                            │
│  Web指纹 / 密钥提取 / API发现 / 模型探测 / WAF检测 / 标准化输出     │
├──────────────────────────────────────────────────────────────────────┤
│  L1: garak/       AI 安全侦查                                       │
│  基线扫描 / 定向深度验证 / 漏洞指纹提取 / 结构化安全画像生成        │
├──────────────────────────────────────────────────────────────────────┤
│  L2: pyrit/core/  攻击指挥中枢                                       │
│  安全画像路由 / PyRIT Orchestrator 编排 / 动态调优 / Token预算管控  │
├──────────────────────────────────────────────────────────────────────┤
│  L3: pyrit/attack/  攻击执行矩阵                                    │
│  3a 直接注入+越狱 / 3b 间接注入XPIA / 3c RAG攻击                   │
│  3d Agent工具滥用 / 3e 模型提取反演                                 │
├──────────────────────────────────────────────────────────────────────┤
│  L4: pyrit/multi_agent/  多Agent系统攻击                             │
│  通信劫持 / 级联故障 / 记忆投毒 / 人机信任利用                      │
├──────────────────────────────────────────────────────────────────────┤
│  L5: promptfoo/eval/  统一评估判定                                   │
│  统一ASR评分 / OWASP LLM Top 10 + Agentic Top 10 双映射              │
├──────────────────────────────────────────────────────────────────────┤
│  L6: promptfoo/reporting/  标准化报告生成                            │
│  OffSec风格报告 / MITRE ATLAS映射 / 修复建议矩阵 / 可复现配置包     │
└──────────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
RedTeam_AI/
├── README.md                    # 本文件
├── Makefile                     # 统一命令入口
├── docs/                        # 项目级文档
│
├── recon/                       # L0 — 前置侦察引擎
│   ├── main.py                  # CLI 入口
│   ├── recon/                   # 核心侦测模块
│   │   ├── scanners/            #   Web 扫描器
│   │   ├── probes/              #   AI 探针
│   │   ├── auth/                #   认证自动化
│   │   └── analysis/            #   行为分析
│   ├── web/                     # Web UI
│   ├── wordlists/               # 扫描字典
│   └── outputs/                 # 侦察结果
│
├── garak/                       # L1 — AI 安全侦查 (独立模块)
│   ├── __init__.py
│   ├── scanner.py               # Garak 扫描器
│   ├── schema.py                # 安全画像数据模型
│   ├── outputs/                 # 扫描输出
│   └── README.md
│
├── pyrit/                       # L2-L4 — 攻击核心
│   ├── core/                    #   L2: 攻击指挥中枢
│   │   ├── orchestrator.py      #     PyRIT 统一调度器
│   │   ├── config.py            #     场景化参数配置
│   │   ├── full_pipeline.py     #     六阶段管道编排
│   │   └── scenario_runner.py   #     场景运行器
│   ├── attack/                  #   L3: 攻击执行矩阵
│   │   ├── direct/              #     3a 直接注入+越狱
│   │   ├── xpia/                #     3b 间接提示注入
│   │   ├── rag/                 #     3c RAG攻击
│   │   ├── agent_abuse/         #     3d Agent滥用
│   │   └── extraction/          #     3e 模型提取
│   ├── multi_agent/             #   L4: 多Agent系统攻击
│   │   ├── __init__.py          #     MultiAgentAttackExecutor
│   │   └── session.py           #     PyRIT 会话编排
│   ├── converters/              # 载荷变形器
│   ├── executor/                # 执行器 (向后兼容)
│   ├── orchestrators/           # 编排器 (向后兼容)
│   ├── targets/                 # 目标适配器
│   ├── scoring/                 # 评分引擎
│   ├── reporting/               # 报告生成器
│   ├── datasets/                # Payloads + 测试用例
│   ├── configs/                 # 多环境配置
│   ├── scenarios/               # 攻击场景 + 模板
│   └── main.py                  # CLI 入口
│
└── promptfoo/                   # L5-L6 — 评估 + 报告 + 提示词模板
    ├── __init__.py
    ├── manager.py               # 提示词管理中心
    ├── schema.py                # 数据模型
    ├── eval/                    #   L5: 评估引擎
    │   └── engine.py            #     ASR + OWASP 映射
    ├── reporting/               #   L6: 报告生成
    │   └── generator.py         #     OffSec + MITRE ATLAS
    ├── templates/               # 提示词模板库
    │   └── README.md
    └── README.md
```

## 快速启动

```bash
# 安装依赖
make setup

# 六阶段全流程一键执行
make pipeline TARGET=https://192.168.0.20

# 或分阶段执行
make recon TARGET=https://192.168.0.20          # L0: 前置侦察
make ai-detect TARGET=https://192.168.0.20      # L1: AI安全侦查
make surface TARGET=https://192.168.0.20        # L2: 攻击面分析
make attack TARGET=https://192.168.0.20         # L3+L4: 攻击执行
make eval                                       # L5: 统一评估
make report                                     # L6: 报告生成
```

## 六层攻击矩阵

| 层级 | 目录 | 核心能力 | 引擎 |
|------|------|---------|------|
| **L0** 前置侦察 | `recon/` | Web指纹 / 密钥提取 / API发现 / 模型探测 / WAF检测 | Playwright + 自研 |
| **L1** AI 侦查 | `garak/` | 基线扫描 / 定向深度验证 / 漏洞指纹提取 | Garak CLI |
| **L2** 攻击指挥 | `pyrit/core/` | 安全画像路由 / 动态调优 / Token预算管控 | PyRIT Orchestrator |
| **L3a** 直接注入 | `pyrit/attack/direct/` | 载荷变形 / 多轮越狱 / 对抗式Prompt生成 | PyRIT Converters |
| **L3b** 间接注入 | `pyrit/attack/xpia/` | 图片/文档/网页载体注入 / 多轮诱导触发 | XPIA |
| **L3c** RAG 攻击 | `pyrit/attack/rag/` | 检索注入 / 文档投毒 / 知识泄露 / 源文件越权 | Promptfoo |
| **L3d** Agent 滥用 | `pyrit/attack/agent_abuse/` | 工具劫持 / Function Call注入 / 沙箱逃逸 | PyRIT+Promptfoo |
| **L3e** 模型提取 | `pyrit/attack/extraction/` | 训练数据提取 / 成员推理 / 参数反演 | PyRIT+Garak |
| **L4** 多Agent攻击 | `pyrit/multi_agent/` | 通信劫持 / 级联故障 / 记忆投毒 | PyRIT Session |
| **L5** 统一评估 | `promptfoo/eval/` | 统一ASR评分 / OWASP LLM+Agentic双映射 | Promptfoo |
| **L6** 报告生成 | `promptfoo/reporting/` | OffSec风格报告 / MITRE ATLAS映射 / 修复建议 | 多源整合 |

## 扩展指南

### 添加新的侦察模块 (L0)
在 `recon/recon/scanners/` 或 `recon/recon/probes/` 下新增模块，
在 `module_registry.py` 中注册即可。

### 添加新的 Garak 探针 (L1)
在 `garak/scanner.py` 的 `GARAK_PROBE_CATEGORIES` 字典中添加新类别。

### 添加新的攻击向量 (L3)
在 `pyrit/attack/` 下创建新的子包，遵循现有模块的接口约定。

### 添加新的提示词模板 (L5)
在 `promptfoo/templates/` 按类别子目录添加 YAML 模板文件。

## 环境要求

- Python 3.10+
- Playwright (Chromium)
- Garak (可选, L1)
- Promptfoo (可选, L3c/L5)

## 许可

本项目仅供授权的安全测试和研究使用。未经授权对他人系统进行测试可能违法。
