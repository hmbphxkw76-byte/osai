# RedTeam_AI 七层架构设计

> **定位**: 本文档定义项目 7 层架构的完整设计、模块映射、数据流和接口规范。
> 详细开发规范见 [docs/contributing/DEVELOPMENT_STANDARDS.md](contributing/DEVELOPMENT_STANDARDS.md)

---

## 一、架构总览

```
┌─ 第零层：前置侦察（Recon）【recon + pyrit/recon_adapter】──────────┐
│ Web 指纹 / 密钥提取 / API 发现 / 认证突破                              │
│ LLM 模型指纹探测 / 接口格式识别 / 防护中间件探查 / 配置标准化输出        │
└───────────────────┬──────────────────────────────────────────────────┘
                    ▼
┌─ 第一层：AI 安全侦查（Garak）【pyrit/executor/garak_scanner.py】──────┐
│ 快速基线扫描 / 定向深度验证 / 漏洞指纹提取 / 结构化安全画像生成          │
└───────────────────┬──────────────────────────────────────────────────┘
                    ▼
┌─ 第二层：攻击指挥中枢【pyrit/orchestrators/pyrit_orchestrator.py】────┐
│ 基于安全画像路由攻击策略 / 动态反馈闭环                                 │
│ 实时成功率动态调优 / 速率与 Token 预算管控                              │
└───────────────────┬──────────────────────────────────────────────────┘
                    ▼
┌─ 第三层：攻击执行矩阵【pyrit/executor/ + pyrit/converters/】──────────┐
│ ├── 3a: 直接提示注入 + 越狱（PyRIT 核心）                              │
│ │ 转换器载荷变形 / 多轮迭代越狱 / 对抗式 Prompt 生成                    │
│ ├── 3b: 间接提示注入 XPIA（PyRIT 多模态）                               │
│ │ 图片 / 文档 / 网页载体注入 / 多轮诱导读取触发                          │
│ ├── 3c: RAG 专项攻击（Promptfoo 核心）                                  │
│ │ 检索注入 / 文档投毒 / 知识泄露 / 源文件越权                            │
│ ├── 3d: Agent 工具滥用攻击（PyRIT+Promptfoo 双引擎）                     │
│ │ 模型层调用诱导 / 应用层业务漏洞利用                                   │
│ └── 3e: 模型提取 / 反演攻击（PyRIT+Garak）                              │
│ 训练数据提取 / 成员推理 / 参数语义反演                                  │
└───────────────────┬──────────────────────────────────────────────────┘
                    ▼
┌─ 第四层：多 Agent 系统攻击【pyrit/executor/multi_agent_attack.py】────┐
│ ├── Agent 间通信劫持                                                    │
│ ├── 级联故障触发                                                        │
│ ├── 记忆 / 上下文持久化投毒                                              │
│ └── 人机信任利用攻击                                                    │
└───────────────────┬──────────────────────────────────────────────────┘
                    ▼
┌─ 第五层：统一评估判定【pyrit/scoring/unified_eval.py】─────────────────┐
│ 统一 ASR 评分 / 风险等级量化 / 业务影响映射                             │
│ ├── OWASP LLM Top 10 自动映射                                           │
│ └── OWASP Agentic Top 10 自动映射                                       │
└───────────────────┬──────────────────────────────────────────────────┘
                    ▼
┌─ 第六层：标准化报告生成【pyrit/reporting/】───────────────────────────┐
│ OffSec 风格渗透报告 / MITRE ATLAS 完整映射 / 修复建议矩阵               │
│ 可复现测试配置包 / 攻击知识库自动沉淀                                    │
└──────────────────────────────────────────────────────────────────────┘
```

## 二、模块映射

### L0 — 前置侦察

| 模块 | 路径 | 职责 |
|------|------|------|
| 核心引擎 | `recon/engine.py` | 侦察流程编排 |
| 浏览器驱动 | `recon/scanners/browser.py` | Playwright 自动化 |
| 模型探测 | `recon/probes/model_probe.py` | LLM 指纹识别 |
| 端点推断 | `recon/analysis/endpoint_infer.py` | API/聊天端点分类 |
| 字典扫描 | `recon/scanners/dict_scan.py` | 路径爆破 |
| WAF 检测 | `recon/scanners/waf_detector.py` | 防护中间件探查 |
| 认证自动化 | `recon/auth/login.py` | Cookie/Token 获取 |
| 侦察适配器 | `pyrit/recon_adapter.py` | Profile → PyRIT 目标配置 |
| 侦察桥接 | `pyrit/targets/_recon_bridge.py` | 目标构建器集成 |

**输入**: URL + 可选的认证信息
**输出**: `target_profile.json` 标准化画像

### L1 — AI 安全侦查 (Garak)

| 模块 | 路径 | 职责 |
|------|------|------|
| Garak 扫描器 | `pyrit/executor/garak_scanner.py` | 两阶段扫描：baseline + deep |
| Garak 配置 | `pyrit/configs/garak.env` | Garak 环境变量 |

**模式**: `baseline` | `deep` | `targeted` | `disabled`

### L2 — 攻击指挥中枢

| 模块 | 路径 | 职责 |
|------|------|------|
| 编排引擎 | `pyrit/orchestrators/pyrit_orchestrator.py` | 攻击策略路由 + 动态反馈 |
| 自适应选择 | `pyrit/executor/adaptive_selector.py` | 成功率驱动的策略选择 |
| 场景运行器 | `pyrit/orchestrators/scenario_runner.py` | 场景执行调度 |

### L3a — 直接提示注入 + 越狱

| 模块 | 路径 | 职责 |
|------|------|------|
| 越狱转换器 | `pyrit/converters/jailbreak.py` | 多轮迭代越狱 |
| 注入转换器 | `pyrit/converters/injection.py` | 直接提示注入 |
| 自适应变形 | `pyrit/converters/adaptive.py` | 载荷自适应 |
| 对抗式生成 | `pyrit/converters/gcg_suffix.py` | GCG 后缀生成 |

### L3b — 间接提示注入 (XPIA)

| 模块 | 路径 | 职责 |
|------|------|------|
| XPIA 转换器 | `pyrit/converters/xpia_injection.py` | 多模态载体注入 |
| 多模态攻击 | `pyrit/converters/multimodal_attack.py` | 图片/音频注入 |
| XPIA Payloads | `promptfoo/templates/xpia_payloads.yaml` | 18+ XPIA 载荷 |


### L3c — RAG 专项攻击 (Promptfoo)

| 模块 | 路径 | 职责 |
|------|------|------|
| RAG 执行器 | `pyrit/executor/rag_attack.py` | RAG 攻击编排 |
| RAG 投毒 | `pyrit/converters/rag_poisoning.py` | 文档/检索投毒 |
| Promptfoo 配置 | `pyrit/configs/promptfoo.env` | 评估引擎配置 |
| RAG Payloads | `promptfoo/templates/rag_payloads.yaml` | RAG 攻击载荷 |


### L3d — Agent 工具滥用

| 模块 | 路径 | 职责 |
|------|------|------|
| Agent 执行器 | `pyrit/executor/agent_abuse.py` | 工具滥用编排 |
| Agent 转换器 | `pyrit/converters/agent_abuse.py` | Function Call 注入 |
| Agent Payloads | `promptfoo/templates/agent_abuse_payloads.yaml` | 工具劫持载荷 |


### L3e — 模型提取

| 模块 | 路径 | 职责 |
|------|------|------|
| 提取执行器 | `pyrit/executor/model_extraction.py` | 模型提取编排 |
| Embedding 攻击 | `pyrit/converters/embedding_attack.py` | 嵌入向量反演 |
| 提取 Payloads | `promptfoo/templates/model_extraction_payloads.yaml` | 提取类载荷 |


### L4 — 多 Agent 系统攻击

| 模块 | 路径 | 职责 |
|------|------|------|
| 多Agent执行器 | `pyrit/executor/multi_agent_attack.py` | 编排多Agent攻击 |
| 多Agent Payloads | `promptfoo/templates/multi_agent_payloads.yaml` | Agent间攻击载荷 |


### L5 — 统一评估判定

| 模块 | 路径 | 职责 |
|------|------|------|
| 统一评估 | `pyrit/scoring/unified_eval.py` | OWASP 双映射 + ASR |
| 混合评分 | `pyrit/scoring/hybrid.py` | 多维度评分 |
| 评分执行 | `pyrit/executor/scorer.py` | 评分器调度 |

### L6 — 标准化报告生成

| 模块 | 路径 | 职责 |
|------|------|------|
| 专业报告 | `pyrit/reporting/professional_report.py` | OffSec 风格报告 |
| 标准映射 | `pyrit/reporting/standards_mapping.py` | MITRE ATLAS 映射 |
| 报告模板 | `pyrit/reporting/` | 报告配置模板 |


## 三、数据流

```
                     L0 (recon)
                         │
                    target_profile.json
                         │
              ┌──────────┼──────────┐
              ▼                     ▼
         L1 (Garak)          L2 (Orchestrator)
         security_profile    attack_plan
              │                     │
              └──────────┬──────────┘
                         ▼
                 ┌── L3 攻击矩阵 ──┐
                 │ 3a  3b  3c      │
                 │ 3d  3e          │
                 └────────┬────────┘
                          ▼
                    raw_results[]
                          │
                    ┌─────┼─────┐
                    ▼           ▼
               L4 (Multi)   L5 (Eval)
               agent_results  scored_results
                    │           │
                    └─────┬─────┘
                          ▼
                    L6 (Report)
                    final_report.{md,json,pdf}
```

## 四、环境配置

各层配置通过 `.env` 文件控制：

| 配置文件 | 覆盖范围 | 关键开关 |
|----------|---------|---------|
| `pyrit/.env` | 全局 | `PLATFORM_SELECTOR`, `TEMPERATURE`, `MAX_TOKENS` |
| `pyrit/configs/garak.env` | L1 | `GARAK_MODE` (baseline/deep/targeted/disabled) |
| `pyrit/configs/promptfoo.env` | L3c/L5 | `PROMPTFOO_ENABLED`, `RAG_MODE` |
| `pyrit/configs/shared.env` | 通用 | 共享配置 |
| `pyrit/configs/targets.env` | 目标 | 靶标配置 |
| `pyrit/configs/recons.env` | L0 | 侦察参数 |
| `pyrit/configs/platforms.env` | 攻击者 | LLM API 配置 |

## 五、开发规范

严格遵循 `docs/contributing/DEVELOPMENT_STANDARDS.md` 中的所有规范：

1. **YAML 唯一真实来源** — 所有 payloads 存储在 `datasets/payloads/`，通过 `manifest.yaml` 注册
2. **配置分离** — 各层独立 `.env`，不跨层引用
3. **模块化部署** — 包内模块可独立运行，不跨包强耦合
4. **SDK 优先** — Garak/Promptfoo 通过 subprocess 集成，不重复造轮子
5. **编码规范** — UTF-8 without BOM, LF, 4空格, 中英文 docstring
6. **数据模型** — 所有模块使用 `@dataclass` + 类型注解 + `field(default_factory=...)`

## 六、实施优先级

| 优先级 | 层级 | 状态 | 备注 |
|--------|------|------|------|
| P0 | L0 前置侦察 | ✅ 完成 | recon 独立引擎 |
| P0 | L2 攻击指挥 | ✅ 完成 | PyRIT Orchestrator |
| P0 | L3a 直接注入 | ✅ 完成 | 越狱 + 注入转换器 |
| P0 | L5 统一评估 | ✅ 完成 | 混合评分 + 统一评估 |
| P0 | L6 报告生成 | ✅ 完成 | 专业报告 + MITRE ATLAS |
| P1 | L3b XPIA | 🆕 框架就绪 | 转换器 + Payloads 已创建 |
| P1 | L3c RAG | 🆕 框架就绪 | 执行器 + Promptfoo 集成 |
| P1 | L3d Agent 滥用 | 🆕 框架就绪 | 执行器 + 转换器 + Payloads |
| P2 | L1 Garak | 🆕 框架就绪 | 扫描器 stub 已创建 |
| P2 | L3e 模型提取 | 🆕 框架就绪 | 执行器 stub 已创建 |
| P2 | L4 多Agent | 🆕 框架就绪 | 执行器 + Payloads 已创建 |
