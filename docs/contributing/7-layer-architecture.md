# OffSec AI 红队平台 — 七层架构设计

> **定位**: 本文档定义 7 层架构的完整设计、模块映射、数据流和接口规范。
> 严格遵循 `contributing/DEVELOPMENT_STANDARDS.md` 中的所有研发规范。

---

## 一、架构总览

```
┌─ 第零层：前置侦察（Recon）【优化：LLM 专属侦察 + 标准化输出】────────────┐
│ Web 指纹 / 密钥提取 / API 发现 / 认证突破                                │
│ LLM 模型指纹探测 / 接口格式识别 / 防护中间件探查 / 配置标准化输出          │
└────────────────────┬─────────────────────────────────────────────────┘
                     ▼
┌─ 第一层：AI 安全侦查（Garak 核心）【优化：两阶段扫描 + 结构化画像】───────┐
│ 快速基线扫描 / 定向深度验证 / 漏洞指纹提取 / 结构化安全画像生成            │
└────────────────────┬─────────────────────────────────────────────────┘
                     ▼
┌─ 第二层：攻击指挥中枢【优化：PyRIT 原生编排 + 动态反馈闭环】──────────────┐
│ 基于安全画像路由攻击策略 / PyRIT Orchestrator 攻击编排                    │
│ 实时成功率动态调优 / 速率与 Token 预算管控                                │
└────────────────────┬─────────────────────────────────────────────────┘
                     ▼
┌─ 第三层：攻击执行矩阵【优化：全场景工具化落地 + 专项能力补强】──────────────┐
│ ├── 3a: 直接提示注入 + 越狱（PyRIT 核心）                                  │
│ │ 转换器载荷变形 / 多轮迭代越狱 / 对抗式 Prompt 生成                        │
│ ├── 3b: 间接提示注入 XPIA（PyRIT 多模态）                                   │
│ │ 图片 / 文档 / 网页载体注入 / 多轮诱导读取触发                              │
│ ├── 3c: RAG 专项攻击（Promptfoo 核心）「新增补强」                           │
│ │ 检索注入 / 文档投毒 / 知识泄露 / 源文件越权                                │
│ ├── 3d: Agent 工具滥用攻击（PyRIT+Promptfoo 双引擎）                         │
│ │ 模型层调用诱导 / 应用层业务漏洞利用                                       │
│ └── 3e: 模型提取 / 反演攻击（PyRIT+Garak）                                  │
│ 训练数据提取 / 成员推理 / 参数语义反演                                      │
└────────────────────┬─────────────────────────────────────────────────┘
                     ▼
┌─ 第四层：多 Agent 系统攻击【优化：PyRIT 会话编排支撑】──────────────────────┐
│ ├── Agent 间通信劫持                                                        │
│ ├── 级联故障触发                                                            │
│ ├── 记忆 / 上下文持久化投毒                                                  │
│ └── 人机信任利用攻击                                                        │
└────────────────────┬─────────────────────────────────────────────────┘
                     ▼
┌─ 第五层：统一评估判定【优化：Promptfoo 统一评估引擎】────────────────────────┐
│ 统一 ASR 评分 / 风险等级量化 / 业务影响映射 / Garak 检测器二次校验          │
│ ├── OWASP LLM Top 10 自动映射                                               │
│ └── OWASP Agentic Top 10 自动映射（NEW）                                     │
└────────────────────┬─────────────────────────────────────────────────┘
                     ▼
┌─ 第六层：标准化报告生成【优化：多源整合 + 可复现合规输出】───────────────────┐
│ OffSec 风格渗透报告 / MITRE ATLAS 完整映射 / 修复建议矩阵                  │
│ 可复现测试配置包 / 攻击知识库自动沉淀                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 二、分层包映射与职责

### 映射总表

| 层级 | 核心包/文件 | 职责 | 依赖方向 |
|------|------------|------|---------|
| **L0** | `recon/` + `pyrit/recon_adapter.py` + `pyrit/targets/_recon_bridge.py` | 前置侦察 → 标准化 Profile 输出 | 无内部依赖 |
| **L1** | `pyrit/executor/garak_scanner.py` | AI 安全侦查 → 结构化安全画像 | → targets |
| **L2** | `pyrit/orchestrators/pyrit_orchestrator.py` + `pyrit/executor/adaptive_selector.py` | 攻击指挥中枢 → 动态反馈闭环 | → executor, converters, reporting |
| **L3a** | `pyrit/converters/jailbreak.py` + `pyrit/converters/injection.py` | 直接注入 + 越狱 | → 外部 PyRIT 框架 |
| **L3b** | `pyrit/converters/multimodal_attack.py` + `pyrit/converters/xpia_injection.py` | 间接注入 XPIA | → 外部 PyRIT 框架 |
| **L3c** | `pyrit/executor/rag_attack.py` + `promptfoo/templates/rag_payloads.yaml` | RAG 专项攻击（Promptfoo） | → targets, promptfoo |
| **L3d** | `pyrit/executor/agent_abuse.py` + `pyrit/converters/agent_abuse.py` | Agent 工具滥用 | → targets, datasets |
| **L3e** | `pyrit/executor/model_extraction.py` + `pyrit/executor/garak_scanner.py` | 模型提取 / 反演 | → targets, datasets |
| **L4** | `pyrit/executor/multi_agent_attack.py` | 多 Agent 系统攻击 | → targets, datasets |
| **L5** | `pyrit/scoring/hybrid.py` + `pyrit/scoring/unified_eval.py` | 统一评估判定（Promptfoo） | → executor |
| **L6** | `pyrit/reporting/professional_report.py` + `pyrit/reporting/standards_mapping.py` | 标准化报告生成 | → executor, scoring |

### L0-L6 间依赖链

```
L6 (reporting) ← L5 (scoring) ← L3-4 (executor) ← L2 (orchestrators) ← L1 (garak) ← L0 (recon)
                                    ↑                    ↑
                              L0 Profile ────────────────┘
```

- 只能从上层引用下层，禁止反向依赖。
- `main.py` 通过 `entrypoint/router.py` 统一路由，不跨层直接调用。

---

## 三、各层详细设计

### 第零层（L0）：前置侦察 — recon/

**现有实现**:
- `recon/main.py` → Playwright 驱动的前置侦察引擎
- `recon/engine.py` → ReconEngine 核心编排
- `pyrit/recon_adapter.py` → 桥接 recon Profile → PyRIT 攻击目标
- `pyrit/targets/_recon_bridge.py` → Profile 解析与 Target 构建

**标准化输出**: `target_profile.json`（JSON Schema 定义在 `recon/schema.py`）

**CLI 入口**:
```bash
# Phase 1: recon 前置侦察
cd recon
python main.py --target https://target-app.com --browser chromium

# Phase 2: PyRIT 消费 Profile
cd ../pyrit
python main.py --recon-profile ../recon/outputs/target_profile.json --phase probe
```

---

### 第一层（L1）：AI 安全侦查 — Garak 核心

**模块**: `pyrit/executor/garak_scanner.py`

**设计模式**: 两阶段扫描
1. **快速基线扫描** (`garak_base_scan`): 30 秒快速探测，覆盖 Top-N 漏洞类
2. **定向深度验证** (`garak_deep_scan`): 基于安全画像选择具体 Probe，逐类验证

**结构化安全画像输出** (`security_profile.json`):
```json
{
  "target_id": "target-001",
  "scan_timestamp": "2026-07-10T14:30:00Z",
  "base_scan_summary": {
    "total_probes": 50,
    "vulnerable_probes": 12,
    "high_severity": 3,
    "medium_severity": 7,
    "low_severity": 2
  },
  "vulnerability_fingerprints": [
    { "category": "prompt_injection", "severity": "high", "confidence": 0.92 },
    { "category": "jailbreak", "severity": "medium", "confidence": 0.85 }
  ],
  "recommended_attack_paths": ["prompt_injection", "jailbreak", "encoding_bypass"]
}
```

**YAML 配置**: `configs/garak.env`（Garak 扫描配置预设）

---

### 第二层（L2）：攻击指挥中枢 — PyRIT Orchestrator

**模块**: `pyrit/orchestrators/pyrit_orchestrator.py`

**核心能力**:
- 基于 L1 安全画像**路由攻击策略**
- PyRIT 原生 `PromptSendingAttack` + `CrescendoAttack` 编排
- **实时成功率动态调优**：`executor/adaptive_selector.py` 根据反馈调整策略权重
- **速率与 Token 预算管控**：自动限频，避免速率限制封锁

**动态反馈闭环**:
```
攻击任务 → 评分器 → 自适应选择器 → 更新策略权重 → 下一轮攻击
   ↑                                                     |
   └────────────────── 结果反馈 ──────────────────────────┘
```

**门控阶段流转**:
```
PROBE → (成功率>=阈值) → SINGLE → CRESCENDO → REPORT
         ↓ (成功率<阈值)
     跳过 SINGLE → 直接 CRESCENDO
```

---

### 第三层（L3）：攻击执行矩阵

#### L3a: 直接提示注入 + 越狱

**现有实现**:
- `converters/jailbreak.py` — DAN/PAIR/AIM/Academic/Developer 越狱前缀
- `converters/injection.py` — Suffix 追加 / JSON 劫持注入
- `datasets/payloads/jailbreak_payloads.yaml` — 角色扮演/编码/多语言/情感越狱
- `datasets/payloads/prompt_injection_payloads.yaml` — 直接/间接/跨上下文注入

**无需新增，现有实现已完整覆盖。**

#### L3b: 间接提示注入 XPIA

**新增模块**: `converters/xpia_injection.py`

**载体类型**:
| 载体 | 注入方式 | 解析 |
|------|---------|------|
| 图片 | EXIF/Steganography/Alt-Text | PIL + 视觉模型解析 |
| 文档 | 隐藏段落/白色字体/脚注隐藏 | python-docx / PyPDF2 |
| 网页 | 隐藏 div / meta 标签 / iframe | BeautifulSoup |
| 音频 | 超声波 / 静音段嵌入 | pydub |

**YAML 载荷**: `datasets/payloads/xpia_payloads.yaml`

#### L3c: RAG 专项攻击（Promptfoo 核心）

**新增模块**: `executor/rag_attack.py`

**集成 Promptfoo** 作为 RAG 专项测试引擎：
- **检索注入**: 恶意文档注入知识库，触发检索污染
- **文档投毒**: 对抗性文本插入检索语料
- **知识泄露**: Prompt 提取攻击 → 获取系统提示/知识库片段
- **源文件越权**: 路径遍历 / 敏感文件读取诱导

**YAML 载荷**: `datasets/payloads/rag_payloads.yaml`（已有，需扩展）

**Promptfoo 集成方式**:
```python
# executor/rag_attack.py
class PromptfooRAGRunner:
    """Promptfoo RAG 专项测试运行器。
    
    通过 subprocess 调用 promptfoo CLI，或直接使用 promptfoo Python API。
    输入: 目标 RAG 端点 + 知识库配置
    输出: 注入成功率 + 知识泄露率 + 详细测试结果
    """
```

#### L3d: Agent 工具滥用攻击

**新增模块**: `executor/agent_abuse.py` + `converters/agent_abuse.py`

**攻击向量**:
| 层级 | 攻击手法 | 目标 |
|------|---------|------|
| 模型层 | Function Call 注入 / 工具描述劫持 | 诱导调用危险工具 |
| 应用层 | 参数注入 / 返回值投毒 / 工具链劫持 | 业务逻辑漏洞利用 |
| 系统层 | 沙箱逃逸 / 文件系统越权 / 命令注入 | 底层系统访问 |

**YAML 载荷**: `datasets/payloads/agent_abuse_payloads.yaml`

#### L3e: 模型提取 / 反演攻击

**新增模块**: `executor/model_extraction.py`

**攻击向量**:
| 攻击类型 | 手法 | 检测指标 |
|---------|------|---------|
| 训练数据提取 | 重复采样 / 单词补全 / 成员推断 | 训练集覆盖度 |
| 参数语义反演 | 对抗性查询 / 梯度泄漏分析 | 参数敏感性 |
| 模型克隆 | 影子模型训练 / API 大量采样 | 输出一致性 |

**复用 L1 Garak** 的 `garak.probes.leakreplay` / `garak.probes.lmrc` 探测器。

**YAML 载荷**: `datasets/payloads/model_extraction_payloads.yaml`

---

### 第四层（L4）：多 Agent 系统攻击

**新增模块**: `executor/multi_agent_attack.py`

**攻击面**:
```
┌──────────────────────────────────────────────────────────┐
│                    Multi-Agent Attack Surface             │
├──────────────┬──────────────┬──────────────┬─────────────┤
│ 通信劫持     │ 级联故障     │ 记忆投毒     │ 信任利用    │
│ A2A 协议劫持 │ 错误放大链   │ 上下文污染   │ 人机信任    │
│ 消息篡改     │ 回滚触发     │ 持久化注入   │ 权限混淆    │
│ 中间人攻击   │ 资源耗尽     │ 检索污染     │ 决策欺骗    │
└──────────────┴──────────────┴──────────────┴─────────────┘
```

**PyRIT 会话编排**:
```python
# executor/multi_agent_attack.py
class MultiAgentAttackOrchestrator:
    """多 Agent 系统攻击编排器。

    利用 PyRIT 的 Memory 和 Orchestrator 能力：
    - 创建多个 Target 模拟多 Agent 环境
    - 通过 CrescendoAttack 实现跨 Agent 级联攻击
    - 使用 SQLiteMemory 记录攻击链路
    """
```

**YAML 载荷**: `datasets/payloads/multi_agent_payloads.yaml`

---

### 第五层（L5）：统一评估判定

**核心模块**: `scoring/unified_eval.py`

**统一 ASR (Attack Success Rate) 评分体系**:

```
                       ┌─────────────────────┐
                       │   Unified Evaluator  │
                       └──────────┬──────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
    ┌─────▼─────┐          ┌─────▼─────┐          ┌─────▼─────┐
    │ PyRIT     │          │ Promptfoo │          │ Garak     │
    │ Scorer    │          │ Eval      │          │ Detector  │
    └─────┬─────┘          └─────┬─────┘          └─────┬─────┘
          │                       │                       │
    ┌─────▼─────┐          ┌─────▼─────┐          ┌─────▼─────┐
    │ 越狱评分  │          │ RAG 注入   │          │ 漏洞检测  │
    │ 注入评分  │          │ 知识泄露   │          │ 二次校验  │
    │ 代码评分  │          │ 检索质量   │          │ 误报过滤  │
    └───────────┘          └───────────┘          └───────────┘
```

**OWASP 映射**（自动）:
- **OWASP LLM Top 10**: LLM01-LM10 自动分类
- **OWASP Agentic Top 10 (NEW)**: AGT01-AGT10 自动分类

**实现**:
```python
# scoring/unified_eval.py
class UnifiedEvaluator:
    """统一评估引擎。

    聚合 PyRIT Scorer + Promptfoo Eval + Garak Detector 三方结果，
    输出统一风险评分和 OWASP 映射。
    """

    def evaluate(self, attack_results: list[dict]) -> UnifiedRiskReport:
        # 1. PyRIT 评分
        # 2. Promptfoo 评估（RAG 专项）
        # 3. Garak 检测器二次校验
        # 4. OWASP 自动映射
        # 5. 业务影响映射
        ...
```

**YAML 配置**: `configs/promptfoo.env`（Promptfoo 评估配置）

---

### 第六层（L6）：标准化报告生成

**核心模块**: `reporting/professional_report.py`

**报告输出标准**:

| 报告组件 | 格式 | 内容 |
|---------|------|------|
| 封面 | OffSec TLP:AMBER | 目标信息/测试日期/密级标记 |
| 执行摘要 | Markdown/PDF | 关键发现/总体风险评级 |
| 方法论 | Markdown | 七层攻击方法论说明 |
| 攻击结果 | 表格+图表 | 按层/按手法/按目标分类 |
| 漏洞详情 | Markdown | 每个漏洞的详细分析 + POC |
| MITRE ATLAS 映射 | 热力图 | TTP 技术映射矩阵 |
| OWASP 映射 | 表格 | LLM Top10 + Agentic Top10 |
| 修复建议矩阵 | 表格 | 按优先级/修复难度/成本排序 |
| 可复现配置包 | ZIP | 完整 YAML 配置 + 攻击链 |
| 知识库沉淀 | JSONL | 结构化知识沉淀 |

**ReportConfig YAML**:
```yaml
# datasets/payloads/report_config.yaml
report:
  style: "offsec"           # offsec / mitre / owasp / custom
  format: ["md", "pdf"]     # 输出格式
  tlp: "AMBER"              # TLP:RED / TLP:AMBER / TLP:GREEN
  include:
    - executive_summary
    - attack_methodology
    - vulnerability_details
    - mitre_atlas_mapping
    - owasp_mapping
    - remediation_matrix
    - reproduce_package
```

---

## 四、配置体系扩展

### 新增配置文件

| 文件 | 用途 | 选择器 |
|------|------|--------|
| `configs/garak.env` | Garak 扫描器配置 | `GARAK_MODE=baseline\|deep` |
| `configs/promptfoo.env` | Promptfoo 评估配置 | `PROMPTFOO_PROVIDER=...` |
| `configs/report.env` | 报告生成配置 | `REPORT_STYLE=offsec` |

### .env 扩展

```ini
# 新增选择器
GARAK_MODE=baseline                       # baseline | deep | disabled
PROMPTFOO_ENABLED=true                    # true | false
REPORT_STYLE=offsec                       # offsec | mitre | owasp | custom
MULTI_AGENT_MODE=sequential               # sequential | parallel | targeted
```

---

## 五、CLI 路由扩展

### 新增 CLI 参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--garak-mode` | str | `baseline` | Garak 扫描模式 (baseline/deep/disabled) |
| `--rag-mode` | str | `standard` | RAG 攻击模式 (standard/deep/injection-only) |
| `--multi-agent` | flag | False | 启用多 Agent 攻击模式 |
| `--agent-abuse` | flag | False | 启用 Agent 工具滥用攻击 |
| `--model-extraction` | flag | False | 启用模型提取攻击 |
| `--report-style` | str | `offsec` | 报告风格 (offsec/mitre/owasp/custom) |
| `--recon-profile` | str | None | recon Profile 文件路径 |

### Router 扩展

```python
# entrypoint/router.py — 新增路由分支
async def route_command(args, ctx):
    # 现有路由 ...
    if args.multi_agent:
        await _route_multi_agent_mode(args, ctx)
    elif args.garak_mode and args.garak_mode != "disabled":
        await _route_garak_scan_mode(args, ctx)
    # ...
```

---

## 六、数据流全景

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          完整攻击流水线数据流                             │
│                                                                         │
│  recon/                                                                  │
│   │  main.py → ReconEngine → target_profile.json                       │
│   │                                                                     │
│   ▼  (recon_adapter.py 桥接)                                            │
│  pyrit/                                                                 │
│   │  L0: recon_adapter.py → 解析 Profile → 构建 Attack Target           │
│   │  L1: garak_scanner.py → 两阶段扫描 → security_profile.json         │
│   │  L2: pyrit_orchestrator.py → 基于画像路由策略                       │
│   │  L3: {jailbreak/xpia/rag/agent_abuse/model_extraction}             │
│   │  L4: multi_agent_attack.py → PyRIT Session 编排                    │
│   │  L5: unified_eval.py → 统一 ASR + OWASP 映射                       │
│   │  L6: professional_report.py → 标准化报告 + Reproduce Package       │
│   ▼                                                                     │
│  outputs/                                                               │
│   ├── recon/                    ← Recon 输出                            │
│   ├── results/                  ← 攻击结果 + 报告                        │
│   └── knowledge_base/           ← 知识库沉淀                            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 七、实施优先级

| 优先级 | 层级/模块 | 状态 | 说明 |
|--------|----------|------|------|
| P0 | L0 (recon) | ✅ 已实现 | 前置侦察完整 |
| P0 | L2 (PyRIT Orchestrator) | ✅ 已实现 | 核心编排完整 |
| P0 | L3a (直接注入/越狱) | ✅ 已实现 | 转换器+载荷完整 |
| P0 | L5 (统一评估) | 🔧 已实现基础 | 需扩展 Promptfoo 集成 |
| P0 | L6 (报告生成) | ✅ 已实现 | 10 章标准报告 |
| P1 | L1 (Garak) | 🆕 新增 | 两阶段扫描 |
| P1 | L3b (XPIA) | 🆕 新增 | 间接注入 |
| P1 | L3c (RAG Promptfoo) | 🆕 新增 | RAG 专项 |
| P2 | L3d (Agent 滥用) | 🆕 新增 | 工具滥用 |
| P2 | L3e (模型提取) | 🆕 新增 | 反演攻击 |
| P2 | L4 (多 Agent) | 🆕 新增 | 多 Agent 攻击 |
| P2 | L5+OWASP Agentic | 🆕 新增 | Agentic Top10 |

---

## 八、与 Contributing 规范对照

| 规范 | 本设计对应 |
|------|-----------|
| YAML 唯一真实来源 | L3c/L3d/L3e/L4 新增载荷文件，注册到 manifest.yaml |
| 配置分离 | 新增 garak.env / promptfoo.env / report.env |
| 模块化部署 | 新增 executor/garak_scanner.py 等，不修改现有包职责 |
| 最小化改动 | 所有新增功能通过新文件实现，不破坏现有代码 |
| Bootstrap 模式 | 复用 BootstrapContext，新增字段有默认值 |
| Factory 模式 | 复用 targets/factories.py 工厂 |
| Router 模式 | entrypoint/router.py 新增分支，不修改现有路由逻辑 |
| Facade 模式 | orchestrators 整合各层调度 |
| 依赖管理 | 新增依赖需审批（garak/promptfoo 为可选依赖） |
| 编码规范 | 所有新文件 UTF-8 without BOM, LF, 4空格缩进 |
