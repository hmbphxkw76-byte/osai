# 侦察架构规则 — 调度器 + 格式转换器原则

## 规则编号: ARCH-001

**生效日期**: 2026-07-17
**优先级**: 强制（MUST）

---

## 规则正文

### 1. 核心原则

本框架只做"调度器 + 格式转换器"，不重复造轮子。

**调度器**：统一调度开源工具，编排执行顺序，处理并发和错误。
**格式转换器**：将各工具的输出格式转为统一的 TargetProfile JSON。
**不重复造轮子**：所有侦察/攻击能力来自开源工具，本框架不重写任何探测逻辑。

### 2. 架构约束

| 约束 | 说明 |
|------|------|
| 模块独立 | `reconnaissance/` 不 import `attack/` 或 `orchestrators/` |
| 接口契约 | 侦察与攻击通过 `target_profile.json` 文件通信 |
| 薄壳适配 | 每个 Adapter ≤ 100 行，仅做格式转换 |
| 失败隔离 | 任一工具失败不影响其他工具，ProfileMerger 合并可用结果 |
| 可扩展 | 新增工具只需实现 BaseAdapter 接口 |

### 3. 推荐工具组合

#### 3.1 核心工具（Python 原生）

| 工具 | 定位 | 集成方式 | 输出 → TargetProfile 字段 |
|------|------|---------|--------------------------|
| LLMmap | 模型指纹识别 | Python import | `fingerprint.model_family` |
| Garak | 漏洞扫描 | Python SDK | `findings.confirmed/potential` |
| DeepTeam | OWASP 红队 | Python import | `findings + attack_references` |

### 4. 目录结构

```
pyrit/                           # 项目根目录
├── tools/                       # 外部工具目录（当前为空）
│   └── README.md                # 工具清单
├── pyrit_ai300/
│   ├── reconnaissance/          # 侦察引擎（完全独立）
│   │   ├── recon_engine.py      # 统一调度入口
│   │   ├── target_profile.py    # TargetProfile 数据模型
│   │   ├── profile_merger.py    # 多工具结果合并
│   │   ├── adapters/            # 薄壳适配器
│   │   │   ├── base_adapter.py  # 抽象基类
│   │   │   ├── llmmap_adapter.py    # → import LLMmap
│   │   │   ├── garak_adapter.py     # → import garak
│   │   │   └── deepteam_adapter.py  # → import deepteam
│   │   └── utils/
│   │       ├── http_client.py   # HTTP 客户端
│   │       └── result_parser.py # 结果解析器
│   ├── attack/                  # 攻击引擎（完全独立）
│   │   ├── attack_engine.py     # 攻击主引擎
│   │   └── profile_loader.py    # 读 TargetProfile → 内部参数
│   └── cli.py                   # 编排层（薄壳路由）
```

### 5. TargetProfile Schema

```yaml
target:
  url: "https://target.com/chat"
  discovered_at: "2026-07-17T10:00:00Z"
  recon_depth: "standard"

fingerprint:
  model_family: "GPT-4"
  model_version: null
  platform_type: "agent"          # chatbot | rag | agent | mcp | unknown
  confidence: 0.85
  evidence: []

capabilities:
  system_prompt: true
  tool_calling: true
  file_upload: false
  multi_turn: true
  streaming: true
  multimodal: false

security_posture:
  content_filter: "moderate"      # strict | moderate | none
  role_isolation: false
  input_validation: "basic"
  rate_limiting: true

findings:
  confirmed:
    - type: "system_prompt_leak"
      confidence: 0.95
      evidence: "..."
      source_tool: "garak"
      owasp_mapping: "LLM01"
  potential:
    - type: "direct_injection"
      confidence: 0.7
      reason: "..."
      source_tool: "deepteam"
      owasp_mapping: "LLM01"

attack_references:
  payload_refs:
    - "owasp:llm:llm01"
    - "owasp:agentic:asi02"
  recommended_strategies:
    - "DIRECT_SINGLE"
    - "PROGRESSIVE"
  excluded_strategies: []
```

### 6. 违规示例

```python
# ❌ 错误：在 Adapter 中重写探测逻辑
class GarakAdapter(BaseAdapter):
    def scan(self, target):
        # 自己写 prompt injection 检测逻辑 — 重复造轮子！
        result = self._custom_injection_check(target)
        ...

# ✅ 正确：调用 Garak 原生 API，只做格式转换
class GarakAdapter(BaseAdapter):
    def scan(self, target):
        report = garak.run(target)  # 调用原生 API
        return self._to_profile(report)  # 格式转换
```

```python
# ❌ 错误：侦察模块 import 攻击模块
from pyrit_ai300.attack.attack_engine import AttackEngine

# ✅ 正确：通过 TargetProfile JSON 文件通信
profile = TargetProfile.load("results/profiles/target.json")
```

---

## 考试映射

| 考试模块 | 侦察工具 | 覆盖 |
|---------|---------|------|
| LLM01 Prompt Injection | Garak + DeepTeam | Prompt Injection, Jailbreak |
| LLM02 Sensitive Disclosure | Garak + DeepTeam | Data Leakage, PII |
| LLM03 Training Data Poisoning | DeepTeam | Bias, Toxicity |
| LLM06 Overreliance | DeepTeam | Hallucination, Misinformation |
| ASI01-ASI10 Agentic | DeepTeam | Goal Theft, Recursive Hijacking, Excessive Agency |
