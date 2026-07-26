# 多数据源组合方案 — 完整攻击载荷数据集成指南

## 1. 概述

本文档说明如何将 **PyRIT 原生内置数据集**、**PyRIT 远程数据集**、**项目 OWASP 本地数据集**（`data/owasp/`）和 **Burp HTTP 请求模板**（`data/burp/`）组合为完整的攻击载荷数据，在 5 层数据驱动架构基础上实现多样性驱动的端到端自动化攻击流水线。

### 数据源总览

| 数据源 | 目录 | 载荷数 | 格式 | 用途 |
|---|---|---|---|---|
| **OWASP 本地** | `data/owasp/` | 975 seeds (98 YAML) | PyRIT SeedDataset | OWASP LLM01-10 + ASI01-10 全分类攻击载荷 |
| **自定义** | `data/custom/` | 按需 | PyRIT SeedDataset | 用户自定义攻击载荷 |
| **PyRIT 远程** | PyRIT SeedDatasetProvider | 60+ 数据集 | PyRIT SeedDataset | HarmBench/JailbreakBench/AdvBench 等 |
| **PyRIT 原生内置** | pyrit.datasets | 10+ 数据集 | PyRIT SeedDataset | pyrit内置 OWASP/红队示例 |
| **Burp HTTP** | `data/burp/` | 2 模板 | HTTP 请求文本 | HTTP 目标攻击请求模板 |

---

## 2. 五层架构中的数据流

```
┌─────────────────────────────────────────────────────────┐
│  ① 数据准备层                                            │
│  ├── OWASP 本地  (data/owasp/)     → 975 seeds          │
│  ├── 自定义      (data/custom/)    → user-defined       │
│  ├── PyRIT 远程  (SeedDatasetProvider) → 60+ datasets   │
│  ├── PyRIT 原生  (pyrit.datasets)  → built-in           │
│  └── Burp HTTP   (data/burp/)      → HTTP targets       │
│         │                                                │
│         ▼  DatasetManager.load_datasets()                │
│  ② 数据管理层 — CentralMemory                            │
│  ├── add_seed_datasets_to_memory_async()                 │
│  ├── get_seed_groups(harm_categories, owasp_id, ...)    │
│  └── get_seeds(dataset_name, technique, ...)            │
│         │                                                │
│         ▼  SeedGroupSelector.build_catalog()             │
│  ②.5 交互选择层 — SeedGroupSelector                      │
│  ├── filter_by_owasp() / filter_by_harm()              │
│  ├── filter_multi_turn() / select_all()                 │
│  └── prompt_user() → selected_groups                     │
│         │                                                │
│         ▼  AttackPreparator.prepare_batch()              │
│  ③ 攻击准备层 — AttackSeedGroup                          │
│  ├── objective / next_message / prepended_conversation  │
│  └── 条件分派: multi_turn→crescendo, single→prompt_send  │
│         │                                                │
│         ▼  NativeAttackExecutor / ScenarioOrchestrator   │
│  ④ 攻击执行层 — 批量并行 + 升级重试                       │
│  ├── SingleTurnExecutor (直发型)                         │
│  ├── MultiTurnExecutor (军师迭代型)                      │
│  └── SequentialExecutor (异构链组合)                     │
│         │                                                │
│         ▼  Scorer + Memory 审计链                        │
│  ⑤ 评估追踪层 — 报告 + 证据 + OWASP 映射                  │
└─────────────────────────────────────────────────────────┘
```

---

## 3. OWASP 本地数据集 (`data/owasp/`)

### 3.1 目录结构

```
data/owasp/
  llm/                          # OWASP LLM Top 10 (2025)
    _registry.yaml              # 分类元数据
    llm01/                      # 提示注入 (975 seeds 中 ~400+)
      direct_injection.yaml     # 原有基础版 (6 seeds)
      direct_injection_expanded.yaml  # 扩充版 (20 seeds)
      skeleton_key.yaml         # ASR 85-100% (9 seeds)
      best_of_n_jailbreak.yaml  # ASR 70-88% (6 seeds)
      many_shot_jailbreak.yaml  # ASR 75-95% (10 seeds)
      crescendo_jailbreak.yaml  # 多轮渐进 (27 seeds)
      bad_likert_judge.yaml     # ASR 55-80% (5 seeds)
      wrapping_attack.yaml      # ASR 55-70% (7 seeds)
      iteration_pair_tap.yaml   # PAIR/TAP (5 seeds)
      cipher_chat.yaml          # ASR 45-65% (6 seeds)
      deep_inception.yaml       # ASR 45-65% (5 seeds)
      autodan.yaml              # ASR 40-70% (5 seeds)
      encoding_bypass.yaml      # 14 种编码绕过 (14 seeds)
      jailbreak_templates.yaml  # 75 活跃越狱模板 (75 seeds)
      jailbreak_archive.yaml    # 90 归档越狱模板 (90 seeds)
      cve_2025_32711_echoleak.yaml  # CVE CVSS 9.3 (11 seeds)
      frontier_2025_001_hcot.yaml   # Frontier CVSS 8.5 (6 seeds)
      ... (共 ~30 个文件)
    llm02/ ~ llm10/             # 其余 LLM 分类
  agentic/                      # OWASP Agentic AI Top 10 (2025)
    asi01/ ~ asi10/             # Agentic 分类
```

### 3.2 载荷元数据

每个 seed 包含丰富的 ASR 元数据：

```yaml
seeds:
  - value: "You are an AI assistant deployed by a trusted organization..."
    role: "user"
    metadata:
      owasp_id: "LLM01"
      technique: "skeleton_key_basic"
      technique_group: "skeleton_key"
      attack_mode: "single_turn"
      technique_name: "Skeleton Key — 基础版"
      difficulty: "medium"
      evasion_level: "high"
      detection_risk: "low"
      asr_baseline:
        gpt_4o: 0.95
        claude_4_opus: 0.72
        gemini_2_5_pro: 0.85
      target_models: [openai, anthropic, google, meta, alibaba]
      last_tested: "2026-07-15"
      severity: "critical"
```

### 3.3 自动加载

`DatasetManager.load_owasp_datasets()` 自动扫描 `data/owasp/{framework}/` 目录：
- 跳过 `_` 前缀文件（registry/metadata）
- 使用 `SeedDataset.from_yaml_file()` 加载每个 YAML
- 统一存入 `CentralMemory`

---

## 4. PyRIT 远程数据集

### 4.1 可用数据集

PyRIT 1.0.0 内置 60+ 远程数据集：

| 数据集 | 描述 | 载荷类型 |
|---|---|---|
| `harmbench` | HarmBench 标准化红队基准 | 有害行为 prompt |
| `jailbreakbench` | JailbreakBench 越狱基准 | 越狱模板 |
| `advbench` | AdvBench 对抗性基准 | 有害 prompt |
| `strongreject` | StrongReject 拒绝评估 | 越狱 prompt |
| `forbidden_question` | 禁止问题数据集 | 敏感问题 |
| `malicious_instruct` | 恶意指令数据集 | 恶意指令 |
| ... | 共 60+ 数据集 | ... |

### 4.2 启用方式

**方式 1：配置文件**

```yaml
# config/defaults/pipeline.yaml → dataset_manager 段
remote_datasets:
  enabled: true
  datasets:
    - harmbench
    - jailbreakbench
    - advbench
```

**方式 2：环境变量**

```bash
# .env
REMOTE_DATASETS_ENABLED=true
REMOTE_DATASET_NAMES=harmbench,jailbreakbench
```

**方式 3：代码**

```python
manager = DatasetManager()
await manager.load_remote_datasets(
    dataset_names=["harmbench", "jailbreakbench"],
    cache=True,
    max_concurrency=3,
)
```

---

## 5. PyRIT 原生内置数据集

PyRIT 1.0.0 自带若干内置数据集，可通过 `SeedDatasetProvider` 直接加载：

```python
from pyrit.datasets import SeedDatasetProvider

# 加载全部内置数据集
datasets = await SeedDatasetProvider.fetch_datasets_async(cache=True)

# 指定数据集
datasets = await SeedDatasetProvider.fetch_datasets_async(
    dataset_names=["pyrit_owasp_llm01", "pyrit_owasp_llm06"],
)
```

---

## 6. Burp HTTP 请求模板 (`data/burp/`)

### 6.1 用途

Burp 数据用于配置 HTTP 攻击目标，而非作为 seed 数据集。`data/burp/` 下的 `.txt` 文件包含原始 HTTP 请求模板，由 `BurpTargetBuilder` 解析为 `HTTPTarget` 配置。

### 6.2 文件格式

```
POST /v1/chat/completions HTTP/1.1
Host: target.example.com
Content-Type: application/json
Authorization: Bearer {{api_key}}

{"model": "gpt-4", "messages": [{"role": "user", "content": "{{prompt}}"}]}
```

### 6.3 集成方式

Burp 模板在侦察阶段（[2/9]）被用于目标端点发现和认证提取，不直接进入 CentralMemory。攻击载荷仍来自 OWASP/远程数据集，通过 HTTPTarget 发送到目标。

---

## 7. 多数据源组合策略

### 7.1 推荐组合

| 场景 | OWASP | 自定义 | 远程 | Burp | 说明 |
|---|---|---|---|---|---|
| **AI-300 考试** | ✅ 全部 | ❌ | ✅ jailbreakbench | ❌ | OWASP 全分类 + 越狱基准 |
| **LLM 红队评估** | ✅ LLM01-02 | ✅ | ✅ harmbench | ❌ | 注入 + 信息泄露 + 基准 |
| **Agent 评估** | ✅ ASI01-10 | ✅ | ❌ | ❌ | Agentic 全分类 |
| **HTTP/Web 攻击** | ✅ LLM01 | ❌ | ❌ | ✅ | 注入 + HTTP 目标 |
| **全面评估** | ✅ 全部 | ✅ | ✅ 全部 | ✅ | 全数据源组合 |
| **CI/CD 回归** | ✅ 指定 ID | ❌ | ❌ | ❌ | 快速回归测试 |

### 7.2 配置示例

**`.env` 配置（全面评估）：**

```bash
# OWASP 本地数据集
OWASP_FRAMEWORKS=llm,agentic
OWASP_IDS=                    # 空=全部
EXCLUDE_IDS=                  # 空=不排除

# 自定义数据集
CUSTOM_DATASETS_ENABLED=true

# PyRIT 远程数据集
REMOTE_DATASETS_ENABLED=true
REMOTE_DATASET_NAMES=harmbench,jailbreakbench,advbench

# 交互选择
INTERACTIVE_SELECTION=false   # CI/CD 模式全选
```

**代码配置：**

```python
manager = DatasetManager()

# ①→② 自由组合数据源
await manager.load_datasets(
    owasp=True,                      # OWASP 本地 (975 seeds)
    owasp_frameworks=["llm", "agentic"],
    custom=True,                     # 自定义数据集
    remote=True,                     # PyRIT 远程数据集
    remote_dataset_names=["harmbench", "jailbreakbench"],
)

# ②→③ 查询（多维过滤）
groups = manager.get_seed_groups(
    harm_categories=["prompt_injection"],
    # dataset_name="owasp_llm01_skeleton_key",
    # metadata={"technique_group": "skeleton_key"},
)
```

---

## 8. 端到端自动化流水线

### 8.1 流水线 9 阶段

```
[1/9] 初始化 PyRIT (CentralMemory + SQLite + 重试配置)
[2/9] 侦察 (端点发现 + AI 类型识别 + Burp HTTP 模板)
[3/9] 分析 (策略选择 + 优先级评估)
[4/9] ①→② 数据准备 + 管理 (多数据源 → CentralMemory + 多样性报告)
[5/9] ②→②.5→③ 查询 + 交互选择 + 攻击准备
[6/9] ④ 批量执行攻击 (单轮/多轮/编码增强/顺序组合)
[7/9] 输出执行结果
[8/9] 报告生成 (OWASP 映射 + 证据导出 + 多样性分析)
[9/9] 总结
```

### 8.2 数据源多样性报告

流水线 [4/9] 阶段自动生成多样性报告：

```
  [OK] CentralMemory: 1035 seeds, 180 seed groups
  [OK] OWASP 覆盖: 20 分类
    ASI01: 22 seeds
    ASI03: 19 seeds
    ASI06: 17 seeds
    ASI07: 16 seeds
    LLM01: 420 seeds
    LLM02: 39 seeds
    LLM03: 59 seeds
    ...
  [OK] 技术覆盖: 65 种技术组
  [OK] 高 ASR 载荷 (>=65%): 185 seeds
  [OK] Burp HTTP 模板: 2 个 (data/burp/)
```

### 8.3 灵活的数据源选择

通过 `owasp_ids` CLI 参数或配置灵活选择：

```bash
# 只测 LLM01 提示注入
python pipeline.py --owasp-ids llm01

# 测 LLM01 + LLM06（注入 + 过度代理）
python pipeline.py --owasp-ids llm01 llm06

# 测全部 Agentic AI
python pipeline.py --owasp-ids asi01 asi02 asi03 asi04 asi05 asi06 asi07 asi08 asi09 asi10

# 全量测试（默认）
python pipeline.py
```

---

## 9. 载荷模板适配器 (`payload_adapter.py`)

### 9.1 功能

`src/payloads/payload_adapter.py` 提供从源项目 "Payload Template" 格式到 PyRIT 原生 SeedDataset 格式的自动转换：

- `convert_payload_file()` — 转换单个 YAML 文件
- `convert_jailbreak_directory()` — 合并转换 jailbreak 模板目录

### 9.2 转换规则

| 源字段 | → | 目标字段 |
|---|---|---|
| `payloads[].payload` (含 `{goal}`) | → | `seeds[].value` (具体值) |
| `payloads[].asr_baseline` | → | `seeds[].metadata.asr_baseline` |
| `payloads[].difficulty` | → | `seeds[].metadata.difficulty` |
| `frontier` (top-level) | → | `seeds[].metadata.frontier` |
| `[轮次1]...[轮次5]` | → | `prompt_group_alias` + `sequence` |
| `{{ }}` (Jinja2 冲突) | → | `{ { } }` (转义) |

### 9.3 使用示例

```python
from src.payloads.payload_adapter import convert_payload_file
from pathlib import Path

count = convert_payload_file(
    source_path=Path("source.yaml"),
    output_path=Path("data/owasp/llm/llm01/skeleton_key.yaml"),
    owasp_id="LLM01",
    dataset_name="owasp_llm01_skeleton_key",
    dataset_description="Skeleton Key 越狱",
)
print(f"Generated {count} seeds")
```

---

## 10. 载荷统计摘要

### 10.1 按 OWASP 分类

| OWASP ID | 文件数 | Seeds 数 | 高 ASR 载荷 | CVE/Frontier |
|---|---|---|---|---|
| LLM01 | ~30 | ~420 | ~120 | 2 (EchoLeak + H-CoT) |
| LLM02 | 4 | ~39 | ~10 | 0 |
| LLM03 | 5 | ~59 | ~15 | 2 (Picklescan + LeRobot) |
| LLM04 | 5 | ~41 | ~10 | 0 |
| LLM05 | 1 | ~17 | ~5 | 0 |
| LLM06 | ~15 | ~120 | ~30 | 4 (Flowise + OpenCode + OpenClaw + SemanticKernel) |
| LLM07 | 3 | ~36 | ~10 | 1 (EchoLeak Prompt Leak) |
| LLM08 | 5 | ~41 | ~5 | 1 (ChromaDB) |
| LLM09 | 3 | ~33 | ~5 | 0 |
| LLM10 | 2 | ~8 | ~0 | 0 |
| ASI01 | 2 | ~22 | ~5 | 0 |
| ASI03 | 2 | ~19 | ~5 | 0 |
| ASI06 | 2 | ~17 | ~5 | 0 |
| ASI07 | 2 | ~16 | ~5 | 0 |
| 其他 ASI | 4 | ~18 | ~0 | 0 |
| **合计** | **98** | **975** | **~225** | **10** |

### 10.2 按技术类型

| 技术类型 | Seeds 数 | ASR 范围 |
|---|---|---|
| Skeleton Key | 9 | 85-100% |
| Best-of-N Jailbreak | 6 | 70-88% |
| Many-Shot Jailbreak | 10 | 75-95% |
| Crescendo (多轮) | 27 | 65-85% |
| Bad Likert Judge | 5 | 55-80% |
| Wrapping Attack | 7 | 55-70% |
| PAIR/TAP | 5 | 45-80% |
| A2A Injection | 6 | 80-85% |
| Jailbreak 模板 (活跃) | 75 | 15-55% |
| Jailbreak 模板 (归档) | 90 | 8-35% |
| CVE/Frontier | 122 | N/A (真实漏洞) |
| 编码绕过 | 14 | 45-60% |
| 其他技术 | ~599 | varies |

---

## 11. 最佳实践

### 11.1 考试准备

```bash
# 1. 加载全部 OWASP + 越狱基准
REMOTE_DATASETS_ENABLED=true
REMOTE_DATASET_NAMES=jailbreakbench
INTERACTIVE_SELECTION=false

# 2. 运行全量测试
python pipeline.py

# 3. 针对薄弱分类加强
python pipeline.py --owasp-ids llm01  # 提示注入专项
```

### 11.2 生产红队评估

```bash
# 1. 选择性加载
OWASP_IDS=llm01,llm02,llm06,llm07
REMOTE_DATASETS_ENABLED=true
REMOTE_DATASET_NAMES=harmbench,advbench

# 2. 启用交互选择
INTERACTIVE_SELECTION=true

# 3. 运行
python pipeline.py https://target.example.com
```

### 11.3 CI/CD 集成

```bash
# 快速回归（仅高 ASR 载荷）
OWASP_IDS=llm01
INTERACTIVE_SELECTION=false
BATCH_MAX_CONCURRENCY=4
BATCH_PER_ATTACK_TIMEOUT=60
SCENARIO_MAX_RETRIES=0

python pipeline.py
```

---

## 12. 设计原则

1. **原生优先**：所有数据源统一通过 PyRIT 原生 `SeedDataset` → `CentralMemory` → `SeedGroup` → `AttackSeedGroup` 流转
2. **向后兼容**：新增 YAML 文件不修改任何现有文件或代码
3. **自由组合**：各数据源独立开关，非一次性打包
4. **元数据保留**：ASR 基线、难度、规避等级完整保留到 `metadata`
5. **多轮正确性**：多轮模板自动拆分为 `prompt_group_alias` + `sequence`
6. **Jinja2 安全**：payload 中的 `{{ }}` 自动转义避免模板解析错误
7. **多样性驱动**：流水线自动报告 OWASP 覆盖/技术覆盖/高 ASR 载荷统计
