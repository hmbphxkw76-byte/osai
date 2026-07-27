# 三项目拆分实施方案

## 一、Context

当前 `pyrit-web-recon` 已完成面向 LLM AI Web 应用的侦察能力（11 阶段流水线、TargetProfile、PyRIT target 导出、AIG/RedAmon/SkillSpector 集成）。但项目边界单一，无法承载攻击执行与模型/RAG/Embedding 评估。历史上 `D:\文档\GitHub\codes\pyrit_20260722\pyrit_ai300` 因把所有能力塞进一个 monolithic 包而失败。本次目标是在当前仓库内按“单仓库多包”形式拆出 3 个逻辑独立项目，避免重复造轮子，对齐 L5 专家水平。

## 二、总体架构

```
d:\文档\GitHub\osai\pyrit-web-recon\         # 仓库根（monorepo）
├── pyrit-web-recon/                          # 项目 1：侦察
│   ├── src/
│   ├── main.py
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
├── pyrit-attack-toolkit/                     # 项目 2：攻击执行
│   ├── src/pyrit_attack_toolkit/
│   ├── main.py
│   ├── pyproject.toml
│   ├── .env.example
│   └── README.md
├── ai300-eval-kit/                           # 项目 3：模型/RAG/Embedding 评估
│   ├── src/ai300_eval_kit/
│   ├── main.py
│   ├── pyproject.toml
│   ├── .env.example
│   └── README.md
├── ai300-schemas/                            # 共享数据契约包
│   ├── src/ai300_schemas/
│   ├── pyproject.toml
│   └── README.md
├── docker-compose.integration.yml            # 已有：AIG + RedAmon + Redis + MinIO
├── .gitignore
└── README.md
```

### 项目间依赖

| 依赖方向 | 类型 | 载体 |
|---------|------|------|
| pyrit-web-recon → ai300-schemas | 代码依赖 | `pip install -e ./ai300-schemas` |
| pyrit-attack-toolkit → ai300-schemas | 代码依赖 | `pip install -e ./ai300-schemas` |
| ai300-eval-kit → ai300-schemas | 代码依赖 | `pip install -e ./ai300-schemas` |
| pyrit-attack-toolkit → pyrit-web-recon output | 数据依赖 | 读取 `../pyrit-web-recon/results/recon/pyrit/*.json` |
| ai300-eval-kit → pyrit-web-recon output | 数据依赖 | 读取 `../pyrit-web-recon/results/recon/profiles/*.json` |
| pyrit-attack-toolkit → PyRIT/Garak | 运行时依赖 | `pyrit[optional]` / `garak` CLI |
| ai300-eval-kit → Giskard/ART/DeepEval | 运行时依赖 | `giskard[optional]` / `art[optional]` |

## 三、Phase 0：仓库结构重组

1. 在仓库根创建 4 个目录：
   - `pyrit-web-recon/`
   - `pyrit-attack-toolkit/`
   - `ai300-eval-kit/`
   - `ai300-schemas/`
2. 将当前所有文件/目录（`src/`、`main.py`、`requirements.txt`、`.env.example`、`.env`、`config/`、`README.md`、`.gitignore` 等）移入 `pyrit-web-recon/`。
3. 保留仓库根 `docker-compose.integration.yml`（AIG/RedAmon 基础设施为全仓库共享）。
4. 在仓库根新建 `README.md`，说明 monorepo 结构和各项目入口。
5. 在仓库根新建/更新 `.gitignore`，忽略各项目的 `.venv/`、`__pycache__/`、`results/`、`credentials/`。

## 四、Phase 1：ai300-schemas 共享契约包

### 目标
把当前 `src/recon/target_profile.py` 和 `src/integration/schemas/unified_finding.py` 下沉为独立包，供 3 个项目共享。

### 关键文件

- `ai300-schemas/pyproject.toml`
- `ai300-schemas/src/ai300_schemas/__init__.py`
- `ai300-schemas/src/ai300_schemas/target_profile.py`（从 `pyrit-web-recon/src/recon/target_profile.py` 迁移并精简）
- `ai300-schemas/src/ai300_schemas/unified_finding.py`（从 `pyrit-web-recon/src/integration/schemas/unified_finding.py` 迁移）
- `ai300-schemas/src/ai300_schemas/pyrit_target.py`（新增 PyRIT target 配置 schema）
- `ai300-schemas/tests/test_target_profile.py`
- `ai300-schemas/tests/test_unified_finding.py`

### 内容要点

1. `TargetProfile`、`FingerprintData`、`VulnerabilityFinding` 保留现有字段，移除与 recon 流水线强耦合的方法（如浏览器相关方法可下沉到 pyrit-web-recon）。
2. `UnifiedFinding`、`Evidence` 保留，增加 `source_tool` 取值范围：`pyrit-web-recon`、`pyrit-attack-toolkit`、`ai300-eval-kit`、`ai-infra-guard`、`redamon`、`skillspector`、`garak`、`pyrit`、`giskard`、`art`。
3. 新增 `PyRITTargetConfig` dataclass，字段：`target_type`（`AzureOpenAITarget`/`HTTPTarget`/`OpenAITarget`/`PlaywrightTarget`）、`endpoint`、`model_name`、`api_key`、`headers`、`extra`。
4. 所有 dataclass 提供 `to_dict()`、`from_dict()`、`to_json()`、`from_json()`。
5. 提供 JSON Schema 文件：`ai300-schemas/schemas/target_profile.schema.json`、`unified_finding.schema.json`。

### 复用现有代码

- 复用 `src/recon/target_profile.py:TargetProfile.to_dict()` 序列化逻辑。
- 复用 `src/integration/schemas/unified_finding.py:UnifiedFinding.to_dict()` / `from_dict()` 逻辑。

## 五、Phase 2：pyrit-web-recon 改造

### 目标
让项目 1 专注于侦察，并成为项目 2/3 的数据生产者。

### 关键文件

- `pyrit-web-recon/requirements.txt`：增加 `-e ../ai300-schemas`。
- `pyrit-web-recon/src/recon/target_profile.py`：保留对 `ai300_schemas.TargetProfile` 的薄封装或改为直接从 schemas 导入；保留 `to_pyrit_target()` 方法（因为该方法依赖 recon 细节）。
- `pyrit-web-recon/src/integration/schemas/unified_finding.py`：改为从 `ai300_schemas` 重新导出，或删除并统一使用 schemas 包。
- `pyrit-web-recon/src/export/profile_exporter.py`：使用 `ai300_schemas.TargetProfile`。
- `pyrit-web-recon/src/pipeline/stages/export.py`：保持 PyRIT target JSON 导出逻辑，确保输出路径与格式稳定。
- `pyrit-web-recon/src/pipeline/stages/external_dispatch.py`：继续调用 AIG/SkillSpector/RedAmon，结果转换为 `UnifiedFinding`。

### 调整点

1. 所有 `from src.recon.target_profile import ...` 改为 `from ai300_schemas import TargetProfile, FingerprintData, VulnerabilityFinding`。
2. `to_pyrit_target()` 作为 `TargetProfile` 的扩展方法保留在 `pyrit-web-recon/src/recon/profile_pyrit_adapter.py`，避免污染 schemas 包。
3. 输出路径约定：
   - `results/recon/profiles/{domain}_{ts}.json`
   - `results/recon/profiles/{domain}_{ts}.yaml`
   - `results/recon/pyrit/{domain}_pyrit_target.json`

### 复用现有代码

- `src/pipeline/stages/export.py:_export_pyrit_target()` 逻辑基本不变。
- `src/export/profile_exporter.py:ProfileExporter.export()` 逻辑基本不变。
- `src/integration/aig/client.py`、`src/integration/skillspector/client.py` 的适配器模式继续复用。

## 六、Phase 3：pyrit-attack-toolkit（项目 2）

### 目标
消费侦察结果，直接调用 PyRIT/Garak 执行对话层攻击，输出 `UnifiedFinding`。

### 目录结构

```
pyrit-attack-toolkit/
├── src/pyrit_attack_toolkit/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py                    # 配置加载
│   ├── loaders/
│   │   ├── __init__.py
│   │   └── profile_loader.py        # 读取 pyrit-web-recon 输出
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base.py                  # AttackAdapter 抽象接口
│   │   ├── pyrit_adapter.py         # PyRIT 库调用（可选依赖，lazy import）
│   │   └── garak_adapter.py         # Garak CLI 子进程调用
│   ├── strategies/
│   │   ├── __init__.py
│   │   └── strategy_selector.py     # 根据 profile 选策略/探针
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── attack_report.py         # 攻击报告模型
│   │   └── unified_converter.py     # 工具输出 → UnifiedFinding
│   └── main.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── system/
├── pyproject.toml
├── .env.example
└── README.md
```

### 关键实现

1. **`profile_loader.py`**
   - 函数 `load_target_profile(path: str) -> TargetProfile`
   - 函数 `load_pyrit_target(path: str) -> PyRITTargetConfig`
   - 支持从 `results/recon/profiles/*.json` 或 `results/recon/pyrit/*.json` 加载。

2. **`adapters/base.py`**
   - `AttackAdapter` 抽象基类，方法：
     - `__init__(config: Dict[str, Any])`
     - `run(target: PyRITTargetConfig, strategy: AttackStrategy) -> AttackResult`
     - `is_available() -> bool`

3. **`adapters/pyrit_adapter.py`**
   - lazy import `pyrit`。
   - 根据 `target_type` 构造 `PromptTarget`：
     - `HTTPTarget` → HTTP API
     - `AzureOpenAITarget` → Azure OpenAI
     - `OpenAITarget` → OpenAI 兼容
     - `PlaywrightTarget` → SPA/Web UI
   - 使用 `PromptSendingOrchestrator` 执行 `SeedPrompt`。
   - 捕获 `PromptRequestResponse` 结果。

4. **`adapters/garak_adapter.py`**
   - 构造 `garak` CLI 命令：`garak --model_type ... --probes ... --target ...`。
   - 通过 subprocess 调用，捕获 `report.json` / `report.html`。
   - 解析 Garak JSON 报告，转换为 `AttackResult`。

5. **`strategies/strategy_selector.py`**
   - 根据 `TargetProfile` 特征返回 `AttackStrategy` 列表：
     - `rag_features` → RAG 上下文操控策略
     - `agent_features` / `mcp` → Tool misuse 策略
     - `target_type == "api"` → Direct API injection
     - `target_type in ("spa", "web_ui")` → Browser automation
     - `model_family` 已知 → 模型专用越狱模板

6. **`reporting/unified_converter.py`**
   - `AttackResult` → `UnifiedFinding`：
     - `source_tool = "pyrit"` / `"garak"`
     - `category` 映射到 `prompt_injection` / `jailbreak` / `data_exfil` 等
     - `owasp_llm_id` 如 `LLM01:2025`
     - `evidence` 保存请求/响应/对话记录

7. **`cli.py` / `main.py`**
   - 入口：`python main.py --profile ../pyrit-web-recon/results/recon/pyrit/*.json --adapter pyrit --output results/attacks/`
   - 支持 `--adapter garak`、`--adapter all`。
   - 支持 `--dry-run` 预览策略。

### 依赖

```toml
[project]
name = "pyrit-attack-toolkit"
dependencies = [
    "ai300-schemas",
    "pyyaml>=6.0",
    "httpx>=0.27.0",
    "python-dotenv>=1.0.0",
]

[project.optional-dependencies]
pyrit = ["pyrit>=0.14.0"]
garak = ["garak>=0.10.0"]
all = ["pyrit>=0.14.0", "garak>=0.10.0"]
```

### 测试

- **单元测试**：`tests/unit/adapters/test_garak_adapter.py`、`tests/unit/strategies/test_strategy_selector.py`
- **集成测试**：`tests/integration/test_pyrit_adapter.py`（需 mock PyRIT）
- **系统测试**：`tests/system/test_recon_to_attack.py`（端到端读取 recon 输出并生成报告）

## 七、Phase 4：ai300-eval-kit（项目 3）

### 目标
消费侦察结果，调用 Giskard/ART/DeepEval 执行 RAG/模型/Embedding 评估，输出 `UnifiedFinding`。

### 目录结构

```
ai300-eval-kit/
├── src/ai300_eval_kit/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── loaders/
│   │   ├── __init__.py
│   │   └── profile_loader.py
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base.py                  # EvalAdapter 抽象接口
│   │   ├── giskard_adapter.py       # RAG/LLM 评估
│   │   ├── art_adapter.py           # Embedding/对抗 ML
│   │   └── deepeval_adapter.py      # 可选
│   ├── strategies/
│   │   ├── __init__.py
│   │   └── eval_strategy_selector.py
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── eval_report.py
│   │   └── unified_converter.py
│   └── main.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── system/
├── pyproject.toml
├── .env.example
└── README.md
```

### 关键实现

1. **`adapters/giskard_adapter.py`**
   - lazy import `giskard`。
   - 支持两种模式：
     - **RAG 评估**：扫描 RAG pipeline（需要 knowledge base + questions）。
     - **LLM 扫描**：使用 `giskard.scan` 对 LLM 做偏见、毒性、提示注入测试。
   - 输入：`TargetProfile` + 可选 `dataset_path`。
   - 输出：`EvalResult`。

2. **`adapters/art_adapter.py`**
   - lazy import `art`。
   - 根据 profile 推断 embedding/模型端点。
   - 支持：
     - `EmbeddingInversionAttack`
     - `MembershipInferenceAttack`
     - `ModelExtractionAttack`（如端点允许）
   - 输出：`EvalResult`。

3. **`adapters/deepeval_adapter.py`**（可选）
   - lazy import `deepeval`。
   - 用于 hallucination、answer relevance、RAG recall 评估。

4. **`strategies/eval_strategy_selector.py`**
   - `rag_features` → Giskard RAG eval
   - `model_family` + API endpoint → Giskard LLM scan
   - `embedding endpoint` exposed → ART embedding attack
   - `target_type == "api"` + model accessible → ART model privacy tests

5. **`reporting/unified_converter.py`**
   - `EvalResult` → `UnifiedFinding`：
     - `source_tool = "giskard"` / `"art"` / `"deepeval"`
     - `category`：`rag_poisoning`、`embedding_inversion`、`membership_inference` 等
     - `owasp_llm_id` 如 `LLM07:2025`（训练数据泄露）

6. **`cli.py` / `main.py`**
   - 入口：`python main.py --profile ../pyrit-web-recon/results/recon/profiles/*.json --adapter giskard --output results/eval/`
   - 支持 `--adapter art`、`--adapter all`。

### 依赖

```toml
[project]
name = "ai300-eval-kit"
dependencies = [
    "ai300-schemas",
    "pyyaml>=6.0",
    "httpx>=0.27.0",
    "python-dotenv>=1.0.0",
]

[project.optional-dependencies]
giskard = ["giskard[llm]>=2.0"]
art = ["adversarial-robustness-toolbox>=1.18"]
deepeval = ["deepeval>=1.0"]
all = ["giskard[llm]>=2.0", "adversarial-robustness-toolbox>=1.18", "deepeval>=1.0"]
```

### 测试

- **单元测试**：`tests/unit/adapters/test_giskard_adapter.py`、`tests/unit/strategies/test_eval_strategy_selector.py`
- **集成测试**：`tests/integration/test_art_adapter.py`（mock ART）
- **系统测试**：`tests/system/test_recon_to_eval.py`

## 八、Phase 5：集成与示例

1. **仓库根 `examples/`**：
   - `examples/01_recon_only/`：仅运行 pyrit-web-recon
   - `examples/02_recon_to_attack/`：recon → pyrit-attack-toolkit
   - `examples/03_recon_to_eval/`：recon → ai300-eval-kit
   - `examples/04_full_pipeline/`：recon → attack + eval → unified report

2. **仓库根 `Makefile`**：
   - `make install-all`：安装 schemas + 3 个项目
   - `make test-all`：运行所有项目的测试
   - `make run-recon` / `make run-attack` / `make run-eval`

3. **统一报告脚本**（可选，可放在仓库根 `scripts/`）：
   - 读取 `pyrit-web-recon/results/recon/`、`pyrit-attack-toolkit/results/attacks/`、`ai300-eval-kit/results/eval/` 中的 `UnifiedFinding` JSON。
   - 去重、排序、生成汇总 Markdown/SARIF。

4. **docker-compose.integration.yml**：保持现有 AIG + RedAmon + Redis + MinIO 编排，作为跨项目共享基础设施。

## 九、Phase 6：文档

1. **根 README.md**：monorepo 总览、安装、快速开始、架构图。
2. **pyrit-web-recon/README.md**：侦察专用说明。
3. **pyrit-attack-toolkit/README.md**：攻击工具包说明、PyRIT/Garak 配置。
4. **ai300-eval-kit/README.md**：评估工具包说明、Giskard/ART 配置。
5. **ai300-schemas/README.md**：数据契约说明、JSON Schema。

## 十、实施顺序

1. **Step 1**：创建目录结构，移动当前代码到 `pyrit-web-recon/`。
2. **Step 2**：创建 `ai300-schemas/` 并迁移 `TargetProfile` / `UnifiedFinding`。
3. **Step 3**：改造 `pyrit-web-recon` 使用 schemas 包，验证 recon 流水线仍可运行。
4. **Step 4**：实现 `pyrit-attack-toolkit` 最小可用版本（Garak adapter + strategy selector + report）。
5. **Step 5**：实现 `ai300-eval-kit` 最小可用版本（Giskard adapter + strategy selector + report）。
6. **Step 6**：添加 PyRIT adapter 和 ART adapter（较重，后做）。
7. **Step 7**：添加测试、示例、根 Makefile、统一文档。
8. **Step 8**：端到端系统测试验证。

## 十一、关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| 项目结构 | 单仓库 4 个顶层目录 | 尊重硬约束，同时保持逻辑独立 |
| 共享契约 | 独立 `ai300-schemas` 包 | 代码复用，版本统一，避免复制 |
| PyRIT/Garak/Giskard/ART | 直接使用，不封装框架 | 不重复造轮子 |
| 重依赖 | optional + lazy import | 不污染核心环境，考试场景可裁剪 |
| Garak | subprocess CLI | Garak 本身就是 CLI 工具，子进程最自然 |
| PyRIT | Python 库调用（lazy import） | PyRIT 是库，直接 import 最自然 |
| Giskard/ART | optional Python 库 | 评估场景通常直接 import |
| 报告 | 各项目输出 UnifiedFinding，根脚本可选汇总 | 不内嵌复杂报告逻辑 |

## 十二、风险与缓解

| 风险 | 缓解 |
|------|------|
| 移动当前 pyrit-web-recon 文件破坏已有功能 | 移动后立即运行端到端验证 |
| PyRIT/Garak/Giskard/ART 版本冲突 | optional dependency + 隔离虚拟环境 |
| lazy import 隐藏运行时错误 | 每个 adapter 提供 `is_available()` 和清晰错误信息 |
| 3 个项目测试分散 | 根 Makefile `make test-all` 统一触发 |
| 共享 schemas 包演进导致版本不一致 | schemas 包使用语义版本，3 个项目 pin 兼容版本 |

## 十三、复用现有代码清单

- `pyrit-web-recon/src/recon/target_profile.py:TargetProfile.to_dict()` → `ai300-schemas`
- `pyrit-web-recon/src/recon/target_profile.py:TargetProfile.to_pyrit_target()` → 保留在 `pyrit-web-recon/src/recon/profile_pyrit_adapter.py`
- `pyrit-web-recon/src/integration/schemas/unified_finding.py:UnifiedFinding.to_dict()/from_dict()` → `ai300-schemas`
- `pyrit-web-recon/src/integration/schemas/unified_finding.py:dedup_findings()` → `ai300-schemas`
- `pyrit-web-recon/src/pipeline/stages/export.py:_export_pyrit_target()` → `pyrit-web-recon` 保持不变
- `pyrit-web-recon/src/integration/aig/client.py` 模式 → `pyrit-attack-toolkit/adapters/base.py` 抽象接口设计参考
- `pyrit-web-recon/src/integration/aig/result_normalizer.py` 模式 → `pyrit-attack-toolkit/reporting/unified_converter.py` 和 `ai300-eval-kit/reporting/unified_converter.py`

## 十四、验证计划

1. **安装验证**：
   ```powershell
   pip install -e ./ai300-schemas
   pip install -e ./pyrit-web-recon
   pip install -e "./pyrit-attack-toolkit[garak]"
   pip install -e "./ai300-eval-kit[giskard]"
   ```

2. **单元测试**：
   ```powershell
   pytest ai300-schemas/tests
   pytest pyrit-web-recon/tests
   pytest pyrit-attack-toolkit/tests/unit
   pytest ai300-eval-kit/tests/unit
   ```

3. **集成测试**：
   ```powershell
   pytest pyrit-attack-toolkit/tests/integration
   pytest ai300-eval-kit/tests/integration
   ```

4. **系统测试/端到端**：
   ```powershell
   cd pyrit-web-recon && python main.py https://example.com
   cd ../pyrit-attack-toolkit && python main.py --profile ../pyrit-web-recon/results/recon/pyrit/example_pyrit_target.json --adapter garak --dry-run
   cd ../ai300-eval-kit && python main.py --profile ../pyrit-web-recon/results/recon/profiles/example.json --adapter giskard --dry-run
   ```

5. **回归验证**：确保原有 Mock LLM server 端到端流水线仍可运行。
