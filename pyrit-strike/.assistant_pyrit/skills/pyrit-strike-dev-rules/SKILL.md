---
name: pyrit-strike-dev-rules
description: Enforces 5 mandatory development rules for the pyrit-strike AI red team pipeline project. Use when writing, editing, reviewing, or running code in the pyrit-strike project. These rules are machine-enforced by pipeline_guard.py, pre-commit hooks, and pytest compliance tests — violations are automatically blocked without manual intervention.
---

# PyRIT-Strike Development Rules

> **执行级别: 强制拦截** — 5 条规则由自动化机制强制执行，**无需手工运行 `pipeline_guard.py`**。
> 违规代码无法通过 `pre-commit`、无法通过 `pytest`、无法通过 `ruff`。

## 规则执行机制

所有规则由以下自动化机制强制执行，**AI 代理无需手工运行任何检查命令**：

1. **`pipeline_guard.py`** — 由 `pre-commit` hook 在 commit 前自动调用，检测代码量/目录/PyRIT原生/参数基线
2. **`pre-commit` hook** — commit 前自动运行 ruff + pytest + pipeline_guard（已配置 `.pre-commit-config.yaml`）
3. **`pyproject.toml` [tool.ruff]** — ruff 代码风格自动检查（由 pre-commit 调用）
4. **`tests/pipeline/test_guard_compliance.py`** — 规则合规测试（pytest 自动执行，违规即 fail）

> **重要**: AI 代理在编码时只需**遵守下方规则**，不需要在每次变更后手工运行 `pipeline_guard.py` 或 `pytest`。
> pre-commit hook 和 pytest 会在 commit / CI 阶段自动捕获违规。
> 如果 agent 想主动验证，可以运行，但这不是必须的流程。

---

## Rule 1: PyRIT 原生优先，禁止造轮子

**一句话**: PyRIT 1.0.1 提供的组件必须用原生的，自建代码仅限胶水/增强/输出层。

### 允许的自建类别（仅这3类）

| 类别 | 定义 | 示例 |
|------|------|------|
| 胶水层 | 连接原生组件，不替代任何原生组件 | `target_router.py` 连接 Burp→HTTPTarget |
| 增强层 | 包装原生组件，原生组件仍为主引擎 | `rate_limited.py` 包装 PromptTarget |
| 输出层 | 从原生结果读取数据，格式化输出 | `evidence.py`、`generator.py` |

### 禁止自建的组件

| 层 | 必须用 PyRIT 原生 | 禁止自建 |
|----|-------------------|----------|
| Target | `OpenAIChatTarget`, `HTTPTarget`, `PlaywrightTarget` | 自定义 Target 类 |
| Executor | `PromptSendingAttack`, `CrescendoAttack`, `TAPAttack`, `PAIRAttack` | 自定义 Executor |
| Scorer | `SelfAskTrueFalseScorer`, `SubStringScorer`, `TrueFalseInverterScorer` | 自定义 Scorer 级联 |
| Memory | `CentralMemory`, `DuckDBMemory` | 自定义 Memory |
| Converter | `pyrit.converter.*` | 自定义 Converter |
| Dataset | `SeedPrompt` YAML | 自定义种子格式 |

### PyRIT 设计域边界

PyRIT 的设计域是**"通过 prompt 文本与 LLM 交互并评估响应"**。
不属于此域的攻击**不得**强行用 PyRIT 实现：

| 域外攻击 | 正确框架 |
|----------|----------|
| ML 模型推理（嵌入反演） | `sentence-transformers` + `torch` |
| HTTP 协议级操作（A2A CRUD） | `httpx` 直接 HTTP 客户端 |
| 供应链攻击 | `pickletools` / `pip` / `git` |
| AI 基础设施攻击 | `boto3` / `kubernetes` 客户端 |

**例外**: MCP JSON-RPC 枚举可通过 `HTTPTarget` 发送 HTTP POST，因为 MCP 基于 HTTP。

### 自动执行

`pipeline_guard.py` + `test_guard_compliance.py` 通过 AST 分析检测：
- 类名匹配 `Custom*Target` / `Custom*Executor` / `Custom*Scorer` / `Custom*Memory` / `Custom*Converter` → **BLOCK**

---

## Rule 2: 代码量上限 + 目录结构强制

**一句话**: pipeline/ 总量 ≤21,000 行，单文件 ≤1,000 行，根目录只允许 5 个入口脚本。

### 代码量阈值（与 `pipeline_guard.py` / `test_guard_compliance.py` 完全一致）

| 维度 | 上限 | 当前 | 状态 |
|------|------|------|------|
| pipeline/ 总行数 | 21,000 | ~20,495 | ✅ |
| 单文件行数 | 1,000 | — | ✅ |
| pipeline/ 文件数 | 61 | 61 | ✅ |
| strike/ 文件数 | 15 | 15 | ✅ |
| defaults.yaml 行数 | 80 | 77 | ✅ |
| 入口脚本单文件 | 600 | 577 (main.py) | ✅ |

### 根目录允许的 .py 文件（仅这些）

| 文件 | 用途 |
|------|------|
| `main.py` | 核心流水线入口 |
| `run_strike.py` | 策略化攻击编排 |
| `run_batch.py` | 批量攻击 |
| `run_web_vuln.py` | Web 漏洞攻击 |
| `pipeline_guard.py` | 规则守卫（由 pre-commit 自动调用） |

**禁止在根目录**: `mini_strike.py`、`_verify_pipeline.py`、`regen_report.py`、测试文件、调试脚本、日志文件、`.txt` 文件。

### 目录结构（强制）

```
pyrit-strike/
├── main.py                     # 入口（允许）
├── run_strike.py               # 入口（允许）
├── run_batch.py                # 入口（允许）
├── run_web_vuln.py             # 入口（允许）
├── pipeline_guard.py           # 守卫（允许）
├── pyproject.toml              # 配置（允许）
├── .pre-commit-config.yaml     # pre-commit 配置（允许）
├── config/                     # 配置文件
│   ├── defaults.yaml           # SSOT
│   ├── target_profiles.yaml
│   └── asr_priors.yaml
├── data/                       # 静态数据
│   ├── burp/
│   ├── scorers/
│   └── seeds/
├── docs/                       # 文档
├── pipeline/                   # 源码
│   ├── config.py
│   ├── context.py
│   ├── arm/                    # 武器化
│   ├── assess/                 # 评分
│   ├── recon/                  # 侦察
│   ├── report/                 # 报告
│   ├── strategy/               # 策略
│   ├── strike/                 # 攻击执行
│   ├── targets/                # Target 适配
│   └── utils/                  # 工具
├── tests/                      # 测试
│   └── pipeline/
└── outputs/                    # 输出（gitignored）
```

### 自动执行

`pipeline_guard.py` + `test_guard_compliance.py` 检测：
- pipeline/ 总行数 > 21,000 → **BLOCK**
- 任一 .py 文件 > 1,000 行 → **BLOCK**
- pipeline/ 文件数 > 61 → **BLOCK**
- strike/ 文件数 > 15 → **BLOCK**
- 根目录出现非允许入口的 .py 文件 → **BLOCK**
- 根目录出现 `.log` / `_log.txt` / `.txt` 文件 → **BLOCK**
- 入口脚本 > 600 行 → **BLOCK**

---

## Rule 3: L5 参数基线 + SSOT 强制

**一句话**: 所有攻击参数从 `config/defaults.yaml` 读取，不得低于 L5 基线，不得在代码中硬编码。

### L5 参数基线（SSOT: `config/defaults.yaml`）

```yaml
# 执行控制
max_concurrency: 3
max_attempts: 3              # ≥3
max_seeds: 25               # ≥25
scenario_timeout: 1200
api_timeout: 120

# 升级
escalation_asr_threshold: 90  # <90% 触发升级
post_l1_exit_threshold: 70     # L1后 ≥70% 跳过 L2-L4
post_l2_exit_threshold: 80     # L2后 ≥80% 跳过 L3-L4
max_escalation_targets: 10

# 多轮
crescendo_max_turns: 10       # ≥10
tap_tree_width: 4              # ≥4
tap_tree_depth: 4             # ≥4
pair_tree_depth: 7

# Best-of-N
best_of_n_retries: 5          # ≥5

# 评分
dual_judge_enabled: true
dual_judge_high_confidence_threshold: 0.85
wilson_confidence_level: 0.95

# Converter
l5_optimal_paths: 7           # ≥7

# 种子扩充
auto_seed_expansion_factor: 3
```

### 禁止硬编码

```python
# 错误 — 硬编码
expansion_factor = 3
max_attempts = 3

# 正确 — 从 SSOT 读取
expansion_factor = getattr(args, "auto_seed_expansion_factor", 3)
max_attempts = _get_config_int(ctx, "max_attempts", 3)
```

### 自动执行

`pipeline_guard.py` + `test_guard_compliance.py` 检测：
- `defaults.yaml` 中关键参数低于 L5 基线 → **BLOCK**
- `defaults.yaml` 缺少 L5 参数 → **BLOCK**
- `defaults.yaml` 行数 > 80 → **BLOCK**

---

## Rule 4: ruff + pytest + 清理（硬门禁）

**一句话**: 每次代码变更后必须通过 ruff + pytest + 临时文件清理，不通过不得标记完成。

### 自动执行流程

以下检查由 `pre-commit` hook（`.pre-commit-config.yaml`）在 commit 前自动执行：

1. **ruff check** — 代码风格 + import 排序（`--fix` 自动修复）
2. **pytest** — 全量测试套件（`tests/` 目录）
3. **pipeline_guard.py** — R1+R2+R3+R5 规则守卫
4. **root-clean** — 根目录干净检查

> AI 代理**无需手工运行**上述命令。pre-commit 会在 `git commit` 时自动执行。
> 如果 pre-commit 失败，agent 应根据错误信息修复代码后重新 commit。

### 代码风格

- Python 3.13+，PEP 695 类型参数语法
- 全类型注解
- keyword-only 参数（`*` 分隔）
- async 函数 `_async` 后缀
- UTF-8 编码（Windows GBK 兼容）
- ruff 配置: `pyproject.toml [tool.ruff]`，line-length=120

### 测试要求

- 每个模块对应 `tests/pipeline/test_<module>.py`
- E2E 覆盖：Burp 解析 → 目标构建 → 种子加载 → 攻击执行 → 评分 → 报告
- 测试不得使用真实 API 调用
- 禁止 `pytest.skip` / `xfail` / `try-except pass` 绕过失败

### 临时文件清理

| 目标 | 时机 |
|------|------|
| `__pycache__/` | pytest 后 / pipeline 运行后 |
| `.pytest_cache/` | pytest 后 |
| `.ruff_cache/` | ruff 后 |
| `*.egg-info/` | 安装后 |

`main.py` 通过 `atexit.register(cleanup_temp_files)` 自动执行。

---

## Rule 5: 学术引用 + 证据标准

**一句话**: 每个攻击技术必须有 arXiv 引用，每个漏洞证据必须包含完整字段。

### arXiv 引用要求

代码中引入新技术时，**必须**在定义处添加 arXiv 注释：

```python
# arXiv:2402.12109 — Russinovich et al., "Crescendo"
crescendo_max_turns = 10
```

`config/defaults.yaml` 中的参数**必须**有学术注释：

```yaml
crescendo_max_turns: 10  # arXiv:2402.12109 — §4.3: max_turns=10 ASR=82%
```

### 核心引用表

| 技术 | arXiv ID | 用途 |
|------|----------|------|
| PyRIT | 2407.01232 | 框架基础 |
| Crescendo | 2402.12109 | 多轮渐进升级 |
| TAP | 2312.02191 | 树搜索攻击 |
| PAIR | 2310.08419 | 迭代越狱 |
| Many-Shot | 2402.05124 | 上下文学习越狱 |
| Encoding Bypass | 2307.15043 | 编码绕过 |
| Persuasion | 2402.19181 | 说服转换器 |
| GCG | 2307.08673 | 对抗后缀 |
| AutoDAN | 2310.04451 | 自动越狱生成 |
| Dual Judge | 2308.07920 | 双 Judge 交叉验证 |
| Parallel Escalation | 2406.12609 | 并行升级+中间退出 |
| Skeleton Key | 2406.18112 | 前缀注入 |
| CoT Hijack | 2307.10292 | 思维链攻击 |
| SmoothLLM | 2310.03816 | 防御+绕过 |
| UCB1 | cs/0207052 | 探索-利用平衡 |
| LLM-as-Judge | 2306.05685 | LLM 评分 |

### 证据记录必填字段

每个 `VulnerabilityEvidence` 必须包含：

| 字段 | 用途 |
|------|------|
| `jailbreak_prompt` | 攻击载荷 |
| `harmful_output` | 目标响应 |
| `conversation_history` | 多轮对话记录 |
| `score_details` | 评分器详情 |
| `converter_log` | Converter 变换记录 |
| `arxiv_reference` | 学术引用 |
| `confidence` | 置信度 |
| `owasp_id` | OWASP 映射 |

### 自动执行

`pipeline_guard.py` 检测（WARNING 级，不阻断 commit）：
- `defaults.yaml` 参数无 arXiv 注释 → **WARNING**
- 新增技术文件无 arXiv 注释 → **WARNING**

---

## 规则冲突解决（唯一优先级链）

当规则冲突时，按此固定优先级链解决，**无需 AI 判断**：

```
R4 (ruff+pytest 硬门禁) > R2 (代码量+目录) > R3 (L5参数+SSOT) > R1 (PyRIT原生) > R5 (学术引用)
```

- R4 是最高优先级：测试不过，一切免谈
- R2 其次：代码膨胀是项目覆灭的主因，严格控制在阈值内
- R3 确保参数不退化
- R1 确保不造轮子
- R5 是软约束（WARNING 不 BLOCK）

---

## AI 代理行为准则

> **核心原则**: 遵守规则，编码即可。自动化机制会保障合规。

### 编码时

1. **遵守 R1**: 不创建 `Custom*Target` / `Custom*Executor` 等类，使用 PyRIT 原生组件
2. **遵守 R2**: 新文件放对目录，单文件不超 1,000 行，根目录不乱放 .py 文件
3. **遵守 R3**: 参数从 `config/defaults.yaml` 读取，不硬编码
4. **遵守 R5**: 新增攻击技术添加 arXiv 注释

### 编码后

- **不需要手工运行 `pipeline_guard.py`** — pre-commit hook 会自动执行
- **不需要手工运行 `pytest`** — pre-commit hook 会自动执行
- **不需要手工运行 `ruff`** — pre-commit hook 会自动执行
- 如果 pre-commit 未安装，运行一次 `pre-commit install` 即可（一次性）
- 如果想主动验证（可选），可运行：`python pipeline_guard.py`

### 优化迭代循环（简化版）

优化类任务（修改攻击代码/参数/技术以提升 ASR）需遵循：

1. **检查清单** — 列出将修改的文件和步骤
2. **实现** — 编码
3. **验证** — `git commit` 触发 pre-commit 自动验证（或主动运行 `pipeline_guard.py`）
4. **差距分析** — 对比 L5 基线，识别差距
5. **下一步** — 提出 1-3 个最高 ASR 影响的优化

**非优化类任务**（typo/注释/重构）只需遵守规则编码，pre-commit 自动保障 R4。
