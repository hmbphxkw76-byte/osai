# 40 — 安全与质量层：红线护栏（Guardrails）

> **文档层级**：L4 / 五层规约金字塔第五层
> **效力**：红线 = 绝对禁止，视同宪法级（裁决序见 00-CONSTITUTION 第二章）。质量门禁 = 完成任务的必要不充分条件。
> **执行机制**：三层防线（静态 guard / 运行时 dry-run / git 钩子），继承 SKILL.md D2 条款并收编。
> **版本**：v3.0（2026-09-09 REV-17：修复 spec-code drift — R-L1/R-L7 真正实现，check_no_defense_in_attack_dirs + check_top_level_structure）

---

## 第一章：红线清单（绝对禁止）

### 1A. 机器可查红线（guard 自动拦截，BLOCKING）

| # | 红线 | guard 检查器 |
|---|------|-------------|
| R-L1 | 攻击端（strike/arm/recon/attack_*）出现安全护栏/内容过滤逻辑 | `check_no_defense_in_attack_dirs()` **[v2.9 已实现]** |
| R-L2 | 自定义 Executor/Target/Scorer 基类替代 PyRIT 原生 | `check_forbidden_custom_classes()` |
| R-L3 | `ConverterConfiguration` 串联堆叠（>1 converter） | `check_serial_stacking()` |
| R-L4 | defaults.yaml 参数低于 L5 基线（max_attempts≥3、escalation_asr_threshold≥90 等） | `check_l5_params()` |
| R-L5 | 升级链缺失 L1/L2 中间退出检查点 | `check_intermediate_exit()` |
| R-L6 | 报告生成未调用 pyrit.output 原生模块 | `check_pyrit_native_output()` |
| R-L7 | 根目录出现未授权顶层目录/文件 | `check_top_level_structure()` **[v2.9 已实现]** |
| R-L8 | `--dry-run` 参数或实现缺失 | `check_dry_run_available()` |

### 1A-DATA. 数据流完整性红线（v1.4 新增）

> 完整规约见 [10-ARCHITECTURE.md 第四章](../specs/10-ARCHITECTURE.md)（原 45-DATA-FLOW-INTEGRITY.md 已合并）

| # | 红线 | guard 检查器 | 级别 |
|---|------|-------------|------|
| R-DATA-1 | ARM→Strike→Assess 数据流完整性（快照验证 29 项测试） | `check_data_flow_integrity()` | INFO/WARNING |

**R-DATA-1 判定**:
- ✅ PASS: 29/29 数据流测试通过 → INFO (不阻断)
- ❌ FAIL: 任何字段契约违规或传递断点 → WARNING (提示修复)
- 🔴 BLOCKING: 严重数据断点 → 阻断 commit (通过 pre-push 全量验证)

### 1B-DATA. ASR 中心数据流完整性红线（v2.0 新增）

| # | 红线 | guard 检查器 | 级别 |
|---|------|-------------|------|
| R-DATA-2 | PipelineContext 字段必须直接服务于 ASR（禁止操作资源句柄混入） | `check_ctx_asr_centered()` | WARNING |
| R-DATA-3 | 取证数据字段必须存在且可被验证器提取 | `check_forensic_fields_exist()` | INFO |

**R-DATA-2 判定**:
- ✅ PASS: ctx 中无 `_playwright_*`, `_browser*`, `_whitebox_confirmed` 等非 ASR 字段
- ❌ FAIL: 发现非 ASR 字段混入 → WARNING (提示移除)

**R-DATA-3 判定**:
- ✅ PASS: `successful_evidence_log`/`refusal_classification_log`/`guardrail_triggers`/`timing_metadata` 字段存在
- ℹ️ INFO: 字段存在但为空列表（首次运行无数据，正常）

### 1C-DOC. 代码-文档同步护栏（v2.7 新增）

> **适用范围**：所有代码变更（尤其是新增/修改 CLI 参数、攻击模块、流水线集成时）。
> **目的**：确保代码变更后，相关规约文档同步更新，防止"代码先进、文档滞后"的漂移。

| # | 红线 | guard 检查器 | 级别 |
|---|------|-------------|------|
| R-DOC-1 | CLI 参数变更必须同步更新 `docs/guides/red-team-dev-guide.md` 附录 D CLI 参数参考 | `check_cli_params_documented()` | WARNING |
| R-DOC-2 | 新增攻击模块必须同步更新 `docs/specs/55-ATTACK-GAP-CLOSURE.md` 对应缺口章节 | `check_attack_gap_documented()` | WARNING |
| R-DOC-3 | 新增需求/红线必须同步更新 `docs/specs/20-REQUIREMENTS.md` 和 `docs/specs/40-GUARDRAILS.md` | `check_requirements_guardrails_synced()` | WARNING |
| R-DOC-4 | 文档版本号变更必须同步更新 `docs/specs/README.md` 金字塔版本索引 | `check_readme_version_synced()` | INFO |
| R-DOC-5 | **新增/修改 CLI 参数必须在交付验收时显示完整命令行用法**，包括：参数组合示例、与其他模块联合使用示例、完整参数列表 | `check_cli_usage_shown_in_delivery()` | WARNING |

**R-DOC-1 判定**:
- ✅ PASS: `core/config.py` 中新增的 `--xxx` 参数在 `docs/guides/red-team-dev-guide.md` 附录 D 中有对应条目
- ❌ FAIL: 发现 CLI 参数未文档化 → WARNING (提示补充文档)

**R-DOC-2 判定**:
- ✅ PASS: `strike/` 下新增攻击模块在 `55-ATTACK-GAP-CLOSURE.md` 中有对应缺口章节
- ❌ FAIL: 发现攻击模块未登记缺口 → WARNING (提示补充缺口分析)

**R-DOC-3 判定**:
- ✅ PASS: `20-REQUIREMENTS.md` 中新增 REQ-xxx 在 `40-GUARDRAILS.md` 1F 登记簿中有对应检查器（如适用）
- ❌ FAIL: 发现需求/红线未同步 → WARNING (提示补充)

**R-DOC-4 判定**:
- ✅ PASS: `README.md` 金字塔版本索引与各文档版本号一致
- ℹ️ INFO: 版本号不一致 → 提示同步

**R-DOC-5 判定**:
- ✅ PASS: 交付验收清单中包含"CLI 文档"章节，显示：完整参数列表、基础用法示例、组合攻击示例
- ❌ FAIL: 新增 CLI 参数但交付验收未显示命令行用法 → WARNING (提示补充)

**文档同步清单**（代码变更时必须检查）：

| 变更类型 | 必须同步的文档 |
|----------|---------------|
| 新增 CLI 参数 | `docs/guides/red-team-dev-guide.md` 附录 D |
| 新增攻击模块 | `docs/specs/55-ATTACK-GAP-CLOSURE.md` |
| 新增需求 | `docs/specs/20-REQUIREMENTS.md` |
| 新增红线/护栏 | `docs/specs/40-GUARDRAILS.md` |
| 版本号变更 | `docs/specs/README.md` 金字塔索引 |
| 新增测试 | `tests/test_*.py` + 文档测试覆盖章节 |
| 交付验收 | 必须显示完整命令行用法（参数列表+示例） |

### 1A-TOOLS. 目录职责红线（v1.3 新增）

| # | 红线 | guard 检查器 |
|---|------|-------------|
| R-TOOLS-1 | `core/` 或 `utils/` 下文件带 `if __name__ == "__main__"` 块（CLI 工具必须放在 `tools/`） | `check_cli_location()` |
| R-TOOLS-2 | 单模块行数上限 850 行（原 R-SIZE 编号归位；原 60-REDTEAM 文档遗留编号 R-DELIVERY-3 一并作废，跨层导入判定改引蓝图 2.2 依赖矩阵） | `check_delivery_module_size()` |

判定标准：
- ✅ 允许：`main.py`（根目录）、`tools/*.py` 带 `__main__`
- ❌ 禁止：`core/*.py`、`utils/*.py`、`recon/*.py`、`arm/*.py`、`strike/*.py`、`assess/*.py`、`report/*.py` 带 `__main__`

修复：
1. 将 CLI 入口文件迁移到 `tools/` 目录
2. 将 `__main__` 块提取到 `tools/` 下的独立文件
3. 更新导入路径（`from core.xxx` → `from tools.xxx`）

### 1B. 人工评审红线（diff 评审必查）

| # | 红线 | 判定特征 |
|---|------|---------|
| R-H1 | 静默降级：stub/空实现/fallback 进入编排链路而未在任何文档登记 | 函数体 `return {}` / `return None` 被真实调用方消费（REV-02 审计实证：cair.py / encoded_injection.py / multi_turn_attacks.py 注释自认"调用方 try/except 优雅降级"） |
| R-H2 | 静默吞错：`except Exception: pass` 或日志级别掩盖故障 | try 块体量远大于 except 处理 |
| R-H3 | 双轨新增：新文件与既有文件职责重叠 | 新模块名与既有模块名词近义（manager/pipeline/handler 变体） |
| R-H4 | 配置断点：效率参数字面量、无 ctx 的配置函数、硬编码日志数字 | 三类根因 A/B/C（R9） |
| R-H5 | 数据旁路：绕过 target_fingerprint / PipelineContext 新开数据通道 | 阶段层直接 import 对方内部函数 |
| R-H6 | 规格蒸发：diff 无法关联 REQ/DEBT/bug 现象 | commit 无任务 ID 或任务规格缺失验收标准 |
| R-H7 | 证据注水：报告/汇报宣称未实际执行的验证 | 无 dry-run/pytest 输出佐证的"通过" |

### 1C. 安全与合规红线（项目特有）

| # | 红线 |
|---|------|
| R-S1 | **仅攻击授权目标**：`data/burp/` 中的目标与 `.env` 配置的端点即攻击边界；禁止将攻击流量导向边界外的任何主机（含"顺手探测"第三方服务）。**考试场景**：OffSec 考试环境下发的目标集即授权边界，同样适用 |
| R-S2 | **密钥纪律**：任何文件（代码/文档/测试/示例/PoC）不得出现真实 API key；PoC 端点一律 `os.environ.get()` 参数化；`.env` 永不入库 |
| R-S3 | **报告不脱敏攻击载荷**：证据链必须保留完整 payload（R1）；但目标 Cookie/Token 等凭证在报告示例中须用占位符 |
| R-S4 | **测试隔离**：tests/ 全部 mock API 调用；禁止测试触发对真实目标的攻击流量 |
| R-S5 | **不当武器化输出**：生成的 PoC/报告默认面向授权红队评估交付；不附加"无授权也可用"的引导性内容 |

### 1D. Web攻击专项护栏（v2.5 更新）

> **适用范围**：strike/ 目录下所有Web攻击模块（auth_attacks.py、web_attacks.py、audit_evasion.py、web_orchestrator.py、file_upload_executor.py）。这些模块作为 PyRIT 原生框架与Web安全攻击之间的桥梁，必须遵守本节专项护栏。

> **v1.6 变更**：从 glue/ 目录迁移到 strike/ 目录，模块扁平化重组。
> **v2.5 变更**：新增文件上传攻击执行器（file_upload_executor.py），扩展适用范围。

| # | 红线 | 级别 | 判定特征 |
|---|------|------|----------|
| R-WEB-1 | **插件化隔离**：Web攻击模块必须通过 try/except ImportError 实现可选依赖安装，不得将企业 SDK（PyJWT等）声明为硬依赖 | BLOCKING | 缺失 try/except 包裹的企业 SDK import |
| R-WEB-2 | **PyRIT 原生委托**：Web攻击模块不得重写攻击执行逻辑（PromptSendingAttack / SkeletonKeyAttack / CrescendoAttack 等），仅允许构造 PyRIT 原生组件可消费的 payload/target/scorer 配置 | WARNING | Web攻击模块内出现 attack.execute() / attack._execute() 等攻击执行逻辑 |
| R-WEB-3 | **配置数据流**：Web攻击参数（JWT 算法类型、Gateway类型、审计日志格式、文件上传目标URL等）必须走 `config/defaults.yaml → ctx.args` 链路，禁止硬编码 | WARNING | Web攻击模块内出现攻击参数字面量（非从 ctx 读取） |
| R-WEB-4 | **静默降级禁止**：Web攻击模块的降级路径（企业 SDK 不可用时的降级策略）必须在 orchestration_log 中显式记录，禁止静默 skip | WARNING | Web攻击模块内 except 块仅含 `pass` / `return None` 而无日志记录 |
| R-WEB-5 | **学术留痕**：每个Web攻击向量（JWT alg=none、HTTP 走私、文件上传间接Prompt注入等）必须有 arXiv 引用或 CVE 编号注释 | INFO | Web攻击函数无 arXiv/CVE 注释 |
| R-WEB-6 | **任意端口支持**：文件上传攻击模块必须支持任意端口 (0-65535)，禁止硬编码端口限制或端口范围校验 | BLOCKING | 文件上传模块中出现端口号硬编码或端口范围校验逻辑 |

**Web攻击向量白名单**（已认可的Web攻击场景）：

| 攻击向量 | 对应模块 | 关键技术 | 引用要求 |
|---------|---------|---------|----------|
| JWT 算法混淆 | `strike/auth_attacks.py` | alg=none、RS256→HS256 降级、kid注入 | CVE-2015-9235（RS256→HS256 混淆）或 CVE-2018-0114（jwk header 注入） |
| HTTP 请求走私 | `strike/web_attacks.py` | CL.TE/TE.CL 走私、路径参数覆盖 | PortSwigger HTTP Desync（Kettle, 2019） |
| 审计日志注入 | `strike/audit_evasion.py` | CRLF 注入、ANSI 注入、时间戳伪造 | CWE-117 / CWE-93（OWASP Log Injection） |
| 文件上传间接Prompt注入 | `strike/file_upload_executor.py` | multipart/form-data 上传、分文档注入 | arXiv:2302.12173（Greshake et al.） |
| RAG知识库投毒 | `strike/file_upload_executor.py` | PoisonedRAG、chunk边界利用 | arXiv:2406.04245（Zou et al.） |

> **v2.5 引用修正**：新增文件上传攻击白名单条目（R-WEB-6 护栏 + 2个攻击向量）。

### 1E-DRIFT. 规范漂移检测护栏（v1.6 新增）

> 完整规约见本章 1E-DRIFT（原 60-REDTEAM-DELIVERY-FRAMEWORK.md §11 已合并入本文件）
> 检测引擎：`tools/drift_detector.py`（独立于 `tools/guard.py`，专责「规范-代码」双向漂移）

| # | 红线 | 级别 | 检查内容 | 检查器 |
|---|------|------|----------|--------|
| R-DRIFT-1 | PyRIT API 解析验证 | BLOCKING | 宪法/规约引用的原生类是否能 `import` 解析（防止 PyRIT 版本升级导致 API 失效） | `check_pyrit_api_resolution()` |
| R-DRIFT-2 | 规范表格-代码同步 | WARNING | 规约文档引用的文件路径是否存在（防止文档引用已删除/重命名的模块） | `check_spec_code_sync()` |
| R-DRIFT-3 | 版本变更锁定 | BLOCKING | 安装版本是否匹配 `pyproject.toml` 锁定（防止依赖更新引入未适配的 API 变更） | `check_version_lock()` |
| R-DRIFT-4 | 契约消费验证 | INFO | `PipelineContext` 字段是否在各阶段被实际消费（防止字段僵尸/未使用） | `check_context_contract_usage()` |
| R-DRIFT-5 | 原生模式违规 | WARNING | 检测自研 `base64_encode`/`check_refusal`/`regex_match` 等替代原生组件的函数 | `check_native_patterns()` |

**R-DRIFT-* 判定逻辑**：
- ✅ PASS: 全部检测通过 → INFO (不阻断)
- ⚠️ WARNING: R-DRIFT-2 文件失同步 / R-DRIFT-5 自研替代 → 提示修复，**不阻断 push**
- [BLOCKING]: R-DRIFT-1 PyRIT API 无法解析 / R-DRIFT-3 版本锁定失效 → **阻断 push**

**调用方式**：
```bash
# 快速检测 (不含版本锁定，开发期高频)
py -m tools.drift_detector
pyrit-drift

# 全量检测 (含版本锁定，pre-push 和 CI 使用)
py -m tools.drift_detector --full
pyrit-drift --full

# JSON 报告输出 (CI 集成)
py -m tools.drift_detector --full --report
pyrit-drift --full --report
```

**自动化集成位置**：
| Hook/阶段 | 命令 | 触发时机 |
|-----------|------|----------|
| `pre-push` | `py -m tools.drift_detector --full` | 每次 push |
| 手动开发 | `pyrit-drift` | 开发时实时检测 |
| CI/CD | `pyrit-drift --full --report` | 定期审计/PR 检查 |

### 1F. Guard 检查器登记簿（v3.1 新增 1 项，总计 47 项）

规约各处引用的检查器汇总（**权威清单以 `tools/guard.py` + `tools/drift_detector.py` 实际实现为准**）：

| 检查器 | 条款/红线 | 级别 | 分类 |
|--------|----------|------|------|
| check_no_defense_in_attack_dirs | C2 / R-L1 | BLOCKING | 核心安全 |
| check_forbidden_custom_classes | C1 / R-L2 | BLOCKING | 核心安全 |
| check_serial_stacking | C2 / R-L3 | BLOCKING | 核心安全 |
| check_l5_params | C2·C7 / R-L4 | BLOCKING | 核心安全 |
| check_intermediate_exit | I4 / R-L5 | BLOCKING | 核心安全 |
| check_pyrit_native_output | I9·C1 / R-L6 | BLOCKING | 核心安全 |
| check_top_level_structure | R-L7 | BLOCKING | 核心安全 |
| check_no_hardcoded_component_names | ADR-007 / R-EVENT-1 | WARNING（W4 起 BLOCKING） | 目标架构 v4.0 |
| check_test_coverage | R-L7 | BLOCKING | 核心安全 |
| check_dry_run_available | C10 / R-L8 | BLOCKING | 核心安全 |
| check_native_attack_usage | C1 | WARNING | PyRIT 原生 |
| check_native_attack_instantiation | C1 | WARNING | PyRIT 原生 |
| check_llm_scorer_in_attack | C2·I2 | WARNING | PyRIT 原生 |
| check_hardcoded_params | C7 | WARNING | 配置纪律 |
| check_config_data_flow | C7 | WARNING | 配置纪律 |
| check_native_params_from_config | C7 | WARNING | 配置纪律 |
| check_arxiv_citations | C8 | INFO | 学术留痕 |
| check_silent_degradation | C9 | WARNING | 静默降级 |
| check_silent_swallowing | C9 | WARNING | 静默吞错 |
| check_dual_track | D-11 / C7 | INFO | 双轨检测 |
| check_glue_pluginisolation | R-WEB-1 | BLOCKING | Web 攻击 |
| check_glue_pyrit_delegation | R-WEB-2 | WARNING | Web 攻击 |
| check_glue_config_flow | R-WEB-3 | WARNING | Web 攻击 |
| check_glue_silent_degradation | R-WEB-4 | WARNING | Web 攻击 |
| check_glue_academic_citation | R-WEB-5 | INFO | Web 攻击 |
| check_pyrit_api_resolution | R-DRIFT-1 | BLOCKING | 漂移检测 |
| check_spec_code_sync | R-DRIFT-2 | WARNING | 漂移检测 |
| check_version_lock | R-DRIFT-3 | BLOCKING | 漂移检测 |
| check_context_contract_usage | R-DRIFT-4 | INFO | 漂移检测 |
| check_native_patterns | R-DRIFT-5 | WARNING | 漂移检测 |
| check_cli_params_documented | R-DOC-1 | WARNING | 文档同步 |
| check_attack_gap_documented | R-DOC-2 | WARNING | 文档同步 |
| check_requirements_guardrails_synced | R-DOC-3 | WARNING | 文档同步 |
| check_readme_version_synced | R-DOC-4 | INFO | 文档同步 |
| check_decision_safety_boundary | R-DECIDE-1 | BLOCKING | 自主决策 |
| check_decision_audit_trail | R-DECIDE-2 | WARNING | 自主决策 |
| check_decision_stability | R-DECIDE-3 | WARNING | 自主决策 |
| check_human_override | R-DECIDE-4 | INFO | 自主决策 |
| check_decision_data_source | R-DECIDE-5 | WARNING | 自主决策 |

**保留注记**：
- **specs-guard 联动**: guard 启动时读取 `00-CONSTITUTION.md` 版本号并输出至报告脚注（裁决序基准）；版本不匹配时以 guard 实现为准、规约文档视为待同步。
- **R9 误报白名单**: `display.py`、`display_stages.py` 中通过 `_resolve('param', default)` 包裹的动态配置读取，视为已修复配置数据流断点（不报 R9）。

### 1G-DECIDE. 自主决策系统护栏（v2.2 新增）

> **适用范围**：全链路自主决策引擎（`determine_*_strategy` 系列函数、`DecisionEngine` 类、反馈闭环机制）。
> **架构依据**：`10-ARCHITECTURE.md` 第十一章 + `55-ATTACK-GAP-CLOSURE.md` 第九章。

| # | 红线 | 级别 | 判定特征 | 检查器 |
|---|------|------|----------|--------|
| R-DECIDE-1 | **安全边界保护**：决策系统不得绕过人工确认的关键安全边界（R-S1 授权目标集） | BLOCKING | 决策引擎输出攻击目标不在授权列表中 | `check_decision_safety_boundary()` |
| R-DECIDE-2 | **决策审计追踪**：所有自主决策必须记录到 `ctx.decision_log` | WARNING | 决策函数执行后 `ctx.decision_log` 无新增条目 | `check_decision_audit_trail()` |
| R-DECIDE-3 | **决策稳定性**：自动策略切换需基于 ≥3 次连续失败或 ASR 显著下降（<50% 预期） | WARNING | 单次失败即触发策略切换 | `check_decision_stability()` |
| R-DECIDE-4 | **人类控制权**：CLI 参数优先级高于自主决策输出 | INFO | CLI 参数被决策引擎覆盖 | `check_human_override()` |
| R-DECIDE-5 | **决策数据完整性**：决策依赖数据必须来自 PipelineContext，禁止旁路数据通道 | WARNING | 决策函数读取非 ctx 数据源 | `check_decision_data_source()` |
| R-DECIDE-6 | **策略先验优先**：决策引擎应优先选择已有高 ASR 证据（asr_history 命中 / priors 校准条目）的策略 | INFO | 选择了无证据策略且未记录理由 | —（人工评审；候选检查器 `check_decision_asr_preference` 待 REQ-141） |

**R-DECIDE-* 判定逻辑**：
- ✅ PASS: 全部检测通过 → INFO (不阻断)
- ⚠️ WARNING: R-DECIDE-2/3/5 违规 → 提示修复，**不阻断 push**
- 🔴 BLOCKING: R-DECIDE-1 安全边界违规 → **阻断 push**

**R-DECIDE-3 适用范围**：仅约束"策略切换"类决策；I4 动态升级阈值（完成度/预算感知）属**参数化触发**，不适用本条（裁定见蓝图 6.1 一致性裁定）。

**决策护栏与既有护栏的关系**：
| 决策护栏 | 关联既有护栏 | 关系 |
|----------|-------------|------|
| R-DECIDE-1 | R-S1 (授权边界) | 强化：决策系统同样受 R-S1 约束 |
| R-DECIDE-2 | R-H6 (规格蒸发) | 互补：决策日志 = 自动化系统的规格追踪 |
| R-DECIDE-3 | R-H1 (静默降级) | 互补：防止决策抖动导致等效静默降级 |
| R-DECIDE-4 | NEG-6 (L5 基线) | 兼容：CLI 参数 = 人工决策的最高优先级 |

**红线冲突裁决**：R-S*（安全合规）> R-L*（机器红线）> R-H*（人工红线）。安全红线与 ASR 冲突时（例如"过滤掉这个目标会更安全"），安全红线赢——但正确答案几乎总是 STOP-REPORT 让人裁决。

### 1I-CROSS. 跨模型规约审查护栏（v2.7 新增）

> **适用范围**：所有规约文档（L0-L4：CONSTITUTION/ARCHITECTURE/REQUIREMENTS/GUARDRAILS/ROADMAP）的变更审查流程。
> **架构依据**：`10-ARCHITECTURE.md` 第十二章 + `60-CROSS-MODEL-VERIFICATION.md` + `00-CONSTITUTION` C14。

| # | 红线 | 级别 | 判定特征 | 检查器 |
|---|------|------|----------|--------|
| R-CROSS-1 | **审查前置**：L0-L4 规约变更必须经过跨模型审查（≥2 模型），single-model 审查结论不得直接写入规约文档 | BLOCKING | 规约文档已变更但 outputs/cross_model_review/ 无对应记录 | `check_cross_model_review()` |
| R-CROSS-2 | **一致性达标**：跨模型审查 Overall κ < 0.6 时禁止合入，必须人工仲裁 | BLOCKING | κ 值低于阈值却已合入 | `check_review_consistency()` |
| R-CROSS-3 | **审查记录完整**：审查记录必须包含 raw/ + aligned/ + adjudication/ 三层产物，永久保留 | WARNING | 审查记录缺失任何一层 | `check_review_artifacts()` |
| R-CROSS-4 | **修复跟踪**：confirmed findings 必须创建跟踪任务，single-model findings 标记待人工 | WARNING | confirmed findings 未创建跟踪或 single-model 未标记 | `check_review_followup()` |
| R-CROSS-5 | **审查时效**：规约变更自合入之日起 90 天内必须有一次跨模型审查 | INFO | 合入超 90 天未审查 | `check_review_freshness()` |

**R-CROSS-* 判定逻辑**：
- ✅ PASS: 全部检测通过 → INFO (不阻断)
- ⚠️ WARNING: R-CROSS-3/4/5 违规 → 提示修复，**不阻断 push**
- 🔴 BLOCKING: R-CROSS-1 无审查即合入 / R-CROSS-2 一致性不达标却已合入 → **阻断 push**

**跨模型审查护栏与既有护栏的关系**：
| 审查护栏 | 关联既有护栏 | 关系 |
|----------|-------------|------|
| R-CROSS-1 | C14 (宪法) | 强化：C14 声明"必须交叉确认"，R-CROSS-1 落地为 BLOCKING |
| R-CROSS-2 | R-H6 (规格蒸发) | 互补：防止单模型幻觉导致规格蒸发 |
| R-CROSS-3 | R-DATA-1 (数据流完整性) | 互补：审查记录 = 规约变更的可审计证据链 |
| R-CROSS-4 | C9 (诚实汇报) | 互补：审查 findings 跟踪 = 诚实汇报的延伸 |
| R-CROSS-5 | R-DRIFT-2 (规范同步) | 互补：审查时效 = 防止规约审查本身僵尸化 |

**降级策略**：模型池不足（<2 可用）时，R-CROSS-1~4 降级为人工审查模式 + 代码存档记录，不阻断合入但标记 `needs-cross-model-pending`。

## 第二章：五步质量门禁（强制，顺序固定）

对应宪法 C10。**全部通过是任务 verified 的必要条件**：

| 步 | 命令 | 通过标准 | 拦截什么 |
|----|------|---------|---------|
| 1 | `py -m tools.guard` | **0 新增 BLOCKING**（相对变更前基线） | 架构模式违规（红线 1A） |
| 1.5 | `python tools/architecture_validator.py full` | 0 BLOCKING | 组件感知流水线架构违规（阶段边界/组件传播/模块路由/元数据连续性） |
| 2 | `ruff check .`（范围由 [tool.ruff] exclude 限定） | 0 违规 | 风格/导入/未用变量 |
| 3 | `python -m pytest tests/ -v --tb=long` | 0 失败 | 功能回归 |
| 4 | `python main.py --dry-run --max-seeds 1` | 无 ImportError/AttributeError/KeyError/TypeError，到达 REPORT 阶段 | **运行时数据流断点**（静态检查抓不到的交接失败） |

> **Step 1.5 说明**：架构体检（ArchCheck）是三层架构合规验证器，验证：> - **StaticAnalyzer**：模块路由完整性（recon→arm→strike→assess→report 组件化子包存在性）
> - **ContractChecker**：阶段边界契约（各阶段 ctx 字段输出符合流水线契约）
> - **RuntimeTracer**：数据流追踪（AttackResult component_type 元数据端到端连续性）

**Tier 2（条件触发）**：变更涉及攻击执行/评分/数据变换逻辑时，追加：

```bash
python main.py --max-seeds 1 --stage strike   # 最小真实验证：attack_results 非空、overall_asr 有效
```

**门禁纪律**（继承 D5 禁止捷径）：
- "改动很小" 不豁免任何一步；
- guard 通过 ≠ 代码可用（静态≠运行时）；
- 禁止用 25 种子做验证（浪费 token，`--max-seeds 1` 是验证专用配置）；
- 门禁失败时禁止标记任务完成，禁止"先合入后修复"。

## 第三章：三层执行防线（继承 D2，不可单点依赖）

| 层 | 机制 | 运行时机 | 失效后果 |
|----|------|---------|---------|
| L1 静态 | `tools/guard.py`（18 项检查，登记簿见 1D） | pre-commit/pre-push 钩子（`py -m tools.hooks` 安装）+ 手动 | BLOCKING 违规进库 |
| L2 运行时 | `--dry-run` / Tier 2 | 每次变更后（C10） | 数据流断点漏检 |
| L3 Git 门禁 | hooks 阻断提交 | 每次 commit/push | 无强制力 |

- **禁止禁用 git hooks 绕过 BLOCKING**——修违规，不是修门禁；
- 三层必须同时在线；任一层失效（如 hooks 未装）必须在任务汇报 ⚠️ 栏声明。

## 第四章：变更前基线与回滚

**基线**（任务 in-progress 开始时）：

```bash
py -m tools.guard > outputs/guard_baseline.json   # 记录当前违规基线
# 项目内路径，Windows/Unix 通用（/tmp 在 Windows 不可写）；outputs/ 不存在时先创建
```

**通过标准是"不新增"**：存量违规（历史 WARNING）允许存在，但 BLOCKING 存量必须登记为 DEBT/backlog，禁止视而不见。

**回滚协议**：

| 情形 | 动作 |
|------|------|
| 门禁失败且 10 分钟内无法定位 | `git checkout -- <files>` 回滚全部变更，任务转 aborted，记录根因 |
| Tier 2 真实攻击验证异常 | 保留代码 + 任务停在 verified-前，汇报 ⚠️ 栏说明，不标 completed |
| 合入后发现回归 | revert 该 commit（不修新补丁覆盖），重新走任务流程 |

**禁止**：在未回滚的情况下叠加"修复修复"的二次 diff。

## 第五章：质量属性检查单（评审用）

评审任何 diff 时逐项打勾（对应人工红线 R-H*）：

- [ ] diff 与任务规格文件清单一一对应（R-H6）
- [ ] 无新增双轨/职责重叠文件（R-H3）
- [ ] 无静默降级与吞错（R-H1/H2）
- [ ] 参数全部 `getattr(ctx.args, ...)`（R-H4）
- [ ] 无绕过 ctx/fingerprint 的数据通道（R-H5）
- [ ] 汇报三栏齐全，验证证据可复跑（R-H7）
- [ ] 无密钥/真实端点/越界目标（R-S1/S2）
- [ ] 新技术有 arXiv 注释（宪法 C8）
- [ ] orchestration_log 覆盖受影响阶段（R8 §8.5）
- [ ] 若动了共享资源/全局状态：清理幂等 + 循环内重置（R8 §8.1/8.3）

## 第六章：与既有资产的关系

| 既有资产 | 在本层的地位 |
|---------|-------------|
| `tools/guard.py`（18 检查，82KB） | 1A 机器红线的唯一执行器；修改它=修改规则，走宪法 C12 |
| `tools/hooks.py` | L3 Git 门禁安装器 |
| `tools/guard.py`（~257 行）+ SKILL.md R1d_extende-R11 /~ 400 行，20+1-D则全集，继续有效；本文件结构化入口，冲突处以裁决序 |
| SKILL.md 失败模式表 | 评审培训材料，保留 |
| `implementation_checklist.md` | 已于 2026-09-06 删除；其职能由 `specs/templates/task-spec.md` 接管（D-09 债务消除） |
| `specs/50-ROADMAP.md` | 无门禁效力；其任务序列仅供领任务顺序参考（REV-02） |
| `tools/watch_guard.py` | L1 静态检查的实时监视模式（开发时后台运行） |
| `tools/quick_check.py` | 单文件快速验证工具（< 1秒响应） |

---

## 第七章：交付验证清单（通用，v2.0 新增）

> **效力**：每次代码修改后的标准交付检查清单。**通用适用**于任意包和任意功能优化。

### 7A. 架构规则验证

```markdown
## 交付验证清单

### 架构规则
- [ ] `py -m tools.guard` → 0 BLOCKING
- [ ] `py -m tools.drift_detector --full` → 0 BLOCKING
- [ ] 新模块 < 850 行（R-TOOLS-2）
- [ ] 无跨层导入违规（蓝图 2.2 依赖矩阵）
- [ ] 公共 API 在 `__init__.py` 导出
```

### 7B. 代码质量验证

```markdown
### 代码质量
- [ ] `ruff check` → 0 errors
- [ ] `py_compile` → 全部通过
- [ ] 所有公共方法有类型注解
- [ ] 新模块有 docstring 说明（模块功能 + 架构对齐 + 学术引用）
```

### 7C. 测试与集成验证

```markdown
### 测试覆盖
- [ ] 单元测试: 全部通过
- [ ] 新模块测试: `tests/test_<module>.py` 存在且通过
- [ ] `python main.py --dry-run` → 无 ImportError/AttributeError

### 集成点
- [ ] 新模块在 `__init__.py` 导出
- [ ] 消费者已更新（如需要）
- [ ] PipelineContext 已更新（如需要）
```

### 7D. CLI 文档验证（v2.9 新增，R-DOC-5）

```markdown
### CLI 文档（R-DOC-5 强制）
- [ ] 交付验收显示完整参数列表（参数名/默认值/说明）
- [ ] 交付验收显示基础用法示例（至少3个场景）
- [ ] 交付验收显示组合攻击示例（与其他模块联合使用）
- [ ] `docs/guides/red-team-dev-guide.md` 附录 D 已更新
- [ ] `python main.py --help` 输出与文档一致
```

### 7E. 自动化执行命令速查

```bash
# 运行全量架构检查
py -m tools.guard
py -m tools.guard -v

# 运行漂移检测
py -m tools.drift_detector          # 快速模式
py -m tools.drift_detector --full   # 含版本锁定

# 单文件快速验证 (< 1秒)
py -m tools.quick_check report/evidence.py
py -m tools.quick_check --all

# 实时监视（开发时后台运行）
py -m tools.watch_guard                        # 监视所有包
py -m tools.watch_guard --package report       # 只监视特定包
py -m tools.watch_guard --fast                 # 快速模式（只检查修改文件）
```

### 7F. .env.local 自动启动配置

在项目根目录创建 `.env.local` 启用自动守卫：

```bash
# .env.local
AUTO_GUARD_WATCH=1
AUTO_GUARD_MODE=fast
```

**效果**：每次启动 `python main.py` 时自动在后台启动 watch_guard，无需手动执行。

### 7G. Git Hooks 完整流程

**Pre-commit**（每次 commit 自动执行）：
```bash
git commit -m "..."
  ↓
[1/3] Data flow validator... → [PASS] 29/29 tests OK
[2/3] Architecture guard...  → [PASS] 0 BLOCKING
[3/3] Quick check (modified files) → [PASS] All checks passed
  ↓
[PASS] Commit allowed.
```

**Pre-push**（每次 push 执行完整审计）：
```bash
git push origin main
  ↓
[1/3] Data flow validator (full)...
[2/3] Architecture guard...
[3/3] Drift detector (full)...
  ↓
[PASS] Push allowed.
```

---

## 第八章：OffSec AI-300 考试合规与证据完整性（v1.3 增补）

> **效力**：本章为考试场景的合规红线与证据完整性约束，视同 R-S* 安全合规红线级（宪法 C2 边界条款）。考试期间任何违反本章的行为 = 严重违宪。

### 7A. 考试合规红线（Exam Compliance Red Lines）

| # | 红线 | 违规后果 | 我们的防护 |
|------|------|---------|------|
| E-CL1 | **工具使用违规**：使用禁止的交互式 AI 聊天助手 | 考试成绩作废 | 本项目 PyRIT 三角色 LLM 是攻击引擎（执行 prompt），非聊天助手（不对话） |
| E-CL2 | **目标越界**：攻击考试下发目标之外的任何主机 | 考试成绩作废 + 可能的纪律处分 | R-S1 授权边界 + 目标硬编码白名单 |
| E-CL3 | **证据造假**：报告未实际执行的攻击 | 考试成绩作废 | 证据全字段非空校验 + PoC 独立可复跑验证 |
| E-CL4 | **密钥泄露**： PoC/笔记中出现真实 API key | 可能导致成绩作废 | R-S2 密钥纪律 + PoC 端点环境变量化 |
| E-CL5 | **报告抄袭**：直接复制他人报告 | 考试成绩作废 | 基于实际证据自动生成，无法抄袭 |

### 7B. 证据完整性约束（Evidence Integrity Constraints）

> **目的**：OffSec 考试中成功攻击必须附可复现证据。本章定义证据链的完整字段集与验证标准。

**证据全字段清单**（REQ-007 + REQ-126 综合）：

| 字段 | 必需 | 验证标准 | 对应报告段落 |
|------|------|---------|------|
| `jailbreak_prompt` | ✅ | 非空字符串，可独立执行 | findings |
| `harmful_output` | ✅ | 非空字符串，含攻击成功标识 | findings |
| `conversation` | ✅ | 完整多轮对话（request/response 对） | evidence/ 附件 |
| `scorer_results` | ✅ | J1/J2 评分结果 + confidence | findings |
| `converter_log` | ✅ | 使用的 Converter 链 + 参数 | appendix |
| `arxiv_reference` | ✅ | 至少一个 arXiv 编号 | findings |
| `validation_runs` | ✅ | PoC 独立运行 ≥1 次成功 | evidence/ 附件 |
| `testing_conditions` | ✅ | 测试环境/时间/版本信息 | appendix |
| `cvss_score` | ✅ | CVSS 类比风险等级 | findings |
| `owasp_mapping` | ✅ | OWASP LLM Top 10 2025 分类 | findings |
| `mitre_atlas_mapping` | ✅ | MITRE ATLAS 战术/技术映射 | findings |
| `remediation` | ✅ | 修复建议（REQ-113 四段结构） | remediation |

### 7C. 证据自动验证检查单

> **验证时机**：攻击成功后**立即执行**（Strike 阶段内，Assess 评分完成后 → 证据写入前）。
> **失败处理**：任何字段验证失败 → 该攻击结果标记为 `partial` 并记录到 `ctx.partial_results`，**不阻断**后续攻击但报告中标注。

```markdown
- [ ] jailbreak_prompt 非空且可独立执行
- [ ] harmful_output 含攻击成功标识（拒绝检测绕过的证据）
- [ ] conversation 含完整 request/response 对
- [ ] scorer_results 非空（J1/J2 任意置信度）
- [ ] converter_log 记录了使用的 Converter 链
- [ ] arxiv_reference 非空（至少一个 arXiv 编号）
- [ ] validation_runs 记录了独立复跑结果
- [ ] testing_conditions 含环境信息
- [ ] cvss_score 已计算
- [ ] owasp_mapping + mitre_atlas_mapping 已关联
```

**验证执行点**（代码落点）：
- `strike/executor.py` → `_validate_attack_evidence(evidence)` 在 `is_attack_successful` 返回 True 后立即调用
- 验证失败 → 写入 `ctx.partial_results.append(evidence)` + `logger.warning("Evidence validation failed for ...")`
- 报告生成时 → `partial_results` 在 findings 段落标注 `[PARTIAL]` 标签

### 7D. 考试日定期自检规程

> **执行时机**：考试中每 4h 执行一次（建议在每个目标切换时）。

| 检查项 | 方法 | 期望结果 |
|------|------|---------|
| 目标白名单 | 确认当前目标在考试下发列表中 | ✅ 在列表内 |
| 工具使用 | 确认未使用交互式 AI 聊天助手 | ✅ 仅用 PyRIT 攻击引擎 |
| 证据完整性 | 跑 7C 检查单 | ✅ 全部字段非空 |
| 密钥泄露扫描 | grep PoC 文件中 `sk-` / `api_key` 模式 | ✅ 零命中 |
| 时间盒进度 | 检查已用时间 / 剩余目标数 | ✅ 在预算范围内 |

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-05 | 初版：R-L/R-H/R-S 红线、四步门禁、三层防线、基线与回滚协议、评审清单 | — |
| v1.1 | 2026-09-05 | REV-01：① 新增 1D 检查器登记簿（16 项引用汇总，级别标注，缺口登记 BL-003）；② 基线落盘路径改项目内 outputs/（Windows 兼容）；③ 第三章 L1 行交叉引用 1D | 用户会话批准 |
| v1.2 | 2026-09-05 | REV-02：① 第二章登记 ruff pipeline/ 盲区缺口（D-16）及临时申报纪律；② R-H1/R-H3 判定特征补充源码实证（stub 注释自认降级、escalation 9 字节孪生）；③ R-S1 补考试场景授权边界说明；④ 第六章登记 50-ROADMAP 的无门禁地位；⑤ guard 实测规模 82KB 入表 | 用户会话批准 |
| v1.3 | 2026-09-06 | REV-03 AI-300 考试合规优化：① 新增第七章 OffSec AI-300 考试合规与证据完整性（考试合规红线 7A、证据完整性约束 7B、证据自动验证检查单 7C、考试日定期自检规程 7D）；② 红线/门禁/防线本体无变更 | 用户会话批准 |
| v1.4 | 2026-09-08 | REV-04 Glue 层专项护栏：① 新增第一章 1D Glue 层专项护栏（R-GLUE-1~R-GLUE-5：插件化隔离、PyRIT 原生委托、配置数据流、静默降级、学术留痕）；② 新增 Glue 层攻击向量白名单（JWT 混淆、向量 DB 投毒、HTTP 走私、审计日志注入、微调后门注入）；③ 1E 检查器登记簿新增 5 项 Glue 层检查器（总计 24 项） | 用户会话批准 | 
| v1.5 | 2026-09-08 | REV-05 过度工程化清理（精简白名单）：① 白名单移除向量DB投毒和微调后门注入（黑盒HTTP不可测试）；② 适用范围移除已删除模块（vector_glue、finetuning_glue）；③ 护栏数量不变（R-GLUE-1~R-GLUE-5 仍适用保留的3个模块） | 用户会话批准 |
| v1.6 | 2026-09-09 | REV-06 规范漂移检测系统：① 新增 1E-DRIFT 规范漂移检测护栏（R-DRIFT-1~R-DRIFT-5：PyRIT API 解析验证 BLOCKING / 规范表格-代码同步 WARNING / 版本变更锁定 BLOCKING / 契约消费验证 INFO / 原生模式违规 WARNING）；② 1F 检查器登记簿新增 5 项 Drift Detector 检查器（总计 29 项）；③ 调用方式：`pyrit-drift` / `py -m tools.drift_detector --full` | 用户会话批准 |
| v2.0 | 2026-09-09 | REV-07 合并 60-REDTEAM-DELIVERY-FRAMEWORK.md：① 新增第七章"交付验证清单"（通用验证模板 + watch/quick 命令速查 + .env.local 配置 + Git Hooks 完整流程）；② 原第七章（考试合规）重命名为第八章；③ 删除冗余文档 `60-REDTEAM-DELIVERY-FRAMEWORK.md` | 用户会话批准 |
| v2.1 | 2026-09-09 | REV-08 新增 R-DATA-2 ASR 中心性红线 + R-DATA-3 取证数据字段红线；R-DATA-1 实测 29 项测试 + R-DATA-2/3 同步覆盖 | 用户会话批准 |
| v2.2 | 2026-09-09 | REV-09 新增自主决策系统护栏：① 新增 1G-DECIDE 自主决策系统护栏（R-DECIDE-1~R-DECIDE-5：安全边界保护 BLOCKING / 决策审计追踪 WARNING / 决策稳定性 WARNING / 人类控制权 INFO / 决策数据完整性 WARNING）；② 1H 检查器登记簿新增 5 项决策检查器（总计 34 项）；③ 决策护栏与既有护栏关系映射 | 用户会话批准 |
| v2.3 | 2026-09-09 | REV-10 P0+P1+P2 文档优化：① 1F 检查器登记簿精简（移除冗余 v1.2/v1.4 锚定标注，新增 R-WEB-1~3 重命名映射，按分类分组）；② 7C 证据验证检查单增强（新增验证时机说明 + 失败处理逻辑 + 代码落点映射：`_validate_attack_evidence()` → `ctx.partial_results`） | 用户会话批准 |
| v2.4 | 2026-09-09 | REV-11 规约优化三批实施：① 登记簿唯一化——1F 为唯一检查器登记簿，删除重复的 1H；② 引用修正——Web 攻击向量白名单三处错误归属（arXiv:2207.01077 / ANSI ISAAC 2023 / CVE-2023-50164）按可验证来源改写；③ R-DATA-1 测试数与 `tests/test_data_flow_integrity.py` 实测 29 项对齐；④ 新增 R-TOOLS-2（单模块行数上限 850 行，R-SIZE 编号归位、R-DELIVERY-3 作废）；⑤ 新增 R-DECIDE-6 策略先验优先；⑥ Step 2 命令统一为 `ruff check .`；⑦ 删除过时 D-16 注记 | 用户会话批准 |
| v2.5 | 2026-09-09 | REV-12 P2-C4 修复：第二章四步门禁 Step 2 命令行字符损坏（mojibake），修复并统一为 `ruff check .`（范围由 [tool.ruff] exclude 限定），对齐宪法 C10 与 task-spec 模板 | 用户会话批准 |
| v2.6 | 2026-09-09 | 新增文件上传攻击护栏：① 1D 适用范围扩展（新增 file_upload_executor.py）；② 新增 R-WEB-6 任意端口支持护栏（BLOCKING）；③ 白名单新增 2 个文件上传攻击向量（间接Prompt注入、RAG知识库投毒）；④ R-WEB-3 配置数据流扩展（文件上传目标URL）；⑤ R-WEB-5 学术留痕扩展（文件上传攻击向量） | 用户会话批准 |
| v2.7 | 2026-09-09 | 新增 1C-DOC 代码-文档同步护栏：① R-DOC-1 CLI参数文档同步检查；② R-DOC-2 攻击模块缺口文档同步检查；③ R-DOC-3 需求/红线同步检查；④ R-DOC-4 README版本索引同步检查；⑤ 1F检查器登记簿新增4项检查器（总计 38 类）；⑥ 文档同步清单（代码变更必查） | 用户会话批准 |
| v2.8 | 2026-09-09 | REV-15 新增跨模型规约审查护栏：① 1I-CROSS 跨模型规约审查护栏（R-CROSS-1~5：审查前置 BLOCKING / 一致性达标 BLOCKING / 审查记录完整 WARNING / 修复跟踪 WARNING / 审查时效 INFO）；② 1F 登记簿新增 5 项跨模型审查检查器（总计 44 项）；③ 降级策略与护栏关系映射 | 用户会话批准 |
| v2.9 | 2026-09-09 | **REV-16：新增 R-DOC-5 命令行文档同步护栏**：① `check_cli_usage_shown_in_delivery()` 检查器 (WARNING)——新增/修改 CLI 参数必须在交付验收时显示完整命令行用法；② 第七章交付验证清单新增 7D CLI 文档验收项（参数列表+基础示例+组合攻击示例）；③ 1F 登记簿新增 1 项检查器（总计 46 项）；④ 文档同步清单新增交付验收项 | 用户会话批准 |
| v3.0 | 2026-09-09 | **REV-17 修复 spec-code drift (R-L1/R-L7)**：① **R-L1 真正实现**——新增 `check_no_defense_in_attack_dirs()` 检查器 (BLOCKING)，检测攻击目录 (strike/arm/recon/attack_*) 中的防御逻辑 (Defense/Sandbox/Filter/Analyzer/Guard 类等)；含 `_DEFENSE_CHECK_WHITELIST` 白名单覆盖合法侦察代码 (guardrail_detector.py、stealth_config.py、session validation 等)；② **R-L7 真正实现**——新增 `check_top_level_structure()` 检查器 (BLOCKING)，基于 `_ALLOWED_TOP_LEVEL_DIRS` / `_ALLOWED_TOP_LEVEL_FILES` 白名单检测未授权顶层目录/文件；③ 1F 登记簿更新名称映射 (check_safety_guardrails→check_no_defense_in_attack_dirs, check_root_directory→check_top_level_structure)；④ R-L1 适用范围扩展至 attack_* 目录模式匹配（未来新增攻击目录自动覆盖） | 用户会话批准 |
