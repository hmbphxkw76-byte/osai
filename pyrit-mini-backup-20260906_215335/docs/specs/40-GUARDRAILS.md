# 40 — 安全与质量层：红线护栏（Guardrails）

> **文档层级**：L4 / 五层规约金字塔第五层
> **效力**：红线 = 绝对禁止，视同宪法级（裁决序见 00-CONSTITUTION 第二章）。质量门禁 = 完成任务的必要不充分条件。
> **执行机制**：三层防线（静态 guard / 运行时 dry-run / git 钩子），继承 SKILL.md D2 条款并收编。
> **版本**：v1.2（2026-09-05 初版；同日 REV-01/REV-02 修正；版本记录见文末）

---

## 第一章：红线清单（绝对禁止）

### 1A. 机器可查红线（guard 自动拦截，BLOCKING）

| # | 红线 | guard 检查器 |
|---|------|-------------|
| R-L1 | 攻击端（strike/arm/recon）出现安全护栏/内容过滤逻辑 | `check_safety_guardrails()` |
| R-L2 | 自定义 Executor/Target/Scorer 基类替代 PyRIT 原生 | `check_forbidden_custom_classes()` |
| R-L3 | `ConverterConfiguration` 串联堆叠（>1 converter） | `check_serial_stacking()` |
| R-L4 | defaults.yaml 参数低于 L5 基线（max_attempts≥3、escalation_asr_threshold≥90 等） | `check_l5_params()` |
| R-L5 | 升级链缺失 L1/L2 中间退出检查点 | `check_intermediate_exit()` |
| R-L6 | 报告生成未调用 pyrit.output 原生模块 | `check_pyrit_native_output()` |
| R-L7 | 根目录出现非法文件；tests/ 缺失 | `check_root_directory()` / `check_test_coverage()` |
| R-L8 | `--dry-run` 参数或实现缺失 | `check_dry_run_available()` |

### 1B. 人工评审红线（diff 评审必查）

| # | 红线 | 判定特征 |
|---|------|---------|
| R-H1 | 静默降级：stub/空实现/fallback 进入编排链路而未在任何文档登记 | 函数体 `return {}` / `return None` 被真实调用方消费（REV-02 审计实证：cair.py / encoded_injection.py / multi_turn_attacks.py 注释自认"调用方 try/except 优雅降级"） |
| R-H2 | 静默吞错：`except Exception: pass` 或日志级别掩盖故障 | try 块体量远大于 except 处理 |
| R-H3 | 双轨新增：新文件与既有文件职责重叠 | 新模块名与既有模块名词近义（manager/pipeline/handler 变体；REV-02 实证：escalation.py 与 escalation_chain.py 仅差 9 字节） |
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

### 1D. Guard 检查器登记簿（v1.1 增补）

规约各处引用的检查器汇总（**权威清单以 `core/architecture_guard.py` 实际实现为准**）：

| 检查器 | 条款/红线 | 级别 | 备注 |
|--------|----------|------|------|
| check_safety_guardrails | C2 / R-L1 | BLOCKING | — |
| check_forbidden_custom_classes | C1 / R-L2 | BLOCKING | — |
| check_serial_stacking | C2 / R-L3 | BLOCKING | — |
| check_l5_params | C2·C7 / R-L4 | BLOCKING | — |
| check_intermediate_exit | I4 / R-L5 | BLOCKING | — |
| check_pyrit_native_output | I9·C1 / R-L6 | BLOCKING | — |
| check_root_directory | R-L7 | BLOCKING | — |
| check_test_coverage | R-L7 | BLOCKING | — |
| check_dry_run_available | C10 / R-L8 | BLOCKING | — |
| check_native_attack_usage | C1 | WARNING | v1.2 锚定 |
| check_native_attack_instantiation | C1 | WARNING | v1.2 锚定 |
| check_llm_scorer_in_attack | C2·I2 | WARNING | v1.2 锚定 |
| check_hardcoded_params | C7 | WARNING | v1.2 锚定 |
| check_config_data_flow | C7 | WARNING | v1.2 锚定 |
| check_native_params_from_config | C7 | WARNING | v1.2 锚定 |
| check_arxiv_citations | C8 | INFO | v1.2 锚定 |
| **check_silent_degradation** | C9 (显式 gap) | WARNING | v1.2 新增 (T0-1) |
| **check_silent_swallowing** | C9 (显式 gap) | WARNING | v1.2 新增 (T0-2) |
| **check_dual_track** | D-11 / C7 | INFO | v1.2 新增 (T0-3) |

- 本表对照 `core/architecture_guard.py` 实际实现同步（19 项，补齐全部待锚定项，新增 3 项）。
- **specs-guard 联动**: guard 启动时读取 `00-CONSTITUTION.md` 版本号并输出至报告脚注（裁决序基准）；版本不匹配时以 guard 实现为准、规约文档视为待同步。
- **R9 误报白名单 (v1.2)**: `display.py`、`display_stages.py` 中通过 `_resolve('param', default)` 包裹的动态配置读取，视为已修复配置数据流断点（不报 R9）。

**红线冲突裁决**：R-S*（安全合规）> R-L*（机器红线）> R-H*（人工红线）。安全红线与 ASR 冲突时（例如"过滤掉这个目标会更安全"），安全红线赢——但正确答案几乎总是 STOP-REPORT 让人裁决。

## 第二章：四步质量门禁（强制，顺序固定）

对应宪法 C10。**全部通过是任务 verified 的必要条件**：

| 步 | 命令 | 通过标准 | 拦截什么 |
|----|------|---------|---------|
| 1 | `python core/architecture_guard.py --fix-hints` | **0 新增 BLOCKING**（相对变更前基线） | 架构模式违规（红线 1A） |
| 2 | `ruff check core/ recon/ arm/ strike/ assess/ report/ targets/ utils/ main.py` | 0 违规 | 风格/导入/未用变量 |
| 3 | `python -m pytest tests/ -v --tb=long` | 0 失败 | 功能回归 |
| 4 | `python main.py --dry-run --max-seeds 1` | 无 ImportError/AttributeError/KeyError/TypeError，到达 REPORT 阶段 | **运行时数据流断点**（静态检查抓不到的交接失败） |

**已知缺口（REV-02 审计，D-16）**：pyproject.toml 的 ruff `exclude` 含 `pipeline/`，且本表 Step 2 命令未含 `pipeline/`——该目录当前处于 lint 盲区。修复属 T0-3 工具链任务（50-ROADMAP 第四章）；修复前，涉及 pipeline/ 的变更须在汇报 ⚠️ 栏声明"pipeline/ 未过 lint"。

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
| L1 静态 | `architecture_guard.py`（18 项检查，登记簿见 1D） | pre-commit/pre-push 钩子（`python core/setup_hooks.py` 安装）+ 手动 | BLOCKING 违规进库 |
| L2 运行时 | `--dry-run` / Tier 2 | 每次变更后（C10） | 数据流断点漏检 |
| L3 Git 门禁 | hooks 阻断提交 | 每次 commit/push | 无强制力 |

- **禁止禁用 git hooks 绕过 BLOCKING**——修违规，不是修门禁；
- 三层必须同时在线；任一层失效（如 hooks 未装）必须在任务汇报 ⚠️ 栏声明。

## 第四章：变更前基线与回滚

**基线**（任务 in-progress 开始时）：

```bash
python core/architecture_guard.py --json > outputs/guard_baseline.json   # 记录当前违规基线
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
| `core/architecture_guard.py`（18 检查，82KB） | 1A 机器红线的唯一执行器；修改它=修改规则，走宪法 C12 |
| `core/setup_hooks.py` | L3 Git 门禁安装器 |
| SKILL.md R1-R11 / D1-D6 | 细则全集，继续有效；本文件是其结构化入口，冲突处以裁决序 |
| SKILL.md 失败模式表 | 评审培训材料，保留 |
| `implementation_checklist.md` | 已于 2026-09-06 删除；其职能由 `specs/templates/task-spec.md` 接管（D-09 债务消除） |
| `specs/50-ROADMAP.md` | 无门禁效力；其任务序列仅供领任务顺序参考（REV-02） |

---

## 第七章：OffSec AI-300 考试合规与证据完整性（v1.3 增补）

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

每次攻击成功后，执行以下自动验证（确保 E-CL3 不触发）：

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
