# CP-010 — 存量债务收敛总提案（长周期专项）

> 状态：**draft（登记与排期；本会话仅完成其中的低风险文档治理部分，代码重构类切片待逐片批准）**
> 关联：BL-025/050、BL-026/053、BL-047、BL-048/059/064/084、BL-058、BL-060、BL-081/087、BL-082(S2~S4)、BL-090、BL-092
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 背景

2026-09-14 开发全审（八目录 A→L + 债务收敛）后，backlog 中剩余项呈现明显共性：

1. **多数不是"没人做"，而是"做了没回填 / 判定口径过期"**（BL-025 经核查是活跃兼容层而非死字段；BL-039/040/041/042/071 复核后直接关单）；
2. **真正需要代码重构的项都跨 3+ 模块**，无法在一次会话内以合规粒度完成（[sid:30-ch3]）；
3. **能力缺口类**（BL-048/059/064/084）直接决定 ASR 上限（宪法 C2），但每项都是"REQ 登记 → task-spec → 实现 → 种子 → T0 → 报告段"的完整链路。

本 CP 把剩余项切成**可独立批准、可独立验收**的切片，按"ASR 影响 × 风险"排序。

## 2. 切片总表（按执行顺序）

| 片 | 承接 | 内容 | 涉及 | 前置/风险 |
|----|------|------|------|-----------|
| **S1** | BL-082 S2 | T0 文本判定下沉 `core.t0_text_checks`（纯函数）；`assess.judge_manager` 改包一层做统计；`strike.common._executor_helpers` 改引 core | 新增 1 + 改 2 | **ASR 关键路径（T0 判定 + 统计）**：必须逐函数比对行为不变，验证 `pytest tests/common/test_assess.py tests/common/test_component_scorers.py` 全绿 + 一次 dry-run 对照 |
| **S2** | BL-082 S3 | asr_history 读写器下沉 `core.asr_history`（回归蓝图 I7：assess 写、arm 读） | 新增 1 + 改 2 | 中：涉及 asr_history.json 落盘口径，需跑 `--dry-run` 前后对照 |
| **S3** | BL-090 / BL-082 S4 | `core → recon` / `strike → recon` / `report → utils` 三组根治（共享件下沉或改注册表解析） | 跨模块 | 并入 REQ-151 波次；IC-2 |
| **S4** | BL-092 | `ctx.{surface_graph, playbook_state, impact_chains, score_manifest}` 零消费：逐字段 a/b/c 判定（接线 / 摘除 / 标注未接线） | `core/context.py` + 蓝图 4.4 总表 | ✅ **本会话已完成**（四字段统一判定 (c) 预留型标注 + 加入 R-PIPE-5 白名单；ASR 中性） |
| **S5** | BL-025 / BL-050 | 兼容层收敛：① 消费者迁新字段 → ② 删 `component.py` merge → ③ 删 YAML 旧字段 | 3+ 模块 + 10 YAML | 中高：必须先确认零回归（`validate_wiring()` + 组件审计） |
| **S6** | BL-081 / BL-087 | 乱码回填：6 文件按历史 rev（7f5790c / e81d5ab / 1c2c7ef / f00e041）**函数级比对**回填；2 文件（`converter_chains_text.py`、`converter_chains_document.py`）语义重写 | 8 文件（分 3 批） | 低（注释/docstring 不改语义）；每批后跑全量 |
| **S7** | BL-026 / BL-053 | 大文件拆分：`guard_extended`(2487) / `attack_surface_mapper`(1150) / `_arg_parser`(1109) / `guard`(940) | 4 文件（逐个） | 中：拆分需保 `check_*` 注册发现机制不变 |
| **S8** | BL-048 / BL-093 | `agent` 组件（YAML + recon/strike/assess/report 四件套 + 种子）已完整落地并注册（BL-048 ✅ completed）；I13 cleanup 动作 `unregister_rogue_tool`/`restore_agent_tools` 已实装并登记入共享 `core.side_effect_cleanup` 注册表（与 multimodal_upload 共用，避免重复基建） | 多文件 | ✅ **BL-048 completed**；BL-093（open）：agent 无 `run_agent_attack` 分发器调用 `preflight/run_side_effect_cleanup`，真实攻击路径清理执行待该分发器落地后接线 |
| **S9** | BL-084 | technique 覆盖缺口 24 项（优先 `memory` 0/4） | 多文件 | ✅ **Wave 1 完成**（memory 0/4→4/4，真实实现非 stub）；✅ **Wave 2 完成**（a2a 5/6→6/6，`task_interception` 真实实现非 stub）；✅ **Wave 3 完成**（recon rag/embedding/model/mcp/api 共 9 项真实策略，纯解析 + monkeypatch 测试，非 stub，`component_purity` 实测 5 组件均 100%）；✅ **Wave 4 完成**（strike web/injection/evasion/session 共 10 项真实技术：auth_bypass/rate_limit_evasion/scope_escalation、auth_injection/document_poisoning/file_upload_injection、audit_log_evasion/encoding_evasion、context_leakage/idor_testing；均委托既有框架基础设施或纯解析，非 stub，`component_purity` 实测 4 组件均 100%）；**S9 全部 24 项 technique 覆盖完成 ✅**；运行期技术分支接线并入 S3/REQ-151 |
| **S10** | BL-059 / BL-064 | `multimodal_upload` YAML 注册；`delete_uploaded_document` cleanup 实装（I13，阻断真实攻击启用） | 2~3 文件 | ✅ **本会话已完成**（代码此前已实装并接线，仅回填滞后；YAML 注释/backlog BL-059/BL-064 已同步；ASR 由 0 升为 >0） |
| **S11** | BL-047 / BL-058 / BL-060 | 规约回填：REQ-005 升级链状态、IA-5（`suitable_for` 口径）、文档纪律 D9（乱码结论须字节级取证，原 D8 被 sid 锚点占用顺延） | 3 文档 | ✅ **本会话已完成**（三件 BL 均 completed；D9 写入 README §5） |
| **S12** | BL-027 / BL-078 / BL-079 / BL-080 | 裁决已落地：BL-027 discarded（删除重复模板，文件已不存在）；BL-079 completed（55-gap-1~6 纳入 R-DOC-4 白名单+索引）；BL-080 completed（降级"本机可选细则"并在 40-G/30-TASKS/10-ARCH 三处标注）；**仅 BL-078（冻结 plan 畸形 sid）仍待人工裁决** | 文档 | BL-078：**需人工裁决**（豁免区内，解冻/复制进活跃规约前必修锚点） |

## 3. 验收总则

每个切片独立满足：
- [ ] 有 `TASK-xxx` + 关联 `REQ/DEBT/BL` 编号（C6）
- [ ] 受影响文件 ≤3、diff ≤300 行、跨模块 ≤2、新增文件 ≤1（[sid:30-ch3]）
- [ ] `python -m tools.gate --stage push` 全绿
- [ ] 若切片改变攻击/评分行为 → 附"ASR 升还是降"的有据答案（C2）
- [ ] 完成后对应 BL 条目置 `completed` 并写清验证证据

## 4. 不做的事

- 不新建第二套链 / 第二套组件机制（C3）；
- 不为凑覆盖率补 stub（R-H1 / BL-030 教训）；
- 不顺手扩大任务范围（C4）；发现新问题一律进 backlog。

## 5. 周期性维护（不在 CP-010 切片范围）

以下项经复核不属"一次性代码重构"，改为周期性维护，不占用 CP-010 切片配额（与 BL-028 同类：登记簿/代码双向滞后）：

| ID | 内容 | 维护动作 |
|----|------|----------|
| BL-028 | 1F 登记簿与代码双向滞后 | 周期跑 `40-GUARDRAILS.md` 1F 头部命令对齐（本轮已同步 3 行） |
| BL-031 | `ctx.techniques` 只喂 Converter、不选 Executor（技术路由断裂） | 正确归宿 REQ-151 PlaybookEngine（W2）；禁止新建第二套链机制（C3） |
| BL-038 / BL-046 | `defaults.yaml` 死配置（BL-038 状态滞后于代码，合并后逐键判定） | 合并后逐键 a/b/c 判定：接真须先提案 / 功能不存在者摘除 / 预留型标注 |
