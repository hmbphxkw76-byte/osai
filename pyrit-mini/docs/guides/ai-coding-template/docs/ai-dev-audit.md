# AI 编程通用审计与度量框架 — Universal AI-Coding Audit & Measurement Framework

> **文档定位**：跨模型、跨项目的 AI 编程**验证与度量**框架模板。与 `ai-dev-guides.md`（规范与流程）配套，本文件是验证维度的**单一事实源**。
> **核心理念**：通过**审计成熟度模型（Audit Maturity A0–A5）** + **六维审计** + **问题等级（BLOCKING/WARNING/INFO）** + **跨模型一致性度量协议**，实现可量化、可复现、跨模型一致的 L5 专家生产标准。
> **关键概念澄清**：
> - **规范分层金字塔（L0–L4）** 在 `ai-dev-guides.md` —— 描述"写什么文档"。
> - **审计成熟度（A0–A5）** 在本文件 —— 描述"验证有多严"。二者不同维度，编号不冲突。
> - **质量关卡（Gate Stages）** 在 guides —— 检查的阶段序列；**问题等级（Severity）** 在本文件 —— BLOCKING/WARNING/INFO。
> **适用范围**：个人项目、团队协作、企业级系统、开源基础设施、跨模型协作。
> **版本**：v2.0（2026-09-12）— 解耦项目细节、重命名成熟度模型、统一 κ/r 口径、补 L5 达标清单与度量指标。

---

## 文档家族与阅读指南

| 文档 | 角色 | 本文件负责 |
|------|------|-----------|
| `ai-dev-guides.md` | 规范 + 流程 | 规范分层、开发工作流、spec 模板、门禁**阶段**、跨模型**政策** |
| **本文件 `ai-dev-audit.md`** | 验证 + 度量 | 审计成熟度 A0–A5、六维审计、门禁**等级**、跨模型**度量协议**、幻觉检测、漂移量化、安全审计 |

**共享术语表**见 `ai-dev-guides.md` 附录 D（单一事实源）。

### 目录

1. [第一部分：审计成熟度模型 A0–A5](#第一部分审计成熟度模型-a0a5)
2. [第二部分：L5 达标清单（可量化）](#第二部分l5-达标清单可量化)
3. [第三部分：六维审计框架](#第三部分六维审计框架)
4. [第四部分：问题等级与门禁机制](#第四部分问题等级与门禁机制)
5. [第五部分：跨模型一致性度量协议](#第五部分跨模型一致性度量协议)
6. [第六部分：六大审计维度详解（通用化）](#第六部分六大审计维度详解通用化)
7. [第七部分：L5 专家级审计维度详解](#第七部分l5-专家级审计维度详解)
8. [第八部分：框架适配指南](#第八部分框架适配指南)
9. [第九部分：FAQ](#第九部分faq)
10. [附录 A：跨模型度量模板库](#附录-a跨模型度量模板库)
11. [附录 B：排错速查](#附录-b排错速查)
12. [附录 C：触发词完整映射表](#附录-c触发词完整映射表)
13. [附录 D：规范 CHANGELOG](#附录-d规范-changelog)
14. [附录 E：失败案例库](#附录-e失败案例库)

---

## 第一部分：审计成熟度模型 A0–A5

> 描述一个项目的 AI 编码**验证体系有多成熟**。这是"质量水位"，与 guides 的规范分层（写什么）正交。

```
┌─────────────────────────────────────────────────────────────┐
│                 审计成熟度模型 (Audit Maturity)               │
├─────────────────────────────────────────────────────────────┤
│  A5 专家 (Expert)      ← 全维度 + 跨模型 + 自动化 + 可观测   │
│  A4 生产 (Production)  ← 关卡全绿 + 全量测试 + 漂移监控       │
│  A3 集成 (Integration) ← 数据流 + 漂移检测 + 契约测试         │
│  A2 组件 (Component)   ← 纯净度 + 覆盖度 + 单测              │
│  A1 基础 (Foundation)  ← Lint + 单测 + 静态规则              │
│  A0 入门 (Starter)     ← 代码风格 + 文件结构                 │
└─────────────────────────────────────────────────────────────┘
```

| 等级 | 名称 | 核心特征 | 退出标准（达成后可升下级） |
|------|------|---------|--------------------------|
| **A0** | 入门 | 风格/结构基本规范 | lint 0 违规 + 目录结构合规 |
| **A1** | 基础 | 静态规则 + 单测 | guard 0 BLOCKING + 关键路径有测试 |
| **A2** | 组件 | 模块纯净 + 覆盖 | 纯净度≥90% + 覆盖率达标（见 guides §5.3） |
| **A3** | 集成 | 数据流 + 漂移 | 全链路契约测试通过 + 漂移 0 BLOCKING |
| **A4** | 生产 | 关卡全绿 + 监控 | 6 步关卡全绿 + 漂移仪表盘运行 + 日志完整 |
| **A5** | 专家 | 跨模型 + 可观测 + 可复现 | 满足第二部分「L5 达标清单」全部项 |

**核心特征（A5 专家）**：
- 全维度覆盖：架构/组件/依赖/数据/漂移/纯净 六维
- 跨模型一致性：同一规约在不同模型产生一致结果（κ/r 达标）
- 自动化门禁：BLOCKING/WARNING/INFO 三级，失败即停
- 可复现：模型版本 + prompt 版本钉死，output_hash 记录
- 可观测：AI 交互日志 + 漂移健康度 + 幻觉率趋势

---

## 第二部分：L5 达标清单（可量化）

> **关键改进**：L5 不再是主观宣称，而是客观 checklist。全部满足 = L5。

```
[ ] A. 质量关卡：6 步关卡（guard/lint/test/dry-run/drift/dataflow）全绿，0 BLOCKING
[ ] B. 红线：0 安全红线违例（R-SEC-01~07），0 机器红线违例
[ ] C. 覆盖：P0 核心行覆盖 ≥90%、分支 ≥80%
[ ] D. 漂移：DRIFT-* 全部 < 健康阈值（API<1% / FILE<2% / VERSION=0% / CONTRACT<5% / SPEC<5%）
[ ] E. 跨模型（如启用）：P0 κ≥0.75、P1 κ≥0.60；输出相似度 r≥0.85；分歧 κ<0.4 已人工仲裁
[ ] F. 纯净：组件纯净度 ≥90%，无双轨/stub 进主干
[ ] G. 可复现：每次生成记录 model 版本 + prompt 版本 + output_hash
[ ] H. 可观测：AI 交互日志完整（AUDIT 级永久留存跨模型/豁免记录）
[ ] I. 文档同步：specs 与代码一致，无规格蒸发（diff 100% 关联 task ID）
[ ] J. 三态汇报：交付清单无 ❌，⚠️ 项有显式理由与证据
```

> 任一项不满足 → 未达 L5。审计工具应输出上述 10 项的逐项判定（PASS/FAIL），而非笼统"全绿"。

---

## 第三部分：六维审计框架

> 任一 AI 编程项目都可用这六个维度审计代码与规范的符合度。维度**通用**，具体检查项按项目替换 `${...}`。

| 维度 | 核心问题 | 检测方法 | 输出 |
|------|---------|---------|------|
| **架构审计** | 模块边界清晰？阶段契约满足？ | 静态分析 + 契约检查 | PASS/WARNING/BLOCKING |
| **组件审计** | 组件目录完整？覆盖充分？ | 基线扫描 + 覆盖 + 种子清单 | 缺失项列表 |
| **依赖审计** | 导入合规？版本锁定？ | import 解析 + 版本对比 | 违规项 + 修复建议 |
| **数据审计** | 数据流完整？字段契约满足？ | 全链路追踪 + 字段存在性 | 断点位置 |
| **漂移审计** | 规范与代码同步？版本偏离？ | 规范-代码交叉验证 | 漂移维度 + 修复提示 |
| **纯净审计** | 组件被污染？必需技术覆盖？ | AST 分析 + 基线对比 | 纯净度 + 覆盖度分数 |

**三维度交叉**：每个维度同时产出「问题等级」（BLOCKING/WARNING/INFO，见第四部分）与「成熟度映射」（A1–A5）。

---

## 第四部分：问题等级与门禁机制

> ⚠️ 术语：**问题等级 = 严重程度**（本文件）；**质量关卡 = 检查阶段序列**（guides §3.4）。勿混。

### 4.1 三级问题等级

| 级别 | 含义 | 处理方式 | 类比 |
|------|------|---------|------|
| **BLOCKING** | 架构违规 / 数据断裂 / 安全漏洞 / 红线违例 | 立即修复，禁止通过 | 红灯 |
| **WARNING** | 潜在风险 / 规范偏离 / 性能隐患 | 建议修复，可人工豁免（有审批+过期日） | 黄灯 |
| **INFO** | 最佳实践提醒 / 改进建议 | 知会即可，无需阻断 | 绿灯 |

### 4.2 门禁决策流程

```
审计触发 → 运行全量检查
  ├─ BLOCKING > 0 → 立即修复，禁止提交
  ├─ WARNING > N  → 建议修复，记录豁免（需审批）
  └─ 否则         → 通过 ✓ 允许提交
```

### 4.3 门禁豁免机制

WARNING 无法立即修复时可申请豁免，须结构化记录：

```yaml
# audit_exemptions.yaml
exemptions:
  - rule: "R-SIZE"
    file: "${module}/large_module.py"
    reason: "单一职责稳定模块，拆分风险高于收益"
    approved_by: "tech_lead"
    expires: "2026-12-31"
```

**纪律**：豁免有审批人与过期日；过期自动重新计为违例；年度豁免次数受控（guides §3.10）。

### 4.4 规则体系（占位符化，项目自定义）

```
R-SIZE    ─ 文件大小（God Object 检测）
R-CONV   ─ Converter/Adapter 串联限制
R-IMPORT ─ 依赖导入合规（含跨层禁止矩阵）
R-TOOLS  ─ CLI 工具位置规范
R-DATA   ─ 数据流完整性
R-PIPE   ─ 流水线模块注册
R-REDTEAM─ 领域最佳实践（按需启用）
R-EVID   ─ 证据收集完整性
R-REPORT ─ 报告生成完整性
R-DELIVERY─ 交付规范（文件/文档/跨层）
R-DRIFT  ─ 规范漂移检测
R-NATIVE ─ 原生优先原则
R-SEC    ─ 安全红线（R-SEC-01~07，见 guides §4.5）
R-CROSS  ─ 跨模型审查/仲裁相关（见第五部分）
```

**跨层导入禁止矩阵（示意，按项目调整）**：

```
_FROM_ → _TO_  | core | feature | util | report
-----------|------|---------|------|-------
core      |  ✓   |   ✗     |  ✗   |  ✗
feature   |  ✓   |   ✓     |  ✗   |  ✗
util      |  ✗   |   ✗     |  ✓   |  ✗
report    |  ✗   |   ✗     |  ✗   |  ✓
规则：高层不得导入低层，依赖方向单向。
```

---

## 第五部分：跨模型一致性度量协议

> 本文件是跨模型**度量方法**的单一事实源；**政策/触发条件**见 `ai-dev-guides.md` §6。

### 5.1 为什么需要跨模型度量

不同模型对同一规约理解可能不同。度量确保：一致性（同 prompt 结构一致输出）、完整性（不遗漏检查维度）、可靠性（不依赖单一模型幻觉）。

### 5.2 两套指标的正确分工（统一口径）

| 指标 | 衡量对象 | 适用场景 | 阈值政策 |
|------|---------|---------|---------|
| **Cohen's κ** | 多模型**审查结论**的一致度（分类一致） | 跨模型代码评审结论是否相同 | P0 ≥0.75 / P1 ≥0.60 |
| **Pearson r** | 生成**产物输出**的相似度（连续量） | 同任务不同模型产出是否等价（C13） | r ≥ 0.85 |
| **精确匹配率** | 输出完全一致比例 | 辅助判据 | ≥ 0.70 |

> ❗ 旧版混淆 κ 与 r。规则：**结论是"同意/不同意"用 κ；输出是"数值/文本相似"用 r**。二者不互换。

### 5.3 度量执行协议

```
Step 1: 准备审查任务（提取变更 + task-spec + 上下文）
Step 2: 独立审查（并行，各模型独立输出结论）
Step 3: 差异提取（自动比对分歧点）
Step 4: 一致性计算（κ / r / 精确匹配率）
Step 5: 分级仲裁（见下方）
Step 6: 报告归档（cross-model-review/）
```

### 5.4 三级仲裁（度量绑定）

| 级别 | κ 条件 | 仲裁方式 | 输出 |
|------|--------|---------|------|
| **Tier 1** | κ ≥ 0.60 | 自动合并 | 合并结论 |
| **Tier 2** | 0.40 ≤ κ < 0.60 | 升级第三方模型 | 第三方裁决 |
| **Tier 3** | κ < 0.40 | 人工仲裁 | 人工决策 |

> κ 与 r 的对应阈值：结论一致度用 κ（上表）；产物相似度用 r≥0.85（C13）。报告须同时呈现二者。

### 5.5 审查报告模板

```markdown
# 跨模型审查报告：REVIEW-___
## 基本信息：任务ID / 时间 / 参与模型 / 变更级别
## 模型结论：A / B 各自结论
## 一致性分析：Cohen's κ=0.XX（等级） / Pearson r=0.XX / 精确匹配率=XX%
## 分歧点：| # | 内容 | A立场 | B立场 | 仲裁结果 |
## 最终结论：[合并/仲裁结果]
## 归档：cross-model-review/REVIEW-___.md
```

### 5.6 模型能力评估矩阵

> 为选择仲裁/主审模型提供量化依据。

| 维度 | 权重 |
|------|------|
| API 准确率 | 25% |
| 规范遵循度 | 20% |
| 幻觉频率（每 1k 行） | 20% |
| 任务完成率 | 15% |
| 安全性（红线违例） | 10% |
| 效率 | 10% |

**决策树**：安全任务→选安全性最高；架构变更→规范遵循度最高；API 密集→API 准确率最高；仲裁→综合最高+偏差中性。

---

## 第六部分：六大审计维度详解（通用化）

> 以下维度去掉 pyrit-mini 专属细节，用 `${pipeline_stages}` 等占位符，适配任意流水线。

### 6.1 架构审计（Architecture Audit）

| 子维度 | 验证内容 | 方法 |
|--------|---------|------|
| 阶段边界契约 | 各阶段是否正确输出到上下文 | 静态正则匹配 `${ctx}.${attr}` 赋值 |
| 组件类型传播 | component_type 全链路一致 | 桥接函数存在性检查 |
| 模块路由完整性 | 组件子模块被正确调用 | 文件+函数存在性 |
| 元数据连续性 | metadata 阶段间保持 | 读取链追踪 |
| 桥接集成 | 组件桥接在正确位置调用 | 调用点检测 |

**输出示例**：
```
[PHASE_BOUNDARY] [PASS] ${stage_1} outputs ${ctx}.${field_a}
[COMPONENT_PROPAGATION] [PASS] bridge has stamp function
[MODULE_ROUTING] [PASS] ${stage_2} module exists for ${component_x}
Summary: PASS=79 WARNING=6 BLOCKING=0
```

### 6.2 组件审计（Component Audit）

| Phase | 名称 | 核心检查 | 可跳过 |
|-------|------|---------|--------|
| 1 | Baseline Scan | 全模块组件目录清单 | 否 |
| 2 | Purity Validation | AST+正则验证纯净度 | 否 |
| 3 | Coverage | 分类模式 + 检查器覆盖 | 否 |
| 4 | Scorer/Report Coverage | 评分/报告组件感知覆盖 | 是 |
| 5 | Seed Inventory | 种子文件数量与类型匹配 | 是 |
| 6 | Validation Gate | test + guard + arch 验证 | 否 |

**纯净度**：
```
纯净度(Purity) = 1.0 - (违规数 / 总行数)   阈值 ≥90% 合格
覆盖度(Coverage) = 已发现技术数 / 必需技术数  阈值 ≥60% 合格
```

### 6.3 依赖审计（Dependency Audit）

| 规则 | 说明 | 级别 |
|------|------|------|
| R-IMPORT-1 | 禁止不推荐第三方库 | WARNING |
| R-IMPORT-2 | 跨层导入禁止 | BLOCKING |
| R-IMPORT-3 | 循环依赖检测 | BLOCKING |
| R-IMPORT-4 | `__all__`/`__getattr__` 导出完整 | WARNING |
| R-IMPORT-5 | 废弃 API 检测 | WARNING |
| R-IMPORT-6 | 版本锁定验证 | BLOCKING |

### 6.4 数据审计（Data Audit）

全链路：`${stage_1} → ${stage_2} → ... → ${stage_n}`。

**字段契约验证点（示意）**：

| 阶段 | 输出字段 | 消费阶段 | 验证方法 |
|------|---------|---------|---------|
| ${stage_1} | ${field_a} | ${stage_2} | `${ctx}.${field_a}` 读取检测 |
| ${stage_2} | ${field_b} | ${stage_3} | `${ctx}.${field_b}` 读取检测 |

### 6.5 漂移审计（Drift Audit）

| 规则 | 维度 | 说明 |
|------|------|------|
| R-DRIFT-1 | api_sync | 规范引用的原生 API 是否真实可解析 |
| R-DRIFT-2 | spec_table | 规范表格引用的代码模块是否仍存在 |
| R-DRIFT-3 | version_lock | 依赖版本是否偏离锁定 |
| R-DRIFT-4 | contract_drift | 上下文字段是否被实际消费 |
| R-NATIVE-* | native_first | 是否存在自研替代原生实现 |

**输出示例**：
```
[API_SYNC] 1 finding(s): [W] R-DRIFT-1: 原生类不在预期位置
Summary: 0 BLOCKING / 1 WARNING / 2 INFO
```

### 6.6 纯净审计（Purity Audit）

**AST 纯净度分析（示意）**：

```python
class PurityAnalyzer(ast.NodeVisitor):
    def visit_Import(self, node):
        if is_cross_component_import(node.names):
            report_violation("cross_component_import")
    def visit_FunctionDef(self, node):
        if matches_forbidden_pattern(node.name):
            report_violation("forbidden_function")
    def visit_ClassDef(self, node):
        if matches_forbidden_pattern(node.name):
            report_violation("forbidden_class")
```

**评分标准**：

| 分数段 | 等级 | 处理建议 |
|--------|------|---------|
| 95–100% | A+ | 无需处理 |
| 90–94% | A | 可选优化 |
| 80–89% | B | 建议修复 |
| 70–79% | C | 需要修复 |
| <70% | D | 立即修复 |

---

## 第七部分：L5 专家级审计维度详解

### 7.1 AI 幻觉检测协议

> 应对 AI 生成"看起来对但实际错误"的代码。

**幻觉分类**：

| 类型 | 名称 | 频率 |
|------|------|------|
| H1 | API 不存在 | 极高 |
| H2 | 参数错误 | 高 |
| H3 | 返回值误解 | 高 |
| H4 | 版本混淆 | 中 |
| H5 | 幻觉依赖 | 中 |
| H6 | 逻辑逆反 | 中 |
| H7 | 幻觉引用 | 低 |

**验证层**：

| 层 | 验证方式 | 级别 |
|----|---------|------|
| V1 静态 | AST + import 检查 | BLOCKING |
| V2 签名 | 函数签名与文档对比 | BLOCKING |
| V3 类型 | mypy/pyright | WARNING |
| V4 运行时 | dry-run 实际调用 | BLOCKING |
| V5 文档 | 与官方文档交叉 | INFO |

**检测器实现模板**：

```python
class HallucinationDetector:
    def validate_api_call(self, func_call: str, module: str) -> ValidationResult:
        if not self._can_import(module):
            return ValidationResult(valid=False, h_type="H5",
                                    message=f"Module '{module}' does not exist")
        if not self._symbol_exists(module, func_call):
            return ValidationResult(valid=False, h_type="H1",
                                    message=f"'{func_call}' not found in '{module}'")
        sig = self._validate_signature(module, func_call)
        return sig if not sig.valid else ValidationResult(valid=True)
```

**日志**：`H-LOG-___`（时间/task/类型/模块/原始输出/修正后/根因/防护策略）。

### 7.2 规范漂移量化检测

| 指标 | 计算方式 | 健康阈值 | 告警阈值 |
|------|---------|---------|--------|
| DRIFT-API | 规范引用但不存在的 API 占比 | <1% | ≥5% |
| DRIFT-FILE | 规范引用但不存在的文件占比 | <2% | ≥8% |
| DRIFT-VERSION | 锁定版本与实际不一致占比 | 0% | ≥3% |
| DRIFT-CONTRACT | 上下文字段未被消费占比 | <5% | ≥15% |
| DRIFT-SPEC | 变更无法关联 task-spec 占比 | <5% | ≥10% |

**告警升级**：INFO（周升 2%）→ WARNING（达告警阈值）→ BLOCKING（2 倍阈值）→ CRITICAL（API≥10%，暂停开发校准）。

**健康度仪表盘（示意）**：
```
整体健康度：[███████░░░] 72%
DRIFT-API   [████░░░░░░] 40% ✅
DRIFT-CONTR[███░░░░░░░] 30% ⚠️
```

### 7.3 安全审计维度

> 红线政策见 `ai-dev-guides.md` §4.5；此处为审计执行。

**威胁分类（通用）**：T1 输入攻击（注入/命令注入/路径穿越）/ T2 输出篡改（隐蔽执行链/恶意依赖/凭证泄露）/ T3 供应链污染（模型劫持/数据中毒/工具链篡改）/ T4 数据泄露（PII/密钥/架构信息）。

**敏感数据检测正则（示意）**：
```python
SENSITIVE_PATTERNS = {
    "api_key": r"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]\w{16,}['\"]",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "password": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
}
```

**依赖供应链检查**：版本锁定+hash（BLOCKING）、CVE 扫描（BLOCKING）、官方仓库+签名（BLOCKING）、许可证（WARNING）。

**安全事件响应**：P1 紧急（隔离+人工评审）/ P2 高危（暂停模块+修复）/ P3 中危（登记下一任务修复）/ P4 低危（记 backlog）。

### 7.4 完整审计流水线（A→H）

> 串联所有关键检查。阶段序列 = guides 的「质量关卡」；每阶段产出问题等级。

| Phase | 名称 | 核心检查 | 可跳过 |
|-------|------|---------|--------|
| A | Spec Impact | 人工阅读规范（提示） | 是 |
| B | Architecture Guard | R-SIZE/CONV/IMPORT/TOOLS/DATA | 否 |
| B2 | ArchCheck | 组件感知架构合规 | 否 |
| C | Lint | 代码风格 | 否 |
| D | Unit Test | 全量单测 | 否 |
| E | Runtime Dry-Run | 流水线运行时验证 | 是 |
| F | Data Flow | 全链路数据流 | 是 |
| G | Drift Detection | 规范-代码漂移 | 是 |
| H | Final Quick Check | 交付规则扫描 | 是 |

**Fail-Fast**：按顺序执行，required 阶段失败即停（除非 `--no-fail-fast`）。

**CLI（占位符）**：
```bash
${AUDIT_FULL_CMD}                 # 全审 B→H
${AUDIT_FULL_CMD} --skip e,f     # 跳过 DryRun/DataFlow
${AUDIT_FULL_CMD} --phase b      # 仅 Architecture Guard
${AUDIT_FULL_CMD} -v             # 详细
${AUDIT_FULL_CMD} --no-fail-fast # 失败继续
```

---

## 第八部分：框架适配指南

### 8.1 适配新项目步骤

**Step 1：目录结构映射**
```yaml
# audit_config.yaml
project: { name: "your-project", root: "." }
modules: { core: "core", feature: "feature", util: "util", report: "report", data: "data" }
components: { core: ["${c1}", "${c2}"], extended: ["${c3}"] }
thresholds: { file_size_warning: 850, file_size_blocking: 1500, min_purity: 0.90, min_coverage: 0.60, min_seeds_per_component: 3 }
```

**Step 2：规则定制**
```python
CUSTOM_RULES = {
    "R-SIZE": {"warning": 850, "blocking": 1500, "whitelist": ["core/orchestrator.py"]},
    "R-IMPORT": {"forbidden": [(r"import\s+requests", "用 httpx 替代")]},
    "R-CROSS-LAYER": {"forbidden": {"report": ["feature"], "util": ["feature", "report"]}},
}
```

**Step 3：集成 CI/CD**
```yaml
# .github/workflows/l5-audit.yml
name: L5 Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -e ".[dev]"
      - run: ${GUARD_CMD}
      - run: ${AUDIT_COMPONENT_CMD}
      - run: ${DRIFT_CMD}
```

### 8.2 不同规模适配策略

| 规模 | 审计策略 | 频率 | 工具链 |
|------|---------|------|--------|
| 个人 | 快速检查 | 每次提交 | lint + guard |
| 小团队 | 标准审计 | PR 时 | + component_audit + pytest |
| 企业 | 全量审计 | 每次 push | 完整 + CI |
| 开源 | 全量 + 跨模型 | Release | 完整 + 多模型对比 |

### 8.3 常见项目类型适配

**Web 后端**：`modules: { core: "app", feature: "services", util: "middleware", report: "serializers" }`，components: `[auth, api, db, cache, queue]`。

**数据科学**：`modules: { core: "src", feature: "models", util: "features", report: "visualization" }`，components: `[classification, regression, clustering]`。

**CLI 工具**：`modules: { core: "cli", feature: "commands", util: "parsers", report: "output" }`，components: `[init, run, config, plugin]`。

### 8.4 monorepo 应用

```yaml
packages:
  - { name: "core", path: "packages/core", components: ["auth", "api", "db"] }
  - { name: "plugins", path: "packages/plugins", components: ["${c1}", "${c2}"] }
```
每个子包独立审计配置 + 共享组织级基线（见 guides §7.4）。

---

## 第九部分：FAQ

### Q1：审计失败怎么办？
按优先级：BLOCKING→立即修复禁止提交；WARNING→评估影响建议修复；INFO→知会即可。

### Q2：如何豁免 WARNING？
在 `audit_exemptions.yaml` 添加条目（rule/file/reason/approved_by/expires）。

### Q3：新组件如何加入审计？
在 `audit_config.yaml` 的 `components.core` 添加名 → 建目录 → 加基线定义。

### Q4：跨模型审查需要多少模型？
至少 2 个对比；3–4 个更可靠。κ 口径见第五部分。

### Q5：审计耗时太长？
增量检查：`${GUARD_CMD} --quick ${file}`；跳过非必需阶段：`${AUDIT_FULL_CMD} --skip e,f`。

### Q6：如何在 monorepo 应用？
每子包独立配置 + 共享基线（§8.4）。

### Q7：κ 和 r 到底用哪个？
结论"同意/不同意"用 κ；产出"数值/文本相似"用 r。详见 §5.2。

### Q8：怎么判断达到 L5？
满足第二部分「L5 达标清单」10 项全部 PASS。非主观宣称。

---

## 附录 A：跨模型度量模板库

### A.1 架构审计度量 Prompt（跨模型通用）

```markdown
# 架构审计任务
## 角色：10 年经验软件架构师，专精 AI 项目架构合规。
## 输入：{project_root} / {architecture_spec} / {component_types}
## 检查清单（按顺序）：
1. 阶段边界契约：每阶段文件存在？输出字段赋值 ${ctx}？下游正确读取？
2. 组件类型传播：桥接模块存在？stamp 逻辑？路由器分类函数？
3. 模块路由完整性：${component} 是否各有 recon/strike/assess/report 对应？
4. 元数据连续性：评分管道读取 component_type？证据收集保留 metadata？
## 输出格式：
[阶段边界契约] [PASS/FAIL] 描述
[组件类型传播] [PASS/FAIL] 描述
[模块路由完整性] [PASS/FAIL] 描述
[元数据连续性] [PASS/FAIL] 描述
总结: PASS={n} / WARNING={n} / BLOCKING={n}
```

### A.2 组件审计度量 Prompt

```markdown
# 组件审计任务
## 角色：AI 编程质量审计专家。
## 输入：{project_root} / {core_components} / {extended_components} / {min_seeds}
## 检查（Phase 1→6）：基线扫描 / 纯净度(AST) / 覆盖 / Scorer-Report 覆盖 / 种子清单 / 验证门禁
## 输出：每 Phase 含 [PASS]/[FAIL]/[WARN] + 问题汇总 + 修复建议
```

### A.3 依赖审计度量 Prompt

```markdown
# 依赖审计任务
## 1. 导入合规：扫描 import，检测禁用品/跨层
## 2. 版本锁定：读 lock 文件 vs 实际安装
## 3. 循环依赖：构建依赖图检测环
## 4. 废弃 API：扫描已知废弃用法，给替代方案
```

---

## 附录 B：排错速查

| 问题 | 原因 | 修复 |
|------|------|------|
| R-SIZE BLOCKING | 文件>1500 行 | 拆分 |
| R-IMPORT BLOCKING | 跨层导入 | 重构为单向依赖 |
| R-TOOLS BLOCKING | CLI 位置错 | 迁到 tools/ |
| R-DATA BLOCKING | 数据流断裂 | 补 ${ctx} 字段 |
| R-DRIFT WARNING | 规范-代码不同步 | 更新规范或代码 |
| Purity WARNING | 组件污染 | 移除跨组件代码 |
| 审计超时 | 文件多/网络 | 增超时/跳网络阶段 |
| CI 耗时过长 | 全量检查 | 增量/并行 |

---

## 附录 C：触发词完整映射表

| 触发词 | 审计类型 | 执行命令（占位符） | 适用场景 |
|--------|---------|-------------------|---------|
| 架构审计 | Architecture | `${GUARD_CMD}` + `${ARCHCHECK_CMD}` | 模块边界/契约 |
| 组件审计 | Component | `${AUDIT_COMPONENT_CMD}` | 完整性/覆盖 |
| 依赖审计 | Dependency | `${GUARD_CMD}` (R-IMPORT) | 导入合规 |
| 数据审计 | Data | `${DATAFLOW_CMD}` | 全链路数据流 |
| 漂移审计 | Drift | `${DRIFT_CMD}` | 规范同步 |
| 开发全审 | Dev Full | `${AUDIT_FULL_CMD}` | A→H 全流水线 |
| 纯净审计 | Purity | `${GUARD_CMD} --component-purity` | 纯净度 |
| 门禁检查 | Gate | `${GUARD_CMD}` | 静态规则 |
| 快速检查 | Quick | `${GUARD_CMD} --quick-all` | 提交前 |
| 单文件 | Single | `${GUARD_CMD} --quick ${file}` | 单文件 |
| 实时监视 | Watch | `${WATCH_CMD}` | 开发时 |

---

## 附录 D：规范 CHANGELOG

| 版本 | 日期 | 变更 |
|------|------|------|
| v2.0 | 2026-09-12 | 重命名成熟度模型为 A0–A5；统一 κ/r 口径；补 L5 达标清单；去项目耦合；OS 通用化 |
| v1.0 | 2026-09-11 | 初始版本（基于 pyrit-mini 实践） |

---

## 附录 E：失败案例库

| # | 案例 | 根因 | 预防 |
|---|------|------|------|
| 1 | 阶段边界契约断裂 | 重构遗漏字段传递 | 重构后必跑架构审计 |
| 2 | 组件类型传播失败 | 桥接未调用 | 新增模块必集成桥接 |
| 3 | 纯净度污染 | AI 混入不相关技术 | 生成后必跑纯净度 |
| 4 | 跨层导入 | 违反依赖方向 | 高→低经 ${ctx} 传递 |
| 5 | 版本漂移 | 未锁版本 | 锁版本 + 定期检测 |
| 6 | 跨模型重大分歧 | 规格歧义 | κ<0.4 强制人工仲裁 |

---

*文档版本：v2.0 | 创建：2026-09-12 | 本文档为验证与度量单一事实源；规范与流程见 `ai-dev-guides.md`。复制至新项目替换 `${...}` 占位符即可运行。*
