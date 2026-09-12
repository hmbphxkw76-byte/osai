# 60-CROSS-MODEL-VERIFICATION: 跨模型规约审查协议 v1.0

> **STATUS: ACTIVE** — 本文档定义 specs/ 规约文档的跨模型交叉确认标准流程
> **文档层级**：L4 配套协议（护栏唯一定义见 `40-GUARDRAILS.md` 1I-CROSS；任务协议见 `30-TASKS.md` 第十章）
> **版本**：v1.0（2026-09-09）
> **版本史**：`git log -- docs/specs/60-CROSS-MODEL-VERIFICATION.md`

> **职责边界**（防三处重复）：本文件**只定义审查协议**（模型池 / Prompt 模板 / Schema / 存储结构）。
> 触发条件与 κ 阈值的**强制力**来自 `40-GUARDRAILS.md` 1I-CROSS；任务生命周期来自 `30-TASKS.md` 第十章。
> 三处数值必须一致；发现不一致即登记 backlog，**不得就地改两处**。

---

## 1. 目的与定位

### 1.1 核心问题

单模型 AI 的规约审查存在系统性偏差：

| 偏差类型 | 表现 | 风险等级 |
|---------|------|---------|
| 模型风格偏好 | Claude 偏保守（安全边界重），GPT 偏激进（功能完备重） | WARNING |
| 幻觉模式 | 虚构不存在的规则编号/护栏名称 | BLOCKING |
| 术语偏好 | 中英文混用、同义词不一致 | WARNING |
| 深度偏差 | 小模型漏检深层不变量，大模型过度设计 | INFO |

### 1.2 协议目标

```
单模型说"OK" ≠ 真正的"OK"
三方一致 + κ ≥ 0.8 + 人工兜底 = 生产级规约质量
```

---

## 2. 审查模型注册簿

### 2.1 模型池配置

| 模型 ID | 提供商 | 角色 | 审查侧重 | 优先级 |
|---------|--------|------|---------|--------|
| claude-3-5-sonnet | Anthropic | 主审查 | 安全边界、红线判定、架构不变量 | 1 |
| gpt-4o | OpenAI | 副审查 | 架构一致性、需求覆盖、跨文档引用 | 2 |
| glm-4 / longcat | 智谱/美团 | 第三审查 | 中文语境、术语统一、本土合规 | 3 |
| deepseek-v2 | DeepSeek | 仲裁 | 低成本快速仲裁、分歧初筛 | 4 |

### 2.2 模型轮换规则

- 每季度评估模型池是否需要更换/新增
- 同一模型连续 3 次审查结果完全一致 → 告警（可能退化或死代码）
- 模型不可用时自动降级到下一优先级

---

## 3. 审查触发规则

### 3.1 变更分级

| 变更类型 | 阈值 | 审查级别 | 最低模型数 |
|---------|------|---------|-----------|
| L0 宪法任何变更 | 任意行 | FULL | 3 |
| L1 蓝图章节新增/删除 | 任意行 | FULL | 3 |
| L2 需求新增/修改 | 任意行 | FULL | 3 |
| L4 护栏新增/修改 | 任意行 | FULL | 3 |
| 版本号升级 | 任意 | FULL | 3 |
| 单文件 docstring/注释 | < 10 行 | LIGHT | 1 |
| 单文件内容变更 | 10-50 行 | STANDARD | 2 |
| 多文件变更 | 任意 | FULL | 3 |

### 3.2 触发条件判定流程

```
变更提交
    ↓
变更规模评估（行数 × 文件数 × 触及层级）
    ↓
    ├─ < 5 行非实质性变更 → LIGHT（1 模型）
    ├─ 5-50 行单文件 → STANDARD（2 模型）
    └─ > 50 行 / 多文件 / L0-L4 核心 → FULL（3 模型）
```

---

## 4. 审查执行协议

### 4.1 Phase 1: 独立审查（并行）

每个模型执行统一 Prompt，输出标准 JSON Schema。

**统一 Prompt 模板**:

```markdown
你是 AI 规约审计专家。审查以下规约文档。

## 审查范围
{file_list}

## 审查维度（逐项执行）

### D1-Structure（结构完整性）
- 章节编号连续无跳号
- 目录索引与实际章节匹配
- 文末版本记录包含当前版本

### D2-SSOT（单一来源验证）
- 检查 ctx 字段是否在多处重复声明（应以 ARCHITECTURE 4.4 为准）
- 检查 R-* 规则是否在多处定义（应以 GUARDRAILS 1F 为准）
- 检查 REQ-* 是否多处登记（应以 REQUIREMENTS 为准）

### D3-Terminology（术语统一）
- 中英文术语使用一致
- 同义词不混用
- 缩写首次出现有全称

### D4-Reference（引用有效性）
- 文件路径存在（相对路径可解析）
- 章节锚点存在（#xxx 跳转可达）
- README 索引版本号匹配

### D5-Executable（可执行性）
- 每条 R-* 有对应检查器函数
- 检查器在与项目约定的检查器文件中
- 检查器函数名与登记簿一致

### D6-CrossDoc（跨文档一致性）
- 宪法条款与护栏对应
- 蓝图不变量在护栏中有保护
- 需求验收标准可被测试验证

### D7-Version（版本对齐）
- 文件头版本 == 文末最新版 == README 索引版

## 输出格式（严格 JSON）

{
  "model": "YOUR_MODEL_NAME",
  "schema_version": "1.0",
  "review_timestamp": "ISO8601",
  "scope": ["list", "of", "files"],
  "findings": [
    {
      "id": "F-001",
      "dimension": "SSOT|structure|terminology|reference|executable|cross_doc|version",
      "severity": "BLOCKING|WARNING|INFO",
      "location": "file:line",
      "description": "具体问题",
      "suggestion": "修复建议",
      "confidence": 0.0-1.0,
      "model_specific_risk": "此判断是否可能是模型偏差（true/false）"
    }
  ],
  "consistency_check": {
    "cross_ref_validated": true|false,
    "version_aligned": true|false,
    "ssot_no_duplicate": true|false
  },
  "summary": {
    "total_findings": N,
    "by_severity": {"BLOCKING": N, "WARNING": N, "INFO": N}
  }
}
```

### 4.2 Phase 2: 差异对齐

**算法逻辑**:

```python
def align_reviews(reviews: list[dict]) -> dict:
    """
    输入: 多模型审查报告列表
    输出: 对齐后的差异分析
    """
    all_findings = union_all_findings(reviews)

    aligned = {
        "confirmed": [],  # ≥2 模型发现
        "single_model": [],  # 仅 1 模型发现
        "disputed": [],  # 模型判定分歧
    }

    for finding in all_findings:
        found_by = [m for m in reviews if finding in m.findings]

        if len(found_by) >= 2:
            aligned["confirmed"].append(
                {"finding": finding, "confirmed_by": [m.model for m in found_by], "status": "auto_accept"}
            )
        elif severity_disagreement(found_by):
            aligned["disputed"].append({"finding": finding, "disagreements": [(m.model, m.severity) for m in found_by]})
        else:
            aligned["single_model"].append(
                {"finding": finding, "found_by": found_by[0].model, "status": "needs_arbitration"}
            )

    # 一致性统计
    kappa = fleiss_kappa(reviews)

    return {
        "aligned_findings": aligned,
        "consistency": {
            "overall_kappa": kappa,
            "agreement_rate": len(aligned["confirmed"]) / len(all_findings),
            "needs_arbitration": len(aligned["disputed"]) + len(aligned["single_model"]),
        },
    }
```

### 4.3 Phase 3: 分级裁决

| κ 范围 | 一致性级别 | 自动动作 |
|--------|-----------|---------|
| ≥ 0.8 | HIGH | 直接采纳 confirmed findings |
| 0.6-0.79 | MEDIUM | confirmed 采纳，single-model 标记待人工 |
| 0.4-0.59 | LOW | 全部 findings 进入仲裁 |
| < 0.4 | CRITICAL | 触发完整人工审查 |

**仲裁协议**:

| 场景 | 仲裁方式 | 输出 |
|------|---------|------|
| 2/3 一致 | 多数票自动采纳 | 自动修复或标记 |
| 三方 severity 分歧 | 取保守级别 | WARNING 升 BLOCKING |
| 三方完全不同 | 第四模型介入 | deepseek-v2 投票 |
| 涉及 L0/L4 变更 | 人工终审 | 人工审批记录 |

---

## 5. 输出 Schema 标准

### 5.1 审查报告 Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["model", "schema_version", "review_timestamp", "scope", "findings"],
  "properties": {
    "model": {"type": "string", "enum": ["claude-3-5-sonnet", "gpt-4o", "glm-4", "longcat", "deepseek-v2"]},
    "schema_version": {"type": "string", "pattern": "^\\d+\\.\\d+$"},
    "review_timestamp": {"type": "string", "format": "date-time"},
    "scope": {"type": "array", "items": {"type": "string"}},
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "dimension", "severity", "location", "description"],
        "properties": {
          "id": {"type": "string", "pattern": "^F-\\d{3}$"},
          "dimension": {"type": "string", "enum": ["SSOT", "structure", "terminology", "reference", "executable", "cross_doc", "version"]},
          "severity": {"type": "string", "enum": ["BLOCKING", "WARNING", "INFO"]},
          "location": {"type": "string", "pattern": "^[\\w/.-]+:\\d+$"},
          "description": {"type": "string", "maxLength": 500},
          "suggestion": {"type": "string", "maxLength": 500},
          "confidence": {"type": "number", "minimum": 0, "maximum": 1},
          "model_specific_risk": {"type": "boolean"}
        }
      }
    },
    "consistency_check": {
      "type": "object",
      "properties": {
        "cross_ref_validated": {"type": "boolean"},
        "version_aligned": {"type": "boolean"},
        "ssot_no_duplicate": {"type": "boolean"}
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "total_findings": {"type": "integer"},
        "by_severity": {
          "type": "object",
          "properties": {
            "BLOCKING": {"type": "integer"},
            "WARNING": {"type": "integer"},
            "INFO": {"type": "integer"}
          }
        }
      }
    }
  }
}
```

### 5.2 对齐结果 Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "aligned_findings": {
      "type": "object",
      "properties": {
        "confirmed": {"type": "array"},
        "single_model": {"type": "array"},
        "disputed": {"type": "array"}
      }
    },
    "consistency": {
      "type": "object",
      "properties": {
        "overall_kappa": {"type": "number", "minimum": -1, "maximum": 1},
        "pairwise_kappa": {"type": "object"},
        "agreement_rate": {"type": "number"},
        "needs_arbitration": {"type": "integer"}
      }
    }
  }
}
```

---

## 6. 审查记录存储

### 6.1 目录结构

```
outputs/cross_model_review/
└── {YYYYMMDD}-{change_id}/
    ├── trigger.md          # 触发变更说明
    ├── raw/                # 原始审查报告
    │   ├── claude.json
    │   ├── gpt4o.json
    │   └── glm4.json
    ├── aligned/            # 对齐结果
    │   ├── diff.json
    │   └── kappa.json
    ├── adjudication/       # 仲裁记录
    │   └── decision.json
    └── summary.md          # 人类可读摘要
```

### 6.2 存储规则

- 审查记录永久保留，用于 κ 趋势分析
- 每次审查生成唯一 change_id（基于 commit hash）
- summary.md 包含人类可读的修复清单

---

## 7. 一致性度量指标

### 7.1 核心指标

| 指标 | 计算方式 | 目标 |
|------|---------|------|
| Pairwise κ | 每对模型的 Cohen's Kappa | ≥ 0.75 |
| Overall κ | Fleiss' Kappa（多模型） | ≥ 0.80 |
| Agreement Rate | 一致发现数 / 总发现数 | ≥ 0.85 |
| Single-model 漏检率 | 仅单模型发现 / 总发现数 | ≤ 0.15 |
| 仲裁率 | 需仲裁数 / 总发现数 | ≤ 0.10 |
| 人工介入率 | 需人工 / 总发现数 | ≤ 0.05 |

### 7.2 κ 解读标准

| κ 范围 | 解读 | 动作 |
|--------|------|------|
| < 0.40 | Poor（严重不一致） | 触发人工审查 |
| 0.40-0.59 | Moderate | 第三模型仲裁 |
| 0.60-0.79 | Substantial | 仲裁 single-model findings |
| 0.80-1.00 | Almost Perfect | 直接采纳 |

---

## 8. 已知模型偏差模式库

### 8.1 偏差登记格式

```markdown
## MB-001: Claude 安全过度判定

**模型**: Claude 3.5
**现象**: 对非安全相关的架构护栏判定为 BLOCKING
**示例**: 将"文档术语建议"判定为"BLOCKING — 安全红线"
**缓解**: 人工复核时降级为 INFO

## MB-002: GPT 功能遗漏

**模型**: GPT-4o
**现象**: 对新增需求覆盖审查不敏感
**示例**: 需求新增但未对应任务，GPT 未检出
**缓解**: 强制交叉检查需求↔任务引用链
```

### 8.2 偏差库维护

- 每次审查发现的模型特异性判断登记入库
- 每季度 review 偏差库，过时条目归档
- 偏差库纳入审查 Prompt 作为 few-shot 示例

---

## 9. 工具链集成

### 9.1 Git Hooks 集成

```bash
# pre-commit hook 新增检查
# 如果 L0-L4 文档变更但无 cross_model_review 记录 → BLOCKING

if git diff --name-only | grep -E "^docs/specs/[0-9]+-"; then
    # 检查是否有审查记录
    if ! grep -q "cross_model_review:" outputs/cross_model_review/latest/summary.md 2>/dev/null; then
        echo "BLOCKING: 规约变更未执行跨模型审查"
        exit 1
    fi
fi
```

### 9.2 Guard 检查器

新增检查器（注册于 40-GUARDRAILS 1I 登记簿）:

- `check_cross_model_review()`: 验证变更已通过跨模型审查
- `check_review_schema()`: 验证审查报告 JSON Schema 合规
- `check_adjudication_record()`: 验证仲裁记录完整
- `check_review_model_pool()`: 验证审查模型池健康（≥2 可用）
- `check_review_freshness()`: 验证审查时效（< 90 天）

---

## 10. 与其他规约的关系

### 10.1 协议栈定位

```
00-CONSTITUTION  C14（跨模型优先）
        ↓
10-ARCHITECTURE  第十二章（审查架构）
        ↓
20-REQUIREMENTS  REQ-138~140（功能需求）
        ↓
30-TASKS         第十章（执行协议）
        ↓
40-GUARDRAILS    1I 登记簿 + R-CROSS-1~5（护栏）
        ↓
60-CROSS-MODEL-VERIFICATION（本协议）
        ↓
templates/cross-model-review.md（报告模板）
```

### 10.2 交叉引用矩阵

| 本文档引用 | 被引用位置 |
|-----------|-----------|
| 2.1 模型池 | 40-GUARDRAILS 1I 登记簿 |
| 3.1 触发规则 | 30-TASKS 第十章 10.1 |
| 4.2 Phase 2 | 30-TASKS 第十章 10.2 |
| 7 度量指标 | 50-ROADMAP.md 阶段 1D 退出条件 |
| 9.2 检查器 | tools/guard.py |

---

## 11. 版本记录

| 版本 | 日期 | 变更 | 批准 |
|------|------|------|------|
| v1.0 | 2026-09-09 | 初始版本：触发规则 / Prompt模板 / 差异对齐 / 仲裁协议 / Schema / 存储 | 用户会话批准 |

---

## 附录 A: 快速参考卡

```
┌─────────────────────────────────────────────────────────┐
│           跨模型审查快速决策                              │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  变更规模?                                               │
│  ├─ < 5 行纯注释 → 跳过（可选 1 模型 LIGHT）            │
│  ├─ 5-50 行 → STANDARD（2 模型）                        │
│  └─ > 50 行 / L0-L4 → FULL（3 模型）                    │
│                                                         │
│  κ 值?                                                   │
│  ├─ ≥ 0.80 → 直接采纳                                   │
│  ├─ 0.60-0.79 → 仲裁 single-model                       │
│  ├─ 0.40-0.59 → 第三模型仲裁                            │
│  └─ < 0.40 → 人工审查                                   │
│                                                         │
│  确定性?                                                 │
│  ├─ ≥ 2 模型一致 → 自动采纳                             │
│  ├─ 仅 1 模型 → 标记待人工                              │
│  └─ 三方分歧 → 保守升级                                 │
│                                                         │
└─────────────────────────────────────────────────────────┘
```
