# 45-DATA-FLOW-INTEGRITY: ASR 中心数据流完整性规约 v2.0

> **版本**: v2.0 (2026-09-09)
> **作者**: AI Red Team Architecture
> **效力**: 强制 — 所有模块修改必须通过数据流完整性验证
> **STATUS: ARCHIVED** — 本文档已合并入 [10-ARCHITECTURE.md 第四章](10-ARCHITECTURE.md)，不再独立维护（v2.3 / REV-13 合并，用户会话批准）。**权威规约以 10-ARCHITECTURE.md 第四章为准**；验证工具链（`tools/data_flow_validator.py` + `tools/data_flow_hooks.py` + `tests/test_data_flow_integrity.py`，29 项测试）仍正常运行。本文件仅作历史归档保留，其内容与 10-ARCHITECTURE.md 第四章冲突时以后者为准。

## 1. 数据流架构概述

### 1.1 主攻击链拓扑

```
Recon ──→ ARM ──→ Strike ──→ Assess ──→ Report/Evidence
  │         │         │          │            │
  │         │         │          │            ├─ EvidenceCollection
  │         │         │          │            ├─ ASR Forensic Report
  │         │         │          │            └─ OWASP/ATLAS Mapping
  │         │         │          │
  │         │         │          ├─ asr_per_technique
  │         │         │          ├─ overall_asr
  │         │         │          ├─ dual_judge_stats
  │         │         │          └─ wilson_ci
  │         │         │
  │         │         ├─ attack_results
  │         │         ├─ successful_evidence_log  ← WHY success
  │         │         ├─ refusal_classification_log ← WHY refused
  │         │         ├─ guardrail_triggers       ← WHAT triggered
  │         │         └─ timing_metadata          ← WHEN response
  │         │
  │         ├─ seeds
  │         ├─ techniques
  │         └─ converter_map
  │
  ├─ service_profile
  ├─ target_fingerprint
  └─ mcpsec_surface/scan_results
```

### 1.2 核心原则

| 原则 | 说明 |
|------|------|
| **ASR 中心性** | 所有 PipelineContext 字段必须直接服务于攻击成功率分析 |
| **Why > What** | 不仅追踪"成功了多少"，更要追踪"为什么成功/失败" |
| **SSOT** | 每个数据字段有且仅有一个写入者、一个权威来源 |
| **契约化** | 阶段间数据传递通过字段契约验证 |
| **失败显式化** | 数据缺失必须明确报错，禁止静默忽略 |

## 2. ASR 取证数据流（Why-Success Data）

### 2.1 设计哲学

传统红队工具只回答 **"ASR = 50%"**。本架构额外回答：

- **为什么成功？** → `successful_evidence_log`（哪个 prompt + 哪个 converter 绕过了防御）
- **为什么被拒？** → `refusal_classification_log`（guardrail/content_policy/format 哪类拒绝）
- **什么触发了护栏？** → `guardrail_triggers`（精确到 token 级别的归因）
- **响应时序特征？** → `timing_metadata`（时序侧信道分析）

### 2.2 取证数据字段契约

| 字段名 | 类型 | 写入阶段 | 消费阶段 | ASR 价值 |
|--------|------|----------|----------|----------|
| `successful_evidence_log` | `list[dict]` | Strike | Assess/Report | 复现成功攻击路径 |
| `refusal_classification_log` | `list[dict]` | Strike | ARM(下一轮) | 指导绕过策略选择 |
| `guardrail_triggers` | `list[dict]` | Strike | Report | 精确定位护栏规则 |
| `timing_metadata` | `list[dict]` | Strike | Assess | 时序异常检测 |

### 2.3 数据结构定义

```python
# 成功攻击取证证据
successful_evidence_log: list[dict] = [
    {
        "technique": str,           # 攻击技术名称
        "converter_chain": str,     # 使用的 converter 链
        "prompt_snippet": str,      # 攻击 prompt 片段（截断）
        "response_snippet": str,    # 成功响应片段（截断）
        "timestamp": float,         # 时间戳
    }
]

# 拒绝分类记录
refusal_classification_log: list[dict] = [
    {
        "technique": str,
        "converter_chain": str,
        "refusal_type": "guardrail" | "content_policy" | "format" | "unknown",
        "matched_pattern": str,     # 匹配到的拒绝模式
        "confidence": float,        # 分类置信度 0-1
        "response_snippet": str,    # 拒绝响应片段
    }
]

# 护栏触发归因
guardrail_triggers: list[dict] = [
    {
        "technique": str,
        "converter_chain": str,
        "trigger_token": str,       # 触发护栏的 token
        "rule_name": str,           # 规则名称
        "confidence": float,
        "context_snippet": str,     # 上下文片段
    }
]

# 时序元数据
timing_metadata: list[dict] = [
    {
        "technique": str,
        "converter_chain": str,
        "request_time": float,      # 请求时间戳
        "response_time": float,     # 响应时间戳
        "total_ms": float,          # 总耗时（毫秒）
    }
]
```

## 3. 数据传递规则

### 3.1 强制规则（R-DATA-1 ~ R-DATA-19）

| 规则ID | 名称 | 源阶段 | 目标阶段 | 字段 | 检查类型 |
|--------|------|--------|----------|------|----------|
| T001 | Recon→ARM service_profile | recon | arm | service_profile_size | positive_count |
| T002 | Recon→ARM target_fingerprint | recon | arm | has_target_fingerprint | exists |
| T003 | Recon→ARM mcpsec_surface | recon | arm | mcpsec_surface_tools_count | exists_optional |
| T004 | ARM→Strike seeds | arm | strike | seeds_count | positive_count |
| T005 | ARM→Strike techniques | arm | strike | techniques_count | positive_count |
| T006 | ARM→Strike converter_map | arm | strike | converter_map_total_converters | positive_count |
| T007 | Strike→Assess attack_results | strike | assess | attack_results_total | positive_count |
| T008 | Strike→Assess 技术覆盖 | strike | assess | attack_results_keys | exists_and_not_empty |
| T009 | Assess→Report asr_per_technique | assess | report | asr_techniques_count | positive_count |
| T010 | Assess→Report overall_asr | assess | report | overall_asr | exists_and_valid_range |
| T011 | Assess→Report dual_judge_stats | assess | report | dual_judge_total_scored | positive_count |
| T012 | Assess→Report wilson_ci | assess | report | wilson_ci | valid_ci |
| T013 | Recon→ARM mcpsec_surface | recon | arm | mcpsec_surface_tools_count | exists_optional |
| T014 | Recon→ARM mcpsec_scan_results | recon | arm | mcpsec_vulnerabilities_count | exists_optional |
| **T015** | **Strike→Report successful_evidence** | **strike** | **report** | **successful_evidence_count** | **exists_optional** |
| **T016** | **Strike→Report refusal 分类** | **strike** | **report** | **refusal_classification_count** | **exists_optional** |
| **T017** | **Strike→Report guardrail 触发** | **strike** | **report** | **guardrail_triggers_count** | **exists_optional** |
| **T018** | **Strike→Report 时序元数据** | **strike** | **report** | **timing_metadata_count** | **exists_optional** |
| **T019** | **Strike→Report 拒绝类型多样性** | **strike** | **report** | **refusal_types_count** | **exists_optional** |

### 3.2 一致性规则

| 规则ID | 名称 | 说明 |
|--------|------|------|
| CONS-001 | 攻击技术 ASR 覆盖一致性 | asr_per_technique 必须覆盖 attack_results 中所有技术 |
| CONS-002 | 审计日志阶段完整性 | orchestration_log 必须包含所有 5 个阶段 |
| CONS-003 | 评判统计完整性 | dual_judge_stats 和 wilson_ci 必须同时存在 |
| CONS-004 | 技术→Converter 覆盖 | converter_map 必须覆盖所有 techniques |
| CONS-005 | 技术→攻击结果覆盖 | attack_results 必须覆盖所有 techniques |

## 4. 非 ASR 数据清理规约

### 4.1 已从 PipelineContext 移除的字段

| 字段 | 原因 | 替代存储 |
|------|------|----------|
| `_playwright_instance` | 操作资源句柄，非攻击数据 | `recon/_target_router_helpers._playwright_handles` |
| `_browser` | 操作资源句柄，非攻击数据 | `recon/_target_router_helpers._playwright_handles` |
| `_browser_context` | 操作资源句柄，非攻击数据 | `recon/_target_router_helpers._playwright_handles` |
| `_whitebox_confirmed` | 死代码，从未被消费 | 已删除 |

### 4.2 ASR 中心性判定标准

一个字段属于 PipelineContext 当且仅当：

1. **直接服务于攻击执行**：影响攻击 payload 生成、技术选择、converter 链构建
2. **直接服务于攻击评估**：用于计算 ASR、分类拒绝、归因护栏触发
3. **直接服务于攻击优化**：用于下一轮攻击的种子/技术/参数调整

**不属于** PipelineContext 的数据：
- 操作资源句柄（浏览器实例、HTTP 连接池）
- 调试/日志基础设施
- 与攻击成功率无关的元数据

## 5. 取证数据提取流程

### 5.1 数据流

```
PyRIT AttackResult[]
    ↓
strike/asr_forensics.py::extract_asr_forensics()
    ↓
dict{successful_evidence, refusals, guardrail_triggers, timing}
    ↓
strike/asr_forensics.py::apply_forensics_to_ctx(ctx, ...)
    ↓
ctx.successful_evidence_log      ← 成功攻击的 prompt/response 片段
ctx.refusal_classification_log   ← 拒绝类型分类（guardrail/content_policy/format）
ctx.guardrail_triggers           ← 触发护栏的精确 token + 规则名
ctx.timing_metadata              ← 请求/响应时间戳
```

### 5.2 拒绝分类器

| 拒绝类型 | 匹配模式示例 | 后续策略 |
|----------|-------------|----------|
| `guardrail` | "i cannot", "unable to help", "against policy" | 尝试角色扮演/编码绕过 |
| `content_policy` | "harmful", "inappropriate", "illegal" | 尝试语义混淆/间接表达 |
| `format` | "please rephrase", "unclear", "invalid input" | 调整 prompt 格式/结构 |
| `unknown` | 短响应/无明确模式 | 增加探测轮次 |

### 5.3 学术依据

- **Greshake et al. (arXiv:2302.12173)** — 知识投毒攻击的响应分析
- **PyRIT (arXiv:2407.01232)** — AttackResult 取证提取
- **Perez et al. (arXiv:2202.03286)** — 角色扮演攻击的拒绝模式分类
- **Chowdhury et al. (arXiv:2404.01833)** — Crescendo 攻击的渐进式探测

## 6. 工具链与自动化

### 6.1 验证工具

| 工具 | 命令 | 用途 |
|------|------|------|
| DataFlowValidator | `py -m tools.data_flow_validator` | 全链路数据流验证 |
| DataFlow Hooks | `py -m tools.data_flow_hooks` | 流水线集成钩子 |
| Git Hooks | `py -m tools.install_hooks_local` | pre-commit/pre-push 自动验证 |

### 6.2 调用方式

```bash
# 手动运行验证
py tools/data_flow_validator.py              # 演示模式
py -m pytest tests/test_data_flow_integrity.py -v  # pytest

# 自动 git hook (已安装)
# 每次 git commit / push 自动触发

# pipeline 集成
from tools.data_flow_hooks import snapshot_hook, validate_and_report
```

## 7. Git Hooks 集成

### 7.1 pre-commit 流程

```
git commit → pre-commit hook → data_flow_validator → architecture_guard
                                    ↓                          ↓
                              数据流完整性检查            架构合规检查
                                    ↓                          ↓
                              BLOCKING → 阻断 commit      BLOCKING → 阻断 commit
```

### 7.2 pre-push 流程

```
git push → pre-push hook → data_flow_validator → architecture_guard → pytest
                                                ↓
                                          全量数据流测试 (50+ 用例)
```

## 8. 流水线集成 API

### 8.1 DataFlowValidator

```python
from tools.data_flow_validator import DataFlowValidator

validator = DataFlowValidator(ctx)
validator.snapshot("post_recon")      # Recon 完成后
validator.snapshot("post_arm")        # ARM 完成后
validator.snapshot("post_strike")     # Strike 完成后
validator.snapshot("post_assess")     # Assess 完成后
validator.snapshot("post_report")     # Report 完成后
report = validator.validate_all()     # 执行全量验证
assert report.is_valid                # 断言无数据流断点
```

### 8.2 ASR Forensics

```python
from strike.asr_forensics import apply_forensics_to_ctx

# 在 Strike 阶段末尾调用
apply_forensics_to_ctx(ctx, attack_results, converter_map=converter_map)
```

## 9. 模块修改检查清单

修改任何模块时，必须确认：

- [ ] 新增字段直接服务于 ASR 分析（参考 4.2 判定标准）
- [ ] 字段有明确的写入阶段和消费阶段
- [ ] 数据传递规则已更新（如新增跨阶段字段）
- [ ] DataFlowValidator 已更新字段提取逻辑
- [ ] 测试用例已覆盖新字段
- [ ] `py -m pytest tests/test_data_flow_integrity.py` 全部通过
- [ ] `py -m tools.guard` 0 BLOCKING

## 10. 版本记录

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-09-08 | 初始版本：5 阶段数据流规约 |
| v2.0 | 2026-09-09 | 新增 ASR 取证数据流（Why-Success）：successful_evidence_log, refusal_classification_log, guardrail_triggers, timing_metadata；清理非 ASR 字段（playwright handles, _whitebox_confirmed） |
