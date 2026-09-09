# 跨模型审查报告

> **审查 ID**: CMR-{YYYYMMDD}-{N}
> **触发变更**: {commit hash / change description}
> **审查级别**: LIGHT | STANDARD | FULL
> **审查模型**: {model_list}
> **审查时间**: {ISO8601 timestamp}

---

## 1. 原始报告摘要

| 模型 | BLOCKING | WARNING | INFO | 总数 | 耗时 |
|------|----------|---------|------|------|------|
| {model_a} | N | N | N | N | Ns |
| {model_b} | N | N | N | N | Ns |
| {model_c} | N | N | N | N | Ns |

---

## 2. 差异对齐结果

### 2.1 确认的问题（≥2 模型一致）

| # | 维度 | 严重性 | 位置 | 描述 | 确认模型 | 采纳 |
|---|------|--------|------|------|---------|------|
| F-001 | SSOT | WARNING | 10-ARCHITECTURE.md:45 | ctx 字段重复登记 | claude, gpt4o | ✅ |

### 2.2 单模型发现（需人工确认）

| # | 模型 | 维度 | 严重性 | 位置 | 描述 | 裁决 |
|---|------|------|--------|------|------|------|
| F-002 | claude | terminology | INFO | 40-GUARDRAILS.md:100 | 术语建议 | ⚠️ 待决 |

### 2.3 分歧项（模型判定不同）

| # | 问题 | claude | gpt4o | glm4 | 仲裁结果 |
|---|------|--------|-------|------|---------|------|
| F-003 | 护栏严度 | WARNING | INFO | WARNING | ⚠️ 升 WARNING |

---

## 3. 一致性指标

| 指标 | 值 | 目标 | 状态 |
|------|-----|------|------|
| Pairwise κ (A vs B) | 0.85 | ≥ 0.75 | ✅ |
| Pairwise κ (A vs C) | 0.78 | ≥ 0.75 | ✅ |
| Pairwise κ (B vs C) | 0.81 | ≥ 0.75 | ✅ |
| Overall κ (Fleiss) | 0.81 | ≥ 0.80 | ✅ |
| Agreement Rate | 87% | ≥ 85% | ✅ |
| 仲裁率 | 5% | ≤ 10% | ✅ |
| 人工介入率 | 2% | ≤ 5% | ✅ |

---

## 4. 修复清单

- [ ] F-001: 修复 ctx 字段重复登记问题
- [ ] F-003: 升级护栏严度判定

---

## 5. 签名

| 角色 | 模型/人员 | 时间 | 签名 |
|------|----------|------|------|
| 审查执行 | claude-3.5, gpt-4o, glm-4 | {timestamp} | — |
| 差异对齐 | automated | {timestamp} | — |
| 仲裁决策 | {model_or_human} | {timestamp} | — |
| 最终确认 | human | {timestamp} | — |

---

## 6. 附件

- `raw/claude.json` — Claude 原始报告
- `raw/gpt4o.json` — GPT-4o 原始报告
- `raw/glm4.json` — GLM-4 原始报告
- `aligned/diff.json` — 差异对齐结果
- `aligned/kappa.json` — κ 计算详情
- `adjudication/decision.json` — 仲裁记录
