---
name: pyrit-strike-dev-rules
description: AI assistant development rules for pyrit-red team pipeline. Use when writing, editing, reviewing, or running code. 权威源：specs/00-CONSTITUTION.md
---

# PyRIT-Strike Development Rules (AI Assistant Guide)

> **MANDATORY** — All rules MUST be followed on every code change.
> **权威源声明**：本文件为 ⑤ 护栏细则层，与 `specs/` 金字塔冲突处以金字塔为准。
> 唯一权威源见 `specs/00-CONSTITUTION.md` 第二章裁决序。

## Quick Reference

| 权威源 | 内容 |
|--------|------|
| `specs/00-CONSTITUTION.md` | 宪法、架构规则 R-H1/H2/H3、红线护栏 R-L1~L8 |
| `specs/10-ARCHITECTURE.md` | 架构规格、模块目录、依赖拓扑 |
| `specs/20-REQUIREMENTS.md` | 需求规格 P0/P1/P2 |
| `specs/30-TASKS.md` | 任务执行协议、生命周期 |
| `specs/40-GUARDRAILS.md` | 护栏登记簿 v1.2 |

## Core Rules (10 Rules)

### R1: Offensive Attacker Mindset
- **MUST**: Escalate when single-turn ASR < 90%
- **MUST NOT**: Add safety guardrails on attacker side
- **Reference**: `docs/specs/20-REQUIREMENTS.md` P0-1

### R2: PyRIT Native First
- **MUST**: Search PyRIT source before writing new class
- **MUST NOT**: Build parallel implementation of PyRIT native
- **Reference**: `docs/specs/00-CONSTITUTION.md` 7B映射表

### R3: ruff + pytest + guard
- **MANDATORY gates**: `ruff check` + `pytest` + `architecture_guard.py`
- **Pre-commit**: Install with `python core/setup_hooks.py`

### R4: L5 Standard Alignment
- **MUST**: All parameters read from `config/defaults.yaml`
- **Reference**: `config/defaults.yaml`

### R5: arXiv-First Grounding
- **MUST**: Every technique has arXiv citation
- **MUST NOT**: Technique without academic reference

### R6: AI Red Team Readiness
- **MUST**: All 10 native attack classes imported and used
- **Reference**: `docs/specs/00-CONSTITUTION.md` 7B映射表

### R7: ASR-Token Balance
- **MUST**: Intermediate exit checkpoints (L1≥70% / L2≥80%)
- **Reference**: `docs/specs/20-REQUIREMENTS.md` P1-3

### R8: Production-Grade Engineering
- **MUST**: Error handling, resource cleanup, logging
- **Reference**: `docs/specs/20-REQUIREMENTS.md` P2

### R9: Config Data Flow Consistency
- **MUST**: `getattr(ctx.args, ...)` for all params
- **Reference**: `docs/specs/00-CONSTITUTION.md` R9

### R10: Post-Change Pipeline Verification
- **MUST**: `python main.py --dry-run --max-seeds 1` after coding
- **Reference**: `docs/specs/30-TASKS.md`

## Anti-Drift Meta-Rules

| Rule | Description |
|------|-------------|
| D1 | Pre-coding: Run `python core/architecture_guard.py` |
| D2 | During coding: Apply all 10 rules continuously |
| D3 | Post-coding: Fill `specs/templates/task-spec.md` |
| D4 | On commit: Git hooks auto-run guard |
| D5 | If violated: STOP, fix, re-verify |
| D6 | Authority: specs/ > SKILL.md |

## Architecture Guard Rules

Run: `python -m core.architecture_guard`

| Category | Rules |
|----------|-------|
| R-H1/H2/H3 | 红线护栏 (模块禁入、双轨审计) |
| R-L1~L8 | 红线护栏 (安全禁入) |
| R-PIPE-1~6 | 流水线集成完整性 |
| R-IMPORT-1~4 | 循环导入与死代码 |
| R-REDTEAM-1~3 | 红队最佳实践 |
| R-SIZE | 文件大小限制 (≤850行) |

**权威规则清单**：见 `docs/specs/00-CONSTITUTION.md` 附录A

## Directory Structure

```
pyrit-mini/
├── main.py               # Main entry point
├── config/               # SSOT configs
├── core/                 # Orchestrator + phases
├── recon/                # Reconnaissance
├── arm/                  # Seed + converter
├── strike/               # Attack execution
├── assess/               # Scoring + ASR
├── report/               # Report generation
├── tools/                # Shared utilities
├── utils/                # Display + cleanup
├── tests/                # Test suite
├── docs/specs/           # 规约金字塔（唯一权威源）
└── outputs/              # Run outputs
```

**详细目录**：见 `docs/specs/10-ARCHITECTURE.md`

## Post-Change Checklist

```bash
# 1. ruff lint
ruff check core/ recon/ arm/ strike/ assess/ report/ tools/ utils/ main.py

# 2. Python syntax check
py -m py_compile <changed_files>

# 3. Architecture guard
py -m core.architecture_guard

# 4. Dry-run pipeline
py main.py --dry-run --max-seeds 1
```

## References

- `docs/specs/00-CONSTITUTION.md` — 宪法 v1.6 (唯一权威源)
- `docs/specs/10-ARCHITECTURE.md` — 架构规格 v1.9
- `docs/specs/20-REQUIREMENTS.md` — 需求规格 v1.5
- `docs/specs/30-TASKS.md` — 任务执行协议
- `docs/specs/40-GUARDRAILS.md` — 护栏登记簿 v1.2
