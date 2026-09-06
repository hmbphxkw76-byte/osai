# MIGRATION — 跨机器 / 跨平台迁移清单

本文档说明: 当项目迁移到另一台电脑或平台 (Linux / macOS / Windows) 时,
如何在不破坏既有规范约束的前提下恢复完整的「宪法守卫」能力。

---

## 1. 随 git 克隆即被保留的规范资产

以下文件已纳入版本控制, 迁移后无需重建:

| 路径 | 作用 |
|------|------|
| `docs/specs/00-CONSTITUTION.md` | 规格宪法 (L0 顶层) |
| `docs/specs/10-ARCHITECTURE.md` | 架构蓝图 (L1) |
| `docs/specs/20-REQUIREMENTS.md` | 需求规约 (L2) |
| `docs/specs/40-GUARDRAILS.md` | 红线护栏 + 检查器登记簿 v1.2 |
| `docs/specs/templates/` | 编号文档模板 (00/10/20/30/40) |
| `core/architecture_guard.py` | 架构契约自动验证器 (19 项检查) |
| `config/defaults.yaml` | 策略默认参数 (R7 单一事实源) |
| `config/target_profiles.yaml` | 目标画像 Profile (4 种) |
| `pyproject.toml` | 依赖声明 (ruff/pytest/pyrit/pyyaml 等) |
| `guard.py` / `guard.bat` | 一键入口 (文本 / Windows 批处理) |

---

## 2. 无外部依赖 — 宪法守卫零安装可运行

`core/architecture_guard.py` 仅依赖 Python 标准库:

```
argparse · json · os · re · sys · dataclasses · enum · pathlib
```

唯一可选依赖 `PyYAML` (用于 R11 scenario 配置校验) 缺失时:
架构守卫仍正常执行其余 18 项检查, 仅 R11 降级为 WARNING。

**结论**: 只要目标机器有 Python 3.13+ 即可立即运行宪法守卫。

---

## 3. 恢复项目依赖 (生产运行,非守卫)

```bash
# 创建虚拟环境 (三平台通用)
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

# 安装核心依赖
pip install -e .

# 安装开发依赖 (可选,含 ruff / pytest)
pip install -e ".[dev]"
```

---

## 4. 首次运行宪法守卫

克隆 / 迁移到任意机器后, 执行一条命令即可跑全量规范校验:

```bash
# 文本报告 (推荐日常用)
py -m core.architecture_guard

# 或根目录一键入口
py guard

# 含修复建议
py guard --fix-hints

# JSON 输出 (CI 集成)
py guard --json

# 单规则检查
py guard --rule R-H1
```

**宪法守卫 = specs 扫描 + 架构检查 + 红线护栏三统一**, 覆盖:

- 规格版本 (`00-CONSTITUTION.md` v1.2 读取并脚注)
- 9 项红线护栏 (R-L1~R-L8 BLOCKING, 含合规/串行/L5 Params/出口/Output)
- 19 项架构检查 (含 T0 新增 R-H1 静默降级 / R-H2 静默吞错 / R-H3 双轨新增)
- 配置数据流 R9 (含 `_resolve()` / f-string 插值误报白名单)
- REQ-108 / 40-GUARDRAILS 登记簿 v1.2 完整锚定

---

## 5. 迁移后验证 checklist

```bash
# 1. 宪法守卫门禁 — 必须 0 BLOCKING
py guard

# 2. 确认 specs 版本读取成功 (报告脚注输出 specs 版本: 1.2)
py guard --fix-hints 2>&1 | grep "specs 版本"

# 3. (可选) 跑测试套件
pip install -e ".[dev]" && pytest

# 4. (可选) 静态类型检查
pyright core/  # 或 mypy core/architecture_guard.py
```

---

## 6. 关键不变式 (迁移不得破坏)

| 不变式 | 校验方式 |
|--------|----------|
| `00-CONSTITUTION.md` 版本号 > 0 | guard 报告脚注 |
| 红线护栏 R-L1~R-L8 零 BLOCKING | guard 出口码 0 |
| 40-GUARDRAILS 登记簿 19 项全锚定 | Guard 第 17 项统计 |
| 配置数据流 `_resolve()` 误报白名单生效 | 扫描 display.py / display_stages.py 时 0 R9 误报 |
| `_ALLOWED_ROOT_ENTRIES` 不含临时脚本 | 根目录仅保留名单内文件 |

---

*文档版本: v1.2 (2026-09-06 随 T0/T1 方案固化)*
