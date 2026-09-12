# AI Coding Template（跨模型 · 通用 · 生产级 L5）

将 AI 编程规范框架（`docs/ai-dev-guides.md` / `docs/ai-dev-audit.md`，本模板自带）落地为**可初始化的项目骨架**。任何新项目复制本模板、填一份配置、跑一条命令，即可获得生产级规范分层 + 门禁 + 跨模型政策。

## 目录结构

```
ai-coding-template/
├── README.md                      # 本文件
├── init.py                        # 占位符替换初始化脚本
├── template.config.yaml           # 初始化时的替换值（改这个）
├── audit_config.yaml.example      # 运行时审计配置（完整参考，含阈值/模块/跨模型）
├── tools/
│   ├── gate.py                    # 通用 guard 参考实现（零依赖，开箱即跑）
│   ├── install_hooks.py           # 把 hooks/ 装成 git hooks（幂等）
│   └── __init__.py
├── .gitignore                     # 生产仓库基础忽略项
├── specs/                         # 规范分层骨架（核心产出）
│   ├── README.md
│   ├── 00-CONSTITUTION.md         # L0 宪法
│   ├── 10-ARCHITECTURE.md         # L1 蓝图
│   ├── 20-REQUIREMENTS.md         # L2 需求
│   ├── 40-GUARDRAILS.md           # L4 护栏
│   ├── 60-CROSS-MODEL.md          # 跨模型政策
│   ├── backlog.md                 # 唯一待办池
│   ├── TASK-TEMPLATE.md           # L3 任务模板
│   ├── CHANGE-PROPOSAL-TEMPLATE.md
│   └── cross-model/REVIEW-TEMPLATE.md
├── hooks/
│   ├── pre-commit
│   └── pre-push
└── .github/workflows/l5-audit.yml
```

## 三步上手（新项目）

1. **复制**：把整个 `ai-coding-template/` 复制到你的项目根目录。
2. **填配置**：编辑 `template.config.yaml` —— 填 `PROJECT_NAME`、命令绑定（`GUARD_CMD` 等）、目录映射、组件、模型版本。
3. **初始化**：运行
   ```bash
   pip install pyyaml          # 仅初始化时需要
   python init.py --output .
   ```
   脚本会读取 `substitutions`，把 `targets` 里每个文件中的 `${KEY}` 替换为对应值，写入 `--output`（默认当前目录），并保留目录结构。`assets` 中的方法论文档会被原样复制到 `<output>/docs/`。

## 占位符约定（重要）

| 类别 | 示例 | 行为 |
|------|------|------|
| **配置级** | `${PROJECT_NAME}` `${GUARD_CMD}` `${CORE_DIR}` `${DIFF_LIMIT}` `${MODEL}` | init.py **会替换**为 config 中的值 |
| **示例级** | `${field_a}` `${stage_1}` `${c1}` `${component_x}` | 替换表中没有 → **保留为 `${...}`**，由你按实际架构填写 |

初始化后若仍有 `${...}` 残留，是正常现象（示例级占位符），脚本会在末尾列出它们所在的文件，提示你后续补全。

## 之后做什么

- 按 `ai-dev-guides.md` §2「5 分钟快速入门」补全使命 / 红线 / 验证 / backlog。
- （推荐）把 `hooks/` 安装为 git hooks：`python tools/install_hooks.py`（幂等，自动委派给统一门禁的快检/全量阶段）。
- （可选）启用 `.github/workflows/l5-audit.yml` 做 CI 审计。

## 依赖

- Python 3.8+；`init.py` 需要 `PyYAML`（`pip install pyyaml`）。
- 模板已自带通用 `tools/gate.py`（零依赖、开箱即跑）。门禁分两层，确保**复制即用就有真实护栏**：
  - **内置检查（初始化后即生效，零外部依赖）**：文件体积 BLOCK、疑似硬编码密钥 BLOCK、L5 规范骨架存在性 BLOCK、裸 except/桩函数 WARN、提交粒度（>300 行）WARN。
  - **外部关卡（按需接入）**：`lint`/`typecheck`/`test`/`drift`/`dataflow` 在 `audit_config.yaml` 的 `commands:` 中声明；**留空则自动 SKIP（非阻塞）**，接好工具且返回非零才 BLOCK。升级路径见 `audit_config.yaml.example`（已含 ruff/pytest/drift 等示例命令）。

## 配套文档（本模板 `docs/` 下）

- `docs/ai-dev-guides.md` —— 规范与流程单一事实源。
- `docs/ai-dev-audit.md` —— 验证与度量单一事实源（审计成熟度 A0–A5、六维审计、跨模型 κ/r 度量）。
