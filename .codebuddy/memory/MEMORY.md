# OSAI 项目长期记忆

## 项目结构（Monorepo）

```
osai/
├── .assistant/rules.md              ← 全局开发规范（G-001 ~ G-120）
├── recon-pipeline/                  ← 共享侦察模块（原 ai-recon-core）
├── pyrit-pipeline/                  ← 基于 PyRIT 的攻击流水线
├── garak-pipeline/                  ← 基于 Garak 的攻击流水线
└── src/                             ← 上游框架源码（PyRIT-1.0.1 / garak-0.15.1）
```

## 关键架构决策

- **2026-08-02**: 创建全局开发规范 `.assistant/rules.md` v1.0.0，49 条规则。
- **2026-08-02**: 升级至 v1.1.0，新增 Git 规范、依赖管理、API 设计、性能、安全、审查、废弃策略，共 108 条规则。
- **2026-08-02**: 升级至 v1.2.0，修正项目名称（ai-recon-core → recon-pipeline），新增附录 C（子项目规则模板 + G-109），确保新增子项目自动继承全局规则。
- **2026-08-03**: 升级至 v1.4.0，新增第 17 章（ruff 与 pytest 工具链规范），G-109~G-120 共 12 条规则，覆盖 ruff 配置/执行/规则选择、pytest 配置/执行/覆盖率。
- **2026-08-03**: 升级至 v1.5.0，扩展第 5 章研究资料优先级：新增 5.2 核心学术论文引用表（6 篇论文，含 arXiv 编号/标题/核心贡献/关联子项目）、5.3 关键开源项目参考表（5 个项目，含仓库/核心能力/参考价值/关联子项目）、5.4 OWASP LLM Top 10 2025 映射表。新增第 18 章侦察设计原则（G-121~G-124）：侦察先行、认证后侦察、探针分层执行、主动探测补充。附录 A 新增 G-121~G-124，附录 B 更新 recon-pipeline 规则文件引用。总规则数：124 条。
- **2026-08-02**: 三个子项目物理隔离，代码零交叉引用。pyrit-pipeline 只 `import pyrit`，garak-pipeline 只 `import garak`，recon-pipeline 不依赖任何框架。
- 子项目规则继承：全局 `.assistant/rules.md` > 子项目 `.assistant_*/rules.md`
- 子项目规则文件头部必须显式声明继承全局规则（已为 pyrit/garak/recon 添加）
- 新增子项目时按附录 C 模板创建 `.assistant_<name>/rules.md` 即可自动继承
- **2026-08-03**: 创建 recon-pipeline 子项目规则 `.assistant_recon/rules.md`（R-100~R-120），包含学术基础（4 篇核心论文）、开源实践参考（AIMap/Garak/VulnerableMCP/PyRIT）、侦察设计原则（先行/认证后/分层/主动探测/攻击面映射）、代码规范、测试规范。

## 开发约定

- 开发时在对话中明确说明"改哪个项目"（pyrit/garak/recon），即可确保代码写到正确目录
- 修改 `recon-pipeline` 时需额外检查对两个 pipeline 的影响
- 代码改动必须遵循 G-024（L5 差距分析流程）：方案概述 → 差距分析 → 完整方案 → 用户确认 → 执行
