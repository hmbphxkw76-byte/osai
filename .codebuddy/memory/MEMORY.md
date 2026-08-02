# OSAI 项目长期记忆

## 项目结构（Monorepo）

```
osai/
├── .assistant/rules.md              ← 全局开发规范（G-001 ~ G-108）
├── recon-pipeline/                  ← 共享侦察模块（原 ai-recon-core）
├── pyrit-pipeline/                  ← 基于 PyRIT 的攻击流水线
├── garak-pipeline/                  ← 基于 Garak 的攻击流水线
└── src/                             ← 上游框架源码（PyRIT-1.0.1 / garak-0.15.1）
```

## 关键架构决策

- **2026-08-02**: 创建全局开发规范 `.assistant/rules.md` v1.0.0，49 条规则。
- **2026-08-02**: 升级至 v1.1.0，新增 Git 规范、依赖管理、API 设计、性能、安全、审查、废弃策略，共 108 条规则。
- **2026-08-02**: 升级至 v1.2.0，修正项目名称（ai-recon-core → recon-pipeline），新增附录 C（子项目规则模板 + G-109），确保新增子项目自动继承全局规则。
- **2026-08-02**: 升级至 v1.3.0，审计全 108 条规则与 Python 最佳实践一致性。删除 2 条冲突规则（原 G-069 函数行数硬限制、原 G-073 keyword-only 强制），微调 3 条规则措辞（G-081 内存管理、G-082 可读性优先、G-099 小步提交），重新编号后规则 G-001~G-108 连续无跳跃。
- **2026-08-02**: 三个子项目物理隔离，代码零交叉引用。pyrit-pipeline 只 `import pyrit`，garak-pipeline 只 `import garak`，recon-pipeline 不依赖任何框架。
- 子项目规则继承：全局 `.assistant/rules.md` > 子项目 `.assistant_*/rules.md`
- 子项目规则文件头部必须显式声明继承全局规则（已为 pyrit/garak 添加，recon 暂无规则文件）
- 新增子项目时按附录 C 模板创建 `.assistant_<name>/rules.md` 即可自动继承

## 开发约定

- 开发时在对话中明确说明"改哪个项目"（pyrit/garak/recon），即可确保代码写到正确目录
- 修改 `recon-pipeline` 时需额外检查对两个 pipeline 的影响
- 代码改动必须遵循 G-024（L5 差距分析流程）：方案概述 → 差距分析 → 完整方案 → 用户确认 → 执行
