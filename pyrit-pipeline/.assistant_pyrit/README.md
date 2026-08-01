# .assistant_pyrit/

AI 助手共享记忆与规则目录，供跨 IDE 平台使用。

## 目录结构

| 文件 | 用途 | 性质 |
|---|---|---|
| `rules.md` | 项目硬性规则，AI 助手编码时**必须遵守** | 不可变约束 |
| `memory.md` | 项目记忆，积累上下文、决策记录和经验教训 | 持续更新 |

## 跨 IDE 使用方式

所有 AI 助手在操作本项目前，应先读取 `rules.md` 和 `memory.md`。

| IDE / 助手 | 引用方式 |
|---|---|
| CatPaw | `.github/copilot-instructions.md` 已内置引用 |
| GitHub Copilot | 读取 `.github/copilot-instructions.md`，间接引用 |
| Cursor | 在 `.cursorrules` 中添加 `@.assistant_pyrit/rules.md` |
| Claude Code | 在 `CLAUDE.md` 中添加引用 |
| 通用 | 将本目录内容粘贴到对应 IDE 的规则文件中 |

## 维护原则

- `rules.md`：只增不删，新增规则追加到末尾，标注日期
- `memory.md`：可更新，记录重要决策和经验教训
- 两个文件均保持简洁，每条不超过 3 行
