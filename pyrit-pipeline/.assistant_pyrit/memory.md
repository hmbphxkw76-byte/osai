# PyRIT 项目记忆

> 积累的上下文、决策记录和经验教训。持续更新。
> **更新记录**:
>   2026-8-1 14:30 — 源码/消费层分离重构，迁移至 pyrit-pipeline/ 独立目录
>   2026-8-1 15:55 — L5 差距分析全部修复: 10 维度全覆盖
> **更新记录**: 2026-8-1 15:00 — 新增 R-007 研究资料优先级规则（arxiv 理论先行 → GitHub 官方源码 → 自行搜索兜底）
> **更新记录**: 2026-8-1 17:30 — 新增 R-008 运行前后自动清理
> **更新记录**: 2026-8-1 22:00 — R-008 更新: 不再清理 output/ 目录，改为仅清理 __pycache__ 等临时文件

---

## 项目定位

本项目基于 PyRIT（Python Risk Identification Tool for LLMs）框架，构建 **ASR 数据驱动的端到端 AI 红队评估流水线**。

## 目录架构（2026-8-1 14:30 重构）

```
osai/
├── src/                        # 源码目录（只读，不可修改）
│   ├── PyRIT-1.0.1/           #   PyRIT 原生源码 (editable install)
│   └── garak-0.15.1/          #   garak 原生源码
│
├── pyrit-pipeline/             # ★ 二次开发目录（本项目工作区）
│   ├── .venv/                  #   独立虚拟环境
│   ├── pipeline/               #   5 阶段流水线（init→scenario→initialize→execute→output）
│   ├── web_bridge/            #   Playwright Web 红队框架（5 阶段: init→auth→target→attack→output）
│   ├── data/                   #   自定义数据集 (.prompt 文件)
│   ├── docs/                   #   自定义文档
│   ├── scripts/                #   自定义工具脚本
│   ├── output/                 #   运行时报告输出
│   ├── .assistant_pyrit/       #   AI 助手规则与记忆
│   ├── .github/instructions/   #   IDE 指令文件
│   ├── .env                     #   API 密钥（.gitignore，根目录）
│   ├── .env.example            #   环境模板（可提交）
│   ├── config/.pyrit_conf      #   PyRIT 结构配置（.gitignore）
│   ├── pyproject.toml           #   依赖管理（pyrit 作为 editable 依赖）
│   ├── main.py                  #   流水线入口
│   └── .gitignore
│
└── garak-0.15.1/               # garak 二次开发（独立目录）
```

## 核心决策记录

| 日期 | 决策 | 理由 |
|---|---|---|
| 2026-08-01 | 采用 ASR 数据驱动架构 | 攻击策略选择需基于实测成功率，非主观判断 |
| 2026-08-01 | 攻击效果优先于其他指标 | 红队评估的核心目标是发现安全漏洞，ASR 是唯一有效度量 |
| 2026-08-01 | PyRIT 原生框架优先 | 避免重复造轮子，保持与上游兼容，降低维护成本 |
| 2026-08-01 | 对齐 L5 专家水平 | 确保评估结果的专业性和可信度 |
| 2026-8-1 11:20 | 流水线拆分为 pipeline/ 五阶段 | 避免改一处导致全流程异常，main.py 降至 42 行 |
| 2026-8-1 11:30 | ASR 驱动优化: per-dataset 独立预算 + 技术选择 + ASR 排行榜 | 充分利用原生 CompoundDatasetAttackConfiguration + scenario_techniques + get_display_groups |
| 2026-8-1 11:37 | 新增规则 R-005 分级测试 + R-006 文档时间标记 | 确保代码质量和文档可追溯性 |
| 2026-8-1 14:30 | 源码/消费层分离: src/ + pyrit-pipeline/ | 源码只读、版本更新秒级完成、.venv 独立、100% 对齐原生 API |
| 2026-8-1 15:00 | 新增规则 R-007 研究资料优先级（理论先行） | 确保方法论严谨性：arxiv 学术文献 → GitHub 高人气/官方源码 → 自行搜索兜底 |
| 2026-8-1 17:30 | 新增规则 R-008 运行前后自动清理 | 初始版本清理 output/ 目录 |
| 2026-8-1 22:00 | R-008 更新: 仅清理 __pycache__ 等临时文件 | 报告保留供人工审查；临时缓存自动清理确保环境干净 |

## 依赖管理

- `pyrit` 通过 `[tool.uv.sources]` 从 `../src/PyRIT-1.0.1` editable 安装
- 安装命令: `cd pyrit-pipeline && uv pip install -e ../src/PyRIT-1.0.1`
- 版本更新: 替换 `src/PyRIT-1.0.1/` 目录 → 重新 `uv pip install -e` → 验证

## 目录约定

| 目录 | 用途 | 性质 |
|---|---|---|
| `src/PyRIT-1.0.1/` | PyRIT 原生源码 | 只读，不可修改 |
| `pipeline/` | 5 阶段流水线 | 可自由修改 |
| `web_bridge/` | Playwright Web 红队框架 | 可自由修改 |
| `scripts/` | 自定义工具脚本 | 可自由添加 |
| `.assistant_pyrit/` | AI 助手共享记忆与规则 | 跨 IDE 平台使用 |
| `.github/instructions/` | IDE 指令文件 | 按 `applyTo` 模式匹配自动加载 |
| `data/` | 自定义 .prompt 数据集 | 可自由添加 |
| `docs/` | 自定义架构文档 | 可自由添加 |
