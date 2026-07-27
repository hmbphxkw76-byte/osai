# ai300-eval-kit

基于 `ai300-recon` 侦察结果，对 LLM 应用执行自动化评估的工具包。

## 核心能力

- **Giskard 适配器**：对目标 LLM API 执行鲁棒性、有害性、偏见、敏感信息泄露等扫描。
- **评估策略选择器**：根据目标指纹（RAG / Agent / API / Web UI）自动选择评估维度。
- **统一报告**：所有评估结果转换为 `UnifiedFinding`，与 `ai300-attack`、`ai300-recon` 共享数据契约。

## 快速开始

```bash
# 安装核心依赖（不安装 Giskard/ART）
pip install -e ./ai300-eval-kit

# 安装包含 Giskard 的版本
pip install -e "./ai300-eval-kit[giskard]"

# 执行评估（dry-run 预览策略）
ai300-eval --profile results/recon/profiles/latest.json --pyrit-target results/recon/pyrit/target.json --dry-run

# 正式评估
ai300-eval --profile results/recon/profiles/latest.json --pyrit-target results/recon/pyrit/target.json --adapter giskard
```

## 环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `EVAL_PROFILE` | TargetProfile JSON 路径 | "" |
| `EVAL_PYRIT_TARGET` | PyRIT target JSON 路径 | "" |
| `EVAL_ADAPTERS` | 评估适配器，逗号分隔 | `giskard` |
| `EVAL_OUTPUT_DIR` | 结果输出目录 | `results/eval` |
| `EVAL_DRY_RUN` | 仅预览策略 | `false` |
| `EVAL_TIMEOUT` | 单次评估超时秒数 | `300` |

## 项目结构

```
ai300-eval-kit/
├── src/ai300_eval_kit/
│   ├── adapters/        # Giskard / ART 适配器
│   ├── strategies/      # 评估策略选择器
│   ├── reporting/       # 评估报告与 UnifiedFinding 转换
│   ├── loaders/         # 读取 recon 输出
│   ├── cli.py           # 命令行入口
│   ├── config.py        # 配置加载
│   └── main.py          # 编排入口
└── tests/               # 单元测试与集成测试
```
