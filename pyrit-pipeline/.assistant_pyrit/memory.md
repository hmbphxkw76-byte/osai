# PyRIT 项目记忆

> AI 红队评估流水线。ASR 驱动，攻击为王，PyRIT 原生优先。
> 更新: 2026-8-11 — 按 R-024 精简, 删除已验证实现细节

---

## 项目定位

基于 PyRIT 1.0.1 构建 **ASR 数据驱动的端到端 AI 红队评估流水线**。
目标: 以攻击成功率 (ASR) 为核心度量, 自动发现 LLM 安全漏洞。

## 目录架构

```
osai/
├── src/PyRIT-1.0.1/           # PyRIT 原生源码 (只读)
├── pyrit-pipeline/            # ★ 二次开发目录
│   ├── pipeline/              #   6 阶段流水线
│   ├── web_redteam/           #   Playwright Web 红队
│   ├── data/                  #   攻击种子数据集
│   ├── scripts/               #   工具脚本
│   ├── docs/                  #   文档
│   ├── .assistant_pyrit/      #   AI 助手规则与记忆
│   ├── main.py                #   流水线入口
│   └── pyproject.toml
└── garak-0.15.1/              # garak 二次开发
```

## 核心决策

| 决策 | 理由 |
|------|------|
| ASR 数据驱动架构 | 攻击策略选择基于实测成功率, 非主观判断 |
| 攻击效果优先 | 红队评估核心目标是发现漏洞, ASR 是唯一有效度量 |
| PyRIT 原生框架优先 | 避免重复造轮子, 保持与上游兼容 |
| 源码/消费层分离 | src/ 只读 + pyrit-pipeline/ 开发, 100% 对齐原生 API |
| 流水线 6 阶段拆分 | init→scenario→initialize→execute→post_analysis→output |

## 依赖管理

- `pyrit` 从 `../src/PyRIT-1.0.1` editable 安装
- 版本更新: 替换源码目录 → 重新 `uv pip install -e` → 验证

## 技术栈关键点

- **评分器**: 16+ 个 (task_achieved + refusal×4 + likert×N + composite AND/MAJORITY/OR), F1 评估指标驱动最优选择
- **技术名解析**: 6 条路径 (get_attack_strategy_identifier → children → metadata → error_message → eval_hash → unknown), 端到端验证 0/193 NULL
- **Converter 路由**: 三层 (CLI 显式 → Target 感知 → Auto-Converter 兜底 + payload affinity)
- **韧性机制**: RateLimitedTarget 重试 + 评分器熔断器 + Converter 熔断 + 内容过滤器 + JSON mode 自动检测
- **预检机制**: 并发验证 3 个模型连通性 + URL 可达性 (默认跳过, --run-preflight 启用)

## 目录约定

| 目录 | 性质 |
|------|------|
| `src/PyRIT-1.0.1/` | 只读, 不可修改 |
| `pipeline/` | 可自由修改 |
| `web_redteam/` | 可自由修改 |
| `scripts/` | 可自由添加 |
| `data/` | 可自由添加 |
| `docs/` | 可自由添加 |
| `.assistant_pyrit/` | 跨 IDE 平台共享 |
