# AI-300 目录结构说明 (PyRIT 最佳实践)

## 设计原则

1. **考试期间最小化代码修改**: 仅需修改 `scenarios/templates/` 下的 YAML 场景模板文件
2. **全自动化流水线**: converters 转换 → 攻击组合选择 → 编排 → 测试 → 报告
3. **PyRIT 框架对齐**: 遵循 PyRIT 0.14.0 原生组件命名和职责划分

## 完整目录树

```
a300/
├── config/                       # [新] 配置文件目录
│   └── __init__.py               # Ai300Config 配置类
│
├── templates/                    # [保持] 模板目录
│   └── datasets/                 # Prompt 素材库 (payload YAML)
│       ├── core/                 # 经典载荷 (双语 + 五档预设)
│       ├── manifest.yaml         # 模块↔文件索引
│       └── *_payloads.yaml       # 各 AI 模块的载荷列表
│
├── scenarios/                    # 🆕 场景模块 (PyRIT 对齐)
│   ├── __init__.py               # 包入口 + 延迟导入 + 模板路径
│   ├── schema.py                  # YAML 模板 Pydantic Schema
│   ├── orchestrator.py           # ExamAutoOrchestrator 场景编排引擎
│   ├── variant_generator.py      # 提示词变体生成器 (10+ 种策略)
│   ├── rag_attacks.py            # RAG 管道攻击 Payload
│   ├── agent_attacks.py          # 多智能体攻击 Payload
│   ├── infra_attacks.py          # 基础设施攻击 Payload
│   ├── reporter.py               # 综合安全评估报告
│   ├── target_presets.py         # HTTP 连接场景预设
│   └── templates/                # YAML 场景模板 (11 个)
│       ├── comprehensive.yaml     # 全场景综合攻击 (exam)
│       ├── prompt_injection.yaml  # Prompt 注入测试 (tech)
│       ├── encoding_bypass.yaml   # 编码绕过测试 (tech)
│       ├── jailbreak_arsenal.yaml # 越狱武器库 (tech)
│       ├── rag_pipeline.yaml      # RAG 管道攻击 (exam)
│       ├── agent_multi_agent.yaml # 多智能体 (exam)
│       ├── mcp_protocol.yaml      # MCP 协议 (exam)
│       ├── supply_chain.yaml      # 供应链 (exam)
│       ├── data_exfiltration.yaml # 数据外泄 (exam)
│       ├── output_handling.yaml   # 输出处理 (exam)
│       └── red_team_scenarios.yaml
│
├── prompt_converters/            # [重命名] converters/ → prompt_converters/
│   ├── __init__.py               # 公共 API
│   ├── registry.py               # 转换器注册表 + 攻击组合
│   ├── jailbreak.py              # 越狱前缀类 (DAN/PAIR/AIM/...)
│   ├── injection.py              # 注入类
│   ├── bypass.py                 # 绕过类
│   ├── reasoning.py              # 推理/宪法类
│   ├── rag_poisoning.py          # RAG 投毒
│   └── embedding_attack.py       # Embedding 对抗
│
├── attack_executor/              # [重命名] engines/ → attack_executor/
│   ├── __init__.py               # 公共 API
│   ├── single.py                 # 单轮攻击引擎
│   ├── crescendo.py              # Crescendo 多轮渐进式
│   ├── sequence_attack.py        # 策略管道 (Multimodal/Training)
│   ├── scorer.py                 # 评分器 (Judge LLM)
│   ├── dashboard.py              # 仪表盘状态
│   ├── template.py               # Payload 模板变量
│   └── utils.py                  # 引擎工具函数
│
├── targets/                      # [保持] 攻击目标
│   ├── __init__.py
│   ├── config.py                 # .env 配置加载
│   ├── http_target.py            # CustomHttpChatTarget
│   ├── factories.py              # Target 工厂
│   ├── scenarios.py              # 场景预设 (连接层)
│   └── model_probe.py            # 模型自动探测
│
├── scoring/                      # [新] 评分引擎
│   └── __init__.py               # CleanedSelfAskTrueFalseScorer 等
│
├── orchestrators/                # [重命名] orchestrator/ → orchestrators/
│   ├── __init__.py               # 公共 API
│   ├── pyrit_orchestrator.py     # AI300Orchestrator
│   └── scenario_runner.py        # A300ScenarioRunner
│
├── exam_mode/                    # 向后兼容桥接 → scenarios/
│   └── __init__.py               # 重新导出 scenarios/ 模块
│
├── reporting/                    # [保持] 报告生成
│   ├── __init__.py
│   ├── data.py                   # 用例分类
│   ├── engine.py                 # 推荐引擎
│   ├── heatmap.py                # 热力图
│   ├── terminal.py               # 终端战报
│   └── exam.py                   # 考试漏洞报告
│
├── data/                         # [保持] 数据层
│   ├── __init__.py
│   ├── models.py                 # Pydantic 数据模型
│   ├── loader.py                 # 数据加载器
│   ├── payload_loader.py         # 统一 Payload 加载
│   ├── payloads.py               # 原始载荷数据
│   ├── test_cases_cn.json        # 中文测试用例
│   └── test_cases_en.json        # 英文测试用例
│
├── utils/                        # [新] 工具函数包
│   ├── __init__.py               # 公共 API
│   ├── helpers.py                # 路径/配置辅助
│   └── retry.py                  # 重试逻辑
│
├── outputs/                      # [新] 输出目录
│   ├── logs/                     # 日志文件
│   └── results/                  # 攻击结果
│
├── scripts/                      # [保持] 脚本
│   ├── validator.py
│   └── generate_cases.py
│
├── docs/                         # [保持] 文档
│   └── *.md
│
├── tests/                        # [保持] 测试
│   └── test_engines.py
│
├── requirements.txt              # [保持] 依赖
├── run_redteam.py                # [新] 主入口
├── main.py                       # [保持] 向后兼容入口
└── README.md                     # [更新] 项目说明
```

## 向后兼容性

为保持向后兼容，以下旧目录保留为桥接包：

| 旧路径 | 新路径 | 说明 |
|--------|--------|------|
| `converters/` | `prompt_converters/` | `__init__.py` 重新导出 |
| `engines/` | `attack_executor/` | `__init__.py` 重新导出 |
| `orchestrator/` | `orchestrators/` | `__init__.py` 重新导出 |
| `exam_mode/` | `scenarios/` | `__init__.py` 重新导出 |
| `templates/scenarios/` | `scenarios/templates/` | 模板路径向后兼容 |
| `utils.py` | `utils/` | 模块级重新导出 |
| `results/` | `outputs/results/` | 向后兼容，旧路径仍可用 |

## 考试工作流

```
1. 编辑 YAML 场景模板
   └── scenarios/templates/*.yaml  (仅此一步！考试期间零代码改动)

2. 运行攻击
   └── python run_redteam.py --exam-mode --exam-template scenarios/templates/comprehensive.yaml

3. 自动化流程:
   ├── 模板加载 (scenarios/schema.py → ExamPromptSet)
   ├── 提示词变体生成 (scenarios/variant_generator.py, 10+ 种策略)
   ├── 攻击编排 (scenarios/orchestrator.py → ExamAutoOrchestrator)
   ├── Converter 转换 (prompt_converters/)
   ├── 攻击执行 (attack_executor/ + orchestrators/)
   ├── 目标测试 (targets/)
   ├── 结果评分 (scoring/ + attack_executor/scorer.py)
   └── 报告生成 (scenarios/reporter.py + reporting/)

4. 输出
   └── outputs/results/*.json + *.md
```
