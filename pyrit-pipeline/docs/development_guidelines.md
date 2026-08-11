# 开发规范

> **版本**: v3.0 (2026-8-11 精简重构: 聚焦红队 offsec 目标, 合并冗余规则)
> **规则**: R-001~R-009 (项目专项) + G-001~G-125 (全局继承)
> **对标**: L5 专家级 — ASR 驱动, 攻击为王, PyRIT 原生优先

---

## 1. 核心原则: ASR 驱动 + 攻击为王 (R-001)

所有攻击策略选择以 **ASR (Attack Success Rate) 实测数据** 为核心驱动。
攻击效果优先于代码美观、覆盖率、性能。冲突时优先保证攻击效果。

## 2. PyRIT 原生优先 + 自研增强 (R-002)

| 优先级 | 方案 | 示例 |
|--------|------|------|
| 1 | 原生 API 直接使用 | `TextAdaptive`, `AttackExecutor`, `CentralMemory` |
| 2 | 原生 API 子类继承/包装 | `FailureTypeRoutingSelector`, `RateLimitedTarget` |
| 3 | 纯自研 (仅兜底) | `EvidenceCollector`, ASR 先验数据 |

**禁止**: 替代原生功能 / 脱离原生组件 / 覆盖原生生命周期 / 绕过原生注册表 / 硬编码 API 调用

## 3. L5 专家水平对齐 (R-003)

- 攻击链路覆盖 OWASP LLM Top 10 + Agentic Security
- 评分器校准, ASR 数据可信
- 代码符合 PyRIT 原生编码规范 (async 后缀, keyword-only, 类型注解)
- 输出报告可追溯, 证据链完整

## 4. 研究资料优先级 (R-004)

1. **arXiv 学术文献** — 标注 arXiv 编号, 确保理论支撑
2. **GitHub 官方源码** — PyRIT/garak/Microsoft AI Red Team
3. **自行搜索** — 仅兜底, 须交叉验证

| 文献 | arXiv | 贡献 |
|------|-------|------|
| PyRIT | 2407.01232 | 框架设计基准 |
| JailbreakBench | 2402.01135 | ASR 基线数据 |
| HarmBench | 2402.04249 | 标准化红队评估 |
| Crescendo | 2404.01833 | 多轮递进攻击 |
| TAP | 2312.02191 | 树搜索攻击优化 |
| PAIR | 2310.08437 | 对抗迭代优化 |
| StrongREJECT | 2402.10260 | 拒绝评估 |

## 5. 工程规范 (R-005)

### 5.1 临时文件清理 + UTF-8 编码

- 运行后+异常退出: 清理 `__pycache__` + `.pyc` + `.pytest_cache`, 静默执行 (运行前不清理, Python 自动管理缓存失效)
- 所有文件 UTF-8, 运行前设 `PYTHONIOENCODING=utf-8`
- 实现: `pipeline/utils/cleaner.py`

### 5.2 代码改动后全量测试 + L5 差距分析 (R-006)

```
代码改动完成
  ├─→ 1. make check-full (ruff + pytest)     ← 自动执行
  ├─→ 2. PyRIT 1.0.1 API 一致性检查            ← 自动执行
  ├─→ 3. L5 差距分析报告                        ← 自动执行
  └─→ 4. 端到端流水线运行 (python main.py)     ← 需用户确认
```

- ruff: `pipeline/` `scripts/` `tests/` `conftest.py` (不用 `ruff check .`)
- pytest: `pytest tests/ -v --tb=short`, 0 failed
- L5 差距分析更新到 `docs/l5_gap_analysis.md`

### 5.3 方案确认前 L5 差距分析 (R-007)

方案优化 → L5 差距分析 (对比表+根因+学术依据) → 100% 对齐方案 → **用户确认后才改代码**

### 5.4 端到端验证自动化 (R-008)

发现端到端验证型差距 → 自动写入记忆库 → 用户确认运行 → 运行后自动对齐 → **验证通过的记忆条目自动删除 (R-024)**

### 5.5 实施前检查清单 (R-009)

方案确认后执行: (a)受影响文件 (b)依赖检查 (c)配置同步 (d)测试覆盖 (e)文档同步 (f)规则合规 (g)记忆库更新

### 5.6 分级测试 + Makefile + 文档标记

- 单模块→单元测试, 模块间→集成测试, 多模块→回归测试
- scripts/*.py 自动可用 `make script-<name>`, 高频注册独立 target
- 更新 .md 时添加时间标记

## 6. 代码规范

### 6.1 风格

- 格式化: `ruff` (配置在 `pyproject.toml`), 行长 120
- Import: stdlib → third-party → pyrit → pipeline → local
- 类型注解 + Docstring: 所有公共函数/类必须

### 6.2 命名

| 类型 | 规范 | 示例 |
|------|------|------|
| 模块/函数 | snake_case | `failure_type_selector.py`, `select_async()` |
| 类 | PascalCase | `FailureTypeRoutingSelector` |
| 常量/环境变量 | UPPER_SNAKE | `DEFAULT_EPSILON`, `OPENAI_CHAT_ENDPOINT` |
| 私有 | _prefix | `_build_warm_start_asr()` |

### 6.3 异步 + 错误处理

- 所有 I/O 用 `async/await`, 不用 `time.sleep()`
- 并发用 `asyncio.Semaphore`
- 三级 fallback 模式, 噪音日志重定向到文件

## 7. 测试规范

- mock 原生 API 调用, 不依赖真实 API
- 使用固定 ASR 数据, 不依赖历史运行
- 每个测试独立运行, 覆盖率 ≥ 80%
- 命名: `test_<模块>_<函数>_<场景>()`

```bash
pytest tests/ -v                    # 全量
pytest tests/unit/test_asr/ -v      # 特定模块
pytest tests/ --cov=pipeline        # 覆盖率
```

## 8. 模块创建

```
原生 API 已支持? → YES: 使用原生, 不创建
                 → NO:
  数据层增强? → pipeline/asr/ 或 pipeline/converters/
  分析层扩展? → pipeline/analysis/
  报告层扩展? → pipeline/reporting/
  目标层增强? → pipeline/targets/
```

## 9. Git 提交

```
<type>: <简述>

<详细说明>
```

类型: `feat` / `fix` / `docs` / `refactor` / `test` / `chore`

## 10. 第三方 Warning 抑制

- `main.py`: `warnings.filterwarnings("ignore", category=SyntaxWarning)` (在所有业务 import 前)
- `pyproject.toml`: `filterwarnings = ["ignore::SyntaxWarning"]`
- 仅抑制 SyntaxWarning (第三方库问题), 不抑制 DeprecationWarning/FutureWarning

---

*文档结束*
