# AI-300 LLM 红队三项目 Monorepo

本仓库包含三个独立但数据契约统一的项目，用于对基于 LLM 的 AI Web 应用进行侦察、攻击与评估：

| 项目 | 目录 | 职责 | CLI |
|---|---|---|---|
| **ai300-recon** | `ai300-recon/` | 侦察 LLM Web 应用，输出 TargetProfile 与 PyRIT target | `python ai300-recon/main.py <URL>` |
| **ai300-attack** | `ai300-attack/` | 基于侦察结果调用 Garak / PyRIT 执行对话层攻击 | `ai300-attack` |
| **ai300-eval** | `ai300-eval/` | 基于侦察结果调用 Giskard / ART 执行模型评估 | `ai300-eval` |
| **ai300-schemas** | `ai300-schemas/` | 三项目共享的数据契约 | 无 CLI |

## 设计原则

- **独立项目**：每个项目有自己的 `pyproject.toml`、源码目录与测试目录，可单独安装与使用。
- **共享数据契约**：`TargetProfile`、`PyRITTargetConfig`、`UnifiedFinding` 由 `ai300-schemas` 统一定义，避免重复造轮子。
- **可选依赖**：Garak、PyRIT、Giskard、ART 等重型框架均为 optional，核心环境保持轻量。
- **延迟导入**：适配器使用 lazy import，未安装对应工具时返回清晰的不可用提示。
- **三层测试**：单元 / 集成 / 系统测试分别覆盖模块内、模块间与跨项目流程。

## 项目结构

```
.
├── ai300-schemas/              # 共享数据契约
│   └── src/ai300_schemas/
├── ai300-recon/                # 侦察阶段
│   ├── src/
│   ├── config/
│   ├── tests/
│   └── main.py
├── ai300-attack/               # 攻击阶段
│   ├── src/ai300_attack/
│   ├── tests/
│   └── pyproject.toml
├── ai300-eval/             # 评估阶段
│   ├── src/ai300_eval/
│   ├── tests/
│   └── pyproject.toml
├── third_party/skillspector/   # SkillSpector 源码（子进程/Docker 调用）
├── redamon/                    # RedAmon 源码克隆目录（运行期拉取）
├── tests/system/               # 跨项目端到端系统测试
├── examples/                   # 使用示例
├── Makefile                    # 统一命令入口
└── README.md                   # 本文档
```

## 快速开始

### 1. 安装依赖

```bash
make install
```

或手动安装：

```bash
pip install -e ./ai300-schemas
pip install -r ./ai300-recon/requirements.txt
pip install -e "./ai300-attack[dev]"
pip install -e "./ai300-eval[dev]"
```

### 2. 配置目标 URL

复制 `ai300-recon/.env.example` 为 `ai300-recon/.env`（或在仓库根目录创建 `.env`），写入：

```env
RECON_TARGET_URL=https://student.syxy.ouchn.cn/
```

### 3. 一键执行完整 dry-run 流水线

```bash
make run-all-dry URL=http://127.0.0.1:18080
```

或使用本地 Mock 服务：

```bash
# 终端 1：启动 Mock LLM 服务
python ai300-recon/tests/integration/mock_llm_server.py

# 终端 2：执行流水线
make run-all-dry URL=http://127.0.0.1:18080
```

### 4. 分阶段执行

```bash
# 侦察
make run-recon URL=http://127.0.0.1:18080

# 攻击（dry-run）
ai300-attack --dry-run

# 评估（dry-run）
ai300-eval --dry-run
```

## 测试

```bash
# 全部测试
make test

# 分层测试
make test-unit
make test-integration
make test-system
```

## 数据流

```
ai300-recon
      │
      ▼
TargetProfile + PyRITTargetConfig
      │
      ├──► ai300-attack ──► UnifiedFinding
      │
      └──► ai300-eval ────────► UnifiedFinding
```

## 扩展新的攻击/评估工具

1. 在 `ai300-attack/src/ai300_attack/adapters/` 或 `ai300-eval/src/ai300_eval/adapters/` 中继承基类实现适配器。
2. 在 `strategies/strategy_selector.py` 中添加对应的策略。
3. 在 `reporting/unified_converter.py` 中添加工具输出到 `UnifiedFinding` 的转换。
4. 补充单元测试与集成测试。
