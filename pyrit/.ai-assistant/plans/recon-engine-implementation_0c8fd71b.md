---
name: recon-engine-implementation
overview: 实施侦察引擎完整架构：reconnaissance/ 模块（含 adapters、target_profile、profile_merger）、attack/ 模块（profile_loader）、CLI 扩展、配置文件、数据模板。遵循 ARCH-001 调度器+格式转换器原则，零重复造轮子。
todos:
  - id: target-profile
    content: 创建 TargetProfile 数据模型（target_profile.py）和侦察配置（config/recon/recon.yaml）
    status: completed
  - id: base-adapter
    content: 实现 BaseAdapter 抽象基类和 ProfileMerger 结果合并器
    status: completed
    dependencies:
      - target-profile
  - id: python-adapters
    content: 实现 LLMmap/Garak/DeepTeam 三个 Python 原生适配器
    status: completed
    dependencies:
      - base-adapter
  - id: cli-adapters
    content: 实现 Augustus/AIMap 两个 CLI 适配器 + HTTP 工具类
    status: completed
    dependencies:
      - base-adapter
  - id: recon-engine
    content: 实现 ReconEngine 统一调度器和 CLI recon 子命令
    status: completed
    dependencies:
      - python-adapters
      - cli-adapters
  - id: attack-integration
    content: 实现 ProfileLoader 和 run 命令的 --profile/--auto-recon 扩展
    status: completed
    dependencies:
      - recon-engine
  - id: tests
    content: 编写侦察模块单元测试并更新 __init__.py 导出
    status: completed
    dependencies:
      - recon-engine
      - attack-integration
---

## 需求概述

基于 ARCH-001 原则（调度器 + 格式转换器，不重复造轮子），实施完全独立的侦察引擎模块。

## 核心功能

1. **TargetProfile 数据模型**：侦察引擎与攻击引擎之间的唯一接口契约
2. **ReconEngine 统一调度器**：编排 5 个开源工具的执行顺序、并发和错误处理
3. **5 个工具适配器**：LLMmap（Python import）、Garak（Python SDK）、DeepTeam（Python import）、Augustus（CLI subprocess）、AIMap（CLI subprocess）
4. **ProfileMerger 结果合并器**：多工具输出合并去重 + 置信度加权
5. **CLI 扩展**：新增 `recon` 子命令，`run` 命令增加 `--profile` 和 `--auto-recon` 参数
6. **Attack ProfileLoader**：读取 TargetProfile → SmartMatcher 参数
7. **测试套件**：覆盖所有新增模块的单元测试

## 设计约束

- reconnaissance/ 不 import attack/ 或 orchestrators/
- 两者通过 target_profile.json 文件通信
- 每个 Adapter ≤100 行
- 遵循现有项目模式（dataclass 模型、argparse CLI、unittest 测试）
- 所有 Python 文件强制 UTF-8 头（Windows 兼容）

## 技术方案

### 架构模式

```
┌──────────────────────────────────────────────────────────────┐
│                     cli.py (薄壳路由)                          │
│              recon 命令 │ run 命令 (--profile)                 │
└──────────┬───────────────────────────────────┬───────────────┘
           │                                   │
           ▼                                   ▼
┌──────────────────────────┐      ┌──────────────────────────┐
│    ReconEngine           │      │    Attack Engine          │
│    (统一调度)             │      │    (已有)                 │
│                          │      │                          │
│  ┌────────────────────┐  │      │  ┌────────────────────┐  │
│  │ Adapters (薄壳)     │  │      │  │ ProfileLoader       │  │
│  │ ├ LLMmap (import)  │  │      │  │ (读 Profile JSON)   │  │
│  │ ├ Garak (SDK)      │  │      │  └────────┬───────────┘  │
│  │ ├ DeepTeam (import)│  │      │           │              │
│  │ ├ Augustus (CLI)   │  │      │           ▼              │
│  │ └ AIMap (CLI)      │  │      │  ┌────────────────────┐  │
│  └────────┬───────────┘  │      │  │ SmartMatcher       │  │
│           │              │      │  │ (已有，策略选择)    │  │
│  ┌────────▼───────────┐  │      │  └────────────────────┘  │
│  │ ProfileMerger      │  │      │                          │
│  │ → TargetProfile    │──┼──写──→│                          │
│  └────────────────────┘  │ 文件  │                          │
└──────────────────────────┘      └──────────────────────────┘
```

### 技术决策

| 决策 | 选择 | 原因 |
| --- | --- | --- |
| 数据模型 | Python dataclass | 与现有 PayloadProfile/ThreatModel 一致 |
| CLI 框架 | argparse | 与现有 cli.py 一致 |
| 测试框架 | unittest | 与现有 test_framework.py 一致 |
| 并发执行 | asyncio.gather | 与现有 AttackOrchestrator 一致 |
| 第三方调用 | import + subprocess | Python 工具 import，Go 工具 CLI |
| 接口契约 | JSON 文件 | 语言无关，模块完全解耦 |


### 关键接口

```python
# 适配器基类
class BaseAdapter(ABC):
    @abstractmethod
    def run(self, target: str, config: dict) -> dict:
        """执行侦察，返回原始结果"""
        ...

# 统一调度器
class ReconEngine:
    def run(self, target: str, depth: str, tools: list) -> TargetProfile:
        """调度所有适配器，合并结果，返回 TargetProfile"""
        ...

# 攻击引擎接入
class ProfileLoader:
    @staticmethod
    def load(path: str) -> dict:
        """读取 TargetProfile JSON → SmartMatcher 参数"""
        ...
```

### 目录结构

```
pyrit_ai300/
├── reconnaissance/              # 【新增】侦察引擎
│   ├── __init__.py              # 导出 ReconEngine, TargetProfile
│   ├── recon_engine.py          # 统一调度入口 (~150 行)
│   ├── target_profile.py        # TargetProfile 数据模型 (~120 行)
│   ├── profile_merger.py        # 多工具结果合并 (~80 行)
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base_adapter.py      # 抽象基类 (~30 行)
│   │   ├── llmmap_adapter.py    # → import LLMmap (~50 行)
│   │   ├── garak_adapter.py     # → import garak (~60 行)
│   │   ├── deepteam_adapter.py  # → import deepteam (~60 行)
│   │   ├── augustus_adapter.py  # → subprocess CLI (~40 行)
│   │   └── aimap_adapter.py     # → subprocess CLI (~40 行)
│   └── utils/
│       ├── __init__.py
│       ├── http_client.py       # HTTP 客户端 (~60 行)
│       └── result_parser.py     # JSONL/JSON 解析 (~50 行)
├── attack/                      # 【新增】攻击引擎适配
│   ├── __init__.py
│   └── profile_loader.py        # 读 Profile → SmartMatcher (~50 行)
├── tests/
│   └── test_recon/              # 【新增】侦察测试
│       ├── __init__.py
│       ├── test_target_profile.py
│       ├── test_recon_engine.py
│       └── test_adapters.py
config/
└── recon/                       # 【新增】侦察配置
    └── recon.yaml               # 侦察全局配置
data/
└── recon_templates/             # 【新增】探测模板
    ├── system_prompt.yaml       # System Prompt 探测
    ├── capability.yaml          # 能力探测
    └── boundary.yaml            # 防护边界测试
```

### 性能考量

- **并发执行**：所有适配器通过 asyncio.gather 并发执行，总耗时 = 最慢工具的耗时
- **超时控制**：每个适配器设置 30s 超时，超时后跳过该工具
- **结果缓存**：TargetProfile 保存为 JSON，避免重复侦察同一目标
- **新增代码量**：约 850 行，零重复造轮子

## Agent Extensions

无适用的扩展。本任务为纯代码实现，不需要外部 Skill、MCP 或 SubAgent。