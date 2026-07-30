"""
PyRIT AI-300 - 端到端全自动 AI 红队框架

本框架基于 PyRIT 1.0.0 构建，为 OffSec AI-300 考试和实际 AI 红队评估提供
数据驱动的端到端全自动提示词层面攻击流程。

核心特点:
- 原生优先：充分利用 PyRIT 80+ Converter、40+ Scorer、20+ Attack 组件
- 数据驱动：所有配置从 YAML 文件读取，无硬编码
- PyRIT 优势聚焦：仅在提示词攻击领域使用 PyRIT，非优势领域推荐外部工具
- 顺序管道：简化的顺序管道架构，易于调试和维护

目录结构:
    src/
        core/           # 核心模型和配置加载
        converters/     # Converter 链配置和注册
        scorers/        # Scorer 配置和注册
        executor/       # 攻击执行子系统（对齐 pyrit.executor 五层架构）
        payloads/       # 数据集五层架构（①→②→②.5→③）
        targets/        # 目标 Target 工厂（含 PyRIT 原生认证）
        recon/          # 侦察层（仅 PyRIT 原生支持的部分）
        analysis/       # 分析层
        reporting/      # 报告层
        exam/           # 考试专用功能
    config/             # 配置文件
    docs/               # 架构设计文档
    pipeline.py         # 主入口

开发规则（见 docs/architecture_design.md §1.4）:
1. 原生优先原则：优先使用 PyRIT 原生组件
2. 避免硬编码原则：所有参数从配置文件读取
3. PyRIT 优势边界原则：非优势领域推荐外部工具
4. 数据结构传递原则：使用 Pydantic 模型
5. 错误处理原则：使用 PyRIT 原生异常
6. 代码组织原则：按功能模块组织
7. 非PyRIT领域排除原则：非PyRIT领域不使用PyRIT实现

性能优化 (v8.2):
  本模块不执行任何 eager import。所有子模块按需加载，
  避免在 import src 时触发 src.payloads (20+ 模块) 和
  src.core (registry_manager 等) 的完整加载链。
  经测试：eager import 导致 ~5s 启动延迟，lazy import 降至 ~0ms。
  代码应直接从子模块导入，如:
    from src.core.config_loader import get_config_loader  # ✓
    from src.core.models import ReconResult               # ✓
  而非:
    from src import ReconResult                           # ✗ 不再支持
"""

__version__ = "1.0.0"
__author__ = "PyRIT AI-300 Team"
__pyrit_version__ = "1.0.0"
