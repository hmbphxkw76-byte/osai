"""pipeline — 攻击链路编排模块。

v57 重构: 从 main.py 提取核心逻辑, 实现关注点分离。

模块结构:
    - orchestrator: 主流程编排 (run, _run_single_endpoint, _run_single_endpoint_to_result)
    - logging_config: 日志配置 (_configure_logging, _switch_log_file)
    - cleanup: 资源清理 (_cleanup_resources)
"""

from pipeline.orchestrator import run
from pipeline.cleanup import cleanup_resources
from pipeline.logging_config import configure_logging, switch_log_file

__all__ = [
    "run",
    "cleanup_resources",
    "configure_logging",
    "switch_log_file",
]
