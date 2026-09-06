"""core — 流水线编排、上下文、配置、日志、资源清理。"""

from core.config import ensure_output_dir, get_output_dir, parse_args, setup_environment
from core.context import PipelineContext, get_effective_concurrency
from core.cleanup import cleanup_resources, has_residual_resources
from core.logging_config import (
    configure_root_logging,
    flush_and_close_handlers,
    install_signal_handlers,
    setup_logging,
    switch_log_file,
)
from core.orchestrator import run_attack_pipeline, run_single_endpoint, run_single_endpoint_to_result

__all__ = [
    # Context
    "PipelineContext",
    "get_effective_concurrency",
    # Config
    "parse_args",
    "get_output_dir",
    "ensure_output_dir",
    "setup_environment",
    # Cleanup
    "cleanup_resources",
    "has_residual_resources",
    # Logging
    "configure_root_logging",
    "flush_and_close_handlers",
    "install_signal_handlers",
    "setup_logging",
    "switch_log_file",
    # Orchestrator
    "run_attack_pipeline",
    "run_single_endpoint",
    "run_single_endpoint_to_result",
]
