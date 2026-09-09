"""Core layer — Pipeline context, configuration, orchestration & phase controllers.

This package is the backbone of the six-phase attack pipeline:
    - config.py: CLI parameter parsing, defaults.yaml SSOT, .env loading
    - context.py: PipelineContext dataclass carrying all data across phases
    - orchestrator.py: Re-exports from core/phases/ (executor/strike/arm/assess/report)
    - phases/: Individual phase implementations (recon/arm/strike/assess/report)
    - seed_*.py: Seed routing, dynamic generation, and quality assessment

Architecture role (per 10-ARCHITECTURE.md §2.1):
    core/ = Core layer; owns config parsing and PipelineContext;
           re-exports phase functions; **forbidden from carrying __main__**.

Academic basis:
    - PyRIT (arXiv:2407.01232): SequentialAttack + CentralMemory
    - Greshake et al. (arXiv:2302.12173): Attack pipeline lifecycle
"""

from core.cleanup import cleanup_resources, has_residual_resources
from core.config import ensure_output_dir, get_output_dir, parse_args, setup_environment
from core.context import PipelineContext, get_effective_concurrency
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
