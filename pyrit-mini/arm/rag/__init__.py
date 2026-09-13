"""arm/rag — object-axis converter façade for `rag`.

Re-exports the generic converter API from arm.converter_presets so that
`arm.rag` is a valid, object-keyed entry point for `--converters rag`.
"""
from arm.converter_presets import (  # noqa: F401
    _classify_target_type,
    _is_file_converter,
    build_converter_map,
    l5_optimal,
    l5_optimal_for_model,
)
from arm.rag.preset import TARGET_TYPE, build_converters, candidate_converters  # noqa: F401

OBJECT = "rag"
