"""验证增量借鉴 5 项功能的参数解析."""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.config import (
    _parse_converter_global,
    _parse_converter_overrides,
    _parse_initializer_specs,
    _parse_memory_labels,
    _parse_seed_filters,
    parse_args,
)


def test_memory_labels():
    """借鉴1: --memory-labels."""
    result = _parse_memory_labels('{"run_id":"r001","target":"deepseek"}')
    assert result == {"run_id": "r001", "target": "deepseek"}, f"Got: {result}"
    assert _parse_memory_labels(None) == {}
    assert _parse_memory_labels({}) == {}
    assert _parse_memory_labels({"a": 1}) == {"a": "1"}
    print("OK: --memory-labels")


def test_seed_filters():
    """借鉴2: --seed-filters."""
    result = _parse_seed_filters("owasp_id=LLM01,difficulty=high")
    assert result == {"owasp_id": "LLM01", "difficulty": "high"}, f"Got: {result}"
    assert _parse_seed_filters(None) == {}
    assert _parse_seed_filters({}) == {}
    print("OK: --seed-filters")


def test_converter_overrides():
    """借鉴3: technique:converter.xxx 语法."""
    overrides = _parse_converter_overrides("l5_optimal;tap:persuasion;pair:decomposition,base64")
    assert overrides == {"tap": ["persuasion"], "pair": ["decomposition", "base64"]}, f"Got: {overrides}"
    assert _parse_converter_overrides("auto") == {}
    assert _parse_converter_overrides(None) == {}
    global_chain = _parse_converter_global("l5_optimal;tap:persuasion")
    assert global_chain == "l5_optimal", f"Got: {global_chain}"
    assert _parse_converter_global("auto") == "auto"
    print("OK: technique:converter.xxx")


def test_initializer_specs():
    """借鉴4: --add-initializer."""
    specs = _parse_initializer_specs(["MyInit,foo=bar,baz=qux", "OtherInit"])
    assert len(specs) == 2, f"Got: {specs}"
    assert specs[0] == {"class": "MyInit", "args": {"foo": "bar", "baz": "qux"}}, f"Got: {specs[0]}"
    assert specs[1] == {"class": "OtherInit", "args": {}}, f"Got: {specs[1]}"
    assert _parse_initializer_specs(None) == []
    print("OK: --add-initializer")


def test_full_parse_args():
    """借鉴5: 完整 parse_args 集成测试."""
    args = parse_args([
        "--memory-labels", '{"run_id":"r001"}',
        "--seed-filters", "owasp_id=LLM01",
        "--converters", "l5_optimal;tap:persuasion",
        "--add-initializer", "MyInit,foo=bar",
        "--config-file", "config/campaigns/default.yaml",
    ])
    assert args.memory_labels_parsed == {"run_id": "r001"}, f"Got: {args.memory_labels_parsed}"
    assert args.seed_filters_parsed == {"owasp_id": "LLM01"}, f"Got: {args.seed_filters_parsed}"
    assert args.converter_overrides == {"tap": ["persuasion"]}, f"Got: {args.converter_overrides}"
    assert args.converters == "l5_optimal", f"Got: {args.converters}"  # global part only
    assert len(args.initializer_specs) == 1, f"Got: {args.initializer_specs}"
    assert args.initializer_specs[0]["class"] == "MyInit"
    # config-file should have filled these from campaigns/default.yaml
    # v2: seeds list auto-normalized to CSV string for downstream .split(",")
    assert args.seeds == "_core/,_encoding_evasion/,_multilingual/", f"Got: {args.seeds}"
    assert args.techniques == "auto", f"Got: {args.techniques}"
    # ── 嵌套 section: scoring ──
    assert args.dual_judge_enabled is True, f"Got: {args.dual_judge_enabled}"
    assert args.best_of_n_retries == 5, f"Got: {args.best_of_n_retries}"
    # ── 嵌套 section: escalation ──
    assert args.escalation_asr_threshold == 90, f"Got: {args.escalation_asr_threshold}"
    assert args.post_l1_exit_threshold == 70, f"Got: {args.post_l1_exit_threshold}"
    assert args.crescendo_max_turns == 10, f"Got: {args.crescendo_max_turns}"
    assert args.tap_tree_width == 4, f"Got: {args.tap_tree_width}"
    assert args.pair_tree_depth == 4, f"Got: {args.pair_tree_depth}"
    # ── 嵌套 section: probe ──
    assert args.probe_timeout == 5, f"Got: {args.probe_timeout}"
    assert args.max_concurrent_probes == 10, f"Got: {args.max_concurrent_probes}"
    # ── 嵌套 section: adaptive ──
    assert args.adaptive_epsilon == 0.2, f"Got: {args.adaptive_epsilon}"
    # ── 嵌套 section: execution ──
    assert args.l5_optimal_paths == 7, f"Got: {args.l5_optimal_paths}"
    assert args.auto_seed_expansion_factor == 3, f"Got: {args.auto_seed_expansion_factor}"
    print("OK: --config-file integration (5-layer structure + list normalization)")


def test_backward_compat():
    """向后兼容: 不使用任何新参数时, 默认值保持不变."""
    args = parse_args([])
    assert args.seeds == "elite_jailbreaks,asi_top10,owasp_full_coverage"
    assert args.converters == "auto"
    assert args.techniques == "auto"
    assert args.memory_labels_parsed == {}
    assert args.seed_filters_parsed == {}
    assert args.converter_overrides == {}
    assert args.initializer_specs == []
    print("OK: backward compatibility")


def test_seed_filter_metadata():
    """借鉴2: _filter_by_metadata 函数."""
    from arm.seed_ranker import _filter_by_metadata

    seeds = [
        {"value": "test1", "metadata": {"owasp_id": "LLM01", "difficulty": "high"}},
        {"value": "test2", "metadata": {"owasp_id": "LLM02", "difficulty": "high"}},
        {"value": "test3", "metadata": {"owasp_id": "LLM01", "difficulty": "low"}},
        {"value": "test4", "metadata": {"owasp_id": "LLM01: Injection", "difficulty": "high"}},
    ]
    # Single filter
    result = _filter_by_metadata(seeds, {"owasp_id": "LLM01"})
    assert len(result) == 3, f"Expected 3, got {len(result)}"  # test1, test3, test4
    # AND filter
    result = _filter_by_metadata(seeds, {"owasp_id": "LLM01", "difficulty": "high"})
    assert len(result) == 2, f"Expected 2, got {len(result)}"  # test1, test4
    # No match → return all
    result = _filter_by_metadata(seeds, {"nonexistent": "value"})
    assert len(result) == 4, f"Expected 4 (fallback), got {len(result)}"
    print("OK: _filter_by_metadata")


if __name__ == "__main__":
    test_memory_labels()
    test_seed_filters()
    test_converter_overrides()
    test_initializer_specs()
    test_full_parse_args()
    test_backward_compat()
    test_seed_filter_metadata()
    print("\n=== All 5 增量借鉴 tests passed! ===")
