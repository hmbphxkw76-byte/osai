"""Stage 2 配置阶段单元测试"""

import json
from pathlib import Path

from pipeline.stage2_configure import (
    DEFAULT_BUFF_SPEC,
    build_probe_spec,
    build_selection,
    sort_by_tier,
)


def _sample_probes():
    return [
        {"name": "probes.knownbadsignatures.IndirectInjection", "tier": "tier1",
         "modality": {"in": ["text"], "out": ["text"]}},
        {"name": "probes.knownbadsignatures.DirectInjection", "tier": "tier1",
         "modality": {"in": ["text"], "out": ["text"]}},
        {"name": "probes.lmrc.DidYouMean", "tier": "tier3",
         "modality": {"in": ["text"], "out": ["text"]}},
    ]


def test_sort_by_tier_prioritizes_tier1(tmp_path):
    probes = sort_by_tier(_sample_probes())
    tiers = [p["tier"] for p in probes]
    assert tiers == ["tier1", "tier1", "tier3"]


def test_build_probe_spec_aggregates_to_namespace(tmp_path):
    specs = build_probe_spec(_sample_probes())
    # 两个 knownbadsignatures probe 聚合为 1 个 namespace 通配
    assert "probes.knownbadsignatures.*" in specs
    assert "probes.lmrc.*" in specs


def test_build_selection_writes_artifacts(tmp_path):
    filtered = tmp_path / "probe_candidates_filtered.json"
    filtered.write_text(json.dumps(_sample_probes()), encoding="utf-8")

    out = build_selection(filtered, "RUN01", str(tmp_path))
    sel = out["selection"]

    assert sel["total_selected"] == 3
    assert sel["buff_spec"] == DEFAULT_BUFF_SPEC
    assert Path(out["sel_path"]).exists()
    assert Path(out["spec_path"]).exists()

    # spec yaml 可被 yaml 解析且含 probe_spec
    import yaml
    spec = yaml.safe_load(Path(out["spec_path"]).read_text(encoding="utf-8"))
    assert "plugins" in spec
    assert spec["plugins"]["probe_spec"]


def test_build_selection_tier_filter(tmp_path):
    filtered = tmp_path / "probe_candidates_filtered.json"
    filtered.write_text(json.dumps(_sample_probes()), encoding="utf-8")

    out = build_selection(filtered, "RUN02", str(tmp_path), tier_filter=["tier1"])
    assert out["selection"]["total_selected"] == 2
