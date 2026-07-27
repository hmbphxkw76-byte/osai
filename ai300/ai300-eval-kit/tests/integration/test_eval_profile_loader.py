# -*- coding: utf-8 -*-
"""
Profile loader 集成测试
"""

import tempfile
from pathlib import Path

from ai300_schemas import FingerprintData, PyRITTargetConfig, TargetProfile

from ai300_eval_kit.loaders import load_pyrit_target, load_target_profile


def test_load_target_profile_from_json():
    """从 JSON 文件加载 TargetProfile"""
    profile = TargetProfile(
        target="https://example.com",
        fingerprint=FingerprintData(model_name="gpt-4"),
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "profile.json"
        path.write_text(profile.to_json(), encoding="utf-8")
        loaded = load_target_profile(path)
    assert loaded.target == "https://example.com"
    assert loaded.fingerprint.model_name == "gpt-4"


def test_load_pyrit_target_from_json():
    """从 JSON 文件加载 PyRIT target 配置"""
    target = PyRITTargetConfig(
        endpoint="https://api.example.com/v1/chat/completions",
        model_name="gpt-4",
        api_type="openai_compatible",
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "target.json"
        path.write_text(target.to_json(), encoding="utf-8")
        loaded = load_pyrit_target(path)
    assert loaded.endpoint == "https://api.example.com/v1/chat/completions"
    assert loaded.model_name == "gpt-4"
