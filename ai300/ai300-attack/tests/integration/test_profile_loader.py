# -*- coding: utf-8 -*-
"""
Profile loader 集成测试
"""

import json
import tempfile
from pathlib import Path

from ai300_schemas import FingerprintData, TargetProfile

from ai300_attack.loaders import load_target_profile


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
