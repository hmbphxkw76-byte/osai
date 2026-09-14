"""CP-012 S5 — core→recon 三对跨层符号收口接缝验证。

验证：
- ParsedBurpRequest / TargetFingerprint 已下沉 core（core._burp_models），
  recon._burp_models 仅作 re-export（core→recon 不再发生）。
- parse_burp_request / get_playwright_handles 经 core.adapter_registry 取用
  （recon 侧导入期登记，recon→core ✓），core 不再静态 import recon。
"""

from __future__ import annotations

import recon  # noqa: F401  # 触发 recon 侧接缝登记（recon→core ✓）
import recon._burp_models  # noqa: F401  # re-export 兼容路径
from core._burp_models import ParsedBurpRequest, TargetFingerprint
from core.adapter_registry import get_adapter


def test_parsed_burp_request_sunk_to_core() -> None:
    # 定义已下沉 core；recon 侧仅为 re-export，指向同一对象（无 core→recon 依赖）
    assert ParsedBurpRequest.__module__ == "core._burp_models"
    assert TargetFingerprint.__module__ == "core._burp_models"
    assert recon._burp_models.ParsedBurpRequest is ParsedBurpRequest
    assert recon._burp_models.TargetFingerprint is TargetFingerprint


def test_burp_adapter_symbols_resolvable_via_registry() -> None:
    # recon 导入期已登记；core 经 get_adapter 取用，不静态 import recon
    parse_burp_request = get_adapter("parse_burp_request")
    get_playwright_handles = get_adapter("get_playwright_handles")
    assert callable(parse_burp_request)
    assert callable(get_playwright_handles)
