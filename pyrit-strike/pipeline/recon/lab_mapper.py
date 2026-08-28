"""lab_mapper — 向后兼容别名模块.

旧名称 (LabMapper, LabEntry) 作为 TargetMapper, ProfileEntry 的别名,
保留向后兼容性. 新代码应使用 target_mapper 模块.

参见: target_mapper.py, target_profiles.yaml
"""

from __future__ import annotations

from pipeline.recon.target_mapper import ProfileEntry, TargetMapper

# ── 向后兼容别名 ──
LabMapper = TargetMapper
"""LabMapper 是 TargetMapper 的旧名别名, 保留向后兼容."""

LabEntry = ProfileEntry
"""LabEntry 是 ProfileEntry 的旧名别名, 保留向后兼容."""

__all__ = ["LabMapper", "LabEntry", "TargetMapper", "ProfileEntry"]
