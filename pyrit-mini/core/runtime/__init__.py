"""core/runtime/ - Runtime monitoring and drift detection modules.

These modules are NOT part of recon/ because they operate DURING attack execution,
not before it. They monitor target behavior changes and adapt strategy accordingly.

Modules:
    capability_drift: Detects guardrail updates, model changes, rate limiting
"""
from core.runtime.capability_drift import CapabilityDriftMonitor, CapabilitySnapshot, get_drift_monitor

__all__ = [
    "CapabilityDriftMonitor",
    "CapabilitySnapshot",
    "get_drift_monitor",
]
