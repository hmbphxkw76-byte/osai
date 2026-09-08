# MCPSec Factory - Unified entry point for MCPSec bridge creation
# Eliminates cross-layer dependencies (recon→strike) by providing shared factory
"""mcpsec_factory - Shared factory for MCPSec bridge instances.

Provides a unified entry point for creating MCPSecBridge instances,
eliminating cross-layer dependencies between recon/ and strike/ phases.

Usage:
    from tools.mcpsec_factory import create_mcpsec_bridge

    bridge = create_mcpsec_bridge()
    if bridge.is_available:
        results = await bridge.scan_target("http://target:8080/mcp")

Reference: MCPSec v2.7.2 (manthanghasadiya/mcpsec)
"""

from __future__ import annotations

from typing import Optional

# Re-export from strike/mcpsec_bridge.py (SSOT location)
from strike.mcpsec_bridge import (
    MCPSecBridge,
    MCPSecBridgeConfig,
    MCPSecScanResult,
    create_mcpsec_bridge,
)

__all__ = [
    "MCPSecBridge",
    "MCPSecBridgeConfig",
    "MCPSecScanResult",
    "create_mcpsec_bridge",
]


def get_shared_bridge(
    *,
    timeout: float = 120.0,
    intensity: str = "high",
    use_ai: bool = False,
) -> Optional[MCPSecBridge]:
    """Get a shared MCPSec bridge instance with standard configuration.

    This is the recommended way to get a bridge instance for reconnaissance
    and other non-attack phases. For attack phases, use create_mcpsec_bridge()
    directly to get phase-specific configuration.

    Args:
        timeout: Command timeout in seconds
        intensity: Fuzz intensity (low/medium/high/insane)
        use_ai: Enable AI-powered payload generation

    Returns:
        MCPSecBridge instance, or None if MCPSec not available
    """
    bridge = create_mcpsec_bridge(
        timeout=timeout,
        intensity=intensity,
        use_ai=use_ai,
    )
    return bridge if bridge.is_available else None
