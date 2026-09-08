# arXiv:2402.14266 - SKELETONKEY, SkeletonKey
# arXiv:2302.12173 - Greshake et al., Indirect prompt injection
# arXiv:2307.00929 - Zhan et al., InjecAgent
# MCPSec Bridge - mcpsec v2.7.2 (manthanghasadiya/mcpsec)
"""mcp_agent_target - PyRIT PromptChatTarget for MCP Server Integration.

Bridge between PyRIT Orchestrator and MCP (Model Context Protocol) servers.
Enables sending prompts to LLM agents that use MCP tools, and intercepting
observing MCP tool calls for attack verification.

Architecture:
    PyRIT Orchestrator → MCPAgentTarget → LLM Agent → MCP Server → Side-effects

Academic basis:
    - Hanna et al. (arXiv:2402.14266) - SkeletonKey, ASR 80-95%
    - Greshake et al. (arXiv:2302.12173) - Indirect prompt injection via tools
    - Zhan et al. (arXiv:2307.00929) - InjecAgent, tool call injection
    - MCPSec (manthanghasadiya/mcpsec) - MCP protocol fuzzing framework

Design principles:
    1. Implements pyrit.PromptChatTarget interface (R2: PyRIT Native First)
    2. Transparently forwards prompts to LLM agent
    3. Captures MCP tool call history for attack verification
    4. Observes side-effects (network requests, file writes) as ground truth
    5. Compatible with MCPSec scanners for automated vulnerability detection
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class MCPSideEffect:
    """Recorded side-effect from MCP tool execution.

    Used as ground truth for attack success verification.
    Side-effects are objective evidence that the attack succeeded,
    independent of response text analysis.
    """
    effect_type: str  # "network_request", "file_write", "env_read", "command_exec"
    tool_name: str
    arguments: dict[str, Any]
    result: Any = None
    timestamp: float = 0.0


@dataclass
class MCPToolCall:
    """Recorded MCP tool call for attribution analysis."""
    tool_name: str
    arguments: dict[str, Any]
    response: Any = None
    call_id: str = ""
    timestamp: float = 0.0


@dataclass
class MCPAgentTargetConfig:
    """Configuration for MCPAgentTarget.

    Attributes:
        endpoint_url: MCP server HTTP endpoint (e.g., http://localhost:8080/mcp)
        transport: MCP transport protocol ("http" or "stdio")
        stdio_command: Command for stdio transport
        auth_token: Optional Bearer <REDACTED> for authentication
        timeout: Request timeout in seconds
        record_side_effects: Whether to record MCP side-effects for verification
        max_tool_calls: Maximum tool calls per prompt (safety limit)
    """
    endpoint_url: Optional[str] = None
    transport: str = "http"
    stdio_command: Optional[str] = None
    auth_token: Optional[str] = None
    timeout: float = 30.0
    record_side_effects: bool = True
    max_tool_calls: int = 20


class MCPAgentTarget:
    """PyRIT-compatible target that interfaces with MCP-enabled LLM agents.

    This target bridges PyRIT's attack orchestration with MCP server testing:
    1. Sends prompts to the LLM agent via PromptChatTarget interface
    2. The LLM agent may invoke MCP tools (via MCP protocol)
    3. Records tool calls and side-effects for ground-truth verification

    Compatible with:
    - MCPSec scanners (prompt-injection, command-injection, path-traversal)
    - PyRIT PromptSendingAttack, SkeletonKeyAttack, CrescendoAttack
    - PyRIT AttackScoringConfig for first-success detection
    """

    def __init__(
        self,
        config: MCPAgentTargetConfig,
        *,
        objective_target: Any = None,
        **kwargs: Any,
    ) -> None:
        """Initialize MCPAgentTarget.

        Args:
            config: MCP connection configuration
            objective_target: Optional PyRIT PromptTarget for direct HTTP fallback
            **kwargs: Additional arguments for compatibility
        """
        self._config = config
        self._objective_target = objective_target
        self._tool_calls: list[MCPToolCall] = []
        self._side_effects: list[MCPSideEffect] = []
        self._session_id = str(uuid.uuid4())[:8]

        logger.info(
            "MCPAgentTarget initialized: transport=%s, endpoint=%s, session=%s",
            config.transport,
            config.endpoint_url or config.stdio_command,
            self._session_id,
        )

    @property
    def tool_calls(self) -> list[MCPToolCall]:
        """Return recorded MCP tool calls."""
        return list(self._tool_calls)

    @property
    def side_effects(self) -> list[MCPSideEffect]:
        """Recorded side-effects for attack verification."""
        return list(self._side_effects)

    def has_side_effects(self) -> bool:
        """Check if any side-effects were recorded (ground-truth for success)."""
        return len(self._side_effects) > 0

    def get_side_effects_by_type(self, effect_type: str) -> list[MCPSideEffect]:
        """Filter side-effects by type."""
        return [e for e in self._side_effects if e.effect_type == effect_type]

    async def send_prompt_async(self, **kwargs: Any) -> Any:
        """Send prompt to MCP-enabled LLM agent.

        Implements PyRIT PromptChatTarget interface.
        Prompts are forwarded to the LLM agent which may invoke MCP tools.

        Compatible with PyRIT's PromptSendingAttack and SkeletonKeyAttack.

        Args:
            **kwargs: PyRIT prompt parameters
                - prompt_pieces: list of PromptPiece
                - conversation_id: str

        Returns:
            PromptResponseBase-compatible result
        """

        from pyrit.models import (
            PromptRequestPiece,
            PromptRequestResponse,
            PromptResponseError,
        )

        # Extract prompt text from kwargs
        prompt_pieces = kwargs.get("prompt_pieces", [])
        prompt_text = ""
        for piece in prompt_pieces:
            if hasattr(piece, "converted_value"):
                prompt_text = piece.converted_value
                break
            elif hasattr(piece, "original_value"):
                prompt_text = piece.original_value
                break

        if not prompt_text:
            logger.warning("MCPAgentTarget: empty prompt received")
            request_piece = PromptRequestPiece(
                role="user",
                original_value="",
                conversation_id=kwargs.get("conversation_id", str(uuid.uuid4())),
            )
            return PromptRequestResponse(
                request_pieces=[
                    PromptRequestPiece(
                        role="assistant",
                        original_value="[ERROR] Empty prompt",
                    )
                ],
                response_error=PromptResponseError.UNPROCESSABLE_REQUEST,
            )

        # Forward to objective target (HTTP-based LLM agent)
        if self._objective_target is not None:
            try:
                response = await asyncio.wait_for(
                    self._objective_target.send_prompt_async(**kwargs),
                    timeout=self._config.timeout,
                )
                # After response, check for MCP side-effects
                # (actual implementation depends on MCP interception method)
                self._record_intercepted_mcp_calls(prompt_text)
                return response
            except asyncio.TimeoutError:
                logger.warning(
                    "MCPAgentTarget: timeout after %ss",
                    self._config.timeout,
                )
                return PromptRequestResponse(
                    request_pieces=[
                        PromptRequestPiece(
                            role="assistant",
                            original_value="[ERROR] Request timeout",
                        )
                    ],
                    response_error=PromptResponseError.OTHER,
                )
            except Exception as e:
                logger.debug("MCPAgentTarget: send failed: %s", e)
                return PromptRequestResponse(
                    request_pieces=[
                        PromptRequestPiece(
                            role="assistant",
                            original_value=f"[ERROR] {e}",
                        )
                    ],
                    response_error=PromptResponseError.OTHER,
                )

        # Fallback: simulate MCP agent response
        logger.debug(
            "MCPAgentTarget: no objective_target, returning stub response"
        )
        request_piece = PromptRequestPiece(
            role="assistant",
            original_value=self._simulate_agent_response(prompt_text),
            conversation_id=kwargs.get("conversation_id", str(uuid.uuid4())),
        )
        return PromptRequestResponse(request_pieces=[request_piece])

    def _record_intercepted_mcp_calls(self, prompt_text: str) -> None:
        """Record MCP tool calls intercepted during agent execution.

        In production, this would integrate with:
        - MCP proxy that intercepts JSON-RPC calls
        - Agent framework hooks (LangChain, AutoGPT, etc.)
        - MCPSec scanner results

        For now, this is a hook for MCPSec integration.
        """
        # Placeholder: actual MCPSec integration populates this
        logger.debug(
            "MCPAgentTarget: prompt sent, MCP interception pending (use MCPSecBridge)"
        )

    def _simulate_agent_response(self, prompt: str) -> str:
        """Simulate an agent response for testing without actual LLM."""
        if "tool" in prompt.lower() or "mcp" in prompt.lower():
            return (
                "I've processed your request through the available MCP tools. "
                "The operation completed successfully."
            )
        return f"Response to: {prompt[:100]}"

    def clear_history(self) -> None:
        """Clear recorded tool calls and side-effects."""
        self._tool_calls.clear()
        self._side_effects.clear()

    def add_side_effect(self, effect: MCPSideEffect) -> None:
        """Record a side-effect (called by MCPSecBridge)."""
        self._side_effects.append(effect)
        logger.info(
            "MCPAgentTarget: side-effect recorded: type=%s, tool=%s",
            effect.effect_type,
            effect.tool_name,
        )

    def add_tool_call(self, call: MCPToolCall) -> None:
        """Record an MCP tool call."""
        self._tool_calls.append(call)


def create_mcp_agent_target(
    *,
    endpoint_url: Optional[str] = None,
    transport: str = "http",
    stdio_command: Optional[str] = None,
    auth_token: Optional[str] = None,
    objective_target: Any = None,
    **kwargs: Any,
) -> MCPAgentTarget:
    """Factory function for MCPAgentTarget.

    Args:
        endpoint_url: MCP server HTTP URL
        transport: "http" or "stdio"
        stdio_command: Command for stdio transport
        auth_token: Optional Bearer <REDACTED>
        objective_target: Optional PyRIT PromptTarget for HTTP forwarding
        **kwargs: Additional config options

    Returns:
        Configured MCPAgentTarget instance
    """
    config = MCPAgentTargetConfig(
        endpoint_url=endpoint_url,
        transport=transport,
        stdio_command=stdio_command,
        auth_token=auth_token,
        timeout=kwargs.get("timeout", 30.0),
        record_side_effects=kwargs.get("record_side_effects", True),
        max_tool_calls=kwargs.get("max_tool_calls", 20),
    )
    return MCPAgentTarget(config, objective_target=objective_target)
