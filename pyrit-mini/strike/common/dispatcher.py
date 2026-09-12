# arXiv:2302.12173 - Greshake et al., PromptSendingAttack (PoisonedDocs)
# arXiv:2405.17350 - Mehrabi et al., TAPAttack (Tree-based Automated Prompting)
"""strike/dispatcher.py — Unified attack surface + strategy routing

Routes --target (attack surface) + --strike (strategy) to appropriate modules:

    Target (Attack Surface)     Strategy (Attack Module)
    ─────────────────────       ───────────────────────
    a2a  (multi-agent)          prompt_sending  → PromptSendingAttack
    mcp  (model context)        crescendo       → CrescendoAttack
    rag  (retrieval-augmented)   tap             → TAPAttack
    session (auth/session)      pair            → PairAttack
    memory (agent memory)       gcg             → GCGAttack
    web  (browser/injection)    native          → native PyRIT
    model (direct LLM)          first_success    → FIRST_SUCCESS mode
                                many_shot       → ManyShotJailbreakAttack
                                figstep         → FigStepAttack
                                sleeper         → SleeperAgentAttack

    Progressive Mode (--strike <target>):
                                progressive     → ProgressiveStrike (auto-escalation)
                                Phase 1: Single-turn → Phase 2: Multi-turn → Phase 3: Iterative → Phase 4: Advanced

Usage:
    from strike.common.dispatcher import AttackDispatcher
    dispatcher = AttackDispatcher(target="a2a", strike="prompt_sending")
    results = await dispatcher.execute(ctx)

    # Progressive mode: auto-escalation based on ASR
    dispatcher = AttackDispatcher(strike="a2a")  # target passed as strike
    results = await dispatcher.execute_progressive(ctx)

Academic basis:
    - NIST SP 800-115 Sec4: Attack surface enumeration
    - PyRIT (arXiv:2407.01232): Native attack framework
    - CrescendoAttack (arXiv:2404.01833): Multi-turn escalation
    - PAIR (arXiv:2310.08419): Iterative refinement
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ============================================================================
# Attack Module Imports (lazy-loaded to avoid circular imports)
# ============================================================================

# Strategy → PyRIT 1.0.1 attack class mapping (verified real import paths).
# PyRIT 1.0.1 exposes these under `pyrit.executor.attack.*`; the legacy
# `pyrit.attacks.*` namespace does not exist (R-DRIFT-1 / R-NATIVE-1).
STRATEGY_MAP: dict[str, str] = {
    "prompt_sending": "pyrit.executor.attack.PromptSendingAttack",
    "crescendo": "pyrit.executor.attack.CrescendoAttack",
    "tap": "pyrit.executor.attack.TAPAttack",
    "pair": "pyrit.executor.attack.PAIRAttack",
    "many_shot": "pyrit.executor.attack.ManyShotJailbreakAttack",
}

# Strategies with no direct PyRIT 1.0.1 single attack class:
#   gcg     → suffix-pool optimization (ADR-002), no gradient/native class
#   figstep → VLM carrier injection, implemented by strike/model/multimodal.py
#   sleeper → backdoor trigger activation, implemented by strike/model/backdoor.py
# These remain valid CLI strategy names (ALL_STRATEGIES) but are routed to the
# native executor with an explicit warning — no silent fallback (R-H1).
NON_NATIVE_STRATEGIES: frozenset[str] = frozenset({"gcg", "figstep", "sleeper"})

# Target → Seed category mapping (which seed directories to load)
# 与 data/seeds/ 目录结构对齐 (a2a/mcp/rag/model/web/memory/session)
TARGET_SEED_MAP: dict[str, list[str]] = {
    "a2a": ["a2a"],
    "mcp": ["mcp"],
    "rag": ["rag"],
    "session": ["session"],
    "memory": ["memory"],
    "web": ["web"],
    "model": ["model", "_core"],  # model 包含核心种子
}

# Target → Compatible strategies mapping
TARGET_STRATEGY_COMPATIBILITY: dict[str, list[str]] = {
    "a2a": ["prompt_sending", "crescendo", "tap", "native", "first_success"],
    "mcp": ["prompt_sending", "tap", "pair", "native", "first_success"],
    "rag": ["prompt_sending", "tap", "pair", "native", "first_success"],
    "session": ["prompt_sending", "crescendo", "native", "first_success"],
    "memory": ["prompt_sending", "crescendo", "tap", "native", "first_success"],
    "web": ["prompt_sending", "native", "many_shot"],
    "model": [
        "prompt_sending",
        "crescendo",
        "tap",
        "pair",
        "gcg",
        "native",
        "first_success",
        "many_shot",
        "figstep",
        "sleeper",
    ],
}

# All valid target names (for progressive mode detection)
ALL_TARGETS: set[str] = set(TARGET_SEED_MAP.keys())

# All valid strategy names
ALL_STRATEGIES: set[str] = set(STRATEGY_MAP.keys()) | set(NON_NATIVE_STRATEGIES) | {"native", "first_success"}

# BL-031 闭合：technique 标签 → Executor 策略。
# 此前 `ctx.techniques` 只喂 Converter（`build_converter_map`），不驱动执行；
# 此处把 technique 名映射到 dispatcher 的合法 strategy，使 `--techniques tap`
# 真正强制 TAPAttack 执行（非仅影响 Converter 链）。归属 REQ-151 PlaybookEngine
# 的同一调度通道（AttackDispatcher），不新建第二套链机制（C3）。
TECHNIQUE_STRATEGY_MAP: dict[str, str] = {
    "tap": "tap",
    "pair": "pair",
    "crescendo": "crescendo",
    "prompt_sending": "prompt_sending",
    "many_shot": "many_shot",
    "gcg": "gcg",
    "figstep": "figstep",
    "sleeper": "sleeper",
    "first_success": "first_success",
}


def resolve_technique_strategy(
    techniques: list[str] | None,
    target: str | None = None,
    fallback: str = "prompt_sending",
) -> str:
    """BL-031：从 `ctx.techniques` 派生 Executor 策略（首项合法即命中）。

    仅当策略与目标兼容（或在 native/first_success 通用档）时才采纳，否则回退。
    """
    if not techniques:
        return fallback
    compat = TARGET_STRATEGY_COMPATIBILITY.get(target) if target else None
    for tech in techniques:
        strat = TECHNIQUE_STRATEGY_MAP.get(tech)
        if strat and strat in ALL_STRATEGIES:
            if compat is None or strat in compat or strat in ("native", "first_success"):
                return strat
    return fallback


# ============================================================================
# Attack Dispatcher
# ============================================================================


@dataclass
class DispatchResult:
    """Result of attack dispatch execution"""

    target: str
    strategy: str
    success: bool
    attack_count: int
    error: str | None = None
    progressive_result: dict[str, Any] | None = None


class AttackDispatcher:
    """Routes target + strategy to attack execution modules

    Usage:
        dispatcher = AttackDispatcher(target="a2a", strike="prompt_sending")
        result = await dispatcher.execute(ctx)

    Progressive Mode:
        dispatcher = AttackDispatcher(strike="a2a")  # target as strike → progressive
        result = await dispatcher.execute_progressive(ctx)
    """

    def __init__(
        self,
        target: str | None = None,
        strike: str | None = None,
    ):
        self.target = target
        self.strike = strike or "prompt_sending"
        self._is_progressive = False
        self._validate()

    def _validate(self) -> None:
        """Validate target + strategy compatibility"""
        # Check if strike is actually a target name (progressive mode)
        if self.strike in ALL_TARGETS and self.target is None:
            self._is_progressive = True
            self.target = self.strike
            logger.info(
                "[DISPATCHER] Progressive mode detected: target=%s (from --strike %s)",
                self.target,
                self.strike,
            )
            return

        if self.target and self.target not in TARGET_SEED_MAP:
            raise ValueError(f"Unknown target: {self.target}. Valid targets: {list(TARGET_SEED_MAP.keys())}")

        if self.strike not in ALL_STRATEGIES:
            raise ValueError(f"Unknown strategy: {self.strike}. Valid strategies: {list(ALL_STRATEGIES)}")

        # Check target-strategy compatibility
        if self.target:
            compatible = TARGET_STRATEGY_COMPATIBILITY.get(self.target, [])
            if self.strike not in compatible and self.strike not in ("native", "first_success"):
                logger.warning(
                    "Strategy '%s' may not be fully compatible with target '%s'. Compatible strategies: %s",
                    self.strike,
                    self.target,
                    compatible,
                )

    @property
    def is_progressive(self) -> bool:
        """Check if dispatcher is in progressive mode."""
        return self._is_progressive

    def get_seed_categories(self) -> list[str]:
        """Get seed categories for the current target"""
        if self.target:
            return TARGET_SEED_MAP.get(self.target, [])
        return ["elite_jailbreaks", "asi_top10", "owasp_full_coverage"]

    def get_strategy_class_path(self) -> str | None:
        """Get PyRIT attack class path for the current strategy"""
        return STRATEGY_MAP.get(self.strike)

    def bias_strategy_from_techniques(self, ctx: Any) -> str:
        """BL-031：未显式指定策略（用默认 prompt_sending）且 `ctx.techniques` 提供时，
        按技术标签派生 Executor 策略，使 `--techniques` 真正驱动执行（非仅 Converter）。

        显式 `--strike` 优先级最高；progressive 模式（strike 即 target）不覆盖。
        """
        if self._is_progressive or self.strike != "prompt_sending":
            return self.strike
        derived = resolve_technique_strategy(
            getattr(ctx, "techniques", None) or [], target=self.target,
            fallback=self.strike,
        )
        if derived != self.strike:
            logger.info(
                "[DISPATCHER] BL-031: techniques=%s → strategy=%s",
                getattr(ctx, "techniques", None), derived,
            )
        return derived

    async def execute(self, ctx: Any) -> DispatchResult:
        """Execute attack pipeline for the configured target + strategy

        Args:
            ctx: PipelineContext with args, seeds, converters, etc.

        Returns:
            DispatchResult with execution summary
        """
        # If in progressive mode, delegate to progressive executor
        if self._is_progressive:
            return await self.execute_progressive(ctx)

        # BL-031：技术路由闭合——让 ctx.techniques 驱动 Executor 策略选择
        self.strike = self.bias_strategy_from_techniques(ctx)

        logger.info(
            "[DISPATCHER] Target=%s, Strategy=%s, Seeds=%s",
            self.target,
            self.strike,
            self.get_seed_categories(),
        )

        try:
            # Select attack strategy
            if self.strike == "native":
                result = await self._execute_native(ctx)
            elif self.strike == "first_success":
                result = await self._execute_first_success(ctx)
            elif self.strike in STRATEGY_MAP:
                result = await self._execute_pyrit_attack(ctx, self.strike)
            elif self.strike in NON_NATIVE_STRATEGIES:
                # No PyRIT-native class for this strategy; its advanced-attack
                # module owns the logic. Route to native executor explicitly.
                logger.warning(
                    "[DISPATCHER] Strategy '%s' has no PyRIT-native attack class; "
                    "routing to native executor (advanced-attack module owns logic)",
                    self.strike,
                )
                result = await self._execute_native(ctx)
            else:
                # Default to prompt_sending
                result = await self._execute_pyrit_attack(ctx, "prompt_sending")

            return DispatchResult(
                target=self.target or "model",
                strategy=self.strike,
                success=True,
                attack_count=result.get("attack_count", 0),
            )

        except Exception as e:
            logger.error("[DISPATCHER] Execution failed: %s", e)
            return DispatchResult(
                target=self.target or "model",
                strategy=self.strike,
                success=False,
                attack_count=0,
                error=str(e),
            )

    async def execute_progressive(self, ctx: Any) -> DispatchResult:
        """Execute progressive attack with automatic escalation.

        Uses ProgressiveStrike to run Phase 1 (single-turn) → evaluate ASR →
        auto-escalate to multi-turn/iterative/advanced strategies as needed.

        Args:
            ctx: PipelineContext with seeds, target, converters

        Returns:
            DispatchResult with progressive execution summary
        """
        logger.info(
            "[DISPATCHER] Progressive mode: target=%s, auto-escalation enabled",
            self.target,
        )

        try:
            from strike.common.progressive_strike import ProgressiveStrike

            striker = ProgressiveStrike(
                target=self.target,
                ctx=ctx,
                stop_on_first_success=True,
            )
            progressive_result = await striker.execute()

            return DispatchResult(
                target=self.target,
                strategy="progressive",
                success=progressive_result.was_successful,
                attack_count=progressive_result.total_attacks,
                progressive_result=progressive_result.to_dict(),
            )

        except ImportError:
            logger.warning("[DISPATCHER] ProgressiveStrike not available, falling back to single-turn")
            # Fallback to single-turn prompt_sending
            self.strike = "prompt_sending"
            return await self.execute(ctx)
        except Exception as e:
            logger.error("[DISPATCHER] Progressive execution failed: %s", e)
            return DispatchResult(
                target=self.target,
                strategy="progressive",
                success=False,
                attack_count=0,
                error=str(e),
            )

    async def _execute_native(self, ctx: Any) -> dict[str, Any]:
        """Execute using PyRIT native attack framework"""
        logger.info("[DISPATCHER] Using native PyRIT attack execution")
        # Delegate to existing strike/executor.py
        from strike.common.executor import execute_attacks

        return await execute_attacks(ctx)

    async def _execute_first_success(self, ctx: Any) -> dict[str, Any]:
        """Execute with FIRST_SUCCESS mode (stop on first successful attack)"""
        logger.info("[DISPATCHER] Using FIRST_SUCCESS mode")
        ctx.first_success = True
        from strike.common.executor import execute_attacks

        return await execute_attacks(ctx)

    async def _execute_pyrit_attack(self, ctx: Any, strategy: str) -> dict[str, Any]:
        """Execute specific PyRIT attack class"""
        class_path = STRATEGY_MAP.get(strategy)
        if not class_path:
            raise ValueError(f"No class path for strategy: {strategy}")

        logger.info("[DISPATCHER] Loading PyRIT attack: %s", class_path)

        # Dynamic import of PyRIT attack class
        module_path, class_name = class_path.rsplit(".", 1)
        try:
            import importlib

            module = importlib.import_module(module_path)
            attack_cls = getattr(module, class_name)
            ctx.attack_cls = attack_cls
            logger.info("[DISPATCHER] Loaded attack class: %s", attack_cls)
        except (ImportError, AttributeError) as e:
            # Clear any stale class from a previous strategy so the executor
            # cannot silently reuse the wrong attack class.
            ctx.attack_cls = None
            logger.warning(
                "[DISPATCHER] Failed to load %s: %s, falling back to native",
                class_path,
                e,
            )

        # Execute via native executor with selected attack class
        from strike.common.executor import execute_attacks

        return await execute_attacks(ctx)


# ============================================================================
# Convenience Functions
# ============================================================================


def create_dispatcher(
    target: str | None = None,
    strike: str | None = None,
) -> AttackDispatcher:
    """Factory function to create an AttackDispatcher

    Args:
        target: Attack surface (a2a, mcp, rag, session, memory, web, model)
        strike: Attack strategy (prompt_sending, crescendo, tap, pair, gcg, native, etc.)
                 OR target name for progressive mode (a2a, mcp, rag, etc.)

    Returns:
        Configured AttackDispatcher instance

    Usage:
        dispatcher = create_dispatcher(target="a2a", strike="prompt_sending")
        # Progressive mode: auto-escalation for target
        dispatcher = create_dispatcher(strike="a2a")
    """
    return AttackDispatcher(target=target, strike=strike)


def create_progressive_dispatcher(target: str, ctx: Any | None = None) -> AttackDispatcher:
    """Create a dispatcher in progressive mode for the given target.

    Args:
        target: Attack surface (a2a, mcp, rag, session, memory, web, model)
        ctx: Optional PipelineContext

    Returns:
        AttackDispatcher configured for progressive execution

    Usage:
        dispatcher = create_progressive_dispatcher("a2a")
        result = await dispatcher.execute_progressive(ctx)
    """
    dispatcher = AttackDispatcher(target=target, strike="prompt_sending")
    dispatcher._is_progressive = True
    return dispatcher


def list_targets() -> dict[str, list[str]]:
    """List all available targets and their compatible strategies

    Returns:
        Dict mapping target names to compatible strategy lists
    """
    return TARGET_STRATEGY_COMPATIBILITY.copy()


def list_strategies() -> dict[str, str]:
    """List all available strategies with their module paths

    Returns:
        Dict mapping strategy names to PyRIT class paths
    """
    result = STRATEGY_MAP.copy()
    result["native"] = "pyrit.executor.attack (native framework)"
    result["first_success"] = "strike.executor (FIRST_SUCCESS mode)"
    for name in sorted(NON_NATIVE_STRATEGIES):
        result[name] = f"strike.model (advanced-attack module; no PyRIT-native class) [{name}]"
    return result


def is_target(value: str) -> bool:
    """Check if a value is a valid target name (for progressive mode detection).

    Args:
        value: String to check

    Returns:
        True if value is a valid target name
    """
    return value in ALL_TARGETS


def is_strategy(value: str) -> bool:
    """Check if a value is a valid strategy name.

    Args:
        value: String to check

    Returns:
        True if value is a valid strategy name
    """
    return value in ALL_STRATEGIES
