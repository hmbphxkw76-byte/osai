# -*- coding: utf-8 -*-
"""P3 优化: Circuit Breaker + Whitebox 状态实例化改造."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ESCALATION = os.path.join(ROOT, "strike", "escalation.py")


def main():
    with open(ESCALATION, "r", encoding="utf-8") as f:
        text = f.read()

    changes = 0

    # 1. Remove global _circuit_breaker_states
    marker = "_circuit_breaker_states: dict[str, dict[str, Any]] = {}"
    if marker in text:
        text = text.replace(
            '# Circuit Breaker \u72b6\u6001\u8ffd\u8e2a (\u6280\u672f\u540d -> {failures, state, last_failure_time})\n'
            '# \u72b6\u6001: "closed" (\u6b63\u5e38), "open" (\u65ad\u5f00, \u8df3\u8fc7), "half-open" (\u63a2\u6d4b)\n'
            '_circuit_breaker_states: dict[str, dict[str, Any]] = {}',
            '# P3 \u4f18\u5316: _circuit_breaker_states \u5df2\u8fc1\u79fb\u81f3 ctx._circuit_breaker_states (\u5b9e\u4f8b\u5c5e\u6027)',
        )
        changes += 1
        print("1. _circuit_breaker_states marked for removal")

    # 2. Remove global _whitebox_confirmed
    if "_whitebox_confirmed: bool = False" in text:
        text = text.replace(
            '# \u767d\u76d2\u653b\u51fb\u786e\u8ba4\u72b6\u6001 (\u907f\u514d\u91cd\u590d\u786e\u8ba4)\n'
            '_whitebox_confirmed: bool = False',
            '# P3 \u4f18\u5316: _whitebox_confirmed \u5df2\u8fc1\u79fb\u81f3 ctx._whitebox_confirmed (\u5b9e\u4f8b\u5c5e\u6027)',
        )
        changes += 1
        print("2. _whitebox_confirmed marked for removal")

    # 3. Replace _reset_circuit_breakers function signature
    if "def _reset_circuit_breakers() -> None:" in text:
        text = text.replace(
            "def _reset_circuit_breakers() -> None:\n"
            '    """\u91cd\u7f6e\u6240\u6709 circuit breaker \u72b6\u6001 (\u901a\u5e38\u5728\u65b0\u653b\u51fb\u4f1a\u8bdd\u5f00\u59cb\u65f6\u8c03\u7528)."""\n'
            "    global _circuit_breaker_states\n"
            "    _circuit_breaker_states.clear()\n"
            '    logger.debug("L-02: Circuit breaker states reset")',
            "def _reset_circuit_breakers(ctx: Any = None) -> None:\n"
            '    """\u91cd\u7f6e\u6307\u5b9a ctx \u7684 circuit breaker \u72b6\u6001."""\n'
            "    if ctx is not None:\n"
            "        ctx._circuit_breaker_states.clear()\n"
            '        logger.debug("L-02: Circuit breaker states reset for ctx")\n'
            "    else:\n"
            '        logger.debug("L-02: No ctx, circuit breaker reset skipped")',
        )
        changes += 1
        print("3. _reset_circuit_breakers updated")

    # 4. Add P3 comment to _is_circuit_open (minimal change to use ctx)
    if "def _is_circuit_open(technique_name: str, ctx: Any | None = None) -> bool:" in text:
        text = text.replace(
            "    state_info = _circuit_breaker_states.get(technique_name)",
            "    # P3: \u4ece ctx \u8bfb\u53d6\u72b6\u6001 (\u5b9e\u4f8b\u5316)\n"
            "    cb_states = getattr(ctx, '_circuit_breaker_states', None)\n"
            "    state_info = cb_states.get(technique_name) if cb_states is not None else None",
        )
        changes += 1
        print("4. _is_circuit_open updated")

    # 5. Add P3 comment to _record_technique_result
    if "def _record_technique_result(technique_name: str, success: bool, ctx: Any | None = None) -> None:" in text:
        text = text.replace(
            "    state_info = _circuit_breaker_states.setdefault(\n"
            '        technique_name,\n'
            '        {"failures": 0, "state": "closed", "last_failure_time": 0.0},\n'
            "    )",
            "    # P3: \u4ece ctx \u8bfb\u53d6\u72b6\u6001 (\u5b9e\u4f8b\u5316)\n"
            "    cb_states = getattr(ctx, '_circuit_breaker_states', None)\n"
            '    state_info = cb_states.setdefault(technique_name, {"failures": 0, "state": "closed", "last_failure_time": 0.0}) if cb_states is not None else None\n'
            "    if state_info is None:\n"
            "        return",
        )
        changes += 1
        print("5. _record_technique_result updated")

    # 6. Update _reset_whitebox_confirmation
    if "def _reset_whitebox_confirmation() -> None:" in text:
        text = text.replace(
            "def _reset_whitebox_confirmation() -> None:\n"
            '    """\u91cd\u7f6e\u767d\u76d2\u786e\u8ba4\u72b6\u6001.\n'
            "\n"
            "    \u901a\u5e38\u5728\u65b0\u7684\u653b\u51fb\u4f1a\u8bdd\u5f00\u59cb\u65f6\u8c03\u7528, \u4ee5\u4fbf\u91cd\u65b0\u786e\u8ba4\u767d\u76d2\u653b\u51fb.\n"
            '    """\n'
            "    global _whitebox_confirmed\n"
            "    _whitebox_confirmed = False\n"
            '    logger.debug("\u767d\u76d2\u786e\u8ba4\u72b6\u6001\u5df2\u91cd\u7f6e")',
            "def _reset_whitebox_confirmation(ctx: Any = None) -> None:\n"
            '    """\u91cd\u7f6e\u767d\u76d2\u786e\u8ba4\u72b6\u6001 (\u4ece ctx \u5b9e\u4f8b)."""\n'
            "    if ctx is not None:\n"
            "        ctx._whitebox_confirmed = False\n"
            '        logger.debug("\u767d\u76d2\u786e\u8ba4\u72b6\u6001\u5df2\u91cd\u7f6e (ctx)")',
        )
        changes += 1
        print("6. _reset_whitebox_confirmation updated")

    # 7. Update _confirm_whitebox_attack to use ctx
    if "global _whitebox_confirmed" in text:
        text = text.replace(
            "    global _whitebox_confirmed\n"
            "    if _whitebox_confirmed:\n"
            "        return True\n",
            "    # P3: \u4ece ctx \u8bfb\u53d6\u767d\u76d2\u786e\u8ba4\u72b6\u6001\n"
            "    _wc = getattr(ctx, '_whitebox_confirmed', False) if ctx else False\n"
            "    if _wc:\n"
            "        return True\n",
        )
        changes += 1
        print("7a. _confirm_whitebox_attack global read updated")

    if "_whitebox_confirmed = True" in text:
        text = text.replace(
            "    _whitebox_confirmed = True\n"
            '    logger.info("\u767d\u76d2\u653b\u51fb\u5df2\u786e\u8ba4, \u540e\u7eed\u4e0d\u518d\u91cd\u590d\u786e\u8ba4")',
            "    # P3: \u5199\u5165 ctx \u5b9e\u4f8b\n"
            "    if ctx is not None:\n"
            "        ctx._whitebox_confirmed = True\n"
            '    logger.info("\u767d\u76d2\u653b\u51fb\u5df2\u786e\u8ba4, \u540e\u7eed\u4e0d\u518d\u91cd\u590d\u786e\u8ba4")',
        )
        changes += 1
        print("7b. _confirm_whitebox_attack global write updated")

    with open(ESCALATION, "w", encoding="utf-8") as f:
        f.write(text)

    print(f"\nTotal changes: {changes}")
    return changes


if __name__ == "__main__":
    main()
