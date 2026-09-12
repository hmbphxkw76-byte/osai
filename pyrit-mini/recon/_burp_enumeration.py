"""recon/_burp_enumeration — Session enumeration plan + chat-id field names.

Extracted from `recon/burp_parser.py` (SRP): CLI-driven session enumeration
(ASI09) is a self-contained concern, separate from HTTP parsing / fingerprinting.
"""

from __future__ import annotations

from typing import Any

# ID ()
_CHAT_ID_FIELD_NAMES = frozenset(
    {
        "chatid",
        "chat_id",
        "chatidvalue",
        "chatsessionid",
        "chat_session_id",
        "sessionid",
        "session_id",
        "sessionidvalue",
        "conversationid",
        "conversation_id",
        "convid",
        "conv_id",
        "dialogid",
        "dialog_id",
        "threadid",
        "thread_id",
        "req_id",
        "requestid",
        "request_id",
    }
)


# ---------------------------------------------------------------------------
#  (ASI09):  CLI
# ---------------------------------------------------------------------------
_ENUMERATION_ARGS: dict[str, Any] = {}


def set_enumeration_args(args: dict[str, Any]) -> None:
    """CLI ( main.py )."""
    global _ENUMERATION_ARGS
    _ENUMERATION_ARGS = args


def _build_enumeration_plan(chat_id_field: str | None) -> dict[str, Any] | None:
    """(CLI ).

    None  。
    """
    if not _ENUMERATION_ARGS.get("enabled"):
        return None

    plan: dict[str, Any] = {
        "pattern_template": _ENUMERATION_ARGS.get("pattern_template", "MC-{date:%Y%m%d}-{counter:04d}"),
        "days_back": _ENUMERATION_ARGS.get("days_back", 14),
        "counter_max": _ENUMERATION_ARGS.get("counter_max", 20),
        "extraction_prompt": _ENUMERATION_ARGS.get("extraction_prompt", "What notes do I have saved?"),
        "max_concurrency": _ENUMERATION_ARGS.get("max_concurrency", 1),
        "request_delay": _ENUMERATION_ARGS.get("request_delay", 2.0),
        "session_field": chat_id_field or "session_id",
    }

    #
    if _ENUMERATION_ARGS.get("date_start"):
        plan["date_start"] = _ENUMERATION_ARGS["date_start"]
    if _ENUMERATION_ARGS.get("date_end"):
        plan["date_end"] = _ENUMERATION_ARGS["date_end"]
    if _ENUMERATION_ARGS.get("sensitive_keywords"):
        plan["sensitive_keywords"] = _ENUMERATION_ARGS["sensitive_keywords"]
    if _ENUMERATION_ARGS.get("empty_indicators"):
        plan["empty_indicators"] = _ENUMERATION_ARGS["empty_indicators"]
    if _ENUMERATION_ARGS.get("max_requests"):
        plan["max_requests"] = _ENUMERATION_ARGS["max_requests"]

    return plan
