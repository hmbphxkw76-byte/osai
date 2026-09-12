# -*- coding: utf-8 -*-
"""Query diversification & stealthy timing for RAG metadata collection.

SRP split from `metadata_parser.py` (R-DELIVERY-1): owns query rephrasing
(behavioral mimicry) and lognormal inter-query delays — the stealth layer,
independent of parsing/collection orchestration.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict

# Query diversification templates (semantic-preserving rephrasing)
# Each intent can be expressed in multiple ways to avoid keyword-based detection
_QUERY_DIVERSIFIER_TEMPLATES: dict[str, list[str]] = {
    "policy": [
        "Could you walk me through the {topic}?",
        "I need to understand our stance on {topic}.",
        "What does the team say about {topic}?",
        "Can you clarify the guidelines around {topic}?",
        "Where can I find info about {topic}?",
    ],
    "compliance": [
        "For the upcoming audit, what do I need to know about {topic}?",
        "How does {topic} align with our compliance requirements?",
        "Are there any regulatory concerns regarding {topic}?",
        "What documentation exists for {topic} compliance?",
    ],
    "technical": [
        "Explain how {topic} works in our setup.",
        "What's the current implementation for {topic}?",
        "How do we handle {topic} technically?",
        "I'm reviewing our {topic} configuration — can you summarize?",
        "What are the operational details for {topic}?",
    ],
    "general": [
        "Tell me more about {topic}.",
        "I'd like to learn about {topic}.",
        "What should I know regarding {topic}?",
        "Got a moment to explain {topic}?",
        "Can you brief me on {topic}?",
    ],
}

# Topic categories for behavioral mimicry (avoid abrupt topic jumps)
_TOPIC_CATEGORIES: dict[str, str] = {
    "PTO policy": "policy",
    "travel reimbursement": "policy",
    "employee benefits": "policy",
    "API rate limiting": "technical",
    "database backup": "technical",
    "deployment rollback": "technical",
    "incident response": "compliance",
    "password requirements": "compliance",
    "access control": "compliance",
    "change management": "process",
    "code review": "process",
    "testing requirements": "process",
    "data retention": "compliance",
    "GDPR compliance": "compliance",
    "data classification": "compliance",
    "executive compensation": "policy",
    "board meetings": "policy",
    "strategic plan": "policy",
    "M&A targets": "policy",
    "security policies": "compliance",
    "vendor management": "process",
    "budget approval": "process",
    "system architecture": "technical",
    "on-call procedures": "process",
}


def _diversify_query(intent: str, category: str = "general", variant_index: int = 0) -> str:
    """Generate a语义-preserving variant of a query intent.

    Uses category-specific templates to produce natural-sounding queries
    that avoid keyword-pattern detection while preserving retrieval semantics.

    Academic basis:
        - Query variation detection evasion (Crothers et al., arXiv:2306.05685)
        - Semantic-preserving paraphrasing (Gao et al., arXiv:2311.10536)

    Args:
        intent: Core topic/intent (e.g., "PTO policy")
        category: Category key for template selection
        variant_index: Which template variant to use

    Returns:
        Natural-language query variant
    """

    templates = _QUERY_DIVERSIFIER_TEMPLATES.get(category, _QUERY_DIVERSIFIER_TEMPLATES["general"])
    template = templates[variant_index % len(templates)]

    # Extract topic from intent (remove leading "What is the" etc.)
    topic = intent
    for prefix in ["What is the ", "What are the ", "Describe the ", "Explain the "]:
        if topic.startswith(prefix):
            topic = topic[len(prefix) :]
            break
    # Remove trailing question mark and lowercase first char for natural embedding
    topic = topic.rstrip("?").strip()
    if topic and topic[0].isupper():
        topic_lower = topic[0].lower() + topic[1:]
    else:
        topic_lower = topic

    return template.format(topic=topic_lower)


def _cluster_queries_by_topic(queries: list[str]) -> list[str]:
    """Reorder queries to group related topics (behavioral mimicry).

    Human users typically explore related topics in clusters rather than
    jumping randomly. This reordering mimics natural browsing patterns.

    Returns:
        Reordered queries with adjacent related topics
    """

    # Group queries by category
    category_buckets: dict[str, list[str]] = defaultdict(list)
    for q in queries:
        cat = "general"
        for keyword, category in _TOPIC_CATEGORIES.items():
            if keyword.lower() in q.lower():
                cat = category
                break
        category_buckets[cat].append(q)

    # Shuffle within each bucket (controlled randomness)
    for bucket in category_buckets.values():
        random.shuffle(bucket)

    # Interleave buckets to simulate natural session (1-2 related queries then switch)
    result = []
    categories = list(category_buckets.keys())
    random.shuffle(categories)

    for cat in categories:
        bucket = category_buckets[cat]
        # Take 1-2 queries from each bucket before switching
        chunk_size = random.randint(1, min(2, len(bucket)))
        result.extend(bucket[:chunk_size])
        # Remaining queries go back to pool for later
        for remaining in bucket[chunk_size:]:
            result.append(remaining)

    return result if result else queries


def _compute_lognormal_delay(
    base_seconds: float,
    sigma: float = 0.5,
    min_delay: float = 1.0,
    max_delay: float = 120.0,
) -> float:
    """Generate delay drawn from lognormal distribution.

    Lognormal distribution mimics human inter-query behavior:
    - Most delays cluster around typical reading/thinking time (5-15s)
    - Occasional long pauses (distraction, reading results)
    - Short gaps possible (quick follow-up)

    Academic basis:
        - Human-computer interaction timing studies (Crothers et al., 2023)
        - Behavioral biometrics evasion (Zhang et al., arXiv:2204.01326)

    Args:
        base_seconds: Median delay (mu parameter)
        sigma: Shape parameter (higher = more variance)
        min_delay: Floor value
        max_delay: Ceiling value (avoid excessive waits)

    Returns:
        Delay in seconds (lognormally distributed)
    """
    import random

    # Lognormal parameters
    mu = math.log(max(min_delay, base_seconds))
    delay = random.lognormvariate(mu, sigma)
    # Clamp to bounds
    return max(min_delay, min(max_delay, delay))
