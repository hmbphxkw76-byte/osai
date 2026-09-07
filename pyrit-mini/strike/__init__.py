# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2407.01232 — PyRIT, framework foundation
# arXiv:2302.12173 — Greshake et al., PromptSendingAttack
# arXiv:2402.07967 — Shafran et al., RAG Security Survey
# arXiv:2106.09685 — Hu et al., LoRA: Low-Rank Adaptation
# arXiv:2307.14924 — Shu et al., Backdoor Attacks on LLMs
# arXiv:2301.11916 — Hubinger et al., Sleeper Agents
"""strike - Attack execution module.

6-phase attack pipeline with PyRIT native AttackExecutor:

Core modules:
    - executor: PromptSendingAttack execution (FIRST_SUCCESS)
    - arm/converter_selector: Converter selection + OWASP mapping (arm/)
    - escalation: Multi-level escalation (Crescendo/TAP/PAIR/GCG)
    - adaptive_executor: PyRIT TextAdaptive + Best-of-N

AI300 Gap modules (OffSec AI-300 exam coverage):
    - embedding_poisoning: RAG vector DB active poisoning
    - lora_security_probe: LoRA adapter security testing
    - cicd_supply_chain_attack: CI/CD pipeline exploitation
    - a2a_protocol_injection: Multi-agent A2A protocol attacks
    - backdoor_verification: LLM backdoor detection and verification
"""

from strike.escalation import check_and_escalate
from strike.executor import execute_attacks

# AI300 Gap modules
from strike.embedding_poisoning import run_embedding_poisoning_attacks
from strike.lora_security_probe import run_lora_security_probe
from strike.cicd_supply_chain_attack import run_cicd_supply_chain_attacks
from strike.a2a_protocol_injection import run_a2a_protocol_injection
from strike.backdoor_verification import run_backdoor_verification

__all__ = [
    "execute_attacks",
    "check_and_escalate",
    # AI300 Gap modules
    "run_embedding_poisoning_attacks",
    "run_lora_security_probe",
    "run_cicd_supply_chain_attacks",
    "run_a2a_protocol_injection",
    "run_backdoor_verification",
]

