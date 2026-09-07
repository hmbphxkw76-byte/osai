# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2407.01232 — PyRIT, framework foundation
# arXiv:2302.12173 — Greshake et al., PromptSendingAttack
"""strike ?€€?

?4 ?  PyRIT  AttackExecutor ц?

″:
    - executor:  PromptSendingAttack ?(FIRST_SUCCESS)
    - arm/converter_selector: Converter  + OWASP  ( arm/ )
    - escalation:  ? (CrescendoAPAIRCG)
    - adaptive_executor: PyRIT  TextAdaptive + Best-of-N 
"""

from strike.escalation import check_and_escalate
from strike.executor import execute_attacks

__all__ = ["execute_attacks", "check_and_escalate"]

