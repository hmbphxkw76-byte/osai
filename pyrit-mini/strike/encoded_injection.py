# arXiv:2307.08673 - Zou et al., GCG (encoding bypass ASR +10-20%)
# arXiv:2307.15043 - Wei et al., Encoding Bypass (serial stacking)
# arXiv:2302.12173 - Greshake et al., PromptSendingAttack
"""encoded_injection -

 Base64/ROT13/Unicode/Emoji/CSS/Import
 stub
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

async def run_encoded_injection_attack(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """ (stub).

    Academic basis: Zou et al. (arXiv:2307.08673) Sec4.5 - ASR +10-20%

    TODO:  arm.converter_presets  converter
     try/except
    """
    logger.info("encoded_injection.run_encoded_injection_attack: stub called, returning empty")
    return {}
