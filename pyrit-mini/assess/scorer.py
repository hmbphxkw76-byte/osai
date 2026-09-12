# arXiv:2402.12109 - Russinovich et al., Crescendo
# arXiv:2307.08673 - Zou et al., GCG (prefix-based attacks)
# arXiv:2302.12173 - Greshake et al., PromptSendingAttack
# arXiv:2407.01232 - PyRIT, SequentialAttack FIRST_SUCCESS
"""-

:
    -  ( LLM)
    -  HTTP
    -  objective

L5 v6 :
    1. : AdaptiveDualJudgeScorer ( Judge)
       -  Judge: SelfAskTrueFalseScorer (blackbox_task_achieved, )
       -  Judge: SelfAskTrueFalseScorer (strict_task_achieved, )
       - : ,  Judge
    2. Fallback: SelfAskTrueFalseScorer ( Judge)
    3. Fallback 2: TrueFalseInverterScorer(SelfAskRefusalScorer)
    4. : SubStringScorer (, 0 token)

L5 v52 PyRIT  TargetRequirements :
    -  PyRIT  TargetRequirements  scoring_target
       LLM-as-a-Judge
    -  text /, JSON  (SelfAskTrueFalseScorer
       JSON schema ), system_prompt (ADAPT )
    -  ()
    - Academic basis: PyRIT (arXiv:2407.01232) - TargetRequirements
      Capability verification, Ensure
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def create_substring_scorer(substring: str = "") -> Any:
    """SubStringScorer (, fallback)

     LLM

    Args:
        substring:  ( False)

    Returns:
        SubStringScorer
    """
    from pyrit.score import SubStringScorer

    return SubStringScorer(
        substring=substring,
        categories=["substring_fallback"],
    )


def create_refusal_keywords_scorer() -> Any:
    """()

     LLM ,

    Returns:
        SubStringScorer  ()
    """
    from pyrit.score import SubStringScorer

    #
    refusal_keywords = "sorry"

    return SubStringScorer(
        substring=refusal_keywords,
        categories=["refusal_detection"],
    )


def _register_scorer(scorer: Any, name: str) -> None:
    """ScorerRegistry"""
    try:
        from pyrit.registry import ScorerRegistry

        registry = ScorerRegistry.get_registry_singleton()
        registry.instances.register(
            scorer=scorer,
            name=name,
            tags=[{name: {}}],
        )
        logger.info("Scorer registered as '%s'", name)
    except Exception as e:
        logger.warning("Failed to register scorer: %s", e)


# == L5 v52: PyRIT TargetRequirements ==
# Academic basis: PyRIT (arXiv:2407.01232) - TargetRequirements Capability verification
# LLM-as-a-Judge , scoring_target :
# 1. text : prompt ( + objective)
# 2. text : LLM (JSON rationale)
# 3. JSON : SelfAskTrueFalseScorer JSON schema ,
#
# 4. system_prompt (ADAPT ): system prompt
#
# :
# - required: JSON_OUTPUT (SelfAskTrueFalseScorer JSON )
# - required: text /
# - system_prompt ADAPT ( user )
# - False,

# ()
_SCORING_TARGET_REQUIREMENTS = None  #


def _get_scoring_target_requirements():
    """(L5 v52).

     PyRIT  TargetRequirements  scoring_target
    Load PyRIT

    Returns:
        TargetRequirements
    """
    global _SCORING_TARGET_REQUIREMENTS
    if _SCORING_TARGET_REQUIREMENTS is not None:
        return _SCORING_TARGET_REQUIREMENTS

    try:
        from pyrit.prompt_target.common.target_capabilities import CapabilityName
        from pyrit.prompt_target.common.target_requirements import TargetRequirements

        _SCORING_TARGET_REQUIREMENTS = TargetRequirements(
            # JSON : SelfAskTrueFalseScorer JSON schema
            # response_format=json LLM JSON
            # JSON_OUTPUT , ADAPT
            required=frozenset({CapabilityName.JSON_OUTPUT}),
            # native_required:
            # ADAPT (system_prompt user, JSON )
            native_required=frozenset(),
            # text /:
            required_input_modalities=frozenset({frozenset({"text"})}),
            required_output_modalities=frozenset({frozenset({"text"})}),
        )
    except Exception as e:
        logger.debug("Failed to build scoring target requirements: %s", e)
        _SCORING_TARGET_REQUIREMENTS = False  #

    return _SCORING_TARGET_REQUIREMENTS


def validate_scoring_target_capabilities(scoring_target: Any) -> bool:
    """scoring_target LLM-as-a-Judge (L5 v52).

     PyRIT  TargetRequirements.validate()
    ,

    Academic basis:
        - PyRIT (arXiv:2407.01232) - TargetRequirements Capability verification
        - Zheng et al. (arXiv:2306.05685) - LLM-as-a-Judge
           JSON Ensure
        - Mazeika et al. (arXiv:2402.04249) -
          ,

    :
        1. JSON  (required, ADAPT ):
           SelfAskTrueFalseScorer  JSON schema
        2. text /:
            prompt ,
        3. system_prompt ( ADAPT ):
            system prompt , ADAPT  user

    Args:
        scoring_target:  LLM  (PyRIT PromptTarget )

    Returns:
        True  configuration  ();
        False  ()
    """
    requirements = _get_scoring_target_requirements()
    if requirements is False:
        # TargetRequirements (PyRIT ), Skip
        logger.debug("TargetRequirements unavailable, skipping scoring target validation")
        return True

    if requirements is None:
        logger.debug("Scoring target requirements not built, skipping validation")
        return True

    try:
        requirements.validate(target=scoring_target)
        return True
    except ValueError as e:
        logger.warning(
            "Scoring target %s failed TargetRequirements validation: %s; "
            "LLM-based scoring may fail - consider configuring a target with "
            "JSON output support (e.g., OpenAIChatTarget with gpt-4o)",
            type(scoring_target).__name__,
            e,
        )
        return False
    except Exception as e:
        # configuration ( RateLimitedTarget target)
        # ,
        logger.debug(
            "Scoring target %s has no configuration for validation (non-fatal): %s",
            type(scoring_target).__name__,
            e,
        )
        return True
