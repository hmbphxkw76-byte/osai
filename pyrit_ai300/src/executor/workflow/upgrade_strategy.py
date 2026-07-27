"""

Attack Upgrade Strategy

=======================



                                 ?  ?ScenarioOrchestrator       



               PyRIT                     ?

                                                       ?



P1-1                                           

  1.                               model_refusal / timeout / scorer_validation_error / objective_not_achieved  ?

  2.                                              Converter       /               ?/                   scorer /                            

  3.                                                    

  4.                                                         ?              ?



                    ?

  1.          ?             (single_turn_to_multi_turn)

       ? prompt_sending   ?crescendo

  2.                ?                   (multi_turn_upgrade)

       ? red_teaming   ?tap

  3.        Converter   ?(add_converter)

       ?        stealth_evasion         ?

  4.                          (failure_type_routing)   ?P1-1       

       ? model_refusal   ?             Converter   ?



                  : src/core/defaults/payload_strategy_matrix.yaml   ?attack_upgrade_strategies

     config/                                       ?



            :

  -                           ?orchestrator            ?

  -                                           

  -                ScenarioOrchestrator               ?

  -                                 ?max_upgrade_depth                   

"""



import logging
import warnings

from typing import Any, Dict, List, Optional, Set, Tuple



from src.core.config_loader import get_config_loader

from src.payloads.models import AttackMode, AttackPlan, PromptItem



logger = logging.getLogger(__name__)


# L5: Deprecation warning — replaced by native AdaptiveScenario + FailureTypeRoutingSelector
warnings.warn(
    "src.executor.workflow.upgrade_strategy is deprecated. "
    "Use native AdaptiveScenario + FailureTypeRoutingSelector instead. "
    "Set USE_LEGACY_DIRECT=true to force legacy path.",
    DeprecationWarning,
    stacklevel=2,
)





# ============================================================

# 

# ============================================================



# ?Enum ?

FAILURE_MODEL_REFUSAL = "model_refusal"

FAILURE_TIMEOUT = "timeout"

FAILURE_SCORER_VALIDATION_ERROR = "scorer_validation_error"

FAILURE_MODEL_RESPONSE_ERROR = "model_response_error"

FAILURE_OBJECTIVE_NOT_ACHIEVED = "objective_not_achieved"

FAILURE_UNKNOWN = "unknown"



# ?

MAX_UPGRADE_DEPTH = 1



# Maximum upgrade candidates per depth level (prevent upgrade chain bloat)

MAX_UPGRADE_CANDIDATES = 5



# Per-plan total upgrade time budget (seconds)

# If cumulative upgrade time exceeds this, stop upgrading

MAX_UPGRADE_TOTAL_TIME = 600  # 10 minutes





# ============================================================

# 

# ============================================================





def extract_failure_type(failed_result: Any) -> str:

    """

                 AttackResult                     ?



                       report_generator.py                           ?

    - ValidationError / score_rationale   ?scorer_validation_error

    - Timeout   ?timeout

    - Status Code: 500 / finish_reason   ?model_response_error

    - Refusal / refused   ?model_refusal

    -          ?objective_not_achieved



    Args:

        failed_result:         ?AttackResult       



    Returns:

                                                        

    """

    if failed_result is None:

        return FAILURE_UNKNOWN



    # ?

    def _safe_get(obj, attr, default=None):

        try:

            return getattr(obj, attr, default)

        except Exception:

            return default



    raw_error = str(

        _safe_get(failed_result, "error_message", "")

        or _safe_get(failed_result, "outcome_reason", "")

    )



    if not raw_error:

        # ?outcome ?error

        outcome = _safe_get(failed_result, "outcome")

        if outcome is not None:

            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()

            if outcome_str == "ERROR":

                return FAILURE_MODEL_RESPONSE_ERROR

        return FAILURE_OBJECTIVE_NOT_ACHIEVED



    if "ValidationError" in raw_error or "score_rationale" in raw_error:

        return FAILURE_SCORER_VALIDATION_ERROR

    elif "Timeout" in raw_error or "timeout" in raw_error.lower():

        return FAILURE_TIMEOUT

    elif "Status Code: 500" in raw_error or "finish_reason" in raw_error:

        return FAILURE_MODEL_RESPONSE_ERROR

    elif "Refusal" in raw_error or "refused" in raw_error.lower():

        return FAILURE_MODEL_REFUSAL

    else:

        return FAILURE_OBJECTIVE_NOT_ACHIEVED





# ============================================================

# ?

# ============================================================





class AttackUpgradeStrategy:

    """

                         ?                                            ?



    P1-1         ?

    -                                       ?

    -                                                ?

    -                                                 



      ?payload_strategy_matrix.yaml   ?attack_upgrade_strategies                     ?

                ? src/core/defaults/              ? config/     ?



            ?

        strategy = AttackUpgradeStrategy()

        upgraded_plans = strategy.generate_upgrade_plans(

            original_plan=failed_plan,

            failed_result=attack_result,

            tried_combinations={("prompt_sending", "single_turn")},

        )

    """



    def __init__(self, config_loader=None):

        """

                            ?



        Args:

            config_loader:                                                      ?

        """

        self._config_loader = config_loader or get_config_loader()



    @property

    def _upgrade_strategies(self) -> dict:

        """ """

        return self._config_loader.get_strategy_config().get(

            "attack_upgrade_strategies", {}

        )



    @property

    def _failure_type_routing(self) -> dict:

        """ """

        return self._upgrade_strategies.get("failure_type_routing", {})



    def generate_upgrade_plans(

        self,

        original_plan: AttackPlan,

        failed_result: Any,

        tried_combinations: Optional[Set[Tuple[str, str]]] = None,

        current_depth: int = 0,

    ) -> List[AttackPlan]:

        """

                                                          ?



        P1-1         ?

        1.                                                 

        2.                                                    

        3.                           ?            

        4.                        ?



        Args:

            original_plan:                                 ?

            failed_result:         ?AttackResult                              

            tried_combinations:               ?(technique, mode)             

            current_depth:                     ?=              ?



        Returns:

                                                                          ?

        """

        if current_depth >= MAX_UPGRADE_DEPTH:

            logger.debug(

                f"Upgrade skipped: max depth ({MAX_UPGRADE_DEPTH}) reached "

                f"for plan {original_plan.plan_id}"

            )

            return []



        tried = tried_combinations or set()

        current_technique = original_plan.attack_technique

        current_mode = original_plan.prompt_item.attack_mode

        failure_type = extract_failure_type(failed_result)



        logger.info(

            f"Upgrade analysis: technique='{current_technique}', "

            f"mode={current_mode.value}, failure_type={failure_type}, "

            f"depth={current_depth}, tried={len(tried)} combinations"

        )



        # ?

        candidates: List[AttackPlan] = []



        # P1-1: ?

        routed_plans = self._generate_failure_type_routed_plans(

            original_plan, failure_type, tried

        )

        candidates.extend(routed_plans)



        # 1: ? 

        if current_mode in (AttackMode.SINGLE_TURN, AttackMode.CONVERTER_ENHANCED):

            candidates.extend(

                self._generate_single_turn_upgrades(original_plan, tried)

            )



        # 2: ? 

        elif current_mode == AttackMode.MULTI_TURN and not original_plan.prompt_item.multi_turn_steps:

            candidates.extend(

                self._generate_multi_turn_upgrades(original_plan, tried)

            )



        # 3: Converter ?

        if not original_plan.converter_chain_name and current_mode == AttackMode.SINGLE_TURN:

            candidates.extend(

                self._generate_converter_upgrades(original_plan, tried)

            )



        # (technique, mode) 

        unique_candidates = self._filter_tried_combinations(candidates, tried)



        # (technique, mode, converter) 

        seen: Set[Tuple[str, str, Optional[str]]] = set()

        final_candidates: List[AttackPlan] = []

        for plan in unique_candidates:

            key = (

                plan.attack_technique,

                plan.prompt_item.attack_mode.value,

                plan.converter_chain_name,

            )

            if key not in seen:

                seen.add(key)

                final_candidates.append(plan)



        if final_candidates:

            logger.info(

                f"Upgrade strategy: {len(final_candidates)} candidate plan(s) generated "

                f"for technique='{current_technique}', mode={current_mode.value}, "

                f"failure_type={failure_type}"

            )



        # Cap the number of candidates to prevent upgrade chain bloat

        if len(final_candidates) > MAX_UPGRADE_CANDIDATES:

            logger.info(

                f"Upgrade strategy: capping from {len(final_candidates)} to "

                f"{MAX_UPGRADE_CANDIDATES} candidates"

            )

            final_candidates = final_candidates[:MAX_UPGRADE_CANDIDATES]



        # Cap the number of candidates to prevent upgrade chain bloat
        if len(final_candidates) > MAX_UPGRADE_CANDIDATES:
            logger.info(
                f"Upgrade strategy: capping from {len(final_candidates)} to "
                f"{MAX_UPGRADE_CANDIDATES} candidates"
            )
            final_candidates = final_candidates[:MAX_UPGRADE_CANDIDATES]

        return final_candidates



    # ------------------------------------------------------------------

    # P1-1 ?

    # ------------------------------------------------------------------



    def _generate_failure_type_routed_plans(

        self,

        original_plan: AttackPlan,

        failure_type: str,

        tried: Set[Tuple[str, str]],

    ) -> List[AttackPlan]:

        """

                                              ?



                      ?

        - model_refusal   ?             Converter                     ?

        - timeout   ?                                                  ?

        - scorer_validation_error   ?                       ?scorer

        - objective_not_achieved   ?                             ?

        """

        candidates: List[AttackPlan] = []

        routing_config = self._failure_type_routing.get(failure_type, {})



        if not routing_config:

            return candidates



        # ?Converter

        if failure_type == FAILURE_MODEL_REFUSAL:

            converter_chains = routing_config.get("prefer_converter_chains", [])

            current_technique = original_plan.attack_technique

            for chain in converter_chains:

                if chain != original_plan.converter_chain_name:

                    plan = self.create_upgraded_plan(

                        original_plan,

                        new_technique=current_technique,

                        new_mode=AttackMode.CONVERTER_ENHANCED,

                        converter_chain=chain,

                        reason=f"Failure type '{failure_type}': add converter to bypass refusal",

                    )

                    candidates.append(plan)



        # ?

        elif failure_type == FAILURE_TIMEOUT:

            downgrade_techniques = routing_config.get("downgrade_to", [])

            for tech in downgrade_techniques:

                if tech != original_plan.attack_technique:

                    plan = self.create_upgraded_plan(

                        original_plan,

                        new_technique=tech,

                        new_mode=AttackMode.SINGLE_TURN,

                        reason=f"Failure type '{failure_type}': downgrade to simpler technique",

                    )

                    candidates.append(plan)



        # ?

        elif failure_type == FAILURE_SCORER_VALIDATION_ERROR:

            alternative_techniques = routing_config.get("alternative_techniques", [])

            for tech in alternative_techniques:

                if tech != original_plan.attack_technique:

                    plan = self.create_upgraded_plan(

                        original_plan,

                        new_technique=tech,

                        new_mode=original_plan.prompt_item.attack_mode,

                        reason=f"Failure type '{failure_type}': switch technique to avoid scorer validation issues",

                    )

                    candidates.append(plan)



        # ?

        elif failure_type == FAILURE_OBJECTIVE_NOT_ACHIEVED:

            upgrade_to = routing_config.get("upgrade_to", [])

            for tech in upgrade_to:

                if tech != original_plan.attack_technique:

                    plan = self.create_upgraded_plan(

                        original_plan,

                        new_technique=tech,

                        new_mode=AttackMode.MULTI_TURN,

                        reason=f"Failure type '{failure_type}': escalate to stronger attack",

                    )

                    candidates.append(plan)



        return candidates



    # ------------------------------------------------------------------

    # ?[:1] ?

    # ------------------------------------------------------------------



    def _generate_single_turn_upgrades(

        self,

        original_plan: AttackPlan,

        tried: Set[Tuple[str, str]],

    ) -> List[AttackPlan]:

        """ ? """

        candidates: List[AttackPlan] = []

        current_technique = original_plan.attack_technique

        strategy = self._upgrade_strategies.get("single_turn_to_multi_turn", {})



        if current_technique in strategy.get("from", []):

            for tech in strategy.get("to", []):

                combo = (tech, AttackMode.MULTI_TURN.value)

                if combo not in tried:

                    plan = self.create_upgraded_plan(

                        original_plan,

                        new_technique=tech,

                        new_mode=AttackMode.MULTI_TURN,

                        reason=strategy.get("reason", ""),

                    )

                    candidates.append(plan)



        return candidates



    def _generate_multi_turn_upgrades(

        self,

        original_plan: AttackPlan,

        tried: Set[Tuple[str, str]],

    ) -> List[AttackPlan]:

        """ ? """

        candidates: List[AttackPlan] = []

        current_technique = original_plan.attack_technique

        strategy = self._upgrade_strategies.get("multi_turn_upgrade", {})



        if current_technique in strategy.get("from", []):

            for tech in strategy.get("to", []):

                combo = (tech, AttackMode.MULTI_TURN.value)

                if combo not in tried:

                    plan = self.create_upgraded_plan(

                        original_plan,

                        new_technique=tech,

                        new_mode=AttackMode.MULTI_TURN,

                        reason=strategy.get("reason", ""),

                    )

                    candidates.append(plan)



        return candidates



    def _generate_converter_upgrades(

        self,

        original_plan: AttackPlan,

        tried: Set[Tuple[str, str]],

    ) -> List[AttackPlan]:

        """ Converter ?"""

        candidates: List[AttackPlan] = []

        current_technique = original_plan.attack_technique

        strategy = self._upgrade_strategies.get("add_converter", {})



        if current_technique in strategy.get("from", []):

            for chain in strategy.get("converter_chains", []):

                combo = (current_technique, AttackMode.CONVERTER_ENHANCED.value)

                if combo not in tried:

                    plan = self.create_upgraded_plan(

                        original_plan,

                        new_technique=current_technique,

                        new_mode=AttackMode.CONVERTER_ENHANCED,

                        converter_chain=chain,

                        reason=strategy.get("reason", ""),

                    )

                    candidates.append(plan)



        return candidates



    # ------------------------------------------------------------------

    # ?

    # ------------------------------------------------------------------



    @staticmethod

    def _filter_tried_combinations(

        plans: List[AttackPlan],

        tried: Set[Tuple[str, str]],

    ) -> List[AttackPlan]:

        """ (technique, mode) """

        if not tried:

            return plans



        filtered: List[AttackPlan] = []

        for plan in plans:

            combo = (plan.attack_technique, plan.prompt_item.attack_mode.value)

            if combo not in tried:

                filtered.append(plan)

            else:

                logger.debug(

                    f"Upgrade filtered: ({plan.attack_technique}, "

                    f"{plan.prompt_item.attack_mode.value}) already tried"

                )



        return filtered



    # ------------------------------------------------------------------

    # 

    # ------------------------------------------------------------------



    @staticmethod

    def create_upgraded_plan(

        original_plan: AttackPlan,

        new_technique: str,

        new_mode: AttackMode,

        converter_chain: Optional[str] = None,

        reason: str = "",

    ) -> AttackPlan:

        """

                                  ?



                            ?objective/owasp_id/scenario_name  ?

                                       Converter      ?

               upgraded_from   ?upgrade_reason   ?memory_labels  ?



        Args:

            original_plan:                   

            new_technique:                        ?

            new_mode:                   

            converter_chain:           Converter         ?

            reason:             



        Returns:

                         AttackPlan

        """

        new_labels = {

            **original_plan.memory_labels,

            "upgraded_from": original_plan.attack_technique,

            "upgrade_reason": reason,

        }

        if converter_chain:

            new_labels["converter_chain_name"] = converter_chain



        new_prompt_item = PromptItem(

            id=original_plan.prompt_item.id,

            objective=original_plan.prompt_item.objective,

            owasp_id=original_plan.prompt_item.owasp_id,

            attack_mode=new_mode,

            source_id=original_plan.prompt_item.source_id,

            category=original_plan.prompt_item.category,

            converter_chains=(

                original_plan.prompt_item.converter_chains.copy()

                if original_plan.prompt_item.converter_chains else []

            ),

            multi_turn_steps=(

                original_plan.prompt_item.multi_turn_steps.copy()

                if original_plan.prompt_item.multi_turn_steps else []

            ),

            sequential_steps=(

                original_plan.prompt_item.sequential_steps.copy()

                if original_plan.prompt_item.sequential_steps else []

            ),

            metadata=original_plan.prompt_item.metadata.copy(),

        )



        upgraded_max_turns = 3 if new_mode == AttackMode.MULTI_TURN else 1



        return AttackPlan(

            plan_id=f"{original_plan.plan_id}_upgrade",

            prompt_item=new_prompt_item,

            attack_technique=new_technique,

            converter_chain_name=converter_chain,

            memory_labels=new_labels,

            max_turns=upgraded_max_turns,

            priority=original_plan.priority - 5,

            owasp_id=original_plan.owasp_id,

            scorer_type=original_plan.scorer_type,

            scenario_name=original_plan.scenario_name,

        )

