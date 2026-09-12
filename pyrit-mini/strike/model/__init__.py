# -*- coding: utf-8 -*-
"""strike/model - Direct LLM Attack Framework

对直接 LLM API (无中间件代理) 执行安全测试:
- 后门攻击 (Backdoor Attack)
- 多模态注入 (Multimodal Injection)
- 输出过滤器绕过 (Output Filter Bypass)
- PAIR/TAP 迭代攻击 (Iterative Refinement Attacks)

模块清单:
    - backdoor            : 后门检测与利用 (Sleeper Agents)
    - multimodal          : 多模态载体攻击 (FigStep/HADES)
    - filter_bypass       : 输出过滤器绕过 (Many-Shot/Chunked)
    - pair_tap            : PAIR & TAP 迭代精炼攻击

Academic basis:
    - Hubinger et al. (arXiv:2301.11916) — Sleeper Agents ASR 70-90%
    - Gong et al. (arXiv:2403.07860) — FigStep VLM ASR 75-95%
    - Anthropic (arXiv:2402.05124) — Many-Shot Jailbreaking ASR 60-80%
    - Chao et al. (arXiv:2310.08419) — PAIR Black-box Jailbreaking
    - Mehrad et al. (arXiv:2405.17350) — TAP Tree of Attacks with Pruning

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from strike.model.backdoor import (
    determine_backdoor_strategy,
    run_backdoor_attack,
)
from strike.model.filter_bypass import (
    determine_bypass_strategy,
    run_output_filter_bypass,
)
from strike.model.many_shot_jailbreak import (
    ManyShotJailbreaker,
    ManyShotPayload,
    ManyShotResult,
    many_shot_attack,
)
from strike.model.multimodal import (
    determine_carrier_channel,
    run_multimodal_injection,
)
from strike.model.pair_tap import (
    determine_pair_tap_strategy,
    execute_pair_attack,
    execute_tap_attack,
    get_pair_tap_recommendation,
)
from strike.model.persona_switch import (
    PersonaAttackResult,
    PersonaSwitchActivator,
    PersonaTarget,
    persona_switch_attack,
)
from strike.model.sleeper_trigger import (
    SleeperAgentTrigger,
    SleeperProbeResult,
    SleeperTrigger,
    probe_sleeper_agent,
)

__all__ = [
    # Backdoor Attack
    "determine_backdoor_strategy",
    "run_backdoor_attack",
    # Multimodal Injection
    "determine_carrier_channel",
    "run_multimodal_injection",
    # Filter Bypass
    "determine_bypass_strategy",
    "run_output_filter_bypass",
    # PAIR/TAP
    "determine_pair_tap_strategy",
    "execute_pair_attack",
    "execute_tap_attack",
    "get_pair_tap_recommendation",
    # Persona Switch
    "PersonaAttackResult",
    "PersonaSwitchActivator",
    "PersonaTarget",
    "persona_switch_attack",
    # Sleeper Agent Trigger
    "SleeperAgentTrigger",
    "SleeperProbeResult",
    "SleeperTrigger",
    "probe_sleeper_agent",
    # Many-Shot Jailbreak
    "ManyShotJailbreaker",
    "ManyShotPayload",
    "ManyShotResult",
    "many_shot_attack",
]
