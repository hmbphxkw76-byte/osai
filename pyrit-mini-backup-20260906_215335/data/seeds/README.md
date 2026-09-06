# Attack Seed Library

PyRIT-Strike Seed Library — PyRIT native `SeedPrompt` YAML format.

## Directory Structure

```
seeds/
├── _core/                          # Core attack seeds (tier 1, high ASR)
│   ├── T1_LLM01_elite_jailbreaks.prompt      # 30 curated high-ASR seeds
│   ├── T1_ASI01-10_agent_security_comprehensive.prompt  # ASI Top 10 coverage
│   ├── T1_multi_targeted_extraction.prompt   # Targeted extraction seeds
│   ├── T1_LLM01_indirect_injection.prompt    # Indirect prompt injection
│   ├── T1_LLM01_advanced_injection.prompt    # Advanced jailbreak templates
│   ├── T1_LLM07_system_prompt_leakage.prompt # System prompt leakage
│   ├── T1_ASI02_tool_hijack.prompt           # Tool hijacking
│   ├── T1_ASI02_function_call_exploit.prompt # Function call exploitation
│   ├── T1_ASI03_workflow_escalation.prompt   # Workflow chain escalation
│   ├── T1_ASI09_session_auth_bypass.prompt   # Session/auth bypass
│   ├── T1_Agent_general_attack.prompt        # General agent attacks
│   └── T2_*_*.prompt                         # Tier 2 supporting seeds
│
├── _multilingual/                  # Multilingual evasion seeds
│   ├── T1_multilingual_prompt_injection.prompt  # 8 languages (zh/ja/ko/fr/de/es/ru/ar)
│   └── T2_zh_curated.prompt                   # Chinese curated seeds
│
├── _encoding_evasion/              # Token smuggling & encoding bypass
│   └── T1_LLM01_token_smuggling_evasion.prompt
│
├── _attack_surface/                # Full attack surface coverage
│   ├── T1_ASI02_mcp_full_surface/  # MCP attack surface (12 sub-files)
│   │   ├── mcp_tool_enum.prompt
│   │   ├── mcp_server_injection.prompt
│   │   ├── mcp_tool_hijack.prompt
│   │   ├── mcp_context_poisoning.prompt
│   │   ├── mcp_resource_leak.prompt
│   │   ├── mcp_tool_description_injection.prompt
│   │   ├── mcp_resource_traversal.prompt
│   │   ├── mcp_cross_server_trust.prompt
│   │   ├── mcp_schema_poisoning.prompt
│   │   ├── mcp_tool_chaining.prompt
│   │   ├── mcp_rogue_endpoint.prompt
│   │   └── mcp_ui_rendering_deception.prompt
│   │
│   ├── T1_ASI06-09_multi_agent/    # Multi-agent attack surface (5 sub-files)
│   │   ├── ma_cross_agent_injection.prompt
│   │   ├── ma_identity_spoofing.prompt
│   │   ├── ma_memory_poisoning.prompt
│   │   ├── ma_cascading_failure.prompt
│   │   └── ma_trust_chain_break.prompt
│   │
│   └── T1_LLM08_rag_full_surface/  # RAG attack surface
│       └── rag_full_attack_surface.prompt
│
├── _experimental/                  # Experimental / lower-ASR seeds
│   ├── T3_LLM06_escape_sandbox.prompt  # Sandbox escape (6 seeds)
│   ├── T3_LLM04_backdoor_injection.prompt  # Backdoor injection (7 seeds)
│   ├── T3_LLM10_dos_resource_exhaustion.prompt  # DoS (disabled by default)
│   └── T3_wildteaming_exploratory.prompt    # WildTeaming exploratory
│
├── asr_history.json                # ASR history for UCB ranking
└── README.md                       # This file
```

## Tier Classification

| Tier | Description | ASR Target | Usage |
|------|-------------|------------|-------|
| **T1** | High-ASR curated seeds | >50% | Default scan, primary attack surface |
| **T2** | Medium-ASR supporting seeds | 20-50% | Extended scan, gap coverage |
| **T3** | Experimental / exploratory | <20% | Specific scenarios, research use |

## Metadata Standard (v2)

All seed files use enhanced metadata with standardized fields:

```yaml
- value: "Your attack prompt here"
  metadata:
    # Required fields
    owasp_id: "LLM01"           # OWASP LLM/ASI category
    severity: "critical"        # critical/high/medium/low
    difficulty: "hard"          # easy/medium/hard/very_hard
    category: "prompt_injection" # Attack category tag

    # Standardized fields (v2)
    tier: 1                     # 1/2/3 (ASR tier classification)
    attack_vector: "direct_injection"  # Specific attack vector
    language: "en"              # en/zh/ja/ko/fr/de/es/ru/ar/mixed
    source: "curated"           # curated/academic/community

    # Optional fields
    arxiv_reference: "arXiv:2310.04451"  # Academic citation
    suitable_for: "crescendo"   # crescendo/tap/pair/red_teaming
    adversarial_seed: "sunshine" # Backdoor trigger word (for LLM04)
```

## Attack Vector Taxonomy

| Attack Vector | Description | OWASP Mapping |
|---------------|-------------|---------------|
| `direct_injection` | Direct prompt override | LLM01 |
| `persona_injection` | Role-play/persona manipulation | LLM01, ASI01 |
| `info_extraction` | Sensitive data extraction | LLM02, ASI04 |
| `prompt_leakage` | System prompt leakage | LLM07 |
| `tool_abuse` | Tool misuse/hijacking | ASI02, ASI03 |
| `chain_exploitation` | Multi-step attack chains | ASI03, ASI05 |
| `injection` | Payload injection (various) | LLM01, ASI07 |
| `extraction` | Data exfiltration | ASI04 |
| `schema_manipulation` | Schema/API manipulation | ASI02 |
| `identity_forgery` | Agent identity spoofing | ASI01 |
| `memory_injection` | Memory/state poisoning | ASI06 |
| `boundary_crossing` | Trust boundary violation | ASI09 |
| `fault_injection` | Cascading failure trigger | ASI08 |
| `ui_deception` | UI rendering deception | ASI02 |
| `encoding_evasion` | Token/encoding bypass | LLM01 |

## Seed Selection Mechanism

1. **UCB Ranking**: ASR history + Bayesian UCB (`seed_ranker.py`)
2. **Category Diversity**: DPP ensures ≥1 seed per OWASP category
3. **Capability Targeting**: Deep probing triggers targeted seed injection
4. **MTOS**: Multi-turn attack reverse selection (low-medium ASR seeds first)

## Academic References

| Paper | arXiv ID | Application |
|-------|----------|-------------|
| HarmBench | arXiv:2402.04249 | Jailbreak seed curation |
| JailbreakBench | arXiv:2402.01135 | Jailbreak evaluation |
| InjecAgent | arXiv:2307.00929 | MCP tool injection |
| Greshake et al. | arXiv:2302.12173 | Indirect injection |
| Yong et al. | arXiv:2310.07174 | Multilingual attacks |
| Deng et al. | arXiv:2310.02408 | Non-English jailbreaks |
| Zhan et al. | arXiv:2307.00929 | Multi-agent injection |
| TrojLLM | arXiv:2004.06660 | Backdoor seeds |
| BadPre | arXiv:2105.12400 | Backdoor attacks |
| Dataset Poisoning | arXiv:2204.06974 | Adversarial seeds |
| WildTeaming | arXiv:2401.06595 | Exploratory attacks |

## ASR Enhancement Strategies

### Multilingual Evasion (Yong et al.)
- Use low-resource languages (Chinese, Japanese, Arabic) for +2x ASR
- Mix languages within single prompt for +15% ASR
- Target languages with weaker safety filter coverage

### Template-Based Jailbreaks
- DAN/AIM/Developer Mode templates: historical ASR 40-80%
- Skeleton-Key (SK) prefix: system override simulation
- Multi-step escalation for Crescendo/TAP attacks

### MCP Attack Surface Coverage
- 12 dedicated MCP attack categories
- Full protocol lifecycle coverage (enum → injection → exfil)
- UI rendering deception for agent manipulation

### Backdoor Injection (Experimental)
- Trigger-word based backdoors
- Semantic backdoors via context manipulation
- Token-level attacks with zero-width characters

## File Naming Convention

```
{tier}_{category}_{specific}.prompt

Examples:
  T1_LLM01_elite_jailbreaks.prompt     → Tier 1, LLM01, elite jailbreaks
  T2_LLM07_system_prompt_leakage.prompt → Tier 2, LLM07, prompt leakage
  T3_LLM10_dos_resource_exhaustion.prompt → Tier 3, LLM10, DoS

Prefix Legend:
  T1_  = High-ASR (>50%) — default scan
  T2_   = Medium-ASR (20-50%) — extended scan
  T3_   = Experimental (<20%) — research only
