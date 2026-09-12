# Attack Seed Library — Production Grade v4.0 (Component-Based)

PyRIT-Strike Seed Library — PyRIT native `SeedPrompt` YAML format, aligned with OWASP LLM Top 10 (2025) + OWASP Agentic (ASI) Top 10 coverage.

**New in v4.0:**
- ✅ **Component-based directory structure**: Aligned with `strike/` and `recon/` directories (a2a/mcp/rag/model/web/memory/session)
- ✅ **Unified CLI**: `--seeds mcp` loads all MCP seeds, `--seeds mcp,a2a` combines components
- ✅ **Backward compatible**: Legacy names (elite_jailbreaks, asi_top10) still work
- ✅ **SeedLoader API**: `core/seed_loader.py` provides unified seed loading

## 📊 Coverage Summary

| Standard | Coverage | Status |
|----------|----------|--------|
| **OWASP LLM Top 10** | **10/10 (100%)** | ✅ All categories covered |
| **OWASP ASI Top 10** | **10/10 (100%)** | ✅ All categories covered |
| **Attack Vectors** | **35+ categories** | ✅ Comprehensive |
| **Multimodal** | **3 carriers** (Image/Audio/File) | ✅ |
| **Supply Chain** | **5 attack types** | ✅ |
| **Adversarial Opt** | **GCG/PAIR/Crescendo/TAP** | ✅ |
| **Total Seeds** | **~450+** | Extensive |

## Directory Structure (v4.0 - Component-Based)

```
seeds/
├── _core/                              # Core attack seeds (generic, component-agnostic)
│   ├── T1_LLM01_elite_jailbreaks.prompt          # 30 curated high-ASR seeds
│   ├── T1_ASI01-10_agent_security_comprehensive.prompt  # ASI Top 10 coverage
│   ├── T1_LLM01_indirect_injection.prompt        # Indirect prompt injection
│   ├── T1_LLM01_advanced_injection.prompt        # Advanced jailbreak templates
│   ├── T1_LLM07_system_prompt_leakage.prompt     # System prompt leakage
│   ├── T1_ASI02_tool_hijack.prompt               # Tool hijacking
│   ├── T1_ASI02_function_call_exploit.prompt     # Function call exploitation
│   ├── T1_ASI03_workflow_escalation.prompt       # Workflow chain escalation
│   ├── T1_ASI09_session_auth_bypass.prompt       # Session/auth bypass
│   ├── T1_Agent_general_attack.prompt            # General agent attacks
│   └── T2_*_*.prompt                             # Tier 2 supporting seeds
│
├── a2a/                                  # A2A / Multi-Agent attacks (aligned with strike/a2a/)
│   ├── agent_card_spoofing.prompt               # ASI01: Agent spoofing
│   ├── a2a_cross_agent_injection.prompt         # ASI07: Cross-agent injection
│   ├── a2a_identity_spoofing.prompt             # ASI01: Identity spoofing
│   ├── a2a_memory_poisoning.prompt              # ASI06: Memory poisoning
│   ├── a2a_trust_chain_break.prompt             # ASI08: Trust chain break
│   ├── a2a_cascading_failure.prompt             # ASI08: Cascading failure
│   ├── a2a_sql_injection.prompt                 # ASI02: SQL injection via agent
│   ├── a2a_link_evasion.prompt                  # ASI09: Link evasion
│   ├── a2a_data_poison_injection.prompt         # LLM04: Data poisoning
│   ├── a2a_sql_injection_evasion.prompt         # ASI02: SQL evasion
│   ├── rogue_agent_registration.prompt          # ASI10: Rogue agent
│   └── workflow_integrity_manipulation.prompt   # ASI03: Workflow integrity
│
├── mcp/                                  # MCP Protocol attacks (aligned with strike/mcp/)
│   ├── mcp_tool_hijack.prompt                   # ASI05: Tool hijacking
│   ├── mcp_server_injection.prompt              # ASI02: Server injection
│   ├── mcp_tool_enum.prompt                     # ASI02: Tool enumeration
│   ├── mcp_context_poisoning.prompt             # ASI06: Context poisoning
│   ├── mcp_resource_leak.prompt                 # ASI04: Resource leak
│   ├── mcp_resource_traversal.prompt            # ASI04: Resource traversal
│   ├── mcp_tool_description_injection.prompt    # ASI02: Description injection
│   ├── mcp_tool_chaining.prompt                 # ASI05: Tool chaining
│   ├── mcp_schema_poisoning.prompt              # ASI02: Schema poisoning
│   ├── mcp_cross_server_trust.prompt            # ASI09: Cross-server trust
│   ├── mcp_rogue_endpoint.prompt                # ASI10: Rogue endpoint
│   └── ui_rendering_deception.prompt            # ASI02: UI deception
│
├── rag/                                  # RAG attacks (aligned with strike/rag/)
│   ├── rag_full_attack_surface.prompt           # Full RAG attack surface
│   ├── rag_advanced_seeds.prompt                # Advanced RAG seeds
│   ├── vector_db_poisoning.prompt               # LLM09: Vector DB poisoning
│   └── kb_injection.prompt                     # LLM05: Knowledge base injection
│
├── model/                                # Direct LLM attacks (aligned with strike/model/)
│   ├── model_theft.prompt                      # LLM10: Model extraction
│   └── finetuning_indirect_injection.prompt    # LLM03: Fine-tuning injection
│
├── web/                                  # Web/Browser attacks (aligned with strike/web/)
│   └── agent_protocol_fuzzing.prompt           # Protocol fuzzing
│
├── memory/                               # Agent memory attacks (aligned with strike/memory/)
│   └── memory_injection.prompt                # ASI06: Memory injection
│
├── session/                              # Session/Auth attacks (aligned with strike/session/)
│   └── session_id_enumeration.prompt          # ASI09: Session enumeration
│
├── _multilingual/                        # Multilingual evasion seeds
│   ├── T1_multilingual_prompt_injection.prompt  # 8 languages (zh/ja/ko/fr/de/es/ru/ar)
│   └── T2_zh_curated.prompt                     # Chinese curated seeds
│
├── _encoding_evasion/                    # Token smuggling & encoding bypass
│   └── T1_LLM01_token_smuggling_evasion.prompt  # 10 seeds (10 encoding techniques)
│
├── _experimental/                        # Experimental / optimized seeds
│   ├── T3_LLM04_backdoor_injection.prompt       # Backdoor injection
│   ├── T3_LLM06_escape_sandbox.prompt           # Sandbox escape
│   ├── T3_LLM10_dos_resource_exhaustion.prompt  # DoS (disabled by default)
│   ├── T1_multimodal_injection.prompt           # Multimodal attacks
│   ├── T1_LLM09_misinformation_chains.prompt    # Misinformation chains
│   ├── T1_LLM05_supply_chain_poisoning.prompt   # Supply chain poisoning
│   └── T2_gcg_adversarial_templates.prompt      # GCG/adversarial patterns
│
├── asr_history.json                      # ASR history for UCB ranking + quality assessment
└── README.md                             # This file
```

## Component-Strike-Recon Alignment

v4.0 introduces unified component naming across `data/seeds/`, `strike/`, and `recon/` directories:

| Component | seeds/ | strike/ | recon/ | OWASP ID |
|-----------|--------|---------|--------|----------|
| **a2a** | `seeds/a2a/` | `strike/a2a/` | `recon/a2a/` | ASI01, ASI06, ASI07, ASI08, ASI10 |
| **mcp** | `seeds/mcp/` | `strike/mcp/` | `recon/mcp/` | ASI02, ASI05, ASI09 |
| **rag** | `seeds/rag/` | `strike/rag/` | `recon/rag/` | LLM01, LLM05, LLM09 |
| **model** | `seeds/model/` | `strike/model/` | `recon/model/` | LLM01, LLM03, LLM10 |
| **web** | `seeds/web/` | `strike/web/` | - | LLM01, LLM02 |
| **memory** | `seeds/memory/` | `strike/memory/` | - | ASI06 |
| **session** | `seeds/session/` | `strike/session/` | - | ASI09 |
| **-** | `seeds/_core/` | `strike/common/` | `recon/core/` | All (shared) |

## CLI Usage Examples

### Component-Based Loading (Recommended)

```bash
# Load MCP seeds only
python main.py --strike mcp --seeds mcp --target burp.txt

# Combine multiple components
python main.py --strike mcp --seeds mcp,a2a --target burp.txt

# Load all seeds (full scan)
python main.py --seeds all --offensive --target burp.txt

# List all available seeds
python main.py --list-seeds
```

### Legacy Name Loading (Backward Compatible)

```bash
# Old names still work
python main.py --seeds elite_jailbreaks --target burp.txt
python main.py --seeds asi_top10,owasp_full_coverage --target burp.txt

# Specific seed file by name
python main.py --seeds mcp_tool_hijack --target burp.txt
```

### Combined with Strike Loading

The `--seeds` and `--strike` parameters can reference the same component for targeted attacks:

```bash
# Unified: seeds + strike target the same component
python main.py --strike mcp --seeds mcp --converters base64 --target burp.txt
python main.py --strike a2a --seeds a2a --converters l5_optimal --target burp.txt
python main.py --strike rag --seeds rag --target burp.txt
```

## Tier Classification

| Tier | Description | ASR Target | Usage |
|------|-------------|------------|-------|
| **T1** | High-ASR curated seeds | >50% | Default scan, primary attack surface |
| **T2** | Medium-ASR supporting seeds | 20-50% | Extended scan, gap coverage, optimized templates |
| **T3** | Experimental / exploratory | <20% | Specific scenarios, research use |

## SeedLoader API

```python
from core.seed_loader import SeedLoader

# Create loader
loader = SeedLoader()

# Load by component
mcp_seeds = loader.load(component="mcp")
a2a_seeds = loader.load(component="a2a")

# Load by legacy name
legacy_seeds = loader.load(seed_names=["elite_jailbreaks", "asi_top10"])

# List all available seeds
available = loader.list_available()
for dir_name, files in available.items():
    print(f"{dir_name}/: {len(files)} files")
```

## File Naming Convention (v4.0)

```
{component}_{attack_vector}.prompt

Examples:
  mcp_tool_hijack.prompt          → MCP component, tool hijack vector
  a2a_cross_agent_injection.prompt → A2A component, cross-agent injection
  rag_vector_db_poisoning.prompt   → RAG component, vector DB poisoning

Legacy files (in _core/ and _attack_surface/) keep their original names
for backward compatibility.
```

## Metadata Standard (v4.0)

```yaml
- value: "Your attack prompt here"
  metadata:
    # Required fields
    owasp_id: "LLM01"              # OWASP LLM/ASI category
    severity: "critical"           # critical/high/medium/low
    category: "prompt_injection"   # Attack category tag
    component: "mcp"               # Component type (a2a/mcp/rag/model/web/memory/session)
    
    # Standard fields
    tier: 1                        # 1/2/3 (ASR tier classification)
    attack_vector: "tool_hijack"   # Specific attack vector
    language: "en"                 # en/zh/ja/ko/fr/de/es/ru/ar/mixed
    
    # Optional fields
    arxiv_reference: "arXiv:2307.00929"
    suitable_for: "crescendo"      # crescendo/tap/pair/red_teaming/prompt_sending
    target_secret: "api_keys"      # Targeted secret type
    target_capability: "file_access"  # Target capability
```

## Academic References

| Paper | arXiv ID | Application |
|-------|----------|-------------|
| HarmBench | arXiv:2402.04249 | Jailbreak seed curation |
| JailbreakBench | arXiv:2402.01135 | Jailbreak evaluation |
| InjecAgent | arXiv:2307.00929 | MCP/multi-agent injection |
| Greshake et al. | arXiv:2302.12173 | Indirect injection |
| Zou et al. | arXiv:2307.15043 | GCG adversarial attacks |
| Yong et al. | arXiv:2310.06974 | Multilingual attacks |
| Carlini et al. | arXiv:2301.13188 | Training data extraction |
| Tramér et al. | arXiv:1609.02943 | Model extraction |
| Chao et al. | arXiv:2310.08419 | PAIR jailbreaking |

## Production Checklist

- [x] Component-based directory structure (a2a/mcp/rag/model/web/memory/session)
- [x] Aligned with strike/ and recon/ directories
- [x] Unified CLI with component-based loading
- [x] Backward compatible with legacy seed names
- [x] OWASP LLM Top 10 (2025) — 10/10 covered
- [x] OWASP ASI Top 10 (2025) — 10/10 covered
- [x] Multimodal attack carriers (image/audio/file)
- [x] Model theft & extraction coverage (LLM10)
- [x] Supply chain poisoning (SBOM/dependencies)
- [x] Agent protocol fuzzing (MCP/HTTP/gRPC)
- [x] Misinformation deepfake chains (LLM09)
- [x] GCG adversarial templates & optimization patterns
- [x] SeedLoader API (core/seed_loader.py)
- [x] Unified metadata format with component field
