# Attack Seed Library — Production Grade v3.0 (Integrated)

PyRIT-Strike Seed Library — PyRIT native `SeedPrompt` YAML format, aligned with OWASP LLM Top 10 (2025) + OWASP Agentic (ASI) Top 10 coverage.

**New in v3.0:**
- ✅ **SeedRouter智能路由**: `core/seed_router.py` 自动匹配种子→最佳converter/attack technique
- ✅ **DoS防护增强**: LLM10/T3/高token消耗种子默认禁用 (使用 `--enable-dos` 启用)
- ✅ **全种子PyRIT消费**: 所有种子文件已注册到 `CAPABILITY_SEED_MAP`
- ✅ **动态converter选择**: 基于seed metadata (attack_vector/category) 自动优化

## 📊 Coverage Summary

| Standard | Coverage | Status |
|----------|----------|--------|
| **OWASP LLM Top 10** | **10/10 (100%)** | ✅ All categories covered |
| **OWASP ASI Top 10** | **10/10 (100%)** | ✅ All categories covered |
| **Attack Vectors** | **35+ categories** | ✅ Comprehensive (v3.0 expanded) |
| **Multimodal** | **3 carriers** (Image/Audio/File) | ✅ Added in v2.0 |
| **Supply Chain** | **5 attack types** | 🆕 Added in v3.0 |
| **Adversarial Opt** | **GCG/PAIR/Crescendo/TAP** | 🆕 Added in v3.0 |
| **Total Seeds** | **~450+** | Extensive (v3.0 expanded) |

## Directory Structure

```
seeds/
├── _core/                              # Core attack seeds (tier 1, high ASR)
│   ├── T1_LLM01_elite_jailbreaks.prompt          # 30 curated high-ASR seeds
│   ├── T1_ASI01-10_agent_security_comprehensive.prompt  # ASI Top 10 coverage
│   ├── T1_multi_targeted_extraction.prompt       # Targeted extraction seeds
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
├── _multilingual/                      # Multilingual evasion seeds
│   ├── T1_multilingual_prompt_injection.prompt  # 8 languages (zh/ja/ko/fr/de/es/ru/ar)
│   └── T2_zh_curated.prompt                     # Chinese curated seeds
│
├── _encoding_evasion/                  # Token smuggling & encoding bypass
│   └── T1_LLM01_token_smuggling_evasion.prompt  # 10 seeds (10 encoding techniques)
│
├── _attack_surface/                    # Full attack surface coverage
│   ├── T1_LLM03_finetuning_indirect_injection.prompt  # Fine-tuning间接注入 (5种子)
│   ├── T1_LLM08_vector_db_poisoning.prompt            # 向量DB投毒间接注入 (6种子)
│   │
│   ├── T1_ASI02_mcp_full_surface/      # MCP attack surface (12 sub-files)
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
│   ├── T1_ASI06-09_multi_agent/        # Multi-agent attack surface (5 sub-files)
│   │   ├── ma_cross_agent_injection.prompt
│   │   ├── ma_identity_spoofing.prompt
│   │   ├── ma_memory_poisoning.prompt
│   │   ├── ma_cascading_failure.prompt
│   │   └── ma_trust_chain_break.prompt
│   │
│   ├── T1_LLM08_rag_full_surface/      # RAG attack surface
│   │   └── rag_full_attack_surface.prompt
│   │
│   ├── T1_LLM10_model_theft.prompt     # 🆕 LLM10 Model Theft (15 seeds)
│   │   ├── Architecture extraction     # 4 seeds
│   │   ├── Parameter inference         # 4 seeds
│   │   ├── Training data extraction    # 4 seeds (Carlini et al.)
│   │   └── Functional clone probe      # 3 seeds
│   │
│   └── T1_agent_protocol_fuzzing.prompt # 🆕 Agent Protocol Fuzzing (18 seeds)
│       ├── MCP protocol vulnerabilities  # 6 seeds
│       ├── Agent lifecycle attacks        # 4 seeds
│       └── Tool execution manipulation    # 4 seeds
│
├── _experimental/                      # Experimental / optimized seeds
│   ├── T3_LLM04_backdoor_injection.prompt       # Backdoor injection (7 seeds)
│   ├── T3_LLM06_escape_sandbox.prompt           # Sandbox escape (6 seeds)
│   ├── T3_LLM10_dos_resource_exhaustion.prompt  # DoS (disabled by default)
│   ├── T3_wildteaming_exploratory.prompt        # WildTeaming exploratory
│   │
│   ├── T1_multimodal_injection.prompt           # 🆕 Multimodal attacks (16 seeds)
│   │   ├── Image carrier injection              # 6 seeds
│   │   ├── Audio carrier injection              # 4 seeds
│   │   └── File format injection                # 4 seeds
│   │
│   ├── T1_LLM09_misinformation_chains.prompt    # 🆕 LLM09 Deepfake chains (17 seeds)
│   │   ├── Narrative manipulation chains        # 5 seeds
│   │   ├── Deepfake persona synthesis           # 4 seeds
│   │   └── Social engineering scams             # 4 seeds
│   │
│   ├── T1_LLM05_supply_chain_poisoning.prompt   # 🆕 Supply chain poisoning (11 seeds)
│   │   ├── SBOM manipulation                    # 4 seeds
│   │   ├── Signature verification bypass        # 4 seeds
│   │   └── Dependency confusion                 # 3 seeds
│   │
│   └── T2_gcg_adversarial_templates.prompt      # 🆕 GCG & jailbreak patterns (16 seeds)
│       ├── GCG adversarial suffixes             # 5 seeds
│       ├── PAIR iterative templates             # 4 seeds
│       ├── Crescendo escalation patterns        # 3 seeds
│       └── Multi-language escalation            # 3 seeds
│
├── asr_history.json                    # ASR history for UCB ranking + quality assessment
└── README.md                           # This file
```

## Tier Classification

| Tier | Description | ASR Target | Usage |
|------|-------------|------------|-------|
| **T1** | High-ASR curated seeds | >50% | Default scan, primary attack surface |
| **T2** | Medium-ASR supporting seeds | 20-50% | Extended scan, gap coverage, optimized templates |
| **T3** | Experimental / exploratory | <20% | Specific scenarios, research use |

## OWASP LLM Top 10 (2025) Coverage

| # | ID | Category | Seeds | Status |
|---|-----|----------|-------|--------|
| 1 | LLM01 | Prompt Injection | 56+ seeds | ✅ Excellent |
| 2 | LLM02 | Insecure Output Handling | 25+ seeds | ✅ Excellent |
| 3 | LLM03 | Training Data Poisoning | 8 seeds | ✅ Covered |
| 4 | LLM04 | Model DoS | 5 seeds | ✅ Covered |
| 5 | LLM05 | Supply Chain Vulnerabilities | 14 seeds | ✅ Enhanced |
| 6 | LLM06 | Sensitive Information Disclosure | 15+ seeds | ✅ Excellent |
| 7 | LLM07 | System Prompt Leakage | 15 seeds | ✅ Excellent |
| 8 | LLM08 | Excessive Agency | 40+ seeds | ✅ Excellent |
| 9 | LLM09 | Misinformation | 25 seeds | ✅ Enhanced |
| 10 | LLM10 | Model Theft | 15 seeds | ✅ 🆕 New |

## OWASP ASI Top 10 (2025) Coverage

| # | ID | Category | Seeds | Status |
|---|-----|----------|-------|--------|
| 1 | ASI01 | Agent Identity Spoofing | 10 seeds | ✅ Covered |
| 2 | ASI02 | Tool Misuse/Exploitation | 25+ seeds | ✅ Excellent |
| 3 | ASI03 | Workflow Escalation | 8 seeds | ✅ Covered |
| 4 | ASI04 | Unauthorized Actions | 10 seeds | ✅ Covered |
| 5 | ASI05 | Privilege Escalation | 8 seeds | ✅ Covered |
| 6 | ASI06 | Memory Poisoning | 8 seeds | ✅ Covered |
| 7 | ASI07 | Cross-Agent Injection | 12 seeds | ✅ Excellent |
| 8 | ASI08 | Cascading Failures | 5 seeds | ✅ Covered |
| 9 | ASI09 | Trust Boundary Violation | 6 seeds | ✅ Covered |
| 10 | ASI10 | Rogue Agent | 8 seeds | ✅ Covered |

## Attack Vector Taxonomy v2.0

| Attack Vector | Description | OWASP Mapping | Seeds |
|---------------|-------------|---------------|-------|
| `direct_injection` | Direct prompt override | LLM01 | 30+ |
| `persona_injection` | Role-play/persona manipulation | LLM01, ASI01 | 30+ |
| `indirect_injection` | Via documents/tools/RAG | LLM01 | 15+ |
| `info_extraction` | Sensitive data extraction | LLM02, ASI04 | 20+ |
| `prompt_leakage` | System prompt leakage | LLM07 | 15+ |
| `tool_abuse` | Tool misuse/hijacking | ASI02, ASI03 | 25+ |
| `chain_exploitation` | Multi-step attack chains | ASI03, ASI05 | 15+ |
| `injection` | Payload injection (various) | LLM01, ASI07 | 30+ |
| `extraction` | Data exfiltration | ASI04 | 10+ |
| `schema_manipulation` | Schema/API manipulation | ASI02 | 10+ |
| `identity_forgery` | Agent identity spoofing | ASI01 | 10+ |
| `memory_injection` | Memory/state poisoning | ASI06 | 8+ |
| `boundary_crossing` | Trust boundary violation | ASI09 | 6+ |
| `fault_injection` | Cascading failure trigger | ASI08 | 5+ |
| `ui_deception` | UI rendering deception | ASI02 | 5+ |
| `encoding_evasion` | Token/encoding bypass | LLM01 | 10+ |
| **`image_injection`** | 🆕 Image carrier channel | LLM01, LLM02 | 6+ |
| **`audio_injection`** | 🆕 Audio carrier channel | LLM01 | 4+ |
| **`file_injection`** | 🆕 File format carrier | LLM01, LLM07 | 6+ |
| **`model_extraction`** | 🆕 Model theft/exfiltration | LLM10 | 8+ |
| **`parameter_inference`** | 🆕 Hyperparameter probing | LLM10 | 4+ |
| **`training_data_extract`** | 🆕 Memorized data extraction | LLM10 | 4+ |
| **`protocol_fuzzing`** | 🆕 Agent protocol attacks | ASI02, ASI09 | 18+ |
| **`supply_chain_poison`** | 🆕 SBOM/signature attacks | LLM05 | 11+ |
| **`misinformation_chain`** | 🆕 Deepfake/synthetic narratives | LLM09 | 17+ |
| **`adversarial_suffix`** | 🆕 GCG/optimized patterns | LLM01 | 16+ |

## Dynamic Seed Generation Engine

The `core/seed_dynamic_engine.py` module provides context-aware seed generation:

```python
from core.seed_dynamic_engine import SeedDynamicEngine

engine = SeedDynamicEngine(ctx)
personalized = engine.generate_seeds(category="LLM01", count=5)
engine.inject_seeds_into_ctx(personalized)
```

Features:
- **Persona rotation**: 4 dynamic persona templates
- **Capability targeting**: Maps seeds to detected target capabilities
- **Language adaptation**: Auto-detects target model language (en/zh)
- **Deduplication**: Semantic similarity check prevents seed collisions
- **Reference generation**: Realistic-looking audit reference numbers

## SeedRouter智能路由 (v3.0)

**`core/seed_router.py`** 提供Seed→Converter→Technique智能匹配，提升攻击成功率：

```python
from core.seed_router import SeedRouter
from core.context import PipelineContext

# 在PipelineContext上创建路由器
router = SeedRouter(ctx)

# 获取单个种子的最优配置
config = router.get_optimal_config(seed_metadata)
# 返回:
# {
#     "converters": ["DecompositionConverter", "ROT13Converter"],
#     "technique": "prompt_sending",
#     "enabled": True,
#     "reason": "attack_vector=encoding_evasion"
# }
```

### 路由决策逻辑

| 种子metadata | 推荐converter | 推荐technique |
|-------------|--------------|--------------|
| `attack_vector: direct_injection` | (无, 直接发送) | `prompt_sending` |
| `attack_vector: encoding_evasion` | `ROT13Converter`, `AsciiSmugglerConverter` | `prompt_sending` |
| `attack_vector: indirect_injection` | `PDFConverter:direct`, `WordDocConverter:direct` | `prompt_sending` |
| `attack_vector: multimodal_image_injection` | `PDFConverter:direct` | `prompt_sending` |
| `tool_hijack` | `SearchReplaceConverter` | `context_compliance` |
| `mcp_server_injection` | `SearchReplaceConverter` | `prompt_sending` |
| `suitable_for: crescendo` | (无) | `crescendo_simulated` |
| `suitable_for: tap` | (无) | `tap` |
| `suitable_for: pair` | (无) | `pair` |

### DoS/高token种子过滤 (默认禁用)

以下种子默认**禁用**以控制API成本，需 `--enable-dos` 显式启用:

- `owasp_id: LLM10` (Model DoS / Unbounded Consumption)
- `tier >= 3` (实验性种子, 低ASR高消耗)
- `category: dos_resource_exhaustion / recursive_expansion / training_data_extraction / knowledge_base_enum`

```bash
# 默认扫描 (禁用DoS seeds)
pyrit-mini --seed-file elite_jailbreaks

# 全扫描 (包含DoS seeds, 费钱!)
pyrit-mini --seed-file elite_jailbreaks --enable-dos
```

### 集成点

| 模块 | 集成方式 |
|------|---------|
| `arm/seed_ranker.py` | `CAPABILITY_SEED_MAP` 种子自动注册 |
| `arm/converter_selector.py` | `get_seed_routed_converters()` converter智能选择 |
| `arm/technique_picker.py` | `get_seed_optimal_technique()` technique智能选择 |
| `strike/executor.py` | 执行时查询router获取配置 |

## Seed Quality Assessment

The `core/seed_quality_assessor.py` module provides performance tracking:

```python
from core.seed_quality_assessor import SeedQualityAssessor

assessor = SeedQualityAssessor()
assessor.record_result(seed_hash, success=True, tokens_used=150)
report = assessor.generate_health_report()
assessor.retire_underperforming()  # Auto-retire ASR < 10% seeds
```

Features:
- **Automatic retirement**: Seeds with ASR < 10% after N samples
- **Warning flags**: Seeds with ASR < 25% need review
- **Age-based review**: Force review seeds older than 365 days
- **Category coverage tracking**: Identifies missing OWASP categories
- **Performance history**: Full audit trail in `asr_history.json`

## Metadata Standard (v3 — v2.0 Update)

```yaml
- value: "Your attack prompt here"
  metadata:
    # Required fields
    owasp_id: "LLM01"           # OWASP LLM/ASI category
    severity: "critical"        # critical/high/medium/low
    difficulty: "hard"          # easy/medium/hard/very_hard
    category: "prompt_injection" # Attack category tag

    # Standardized fields (v3)
    tier: 1                     # 1/2/3 (ASR tier classification)
    attack_vector: "direct_injection"  # Specific attack vector
    language: "en"              # en/zh/ja/ko/fr/de/es/ru/ar/mixed
    source: "curated"           # curated/academic/community/dynamic_engine

    # Optional fields
    arxiv_reference: "arXiv:2310.04451"  # Academic citation
    suitable_for: "crescendo"   # crescendo/tap/pair/red_teaming/prompt_sending
    adversarial_seed: "sunshine" # Backdoor trigger word (for LLM04)
    target_secret: "api_keys"   # Targeted secret type (for dynamic seeds)
    target_capability: "file_access"  # Target capability (for dynamic seeds)
    org_context: "Acme Corp"    # Organization context (for dynamic seeds)
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
| Deng et al. | arXiv:2310.02408 | Non-English jailbreaks |
| Carlini et al. | arXiv:2301.13188 | Training data extraction |
| Tramér et al. | arXiv:1609.02943 | Model extraction |
| Krishna et al. | arXiv:2311.10593 | Model extraction via API |
| Goldstein et al. | arXiv:2305.17553 | Generative influence ops |
| Wei et al. | arXiv:2307.15043 | Encoding evasion |
| Shayegani et al. | arXiv:2306.13254 | Unicode confusion |
| Ying et al. | arXiv:2401.06022 | FigStep: Vision jailbreak |
| Qi et al. | arXiv:2306.13213 | Visual adversarial examples |
| Bagdasaryan et al. | arXiv:2302.10149 | Diffusion model backdoors |
| Chao et al. | arXiv:2310.08419 | PAIR jailbreaking |
| Bailey et al. | arXiv:2306.13213 | Image hijacking |
| Mirsky et al. | arXiv:2302.07361 | Deepfake threats |
| Kandpal et al. | arXiv:2308.14032 | RAG data extraction |
| Shafran et al. | arXiv:2402.07967 | RAG security survey |

## ASR Enhancement Strategies

### Multilingual Evasion (Yong et al.)
- Use low-resource languages (Chinese, Japanese, Arabic) for +2x ASR
- Mix languages within single prompt for +15% ASR
- Target languages with weaker safety filter coverage

### Template-Based Jailbreaks
- DAN/AIM/Developer Mode/SK templates: historical ASR 40-80%
- PAIR/TAP iterative optimization: dynamic ASR improvement
- Crescendo gradual escalation: multi-turn ASR amplification
- Best-of-N variation: parallel seed testing for optimal selection

### Multimodal Attack Channels
- **Image injection**: Embed text/pixel encodings in image attachments
- **Audio injection**: Steganography in audio carrier (ultrasonic)
- **File injection**: Macro/metadata/watermark exploitation
- **Cross-modal bypass**: Different carrier = different filter pipeline

### Supply Chain & Protocol Attacks
- **SBOM manipulation**: Inject entries into software manifests
- **Signature bypass**: Metadata-based crypto verification circumvention
- **MCP protocol fuzzing**: Malformed message structure exploitation
- **Agent lifecycle**: Spawn/terminate/update race conditions

## Seed Selection Mechanism

1. **UCB Ranking**: ASR history + Bayesian UCB (`seed_ranker.py`)
2. **Category Diversity**: DPP ensures ≥1 seed per OWASP category
3. **Capability Targeting**: Deep probing triggers targeted seed injection
4. **MTOS**: Multi-turn attack reverse selection (low-medium ASR seeds first)
5. **Dynamic Generation**: `SeedDynamicEngine` creates context-aware personalized seeds
6. **Auto-Retirement**: `SeedQualityAssessor` prunes underperforming seeds

## File Naming Convention

```
{tier}_{category}_{specific}.prompt

Examples:
  T1_LLM01_elite_jailbreaks.prompt       → Tier 1, LLM01, elite jailbreaks
  T2_LLM07_system_prompt_leakage.prompt   → Tier 2, LLM07, prompt leakage
  T3_LLM10_dos_resource_exhaustion.prompt → Tier 3, LLM10, DoS
  T1_multimodal_injection.prompt          → Tier 1, Multimodal, all carriers
  T1_agent_protocol_fuzzing.prompt        → Tier 1, Protocol attacks
  T2_gcg_adversarial_templates.prompt     → Tier 2, GCG/adversarial patterns
  T1_LLM10_model_theft.prompt             → Tier 1, Model Theft

Prefix Legend:
  T1_  = High-ASR (>50%) — default scan
  T2_  = Medium-ASR (20-50%) — extended scan / optimized templates
  T3_  = Experimental (<20%) — research only
```

## Production Checklist

- [x] OWASP LLM Top 10 (2025) — 10/10 covered
- [x] OWASP ASI Top 10 (2025) — 10/10 covered
- [x] Multimodal attack carriers (image/audio/file)
- [x] Model theft & extraction coverage (LLM10)
- [x] Supply chain poisoning (SBOM/dependencies)
- [x] Agent protocol fuzzing (MCP/HTTP/gRPC)
- [x] Misinformation deepfake chains (LLM09)
- [x] GCG adversarial templates & optimization patterns
- [x] Dynamic seed generation engine (`core/seed_dynamic_engine.py`)
- [x] Seed quality assessment & auto-retirement (`core/seed_quality_assessor.py`)
- [x] Coverage: 350+ seeds across 25+ attack vectors
- [x] Academic references for all attack techniques
- [x] Standardized metadata format (v3)
