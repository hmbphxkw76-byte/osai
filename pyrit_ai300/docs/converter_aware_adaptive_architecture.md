# Converter-Aware Adaptive Architecture 鈥?鍘熺敓浼樺厛 Converter 娓愯繘寮忓崌绾ф灦鏋?

> 鐗堟湰: 4.0.0 | 鏃ユ湡: 2026-07-28

## 1. 鏋舵瀯姒傝堪

鏈枃妗ｆ弿杩?AI-300 椤圭洰鐨?**Converter-Aware Adaptive Architecture** 鈥?閫氳繃鍘熺敓 PyRIT 鏈哄埗瀹炵幇 Converter 娓愯繘寮忓崌绾э紝娑堥櫎鑷缓 `AttackUpgradeStrategy` 鍙岃建銆?

### v4.0 鏂板锛堟柟妗圖锛?

| 鏂板姛鑳?| 鎻忚堪 |
|------|------|
| **ASR Prior Registry** | 寮曞叆 JailbreakBench/HarmBench 瀛︽湳 ASR 鍏堥獙 Q 鍊硷紝娑堥櫎鍐峰惎鍔ㄩ殢鏈烘帰绱?|
| **Tiered Prioritization** | 鎶€鏈垎 Tier S/A/B/C锛屾寜 ASR 鍒嗗眰鎺掑簭 |
| **Strategy Modes** | `academic`/`exam`/`balanced` 涓夌绛栫暐妯″紡鍙垏鎹?|
| **Model-Tier Awareness** | 寮鸿繃婊?GPT-4o)/寮辫繃婊?GPT-3.5)妯″瀷鍒嗗眰璺敱 |
| **Pipeline Display** | [3/9]/[5/9]/[6/9] 闃舵鍏抽敭閫夋嫨缁撴灉瀹炴椂灞曠ず |
| **Academic Payload Cache** | 楂?ASR 杞借嵎鏈湴缂撳瓨 (`data/academic/`)锛岀绾垮彲鐢?|

### 1.1 璁捐鍘熷垯

| 鍘熷垯 | 鎻忚堪 |
|------|------|
| **鍘熺敓浼樺厛** | 浣跨敤 PyRIT 鍘熺敓 `AdaptiveScenario` + `AdaptiveTechniqueDispatcher` + `SequentialAttack(FIRST_SUCCESS)` |
| **鍘熺敓 extra_request_converters** | v3.0: 浣跨敤鍘熺敓 `AttackTechniqueFactory.create(extra_request_converters=...)` 鍔ㄦ€佸垱寤哄彉浣擄紝涓嶅啀棰勬敞鍐?110+ 宸ュ巶 |
| **娑堥櫎鍙岃建** | 绉婚櫎鑷缓 `AttackUpgradeStrategy` 鐨勫鍊欓€夐€掑綊閫昏緫锛屼緷璧栧師鐢?`FIRST_SUCCESS` 鎻愬墠鍋滄 |
| **澶辫触鎰熺煡璺敱** | P0-A: 鎵ц鍚庢彁鍙栧け璐ョ被鍨嬶紝鏇存柊 selector锛堜緵 resume 浣跨敤锛? memory 鎸佷箙鍖栵紙璺?run 瀛︿範锛?|
| **SelectorScope** | P1-A: 鍘熺敓 `SelectorScope` 闄愬畾瀛︿範鑼冨洿锛坅ll_runs / current_run锛?|
| **淇濈暀鑷缓** | OWASP 鏄犲皠锛堥€氳繃 `memory_labels`锛墊

### 1.2 鏍稿績鏋舵瀯

```
鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
鈹?                   pipeline.py                                    鈹?
鈹? USE_LEGACY_DIRECT=false (榛樿) 鈫?run_adaptive_scenario_async() 鈹?
鈹? USE_LEGACY_DIRECT=true  鈫?Legacy 鐩存帴鎵归噺 (deprecated)          鈹?
鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
                            鈹?
鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈻尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
鈹?             adaptive_runner.py                                    鈹?
鈹? 1. register_ai300_techniques(include_variants=False)  鈫?浠呭熀纭€   鈹?
鈹? 2. AI300AdaptiveScenario(converter_target, target_type, owasp_id)鈹?
鈹? 3. scenario.initialize_async() + run_async()                    鈹?
鈹? 4. P0-A: 澶辫触绫诲瀷鍒嗘瀽 鈫?extract_failure_type_from_result        鈹?
鈹?    鈫?selector.update_failure_type() (渚?resume 浣跨敤)             鈹?
鈹? 5. _convert_native_to_batch_result() (鍚戝悗鍏煎)                  鈹?
鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
                            鈹?
鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈻尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
鈹?          AI300AdaptiveScenario (extends AdaptiveScenario)        鈹?
鈹? 鈹溾攢 _infer_target_type() 鈫?鑷姩鎺ㄦ柇 (14 绫诲悕鏄犲皠)                 鈹?
鈹? 鈹溾攢 _build_techniques_dict() 鈫?v3.0 瑕嗙洊                           鈹?
鈹? 鈹?  鈹溾攢 super() 鈫?鍩虹鎶€鏈?bundles (鏋氫妇椹卞姩)                    鈹?
鈹? 鈹?  鈹溾攢 _filter_by_modality() 鈫?ModalityRouter 杩囨护              鈹?
鈹? 鈹?  鈹斺攢 鍘熺敓 extra_request_converters 鍔ㄦ€佸垱寤哄彉浣?bundles        鈹?
鈹? 鈹?      (factory.create(extra_request_converters=chain.converters))鈹?
鈹? 鈹溾攢 _get_attack_technique_factories() 鈫?浠?super() (P1-C)        鈹?
鈹? 鈹溾攢 FailureTypeRoutingSelector (with SelectorScope) [P1-A]       鈹?
鈹? 鈹?  鈹溾攢 epsilon-greedy (鍘熺敓 memory 瀛︿範)                        鈹?
鈹? 鈹?  鈹溾攢 澶辫触绫诲瀷璺敱 (P0-A 鎵ц鍚庢縺娲?                            鈹?
鈹? 鈹?  鈹溾攢 Converter 鍙樹綋鎰熺煡鎺掑簭                                    鈹?
鈹? 鈹?  鈹斺攢 OWASP 绛栫暐鍋忓ソ (v2.0)                                    鈹?
鈹? 鈹斺攢 鍘熺敓 max_retries + max_concurrency (寮规€ф仮澶?                鈹?
鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
                            鈹?
鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈻尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
鈹?        鍘熺敓 AdaptiveTechniqueDispatcher                           鈹?
鈹? 鈹溾攢 SequentialAttack(FIRST_SUCCESS)                               鈹?
鈹? 鈹?  鈹溾攢 attempt 1: prompt_sending (鏃?Converter)                  鈹?
鈹? 鈹?  鈹溾攢 attempt 2: prompt_sending + extra_request_converters     鈹?
鈹? 鈹?  鈹?             (stealth_evasion) [鍘熺敓娓愯繘寮忚拷鍔燷            鈹?
鈹? 鈹?  鈹溾攢 attempt 3: prompt_sending + extra_request_converters     鈹?
鈹? 鈹?  鈹?             (encoding_bypass) [鍘熺敓娓愯繘寮忚拷鍔燷            鈹?
鈹? 鈹?  鈹斺攢 鎴愬姛鍗冲仠姝?鈫?澶╃劧鏇夸唬鑷缓閫掑綊鍗囩骇                          鈹?
鈹? 鈹斺攢 澶辫触绫诲瀷鍙嶉 鈫?selector.update_failure_type() [P0-A]         鈹?
鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
```

## 2. P0-B: 鍘熺敓 extra_request_converters 娓愯繘寮忓崌绾?(v3.0)

### 2.1 璁捐

v3.0 浣跨敤 PyRIT 鍘熺敓 `AttackTechniqueFactory.create(extra_request_converters=...)` 鍔ㄦ€佸垱寤?Converter 鍙樹綋銆?

**v2.0 鏂规锛堝凡搴熷純锛?*锛氫负姣忎釜鍩虹鎶€鏈?脳 姣忎釜 Converter 閾惧垱寤虹嫭绔嬬殑 `AttackTechniqueFactory`锛屽皢瀹屾暣 `AttackConverterConfig` 鐑樼剻鍒?`attack_kwargs` 涓€傚鑷?Registry 鑶ㄨ儉鑷?110+ 鏉＄洰銆?

**v3.0 鏂规锛堝綋鍓嶏級**锛歊egistry 浠呬繚鐣?~34 涓熀纭€鎶€鏈€傚湪 `_build_techniques_dict()` 涓紝涓烘瘡涓凡瑙ｆ瀽鐨勫熀纭€鎶€鏈紝浣跨敤 `factory.create(extra_request_converters=...)` 鍔ㄦ€佸垱寤哄彉浣?TechniqueBundle銆俙extra_request_converters` 鏄師鐢?additive 鏈哄埗 鈥?鍦ㄥ凡鏈?Converter 鍩虹涓婅拷鍔狅紝鑰岄潪鏇挎崲銆?

### 2.2 Converter 鍙樹綋閾撅紙22 鏉★級

| 閾惧悕 | 妯℃€?| 闇€瑕?LLM | 浼樺厛绾?| 鎻忚堪 |
|------|------|---------|--------|------|
| `stealth_evasion` | text | 鍚?| 1 | Unicode 娣锋穯 + Base64 + 鍚庣紑杩藉姞 |
| `encoding_bypass` | text | 鍚?| 2 | Base64 + ROT13 + Caesar 缂栫爜缁曡繃 |
| `multi_encoding_v2` | text | 鍚?| 1 | 鍥涘眰缂栫爜: Base64 + ROT13 + Caesar(5) + Atbash |
| `agent_injection_chain` | text | 鍚?| 3 | Agent 娉ㄥ叆: Unicode 娣锋穯 + 鍚庣紑杩藉姞 + 浠诲姟浼 |
| `policy_puppetry` | text | 鍚?| 3 | 绛栫暐鍌€鍎? 妯℃嫙绯荤粺绛栫暐鏍煎紡缁曡繃瀹夊叏妫€鏌?|
| `unicode_attack` | text | 鍚?| 2 | Unicode 娣锋穯 + 鍙屽悜鏂囨湰 + 闆跺瀛楃 |
| `random_case` | text | 鍚?| 3 | 闅忔満澶у啓瀛楃缁曡繃鍏抽敭璇嶆娴?|
| `format_injection` | text | 鍚?| 2 | ASCII 鑹烘湳鏍煎紡娉ㄥ叆 |
| `text_jailbreak` | text | 鍚?| 3 | 瓒婄嫳妯℃澘鍖呰 (闇€杩愯鏃跺弬鏁? |
| `xpia_stealth_chain` | file | 鍚?| 1 | XPIA 闅愬啓: PDF 鐧借壊灏忓瓧宓屽叆 (闇€杩愯鏃跺弬鏁? |
| `pdf_injection` | file | 鍚?| 2 | PDF 娉ㄥ叆 (闇€杩愯鏃跺弬鏁? |
| `worddoc_injection` | file | 鍚?| 3 | WordDoc 娉ㄥ叆 (闇€杩愯鏃跺弬鏁? |
| `multimodal_image_attack` | image | 鍚?| 1 | 澶氭ā鎬佸浘鐗囨敾鍑? 鏂囨湰鈫扱R鐮佸浘鐗?|
| `multimodal_steganography` | image | 鍚?| 2 | 澶氭ā鎬侀殣鍐?(闇€杩愯鏃跺弬鏁? |
| `llm_assisted` | text | 鏄?| 3 | 璇存湇 + 璇皵 + 缈昏瘧 (LLM 杈呭姪) |
| `persuasion_authority` | text | 鏄?| 4 | 鏉冨▉璇存湇: authority_endorsement + formal + en |
| `persuasion_chain` | text | 鏄?| 5 | 璇存湇鏀诲嚮閾?(LLM 杈呭姪) |
| `decomposition_chain` | text | 鏄?| 3 | 鍒嗚В閲嶆瀯: 灏嗘湁瀹宠姹傚垎瑙ｄ负鏃犲瀛愪换鍔?|
| `decomposition_policy_chain` | text | 鏄?| 3 | 鍒嗚В+閲嶆瀯: 鍒嗚В涓哄瓙浠诲姟 + 浠诲姟妗嗘灦鍖呰 |
| `policy_puppetry_chain` | text | 鏄?| 4 | 绛栫暐鍌€鍎?璇皵: PolicyPuppetry + Tone |
| `task_framing_chain` | text | 鏄?| 4 | 浠诲姟妗嗘灦+璇存湇: TaskFraming + Persuasion |
| `noise_case_chain` | text | 鏄?| 2 | 鍣０ + 闅忔満澶у啓 + Base64 (LLM 杈呭姪鍣０鐢熸垚) |

### 2.3 涓夊眰杩囨护

1. **R0 Target 鎰熺煡**: 褰?`target_type` 鎻愪緵鏃讹紝浣跨敤 `TargetAwareConverterRouter` 鎺ㄨ崘閾惧簭鍒楁浛浠ｉ潤鎬佹槧灏?
2. **LLM 鍙敤鎬?*: 闈?LLM 閾炬棤闇€ `converter_target`锛汱LM 閾鹃渶 `converter_target`
3. **R2 妯℃€佸吋瀹?*: 褰?`objective_target` 鎻愪緵鏃讹紝浣跨敤 `ModalityRouter` 妫€娴?Target 鑳藉姏

### 2.4 閫傜敤鍩虹鎶€鏈?

浠呭崟杞妧鏈€傚悎杩藉姞 Converter锛堝杞妧鏈唴閮ㄥ凡鏈?adversarial chat 杩唬锛夛細

- `prompt_sending` 鈫?14 鏉￠摼
- `many_shot` 鈫?5 鏉￠摼
- `skeleton_key` 鈫?3 鏉￠摼
- `chunked_request` 鈫?3 鏉￠摼
- `multi_prompt_sending` 鈫?2 鏉￠摼

### 2.5 鍘熺敓 API

```python
# v3.0: 鍦?_build_techniques_dict() 涓姩鎬佸垱寤哄彉浣?
converter_config = load_preset_converter_chain(chain_name, converter_target)
extra_converters = converter_config.request_converters

technique = factory.create(
    objective_target=objective_target,
    attack_scoring_config=scoring_config,
    extra_request_converters=extra_converters,  # 鍘熺敓 additive 杩藉姞
)
```

## 3. P0-A: 澶辫触绫诲瀷鍒嗘瀽

### 3.1 闂鏍瑰洜

v2.0 涓?`extract_failure_type_from_result()` 宸插疄鐜颁絾浠庢湭琚皟鐢紝`FailureTypeRoutingSelector._last_failure_type` 濮嬬粓涓?`None`锛屾墍鏈夊け璐ョ被鍨嬭矾鐢辩瓥鐣ュ叏閮ㄥけ鏁堛€?

### 3.2 v3.0 淇

鍦?`adaptive_runner.py` 鐨勬墽琛屽悗闃舵锛?
1. 閬嶅巻鎵€鏈?`AttackResult`锛堝惈 `SequentialAttackResult.child_attack_results`锛?
2. 瀵规瘡涓け璐ョ粨鏋滆皟鐢?`extract_failure_type_from_result()`
3. 鑱氬悎澶辫触绫诲瀷鍒嗗竷锛坄Counter`锛?
4. 鏇存柊 selector 鐨?`_last_failure_type`锛堜緵 resume 鍦烘櫙浣跨敤锛?
5. 瀛樺偍鍒?`AdaptiveRunResult.failure_type_distribution`

### 3.3 澶辫触绫诲瀷璺敱绛栫暐

| 澶辫触绫诲瀷 | 鎺掑簭绛栫暐 | 鍘熺悊 |
|---------|---------|------|
| `model_refusal` | Converter 鍙樹綋浼樺厛锛堟寜閾句紭鍏堢骇鎺掑簭锛墊 缂栫爜/娣锋穯缁曡繃鍐呭杩囨护 |
| `timeout` | 鍩虹鍗曡疆鎶€鏈紭鍏堬紙鏃?Converter锛墊 鍑忓皯杞崲寮€閿€鍜屾墽琛屾椂闂?|
| `objective_not_achieved` | 寮烘妧鏈?+ Converter 鍙樹綋浼樺厛 | 澶氳疆鍗囩骇 + 缂栫爜缁曡繃 |
| `scorer_validation_error` | 淇濇寔 epsilon-greedy 榛樿鎺掑簭 | 鎶€鏈鏍锋€?|
| `None`锛堥娆★級 | OWASP 鍋忓ソ + Converter 鍙樹綋 + 缂栫爜浼樺厛 | 蹇€熼珮鎴愬姛鐜?|

### 3.4 鏋舵瀯闄愬埗璇存槑

鍘熺敓 `AdaptiveScenario` 鍦?`initialize_async()` 鏃跺畬鎴愭墍鏈夋妧鏈€夋嫨锛坄selector.select_async()`锛夛紝鎵ц鍦?`run_async()` 鏃舵墠寮€濮嬨€傚洜姝わ細
- **褰撳墠 run 鍐?*锛氬け璐ョ被鍨嬭矾鐢辨棤娉曞奖鍝嶅凡鏋勫缓鐨勬妧鏈帓搴?
- **Resume 鍦烘櫙**锛歴elector 淇濆瓨鐨?`_last_failure_type` 褰卞搷鎭㈠鍚庣殑鍒濆鎺掑簭
- **璺?run 瀛︿範**锛氬師鐢?epsilon-greedy 閫氳繃 memory 鍘嗗彶鎴愬姛鐜囧疄鐜拌法 run 瀛︿範

## 4. P1-A: SelectorScope 闄愬畾瀛︿範鑼冨洿

### 4.1 鍘熺敓 API

```python
from pyrit.scenario.scenarios.adaptive.selectors import SelectorScope

# all_runs (榛樿): 鍒╃敤鍏ㄩ儴鍘嗗彶鏁版嵁锛堣法 run 瀛︿範锛?
scope = SelectorScope.all_runs()

# current_run: 浠呭涔犲綋鍓?run锛堥伩鍏嶈法妯″瀷骞叉壈锛?
scope = SelectorScope.current_run()

# 鎸?harm category 杩囨护
scope = SelectorScope(targeted_harm_categories=["hate", "violence"])
```

### 4.2 浣跨敤鏂瑰紡

```python
selector = AI300EpsilonGreedySelector(
    target_type="openai_chat",
    owasp_id="LLM01",
    scope=SelectorScope.all_runs(),  # 榛樿
)
```

## 5. P1-B: 绉婚櫎 per_attack_timeout

### 5.1 鍐崇瓥

v3.0 绉婚櫎 `per_attack_timeout` Parameter 澹版槑銆傚師鍥狅細
- 鍘熺敓 `max_retries` 鎻愪緵 Scenario 绾у埆寮规€ф仮澶?
- 鍘熺敓 `max_concurrency` 鎺у埗骞惰搴?
- `asyncio.wait_for` 鍖呰９鏁翠釜 `scenario.run_async()` 浼氱牬鍧忓師鐢熺殑 retry/resume 鏈哄埗
- PyRIT 鍘熺敓 `AttackExecutor` 鏈夊唴缃殑 timeout 鍜?retry 鏈哄埗

### 5.2 鍚戝悗鍏煎

`adaptive_runner.py` 鐨勫嚱鏁扮鍚嶄繚鐣?`per_attack_timeout` 鍙傛暟锛堟爣璁?deprecated锛夛紝浣嗕笉鍐嶄紶閫掔粰 Scenario銆?

## 6. P1-C: 娑堥櫎鎶€鏈敞鍐屽弻閲嶈皟鐢?

### 6.1 闂

v2.0 涓?`register_ai300_techniques()` 鍦?`adaptive_runner.py` 鏄惧紡璋冪敤锛堟敞鍐屽彉浣撳埌 Registry锛夛紝鍚屾椂 `_get_attack_technique_factories()` 瑕嗗啓涔熻皟鐢?`build_converter_variant_factories()`锛堝啀娆℃瀯寤哄彉浣擄級銆俙build_converter_variant_factories()` 琚皟鐢ㄤ袱娆°€?

### 6.2 v3.0 淇

- `_get_attack_technique_factories()` 绠€鍖栦负浠?`super()`锛堜笉鍚彉浣擄級
- `register_ai300_techniques()` 璋冪敤鏃?`include_variants=False`
- 鍙樹綋鍦?`_build_techniques_dict()` 涓€氳繃 `extra_request_converters` 鍔ㄦ€佸垱寤?

## 7. 鐜鍙橀噺

| 鍙橀噺 | 榛樿 | 鎻忚堪 |
|------|------|------|
| `USE_LEGACY_DIRECT` | `false` | `false`=鍘熺敓 AdaptiveScenario (榛樿); `true`=Legacy 鐩存帴鎵归噺 (deprecated) |
| `STRATEGY_MODE` | `academic` | 绛栫暐妯″紡: `academic`=绛栫暐浼樺厛 / `exam`=缂栫爜浼樺厛 / `balanced`=鍧囪　 |
| `TARGET_MODEL_FOR_ASR` | (绌? | 鐢ㄤ簬 ASR 鏌ヨ鐨勬ā鍨嬪悕 (鐣欑┖=鑷姩浠?TARGET_MODEL 鎺ㄦ柇) |
| `ACADEMIC_PAYLOADS_ENABLED` | `false` | 鍚敤 `data/academic/` 鏈湴瀛︽湳杞借嵎 (闇€鍏堣繍琛屼笅杞? |

## 8. Pipeline 鍏抽敭閫夋嫨缁撴灉灞曠ず (v4.0)

### 8.1 灞曠ず闃舵

| 闃舵 | 灞曠ず鍐呭 | 妯″潡 |
|------|---------|------|
| **[3/9] 鍒嗘瀽** | 绛栫暐妯″紡 + 妯″瀷鍒嗗眰 + 杩囨护寮哄害鎺ㄦ柇 | `display_analysis_stage()` |
| **[5/9] 閫夋嫨** | ASR 鍏堥獙鎺掑簭 + Tier 鍒嗗眰 + 瀛︽湳鏁版嵁鍙鍖?| `display_selection_stage()` |
| **[6/9] 鎵ц鍓?* | Target 鎰熺煡璺敱 + 鎶€鏈墽琛岄『搴?+ 澶辫触璺敱绛栫暐琛?| `display_execution_stage()` |
| **[6/9] 鎵ц鍚?* | ASR 瀹炴祴 vs 瀛︽湳鍏堥獙瀵规瘮 + 澶辫触绫诲瀷鍒嗗竷 | `display_post_execution()` |

### 8.2 灞曠ず绀轰緥

```
  鈹屸攢 鏂规D: 绛栫暐鍒嗘瀽 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
  鈹?绛栫暐妯″紡: academic
  鈹?  鈫?瀛︽湳鍏堥獙椹卞姩 (绛栫暐浼樺厛, 楂?ASR 鎶€鏈紭鍏堝皾璇?
  鈹?鐩爣妯″瀷: gpt-4o
  鈹?妯″瀷鍒嗗眰: strong (寮哄唴瀹硅繃婊?鈫?绛栫暐鏀诲嚮浼樺厛, 缂栫爜鏀诲嚮浣庢晥)
  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?

  鈹屸攢 鏂规D: 瀛︽湳 ASR 鍏堥獙鎺掑簭 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
  鈹?妯″瀷: gpt-4o | 绛栫暐: academic
  鈹?
  鈹?Tier S (ASR >=70%) 鈥?澶氳疆杩唬鏀诲嚮:
  鈹?  crescendo                              82% 鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻戔枒鈻戔枒
  鈹?
  鈹?Tier A (ASR 40-70%) 鈥?鏍戞悳绱?杩唬/妯℃嫙瀵硅瘽:
  鈹?  tap                                    62% 鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻戔枒鈻戔枒鈻戔枒鈻戔枒
  鈹?  pair                                   53% 鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻堚枅鈻戔枒鈻戔枒鈻戔枒鈻戔枒鈻戔枒
  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?

  鈹屸攢 鏂规D: 鎵ц鍐崇瓥 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
  鈹?Target 璺敱: openai_chat 鈫?llm_direct_strong
  鈹?澶辫触绫诲瀷璺敱绛栫暐:
  鈹?  model_refusal       鈫?绛栫暐鍗囩骇 (Tier S/A 浼樺厛)
  鈹?  timeout             鈫?闄嶇骇鍒板崟杞?(prompt_sending)
  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?

  鈹屸攢 鏂规D: ASR 瀹炴祴 vs 瀛︽湳鍏堥獙 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
  鈹?鎶€鏈?                                    瀹炴祴ASR 瀛︽湳鍏堥獙     宸紓   鏍锋湰
  鈹?crescendo                                   90%      82%    +8% 鈫?    5
  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
```

## 9. 瀛︽湳杞借嵎鏈湴缂撳瓨 (v4.0)

### 9.1 涓嬭浇

```bash
# 涓嬭浇鍏ㄩ儴楂?ASR 鏁版嵁闆?(JailbreakBench + HarmBench + AdvBench)
python download_academic_payloads.py

# 浠呬笅杞?JailbreakBench
python download_academic_payloads.py jailbreakbench

# 鍒楀嚭宸蹭笅杞界殑杞借嵎
python download_academic_payloads.py --list
```

### 9.2 鐩綍缁撴瀯

```
data/academic/
  jailbreakbench/
    tier_s_crescendo.yaml          # ASR >= 70%
    tier_s_red_teaming.yaml
    tier_a_tap.yaml                # ASR 40-70%
    tier_a_pair.yaml
    tier_b_persuasion_authority.yaml  # ASR 15-40%
  harmbench/
    tier_s_crescendo_hb.yaml
    tier_a_tap_hb.yaml
  advbench/
    tier_b_direct_injection.yaml
  _manifest.yaml                   # 涓嬭浇娓呭崟
```

### 9.3 闆嗘垚鍒?Pipeline

```bash
# .env
ACADEMIC_PAYLOADS_ENABLED=true
```

鍚敤鍚?`DatasetManager.load_datasets(academic=True)` 鑷姩鍔犺浇 `data/academic/` 涓嬬殑 YAML 鏂囦欢鍒?CentralMemory銆?

### 9.4 杩囨护绛栫暐

- **鏈€浣?ASR 闃堝€?*: 15% (Tier B 浠ヤ笂鎵嶄笅杞?
- **Tier C 杩囨护**: `prompt_sending`/`rot13`/`base64` 绛変綆 ASR 鎶€鏈笉涓嬭浇
- **patched 鏍囪**: 宸茶琛ヤ竵淇鐨勬妧鏈爣璁颁絾涓嶆帓闄わ紙瀵规棫鐗堟湰妯″瀷浠嶆湁鏁堬級
- **per-model ASR**: 涓嬭浇鏃舵寜 `TARGET_MODEL_FOR_ASR` 鏌ヨ瀵瑰簲妯″瀷鐨?ASR

## 11. 娑堥櫎鍙岃建瀵圭収琛?

| 鑷缓閫昏緫 | 鍘熺敓鏇夸唬 | 鐘舵€?|
|---------|---------|------|
| `AttackUpgradeStrategy.generate_upgrade_plans()` | `AdaptiveTechniqueDispatcher` 鑷姩鏋勫缓 | 鉁?娑堥櫎 |
| `AttackUpgradeStrategy._add_converter()` | 鍘熺敓 `extra_request_converters` (v3.0) | 鉁?娑堥櫎 |
| `ScenarioOrchestrator._try_upgrade_plans()` 閫掑綊 | `SequentialAttack(FIRST_SUCCESS)` 鎻愬墠鍋滄 | 鉁?娑堥櫎 |
| `extract_failure_type()` 鈫?`add_converter` 璺敱 | `FailureTypeRoutingSelector` + P0-A 鍒嗘瀽 | 鉁?娑堥櫎 |
| 鍙樹綋棰勬敞鍐?`build_converter_variant_factories()` | 鍘熺敓 `extra_request_converters` (v3.0) | 鉁?娑堥櫎 |
| `per_attack_timeout` | 鍘熺敓 `max_retries` + `max_concurrency` (v3.0) | 鉁?绉婚櫎 |
| OWASP 鏄犲皠 | 閫氳繃 `memory_labels` 闆嗘垚 | 馃敀 淇濈暀鑷缓 |

## 10. 鏂囦欢鍙樻洿娓呭崟

| 鏂囦欢 | 鍙樻洿绫诲瀷 | 鎻忚堪 |
|------|---------|------|
| `src/scenarios/ai300_adaptive_scenario.py` | 閲嶅啓 | v3.0: extra_request_converters + P1-A/P1-B/P1-C |
| `src/scenarios/adaptive_runner.py` | 閲嶅啓 | P0-A: 澶辫触绫诲瀷鍒嗘瀽 + P1-B: 绉婚櫎 per_attack_timeout |
| `src/scenarios/failure_type_selector.py` | 淇敼 | P1-A: SelectorScope + 鏂规D: Tier 鍒嗗眰 + 绛栫暐妯″紡 |
| `src/payloads/asr_prior_registry.py` | 鏂板 | 鏂规D: JailbreakBench/HarmBench 瀛︽湳 ASR 鍏堥獙鏁版嵁 |
| `src/scenarios/plan_d_display.py` | 鏂板 | 鏂规D: Pipeline 鍏抽敭閫夋嫨缁撴灉灞曠ず |
| `src/payloads/payload_downloader.py` | 鏂板 | 鏂规D: 楂?ASR 瀛︽湳杞借嵎鏈湴涓嬭浇鍣?|
| `download_academic_payloads.py` | 鏂板 | 鏂规D: 涓嬭浇 CLI 鍏ュ彛 |
| `pipeline.py` | 淇敼 | 闆嗘垚鏂规D灞曠ず + strategy_mode/model_name 閫忎紶 + academic 鏁版嵁婧?|
| `src/payloads/dataset_manager.py` | 淇敼 | 鏂板 load_academic_datasets() + load_datasets(academic=) |
| `src/payloads/__init__.py` | 淇敼 | 瀵煎嚭 payload_downloader API |
| `src/scenarios/__init__.py` | 淇敼 | 瀵煎嚭 plan_d_display API |
| `src/core/config_loader.py` | 淇敼 | 鏂板 academic 閰嶇疆鏀寔 |
| `.env` | 淇敼 | 鏂板鏂规D鐜鍙橀噺 |
| `docs/converter_aware_adaptive_architecture.md` | 閲嶅啓 | v4.0 鏂囨。鍚屾 |
| `tests/unit/test_plan_d_display.py` | 鏂板 | 31 涓祴璇曡鐩栧睍绀?+ 涓嬭浇鍣?|

## 12. Exploitation-Exploration 骞宠　

### 10.1 瀛︽湳鍩虹

鑷€傚簲鏀诲嚮鐨勬牳蹇冨湪浜?**exploitation-exploration 骞宠　**锛?
- **Exploration**锛氬皾璇曟湭浣跨敤鐨勬妧鏈紝鍙戠幇鏂扮殑鏀诲嚮璺緞
- **Exploitation**锛氫紭鍏堜娇鐢ㄥ巻鍙叉垚鍔熺巼楂樼殑鎶€鏈紝鏈€澶у寲褰撳墠鏁堟灉

### 10.2 鍘熺敓瀹炵幇

PyRIT 鍘熺敓 `EpsilonGreedyTechniqueSelector` 鐢?Laplace 骞虫粦瀹炵幇姝ゅ钩琛★細
- **Exploration**锛氫互姒傜巼 `epsilon`锛堥粯璁?0.2锛夐殢鏈洪€夋嫨鎶€鏈?
- **Exploitation**锛氫互姒傜巼 `1-epsilon` 閫夋嫨鍘嗗彶鎴愬姛鐜囨渶楂樼殑鎶€鏈?
- **Laplace 骞虫粦**锛氭湭瑙佽繃鎶€鏈垵濮嬩及璁?`(0+1)/(0+1)=1.0`锛堜箰瑙傚垵濮嬪寲锛夛紝榧撳姳鎺㈢储鏂版妧鏈?
- **Memory 椹卞姩**锛氭墍鏈夋暟鎹潵鑷?memory 鏁版嵁搴擄紝鏃犲唴閮ㄧ姸鎬?

### 10.3 AI-300 澧炲己灞?

| 灞?| 鏈哄埗 | 鏉ユ簮 |
|----|------|------|
| L0: Epsilon-Greedy | Laplace 骞虫粦 + memory 瀛︿範 | PyRIT 鍘熺敓 |
| L1: FIRST_SUCCESS | 棣栨鎴愬姛鍗冲仠姝?| PyRIT 鍘熺敓 |
| L2: OWASP 鍋忓ソ | 鍒濆鎺掑簭瀵归綈 Legacy 璺緞 | 鑷缓 (v2.0) |
| L3: 澶辫触绫诲瀷璺敱 | 澶辫触鎰熺煡鎶€鏈噸鎺?| 鑷缓 (P0-A 婵€娲? |
| L4: Target 鎰熺煡 | 鎸?Target 绫诲瀷鎺掑簭 Converter 閾?| 鑷缓 (R0-R6) |
| L5: ModalityRouter | 杩囨护 Target 涓嶆敮鎸佺殑鎶€鏈?| 鑷缓 (L5) |
| L6: SelectorScope | 闄愬畾瀛︿範鑼冨洿 | PyRIT 鍘熺敓 (P1-A) |

