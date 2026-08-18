"""L5 优化方案 O1-O7 单元测试.

学术依据: HarmBench (arXiv:2402.04249), JailbreakBench (arXiv:2402.01135),
  Greshake et al. (arXiv:2302.12173), Russinovich et al. (arXiv:2402.12109)
"""

from unittest.mock import MagicMock

# ── O1: 侦察种子层注入 ──


class TestO1ReconSeeds:
    """O1: 侦察种子层加载与注入."""

    def test_load_recon_seeds(self):
        """O1: 加载4个YAML侦察种子集."""
        from pipeline.stages.stage_scenario import _load_recon_seeds

        seeds = _load_recon_seeds()
        assert len(seeds) > 0, "侦察种子应非空"

        # 检查4个类别都存在
        categories = {s.get("category") for s in seeds}
        assert "recon_system_prompt" in categories
        assert "recon_tool_list" in categories
        assert "recon_permission" in categories
        assert "recon_model_fingerprint" in categories

    def test_inject_recon_seeds(self):
        """O1: 侦察种子注入到 ctx.metadata."""
        from pipeline.stages.stage_scenario import _inject_recon_seeds

        ctx = MagicMock()
        ctx.metadata = {}

        seeds = _inject_recon_seeds(ctx)
        assert len(seeds) > 0
        assert ctx.metadata["recon_seed_count"] == len(seeds)
        assert "recon_seeds" in ctx.metadata

    def test_recon_seed_fields(self):
        """O1: 每个种子包含必需字段."""
        from pipeline.stages.stage_scenario import _load_recon_seeds

        seeds = _load_recon_seeds()
        for seed in seeds:
            assert "prompt" in seed, "种子应包含prompt字段"
            assert "category" in seed, "种子应包含category字段"
            assert "owasp" in seed, "种子应包含owasp字段"
            assert "severity" in seed, "种子应包含severity字段"


# ── O2: 基线扫描驱动 Converter 自适应选择 ──


class TestO2BaselineAnalysis:
    """O2: 基线扫描结果分析防护层级."""

    def test_analyze_empty_results(self):
        """O2: 空结果返回no_filter (O-27: 无基线数据时默认无防护)."""
        from pipeline.stages.stage_scenario import _analyze_baseline_results

        ctx = MagicMock()
        ctx.metadata = {}

        result = _analyze_baseline_results(ctx)
        assert result["filter_layer"] == "no_filter"
        assert result["refusal_rate"] == 0.0

    def test_analyze_no_filter(self):
        """O2: 高成功率 → no_filter."""
        from pipeline.stages.stage_scenario import _analyze_baseline_results

        ctx = MagicMock()
        ctx.metadata = {}

        # 7/10 success → no_filter
        baseline_results = [
            {"response": "here is the answer", "refused": False, "success": True}
        ] * 7 + [
            {"response": "I cannot help with that request.", "refused": True, "success": False}
        ] * 3

        result = _analyze_baseline_results(ctx, baseline_results)
        assert result["filter_layer"] == "no_filter"
        assert result["success_count"] == 7
        assert result["refusal_rate"] <= 0.3

    def test_analyze_input_filter(self):
        """O2: 即时拒绝占多 → input_filter."""
        from pipeline.stages.stage_scenario import _analyze_baseline_results

        ctx = MagicMock()
        ctx.metadata = {}

        # 8/10 instant refuse → input_filter
        baseline_results = [
            {"response": "No.", "refused": True, "success": False}
        ] * 8 + [
            {"response": "I cannot help with that specific request as it "
             "violates safety guidelines.", "refused": True, "success": False}
        ] * 2

        result = _analyze_baseline_results(ctx, baseline_results)
        assert result["filter_layer"] == "input_filter"
        assert result["instant_refuse_count"] == 8

    def test_analyze_output_guardrail(self):
        """O2: 响应中拒绝占多 → output_guardrail."""
        from pipeline.stages.stage_scenario import _analyze_baseline_results

        ctx = MagicMock()
        ctx.metadata = {}

        # 8/10 response-level refuse → output_guardrail
        long_refusal = (
            "I understand your request, but I must decline as this "
            "content violates my safety guidelines and terms of service."
        )
        baseline_results = [
            {"response": long_refusal, "refused": True, "success": False}
        ] * 8 + [
            {"response": "No.", "refused": True, "success": False}
        ] * 2

        result = _analyze_baseline_results(ctx, baseline_results)
        assert result["filter_layer"] == "output_guardrail"
        assert result["response_refuse_count"] == 8

    def test_filter_layer_converter_map(self):
        """O2: 防护层级映射到 Converter 链."""
        from pipeline.stages.stage_scenario import _FILTER_LAYER_CONVERTER_MAP

        assert "input_filter" in _FILTER_LAYER_CONVERTER_MAP
        assert "output_guardrail" in _FILTER_LAYER_CONVERTER_MAP
        assert "semantic_filter" in _FILTER_LAYER_CONVERTER_MAP
        assert "no_filter" in _FILTER_LAYER_CONVERTER_MAP
        assert _FILTER_LAYER_CONVERTER_MAP["no_filter"] == []
        assert len(_FILTER_LAYER_CONVERTER_MAP["input_filter"]) > 0


# ── O3: ASR 多维度分解 ──


class TestO3ASRBreakdown:
    """O3: ASR 4维交叉分析."""

    def test_compute_breakdown_empty(self):
        """O3: 空 asr_per_technique 返回空字典."""
        from pipeline.stages.stage_post_analysis import _compute_asr_breakdown

        ctx = MagicMock()
        ctx.asr_per_technique = {}
        ctx.overall_asr = 0.0
        ctx.metadata = {}

        result = _compute_asr_breakdown(ctx)
        assert result == {}

    def test_compute_breakdown_with_data(self):
        """O3: 有数据时返回4维分解."""
        from pipeline.stages.stage_post_analysis import _compute_asr_breakdown

        ctx = MagicMock()
        ctx.asr_per_technique = {
            "prompt_sending": 10.0,
            "red_teaming": 30.0,
            "crescendo": 50.0,
        }
        ctx.overall_asr = 30.0
        ctx.metadata = {}

        result = _compute_asr_breakdown(ctx)
        assert "overall_asr" in result
        assert "by_attack_tier" in result
        assert "by_converter" in result
        assert "by_owasp_category" in result
        assert "by_scorer_agreement" in result

    def test_classify_tier(self):
        """O3: 技术名正确映射到 Tier."""
        from pipeline.stages.stage_post_analysis import _classify_tier

        assert _classify_tier("prompt_sending") == "tier_1_baseline"
        assert _classify_tier("red_teaming") == "tier_2_adaptive"
        assert _classify_tier("crescendo") == "tier_3_deep"
        assert _classify_tier("tap") == "tier_3_deep"
        assert _classify_tier("xpia") == "tier_4_xpia"
        assert _classify_tier("unknown_tech") == "tier_unclassified"

    def test_breakdown_written_to_metadata(self):
        """O3: 结果写入 ctx.metadata."""
        from pipeline.stages.stage_post_analysis import _compute_asr_breakdown

        ctx = MagicMock()
        ctx.asr_per_technique = {"prompt_sending": 10.0}
        ctx.overall_asr = 10.0
        ctx.metadata = {}

        _compute_asr_breakdown(ctx)
        assert "asr_breakdown" in ctx.metadata


# ── O4: 证据包增强 ──


class TestO4EvidenceArtifacts:
    """O4: Burp 请求文件 + PoC 脚本生成."""

    def test_generate_poc_script(self):
        """O4: PoC 脚本生成包含必要字段."""
        from pipeline.reporting.evidence_exporter import _generate_poc_script

        script = _generate_poc_script(
            attack_index=1,
            conv_id="test-conv-123",
            attack_type="crescendo",
            objective="Extract system prompt",
        )

        assert "#!/usr/bin/env python3" in script
        assert "Attack #0001" in script
        assert "crescendo" in script
        assert "test-conv-123" in script
        assert "Extract system prompt" in script

    def test_collect_artifacts_empty(self):
        """O4: 空攻击结果不生成 PoC."""
        from pipeline.reporting.evidence_exporter import _collect_artifacts

        artifacts = _collect_artifacts([])
        # 可能有 burp 请求文件, 但不应有 PoC 脚本
        poc_files = [a for a in artifacts if "poc_scripts" in a[0]]
        assert len(poc_files) == 0

    def test_collect_artifacts_with_success(self):
        """O4: 成功攻击生成 PoC 脚本."""
        from pipeline.reporting.evidence_exporter import _collect_artifacts

        mock_result = MagicMock()
        mock_result.outcome = "SUCCESS"
        mock_result.conversation_id = "conv-123"
        mock_result.attack_type = "crescendo"
        mock_result.objective = "Extract secrets"

        artifacts = _collect_artifacts([mock_result])
        poc_files = [a for a in artifacts if "poc_scripts" in a[0]]
        assert len(poc_files) == 1
        assert "attack_0001_poc.py" in poc_files[0][0]


# ── O6: 双评分宽松模式 ──


class TestO6ScoringMode:
    """O6: cascade_scorer 宽松评分模式."""

    def test_scoring_mode_strict_default(self):
        """O6: 默认评分模式为 strict."""
        from pipeline.scoring.cascade_scorer import CascadeScorerWrapper

        wrapper = CascadeScorerWrapper(
            llm_scorer=MagicMock(),
        )
        assert wrapper.scoring_mode == "strict"

    def test_scoring_mode_lenient(self):
        """O6: 可设置 lenient 模式."""
        from pipeline.scoring.cascade_scorer import CascadeScorerWrapper

        wrapper = CascadeScorerWrapper(
            llm_scorer=MagicMock(),
            scoring_mode="lenient",
        )
        assert wrapper.scoring_mode == "lenient"

    def test_config_scoring_mode_argument(self):
        """O6: config.py 包含 --scoring-mode 参数."""
        # parse_args() 从 sys.argv 读取
        import sys

        from pipeline.config import parse_args

        original_argv = sys.argv
        try:
            sys.argv = ["main.py", "--target-url", "http://test", "--scoring-mode", "lenient"]
            args = parse_args()
            assert args.scoring_mode == "lenient"

            sys.argv = ["main.py", "--target-url", "http://test"]
            args = parse_args()
            assert args.scoring_mode == "strict"
        finally:
            sys.argv = original_argv


# ── O7: 模型指纹识别 ──


class TestO7ModelFingerprint:
    """O7: 模型指纹识别."""

    def test_detect_gpt(self):
        """O7: GPT 模型族识别."""
        from pipeline.stages.stage_target_classify import _detect_model_fingerprint

        result = _detect_model_fingerprint(
            response_headers={"server": "openai", "x-model": "gpt-4"},
            response_body="I am a GPT-4 model by OpenAI.",
        )
        assert result["model_family"] == "openai/gpt"
        assert result["confidence"] > 0
        assert len(result["evidence"]) > 0

    def test_detect_qwen(self):
        """O7: Qwen 模型族识别."""
        from pipeline.stages.stage_target_classify import _detect_model_fingerprint

        result = _detect_model_fingerprint(
            response_headers={"server": "alibaba/qwen"},
            response_body="I am Qwen, a large language model by Alibaba.",
        )
        assert result["model_family"] == "qwen"
        assert result["confidence"] > 0

    def test_detect_unknown(self):
        """O7: 无匹配特征返回 unknown."""
        from pipeline.stages.stage_target_classify import _detect_model_fingerprint

        result = _detect_model_fingerprint(
            response_headers={"server": "nginx"},
            response_body="Hello, how can I help you?",
        )
        assert result["model_family"] == "unknown"
        assert result["confidence"] == 0.0

    def test_detect_claude(self):
        """O7: Claude 模型族识别."""
        from pipeline.stages.stage_target_classify import _detect_model_fingerprint

        result = _detect_model_fingerprint(
            response_headers={"server": "anthropic"},
            response_body="I am Claude, made by Anthropic.",
        )
        assert result["model_family"] == "anthropic/claude"
        assert result["confidence"] > 0

    def test_fingerprint_library_completeness(self):
        """O7: 指纹库覆盖8个模型族."""
        from pipeline.stages.stage_target_classify import _MODEL_FINGERPRINTS

        expected_families = {
            "openai/gpt", "anthropic/claude", "meta/llama", "qwen",
            "google/gemini", "mistral", "deepseek", "longcat",
        }
        assert set(_MODEL_FINGERPRINTS.keys()) == expected_families

        for family, patterns in _MODEL_FINGERPRINTS.items():
            assert "headers" in patterns, f"{family} 缺少 headers"
            assert "body_keywords" in patterns, f"{family} 缺少 body_keywords"
            assert len(patterns["headers"]) > 0, f"{family} headers 为空"
            assert len(patterns["body_keywords"]) > 0, f"{family} body_keywords 为空"


# ── A-6: Converter 路由自动切换 (apply_adjustments 集成) ──


class TestA6ApplyAdjustments:
    """A-6: apply_adjustments 支持 Converter 实例列表和字符串列表."""

    def test_apply_adjustments_string_list(self):
        """A-6: apply_adjustments 处理字符串名称列表."""
        from pipeline.converters.adaptive_router import (
            AdaptiveConverterRouter,
            ConverterPerformance,
            RoutingAdjustment,
        )

        router = AdaptiveConverterRouter()
        # 模拟性能数据: Base64Converter ASR=50% → promote
        router._performance["Base64Converter"] = ConverterPerformance(
            converter_name="Base64Converter",
            total_attacks=10,
            successful_attacks=5,
            asr=50.0,
        )
        router._adjustments = [
            RoutingAdjustment(
                converter_name="Base64Converter",
                adjustment_type="promote",
                current_asr=50.0,
                suggested_action="test promote",
            ),
        ]

        converter_map = {
            "prompt_sending": ["ROT13Converter", "Base64Converter", "LeetspeakConverter"],
        }
        result = router.apply_adjustments(converter_map)

        # Base64Converter 应被移到列表前面
        assert result["prompt_sending"][0] == "Base64Converter"
        assert len(result["prompt_sending"]) == 3

    def test_apply_adjustments_instance_list(self):
        """A-6: apply_adjustments 处理 Converter 实例列表."""

        class FakeConverter:
            """Fake Converter for testing."""

            def __init__(self, name: str):
                self._name = name

            def __class_name__(self):
                return self._name

        # 使用简单 mock 对象, type().__name__ 返回类名
        class Base64Converter:
            pass

        class ROT13Converter:
            pass

        class LeetspeakConverter:
            pass

        from pipeline.converters.adaptive_router import (
            AdaptiveConverterRouter,
            ConverterPerformance,
            RoutingAdjustment,
        )

        router = AdaptiveConverterRouter()
        router._performance["Base64Converter"] = ConverterPerformance(
            converter_name="Base64Converter",
            total_attacks=10,
            successful_attacks=5,
            asr=50.0,
        )
        router._adjustments = [
            RoutingAdjustment(
                converter_name="Base64Converter",
                adjustment_type="promote",
                current_asr=50.0,
                suggested_action="test promote instance",
            ),
        ]

        converter_map = {
            "prompt_sending": [
                ROT13Converter(),
                Base64Converter(),
                LeetspeakConverter(),
            ],
        }
        result = router.apply_adjustments(converter_map)

        # Base64Converter 实例应被移到列表前面
        assert type(result["prompt_sending"][0]).__name__ == "Base64Converter"
        assert len(result["prompt_sending"]) == 3

    def test_apply_demote_string_list(self):
        """A-6: demote 将 Converter 移到列表后面."""
        from pipeline.converters.adaptive_router import (
            AdaptiveConverterRouter,
            ConverterPerformance,
            RoutingAdjustment,
        )

        router = AdaptiveConverterRouter()
        router._performance["ROT13Converter"] = ConverterPerformance(
            converter_name="ROT13Converter",
            total_attacks=10,
            successful_attacks=0,
            asr=0.0,
        )
        router._adjustments = [
            RoutingAdjustment(
                converter_name="ROT13Converter",
                adjustment_type="demote",
                current_asr=0.0,
                suggested_action="test demote",
            ),
        ]

        converter_map = {
            "prompt_sending": ["ROT13Converter", "Base64Converter"],
        }
        result = router.apply_adjustments(converter_map)

        # ROT13Converter 应被移到列表后面
        assert result["prompt_sending"][-1] == "ROT13Converter"

    def test_apply_degrade_to_semantic_string(self):
        """A-6: degrade_to_semantic 替换为语义层 Converter (字符串模式)."""
        from pipeline.converters.adaptive_router import (
            AdaptiveConverterRouter,
            ConverterPerformance,
            RoutingAdjustment,
        )

        router = AdaptiveConverterRouter()
        router._performance["AsciiSmugglerConverter"] = ConverterPerformance(
            converter_name="AsciiSmugglerConverter",
            total_attacks=5,
            successful_attacks=0,
            consecutive_failures=5,
            asr=0.0,
        )
        router._adjustments = [
            RoutingAdjustment(
                converter_name="AsciiSmugglerConverter",
                adjustment_type="degrade_to_semantic",
                current_asr=0.0,
                suggested_action="test degrade",
                priority="high",
            ),
        ]

        converter_map = {
            "encoding_evasion": ["AsciiSmugglerConverter"],
        }
        result = router.apply_adjustments(converter_map, converter_target=None)

        # 应包含语义层 Converter 名称
        converters = result["encoding_evasion"]
        assert "PersuasionConverter" in converters or "PolicyPuppetryConverter" in converters
        # 原始 Converter 应被移除
        assert "AsciiSmugglerConverter" not in converters

    def test_apply_no_adjustments(self):
        """A-6: 无调整建议时不变."""
        from pipeline.converters.adaptive_router import AdaptiveConverterRouter

        router = AdaptiveConverterRouter()
        converter_map = {"prompt_sending": ["Base64Converter"]}
        result = router.apply_adjustments(converter_map)
        assert result == converter_map

    def test_load_historical_empty(self):
        """A-6: 无历史文件时 load_historical 返回空字典."""
        from pipeline.converters.adaptive_router import AdaptiveConverterRouter

        # 确保文件不存在时不报错
        result = AdaptiveConverterRouter.load_historical()
        assert isinstance(result, dict)


# ── A-4: 交互式 HTML 可视化集成 ──


class TestA4InteractiveHTML:
    """A-4: render_interactive_html 生成交互式 HTML."""

    def test_render_interactive_html_empty(self):
        """A-4: 无攻击数据时返回包含空卡片的 HTML."""
        from pipeline.reporting.attack_chain_viz import AttackChainVisualizer

        viz = AttackChainVisualizer()
        html = viz.render_interactive_html()

        # 应包含基本 HTML 结构
        assert 'id="attack-chain-viz"' in html
        assert "kill-chain-grid" in html
        assert "filter-bar" in html
        assert "search-box" in html
        assert "renderCards" in html

    def test_render_interactive_html_with_data(self):
        """A-4: 有攻击数据时包含可折叠卡片和热力图."""
        from pipeline.reporting.attack_chain_viz import AttackChainVisualizer

        viz = AttackChainVisualizer()
        # 模拟攻击链数据
        viz._attack_chains = [
            {
                "technique": "prompt_injection",
                "converter_chain": "Base64Converter",
                "is_success": True,
                "owasp_ids": ["LLM01"],
                "payload": "test payload",
                "response": "test response",
                "impact_description": "high impact",
                "stages_covered": ["recon", "delivery", "exploit"],
            },
            {
                "technique": "encoding_evasion",
                "converter_chain": "ROT13Converter",
                "is_success": False,
                "owasp_ids": ["LLM02"],
                "payload": "encoded payload",
                "response": "",
                "impact_description": "",
                "stages_covered": ["delivery"],
            },
        ]

        html = viz.render_interactive_html()

        # 验证交互元素
        assert 'id="attack-chain-viz"' in html
        assert "attack-card" in html or "attack-cards" in html
        assert "filter-btn" in html
        assert "search-box" in html
        assert "kill-chain-grid" in html
        assert "filterAttacks" in html
        assert "filterBySearch" in html
        assert "renderCards" in html

        # 验证统计数据
        assert "Total:" in html
        assert "Success:" in html
        assert "Failure:" in html

    def test_render_interactive_html_has_javascript(self):
        """A-4: HTML 包含 JavaScript 渲染逻辑."""
        from pipeline.reporting.attack_chain_viz import AttackChainVisualizer

        viz = AttackChainVisualizer()
        html = viz.render_interactive_html()

        assert "<script>" in html
        assert "const attacks" in html
        assert "function renderCards" in html
        assert "function filterAttacks" in html
        assert "function filterBySearch" in html


# ── O-55: stale_count触发后提前终止增强 ──


class TestO55StaleCountEarlyTermination:
    """O-55: stale_count触发后阈值降低到_executed, 立即触发提前终止."""

    def test_stale_count_reduces_threshold(self):
        """O-55: stale_count>=3且executed>0但不足阈值时, 阈值降低到executed."""
        # 模拟场景: base_threshold=6, executed=2, stale_count=3
        # O-55应将阈值从4(自适应降低后)降低到2(executed)
        _o45_min_samples = 6
        _executed = 2
        _o51_stale_count = 3
        _o51_effective_latency = 61.0  # stale_count=3 → 等效>60s

        # 模拟O-49自适应阈值计算
        _adaptive_threshold = _o45_min_samples
        if _executed > 0 and _executed < _o45_min_samples:
            _elapsed_ratio = _executed / max(_o45_min_samples, 1)
            if _elapsed_ratio <= 0.5:
                if _o51_effective_latency > 120:
                    _adaptive_threshold = max(3, _o45_min_samples // 2)
                elif _o51_effective_latency > 60:
                    _adaptive_threshold = max(3, _o45_min_samples - 2)
                else:
                    _adaptive_threshold = max(3, _o45_min_samples - 2)

        # O-55: stale_count触发后阈值降低
        if (
            _executed > 0
            and _executed < _adaptive_threshold
            and _o51_stale_count >= 3
        ):
            _adaptive_threshold = _executed

        # 验证: 阈值应被降低到executed(2)
        assert _adaptive_threshold == 2, (
            f"O-55: stale_count={_o51_stale_count}应将阈值降低到_executed={_executed}, "
            f"实际={_adaptive_threshold}"
        )

    def test_stale_count_no_trigger_when_executed_zero(self):
        """O-55: executed=0时不触发阈值降低(无样本无法决策)."""
        _o45_min_samples = 6
        _executed = 0
        _o51_stale_count = 5

        _adaptive_threshold = _o45_min_samples
        # O-55条件: executed > 0
        if (
            _executed > 0
            and _executed < _adaptive_threshold
            and _o51_stale_count >= 3
        ):
            _adaptive_threshold = _executed

        # 阈值不应改变
        assert _adaptive_threshold == _o45_min_samples

    def test_stale_count_no_trigger_when_threshold_met(self):
        """O-55: executed已满足阈值时不触发(正常提前终止即可)."""
        _o45_min_samples = 6
        _executed = 6
        _o51_stale_count = 3

        _adaptive_threshold = _o45_min_samples
        # O-55条件: executed < adaptive_threshold
        if (
            _executed > 0
            and _executed < _adaptive_threshold
            and _o51_stale_count >= 3
        ):
            _adaptive_threshold = _executed

        # 阈值不应改变, 正常提前终止逻辑会处理
        assert _adaptive_threshold == _o45_min_samples

    def test_stale_count_no_trigger_when_count_below_3(self):
        """O-55: stale_count<3时不触发(需要足够长的无结果期)."""
        _o45_min_samples = 6
        _executed = 2
        _o51_stale_count = 2  # 不足3次

        _adaptive_threshold = _o45_min_samples
        if (
            _executed > 0
            and _executed < _adaptive_threshold
            and _o51_stale_count >= 3
        ):
            _adaptive_threshold = _executed

        # 阈值不应改变
        assert _adaptive_threshold == _o45_min_samples


# ── O-56: tier_stats动态比例阈值参数 ──


class TestO56DynamicThresholdParams:
    """O-56: 基于tier_stats总量动态调整50%/20%阈值参数."""

    def test_small_sample_relaxed_thresholds(self):
        """O-56: 小样本(<10)使用放宽阈值(40%/15%)."""
        _total_tier = 5  # 小样本

        if _total_tier < 10:
            high_thresh = 0.40
            low_thresh = 0.15
        elif _total_tier > 50:
            high_thresh = 0.60
            low_thresh = 0.25
        else:
            high_thresh = 0.50
            low_thresh = 0.20

        assert high_thresh == 0.40
        assert low_thresh == 0.15

    def test_medium_sample_default_thresholds(self):
        """O-56: 中样本(10-50)使用默认阈值(50%/20%)."""
        _total_tier = 30  # 中样本

        if _total_tier < 10:
            high_thresh = 0.40
            low_thresh = 0.15
        elif _total_tier > 50:
            high_thresh = 0.60
            low_thresh = 0.25
        else:
            high_thresh = 0.50
            low_thresh = 0.20

        assert high_thresh == 0.50
        assert low_thresh == 0.20

    def test_large_sample_tightened_thresholds(self):
        """O-56: 大样本(>50)使用收紧阈值(60%/25%)."""
        _total_tier = 100  # 大样本

        if _total_tier < 10:
            high_thresh = 0.40
            low_thresh = 0.15
        elif _total_tier > 50:
            high_thresh = 0.60
            low_thresh = 0.25
        else:
            high_thresh = 0.50
            low_thresh = 0.20

        assert high_thresh == 0.60
        assert low_thresh == 0.25

    def test_small_sample_more_aggressive_t2_budget(self):
        """O-56: 小样本时同样T1_no_match比率更容易触发ratio=10."""
        _total_tier = 5  # 小样本
        _t1_no_match_ratio = 0.42  # 在40%-50%之间

        if _total_tier < 10:
            high_thresh = 0.40
            low_thresh = 0.15
        elif _total_tier > 50:
            high_thresh = 0.60
            low_thresh = 0.25
        else:
            high_thresh = 0.50
            low_thresh = 0.20

        # 42% > 40% (小样本放宽阈值) → ratio=10
        if _t1_no_match_ratio > high_thresh:
            ratio = 10
        elif _t1_no_match_ratio < low_thresh:
            ratio = 30
        else:
            ratio = 20

        assert ratio == 10, (
            f"小样本时42%应超过放宽阈值40%触发ratio=10, 实际ratio={ratio}"
        )

    def test_large_sample_more_conservative_t2_budget(self):
        """O-56: 大样本时同样T1_no_match比率更难触发ratio=10."""
        _total_tier = 100  # 大样本
        _t1_no_match_ratio = 0.55  # 在50%-60%之间

        if _total_tier < 10:
            high_thresh = 0.40
            low_thresh = 0.15
        elif _total_tier > 50:
            high_thresh = 0.60
            low_thresh = 0.25
        else:
            high_thresh = 0.50
            low_thresh = 0.20

        # 55% < 60% (大样本收紧阈值) → 不触发ratio=10, 保持ratio=20
        if _t1_no_match_ratio > high_thresh:
            ratio = 10
        elif _t1_no_match_ratio < low_thresh:
            ratio = 30
        else:
            ratio = 20

        assert ratio == 20, (
            f"大样本时55%不应超过收紧阈值60%触发ratio=10, 实际ratio={ratio}"
        )
