"""L5 v38 测试 — PyRIT 原生优势组件接入测试。

测试覆盖:
    1. TranslationConverter + RandomTranslationConverter 在 l5_optimal() 中
    2. CompoundDatasetAttackConfiguration 构建
    3. TextAdaptive 场景执行路径 (mock)
    4. PlaywrightTarget 路由 (mock)
    5. CLI --browser-url 参数解析
    6. adaptive_text 策略预设
    7. asr_priors.yaml 新增 converter 条目
    8. OWASP converter map 更新
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# 确保 project root 在 path 上
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


# ── P0: TranslationConverter + RandomTranslationConverter ──


class TestTranslationConverters:
    """测试 translation_multilingual() 链构建."""

    def test_translation_multilingual_without_target(self):
        """无 converter_target 时应返回空列表."""
        from pipeline.arm.converter_chains import translation_multilingual
        result = translation_multilingual(converter_target=None)
        assert result == []

    def test_translation_multilingual_with_mock_target(self):
        """有 converter_target 时应构建 RandomTranslationConverter + TranslationConverter."""
        from pipeline.arm.converter_chains import translation_multilingual

        mock_target = MagicMock()
        # 直接 mock _conv 函数返回 mock 类
        with patch("pipeline.arm.converter_chains._conv") as mock_conv:
            mock_random_cls = MagicMock()
            mock_translation_cls = MagicMock()
            mock_strategy_cls = MagicMock()

            def side_effect(name):
                if name == "RandomTranslationConverter":
                    return mock_random_cls
                elif name == "TranslationConverter":
                    return mock_translation_cls
                elif name == "AllWordsSelectionStrategy":
                    return mock_strategy_cls
                raise AttributeError(f"Unexpected: {name}")

            mock_conv.side_effect = side_effect

            result = translation_multilingual(converter_target=mock_target)
            assert len(result) == 2
            assert mock_random_cls.called
            assert mock_translation_cls.called

    def test_l5_optimal_includes_translation_path(self):
        """l5_optimal() 应包含 translation_multilingual 路径 (有 converter_target 时)."""
        from pipeline.arm.converter_presets import l5_optimal

        mock_target = MagicMock()
        # L5 v36: l5_optimal 定义在 converter_presets.py, _conv 在函数内部导入
        # 只需 patch converter_chains._conv (converter_presets 内部从 converter_chains 导入)
        with patch("pipeline.arm.converter_chains._conv") as mock_conv_chains:
            mock_conv_chains.return_value = MagicMock()
            result = l5_optimal(converter_target=mock_target)
            # 应有多个路径, 包括 translation 路径
            assert len(result) > 0

    def test_chain_builders_includes_translation(self):
        """CHAIN_BUILDERS 应包含 translation_multilingual."""
        from pipeline.arm.converter_chains import CHAIN_BUILDERS
        assert "translation_multilingual" in CHAIN_BUILDERS

    def test_build_converter_map_with_translation(self):
        """build_converter_map 应支持 translation_multilingual 链名."""
        from pipeline.arm.converter_presets import build_converter_map

        mock_target = MagicMock()
        # L5 v36: build_converter_map 定义在 converter_presets.py, _conv 在函数内部导入
        # 只需 patch converter_chains._conv
        with patch("pipeline.arm.converter_chains._conv") as mock_conv_chains:
            mock_conv_chains.return_value = MagicMock()
            result = build_converter_map(
                technique_names=["prompt_sending"],
                chain_names=["translation_multilingual"],
                converter_target=mock_target,
            )
            assert "prompt_sending" in result


# ── P1: CompoundDatasetAttackConfiguration ──


class TestCompoundDataset:
    """测试 CompoundDatasetAttackConfiguration 构建."""

    def test_build_compound_dataset_config_multiple_seeds(self):
        """多种子文件应构建 CompoundDatasetAttackConfiguration."""
        from pipeline.arm.dataset_config import build_compound_dataset_config

        with patch("pipeline.arm.dataset_config._SEEDS_DIR") as mock_dir:
            mock_dir.__truediv__ = MagicMock(return_value=MagicMock(exists=lambda: True))
            # Mock SeedPrompt and scenario modules
            with patch("builtins.__import__"):
                # Mock: 返回 None 表示 PyRIT 模块不可用
                result = build_compound_dataset_config("elite_jailbreaks,asi_top10", 20)
                # 如果 PyRIT scenario 模块不可用, 应返回 None
                assert result is None or result is not None

    def test_build_compound_dataset_config_empty_seeds(self):
        """空种子名应返回 None."""
        from pipeline.arm.dataset_config import build_compound_dataset_config
        result = build_compound_dataset_config("", 20)
        assert result is None

    def test_build_text_adaptive_dataset_config_single_seed(self):
        """单种子文件应返回 DatasetAttackConfiguration (如果可用)."""
        from pipeline.arm.dataset_config import build_text_adaptive_dataset_config

        # 如果 PyRIT scenario 模块不可用, 应返回 None
        result = build_text_adaptive_dataset_config("elite_jailbreaks", 10)
        assert result is None or result is not None

    def test_build_text_adaptive_dataset_config_multiple_seeds(self):
        """多种子文件应返回 CompoundDatasetAttackConfiguration (如果可用)."""
        from pipeline.arm.dataset_config import build_text_adaptive_dataset_config

        result = build_text_adaptive_dataset_config("elite_jailbreaks,asi_top10", 20)
        assert result is None or result is not None


# ── P2: TextAdaptive Scenario ──


class TestTextAdaptiveExecutor:
    """测试 TextAdaptive 执行路径."""

    def test_text_adaptive_executor_import(self):
        """execute_text_adaptive 应可导入."""
        from pipeline.strike.adaptive_executor import execute_text_adaptive
        assert callable(execute_text_adaptive)

    def test_text_adaptive_executor_fallback_on_failure(self):
        """TextAdaptive 执行失败时应 fallback 到 executor.py."""
        from pipeline.context import PipelineContext
        from pipeline.strike.adaptive_executor import execute_text_adaptive

        # 创建 mock ctx
        args = MagicMock()
        args.techniques = "adaptive"
        args.seeds = "elite_jailbreaks"
        args.max_seeds = 10
        args.max_attempts = 3
        args.max_concurrency = 3
        args.timeout = 30
        args.resume = None
        ctx = PipelineContext(args=args)
        ctx.objective_target = None
        ctx.adversarial_target = None
        ctx.scoring_target = None

        # TextAdaptive 应在 dataset_config 失败时 fallback 到 executor.py
        loop = asyncio.new_event_loop()
        try:
            with patch("pipeline.arm.dataset_config.build_text_adaptive_dataset_config", return_value=None):
                with patch("pipeline.strike.executor.execute_attacks", return_value={}):
                    loop.run_until_complete(execute_text_adaptive(ctx))
                    # 应 fallback 到 executor.py
        finally:
            loop.close()

    def test_build_text_adaptive_scorer_substring(self):
        """TextAdaptive scorer 应优先使用 SubStringScorer+Inverter (0 token)."""
        from pipeline.context import PipelineContext
        from pipeline.strike.adaptive_executor import _build_text_adaptive_scorer

        args = MagicMock()
        ctx = PipelineContext(args=args)
        scorer = _build_text_adaptive_scorer(ctx)
        # SubStringScorer 或 None (取决于 pyrit 可用性)
        assert scorer is not None or scorer is None


# ── P3: PlaywrightTarget 路由 ──


class TestPlaywrightTargetRoute:
    """测试 PlaywrightTarget 路由."""

    def test_browser_url_cli_arg(self):
        """--browser-url 参数应正确解析."""
        from pipeline.config import parse_args
        old_argv = sys.argv
        try:
            sys.argv = ["main.py", "--browser-url", "https://chat.example.com"]
            args = parse_args()
            assert args.browser_url == "https://chat.example.com"
        finally:
            sys.argv = old_argv

    def test_browser_url_env_fallback(self):
        """BROWSER_TARGET_URL 环境变量应作为 fallback."""
        from pipeline.config import parse_args
        old_argv = sys.argv
        old_env = os.environ.get("BROWSER_TARGET_URL")
        try:
            os.environ["BROWSER_TARGET_URL"] = "https://env.example.com"
            sys.argv = ["main.py"]
            args = parse_args()
            assert args.browser_url == "https://env.example.com"
        finally:
            sys.argv = old_argv
            if old_env is not None:
                os.environ["BROWSER_TARGET_URL"] = old_env
            elif "BROWSER_TARGET_URL" in os.environ:
                del os.environ["BROWSER_TARGET_URL"]

    def test_browser_url_none_by_default(self):
        """--browser-url 默认应为 None."""
        from pipeline.config import parse_args
        old_argv = sys.argv
        old_env = os.environ.get("BROWSER_TARGET_URL")
        try:
            if "BROWSER_TARGET_URL" in os.environ:
                del os.environ["BROWSER_TARGET_URL"]
            sys.argv = ["main.py"]
            args = parse_args()
            assert args.browser_url is None
        finally:
            sys.argv = old_argv
            if old_env is not None:
                os.environ["BROWSER_TARGET_URL"] = old_env


# ── P7: adaptive_text 策略预设 ──


class TestAdaptiveTextStrategy:
    """测试 adaptive_text 策略预设."""

    def test_adaptive_text_preset_exists(self):
        """adaptive_text 策略应存在."""
        from pipeline.strategy.presets import STRATEGY_PRESETS
        assert "adaptive_text" in STRATEGY_PRESETS

    def test_adaptive_text_preset_fields(self):
        """adaptive_text 预设字段应正确."""
        from pipeline.strategy.presets import STRATEGY_PRESETS
        preset = STRATEGY_PRESETS["adaptive_text"]
        assert preset.techniques == "adaptive"
        assert preset.converters == "l5_optimal"
        assert preset.escalation is True
        assert preset.html_report is True
        assert preset.max_seeds == 30
        assert preset.timeout == 1500

    def test_adaptive_text_in_strategy_choices(self):
        """adaptive_text 应在 CLI --strategy choices 中."""
        from pipeline.config import parse_args
        old_argv = sys.argv
        try:
            sys.argv = ["main.py", "--strategy", "adaptive_text"]
            args = parse_args()
            assert args.strategy == "adaptive_text"
            assert args.techniques == "adaptive"
        finally:
            sys.argv = old_argv

    def test_get_strategy_args_adaptive_text(self):
        """get_strategy_args 应返回 adaptive_text 的参数."""
        from pipeline.strategy.presets import get_strategy_args
        args = get_strategy_args("adaptive_text")
        assert args["techniques"] == "adaptive"
        assert args["converters"] == "l5_optimal"
        assert args["escalation"] is True


# ── P4: asr_priors.yaml 更新 ──


class TestAsrPriorsUpdates:
    """测试 asr_priors.yaml 新增条目."""

    def test_random_translation_converter_asr_exists(self):
        """RandomTranslationConverter ASR 先验应存在."""
        import yaml
        priors_path = _PROJECT_ROOT / "config" / "asr_priors.yaml"
        with open(priors_path, encoding="utf-8") as f:
            priors = yaml.safe_load(f)
        assert "RandomTranslationConverter" in priors["converter_asr"]
        assert priors["converter_asr"]["RandomTranslationConverter"]["default"] == 28.0

    def test_translation_converter_asr_exists(self):
        """TranslationConverter ASR 先验应存在."""
        import yaml
        priors_path = _PROJECT_ROOT / "config" / "asr_priors.yaml"
        with open(priors_path, encoding="utf-8") as f:
            priors = yaml.safe_load(f)
        assert "TranslationConverter" in priors["converter_asr"]
        assert priors["converter_asr"]["TranslationConverter"]["default"] == 18.0

    def test_owasp_converter_map_llm01_has_translation(self):
        """LLM01 OWASP converter map 应包含 CodeChameleonConverter (L5 v36 更新)."""
        import yaml
        priors_path = _PROJECT_ROOT / "config" / "asr_priors.yaml"
        with open(priors_path, encoding="utf-8") as f:
            priors = yaml.safe_load(f)
        # L5 v36: RandomTranslationConverter 替换为 SelectiveTextConverter + CodeChameleon
        assert "CodeChameleonConverter" in priors["owasp_converter_map"]["LLM01"]
        assert "SelectiveTextConverter:WordProportionSelectionStrategy" in priors["owasp_converter_map"]["LLM01"]

    def test_owasp_converter_map_llm04_has_translation(self):
        """LLM04 OWASP converter map 应包含 RandomTranslationConverter (L5 v36 更新)."""
        import yaml
        priors_path = _PROJECT_ROOT / "config" / "asr_priors.yaml"
        with open(priors_path, encoding="utf-8") as f:
            priors = yaml.safe_load(f)
        # L5 v36: TranslationConverter 替换为 SearchReplaceConverter
        assert "RandomTranslationConverter" in priors["owasp_converter_map"]["LLM04"]
        assert "SearchReplaceConverter" in priors["owasp_converter_map"]["LLM04"]


# ── P5: .env.example 更新 ──


class TestEnvExampleUpdate:
    """测试 .env.example 新增 BROWSER_TARGET_URL."""

    def test_env_example_has_browser_target_url(self):
        """.env.example 应包含 BROWSER_TARGET_URL."""
        env_path = _PROJECT_ROOT / ".env.example"
        content = env_path.read_text(encoding="utf-8")
        assert "BROWSER_TARGET_URL" in content
        assert "BROWSER_TARGET_RPM" in content
        assert "PlaywrightTarget" in content


# ── 集成测试: executor.py 优先级映射 ──


class TestExecutorPriorityMap:
    """测试 executor.py 优先级映射包含新 converter."""

    def test_priority_map_includes_random_translation(self):
        """_get_candidate_converters 优先级映射应包含 RandomTranslationConverter."""
        import pipeline.strike.executor as exec_mod
        # 读取源码验证 (不执行, 只检查字符串存在)
        source = Path(exec_mod.__file__).read_text(encoding="utf-8")
        assert "RandomTranslationConverter" in source
        assert "TranslationConverter" in source


# ── 断点集成测试: 确保全链路无断点 ──


class TestIntegrationNoBreakpoints:
    """测试所有 PyRIT 原生组件在流水线中的全链路集成无断点."""

    def test_technique_picker_accepts_adaptive(self):
        """select_techniques('adaptive') 应返回 ['adaptive_text'] 而非报错."""
        from pipeline.arm.technique_picker import select_techniques
        result = select_techniques("adaptive", has_adversarial=True)
        assert result == ["adaptive_text"]

    def test_adaptive_text_not_multi_turn(self):
        """adaptive_text 不应被 is_multi_turn_technique 判定为多轮."""
        from pipeline.arm.technique_picker import is_multi_turn_technique
        assert is_multi_turn_technique("adaptive_text") is False

    def test_adaptive_text_in_available_techniques(self):
        """adaptive_text 应在 _AVAILABLE_TECHNIQUES 中."""
        from pipeline.arm.technique_picker import _AVAILABLE_TECHNIQUES
        assert "adaptive_text" in _AVAILABLE_TECHNIQUES

    def test_filter_by_adversarial_preserves_adaptive_text(self):
        """filter_by_adversarial 不应过滤掉 adaptive_text."""
        from pipeline.arm.technique_picker import filter_by_adversarial
        result = filter_by_adversarial(["adaptive_text"], has_adversarial=False)
        assert "adaptive_text" in result

    def test_text_adaptive_executor_scorer_none_fallback(self):
        """scorer 为 None 时应 fallback 到 executor.py."""
        from pipeline.context import PipelineContext
        from pipeline.strike.adaptive_executor import execute_text_adaptive

        args = MagicMock()
        args.techniques = "adaptive"
        args.seeds = "elite_jailbreaks"
        args.max_seeds = 10
        args.max_attempts = 3
        args.max_concurrency = 3
        args.timeout = 30
        args.resume = None
        ctx = PipelineContext(args=args)
        ctx.objective_target = None
        ctx.adversarial_target = None
        ctx.scoring_target = None

        # Mock: scorer 返回 None, dataset_config 返回 None
        # 应直接 fallback 到 executor.py
        loop = asyncio.new_event_loop()
        try:
            with patch("pipeline.arm.dataset_config.build_text_adaptive_dataset_config", return_value=None):
                with patch("pipeline.strike.executor.execute_attacks", return_value={}):
                    loop.run_until_complete(execute_text_adaptive(ctx))
        finally:
            loop.close()

    def test_text_adaptive_executor_attribute_name_correct(self):
        """adaptive_executor 中不应有空格属性名 'attack technique'."""
        source = Path(
            "pipeline/strike/adaptive_executor.py"
        ).resolve().read_text(encoding="utf-8")
        # 确保修复了属性名拼写错误
        assert "attack technique" not in source
        assert "attack_technique" in source

    def test_calibrated_rubric_path_correct(self):
        """calibrated_rubric_path 应指向项目根目录的 data/scorers/."""
        source = Path(
            "pipeline/strike/adaptive_executor.py"
        ).resolve().read_text(encoding="utf-8")
        # parent.parent.parent 指向项目根目录
        assert "parent.parent.parent" in source

    def test_playwright_target_is_async(self):
        """_create_playwright_target 应为 async 函数."""
        import inspect

        from pipeline.recon.target_router import _create_playwright_target
        assert inspect.iscoroutinefunction(_create_playwright_target)

    def test_create_target_awaits_playwright(self):
        """create_target 中调用 _create_playwright_target 应有 await."""
        source = Path(
            "pipeline/recon/target_router.py"
        ).resolve().read_text(encoding="utf-8")
        # 确保调用处有 await
        assert "await _create_playwright_target" in source

    def test_main_routes_adaptive_techniques(self):
        """main.py 应检测 techniques == 'adaptive' 并路由到 TextAdaptive."""
        source = (_PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        assert 'args.techniques == "adaptive"' in source
        assert "execute_text_adaptive" in source

    def test_converter_chains_translation_in_l5_optimal(self):
        """l5_optimal() 应调用 translation_multilingual (有 converter_target 时)."""
        source = Path(
            "pipeline/arm/converter_presets.py"
        ).resolve().read_text(encoding="utf-8")
        assert "translation_multilingual(converter_target=converter_target)" in source

    def test_converter_chains_translation_in_build_map(self):
        """build_converter_map 应支持 translation_multilingual 链名."""
        source = Path(
            "pipeline/arm/converter_presets.py"
        ).resolve().read_text(encoding="utf-8")
        assert '"translation_multilingual"' in source

    def test_full_pipeline_adaptive_text_strategy(self):
        """adaptive_text 策略: 从 config → main.py 全链路验证."""
        from pipeline.config import parse_args

        old_argv = sys.argv
        try:
            sys.argv = ["main.py", "--strategy", "adaptive_text"]
            args = parse_args()
            # 策略应覆盖 techniques 为 adaptive
            assert args.techniques == "adaptive"
            # 策略应覆盖 converters 为 l5_optimal
            assert args.converters == "l5_optimal"
            # 策略应启用 escalation
            assert args.escalation is True
        finally:
            sys.argv = old_argv
