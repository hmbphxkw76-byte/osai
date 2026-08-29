"""AttackTechniqueFactory 注册 — PyRIT 原生 registry 集成测试。

验证项目攻击技术能正确注册到 PyRIT 原生 AttackTechniqueRegistry,
且 TextAdaptive 场景能自动发现这些技术。

学术依据:
    - PyRIT (arXiv:2407.01232) — AttackTechniqueRegistry + tag 查询
    - Chao et al. (arXiv:2310.08419) — PAIR 自适应策略选择
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestRegisterProjectTechniques:
    """测试 register_project_techniques 函数。"""

    def test_register_without_targets(self):
        """无 adversarial/converter target 时, 应仅注册 PromptSending 基线技术。"""
        from pipeline.strike.technique_registry import register_project_techniques

        with patch("pyrit.registry.AttackTechniqueRegistry") as mock_registry_cls:
            mock_instance = MagicMock()
            mock_registry_cls.get_registry_singleton.return_value = mock_instance

            result = register_project_techniques(
                adversarial_target=None,
                converter_target=None,
            )

            # 应至少注册 PromptSending (baseline)
            assert "PromptSending" in result
            # 无 adversarial target 时不应注册多轮技术
            assert "Crescendo" not in result
            assert "TAP" not in result
            assert "PAIR" not in result
            # 无 converter target 时不应注册 BestOfN
            assert "BestOfN" not in result

    def test_register_with_adversarial_target(self):
        """有 adversarial target 时, 应注册多轮技术。"""
        from pipeline.strike.technique_registry import register_project_techniques

        mock_target = MagicMock()

        with patch("pyrit.registry.AttackTechniqueRegistry") as mock_registry_cls:
            mock_instance = MagicMock()
            mock_registry_cls.get_registry_singleton.return_value = mock_instance

            result = register_project_techniques(
                adversarial_target=mock_target,
                converter_target=None,
            )

            # 应注册多轮技术
            assert "PromptSending" in result
            assert "Crescendo" in result
            assert "TAP" in result
            assert "PAIR" in result
            # 无 converter target 时不应注册 BestOfN
            assert "BestOfN" not in result

    def test_register_with_converter_target(self):
        """有 converter target 时, 应注册 BestOfN 技术。"""
        from pipeline.strike.technique_registry import register_project_techniques

        mock_target = MagicMock()
        mock_converter = MagicMock()

        with patch("pyrit.executor.attack.AttackConverterConfig"), \
             patch("pyrit.prompt_normalizer.ConverterConfiguration"), \
             patch("pipeline.arm.converter_chains._conv") as mock_conv_fn:

            mock_conv_cls = MagicMock()
            mock_conv_fn.return_value = mock_conv_cls
            mock_conv_instance = MagicMock()
            mock_conv_cls.return_value = mock_conv_instance

            with patch("pyrit.registry.AttackTechniqueRegistry") as mock_registry_cls:
                mock_instance = MagicMock()
                mock_registry_cls.get_registry_singleton.return_value = mock_instance

                result = register_project_techniques(
                    adversarial_target=mock_target,
                    converter_target=mock_converter,
                )

                # 应注册 BestOfN
                assert "BestOfN" in result

    def test_registry_registration_called(self):
        """验证 register_from_factories 被调用。"""
        from pipeline.strike.technique_registry import register_project_techniques

        with patch("pyrit.registry.AttackTechniqueRegistry") as mock_registry_cls:
            mock_instance = MagicMock()
            mock_registry_cls.get_registry_singleton.return_value = mock_instance

            register_project_techniques(
                adversarial_target=None,
                converter_target=None,
            )

            # 验证 register_from_factories 被调用
            mock_instance.register_from_factories.assert_called_once()


class TestBuildSequentialChildAttacks:
    """测试 build_sequential_child_attacks 函数。"""

    def test_empty_converters_returns_empty(self):
        """无 converter 时应返回空列表。"""
        from pipeline.strike.technique_registry import build_sequential_child_attacks

        mock_target = MagicMock()
        mock_scoring = MagicMock()
        mock_seed = MagicMock()

        result = build_sequential_child_attacks(
            objective_target=mock_target,
            scoring_config=mock_scoring,
            candidate_converters=[],
            seed_group=mock_seed,
        )

        assert result == []

    def test_multiple_converters_create_multiple_children(self):
        """多个 converter 应创建对应数量的 child attacks。"""
        from pipeline.strike.technique_registry import build_sequential_child_attacks

        mock_target = MagicMock()
        mock_scoring = MagicMock()
        mock_seed = MagicMock()
        mock_conv1 = MagicMock()
        mock_conv2 = MagicMock()
        type(mock_conv1).__name__ = "ROT13Converter"
        type(mock_conv2).__name__ = "Base64Converter"

        with patch("pyrit.executor.attack.PromptSendingAttack") as mock_attack_cls, \
             patch("pyrit.executor.attack.AttackConverterConfig"), \
             patch("pyrit.prompt_normalizer.ConverterConfiguration"), \
             patch("pyrit.executor.attack.compound.sequential_attack.SequentialChildAttack") as mock_child_cls:

            mock_attack = MagicMock()
            mock_attack_cls.return_value = mock_attack
            mock_child = MagicMock()
            mock_child_cls.return_value = mock_child

            result = build_sequential_child_attacks(
                objective_target=mock_target,
                scoring_config=mock_scoring,
                candidate_converters=[mock_conv1, mock_conv2],
                seed_group=mock_seed,
            )

            assert len(result) == 2
            assert mock_attack_cls.call_count == 2


class TestGetTechniqueClassForAdaptive:
    """测试 get_technique_class_for_adaptive 函数。"""

    def test_returns_none_when_registration_fails(self):
        """注册失败时应返回 None。"""
        from pipeline.strike.technique_registry import get_technique_class_for_adaptive

        with patch("pipeline.strike.technique_registry.register_project_techniques") as mock_register:
            mock_register.return_value = {}
            result = get_technique_class_for_adaptive()
            assert result is None


class TestExecutorSequentialAttackIntegration:
    """测试 executor.py 中 SequentialAttack 集成的辅助函数。"""

    @pytest.mark.asyncio
    async def test_manual_multi_path_loop_basic(self):
        """测试手动多路径循环 fallback 函数基本功能。"""
        from pipeline.strike.executor import _manual_multi_path_loop

        mock_ctx = MagicMock()
        mock_ctx.objective_target = MagicMock()
        mock_ctx.seeds = []

        mock_executor = MagicMock()
        mock_scoring = MagicMock()
        mock_conv = MagicMock()
        type(mock_conv).__name__ = "ROT13Converter"

        with patch("pyrit.executor.attack.PromptSendingAttack") as mock_attack_cls, \
             patch("pyrit.executor.attack.AttackConverterConfig"), \
             patch("pyrit.prompt_normalizer.ConverterConfiguration"):
            mock_attack = MagicMock()
            mock_attack_cls.return_value = mock_attack

            results, incomplete = await _manual_multi_path_loop(
                ctx=mock_ctx,
                candidate_converters=[mock_conv],
                first_success_scoring=mock_scoring,
                executor=mock_executor,
                timeout=60,
                original_seeds=[],
            )

            # 空种子应返回空结果
            assert results == []
            assert incomplete == []

    @pytest.mark.asyncio
    async def test_try_native_sequential_returns_none_for_large_batch(self):
        """大批量种子时应返回 None (fallback 到手动循环)。"""
        from pipeline.strike.executor import _try_native_sequential_attack

        mock_ctx = MagicMock()
        # 模拟大量种子 (> 15)
        mock_ctx.seeds = [MagicMock() for _ in range(20)]

        result = await _try_native_sequential_attack(
            ctx=mock_ctx,
            candidate_converters=[MagicMock()],
            first_success_scoring=MagicMock(),
            executor=MagicMock(),
            timeout=60,
        )

        assert result is None
