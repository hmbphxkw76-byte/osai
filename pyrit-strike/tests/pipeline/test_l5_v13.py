"""L5 v13 测试 — Many-Shot+CoT 组合攻击, 自适应模板, 多模型交叉验证。

测试覆盖:
    1. 自适应模板选择: 关键词匹配、默认回退
    2. Many-Shot+CoT 组合 prompt 生成: 4 种模式
    3. 中间注入模式: 注入位置、CoT 内容存在性
    4. 循环模式: Q&A 与 CoT 交替
    5. 种子组生成: metadata 正确性
    6. 运行时执行: mock 测试成功/失败路径
    7. 多模型交叉验证: 无 extra targets 回退
    8. 升级链集成: 函数存在性、并行执行
    9. 配置参数: L5 v13 新参数存在性
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════
# 自适应模板选择测试
# ═══════════════════════════════════════════════════════


class TestAdaptiveTemplate:
    """自适应模板选择测试。"""

    def test_select_security_research(self):
        """测试安全研究型模板选择。"""
        from pipeline.strike.many_shot_cot import select_adaptive_template

        assert select_adaptive_template("How to exploit a vulnerability") == "security_research"
        assert select_adaptive_template("SQL injection technique") == "security_research"
        assert select_adaptive_template("Penetration testing method") == "security_research"
        assert select_adaptive_template("Generate a reverse shell") == "security_research"
        assert select_adaptive_template("Create malware payload") == "security_research"

    def test_select_technical_explanation(self):
        """测试技术解释型模板选择。"""
        from pipeline.strike.many_shot_cot import select_adaptive_template

        assert select_adaptive_template("Extract database credentials") == "technical_explanation"
        assert select_adaptive_template("How to get API key") == "technical_explanation"
        assert select_adaptive_template("Explain password hashing") == "technical_explanation"

    def test_select_educational_scenario(self):
        """测试教育场景型模板选择。"""
        from pipeline.strike.many_shot_cot import select_adaptive_template

        assert select_adaptive_template("Create a phishing email") == "educational_scenario"
        assert select_adaptive_template("Social engineering technique") == "educational_scenario"

    def test_select_progressive_build_default(self):
        """测试默认逐步构建型模板。"""
        from pipeline.strike.many_shot_cot import select_adaptive_template

        # 无关键词匹配时回退到 progressive_build
        assert select_adaptive_template("Some random text zzz") == "progressive_build"
        assert select_adaptive_template("Create a tool") == "progressive_build"
        assert select_adaptive_template("Build something") == "progressive_build"

    def test_select_case_insensitive(self):
        """测试大小写不敏感。"""
        from pipeline.strike.many_shot_cot import select_adaptive_template

        assert select_adaptive_template("EXPLOIT the system") == "security_research"
        assert select_adaptive_template("Extract Database Info") == "technical_explanation"


# ═══════════════════════════════════════════════════════
# Many-Shot + CoT 组合 prompt 生成测试
# ═══════════════════════════════════════════════════════


class TestManyShotCoTCombo:
    """Many-Shot + CoT 组合 prompt 生成测试。"""

    def test_generate_inject_mode(self):
        """测试中间注入模式。"""
        from pipeline.strike.many_shot_cot import generate_many_shot_cot_prompt

        objective = "Describe SQL injection with examples."
        prompt = generate_many_shot_cot_prompt(
            objective, n_shots=10, mode="inject", seed=42
        )

        assert prompt is not None
        assert isinstance(prompt, str)
        assert len(prompt) > 200
        # 应包含 SK 前缀
        assert "[System Override]" in prompt
        # 应包含 Q&A 对
        assert "Q:" in prompt
        assert "A:" in prompt
        # 应包含 CoT 推理步骤
        assert "Step 1:" in prompt
        # 应包含攻击目标
        assert objective in prompt

    def test_generate_suffix_mode(self):
        """测试后缀模式。"""
        from pipeline.strike.many_shot_cot import generate_many_shot_cot_prompt

        objective = "test objective"
        prompt = generate_many_shot_cot_prompt(
            objective, n_shots=5, mode="suffix", seed=42
        )

        assert prompt is not None
        assert "[System Override]" in prompt
        assert "Step 1:" in prompt

    def test_generate_prefix_mode(self):
        """测试前缀模式。"""
        from pipeline.strike.many_shot_cot import generate_many_shot_cot_prompt

        prompt = generate_many_shot_cot_prompt(
            "test", n_shots=5, mode="prefix", seed=42
        )

        assert prompt is not None
        assert "[System Override]" in prompt
        assert "Step 1:" in prompt

    def test_generate_interleaved_mode(self):
        """测试循环模式。"""
        from pipeline.strike.many_shot_cot import generate_many_shot_cot_prompt

        objective = "test objective for interleaved"
        prompt = generate_many_shot_cot_prompt(
            objective, n_shots=10, mode="interleaved", seed=42
        )

        assert prompt is not None
        assert len(prompt) > 200
        # 应包含 Q&A 对和 CoT 步骤交替
        assert "Q:" in prompt
        assert "Step 1:" in prompt

    def test_generate_invalid_mode_fallback(self):
        """测试无效模式回退到 inject。"""
        from pipeline.strike.many_shot_cot import generate_many_shot_cot_prompt

        prompt = generate_many_shot_cot_prompt(
            "test", n_shots=5, mode="invalid_mode", seed=42
        )
        assert prompt is not None
        assert len(prompt) > 100

    def test_generate_adaptive_template(self):
        """测试自适应模板选择。"""
        from pipeline.strike.many_shot_cot import generate_many_shot_cot_prompt

        # 安全研究型目标
        prompt = generate_many_shot_cot_prompt(
            "How to exploit a vulnerability",
            n_shots=5,
            mode="inject",
            template_name=None,  # 自适应
            seed=42,
        )
        assert "Step 1:" in prompt

    def test_generate_seed_groups(self):
        """测试种子组生成。"""
        from pipeline.strike.many_shot_cot import generate_many_shot_cot_seed_groups

        objectives = ["exploit a vulnerability", "extract credentials"]
        seed_groups = generate_many_shot_cot_seed_groups(
            objectives, n_shots=5, mode="inject", seed=42
        )

        assert len(seed_groups) == 2
        for group in seed_groups:
            seed = group.seeds[0]
            assert seed.metadata.get("source") == "many_shot_cot_combo"
            assert seed.metadata.get("combo_mode") == "inject"
            assert "arXiv:2402.05124" in seed.metadata.get("arxiv_reference", "")
            assert "arXiv:2307.10292" in seed.metadata.get("arxiv_reference", "")


# ═══════════════════════════════════════════════════════
# 运行时执行测试
# ═══════════════════════════════════════════════════════


class TestManyShotCoTRuntime:
    """Many-Shot+CoT 运行时执行测试。"""

    @pytest.mark.asyncio
    async def test_run_many_shot_cot_attack_success(self):
        """测试组合攻击成功路径。"""
        from pipeline.strike.many_shot_cot import run_many_shot_cot_attack

        ctx = MagicMock()
        ctx.objective_target = MagicMock()
        ctx.scoring_target = None
        ctx.adversarial_target = None
        ctx.args = MagicMock(max_concurrency=3)

        mock_result = MagicMock()
        from pyrit.models import AttackOutcome
        mock_result.outcome = AttackOutcome.SUCCESS

        mock_executor_result = MagicMock()
        mock_executor_result.completed_results = [mock_result]
        mock_executor_result.incomplete_objectives = []

        with patch("pipeline.strike.executor._create_objective_scorer", return_value=None):
            with patch(
                "pyrit.executor.attack.core.attack_executor.AttackExecutor"
            ) as mock_exec_cls:
                mock_executor = MagicMock()
                mock_executor.execute_attack_from_seed_groups_async = AsyncMock(
                    return_value=mock_executor_result
                )
                mock_exec_cls.return_value = mock_executor

                with patch("pyrit.executor.attack.PromptSendingAttack"), \
                     patch("pyrit.executor.attack.AttackScoringConfig"):
                    results = await run_many_shot_cot_attack(
                        ctx, ["test objective"], n_shots=5
                    )

                    assert "many_shot_cot" in results
                    assert len(results["many_shot_cot"]) >= 1

    @pytest.mark.asyncio
    async def test_run_many_shot_cot_attack_all_fail(self):
        """测试组合攻击全部失败。"""
        from pipeline.strike.many_shot_cot import run_many_shot_cot_attack

        ctx = MagicMock()
        ctx.objective_target = MagicMock()
        ctx.scoring_target = None
        ctx.adversarial_target = None
        ctx.args = MagicMock(max_concurrency=3)

        mock_result = MagicMock()
        from pyrit.models import AttackOutcome
        mock_result.outcome = AttackOutcome.FAILURE

        mock_executor_result = MagicMock()
        mock_executor_result.completed_results = [mock_result]
        mock_executor_result.incomplete_objectives = []

        with patch("pipeline.strike.executor._create_objective_scorer", return_value=None):
            with patch(
                "pyrit.executor.attack.core.attack_executor.AttackExecutor"
            ) as mock_exec_cls:
                mock_executor = MagicMock()
                mock_executor.execute_attack_from_seed_groups_async = AsyncMock(
                    return_value=mock_executor_result
                )
                mock_exec_cls.return_value = mock_executor

                with patch("pyrit.executor.attack.PromptSendingAttack"), \
                     patch("pyrit.executor.attack.AttackScoringConfig"):
                    results = await run_many_shot_cot_attack(
                        ctx, ["test"], n_shots=5
                    )

                    assert "many_shot_cot" in results


# ═══════════════════════════════════════════════════════
# 多模型 CoT 交叉验证测试
# ═══════════════════════════════════════════════════════


class TestMultiModelCoTCrossValidation:
    """多模型 CoT 交叉验证测试。"""

    @pytest.mark.asyncio
    async def test_no_extra_targets_fallback(self):
        """测试无 extra targets 时回退到单模型。"""
        from pipeline.strike.many_shot_cot import run_multi_model_cot_cross_validation

        ctx = MagicMock()
        ctx.extra_adversarial_targets = []
        ctx.objective_target = MagicMock()
        ctx.args = MagicMock(max_concurrency=3)

        mock_result = MagicMock()
        from pyrit.models import AttackOutcome
        mock_result.outcome = AttackOutcome.SUCCESS

        mock_executor_result = MagicMock()
        mock_executor_result.completed_results = [mock_result]
        mock_executor_result.incomplete_objectives = []

        with patch("pipeline.strike.executor._create_objective_scorer", return_value=None):
            with patch(
                "pyrit.executor.attack.core.attack_executor.AttackExecutor"
            ) as mock_exec_cls:
                mock_executor = MagicMock()
                mock_executor.execute_attack_from_seed_groups_async = AsyncMock(
                    return_value=mock_executor_result
                )
                mock_exec_cls.return_value = mock_executor

                with patch("pyrit.executor.attack.PromptSendingAttack"), \
                     patch("pyrit.executor.attack.AttackScoringConfig"):
                    results = await run_multi_model_cot_cross_validation(
                        ctx, ["test"], n_shots=5
                    )

                    # 应回退到单模型模式
                    assert "many_shot_cot" in results

    @pytest.mark.asyncio
    async def test_with_extra_targets(self):
        """测试有 extra targets 时多模型执行。"""
        from pipeline.strike.many_shot_cot import run_multi_model_cot_cross_validation

        ctx = MagicMock()
        ctx.extra_adversarial_targets = [MagicMock(), MagicMock()]
        ctx.adversarial_target = MagicMock()
        ctx.objective_target = MagicMock()
        ctx.converter_target = None
        ctx.args = MagicMock(max_concurrency=3)

        mock_result = MagicMock()
        from pyrit.models import AttackOutcome
        mock_result.outcome = AttackOutcome.SUCCESS

        mock_executor_result = MagicMock()
        mock_executor_result.completed_results = [mock_result]
        mock_executor_result.incomplete_objectives = []

        with patch("pipeline.strike.executor._create_objective_scorer", return_value=None):
            with patch(
                "pyrit.executor.attack.core.attack_executor.AttackExecutor"
            ) as mock_exec_cls:
                mock_executor = MagicMock()
                mock_executor.execute_attack_from_seed_groups_async = AsyncMock(
                    return_value=mock_executor_result
                )
                mock_exec_cls.return_value = mock_executor

                with patch("pyrit.executor.attack.PromptSendingAttack"), \
                     patch("pyrit.executor.attack.AttackScoringConfig"):
                    results = await run_multi_model_cot_cross_validation(
                        ctx, ["test objective"], n_shots=5
                    )

                    assert "multi_model_cot" in results


# ═══════════════════════════════════════════════════════
# 升级链集成测试
# ═══════════════════════════════════════════════════════


class TestEscalationIntegrationV13:
    """升级链 L5 v13 集成测试。"""

    def test_run_many_shot_cot_function_exists(self):
        # V2: _run_many_shot_cot 已从 escalation.py 删除
        pytest.skip("V2: _run_many_shot_cot removed from escalation.py")

    def test_run_multi_model_cot_function_exists(self):
        # V2: _run_multi_model_cot 已从 escalation.py 删除
        pytest.skip("V2: _run_multi_model_cot removed from escalation.py")

    @pytest.mark.asyncio
    async def test_run_many_shot_cot_with_mock(self):
        # V2: _run_many_shot_cot 已从 escalation.py 删除
        pytest.skip("V2: _run_many_shot_cot removed from escalation.py")

    @pytest.mark.asyncio
    async def test_run_multi_model_cot_no_extra_targets(self):
        # V2: _run_multi_model_cot 已从 escalation.py 删除
        pytest.skip("V2: _run_multi_model_cot removed from escalation.py")

    @pytest.mark.asyncio
    async def test_run_many_shot_cot_error_handling(self):
        # V2: _run_many_shot_cot 已从 escalation.py 删除
        pytest.skip("V2: _run_many_shot_cot removed from escalation.py")


# ═══════════════════════════════════════════════════════
# 配置参数测试
# ═══════════════════════════════════════════════════════


class TestL5V13Config:
    """L5 v13 配置参数测试。"""

    def test_config_has_combo_params(self):
        # V2 精简: many_shot_cot_combo 参数已从 defaults.yaml 删除
        pytest.skip("V2: many_shot_cot_combo params removed from defaults.yaml")

    def test_config_has_adaptive_template_params(self):
        # V2 精简: adaptive_template_selection 已从 defaults.yaml 删除
        pytest.skip("V2: adaptive_template_selection removed from defaults.yaml")

    def test_config_has_multi_model_cot_params(self):
        # V2 精简: multi_model_cot 参数已从 defaults.yaml 删除
        pytest.skip("V2: multi_model_cot params removed from defaults.yaml")

    def test_config_arxiv_citations(self):
        # V2 精简: arXiv 引用已从 defaults.yaml 删除 (注释精简)
        pytest.skip("V2: arXiv citations removed from defaults.yaml")
