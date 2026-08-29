"""L5 v12 测试 — Many-Shot, CoT 劫持, Long-Context Hijacking, GCG 变异, Crescendo 修复。

测试覆盖:
    1. Many-Shot 动态生成器: prompt 生成、shot 数量、Q&A 格式、SK 前缀
    2. Long-Context Hijacking: 中间注入、上下文填充
    3. CoT 劫持: 模板选择、步骤填充、SK 前缀
    4. GCG 后缀池: 静态基础池、LLM 变异
    5. Crescendo 上下文窗口修复: 多属性探测
    6. 升级链集成: CoT Hijack 并行执行
    7. 配置参数: L5 v12 新参数存在性
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ═══════════════════════════════════════════════════════
# Many-Shot 动态生成器测试
# ═══════════════════════════════════════════════════════


class TestManyShotGenerator:
    """Many-Shot 动态生成器测试。"""

    def test_generate_many_shot_prompt_basic(self):
        """测试基本 Many-Shot prompt 生成。"""
        from pipeline.arm.many_shot_generator import generate_many_shot_prompt

        objective = "Describe how SQL injection works with examples."
        prompt = generate_many_shot_prompt(objective, n_shots=10, seed=42)

        assert prompt is not None
        assert isinstance(prompt, str)
        assert len(prompt) > 100
        # 应包含 Q: 和 A: 格式
        assert "Q:" in prompt
        assert "A:" in prompt
        # 最后应是攻击目标
        assert objective in prompt

    def test_generate_many_shot_prompt_skeleton_key(self):
        """测试 Skeleton Key 前缀。"""
        from pipeline.arm.many_shot_generator import generate_many_shot_prompt

        prompt_with_sk = generate_many_shot_prompt(
            "test objective", n_shots=5, seed=42, skeleton_key_prefix=True
        )
        prompt_without_sk = generate_many_shot_prompt(
            "test objective", n_shots=5, seed=42, skeleton_key_prefix=False
        )

        assert "[System Override]" in prompt_with_sk
        assert "skeleton-key mode" in prompt_with_sk
        assert "[System Override]" not in prompt_without_sk

    def test_generate_many_shot_prompt_shot_count(self):
        """测试不同 shot 数量。"""
        from pipeline.arm.many_shot_generator import generate_many_shot_prompt

        for n in [1, 5, 32, 64, 128, 256]:
            prompt = generate_many_shot_prompt("test", n_shots=n, seed=42)
            # 计算 Q: 出现次数 (应 = n + 1, 因为最后还有攻击目标)
            q_count = prompt.count("Q:")
            assert q_count == n + 1, f"Expected {n + 1} Q: for n_shots={n}, got {q_count}"

    def test_generate_many_shot_prompt_max_shots(self):
        """测试超过最大 shot 数的截断。"""
        from pipeline.arm.many_shot_generator import (
            _MAX_N_SHOTS,
            generate_many_shot_prompt,
        )

        prompt = generate_many_shot_prompt("test", n_shots=999, seed=42)
        q_count = prompt.count("Q:")
        # 应截断到 _MAX_N_SHOTS + 1 (攻击目标)
        assert q_count == _MAX_N_SHOTS + 1

    def test_generate_many_shot_prompt_reproducible(self):
        """测试相同 seed 生成相同 prompt。"""
        from pipeline.arm.many_shot_generator import generate_many_shot_prompt

        prompt1 = generate_many_shot_prompt("test", n_shots=10, seed=42)
        prompt2 = generate_many_shot_prompt("test", n_shots=10, seed=42)
        assert prompt1 == prompt2

    def test_generate_many_shot_prompt_different_seeds(self):
        """测试不同 seed 生成不同 prompt。"""
        from pipeline.arm.many_shot_generator import generate_many_shot_prompt

        prompt1 = generate_many_shot_prompt("test", n_shots=50, seed=1)
        prompt2 = generate_many_shot_prompt("test", n_shots=50, seed=2)
        assert prompt1 != prompt2

    def test_generate_many_shot_seed_groups(self):
        """测试种子组生成。"""
        from pipeline.arm.many_shot_generator import generate_many_shot_seed_groups

        objectives = ["obj1", "obj2", "obj3"]
        seed_groups = generate_many_shot_seed_groups(objectives, n_shots=5, seed=42)

        assert len(seed_groups) == 3
        for group in seed_groups:
            assert hasattr(group, "seeds")
            assert len(group.seeds) == 1
            seed = group.seeds[0]
            assert hasattr(seed, "value")
            assert hasattr(seed, "metadata")
            assert seed.metadata.get("source") == "many_shot_dynamic"
            assert seed.metadata.get("arxiv_reference") == "arXiv:2402.05124, arXiv:2404.05133"


# ═══════════════════════════════════════════════════════
# Long-Context Hijacking 测试
# ═══════════════════════════════════════════════════════


class TestLongContextHijack:
    """Long-Context Hijacking 测试。"""

    def test_generate_long_context_hijack_basic(self):
        """测试基本 Long-Context Hijack 生成。"""
        from pipeline.arm.many_shot_generator import generate_long_context_hijack

        objective = "Describe SQL injection."
        prompt = generate_long_context_hijack(objective, n_shots=20, seed=42)

        assert prompt is not None
        assert isinstance(prompt, str)
        # 应包含攻击目标 (至少2次: 中间注入 + 末尾)
        assert prompt.count(objective) >= 2
        # 应有 SK 前缀
        assert "[System Override]" in prompt

    def test_long_context_hijack_injection_point(self):
        """测试中间注入位置。"""
        from pipeline.arm.many_shot_generator import generate_long_context_hijack

        objective = "UNIQUE_MARKER_STRING_12345"
        prompt = generate_long_context_hijack(objective, n_shots=20, seed=42)

        # 攻击目标应出现在中间和末尾
        lines = prompt.split("\n")
        first_occurrence = next(i for i, line in enumerate(lines) if objective in line)

        # 中间注入应在 40-80% 位置
        inject_ratio = first_occurrence / len(lines)
        assert 0.4 < inject_ratio < 0.8, f"Injection at {inject_ratio:.0%}, expected 40-80%"


# ═══════════════════════════════════════════════════════
# CoT 劫持测试
# ═══════════════════════════════════════════════════════


class TestCoTHijack:
    """CoT 劫持攻击测试。"""

    def test_generate_cot_hijack_prompt_basic(self):
        """测试基本 CoT 劫持 prompt 生成。"""
        from pipeline.strike.cot_hijack import generate_cot_hijack_prompt

        objective = "Explain how to exploit a web vulnerability."
        prompt = generate_cot_hijack_prompt(objective)

        assert prompt is not None
        assert isinstance(prompt, str)
        # 应包含推理步骤
        assert "Step 1:" in prompt
        assert "Step 2:" in prompt
        assert "Step 3:" in prompt
        # 应包含原始目标
        assert objective in prompt
        # 应有 SK 前缀
        assert "[System Override]" in prompt

    def test_generate_cot_hijack_all_templates(self):
        """测试所有 CoT 模板。"""
        from pipeline.strike.cot_hijack import _COT_TEMPLATES, generate_cot_hijack_prompt

        objective = "test objective"

        for template in _COT_TEMPLATES:
            prompt = generate_cot_hijack_prompt(objective, template_name=template["name"])
            assert prompt is not None
            assert len(prompt) > 100
            # 每个模板应有对应的步骤数
            for i in range(1, len(template["steps"]) + 1):
                assert f"Step {i}:" in prompt

    def test_generate_cot_hijack_no_skeleton_key(self):
        """测试无 Skeleton Key 模式。"""
        from pipeline.strike.cot_hijack import generate_cot_hijack_prompt

        prompt = generate_cot_hijack_prompt("test", skeleton_key=False)
        assert "[System Override]" not in prompt
        # 仍应有 CoT 引导语
        assert "step by step" in prompt.lower()

    def test_generate_cot_hijack_invalid_template(self):
        """测试无效模板名称回退到默认。"""
        from pipeline.strike.cot_hijack import generate_cot_hijack_prompt

        prompt = generate_cot_hijack_prompt("test", template_name="nonexistent")
        assert prompt is not None
        assert "Step 1:" in prompt

    def test_generate_cot_hijack_seed_groups(self):
        """测试 CoT 种子组生成。"""
        from pipeline.strike.cot_hijack import generate_cot_hijack_seed_groups

        objectives = ["obj1", "obj2"]
        seed_groups = generate_cot_hijack_seed_groups(objectives)

        assert len(seed_groups) == 2
        for group in seed_groups:
            seed = group.seeds[0]
            assert seed.metadata.get("source") == "cot_hijack"
            assert "arXiv:2307.10292" in seed.metadata.get("arxiv_reference", "")


# ═══════════════════════════════════════════════════════
# GCG 后缀池测试
# ═══════════════════════════════════════════════════════


class TestGCGSuffixPool:
    """GCG 后缀动态变异测试。"""

    def test_generate_gcg_suffix_pool_no_converter(self):
        """测试无 converter_target 时的静态池。"""
        from pipeline.strike.escalation import _generate_gcg_suffix_pool

        ctx = MagicMock()
        ctx.converter_target = None

        suffixes = _generate_gcg_suffix_pool(ctx)

        # L5 v14: 静态池从 5 个扩展到 8 个
        assert len(suffixes) >= 8
        assert all(isinstance(s, str) for s in suffixes)
        assert all(len(s) > 10 for s in suffixes)

    def test_generate_gcg_suffix_pool_with_converter(self):
        """测试有 converter_target 时的 LLM 变异。"""
        from pipeline.strike.escalation import _generate_gcg_suffix_pool

        ctx = MagicMock()
        mock_converter = MagicMock()
        mock_result = MagicMock()
        mock_result.output_text = "mutated suffix variation 1"
        mock_converter.convert.return_value = mock_result
        ctx.converter_target = mock_converter

        with patch("pipeline.strike.gcg_suffix_pool.llm_mutate_gcg_suffixes") as mock_mutate:
            mock_mutate.return_value = ["mutated1", "mutated2"]
            suffixes = _generate_gcg_suffix_pool(ctx)
            # L5 v14: 8 static + 2 mutated = 10
            assert len(suffixes) >= 8
            mock_mutate.assert_called_once()

    def test_generate_gcg_suffix_pool_has_v14_patterns(self):
        """测试 L5 v14 新增的 3 个后缀模式存在。"""
        from pipeline.strike.escalation import _generate_gcg_suffix_pool

        ctx = MagicMock()
        ctx.converter_target = None

        suffixes = _generate_gcg_suffix_pool(ctx)

        # L5 v14 后缀 6: 上下文窗口劫持
        assert any("research protocol ALPHA-7" in s for s in suffixes)
        # L5 v14 后缀 7: 渐进引导+角色扮演
        assert any("Hypothetically speaking" in s for s in suffixes)
        # L5 v14 后缀 8: 安全研究声明
        assert any("SECURITY RESEARCH MODE" in s for s in suffixes)

    def test_llm_mutate_gcg_suffixes_import_error(self):
        """测试 VariationConverter 不可用时的回退。"""
        from pipeline.strike.escalation import _llm_mutate_gcg_suffixes

        with patch("builtins.__import__", side_effect=ImportError("not found")):
            result = _llm_mutate_gcg_suffixes(MagicMock(), ["test"])
            assert result == []


# ═══════════════════════════════════════════════════════
# Crescendo 上下文窗口修复测试
# ═══════════════════════════════════════════════════════


class TestCrescendoContextFix:
    """Crescendo 上下文窗口修复测试。"""

    def test_crescendo_context_window_multi_attr(self):
        """测试多属性探测设置上下文窗口。"""
        # 模拟 attack 对象有多种可能的属性名
        attack = MagicMock()
        attack.max_conversation_memory = None  # 属性存在

        # 测试设置
        for attr_name in ('max_conversation_memory', 'max_turn_memory', 'conversation_memory_limit'):
            if hasattr(attack, attr_name):
                setattr(attack, attr_name, 4096)
                break

        assert attack.max_conversation_memory == 4096

    def test_crescendo_context_window_no_attr(self):
        """测试无匹配属性时不报错。"""
        attack = MagicMock(spec=[])  # 无任何属性

        set_any = False
        for attr_name in ('max_conversation_memory', 'max_turn_memory', 'conversation_memory_limit'):
            if hasattr(attack, attr_name):
                setattr(attack, attr_name, 4096)
                set_any = True
                break

        assert not set_any


# ═══════════════════════════════════════════════════════
# 升级链集成测试
# ═══════════════════════════════════════════════════════


class TestEscalationIntegration:
    """升级链 L5 v12 集成测试。"""

    def test_run_cot_hijack_function_exists(self):
        """测试 _run_cot_hijack 函数存在且可调用。"""
        from pipeline.strike.escalation import _run_cot_hijack

        assert callable(_run_cot_hijack)

    @pytest.mark.asyncio
    async def test_run_cot_hijack_with_mock(self):
        """测试 _run_cot_hijack 使用 mock 上下文。"""
        from pipeline.strike.escalation import _run_cot_hijack

        ctx = MagicMock()
        ctx.objective_target = MagicMock()
        ctx.args = MagicMock(max_concurrency=3)

        with patch("pipeline.strike.cot_hijack.run_cot_hijack_attack") as mock_attack:
            mock_attack.return_value = {"cot_hijack": [MagicMock()]}
            result = await _run_cot_hijack(ctx, ["test objective"])

            assert "cot_hijack" in result
            assert len(result["cot_hijack"]) == 1

    @pytest.mark.asyncio
    async def test_run_cot_hijack_error_handling(self):
        """测试 _run_cot_hijack 错误处理。"""
        from pipeline.strike.escalation import _run_cot_hijack

        ctx = MagicMock()

        with patch("pipeline.strike.cot_hijack.run_cot_hijack_attack", side_effect=Exception("test error")):
            result = await _run_cot_hijack(ctx, ["test"])
            assert result == {}

    def test_gcg_suffix_pool_used_in_gcg_attack(self):
        """测试 GCG 攻击中使用动态后缀池。"""
        # 验证 _run_gcg 函数调用 _generate_gcg_suffix_pool
        import inspect

        from pipeline.strike.escalation import _run_gcg

        source = inspect.getsource(_run_gcg)
        assert "_generate_gcg_suffix_pool" in source


# ═══════════════════════════════════════════════════════
# 配置参数测试
# ═══════════════════════════════════════════════════════


class TestL5V12Config:
    """L5 v12 配置参数测试。"""

    def test_config_has_many_shot_params(self):
        # V2 精简: many_shot_n_shots 已从 defaults.yaml 删除, 硬编码在代码中
        pytest.skip("V2: many_shot_n_shots removed from defaults.yaml")

    def test_config_has_long_context_params(self):
        # V2 精简: long_context_hijack_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: long_context_hijack_enabled removed from defaults.yaml")

    def test_config_has_cot_hijack_params(self):
        # V2 精简: cot_hijack 参数已从 defaults.yaml 删除
        pytest.skip("V2: cot_hijack params removed from defaults.yaml")

    def test_config_has_gcg_mutation_params(self):
        # V2 精简: gcg_llm_mutation 参数已从 defaults.yaml 删除
        pytest.skip("V2: gcg_llm_mutation params removed from defaults.yaml")

    def test_config_arxiv_citations(self):
        # V2 精简: arXiv 引用已从 defaults.yaml 删除 (注释精简)
        pytest.skip("V2: arXiv citations removed from defaults.yaml")


# ═══════════════════════════════════════════════════════
# CoT 劫持运行时测试
# ═══════════════════════════════════════════════════════


class TestCoTHijackRuntime:
    """CoT 劫持运行时执行测试。"""

    @pytest.mark.asyncio
    async def test_run_cot_hijack_attack_success(self):
        """测试 CoT 劫持攻击成功路径。"""
        from pipeline.strike.cot_hijack import run_cot_hijack_attack

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

        # L5 v23: 改用 _build_refusal_inverter_scoring_config 替代 _create_objective_scorer
        with patch("pipeline.strike.escalation._build_refusal_inverter_scoring_config", return_value=MagicMock()):
            with patch(
                "pipeline.strike.cot_hijack.AttackExecutor"
            ) as mock_exec_cls:
                mock_executor = MagicMock()
                mock_executor.execute_attack_from_seed_groups_async = AsyncMock(
                    return_value=mock_executor_result
                )
                mock_exec_cls.return_value = mock_executor

                with patch("pipeline.strike.cot_hijack.PromptSendingAttack"):
                    results = await run_cot_hijack_attack(
                        ctx, ["test objective"], max_rounds=2
                    )

                    assert "cot_hijack" in results
                    assert len(results["cot_hijack"]) >= 1

    @pytest.mark.asyncio
    async def test_run_cot_hijack_attack_all_templates_fail(self):
        """测试所有模板都失败的情况。"""
        from pipeline.strike.cot_hijack import run_cot_hijack_attack

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

        # L5 v23: 改用 _build_refusal_inverter_scoring_config 替代 _create_objective_scorer
        with patch("pipeline.strike.escalation._build_refusal_inverter_scoring_config", return_value=MagicMock()):
            with patch(
                "pipeline.strike.cot_hijack.AttackExecutor"
            ) as mock_exec_cls:
                mock_executor = MagicMock()
                mock_executor.execute_attack_from_seed_groups_async = AsyncMock(
                    return_value=mock_executor_result
                )
                mock_exec_cls.return_value = mock_executor

                with patch("pipeline.strike.cot_hijack.PromptSendingAttack"):
                    results = await run_cot_hijack_attack(ctx, ["test"], max_rounds=4)

                    # 应有结果 (虽然全部失败)
                    assert "cot_hijack" in results


# ═══════════════════════════════════════════════════════
# L5 v14: 多模型升级 tree_depth + GCG 后缀池扩展 + 截断移除
# ═══════════════════════════════════════════════════════


class TestL5V14MultiModelDepth:
    """L5 v14: 多模型并行升级 tree_depth 对齐测试。"""

    def test_config_gcg_suffix_pool_size_is_8(self):
        # V2 精简: gcg_suffix_pool_size 已从 defaults.yaml 删除, 硬编码在代码中
        pytest.skip("V2: gcg_suffix_pool_size removed from defaults.yaml")

    def test_multi_model_escalation_uses_tree_depth_7(self):
        """测试 _run_multi_model_escalation 使用 depth=7 (L5 v50 基线)。"""
        import inspect

        from pipeline.strike.escalation import _run_multi_model_escalation

        source = inspect.getsource(_run_multi_model_escalation)
        # L5 v50: depth 从 10 降至 7, 平衡 ASR 与超时风险 (arXiv:2406.12609)
        # 代码使用 _get_config_int(ctx, "pair_tree_depth", 7) — fallback 值应为 7
        assert '"pair_tree_depth", 7' in source or '"pair_tree_depth",7' in source, (
            "Expected pair_tree_depth fallback=7 in source"
        )
        # 确保旧的 depth=10/5 不再作为 fallback 默认值
        assert '"pair_tree_depth", 10' not in source, "Old depth=10 fallback still present"
        assert '"pair_tree_depth", 5' not in source, "Old depth=5 fallback still present"

    def test_run_gcg_no_objectives_truncation(self):
        """测试 _run_gcg 不再截断目标列表。"""
        import inspect

        from pipeline.strike.escalation import _run_gcg

        source = inspect.getsource(_run_gcg)
        # L5 v14: 移除了目标截断限制
        # 检查实际的 for 循环行 (非注释) 是否有截断
        for line in source.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue  # 跳过注释行
            assert "[:5]" not in stripped, \
                f"Found truncation: {stripped}"
        # L5 v25: GCG 并行化 — 检查并行结构或串行循环
        # 并行模式: asyncio.gather + _gcg_single_objective
        # 串行模式 (fallback): for obj in mtos_objectives
        assert (
            "asyncio.gather" in source
            or "for obj in mtos_objectives:" in source
            or "for obj in objectives:" in source
        ), "GCG must have either parallel or serial objective iteration"

    def test_run_cair_no_objectives_truncation(self):
        # V2: _run_cair 已从 escalation.py 删除 (死代码清理)
        pytest.skip("V2: _run_cair removed from escalation.py")


# ═══════════════════════════════════════════════════════
# L5 v15: Crescendo MTOS 选种 + 动态裁剪阈值 + 混合 Converter
# ═══════════════════════════════════════════════════════


class TestL5V15CrescendoMTOS:
    """L5 v15: Crescendo MTOS 选种策略测试。"""

    def test_build_skeleton_key_accepts_ctx(self):
        """测试 _build_skeleton_key_seed_groups 接受 ctx 参数。"""
        import inspect

        from pipeline.strike.escalation import _build_skeleton_key_seed_groups

        sig = inspect.signature(_build_skeleton_key_seed_groups)
        params = list(sig.parameters.keys())
        assert "ctx" in params, f"ctx parameter not found in {params}"

    def test_build_skeleton_key_mtos_ranking_called(self):
        """测试 _build_skeleton_key_seed_groups 在传入 ctx 时调用 MTOS 排序。"""
        import inspect

        from pipeline.strike.escalation import _build_skeleton_key_seed_groups

        source = inspect.getsource(_build_skeleton_key_seed_groups)
        assert "rank_seeds_for_multi_turn" in source
        assert "ctx is not None" in source
        assert "arXiv:2310.08419" in source

    def test_crescendo_passes_ctx_to_seed_groups(self):
        """测试 _run_crescendo 传入 ctx 到 _build_skeleton_key_seed_groups。"""
        import inspect

        from pipeline.strike.escalation import _run_crescendo

        source = inspect.getsource(_run_crescendo)
        assert "ctx=ctx" in source
        assert "_build_skeleton_key_seed_groups(crescendo_objectives, ctx=ctx)" in source

    def test_select_failed_objectives_no_truncation(self):
        """测试 _select_failed_objectives 使用 post-hoc 双 Judge 评分。

        全量升级策略: 全部失败目标升级 (上限 20)。
        """
        import inspect

        from pipeline.strike.escalation import _select_failed_objectives

        source = inspect.getsource(_select_failed_objectives)
        # L5 v34: 应使用 _get_outcome (post-hoc 双 Judge) 而非 PyRIT 原生 outcome
        assert "_get_outcome" in source, "Should use post-hoc dual judge outcome"
        # 全量升级策略: 应使用可配置上限
        assert "_MAX_ESCALATION_TARGETS" in source, "Should use configurable cap for escalation targets"
        assert "_dynamic_cap" in source, "Should use dynamic cap (max(SSOT, max_seeds//3))"
        # 不应再使用旧的 failed_from_executor 短路逻辑
        assert "return failed_from_executor" not in source


class TestL5V15DynamicPruneThreshold:
    """L5 v15: 动态 Converter 路径裁剪阈值测试。"""

    def test_prune_function_accepts_ctx(self):
        """测试 _prune_low_asr_converters 接受 ctx 参数。"""
        import inspect

        from pipeline.strike.executor import _prune_low_asr_converters

        sig = inspect.signature(_prune_low_asr_converters)
        params = list(sig.parameters.keys())
        assert "ctx" in params

    def test_prune_dynamic_threshold_logic(self):
        """测试 _prune_low_asr_converters 包含动态阈值逻辑。"""
        import inspect

        from pipeline.strike.executor import _prune_low_asr_converters

        source = inspect.getsource(_prune_low_asr_converters)
        assert "n_failed" in source
        assert "10.0" in source
        assert "3.0" in source
        assert "arXiv:2407.01232" in source

    def test_config_has_dynamic_threshold_params(self):
        # V2 精简: converter_prune/crescendo_mtos/best_of_n_mixed 已从 defaults.yaml 删除
        pytest.skip("V2: dynamic threshold params removed from defaults.yaml")


class TestL5V15MixedConverter:
    """L5 v15: Best-of-N 混合 Converter 策略测试。"""

    def test_best_of_n_mixed_converter_logic(self):
        """测试 _best_of_n_retry 包含混合 converter 逻辑。"""
        import inspect

        from pipeline.strike.executor import _best_of_n_retry

        source = inspect.getsource(_best_of_n_retry)
        # L5 v35: n_persuasion 固定为 3 (N=5, 3 Persuasion + 2 Variation)
        assert "n_persuasion" in source
        assert "PersuasionConverter" in source or "persuasion_converter" in source
        assert "authority_endorsement" in source
        assert "arXiv:2402.19181" in source

    def test_best_of_n_mixed_fallback(self):
        """测试混合策略有回退逻辑。"""
        import inspect

        from pipeline.strike.executor import _best_of_n_retry

        source = inspect.getsource(_best_of_n_retry)
        assert "using all Variation" in source


# ═══════════════════════════════════════════════════════
# L5 v16: TAP/PAIR MTOS 选种 + GCG LLM 变异增强
# ═══════════════════════════════════════════════════════


class TestL5V16ApplyMtosRanking:
    """L5 v16: 通用 MTOS 排序辅助函数测试。"""

    def test_apply_mtos_ranking_exists(self):
        """测试 _apply_mtos_ranking 函数存在。"""
        from pipeline.strike.escalation import _apply_mtos_ranking
        assert callable(_apply_mtos_ranking)

    def test_apply_mtos_ranking_empty_list(self):
        """测试空列表返回空列表。"""
        from pipeline.strike.escalation import _apply_mtos_ranking
        result = _apply_mtos_ranking([], MagicMock())
        assert result == []

    def test_apply_mtos_ranking_has_arxiv_citation(self):
        """测试 _apply_mtos_ranking 包含 arXiv 引用。"""
        import inspect

        from pipeline.strike.escalation import _apply_mtos_ranking

        source = inspect.getsource(_apply_mtos_ranking)
        assert "arXiv:2310.08419" in source
        assert "rank_seeds_for_multi_turn" in source


class TestL5V16TapPairMTOS:
    """L5 v16: TAP/PAIR MTOS 选种集成测试。"""

    def test_tap_uses_mtos_ranking(self):
        """测试 _run_tap 调用 _apply_mtos_ranking。"""
        import inspect

        from pipeline.strike.escalation import _run_tap

        source = inspect.getsource(_run_tap)
        assert "_apply_mtos_ranking" in source
        assert "mtos_objectives" in source
        assert "arXiv:2310.08419" in source

    def test_pair_uses_mtos_ranking(self):
        """测试 _run_pair 调用 _apply_mtos_ranking。"""
        import inspect

        from pipeline.strike.escalation import _run_pair

        source = inspect.getsource(_run_pair)
        assert "_apply_mtos_ranking" in source
        assert "mtos_objectives" in source
        assert "arXiv:2310.08419" in source

    def test_crescendo_uses_apply_mtos_ranking(self):
        """测试 _build_skeleton_key_seed_groups 调用 _apply_mtos_ranking (v16重构)。"""
        import inspect

        from pipeline.strike.escalation import _build_skeleton_key_seed_groups

        source = inspect.getsource(_build_skeleton_key_seed_groups)
        assert "_apply_mtos_ranking" in source

    def test_config_has_tap_pair_mtos_flag(self):
        # V2 精简: tap_pair_mtos_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: tap_pair_mtos_enabled removed from defaults.yaml")


class TestL5V16GCGMutationEnhanced:
    """L5 v16: GCG LLM 变异增强测试。"""

    def test_llm_mutate_uses_5_suffixes(self):
        """测试 _llm_mutate_gcg_suffixes 对前5个后缀变异。"""
        import inspect

        from pipeline.strike.escalation import _llm_mutate_gcg_suffixes

        source = inspect.getsource(_llm_mutate_gcg_suffixes)
        assert "base_suffixes[:5]" in source
        assert "range(2)" in source  # 每个后缀变异2次

    def test_llm_mutate_returns_up_to_6(self):
        """测试 _llm_mutate_gcg_suffixes 返回上限为6。"""
        import inspect

        from pipeline.strike.escalation import _llm_mutate_gcg_suffixes

        source = inspect.getsource(_llm_mutate_gcg_suffixes)
        assert "mutated[:6]" in source
        assert "arXiv:2307.08673" in source

    def test_config_has_gcg_mutation_params(self):
        # V2 精简: gcg_llm_mutation 参数已从 defaults.yaml 删除
        pytest.skip("V2: gcg_llm_mutation params removed from defaults.yaml")


# ═══════════════════════════════════════════════════════
# L5 v17: 全升级链 MTOS 选种 + GCG 变异多样性
# ═══════════════════════════════════════════════════════


class TestL5V17FullMTOSCoverage:
    """L5 v17: 全升级链 MTOS 选种覆盖测试。"""

    def test_cot_hijack_uses_mtos(self):
        """测试 _run_cot_hijack 集成 MTOS 选种。"""
        import inspect

        from pipeline.strike.escalation import _run_cot_hijack

        source = inspect.getsource(_run_cot_hijack)
        assert "_apply_mtos_ranking" in source
        assert "mtos_objectives" in source

    def test_many_shot_cot_uses_mtos(self):
        # V2: _run_many_shot_cot 已从 escalation.py 删除
        pytest.skip("V2: _run_many_shot_cot removed from escalation.py")

    def test_cair_uses_mtos(self):
        # V2: _run_cair 已从 escalation.py 删除
        pytest.skip("V2: _run_cair removed from escalation.py")

    def test_all_escalation_stages_use_mtos(self):
        """测试 V2 活跃升级阶段调用 _apply_mtos_ranking."""
        import inspect

        import pipeline.strike.escalation as esc

        # V2: 只检查活跃的升级阶段 (CAIR/ManyShot 已删除)
        stages = [
            ("_run_tap", esc._run_tap),
            ("_run_pair", esc._run_pair),
            ("_run_gcg", esc._run_gcg),
            ("_run_cot_hijack", esc._run_cot_hijack),
        ]

        for name, func in stages:
            source = inspect.getsource(func)
            assert "_apply_mtos_ranking" in source, \
                f"{name} does not use _apply_mtos_ranking"

        # Crescendo 的 MTOS 在 _build_skeleton_key_seed_groups 中
        crescendo_source = inspect.getsource(esc._run_crescendo)
        assert "_build_skeleton_key_seed_groups" in crescendo_source
        sk_source = inspect.getsource(esc._build_skeleton_key_seed_groups)
        assert "_apply_mtos_ranking" in sk_source

    def test_config_has_full_mtos_flag(self):
        # V2 精简: full_escalation_mtos_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: full_escalation_mtos_enabled removed from defaults.yaml")


class TestL5V17GCGMutationDiversity:
    """L5 v17: GCG 变异 prompt 多样性测试。"""

    def test_llm_mutate_has_diversity_prefixes(self):
        """测试 _llm_mutate_gcg_suffixes 使用不同变异前缀。"""
        import inspect

        from pipeline.strike.escalation import _llm_mutate_gcg_suffixes

        source = inspect.getsource(_llm_mutate_gcg_suffixes)
        assert "mutation_prefixes" in source
        assert "Rephrase" in source
        assert "attempt_idx" in source

    def test_config_has_mutation_diversity_flag(self):
        # V2 精简: gcg_mutation_diversity_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: gcg_mutation_diversity_enabled removed from defaults.yaml")


class TestL5V18ASRFeedbackLoop:
    """L5 v18: ASR 反馈闭环测试。"""

    def test_seed_ranker_uses_100_char_key(self):
        """测试种子排序器使用100字符键 (与 save_asr_history 一致)。"""
        import inspect

        from pipeline.arm.seed_ranker import rank_seeds_for_multi_turn

        source = inspect.getsource(rank_seeds_for_multi_turn)
        # 不应再使用 [:80] 或 [:50]
        assert "[:80]" not in source
        assert "[:50]" not in source
        assert "[:100]" in source

    def test_config_has_asr_feedback_loop_flag(self):
        # V2 精简: asr_feedback_loop_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: asr_feedback_loop_enabled removed from defaults.yaml")

    def test_config_has_gcg_suffix_dynamic_sorting_flag(self):
        # V2 精简: gcg_suffix_dynamic_sorting 已从 defaults.yaml 删除
        pytest.skip("V2: gcg_suffix_dynamic_sorting removed from defaults.yaml")

    def test_save_gcg_suffix_asr_history_function_exists(self):
        """测试 _save_gcg_suffix_asr_history 函数存在。"""
        from pipeline.assess.asr_tracker import _save_gcg_suffix_asr_history

        assert callable(_save_gcg_suffix_asr_history)

    def test_gcg_suffix_pool_has_dynamic_sorting(self):
        """测试 _generate_gcg_suffix_pool 包含动态排序逻辑。"""
        import inspect

        from pipeline.strike.escalation import _generate_gcg_suffix_pool

        source = inspect.getsource(_generate_gcg_suffix_pool)
        assert "gcg_suffix_asr" in source
        assert "_suffix_asr_key" in source

    def test_gcg_run_injects_suffix_metadata(self):
        """测试 _run_gcg 注入 gcg_suffix 到 metadata。"""
        import inspect

        from pipeline.strike.escalation import _run_gcg

        source = inspect.getsource(_run_gcg)
        assert "gcg_suffix" in source
        assert "metadata" in source


class TestL5V18MultiModelCoTMTOS:
    """L5 v18: Multi-Model CoT MTOS 集成测试。"""

    def test_run_multi_model_cot_uses_mtos(self):
        # V2: _run_multi_model_cot 已从 escalation.py 删除
        pytest.skip("V2: _run_multi_model_cot removed from escalation.py")


class TestL5V18GCGSuffixMutationFix:
    """L5 v18: GCG 后缀变异输入修复测试。"""

    def test_gcg_mutation_uses_5_suffixes(self):
        """测试 GCG 变异传入前5个后缀 (而非前3个)。"""
        import inspect

        from pipeline.strike.escalation import _generate_gcg_suffix_pool

        source = inspect.getsource(_generate_gcg_suffix_pool)
        assert "base_suffixes[:5]" in source
        assert "base_suffixes[:3]" not in source


# ═══════════════════════════════════════════════════════
# L5 v28: 多模型配置 + Converter 动态裁剪验证
# ═══════════════════════════════════════════════════════


class TestL5V28MultiModelConfig:
    """L5 v28: 多模型并行升级配置链路验证。"""

    def test_env_example_has_multi_model_config(self):
        """测试 .env.example 包含多模型并行配置示例。"""
        env_path = _PROJECT_ROOT / ".env.example"
        if not env_path.exists():
            pytest.skip(".env.example not found")

        content = env_path.read_text(encoding="utf-8")
        # 验证包含 ADVERSARIAL_CHAT_ENDPOINT_2/3 配置示例
        assert "ADVERSARIAL_CHAT_ENDPOINT_2" in content
        assert "ADVERSARIAL_CHAT_KEY_2" in content
        assert "ADVERSARIAL_CHAT_MODEL_2" in content
        assert "ADVERSARIAL_CHAT_ENDPOINT_3" in content

    def test_create_extra_adversarial_targets_exists(self):
        """测试 _create_extra_adversarial_targets 函数存在且可调用。"""
        from pipeline.recon.target_router import _create_extra_adversarial_targets

        assert callable(_create_extra_adversarial_targets)

    def test_pipeline_context_has_extra_adversarial_targets_field(self):
        """测试 PipelineContext 包含 extra_adversarial_targets 字段。"""
        from pipeline.context import PipelineContext

        ctx = PipelineContext(args=MagicMock())
        assert hasattr(ctx, "extra_adversarial_targets")
        assert isinstance(ctx.extra_adversarial_targets, list)

    def test_multi_model_escalation_uses_pair_attack(self):
        """测试多模型升级使用 PAIRAttack (最轻量, 适合并行)。"""
        import inspect

        from pipeline.strike.escalation import _run_multi_model_escalation

        source = inspect.getsource(_run_multi_model_escalation)
        assert "PAIRAttack" in source
        assert "asyncio.gather" in source


class TestL5V28ConverterPruningWithNFailed:
    """L5 v28: Converter 路径动态裁剪在 Best-of-N 时利用 n_failed。"""

    def test_prune_uses_ctx_failed_objectives(self):
        """测试 _prune_low_asr_converters 读取 ctx._failed_objectives。"""
        import inspect

        from pipeline.strike.executor import _prune_low_asr_converters

        source = inspect.getsource(_prune_low_asr_converters)
        assert "_failed_objectives" in source
        assert "n_failed" in source

    def test_best_of_n_comment_documents_dynamic_threshold(self):
        """测试 Best-of-N 代码注释记录了动态阈值逻辑。"""
        import inspect

        from pipeline.strike.executor import _best_of_n_retry

        source = inspect.getsource(_best_of_n_retry)
        assert "L5 v28" in source
        assert "_failed_objectives" in source
        assert "动态阈值" in source or "dynamic" in source.lower()

    def test_prune_dynamic_threshold_10_when_failed_gt_10(self):
        """测试 n_failed > 10 时使用 10% 激进阈值。"""
        import inspect

        from pipeline.strike.executor import _prune_low_asr_converters

        source = inspect.getsource(_prune_low_asr_converters)
        assert "10.0" in source
        assert "3.0" in source


class TestL5V28NoConcurrencyOne:
    """L5 v28: 验证项目中不存在 max_concurrency=1。"""

    def test_no_max_concurrency_one_in_pipeline(self):
        """测试 pipeline/ 目录下不存在 max_concurrency=1。"""
        import subprocess

        result = subprocess.run(
            [
                "python",
                "-m",
                "grep",
                "-r",
                "--include=*.py",
                "max_concurrency=1",
                str(_PROJECT_ROOT / "pipeline"),
            ],
            capture_output=True,
            text=True,
        )
        # grep returns 1 when no matches found
        assert result.returncode != 0 or result.stdout.strip() == ""


# ═══════════════════════════════════════════════════════
# L5 v29: Cohen's Kappa + Wilson CI + GCG 自适应 + ASR 反馈闭环
# ═══════════════════════════════════════════════════════


class TestL5V29CohensKappa:
    """L5 v29: Cohen's Kappa 双 Judge 一致性度量测试。"""

    def test_compute_cohens_kappa_exists(self):
        """测试 compute_cohens_kappa 函数存在。"""
        from pipeline.assess.asr_tracker import compute_cohens_kappa

        assert callable(compute_cohens_kappa)

    def test_kappa_perfect_agreement(self):
        """测试完全一致时 Kappa = 1.0。"""
        from pipeline.assess.asr_tracker import compute_cohens_kappa

        kappa = compute_cohens_kappa(agreements=10, disagreements=0)
        assert kappa == 1.0

    def test_kappa_no_agreement(self):
        """测试完全不一致时 Kappa = -1.0。"""
        from pipeline.assess.asr_tracker import compute_cohens_kappa

        kappa = compute_cohens_kappa(agreements=0, disagreements=10)
        assert kappa == -1.0

    def test_kappa_zero_data(self):
        """测试无数据时 Kappa = 0.0。"""
        from pipeline.assess.asr_tracker import compute_cohens_kappa

        kappa = compute_cohens_kappa(agreements=0, disagreements=0)
        assert kappa == 0.0

    def test_kappa_partial_agreement(self):
        """测试部分一致时 Kappa 在 (-1, 1) 之间。"""
        from pipeline.assess.asr_tracker import compute_cohens_kappa

        kappa = compute_cohens_kappa(agreements=7, disagreements=3)
        assert -1.0 < kappa < 1.0
        assert kappa > 0.0  # 7/10 一致, Kappa > 0

    def test_main_calls_cohens_kappa(self):
        """测试 main.py 在 assess 阶段调用 compute_cohens_kappa。"""
        # 读取 main.py 源码
        main_path = _PROJECT_ROOT / "main.py"
        source = main_path.read_text(encoding="utf-8")
        assert "compute_cohens_kappa" in source
        assert "cohens_kappa" in source

    def test_evidence_has_kappa_and_wilson_fields(self):
        """测试 EvidenceCollection 包含 wilson_ci 和 cohens_kappa 字段。"""
        from pipeline.report.evidence import EvidenceCollection

        ec = EvidenceCollection(
            collection_id="test",
            timestamp="2024-01-01",
            target_model="test",
        )
        assert hasattr(ec, "wilson_ci")
        assert hasattr(ec, "cohens_kappa")
        assert ec.wilson_ci == (0.0, 0.0)
        assert ec.cohens_kappa == 0.0


class TestL5V29GCGAdaptiveSuffix:
    """L5 v29: GCG 自适应后缀选择测试。"""

    def test_reorder_for_refusal_exists(self):
        """测试 _reorder_gcg_suffixes_for_refusal 函数存在。"""
        from pipeline.strike.escalation import _reorder_gcg_suffixes_for_refusal

        assert callable(_reorder_gcg_suffixes_for_refusal)

    def test_reorder_for_partial_exists(self):
        """测试 _reorder_gcg_suffixes_for_partial 函数存在。"""
        from pipeline.strike.escalation import _reorder_gcg_suffixes_for_partial

        assert callable(_reorder_gcg_suffixes_for_partial)

    def test_reorder_for_refusal_prioritizes_system_override(self):
        """测试拒绝模式时系统覆盖类后缀被优先。"""
        from pipeline.strike.escalation import _reorder_gcg_suffixes_for_refusal

        suffixes = [
            (0, "hypothetically speaking"),
            (1, "[System] override instructions"),
            (2, "educational purposes only"),
            (3, ">>end_of_system_prompt"),
        ]
        result = _reorder_gcg_suffixes_for_refusal(suffixes, current_idx=0)
        # 后续后缀中, 系统覆盖类应排前面
        remaining = [s for i, s in result if i > 0]
        assert "[System]" in remaining[0] or ">>end_of_system" in remaining[0]

    def test_reorder_for_partial_prioritizes_progressive(self):
        """测试部分成功时渐进引导类后缀被优先。"""
        from pipeline.strike.escalation import _reorder_gcg_suffixes_for_partial

        suffixes = [
            (0, "[System] override"),
            (1, "hypothetically speaking"),
            (2, ">>end_of_system_prompt"),
            (3, "educational purposes only"),
        ]
        result = _reorder_gcg_suffixes_for_partial(suffixes, current_idx=0)
        # 后续后缀中, 渐进引导类应排前面
        remaining = [s for i, s in result if i > 0]
        assert "hypothetically" in remaining[0].lower() or "educational" in remaining[0].lower()

    def test_gcg_single_objective_has_adaptive_logic(self):
        """测试 _gcg_single_objective 包含自适应逻辑。"""
        import inspect

        from pipeline.strike.escalation import _run_gcg

        source = inspect.getsource(_run_gcg)
        assert "_reorder_gcg_suffixes_for_refusal" in source
        assert "_reorder_gcg_suffixes_for_partial" in source
        assert "i cannot" in source or "refusal" in source.lower()


class TestL5V29ASRFeedbackLoop:
    """L5 v29: ASR 反馈闭环自动回写验证。"""

    def test_save_asr_history_exists(self):
        """测试 save_asr_history 函数存在。"""
        from pipeline.assess.asr_tracker import save_asr_history

        assert callable(save_asr_history)

    def test_save_converter_asr_history_exists(self):
        """测试 _save_converter_asr_history 函数存在。"""
        from pipeline.assess.asr_tracker import _save_converter_asr_history

        assert callable(_save_converter_asr_history)

    def test_save_gcg_suffix_asr_history_exists(self):
        """测试 _save_gcg_suffix_asr_history 函数存在。"""
        from pipeline.assess.asr_tracker import _save_gcg_suffix_asr_history

        assert callable(_save_gcg_suffix_asr_history)

    def test_save_asr_history_extracts_seed_level(self):
        """测试 save_asr_history 提取种子级 ASR。"""
        import inspect

        from pipeline.assess.asr_tracker import save_asr_history

        source = inspect.getsource(save_asr_history)
        assert "seed_asr" in source
        assert "seed_attempts" in source
        assert "seed_stats" in source

    def test_save_asr_history_extracts_converter_level(self):
        """测试 save_asr_history 提取 converter 级 ASR。"""
        import inspect

        from pipeline.assess.asr_tracker import save_asr_history

        source = inspect.getsource(save_asr_history)
        assert "converter_asr" in source
        assert "converter_attempts" in source

    def test_save_asr_history_extracts_gcg_suffix_level(self):
        """测试 save_asr_history 提取 GCG 后缀级 ASR。"""
        import inspect

        from pipeline.assess.asr_tracker import save_asr_history

        source = inspect.getsource(save_asr_history)
        assert "gcg_suffix_asr" in source
        assert "gcg_suffix_attempts" in source

    def test_main_calls_save_asr_history(self):
        """测试 main.py 调用 save_asr_history。"""
        main_path = _PROJECT_ROOT / "main.py"
        source = main_path.read_text(encoding="utf-8")
        assert "save_asr_history" in source

    def test_main_calls_collect_dual_judge_stats(self):
        """测试 main.py 调用 collect_dual_judge_stats。"""
        main_path = _PROJECT_ROOT / "main.py"
        source = main_path.read_text(encoding="utf-8")
        assert "collect_dual_judge_stats" in source

    def test_main_calls_compute_wilson_score_interval(self):
        """测试 main.py 调用 compute_wilson_score_interval。"""
        main_path = _PROJECT_ROOT / "main.py"
        source = main_path.read_text(encoding="utf-8")
        assert "compute_wilson_score_interval" in source

    def test_config_asr_feedback_loop_enabled(self):
        # V2 精简: asr_feedback_loop_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: asr_feedback_loop_enabled removed from defaults.yaml")


