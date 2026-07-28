"""
Roadmap Implementation Tests
============================

验证 P0-P3 路线图所有改动的正确性。

测试覆盖：
- P0-1: 模拟对话生成工具函数 + 预计算/重放流程
- P0-2: AttackPreparator SeedSimulatedConversation 检测
- P1-1: 自定义 _RemoteDatasetLoader 子类自动注册
- P1-2: SeedPromptAdapter 多模态种子处理
- P2-1: SeedGroupBuilder 多模态/system 角色支持
- P2-2: YAML 数据角色交替修正验证
- P3: 原生管道 + AttackPlan 评估工具
"""

import asyncio
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from pyrit.models import (
    AttackSeedGroup,
    SeedGroup,
    SeedObjective,
    SeedPrompt,
    SeedSimulatedConversation,
    SeedDataset,
)


# ============================================================
# P0-1: 模拟对话生成工具函数
# ============================================================


class TestSimulatedConversationP0:
    """P0-1: 模拟对话生成与重放"""

    def test_get_preset_combos(self):
        """测试预置组合可用性"""
        from src.payloads.simulated_conversation import get_preset_combos

        combos = get_preset_combos()
        assert "red_team_direct" in combos
        assert "red_team_no_next" in combos
        assert "red_team_role_play" in combos
        assert "crescendo_simulated" in combos
        assert "context_compliance" in combos

    def test_get_preset(self):
        """测试获取指定预置"""
        from src.payloads.simulated_conversation import get_preset

        combo = get_preset("red_team_direct")
        assert combo["adversarial_chat_system_prompt_path"] is not None
        assert combo["simulated_target_system_prompt_path"] is not None
        assert combo["next_message_system_prompt_path"] is not None

    def test_get_preset_unknown_raises(self):
        """测试未知预置名称抛出异常"""
        from src.payloads.simulated_conversation import get_preset

        with pytest.raises(ValueError, match="Unknown preset"):
            get_preset("nonexistent_preset")

    def test_create_simulated_conversation_seed(self):
        """测试创建 SeedSimulatedConversation 配置种子"""
        from src.payloads.simulated_conversation import create_simulated_conversation_seed

        seed = create_simulated_conversation_seed(
            objective="Test objective",
            num_turns=2,
            preset="red_team_direct",
        )

        assert isinstance(seed, SeedSimulatedConversation)
        assert seed.num_turns == 2
        assert seed.sequence == 0
        assert seed.adversarial_chat_system_prompt_path is not None

    def test_create_attack_with_simulated_conversation(self):
        """测试一键创建带模拟对话的 AttackSeedGroup"""
        from src.payloads.simulated_conversation import create_attack_with_simulated_conversation

        group = create_attack_with_simulated_conversation(
            objective="Extract system prompt",
            num_turns=3,
            preset="red_team_direct",
        )

        assert isinstance(group, AttackSeedGroup)
        assert group.has_simulated_conversation is True
        assert group.objective is not None
        assert group.objective.value == "Extract system prompt"

    def test_inject_simulated_conversation_into_group(self):
        """测试将模拟对话注入现有 SeedGroup"""
        from src.payloads.simulated_conversation import inject_simulated_conversation_into_group

        # 创建一个简单的 SeedGroup
        sg = SeedGroup(seeds=[
            SeedObjective(value="Test objective"),
            SeedPrompt(value="Hello", sequence=10, role="user"),
        ])

        result = inject_simulated_conversation_into_group(
            sg,
            num_turns=2,
            sequence=20,  # 避免与现有 sequence=10 冲突
            preset="red_team_direct",
        )

        assert isinstance(result, AttackSeedGroup)
        assert result.has_simulated_conversation is True

    def test_generate_simulated_conversation_missing_chat_raises(self):
        """测试缺少 adversarial_chat 抛出异常"""
        from src.payloads.simulated_conversation import generate_simulated_conversation_async

        with pytest.raises(ValueError, match="adversarial_chat is required"):
            asyncio.run(
                generate_simulated_conversation_async(
                    objective="test",
                    adversarial_chat=None,
                    objective_scorer=MagicMock(),
                )
            )

    def test_generate_simulated_conversation_missing_scorer_raises(self):
        """测试缺少 objective_scorer 抛出异常"""
        from src.payloads.simulated_conversation import generate_simulated_conversation_async

        with pytest.raises(ValueError, match="objective_scorer is required"):
            asyncio.run(
                generate_simulated_conversation_async(
                    objective="test",
                    adversarial_chat=MagicMock(),
                    objective_scorer=None,
                )
            )


# ============================================================
# P0-2: AttackPreparator SeedSimulatedConversation 检测
# ============================================================


class TestAttackPreparatorP0:
    """P0-2: AttackPreparator 集成 SeedSimulatedConversation"""

    def test_prepare_detects_simulated_conversation_without_chat(self):
        """测试 prepare() 检测 SeedSimulatedConversation 但缺少 adversarial_chat"""
        from src.payloads.attack_preparator import AttackPreparator

        # 创建带 SeedSimulatedConversation 的 SeedGroup
        sg = SeedGroup(seeds=[
            SeedObjective(value="Test"),
            SeedSimulatedConversation(
                num_turns=2,
                sequence=0,
                adversarial_chat_system_prompt_path=Path("dummy.yaml"),
            ),
        ])

        with pytest.raises(ValueError, match="adversarial_chat is None"):
            asyncio.run(
                AttackPreparator.prepare(sg)
            )

    def test_prepare_detects_simulated_conversation_without_scorer(self):
        """测试 prepare() 检测 SeedSimulatedConversation 但缺少 objective_scorer"""
        from src.payloads.attack_preparator import AttackPreparator

        sg = SeedGroup(seeds=[
            SeedObjective(value="Test"),
            SeedSimulatedConversation(
                num_turns=2,
                sequence=0,
                adversarial_chat_system_prompt_path=Path("dummy.yaml"),
            ),
        ])

        with pytest.raises(ValueError, match="objective_scorer is None"):
            asyncio.run(
                AttackPreparator.prepare(sg, adversarial_chat=MagicMock())
            )

    def test_prepare_with_simulated_conversation_succeeds(self):
        """测试 prepare() 成功处理带 SeedSimulatedConversation 的种子组"""
        from src.payloads.attack_preparator import AttackPreparator

        sg = SeedGroup(seeds=[
            SeedObjective(value="Test objective"),
            SeedSimulatedConversation(
                num_turns=2,
                sequence=0,
                adversarial_chat_system_prompt_path=Path("dummy.yaml"),
            ),
        ])

        result = asyncio.run(
            AttackPreparator.prepare(
                sg,
                adversarial_chat=MagicMock(),
                objective_scorer=MagicMock(),
            )
        )

        assert isinstance(result, AttackSeedGroup)
        assert result.has_simulated_conversation is True

    def test_select_attack_technique_with_simulated_conversation(self):
        """测试 select_attack_technique 对模拟对话返回 red_teaming"""
        from src.payloads.attack_preparator import AttackPreparator

        # 创建带 SeedSimulatedConversation 的 AttackSeedGroup
        ag = AttackSeedGroup(seeds=[
            SeedObjective(value="Test"),
            SeedSimulatedConversation(
                num_turns=2,
                sequence=0,
                adversarial_chat_system_prompt_path=Path("dummy.yaml"),
            ),
        ])

        technique = AttackPreparator.select_attack_technique(ag)
        assert technique == "red_teaming"


# ============================================================
# P1-1: 自定义 _RemoteDatasetLoader 子类
# ============================================================


class TestRemoteLoadersP1:
    """P1-1: 项目自定义远程数据集加载器"""

    def test_ai300_owasp_custom_dataset_registered(self):
        """测试 AI300OWASPCustomDataset 自动注册"""
        # 导入模块以触发注册
        import src.payloads.remote_loaders  # noqa: F401
        from pyrit.datasets import SeedDatasetProvider

        # 检查注册
        assert "AI300OWASPCustomDataset" in SeedDatasetProvider._registry

    def test_ai300_agentic_threats_dataset_registered(self):
        """测试 AI300AgenticThreatsDataset 自动注册"""
        import src.payloads.remote_loaders  # noqa: F401
        from pyrit.datasets import SeedDatasetProvider

        assert "AI300AgenticThreatsDataset" in SeedDatasetProvider._registry

    def test_ai300_exam_sim_dataset_registered(self):
        """测试 AI300ExamSimDataset 自动注册"""
        import src.payloads.remote_loaders  # noqa: F401
        from pyrit.datasets import SeedDatasetProvider

        assert "AI300ExamSimDataset" in SeedDatasetProvider._registry

    def test_dataset_name_property(self):
        """测试 dataset_name 属性"""
        from src.payloads.remote_loaders import (
            AI300OWASPCustomDataset,
            AI300AgenticThreatsDataset,
            AI300ExamSimDataset,
        )

        assert AI300OWASPCustomDataset().dataset_name == "ai300_owasp_custom"
        assert AI300AgenticThreatsDataset().dataset_name == "ai300_agentic_threats"
        assert AI300ExamSimDataset().dataset_name == "ai300_exam_sim"

    def test_get_project_dataset_names(self):
        """测试获取项目数据集名称列表"""
        from src.payloads.remote_loaders import get_project_dataset_names

        names = get_project_dataset_names()
        assert "ai300_owasp_custom" in names
        assert "ai300_agentic_threats" in names
        assert "ai300_exam_sim" in names

    def test_is_project_dataset_registered(self):
        """测试检查数据集注册状态"""
        import src.payloads.remote_loaders  # noqa: F401
        from src.payloads.remote_loaders import is_project_dataset_registered

        assert is_project_dataset_registered("ai300_owasp_custom") is True
        assert is_project_dataset_registered("nonexistent_dataset") is False


# ============================================================
# P1-2: SeedPromptAdapter 多模态增强
# ============================================================


class TestSeedPromptAdapterMultimodalP1:
    """P1-2: SeedPromptAdapter 多模态种子处理"""

    def test_extract_multimodal_pieces_image(self):
        """测试提取 image_path 多模态片段"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        prompts = [
            SeedPrompt(value="/path/to/image.png", sequence=0, role="user", data_type="image_path"),
            SeedPrompt(value="Describe this image", sequence=1, role="user", data_type="text"),
        ]

        pieces = SeedPromptAdapter._extract_multimodal_pieces(prompts)
        assert len(pieces) == 1
        assert pieces[0]["data_type"] == "image_path"
        assert pieces[0]["value"] == "/path/to/image.png"

    def test_extract_multimodal_pieces_audio(self):
        """测试提取 audio_path 多模态片段"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        prompts = [
            SeedPrompt(value="/path/to/audio.wav", sequence=0, role="user", data_type="audio_path"),
        ]

        pieces = SeedPromptAdapter._extract_multimodal_pieces(prompts)
        assert len(pieces) == 1
        assert pieces[0]["data_type"] == "audio_path"

    def test_extract_multimodal_pieces_text_only(self):
        """测试纯文本种子不返回多模态片段"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        prompts = [
            SeedPrompt(value="Hello", sequence=0, role="user", data_type="text"),
            SeedPrompt(value="World", sequence=1, role="user", data_type="text"),
        ]

        pieces = SeedPromptAdapter._extract_multimodal_pieces(prompts)
        assert len(pieces) == 0

    def test_seed_group_to_item_with_multimodal(self):
        """测试包含多模态种子的 SeedGroup 转换"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        sg = SeedGroup(seeds=[
            SeedPrompt(value="/path/to/image.png", sequence=0, role="user", data_type="image_path"),
        ])

        item = SeedPromptAdapter._seed_group_to_item(sg, owasp_id=None, dataset_name="test")
        assert item is not None
        assert item.metadata.get("has_multimodal") is True
        assert "multimodal" in item.metadata
        assert item.metadata["multimodal"][0]["data_type"] == "image_path"


# ============================================================
# P2-1: SeedGroupBuilder 多模态/system 支持
# ============================================================


class TestSeedGroupBuilderMultimodalP2:
    """P2-1: SeedGroupBuilder 多模态/system 角色支持"""

    def test_build_with_multimodal_metadata(self):
        """测试构建带多模态 metadata 的 AttackSeedGroup"""
        from src.executor.attack.component.seed_group_builder import SeedGroupBuilder
        from src.payloads.models import AttackPlan, PromptItem, AttackMode

        item = PromptItem(
            id="test_multimodal",
            objective="Analyze this image",
            attack_mode=AttackMode.MULTI_TURN,
            multi_turn_steps=["What is in this image?", "Describe the security implications"],
            metadata={
                "multimodal": [
                    {"data_type": "image_path", "value": "/path/to/image.png", "sequence": 0, "role": "user"},
                ],
            },
        )
        plan = AttackPlan(
            plan_id="test_001",
            prompt_item=item,
            attack_technique="prompt_sending",
        )

        group = SeedGroupBuilder.build(plan, "Analyze this image")
        assert isinstance(group, AttackSeedGroup)

        # Check that the first prompt has image_path data_type
        prompts = list(group.prompts)
        assert len(prompts) >= 2
        assert prompts[0].data_type == "image_path"

    def test_build_with_system_message(self):
        """测试构建带 system 角色消息的 AttackSeedGroup"""
        from src.executor.attack.component.seed_group_builder import SeedGroupBuilder
        from src.payloads.models import AttackPlan, PromptItem, AttackMode

        item = PromptItem(
            id="test_system",
            objective="Test objective",
            attack_mode=AttackMode.MULTI_TURN,
            multi_turn_steps=["Hello", "What can you do?"],
            metadata={
                "system_message": "You are a helpful assistant",
            },
        )
        plan = AttackPlan(
            plan_id="test_002",
            prompt_item=item,
            attack_technique="prompt_sending",
        )

        group = SeedGroupBuilder.build(plan, "Test objective")

        # Check that there's a system role prompt
        prompts = list(group.prompts)
        system_prompts = [p for p in prompts if p.role == "system"]
        assert len(system_prompts) == 1
        assert system_prompts[0].value == "You are a helpful assistant"

    def test_build_with_multimodal_explicit(self):
        """测试 build_with_multimodal 方法"""
        from src.executor.attack.component.seed_group_builder import SeedGroupBuilder
        from src.payloads.models import AttackPlan, PromptItem, AttackMode

        item = PromptItem(
            id="test_mm_explicit",
            objective="Test",
            attack_mode=AttackMode.SINGLE_TURN,
        )
        plan = AttackPlan(
            plan_id="test_003",
            prompt_item=item,
            attack_technique="prompt_sending",
        )

        group = SeedGroupBuilder.build_with_multimodal(
            plan, "Test objective",
            multimodal_pieces=[
                {"data_type": "image_path", "value": "/img.png", "sequence": 0, "role": "user"},
                {"data_type": "text", "value": "Describe", "sequence": 1, "role": "user"},
            ],
        )

        prompts = list(group.prompts)
        assert len(prompts) == 2
        assert prompts[0].data_type == "image_path"
        assert prompts[1].data_type == "text"

    def test_build_from_seed_group(self):
        """测试从现有 AttackSeedGroup 重建"""
        from src.executor.attack.component.seed_group_builder import SeedGroupBuilder

        original = AttackSeedGroup(seeds=[
            SeedObjective(value="Original objective"),
            SeedPrompt(value="Hello", sequence=0, role="user"),
        ])

        rebuilt = SeedGroupBuilder.build_from_seed_group(
            original, objective_override="New objective"
        )

        assert rebuilt.objective.value == "New objective"
        # Check that prompts are preserved
        prompts = list(rebuilt.prompts)
        assert len(prompts) == 1
        assert prompts[0].value == "Hello"


# ============================================================
# P2-2: YAML 数据角色交替修正验证
# ============================================================


class TestYamlRoleAlternationP2:
    """P2-2: YAML 数据角色交替修正"""

    def test_llm02_memory_extraction_has_assistant_role(self):
        """测试 LLM02 多轮组有 assistant 角色"""
        from pyrit.models import SeedDataset

        ds = SeedDataset.from_yaml_file("data/owasp/llm/llm02/memory_extraction.yaml")

        # 找到多轮组
        multi_turn_groups = [
            sg for sg in ds.seed_groups if sg.objective is not None
        ]
        assert len(multi_turn_groups) > 0

        for sg in multi_turn_groups:
            prompts = list(sg.prompts)
            if len(prompts) >= 3:
                roles = [p.role for p in prompts]
                # Should have at least one assistant role
                assert "assistant" in roles, f"Group has no assistant role: {roles}"

    def test_llm07_prompt_leakage_has_assistant_role(self):
        """测试 LLM07 多轮组有 assistant 角色"""
        from pyrit.models import SeedDataset

        ds = SeedDataset.from_yaml_file("data/owasp/llm/llm07/prompt_leakage.yaml")

        multi_turn_groups = [
            sg for sg in ds.seed_groups if sg.objective is not None
        ]
        assert len(multi_turn_groups) > 0

        for sg in multi_turn_groups:
            prompts = list(sg.prompts)
            if len(prompts) >= 3:
                roles = [p.role for p in prompts]
                assert "assistant" in roles, f"Group has no assistant role: {roles}"

    def test_asi01_goal_hijack_has_assistant_role(self):
        """测试 ASI01 多轮组有 assistant 角色"""
        from pyrit.models import SeedDataset

        ds = SeedDataset.from_yaml_file("data/owasp/agentic/asi01/goal_hijack.yaml")

        multi_turn_groups = [
            sg for sg in ds.seed_groups if sg.objective is not None
        ]
        assert len(multi_turn_groups) > 0

        for sg in multi_turn_groups:
            prompts = list(sg.prompts)
            if len(prompts) >= 3:
                roles = [p.role for p in prompts]
                assert "assistant" in roles, f"Group has no assistant role: {roles}"

    def test_multi_turn_group_correct_alternation(self):
        """测试多轮组的角色交替模式正确"""
        from pyrit.models import SeedDataset

        ds = SeedDataset.from_yaml_file("data/owasp/llm/llm02/memory_extraction.yaml")

        for sg in ds.seed_groups:
            if sg.objective is None:
                continue
            prompts = list(sg.prompts)
            if len(prompts) >= 3:
                # Last prompt should be "user" (next_message)
                assert prompts[-1].role == "user"
                # The prompt before last should be "assistant"
                assert prompts[-2].role == "assistant"

    def test_prepended_conversation_extraction(self):
        """测试 prepended_conversation 正确提取"""
        from pyrit.models import SeedDataset

        ds = SeedDataset.from_yaml_file("data/owasp/llm/llm02/memory_extraction.yaml")

        for sg in ds.seed_groups:
            if sg.objective is None:
                continue
            prompts = list(sg.prompts)
            if len(prompts) >= 3:
                # Should have prepended conversation
                assert sg.prepended_conversation is not None
                # Should have next_message
                assert sg.next_message is not None
                # prepended should have at least 2 messages (user + assistant)
                assert len(sg.prepended_conversation) >= 2


# ============================================================
# P3: 原生管道 + AttackPlan 评估
# ============================================================


class TestNativePipelineP3:
    """P3: 原生管道和 AttackPlan 评估"""

    def test_evaluate_attack_plan_necessity_simple(self):
        """测试简单 SeedGroup 不需要 AttackPlan"""
        from src.payloads.native_pipeline import evaluate_attack_plan_necessity

        sg = SeedGroup(seeds=[
            SeedObjective(value="Simple objective"),
            SeedPrompt(value="Hello", sequence=0, role="user"),
        ])

        result = evaluate_attack_plan_necessity(sg)
        assert result["needs_attack_plan"] is False
        assert result["recommended_pipeline"] == "native"

    def test_evaluate_attack_plan_necessity_with_converters(self):
        """测试带 converter_chains 的 SeedGroup 需要 AttackPlan"""
        from src.payloads.native_pipeline import evaluate_attack_plan_necessity

        sg = SeedGroup(seeds=[
            SeedObjective(value="Test"),
            SeedPrompt(
                value="Hello",
                sequence=0,
                role="user",
                metadata={"converter_chains": ["base64", "rot13"]},
            ),
        ])

        result = evaluate_attack_plan_necessity(sg)
        assert result["needs_attack_plan"] is True
        assert result["recommended_pipeline"] == "compat"

    def test_evaluate_attack_plan_necessity_sequential(self):
        """测试 sequential 攻击模式需要 AttackPlan"""
        from src.payloads.native_pipeline import evaluate_attack_plan_necessity

        sg = SeedGroup(seeds=[
            SeedObjective(value="Test"),
            SeedPrompt(
                value="Step 1",
                sequence=0,
                role="user",
                metadata={"attack_mode": "sequential"},
            ),
        ])

        result = evaluate_attack_plan_necessity(sg)
        assert result["needs_attack_plan"] is True

    def test_native_pipeline_executor_init(self):
        """测试 NativePipelineExecutor 初始化"""
        from src.payloads.native_pipeline import NativePipelineExecutor

        pipeline = NativePipelineExecutor()
        assert pipeline is not None
        assert pipeline._executor is not None

    def test_get_native_pipeline_singleton(self):
        """测试 get_native_pipeline 单例"""
        from src.payloads.native_pipeline import get_native_pipeline

        p1 = get_native_pipeline()
        p2 = get_native_pipeline()
        assert p1 is p2

    def test_execute_native_async_import(self):
        """测试 execute_native_async 可导入"""
        from src.payloads.native_pipeline import execute_native_async
        assert callable(execute_native_async)


# ============================================================
# 集成测试：__init__.py 导出验证
# ============================================================


class TestInitExports:
    """验证 __init__.py 正确导出所有新模块"""

    def test_simulated_conversation_exports(self):
        """测试模拟对话模块导出"""
        from src.payloads import (
            generate_simulated_conversation_async,
            precompute_simulated_conversation_async,
            create_simulated_conversation_seed,
            create_attack_with_simulated_conversation,
            inject_simulated_conversation_into_group,
            get_preset,
            get_preset_combos,
        )
        assert callable(generate_simulated_conversation_async)
        assert callable(precompute_simulated_conversation_async)
        assert callable(create_simulated_conversation_seed)
        assert callable(create_attack_with_simulated_conversation)
        assert callable(inject_simulated_conversation_into_group)
        assert callable(get_preset)
        assert callable(get_preset_combos)

    def test_remote_loaders_exports(self):
        """测试远程加载器模块导出"""
        from src.payloads import (
            AI300OWASPCustomDataset,
            AI300AgenticThreatsDataset,
            AI300ExamSimDataset,
            get_project_dataset_names,
            is_project_dataset_registered,
        )
        assert AI300OWASPCustomDataset is not None
        assert AI300AgenticThreatsDataset is not None
        assert AI300ExamSimDataset is not None
        assert callable(get_project_dataset_names)
        assert callable(is_project_dataset_registered)

    def test_native_pipeline_exports(self):
        """测试原生管道模块导出"""
        from src.payloads import (
            NativePipelineExecutor,
            get_native_pipeline,
            execute_native_async,
            evaluate_attack_plan_necessity,
        )
        assert NativePipelineExecutor is not None
        assert callable(get_native_pipeline)
        assert callable(execute_native_async)
        assert callable(evaluate_attack_plan_necessity)


# ============================================================
# L5 Gap Fixes: response_json_schema + CentralMemory bridge + .prompt
# ============================================================


class TestResponseJsonSchemaSupport:
    """P2: response_json_schema / response_json_schema_name 支持"""

    def test_prompt_item_has_response_json_schema_field(self):
        """PromptItem 模型应包含 response_json_schema 字段"""
        from src.payloads.models import PromptItem, AttackMode

        item = PromptItem(
            id="test",
            objective="test objective",
            attack_mode=AttackMode.SINGLE_TURN,
            response_json_schema={"type": "object", "properties": {"x": {"type": "string"}}},
        )
        assert item.response_json_schema is not None
        assert item.response_json_schema["type"] == "object"

    def test_prompt_item_response_json_schema_default_none(self):
        """response_json_schema 默认为 None"""
        from src.payloads.models import PromptItem, AttackMode

        item = PromptItem(
            id="test",
            objective="test",
            attack_mode=AttackMode.SINGLE_TURN,
        )
        assert item.response_json_schema is None

    def test_extract_response_json_schema_from_prompt(self):
        """从 SeedPrompt 提取 response_json_schema"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        schema = {"type": "object", "properties": {"result": {"type": "string"}}}
        prompt = SeedPrompt(
            value="test prompt",
            role="user",
            response_json_schema=schema,
        )
        extracted = SeedPromptAdapter._extract_response_json_schema([prompt])
        assert extracted is not None
        assert extracted == schema

    def test_extract_response_json_schema_from_objective(self):
        """从 SeedObjective 回退提取 response_json_schema (SeedObjective 无此字段，返回 None)"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        objective = SeedObjective(value="test objective")
        extracted = SeedPromptAdapter._extract_response_json_schema([], objective=objective)
        # SeedObjective 没有 response_json_schema 字段
        assert extracted is None

    def test_extract_response_json_schema_none(self):
        """无 schema 时返回 None"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        prompt = SeedPrompt(value="test", role="user")
        extracted = SeedPromptAdapter._extract_response_json_schema([prompt])
        assert extracted is None

    def test_yaml_loads_response_json_schema_inline(self):
        """YAML 内联 response_json_schema 正确加载"""
        ds = SeedDataset.from_yaml_file(
            "data/owasp/llm/llm05/structured_output_extraction.yaml"
        )
        # seed 1 有内联 schema
        prompt_with_schema = ds.seeds[1]
        assert hasattr(prompt_with_schema, "response_json_schema")
        assert prompt_with_schema.response_json_schema is not None
        assert prompt_with_schema.response_json_schema["type"] == "object"

    def test_yaml_loads_response_json_schema_name(self):
        """YAML response_json_schema_name 正确解析为 response_json_schema"""
        ds = SeedDataset.from_yaml_file(
            "data/owasp/llm/llm05/structured_output_extraction.yaml"
        )
        # seed 0 使用 response_json_schema_name: true_false_with_rationale
        prompt_with_name = ds.seeds[0]
        assert prompt_with_name.response_json_schema is not None
        # 解析后应该是 dict
        assert isinstance(prompt_with_name.response_json_schema, dict)

    def test_adapter_propagates_schema_to_prompt_item(self):
        """SeedPromptAdapter 将 response_json_schema 传播到 PromptItem"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        ds = SeedDataset.from_yaml_file(
            "data/owasp/llm/llm05/structured_output_extraction.yaml"
        )
        batches = SeedPromptAdapter.dataset_to_batches(ds)
        assert len(batches) > 0
        batch = batches[0]
        # 至少有一些 prompts 有 schema
        items_with_schema = [p for p in batch.prompts if p.response_json_schema is not None]
        assert len(items_with_schema) > 0

    def test_metadata_has_schema_flag(self):
        """metadata 中设置 has_response_json_schema 标志"""
        from src.payloads.seed_adapter import SeedPromptAdapter

        ds = SeedDataset.from_yaml_file(
            "data/owasp/llm/llm05/structured_output_extraction.yaml"
        )
        batches = SeedPromptAdapter.dataset_to_batches(ds)
        batch = batches[0]
        items_with_flag = [
            p for p in batch.prompts
            if p.metadata.get("has_response_json_schema")
        ]
        assert len(items_with_flag) > 0

    def test_seed_group_builder_propagates_schema(self):
        """SeedGroupBuilder 将 response_json_schema 传播到 SeedPrompt"""
        from src.payloads.models import PromptItem, AttackMode, AttackPlan
        from src.executor.attack.component.seed_group_builder import SeedGroupBuilder

        schema = {"type": "object", "properties": {"result": {"type": "string"}}}
        item = PromptItem(
            id="test",
            objective="test objective",
            attack_mode=AttackMode.SINGLE_TURN,
            multi_turn_steps=["step1", "step2"],
            response_json_schema=schema,
        )
        plan = AttackPlan(
            plan_id="test_plan",
            prompt_item=item,
            attack_technique="prompt_sending",
        )
        seed_group = SeedGroupBuilder.build(plan, "test objective")
        # 找到最后一个 user SeedPrompt（next_message）
        user_prompts = [
            s for s in seed_group.seeds
            if isinstance(s, SeedPrompt) and s.role == "user"
        ]
        assert len(user_prompts) > 0
        last_user = user_prompts[-1]
        assert last_user.response_json_schema is not None
        assert last_user.response_json_schema == schema

    def test_seed_group_builder_no_schema_when_none(self):
        """无 response_json_schema 时不设置"""
        from src.payloads.models import PromptItem, AttackMode, AttackPlan
        from src.executor.attack.component.seed_group_builder import SeedGroupBuilder

        item = PromptItem(
            id="test",
            objective="test objective",
            attack_mode=AttackMode.SINGLE_TURN,
            multi_turn_steps=["step1", "step2"],
        )
        plan = AttackPlan(
            plan_id="test_plan",
            prompt_item=item,
            attack_technique="prompt_sending",
        )
        seed_group = SeedGroupBuilder.build(plan, "test objective")
        user_prompts = [
            s for s in seed_group.seeds
            if isinstance(s, SeedPrompt) and s.role == "user"
        ]
        for p in user_prompts:
            assert p.response_json_schema is None


class TestCentralMemoryBridge:
    """P3: 兼容管道 CentralMemory 桥接"""

    def test_sync_batches_to_memory_async_exported(self):
        """sync_batches_to_memory_async 已导出"""
        from src.payloads import sync_batches_to_memory_async
        assert callable(sync_batches_to_memory_async)

    def test_load_all_payloads_async_has_sync_to_memory_param(self):
        """load_all_payloads_async 支持 sync_to_memory 参数"""
        import inspect
        from src.payloads.source_loader import load_all_payloads_async
        sig = inspect.signature(load_all_payloads_async)
        assert "sync_to_memory" in sig.parameters
        assert sig.parameters["sync_to_memory"].default is False

    def test_load_payloads_deprecation_warning(self):
        """load_payloads 发出 DeprecationWarning"""
        import warnings
        from src.payloads.source_loader import load_payloads

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                load_payloads(owasp_ids=["LLM01"], include_custom=False)
            except Exception:
                pass  # May fail on env, just check warning
            deprecation_warnings = [
                x for x in w if issubclass(x.category, DeprecationWarning)
            ]
            assert len(deprecation_warnings) > 0


class TestPromptExtensionSupport:
    """P4: .prompt 文件扩展名支持"""

    def test_dataset_manager_supports_prompt_glob(self):
        """DatasetManager 源码包含 .prompt glob"""
        import inspect
        from src.payloads.dataset_manager import DatasetManager
        src = inspect.getsource(DatasetManager)
        assert "*.prompt" in src

    def test_source_loader_supports_prompt_glob(self):
        """PayloadSourceLoader 源码包含 .prompt glob"""
        import inspect
        from src.payloads.source_loader import PayloadSourceLoader
        src = inspect.getsource(PayloadSourceLoader)
        assert "*.prompt" in src

    def test_owasp_provider_supports_prompt_glob(self):
        """OwaspLocalDatasetProvider 注册支持 .prompt"""
        import inspect
        from src.payloads.owasp_provider import _register_owasp_datasets
        src = inspect.getsource(_register_owasp_datasets)
        assert "*.prompt" in src
