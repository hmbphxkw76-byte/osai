# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AttackResultAnalyzer 单元测试 — Path 4/5 技术名提取.

测试覆盖:
- Path 4: error_message 正则提取策略类名 (API 超时/错误回退)
- Path 5: attribution_data.parent_eval_hash 关联查询 (eval_hash_map 回退)
- build_eval_hash_map() 两遍遍历映射构建
- extract_technique_name_optional() Path 4/5 一致性
"""

from __future__ import annotations

from unittest.mock import MagicMock

from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer

# ============================================================
# Path 4: error_message 正则提取策略类名
# ============================================================


class TestExtractTechniqueFromErrorMessage:
    """Path 4: extract_technique_name() 从 error_message 正则提取策略类名。

    适用场景: 攻击因 API 超时/限速失败, atomic_attack_identifier 为 NULL,
    但 error_message 含 "Strategy execution failed for ... in {ClassName}:"
    """

    def test_prompt_sending_from_error_message(self) -> None:
        """error_message 含 PromptSendingAttack 类名时提取为 prompt_sending。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": (
                "Strategy execution failed for objective_target in PromptSendingAttack: Error sending prompt"
            ),
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "prompt_sending"

    def test_red_teaming_from_error_message(self) -> None:
        """error_message 含 RedTeamingAttack 类名时提取为 red_teaming。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in RedTeamingAttack: ReadTimeout",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "red_teaming"

    def test_many_shot_from_error_message(self) -> None:
        """error_message 含 ManyShotJailbreakAttack 类名时提取为 many_shot。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in ManyShotJailbreakAttack: timeout",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "many_shot"

    def test_no_class_name_in_error_message_returns_unknown(self) -> None:
        """error_message 不含策略类名时回退到 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Error sending prompt with conversation ID: test-123",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "unknown"

    def test_none_error_message_returns_unknown(self) -> None:
        """error_message 为 None 时回退到 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "unknown"

    def test_empty_error_message_returns_unknown(self) -> None:
        """error_message 为空字符串时回退到 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "unknown"

    def test_path_4_unmapped_class_name_keeps_original(self) -> None:
        """error_message 含未映射的类名时保留原始 class_name。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in SomeNewAttack: error",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "SomeNewAttack"


# ============================================================
# Path 5: eval_hash 关联查询
# ============================================================


class TestExtractTechniqueFromEvalHash:
    """Path 5: extract_technique_name() 通过 attribution_data.parent_eval_hash 关联查询技术名。

    适用场景: 攻击因 API 超时/错误失败, atomic_attack_identifier 为 NULL,
    但 attribution_data.parent_eval_hash 可关联到同批次已知结果的技术名。
    """

    def test_path_5_resolves_unknown_via_parent_eval_hash(self) -> None:
        """parent_eval_hash 在映射中时返回对应技术名。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Error sending prompt with conversation ID: test-123",
            "attribution_data": {
                "parent_collection": "baseline",
                "parent_eval_hash": "abc123def456",
            },
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"abc123def456": "prompt_sending"}
        result = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map=eval_hash_map)
        assert result == "prompt_sending"

    def test_path_5_resolves_many_shot(self) -> None:
        """parent_eval_hash 映射到 many_shot 技术时正确返回。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
            "attribution_data": {
                "parent_collection": "enhanced",
                "parent_eval_hash": "hash_many_shot_789",
            },
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"hash_many_shot_789": "many_shot"}
        result = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map=eval_hash_map)
        assert result == "many_shot"

    def test_path_5_not_in_map_returns_unknown(self) -> None:
        """parent_eval_hash 不在映射中时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Error sending prompt with conversation ID: test-456",
            "attribution_data": {
                "parent_collection": "baseline",
                "parent_eval_hash": "unknown_hash_999",
            },
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"abc123def456": "prompt_sending"}
        result = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map=eval_hash_map)
        assert result == "unknown"

    def test_path_5_no_attribution_data_returns_unknown(self) -> None:
        """attribution_data 为 None 时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
            "attribution_data": None,
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"abc123": "prompt_sending"}
        result = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map=eval_hash_map)
        assert result == "unknown"

    def test_path_5_no_eval_hash_map_returns_unknown(self) -> None:
        """eval_hash_map 为 None 时跳过路径 5, 返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
            "attribution_data": {"parent_eval_hash": "abc123"},
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "unknown"

    def test_path_5_empty_eval_hash_map_returns_unknown(self) -> None:
        """eval_hash_map 为空字典时跳过路径 5。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
            "attribution_data": {"parent_eval_hash": "abc123"},
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map={})
        assert result == "unknown"

    def test_path_5_attribution_data_not_dict_returns_unknown(self) -> None:
        """attribution_data 不是 dict 类型时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
            "attribution_data": "not_a_dict",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"abc123": "prompt_sending"}
        result = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map=eval_hash_map)
        assert result == "unknown"

    def test_path_5_parent_eval_hash_not_string_returns_unknown(self) -> None:
        """parent_eval_hash 不是字符串时返回 unknown。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
            "attribution_data": {"parent_eval_hash": 12345},
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"12345": "prompt_sending"}
        result = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map=eval_hash_map)
        assert result == "unknown"


# ============================================================
# Path 4 + Path 5 优先级测试
# ============================================================


class TestPath4PrecedenceOverPath5:
    """Path 4 (error_message) 优先于 Path 5 (eval_hash) — 更精确。

    Path 4 从 error_message 提取实际策略类名, 比 Path 5 的 parent_eval_hash
    关联查询更精确 (parent_eval_hash 指向父集合, 非具体技术)。
    """

    def test_path_4_takes_precedence_over_path_5(self) -> None:
        """Path 4 提取的类名优先于 Path 5 的 eval_hash 映射。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in RedTeamingAttack: timeout",
            "attribution_data": {"parent_eval_hash": "hash_prompt_sending"},
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"hash_prompt_sending": "prompt_sending"}
        result = AttackResultAnalyzer.extract_technique_name(ar, eval_hash_map=eval_hash_map)
        # Path 4 应优先返回 red_teaming, 而非 Path 5 的 prompt_sending
        assert result == "red_teaming"


# ============================================================
# build_eval_hash_map 测试
# ============================================================


class TestBuildEvalHashMap:
    """build_eval_hash_map() 从 AttackResult 列表构建 eval_hash → technique 映射。"""

    def test_build_map_with_known_results(self) -> None:
        """有 atomic_attack_identifier 的结果正确构建映射。"""
        # 模拟已知结果 (many_shot)
        ar1 = MagicMock()
        mock_id1 = MagicMock()
        mock_id1.name = None
        mock_id1.class_name = "ManyShotJailbreakAttack"
        mock_id1.children = {}
        ar1.get_attack_strategy_identifier = MagicMock(return_value=mock_id1)
        ar1.__dict__.update({
            "atomic_attack_identifier": MagicMock(eval_hash="hash_many_shot_123"),
            "error_message": None,
        })

        # 模拟已知结果 (prompt_sending)
        ar2 = MagicMock()
        mock_id2 = MagicMock()
        mock_id2.name = None
        mock_id2.class_name = "PromptSendingAttack"
        mock_id2.children = {}
        ar2.get_attack_strategy_identifier = MagicMock(return_value=mock_id2)
        ar2.__dict__.update({
            "atomic_attack_identifier": MagicMock(eval_hash="hash_prompt_sending_456"),
            "error_message": None,
        })

        result = AttackResultAnalyzer.build_eval_hash_map([ar1, ar2])
        assert result["hash_many_shot_123"] == "many_shot"
        assert result["hash_prompt_sending_456"] == "prompt_sending"

    def test_build_map_skips_unknown_results(self) -> None:
        """技术名为 unknown 的结果不加入映射。"""
        ar = MagicMock()
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "error_message": "Error sending prompt",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.build_eval_hash_map([ar])
        assert len(result) == 0

    def test_build_map_skips_null_aai(self) -> None:
        """atomic_attack_identifier 为 None 的结果不加入映射。"""
        ar = MagicMock()
        mock_id = MagicMock()
        mock_id.name = "prompt_sending"
        mock_id.class_name = None
        mock_id.children = {}
        ar.get_attack_strategy_identifier = MagicMock(return_value=mock_id)
        ar.__dict__.update({
            "atomic_attack_identifier": None,
            "error_message": None,
        })

        result = AttackResultAnalyzer.build_eval_hash_map([ar])
        assert len(result) == 0

    def test_build_map_deduplicates(self) -> None:
        """相同 eval_hash 的结果不重复添加。"""
        mock_id = MagicMock()
        mock_id.name = "prompt_sending"
        mock_id.class_name = None
        mock_id.children = {}
        aai = MagicMock(eval_hash="same_hash_789")

        ar1 = MagicMock()
        ar1.get_attack_strategy_identifier = MagicMock(return_value=mock_id)
        ar1.__dict__.update({"atomic_attack_identifier": aai, "error_message": None})

        ar2 = MagicMock()
        ar2.get_attack_strategy_identifier = MagicMock(return_value=mock_id)
        ar2.__dict__.update({"atomic_attack_identifier": aai, "error_message": None})

        result = AttackResultAnalyzer.build_eval_hash_map([ar1, ar2])
        assert len(result) == 1
        assert result["same_hash_789"] == "prompt_sending"

    def test_build_map_empty_list(self) -> None:
        """空列表返回空映射。"""
        result = AttackResultAnalyzer.build_eval_hash_map([])
        assert len(result) == 0


# ============================================================
# extract_technique_name_optional Path 4/5 一致性测试
# ============================================================


class TestExtractTechniqueNameOptionalPath4Path5:
    """extract_technique_name_optional() Path 4/5 与 extract_technique_name() 一致。"""

    def test_optional_path_4_returns_technique(self) -> None:
        """Path 4 在 optional 版本中同样工作。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": "Strategy execution failed for objective_target in PromptSendingAttack: error",
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name_optional(ar)
        assert result == "prompt_sending"

    def test_optional_path_5_returns_technique(self) -> None:
        """Path 5 在 optional 版本中同样工作。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
            "attribution_data": {"parent_eval_hash": "hash_abc"},
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        eval_hash_map = {"hash_abc": "many_shot"}
        result = AttackResultAnalyzer.extract_technique_name_optional(ar, eval_hash_map=eval_hash_map)
        assert result == "many_shot"

    def test_optional_all_paths_fail_returns_none(self) -> None:
        """所有路径都失败时返回 None (而非 "unknown")。"""
        ar = MagicMock()
        ar.__dict__.update({
            "error_message": None,
            "attribution_data": None,
        })
        ar.get_attack_strategy_identifier = MagicMock(return_value=None)

        result = AttackResultAnalyzer.extract_technique_name_optional(ar)
        assert result is None
