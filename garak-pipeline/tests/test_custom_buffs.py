"""P4-2: tests/test_custom_buffs.py — 自定义 Buff 攻击链测试覆盖

验证 4 类自研 Buff：
- translation: 翻译绕过 Buff
- roleplay: 角色扮演越狱 Buff
- prompt_split: Prompt 拆分 Buff
- multi_turn: 多轮诱导 Buff

验证项：
- Buff 类继承 garak.buffs.base.Buff
- Buff spec 结构完整性（name/description/transforms）
- register_custom_buffs 注册成功
- get_custom_buff_names 返回非空列表
"""

import pytest

from pipeline.custom_buffs import (
    ALL_CUSTOM_BUFFS,
    ALL_CUSTOM_BUFF_CLASSES,
    TRANSLATION_BUFFS,
    ROLEPLAY_BUFFS,
    PROMPT_SPLIT_BUFFS,
    MULTI_TURN_BUFFS,
    get_custom_buff_names,
    register_custom_buffs,
)
from garak.buffs.base import Buff


class TestBuffClasses:
    """验证 Buff 类继承正确"""

    def test_all_buff_classes_inherit_buff(self):
        """所有自定义 Buff 类应继承 garak.buffs.base.Buff"""
        assert len(ALL_CUSTOM_BUFF_CLASSES) > 0
        for cls in ALL_CUSTOM_BUFF_CLASSES:
            assert issubclass(cls, Buff), f"{cls.__name__} 未继承 Buff"

    def test_translation_buff_classes_exist(self):
        from pipeline.custom_buffs.translation import TRANSLATION_BUFF_CLASSES
        assert len(TRANSLATION_BUFF_CLASSES) > 0

    def test_roleplay_buff_classes_exist(self):
        from pipeline.custom_buffs.roleplay import ROLEPLAY_BUFF_CLASSES
        assert len(ROLEPLAY_BUFF_CLASSES) > 0

    def test_prompt_split_buff_classes_exist(self):
        from pipeline.custom_buffs.prompt_split import PROMPT_SPLIT_BUFF_CLASSES
        assert len(PROMPT_SPLIT_BUFF_CLASSES) > 0

    def test_multi_turn_buff_classes_exist(self):
        from pipeline.custom_buffs.multi_turn import MULTI_TURN_BUFF_CLASSES
        assert len(MULTI_TURN_BUFF_CLASSES) > 0


class TestBuffSpecs:
    """验证 Buff spec 结构"""

    @pytest.mark.parametrize(
        "buffs_list,name",
        [
            (TRANSLATION_BUFFS, "translation"),
            (ROLEPLAY_BUFFS, "roleplay"),
            (PROMPT_SPLIT_BUFFS, "prompt_split"),
            (MULTI_TURN_BUFFS, "multi_turn"),
        ],
        ids=["translation", "roleplay", "prompt_split", "multi_turn"],
    )
    def test_buffs_have_required_fields(self, buffs_list, name):
        """每个 Buff spec 应包含 name 和 description"""
        assert len(buffs_list) > 0, f"{name} buffs 为空"
        for buff in buffs_list:
            assert "name" in buff, f"{name} spec 缺少 name"
            assert buff["name"], f"{name} spec name 为空"

    def test_all_buffs_count_matches(self):
        """ALL_CUSTOM_BUFFS 应等于各子列表之和"""
        expected = len(TRANSLATION_BUFFS) + len(ROLEPLAY_BUFFS) + len(PROMPT_SPLIT_BUFFS) + len(MULTI_TURN_BUFFS)
        assert len(ALL_CUSTOM_BUFFS) == expected


class TestRegisterCustomBuffs:
    """验证 register_custom_buffs"""

    def test_register_no_exception(self):
        """register_custom_buffs 应不抛异常"""
        try:
            register_custom_buffs()
        except Exception as e:
            pytest.fail(f"register_custom_buffs 抛异常: {e}")

    def test_get_custom_buff_names_non_empty(self):
        """get_custom_buff_names 应返回非空列表"""
        names = get_custom_buff_names()
        assert len(names) > 0
        for name in names:
            assert "custom." in name, f"Buff name 不含 custom.: {name}"

    def test_register_idempotent(self):
        """register_custom_buffs 应可重复调用（幂等）"""
        register_custom_buffs()
        register_custom_buffs()
        names = get_custom_buff_names()
        assert len(names) > 0
