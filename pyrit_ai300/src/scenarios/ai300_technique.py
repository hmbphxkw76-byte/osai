"""
AI-300 Technique Enum — 对齐 pyrit.scenario.ScenarioTechnique
==============================================================

P1: Technique 注册与发现 — ScenarioTechnique 枚举 + tags 体系

定义 AI-300 考试场景中可用的攻击技术枚举。
每个成员定义为 (value, tags) 元组，tags 用于聚合选择。

对齐 PyRIT 1.0.0 ScenarioTechnique 体系：
  - ALL 聚合成员（始终存在）
  - 按标签聚合：single_turn / multi_turn / light / encoding
  - default() classmethod 返回默认技术
"""

from pyrit.scenario import ScenarioTechnique


class AI300Technique(ScenarioTechnique):
    """
    AI-300 考试攻击技术枚举。

    覆盖 PyRIT 1.0.0 核心技术目录中的常用攻击技术，
    按考试优先级组织为三级：
      - encoding（编码攻击，快速高成功率）
      - single_turn（单轮攻击，中等成本）
      - multi_turn（多轮攻击，高成本兜底）
    """

    # ── 聚合成员 ──
    ALL = ("all", {"all"})
    DEFAULT = ("default", {"default"})
    SINGLE_TURN = ("single_turn", {"single_turn"})
    MULTI_TURN = ("multi_turn", {"multi_turn"})
    LIGHT = ("light", {"light"})

    # ── 编码攻击（第一优先级：快速高成功率）──
    PROMPT_SENDING = ("prompt_sending", {"single_turn", "default", "light", "encoding"})
    ROT13 = ("rot13", {"single_turn", "encoding"})
    BASE64 = ("base64", {"single_turn", "encoding"})
    CAESAR = ("caesar", {"single_turn", "encoding"})
    BINARY = ("binary", {"single_turn", "encoding"})
    MORSE = ("morse", {"single_turn", "encoding"})
    LEETSPEAK = ("leetspeak", {"single_turn", "encoding"})
    FLIP = ("flip", {"single_turn", "encoding", "light"})
    CHAR_SWAP = ("char_swap", {"single_turn", "encoding"})
    DIACRITIC = ("diacritic", {"single_turn", "encoding"})
    CHARACTER_SPACE = ("character_space", {"single_turn", "encoding"})
    STRING_JOIN = ("string_join", {"single_turn", "encoding"})
    SUFFIX_APPEND = ("suffix_append", {"single_turn", "encoding"})

    # ── 单轮攻击（第二优先级：角色扮演等）──
    ROLE_PLAY_MOVIE_SCRIPT = ("role_play_movie_script", {"single_turn", "light"})
    ROLE_PLAY_PERSUASION = ("role_play_persuasion", {"single_turn", "light"})
    ROLE_PLAY_PERSUASION_WRITTEN = ("role_play_persuasion_written", {"single_turn", "light"})
    ROLE_PLAY_TRIVIA_GAME = ("role_play_trivia_game", {"single_turn", "light"})
    ROLE_PLAY_VIDEO_GAME = ("role_play_video_game", {"single_turn", "light"})
    CRESCENDO_SIMULATED = ("crescendo_simulated", {"single_turn"})
    CRESCENDO_MOVIE_DIRECTOR = ("crescendo_movie_director", {"single_turn"})
    CRESCENDO_HISTORY_LECTURE = ("crescendo_history_lecture", {"single_turn"})
    CRESCENDO_JOURNALIST_INTERVIEW = ("crescendo_journalist_interview", {"single_turn"})
    CONTEXT_COMPLIANCE = ("context_compliance", {"single_turn", "light"})
    MANY_SHOT = ("many_shot", {"multi_turn", "light"})
    SKELETON_KEY = ("skeleton_key", {"single_turn"})

    # ── 多轮攻击（第三优先级：兜底方案）──
    RED_TEAMING = ("red_teaming", {"multi_turn", "light"})
    CRESCENDO = ("crescendo", {"multi_turn"})
    TAP = ("tap", {"multi_turn"})
    PAIR = ("pair", {"multi_turn"})
    TREE_OF_ATTACKS_PRUNED = ("tree_of_attacks_pruned", {"multi_turn"})

    @classmethod
    def default(cls) -> "AI300Technique":
        """默认技术：DEFAULT 聚合（展开为 prompt_sending + 编码攻击）"""
        return cls.DEFAULT

    @classmethod
    def get_aggregate_tags(cls) -> set[str]:
        """返回聚合标签集合"""
        return {"all", "default", "single_turn", "multi_turn", "light", "encoding"}


class AI300EncodingTechnique(ScenarioTechnique):
    """
    编码攻击专用技术枚举 — 对齐 garak.encoding Scenario

    用于快速编码攻击场景，覆盖 17 种编码方案。
    适用于 AI-300 考试中目标模型对编码解码防御薄弱的情况。
    """

    ALL = ("all", {"all"})

    # ── 常用编码（考试高成功率）──
    ROT13 = ("rot13", {"encoding", "common"})
    BASE64 = ("base64", {"encoding", "common"})
    CAESAR = ("caesar", {"encoding", "common"})
    BINARY = ("binary", {"encoding", "common"})
    MORSE = ("morse", {"encoding", "common"})
    LEETSPEAK = ("leetspeak", {"encoding", "common"})
    FLIP = ("flip", {"encoding", "common"})
    CHAR_SWAP = ("char_swap", {"encoding"})
    DIACRITIC = ("diacritic", {"encoding"})
    CHARACTER_SPACE = ("character_space", {"encoding"})
    STRING_JOIN = ("string_join", {"encoding"})
    SUFFIX_APPEND = ("suffix_append", {"encoding"})
    ATBASH = ("atbash", {"encoding"})
    MORSE_CODE = ("morse_code", {"encoding"})
    NATO = ("nato", {"encoding"})
    ASCII_SMUGGLER = ("ascii_smuggler", {"encoding"})
    URL = ("url", {"encoding"})

    @classmethod
    def default(cls) -> "AI300EncodingTechnique":
        return cls.ALL
