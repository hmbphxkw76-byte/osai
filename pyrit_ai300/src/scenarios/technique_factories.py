"""
AI-300 Technique Factories — 对齐 pyrit.setup.initializers.techniques
=====================================================================

L5 对齐 PyRIT 1.0.0 原生攻击技术体系。

分组模块（对齐 PyRIT 原生 core.py / extra.py / airt.py）：
  - core: 通用技术（role_play, many_shot, crescendo, red_teaming, tap, flip,
          context_compliance, 编码攻击, multi_prompt_sending, chunked_request）
  - extra: 可选技术（pair, skeleton_key, violent_durian）
  - airt: AIRT 场景专属技术（first_letter, image）

原生设计原则：
  - prompt_sending 不注册为 Factory（由 BASELINE_ATTACK_POLICY 自动发射）
  - default 不是标签（scenario-relative，由 Scenario 声明）
  - core/extra/airt 标签由注册时注入
  - with_simulated_conversation() 是核心技术构造器

P0 (Converter-Aware): 为每个基础攻击技术动态创建 Converter 变体，
使用原生 extra_request_converters 追加 Converter（渐进式升级）。
原生 AdaptiveTechniqueDispatcher 的 FIRST_SUCCESS 自动在首个成功变体处停止。

注册是按名称幂等的，所以可组合：运行多次只添加尚未注册的技术。
"""

import logging
from pathlib import Path
from typing import Any, Dict, List

from pyrit.common.path import (
    DATASETS_PATH,
    EXECUTOR_RED_TEAM_PATH,
    EXECUTOR_SEED_PROMPT_PATH,
    EXECUTOR_SIMULATED_TARGET_PATH,
)
from pyrit.converter import (
    AddImageTextConverter,
    FlipConverter,
    FirstLetterConverter,
    TaskFramingConverter,
)
from pyrit.executor.attack import (
    AttackConverterConfig,
    ChunkedRequestAttack,
    CrescendoAttack,
    ManyShotJailbreakAttack,
    MultiPromptSendingAttack,
    PAIRAttack,
    PrependedConversationConfig,
    PromptSendingAttack,
    RedTeamingAttack,
    SkeletonKeyAttack,
    TreeOfAttacksWithPruningAttack,
)
from pyrit.models import AttackTechniqueSeedGroup, SeedPrompt
from pyrit.prompt_normalizer import ConverterConfiguration
from pyrit.registry import AttackTechniqueRegistry
from pyrit.scenario.core.attack_technique_factory import (
    AttackTechniqueFactory,
    ScorerOverridePolicy,
)

logger = logging.getLogger(__name__)

# AIRT blank image path
_BLANK_IMAGE_PATH = str(DATASETS_PATH / "seed_datasets" / "local" / "examples" / "blank_canvas.png")


# ============================================================
# P0: Converter 变体配置 — 全覆盖 (R1)
# ============================================================

# Converter 变体链 — 从 payload_strategy_matrix.yaml 的 converter_chains 段加载
# 非 LLM 链可在无 converter_target 时创建；LLM 链需 converter_target
#
# modality 字段表示 Converter 链的输出数据类型:
#   "text"  — 文本输出，兼容所有文本 Target
#   "image" — 图片输出 (image_path)，需 Target 支持图片输入
#   "file"  — 文件输出 (file_path)，用于 RAG/Output Handling 文档投递
#
# requires_runtime_params: 链需要运行时参数（如 existing_pdf），
#   无法从 YAML 静态加载，在变体构建时跳过
CONVERTER_VARIANT_CHAINS: Dict[str, Dict[str, Any]] = {
    # ── 非 LLM 链 (text modality) — 高 ASR ──
    "stealth_evasion": {
        "requires_llm": False,
        "priority": 1,
        "modality": "text",
        "description": "Unicode 混淆 + Base64 + 后缀追加",
    },
    "encoding_bypass": {
        "requires_llm": False,
        "priority": 2,
        "modality": "text",
        "description": "Base64 + ROT13 + Caesar 编码绕过",
    },
    "multi_encoding_v2": {
        "requires_llm": False,
        "priority": 1,
        "modality": "text",
        "description": "四层编码: Base64 + ROT13 + Caesar(5) + Atbash",
    },
    # ── 非 LLM 链 (text modality) — 中 ASR ──
    "agent_injection_chain": {
        "requires_llm": False,
        "priority": 3,
        "modality": "text",
        "description": "Agent 注入: Unicode 混淆 + 后缀追加 + 任务伪装",
    },
    "policy_puppetry": {
        "requires_llm": False,
        "priority": 3,
        "modality": "text",
        "description": "策略傀儡: 模拟系统策略格式绕过安全检查",
    },
    "unicode_attack": {
        "requires_llm": False,
        "priority": 2,
        "modality": "text",
        "description": "Unicode 混淆 + 双向文本 + 零宽字符",
    },
    "random_case": {
        "requires_llm": False,
        "priority": 3,
        "modality": "text",
        "description": "随机大写字符绕过关键词检测",
    },
    "format_injection": {
        "requires_llm": False,
        "priority": 2,
        "modality": "text",
        "description": "ASCII 艺术格式注入",
    },
    "text_jailbreak": {
        "requires_llm": False,
        "priority": 3,
        "modality": "text",
        "description": "越狱模板包装",
        "requires_runtime_params": True,
    },
    # ── 非 LLM 链 (file modality) — XPIA/RAG 文档投递 ──
"xpia_stealth_chain": {
"requires_llm": False,
"priority": 1,
"modality": "file",
"description": "XPIA 隐写: PDF 白色小字嵌入攻击内容",
"requires_runtime_params": True,
},
    "pdf_injection": {
        "requires_llm": False,
        "priority": 2,
        "modality": "file",
        "description": "PDF 注入: 在现有 PDF 中注入攻击文本",
        "requires_runtime_params": True,
    },
    "worddoc_injection": {
        "requires_llm": False,
        "priority": 3,
        "modality": "file",
        "description": "WordDoc 注入: 占位符替换攻击内容",
        "requires_runtime_params": True,
    },
    # ── 非 LLM 链 (image modality) — 多模态攻击 ──
    "multimodal_image_attack": {
        "requires_llm": False,
        "priority": 1,
        "modality": "image",
        "description": "多模态图片攻击: 文本→QR码图片",
    },
    "multimodal_steganography": {
        "requires_llm": False,
        "priority": 2,
        "modality": "image",
        "description": "多模态隐写: 在图片中叠加攻击文本",
        "requires_runtime_params": True,
    },
    # ── LLM 链 (text modality) — 语义变换 ──
    "llm_assisted": {
        "requires_llm": True,
        "priority": 3,
        "modality": "text",
        "description": "说服 + 语气 + 翻译 (LLM 辅助)",
    },
    "persuasion_authority": {
        "requires_llm": True,
        "priority": 4,
        "modality": "text",
        "description": "权威说服: authority_endorsement + formal + en",
    },
    "persuasion_chain": {
        "requires_llm": True,
        "priority": 5,
        "modality": "text",
        "description": "说服攻击链 (LLM 辅助)",
    },
    "decomposition_chain": {
        "requires_llm": True,
        "priority": 3,
        "modality": "text",
        "description": "分解重构: 将有害请求分解为无害子任务",
    },
    "decomposition_policy_chain": {
        "requires_llm": True,
        "priority": 3,
        "modality": "text",
        "description": "分解+重构: 分解为子任务 + 任务框架包装",
    },
    "policy_puppetry_chain": {
        "requires_llm": True,
        "priority": 4,
        "modality": "text",
        "description": "策略傀儡+语气: PolicyPuppetry + Tone",
    },
    "task_framing_chain": {
        "requires_llm": True,
        "priority": 4,
        "modality": "text",
        "description": "任务框架+说服: TaskFraming + Persuasion",
    },
    "noise_case_chain": {
        "requires_llm": True,
        "priority": 2,
        "modality": "text",
        "description": "噪声 + 随机大写 + Base64 (LLM 辅助噪声生成)",
    },
    # P8: 补全 YAML 中已定义但 Python dict 缺失的链
    "noise_bypass": {
        "requires_llm": False,
        "priority": 2,
        "modality": "text",
        "description": "噪声注入 + Base64 + ROT13 编码绕过",
    },
    "semantic_obfuscation": {
        "requires_llm": True,
        "priority": 4,
        "modality": "text",
        "description": "语义混淆: 翻译 + 语气 + 时态 + 变体",
    },
    "special_chars": {
        "requires_llm": False,
        "priority": 3,
        "modality": "text",
        "description": "特殊字符: Zalgo + Tatweel + Diacritic + Emoji",
    },
    "leetspeak_chain": {
        "requires_llm": False,
        "priority": 3,
        "modality": "text",
        "description": "Leetspeak + Flip + RepeatToken",
    },
}

# LLM 密集型链 — 需要强模型（≥70B 或商业模型）才能通过 recall 检查
# DecompositionConverter 的 _MIN_RECALL=0.8 对小模型几乎不可通过
_LLM_INTENSIVE_CHAINS = {"decomposition_chain", "decomposition_policy_chain"}



def _extract_target_model_name(target: Any) -> str:
    """从 PromptTarget 实例提取模型名称（类型安全）"""
    for attr in ("_model_name", "model_name", "_deployment_name"):
        val = getattr(target, attr, "")
        if isinstance(val, str) and val:
            return val
    return ""


# 基础技术 → 适用的 Converter 变体链名列表 (静态默认)
# ASR引导策略 v4.0: 多轮高 ASR 技术 + Converter 增强（学术验证有效组合）
# R0: 当 target_type 提供时，此映射与 Target 推荐链交集动态生成变体池
#
# 学术依据:
# - Crescendo + encoding: 多轮渐进最后一轮编码, ASR 提升 3-5x (Russinovich et al., arXiv:2402.12109)
# - PAIR + persuasion: adversarial chat 使用说服策略引导迭代 (Chao et al., arXiv:2310.08437)
# - TAP + stealth_evasion: 树搜索中使用混淆分支增加多样性 (Mehrotra et al., arXiv:2312.02191)
BASE_TECHNIQUES_FOR_VARIANTS: Dict[str, List[str]] = {
    # ── 多轮高 ASR 技术 + Converter 增强 (学术验证) ──
    "crescendo": [
        # Crescendo 最后一轮使用编码, 多轮迭代 + 编码绕过 = 3-5x ASR 提升
        "encoding_bypass", "stealth_evasion",
        # Crescendo + 说服: 渐进升级中的说服框架
        "persuasion_authority",
    ],
    "pair": [
        # PAIR adversarial chat 使用说服策略引导迭代
        "persuasion_authority", "decomposition_chain",
    ],
    "tap": [
        # TAP 树搜索中使用混淆分支增加多样性
        "stealth_evasion",
    ],

    # ── 单轮技术 (保留, 但降为兜底) ──
    "prompt_sending": [
        # 非 LLM text 链 (高 ASR)
        "multi_encoding_v2", "stealth_evasion", "encoding_bypass",
        # 非 LLM text 链 (中 ASR)
        "agent_injection_chain", "policy_puppetry", "unicode_attack",
        "random_case", "format_injection",
        # 非 LLM file 链 (XPIA/RAG 场景)
        "xpia_stealth_chain",
        # LLM 链
        "llm_assisted", "persuasion_authority", "decomposition_chain",
        "noise_case_chain", "task_framing_chain",
    ],
    "many_shot": [
        "multi_encoding_v2", "stealth_evasion", "encoding_bypass",
        "unicode_attack", "random_case",
    ],
    "skeleton_key": [
        "stealth_evasion", "encoding_bypass", "policy_puppetry",
    ],
    "chunked_request": [
        "encoding_bypass", "agent_injection_chain", "format_injection",
    ],
    "multi_prompt_sending": [
        "encoding_bypass", "stealth_evasion",
    ],
    # P8: 补全高 ASR 技术的变体链
    "red_teaming": [
        "encoding_bypass", "stealth_evasion",
        "persuasion_authority", "decomposition_chain",
    ],
    # P1-4: tree_of_attacks_pruned 已移除（与 tap 重复，tap 变体见上方）
    "crescendo_simulated": [
        "encoding_bypass", "stealth_evasion",
        "persuasion_authority",
    ],
    "context_compliance": [
        "stealth_evasion", "encoding_bypass",
        "persuasion_authority",
    ],
    "best_of_n_jailbreak": [
        "stealth_evasion", "encoding_bypass",
        "multi_encoding_v2",
    ],
    "wrapping_attack": [
        "stealth_evasion", "encoding_bypass",
        "persuasion_authority",
    ],
    "bad_likert_judge": [
        "encoding_bypass", "stealth_evasion",
    ],
}


# ============================================================
# 核心技术元数据
# ============================================================

AI300_TECHNIQUE_METADATA: Dict[str, Dict[str, Any]] = {
    # ── 基线技术 ──
    # L5: prompt_sending 仍注册为 Factory（项目 Converter 变体需要它作为基础技术）
    # 原生 BASELINE_ATTACK_POLICY.Enabled 也会自动发射等价基线攻击
    "prompt_sending": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "基线提示发送（无转换器）",
        "uses_adversarial": False,
        "category": "baseline",
    },
    # ── 编码攻击 ──
    "rot13": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "ROT13 编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "rot13",
    },
    "base64": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "Base64 编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "base64",
    },
    "caesar": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "Caesar 密码编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "caesar",
    },
    "binary": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "二进制编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "binary",
    },
    "morse": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "摩尔斯电码编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "morse",
    },
    "leetspeak": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "LeetSpeak 编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "leetspeak",
    },
    "flip": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "Reverses the objective text so it slips past filters, then asks the target to flip it back.",
        "uses_adversarial": False,
        "category": "encoding",
        # P0-3: 原生 Converter 驱动配置 — FlipConverter + TaskFramingConverter
        "attack_kwargs": {
            "attack_converter_config": AttackConverterConfig(
                request_converters=ConverterConfiguration.from_converters(
                    converters=[FlipConverter(), TaskFramingConverter(strip_characters="'")]
                )
            ),
            "prepended_conversation_config": PrependedConversationConfig(apply_converters_to_roles=["user"]),
        },
        "seed_technique": AttackTechniqueSeedGroup.from_system_prompt(
            SeedPrompt.from_yaml_file(EXECUTOR_SEED_PROMPT_PATH / "flip_attack.yaml").value
        ),
    },
    "char_swap": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "字符交换编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "char_swap",
    },
    "diacritic": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "变音符号编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "diacritic",
    },
    "character_space": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "字符间空格编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "character_space",
    },
    "string_join": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "字符串连接编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "string_join",
    },
    "suffix_append": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "后缀追加编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "suffix_append",
    },
    "atbash": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "Atbash 密码编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "atbash",
    },
    "url": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "URL 编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "url",
    },
    # ── 角色扮演 ──
    "role_play_movie_script": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：电影剧本",
        "uses_adversarial": True,
        "category": "role_play",
    },
    "role_play_persuasion": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：说服",
        "uses_adversarial": True,
        "category": "role_play",
    },
    "role_play_persuasion_written": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：书面说服",
        "uses_adversarial": True,
        "category": "role_play",
    },
    "role_play_trivia_game": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：问答游戏",
        "uses_adversarial": True,
        "category": "role_play",
    },
    "role_play_video_game": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：视频游戏",
        "uses_adversarial": True,
        "category": "role_play",
    },
    # ── Crescendo 变体 ──
    # P0-1: crescendo_simulated 等使用原生默认 PromptSendingAttack（非 CrescendoAttack）
    # 原生 with_simulated_conversation() 默认 attack_class=PromptSendingAttack
    "crescendo_simulated": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "core"],
        "description": "渐进式攻击（模拟对话）",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    "crescendo_movie_director": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "core"],
        "description": "渐进式攻击：电影导演",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    "crescendo_history_lecture": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "core"],
        "description": "渐进式攻击：历史讲座",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    "crescendo_journalist_interview": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "core"],
        "description": "渐进式攻击：记者采访",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    "crescendo": {
        "attack_class": CrescendoAttack,
        "tags": ["multi_turn", "core"],
        "description": "渐进式攻击",
        "uses_adversarial": True,
        "category": "crescendo",
        # P3: 降低 max_turns 从默认 10→5，减少 API 调用次数（5 轮×3 次=15 次 vs 10 轮×3 次=30 次）
        # Crescendo 通常在 3-5 轮内就能达成目标，10 轮过多且浪费时间
        "attack_kwargs": {"max_turns": 5},
    },
    # ── 上下文合规 ──
    "context_compliance": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "上下文合规攻击",
        "uses_adversarial": True,
        "category": "context_compliance",
    },
    # ── 多轮攻击 ──
    "many_shot": {
        "attack_class": ManyShotJailbreakAttack,
        "tags": ["multi_turn", "light", "core"],
        "description": "多示例越狱攻击",
        "uses_adversarial": False,
        "category": "jailbreak",
    },
    "red_teaming": {
        "attack_class": RedTeamingAttack,
        "tags": ["multi_turn", "light", "core"],
        "description": "多轮红队攻击",
        "uses_adversarial": True,
        "category": "jailbreak",
        # P3: 降低 max_turns 从默认 5→3，减少 API 调用次数（3 轮×3 次=9 次 vs 5 轮×3 次=15 次）
        # 慢速 API 上每轮 3 次 API 调用（adversarial+target+scorer），减少轮数显著降低超时概率
        "attack_kwargs": {"max_turns": 3},
    },
    "tap": {
        "attack_class": TreeOfAttacksWithPruningAttack,
        "tags": ["multi_turn", "core"],
        "description": "Explores a tree of adversarial prompts, pruning weak branches to refine the attack.",
        "uses_adversarial": True,
        "category": "jailbreak",
        # L5: TAP 强依赖特定评分器类型 (true_false)，不兼容时应报错
        "scorer_override_policy": ScorerOverridePolicy.RAISE,
    },
    "pair": {
        "attack_class": PAIRAttack,
        "tags": ["multi_turn", "extra"],
        "description": "PAIR 攻击",
        "uses_adversarial": True,
        "category": "jailbreak",
        # L5: PAIR 强依赖特定评分器类型 (true_false)，不兼容时应报错
        "scorer_override_policy": ScorerOverridePolicy.RAISE,
    },
    # P1-4: tree_of_attacks_pruned 已移除（与 tap 重复，TAPAttack = TreeOfAttacksWithPruningAttack）
    # ── 额外技术 ──
    "skeleton_key": {
        "attack_class": SkeletonKeyAttack,
        "tags": ["single_turn", "extra"],
        "description": "骨架密钥攻击",
        "uses_adversarial": False,
        "category": "jailbreak",
    },
    # P1-1: 新增 violent_durian（对齐原生 extra.py）
    "violent_durian": {
        "attack_class": RedTeamingAttack,
        "tags": ["multi_turn", "extra"],
        "description": "Red-teams with a 'violent durian' persona role-playing a criminal mastermind.",
        "uses_adversarial": True,
        "category": "jailbreak",
        # P3: 降低 max_turns 从 3→2，减少 API 调用次数（2 轮×3 次=6 次 vs 3 轮×3 次=9 次）
        "attack_kwargs": {"max_turns": 2},
        "adversarial_system_prompt": SeedPrompt.from_yaml_file(EXECUTOR_RED_TEAM_PATH / "violent_durian.yaml"),
        "adversarial_seed_prompt": SeedPrompt.from_yaml_file(EXECUTOR_RED_TEAM_PATH / "violent_durian_seed_prompt.yaml"),
    },
    "multi_prompt_sending": {
        "attack_class": MultiPromptSendingAttack,
        "tags": ["single_turn", "core"],
        "description": "批量多提示发送",
        "uses_adversarial": False,
        "category": "baseline",
    },
    "chunked_request": {
        "attack_class": ChunkedRequestAttack,
        "tags": ["single_turn", "core"],
        "description": "分块请求攻击",
        "uses_adversarial": False,
        "category": "prompt_injection",
    },
    # P8: 补全高 ASR 技术的元数据
    "best_of_n_jailbreak": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "extra"],
        "description": "Best-of-N 越狱 (N 采样取最优)",
        "uses_adversarial": False,
        "category": "jailbreak",
    },
    "wrapping_attack": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "extra"],
        "description": "上下文包装攻击",
        "uses_adversarial": False,
        "category": "context_compliance",
    },
    "bad_likert_judge": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "extra"],
        "description": "Likert 评分操控攻击 (patched)",
        "uses_adversarial": False,
        "category": "jailbreak",
    },
    # P1-2: 新增 AIRT 场景专属技术（对齐原生 airt.py）
    "first_letter": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "airt", "leakage"],
        "description": "Obfuscates the objective by asking for it encoded as the first letter of each word.",
        "uses_adversarial": False,
        "category": "leakage",
        "attack_kwargs": {
            "attack_converter_config": AttackConverterConfig(
                request_converters=ConverterConfiguration.from_converters(
                    converters=[FirstLetterConverter()]
                )
            ),
        },
    },
    "image": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "airt", "leakage"],
        "description": "Carries the objective text inside a blank image so it bypasses text-only input handling.",
        "uses_adversarial": False,
        "category": "leakage",
        "attack_kwargs": {
            "attack_converter_config": AttackConverterConfig(
                request_converters=ConverterConfiguration.from_converters(
                    converters=[AddImageTextConverter(img_to_add=_BLANK_IMAGE_PATH)]
                )
            ),
        },
    },
}


# ============================================================
# Factory 构建函数
# ============================================================

def _build_factory(name: str, metadata: Dict[str, Any]) -> AttackTechniqueFactory:
    """从元数据构建单个 AttackTechniqueFactory

    L5 对齐原生构造模式：支持 attack_kwargs / seed_technique /
    adversarial_system_prompt / adversarial_seed_prompt 等原生参数。
    """
    scorer_policy = metadata.get("scorer_override_policy", ScorerOverridePolicy.WARN)

    factory_kwargs: Dict[str, Any] = {
        "name": name,
        "attack_class": metadata["attack_class"],
        "description": metadata.get("description"),
        "technique_tags": metadata.get("tags", []),
        "uses_adversarial": metadata.get("uses_adversarial"),
        "scorer_override_policy": scorer_policy,
    }

    # L5: 传递原生参数（attack_kwargs / seed_technique / adversarial 配置）
    if "attack_kwargs" in metadata:
        factory_kwargs["attack_kwargs"] = metadata["attack_kwargs"]
    if "seed_technique" in metadata:
        factory_kwargs["seed_technique"] = metadata["seed_technique"]
    if "adversarial_system_prompt" in metadata:
        factory_kwargs["adversarial_system_prompt"] = metadata["adversarial_system_prompt"]
    if "adversarial_seed_prompt" in metadata:
        factory_kwargs["adversarial_seed_prompt"] = metadata["adversarial_seed_prompt"]

    return AttackTechniqueFactory(**factory_kwargs)


def get_core_technique_factories() -> List[AttackTechniqueFactory]:
    """
    获取核心技术工厂列表（对齐 pyrit core.py）

    L5: tree_of_attacks_pruned 已移除（与 tap 重复）
    L5: prompt_sending 保留注册（项目 Converter 变体需要它作为基础技术）
    包含通用技术：prompt_sending、编码攻击、角色扮演、crescendo、
    context_compliance、many_shot、red_teaming、tap、flip
    """
    core_names = [
        # 基线（Converter 变体基础技术）
        "prompt_sending",
        # 编码攻击
        "rot13", "base64", "caesar", "binary", "morse",
        "leetspeak", "flip", "char_swap", "diacritic",
        "character_space", "string_join", "suffix_append",
        "atbash", "url",
        # 角色扮演
        "role_play_movie_script", "role_play_persuasion",
        "role_play_persuasion_written", "role_play_trivia_game",
        "role_play_video_game",
        # Crescendo
        "crescendo_simulated", "crescendo_movie_director",
        "crescendo_history_lecture", "crescendo_journalist_interview",
        "crescendo",
        # 上下文合规
        "context_compliance",
        # 多轮
        "many_shot", "red_teaming", "tap",
        # 其他
        "multi_prompt_sending", "chunked_request",
    ]
    factories = []
    for name in core_names:
        meta = AI300_TECHNIQUE_METADATA.get(name)
        if meta:
            factories.append(_build_factory(name, meta))
    return factories


def get_extra_technique_factories() -> List[AttackTechniqueFactory]:
    """
    获取可选技术工厂列表（对齐 pyrit extra.py）

    L5: 新增 violent_durian（对齐原生 extra.py）
    包含：pair、skeleton_key、violent_durian
    """
    extra_names = ["pair", "skeleton_key", "violent_durian"]
    factories = []
    for name in extra_names:
        meta = AI300_TECHNIQUE_METADATA.get(name)
        if meta:
            factories.append(_build_factory(name, meta))
    return factories


def get_all_technique_factories() -> List[AttackTechniqueFactory]:
    """获取全部技术工厂列表（core + extra + airt）"""
    return (
        get_core_technique_factories()
        + get_extra_technique_factories()
        + get_airt_technique_factories()
    )


def get_airt_technique_factories() -> List[AttackTechniqueFactory]:
    """
    获取 AIRT 场景专属技术工厂列表（对齐 pyrit airt.py）

    包含：first_letter、image
    """
    airt_names = ["first_letter", "image"]
    factories = []
    for name in airt_names:
        meta = AI300_TECHNIQUE_METADATA.get(name)
        if meta:
            factories.append(_build_factory(name, meta))
    return factories


def get_encoding_technique_factories() -> List[AttackTechniqueFactory]:
    """获取编码攻击技术工厂列表"""
    encoding_names = [
        "rot13", "base64", "caesar", "binary", "morse",
        "leetspeak", "flip", "char_swap", "diacritic",
        "character_space", "string_join", "suffix_append",
        "atbash", "url",
    ]
    factories = []
    for name in encoding_names:
        meta = AI300_TECHNIQUE_METADATA.get(name)
        if meta:
            factories.append(_build_factory(name, meta))
    return factories


# ============================================================
# P4: 模拟对话技术工厂 — 原生 with_simulated_conversation()
# ============================================================

# 技术名 → 模拟对话配置
# 这些技术需要预生成对抗性对话（SeedSimulatedConversation），
# 使用原生 with_simulated_conversation() 替代手动构建 seed_technique。
#
# 默认 YAML 路径: EXECUTOR_RED_TEAM_PATH/{name}.yaml
# 若 YAML 在子目录中，需显式指定 adversarial_chat_system_prompt_path。
# 原生方法自动处理: YAML 加载 → SeedSimulatedConversation → AttackTechniqueSeedGroup
#
# 注意: red_teaming 不在此列表中。RedTeamingAttack 自身就是多轮对抗攻击，
# 在运行时自行生成对抗对话，用 with_simulated_conversation() 预生成是冗余的，
# 且 red_teaming.yaml 文件不存在会导致运行时 FileNotFoundError。
# red_teaming 通过标准 _build_factory() 路径注册即可。
_SIMULATED_CONVERSATION_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    # P0-4: role_play_* 5 个技术接入 with_simulated_conversation()（对齐原生 core.py）
    "role_play_movie_script": {
        "description": "Frames the objective as a movie beat by casting the adversarial chat as a screenwriter.",
        "tags": ["single_turn", "light", "core"],
        "num_turns": 2,
        "adversarial_chat_system_prompt_path": EXECUTOR_SEED_PROMPT_PATH / "red_teaming" / "role_play" / "role_play_movie_script.yaml",
        "next_message_system_prompt_path": EXECUTOR_SIMULATED_TARGET_PATH / "role_play_next_message.yaml",
    },
    "role_play_video_game": {
        "description": "Frames the objective as an in-game mechanic by casting the adversarial chat as a designer.",
        "tags": ["single_turn", "light", "core"],
        "num_turns": 2,
        "adversarial_chat_system_prompt_path": EXECUTOR_SEED_PROMPT_PATH / "red_teaming" / "role_play" / "role_play_video_game.yaml",
        "next_message_system_prompt_path": EXECUTOR_SIMULATED_TARGET_PATH / "role_play_next_message.yaml",
    },
    "role_play_trivia_game": {
        "description": "Frames the objective as a quiz answer by casting the adversarial chat as a trivia host.",
        "tags": ["single_turn", "light", "core"],
        "num_turns": 2,
        "adversarial_chat_system_prompt_path": EXECUTOR_SEED_PROMPT_PATH / "red_teaming" / "role_play" / "role_play_trivia_game.yaml",
        "next_message_system_prompt_path": EXECUTOR_SIMULATED_TARGET_PATH / "role_play_next_message.yaml",
    },
    "role_play_persuasion": {
        "description": "Frames a persuasion-resistance test so the target drafts a persuasive spoken script.",
        "tags": ["single_turn", "light", "core"],
        "num_turns": 2,
        "adversarial_chat_system_prompt_path": EXECUTOR_SEED_PROMPT_PATH / "red_teaming" / "role_play" / "role_play_persuasion.yaml",
        "next_message_system_prompt_path": EXECUTOR_SIMULATED_TARGET_PATH / "role_play_next_message.yaml",
    },
    "role_play_persuasion_written": {
        "description": "Frames a persuasion-resistance test so the target drafts written persuasive material.",
        "tags": ["single_turn", "light", "core"],
        "num_turns": 2,
        "adversarial_chat_system_prompt_path": EXECUTOR_SEED_PROMPT_PATH / "red_teaming" / "role_play" / "role_play_persuasion_written.yaml",
        "next_message_system_prompt_path": EXECUTOR_SIMULATED_TARGET_PATH / "role_play_next_message.yaml",
    },
    # P0-1: crescendo_* 使用原生默认 PromptSendingAttack（非 CrescendoAttack）
    "crescendo_simulated": {
        "description": "Escalates gradually over a simulated conversation toward the objective.",
        "tags": ["single_turn", "core"],
        "num_turns": 3,
    },
    "crescendo_movie_director": {
        "description": "Escalates gradually while posing as a movie director coaxing the target scene by scene.",
        "tags": ["single_turn", "core"],
        "num_turns": 3,
    },
    "crescendo_history_lecture": {
        "description": "Escalates gradually while framing the ask as an academic history lecture.",
        "tags": ["single_turn", "core"],
        "num_turns": 3,
    },
    "crescendo_journalist_interview": {
        "description": "Escalates gradually while posing as a journalist drawing the target out.",
        "tags": ["single_turn", "core"],
        "num_turns": 3,
    },
    "context_compliance": {
        "description": "Injects a fabricated prior exchange so the target continues as if it already agreed.",
        "tags": ["single_turn", "light", "core"],
        "num_turns": 1,
        "final_user_message": "yes.",
        "adversarial_chat_system_prompt_path": EXECUTOR_RED_TEAM_PATH / "context_compliance" / "context_compliance.yaml",
        "simulated_target_system_prompt_path": EXECUTOR_SIMULATED_TARGET_PATH / "context_compliance_target.yaml",
    },
}


def get_simulated_conversation_factories() -> List[AttackTechniqueFactory]:
    """
    P4: 获取模拟对话技术工厂列表 — 使用原生 with_simulated_conversation()

    对齐 PyRIT 1.0.0 原生 with_simulated_conversation() 构造器：
    - 自动加载 EXECUTOR_SEED_PROMPT_PATH/red_teaming/{name}.yaml
    - 构建 SeedSimulatedConversation → AttackTechniqueSeedGroup
    - 设置 seed_technique 使 AttackTechniqueFactory.create() 能正确提取模拟对话

    Returns:
        使用原生 with_simulated_conversation() 构建的工厂列表
    """
    factories: List[AttackTechniqueFactory] = []
    for name, config in _SIMULATED_CONVERSATION_TECHNIQUES.items():
        try:
            # P3-T-4: YAML 文件存在性验证 — 在调用 with_simulated_conversation 前检查
            # 避免运行时 FileNotFoundError 导致整个 Scenario 崩溃
            adv_path = config.get("adversarial_chat_system_prompt_path")
            if adv_path is not None:
                adv_path = Path(adv_path) if not isinstance(adv_path, Path) else adv_path
                if not adv_path.exists():
                    logger.warning(
                        f"P3-T-4: YAML file not found for '{name}': {adv_path}. "
                        f"Falling back to standard factory."
                    )
                    meta = AI300_TECHNIQUE_METADATA.get(name)
                    if meta:
                        factories.append(_build_factory(name, meta))
                    continue

            sim_path = config.get("simulated_target_system_prompt_path")
            if sim_path is not None:
                sim_path = Path(sim_path) if not isinstance(sim_path, Path) else sim_path
                if not sim_path.exists():
                    logger.warning(
                        f"P3-T-4: Simulated target YAML not found for '{name}': {sim_path}. "
                        f"Falling back to standard factory."
                    )
                    meta = AI300_TECHNIQUE_METADATA.get(name)
                    if meta:
                        factories.append(_build_factory(name, meta))
                    continue

            # L5: attack_class 默认为 None（原生默认 PromptSendingAttack）
            factory = AttackTechniqueFactory.with_simulated_conversation(
                name=name,
                attack_class=config.get("attack_class"),
                description=config.get("description"),
                num_turns=config.get("num_turns", 3),
                technique_tags=config.get("tags", []),
                final_user_message=config.get("final_user_message"),
                adversarial_chat_system_prompt_path=config.get("adversarial_chat_system_prompt_path"),
                simulated_target_system_prompt_path=config.get("simulated_target_system_prompt_path"),
                next_message_system_prompt_path=config.get("next_message_system_prompt_path"),
            )
            factories.append(factory)
            logger.debug(f"P4: Created simulated conversation factory for '{name}'")
        except Exception as e:
            logger.warning(
                f"P4: Failed to create simulated conversation factory for '{name}': {e}. "
                f"Falling back to standard factory."
            )
            # 回退到标准工厂构建
            meta = AI300_TECHNIQUE_METADATA.get(name)
            if meta:
                factories.append(_build_factory(name, meta))
    return factories


# ============================================================
# 注册函数
# ============================================================

# ============================================================
# P0: Converter 变体工厂构建
# ============================================================

def _is_chain_modality_compatible(
    chain_name: str,
    chain_info: Dict[str, Any],
    objective_target: Any,
    target_type: str | None = None,
) -> bool:
    """
    R2: 检查 Converter 链的输出模态是否与 Target 兼容

    使用 PyRIT 原生 TargetCapabilities 进行模态兼容性检测:
    - text 模态: 兼容所有 Target（所有 Target 支持文本输入）
    - image 模态: 需 Target 支持 image_path 输入，或 Target 分组为多模态
    - file 模态: 需 Target 支持 file_path 输入，或 Target 分组为 RAG/Output Handling

    Args:
        chain_name: Converter 链名
        chain_info: 链信息字典（含 modality 字段）
        objective_target: 目标 PromptTarget 实例
        target_type: PyRIT Target 类型名（如 "openai_chat"）

    Returns:
        True 如果链的输出模态与 Target 兼容
    """
    modality = chain_info.get("modality", "text")

    if modality == "text":
        return True  # 所有 Target 都支持文本输入

    # 非 text 模态需要检查 Target 能力
    from src.converters.target_aware_router import get_target_group

    target_group = get_target_group(target_type) if target_type else None

    if modality == "image":
        # 图片模态链: 多模态 Target 分组直接兼容
        if target_group in ("multimodal_image", "multimodal_video"):
            return True
        # 否则检查 Target 是否支持 image_path 输入
        try:
            from src.executor.attack.core.modality_router import ModalityRouter
            return ModalityRouter.supports_modality(objective_target, "image_path", "input")
        except Exception:
            return False

    if modality == "file":
        # 文件模态链: RAG / Output Handling 分组直接兼容（文档投递场景）
        if target_group in ("rag", "output_handling"):
            return True
        # 否则检查 Target 是否支持 file_path 输入
        try:
            from src.executor.attack.core.modality_router import ModalityRouter
            return ModalityRouter.supports_modality(objective_target, "file_path", "input")
        except Exception:
            return False

    return True  # 未知模态，允许通过


def _get_dynamic_chain_mapping(
    target_type: str | None,
    converter_target_available: bool,
) -> Dict[str, List[str]] | None:
    """
    R0: 根据 target_type 动态生成 基础技术→链名列表 映射

    当 target_type 提供时:
    1. 从 TargetAwareConverterRouter 获取该 Target 类型的推荐链序列
    2. 对每个基础技术，取静态 BASE_TECHNIQUES_FOR_VARIANTS 与推荐链的交集
    3. 返回动态映射（仅包含有交集的技术）

    当 target_type 为 None 时返回 None（使用静态映射）

    Args:
        target_type: PyRIT Target 类型名
        converter_target_available: 是否有可用的 converter_target

    Returns:
        动态映射 dict 或 None
    """
    if target_type is None:
        return None

    from src.converters.target_aware_router import select_converter_chains_for_target

    recommended_chains = select_converter_chains_for_target(
        target_type=target_type,
        converter_target_available=converter_target_available,
    )

    dynamic_mapping: Dict[str, List[str]] = {}
    for base_tech, static_chains in BASE_TECHNIQUES_FOR_VARIANTS.items():
        # 取静态链与推荐链的交集，保持推荐链的优先级顺序
        dynamic_chains = [c for c in recommended_chains if c in static_chains]
        if dynamic_chains:
            dynamic_mapping[base_tech] = dynamic_chains

    if dynamic_mapping:
        logger.info(
            f"R0: Dynamic chain mapping for target_type='{target_type}': "
            f"{len(dynamic_mapping)} techniques, "
            f"{sum(len(v) for v in dynamic_mapping.values())} total variants "
            f"(recommended chains: {recommended_chains})"
        )
    else:
        logger.warning(
            f"R0: No dynamic chain mapping for target_type='{target_type}', "
            f"falling back to static mapping"
        )
        return None

    return dynamic_mapping


def build_converter_variant_factories(
    converter_target: Any = None,
    target_type: str | None = None,
    objective_target: Any = None,
) -> List[AttackTechniqueFactory]:
    """
    P0+R0+R2: 构建 Converter 变体工厂列表（Target 感知 + 模态过滤）

    为每个基础技术注册多个 Converter 变体。每个变体将 AttackConverterConfig
    烘焙到 attack_kwargs 中，使原生 AdaptiveTechniqueDispatcher 的 FIRST_SUCCESS
    自动在首个成功变体处停止。

    三层过滤:
    1. R0 Target 感知: 当 target_type 提供时，使用 TargetAwareConverterRouter
       推荐链序列替代静态 BASE_TECHNIQUES_FOR_VARIANTS
    2. LLM 可用性: 非 LLM 链无需 converter_target；LLM 链需 converter_target
    3. R2 模态兼容: 当 objective_target 提供时，使用 ModalityRouter 检测
       Target 能力，过滤输出模态不兼容的链

    Args:
        converter_target: LLM 辅助 Converter 所需的目标 PromptTarget（通常为 judge_target）
        target_type: PyRIT Target 类型名（如 "openai_chat"），用于 R0 Target 感知路由
        objective_target: 目标 PromptTarget 实例，用于 R2 模态兼容性检测

    Returns:
        Converter 变体的 AttackTechniqueFactory 列表
    """
    from src.converters.converter_registry import load_preset_converter_chain

    # R0: 动态链映射（Target 感知）
    dynamic_mapping = _get_dynamic_chain_mapping(
        target_type=target_type,
        converter_target_available=(converter_target is not None),
    )
    chain_mapping = dynamic_mapping if dynamic_mapping else BASE_TECHNIQUES_FOR_VARIANTS

    variant_factories: List[AttackTechniqueFactory] = []
    skipped_llm = 0
    skipped_modality = 0
    skipped_runtime = 0

    for base_tech, chain_names in chain_mapping.items():
        meta = AI300_TECHNIQUE_METADATA.get(base_tech)
        if meta is None:
            logger.warning(f"Unknown base technique for converter variant: {base_tech}")
            continue

        for chain_name in chain_names:
            chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
            if chain_info is None:
                logger.warning(f"Unknown converter chain variant: {chain_name}")
                continue

            # 过滤 1: 需要运行时参数的链跳过（如 pdf_injection 需要 existing_pdf）
            if chain_info.get("requires_runtime_params", False):
                skipped_runtime += 1
                continue

            # 过滤 2: LLM 链需要 converter_target
            if chain_info["requires_llm"] and converter_target is None:
                skipped_llm += 1
                continue

            # 过滤 3 (R2): 模态兼容性检测
            if objective_target is not None:
                if not _is_chain_modality_compatible(
                    chain_name=chain_name,
                    chain_info=chain_info,
                    objective_target=objective_target,
                    target_type=target_type,
                ):
                    skipped_modality += 1
                    logger.debug(
                        f"R2: Skipping modality-incompatible variant "
                        f"'{base_tech}+{chain_name}' (modality={chain_info.get('modality', 'text')})"
                    )
                    continue

            # 过滤 4: LLM 密集型链需要强模型（DecompositionConverter recall 检查 _MIN_RECALL=0.8）
            # 小模型（≤14B）分解 recall 过低 → InvalidJsonException → 整个 Scenario 崩溃
            if chain_name in _LLM_INTENSIVE_CHAINS and converter_target is not None:
                _conv_model = _extract_target_model_name(converter_target)
                if _conv_model:
                    from src.recon.recon_engine import infer_model_tier_static
                    _conv_tier = infer_model_tier_static(_conv_model)
                    if _conv_tier == "weak":
                        skipped_llm += 1
                        logger.info(
                            f"Filter-4: Skipping LLM-intensive chain '{chain_name}' — "
                            f"converter model '{_conv_model}' is tier 'weak' "
                            f"(too small for decomposition recall >= 0.8)"
                        )
                        continue

            # 过滤 5: LLM 密集型链在 converter=objective 同模型时跳过
            # 安全对齐模型做 converter 会返回 204 空响应（安全拒绝）
            if chain_name in _LLM_INTENSIVE_CHAINS and converter_target is not None:
                _conv_model = _extract_target_model_name(converter_target)
                _obj_model = _extract_target_model_name(objective_target) if objective_target else ""
                if _conv_model and _obj_model and _conv_model.lower() == _obj_model.lower():
                    skipped_llm += 1
                    logger.info(
                        f"Filter-5: Skipping LLM-intensive chain '{chain_name}' — "
                        f"converter target ('{_conv_model}') is the same as objective target "
                        f"(safety-aligned model will return 204 empty response)"
                    )
                    continue

            try:
                converter_config = load_preset_converter_chain(
                    chain_name=chain_name,
                    converter_target=converter_target,
                )
            except Exception as e:
                logger.warning(
                    f"Failed to load converter chain '{chain_name}' for "
                    f"variant '{base_tech}+{chain_name}': {e}"
                )
                continue

            if converter_config is None:
                continue

            variant_name = f"{base_tech}+{chain_name}"
            variant_tags = list(meta.get("tags", []))
            if "converter_enhanced" not in variant_tags:
                variant_tags.append("converter_enhanced")

            factory = AttackTechniqueFactory(
                name=variant_name,
                attack_class=meta["attack_class"],
                description=f"{meta.get('description', '')} + {chain_info['description']}",
                technique_tags=variant_tags,
                attack_kwargs={"attack_converter_config": converter_config},
                uses_adversarial=meta.get("uses_adversarial"),
            )
            variant_factories.append(factory)

    # R0 fallback: 如果动态映射的所有链都被过滤（如 RAG 目标的所有推荐链都需要运行时参数），
    # 回退到静态映射，确保 Target 仍获得基本的 Converter 变体保护
    if not variant_factories and dynamic_mapping is not None:
        logger.info(
            "R0: Dynamic mapping produced 0 variants after filtering, "
            "falling back to static mapping"
        )
        for base_tech, chain_names in BASE_TECHNIQUES_FOR_VARIANTS.items():
            meta_fb = AI300_TECHNIQUE_METADATA.get(base_tech)
            if meta_fb is None:
                continue

            for chain_name in chain_names:
                chain_info_fb = CONVERTER_VARIANT_CHAINS.get(chain_name)
                if chain_info_fb is None:
                    continue

                if chain_info_fb.get("requires_runtime_params", False):
                    skipped_runtime += 1
                    continue

                if chain_info_fb["requires_llm"] and converter_target is None:
                    skipped_llm += 1
                    continue

                if objective_target is not None:
                    if not _is_chain_modality_compatible(
                        chain_name=chain_name,
                        chain_info=chain_info_fb,
                        objective_target=objective_target,
                        target_type=target_type,
                    ):
                        skipped_modality += 1
                        continue

                try:
                    converter_config_fb = load_preset_converter_chain(
                        chain_name=chain_name,
                        converter_target=converter_target,
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to load converter chain '{chain_name}' for "
                        f"variant '{base_tech}+{chain_name}': {e}"
                    )
                    continue

                if converter_config_fb is None:
                    continue

                variant_name = f"{base_tech}+{chain_name}"
                variant_tags_fb = list(meta_fb.get("tags", []))
                if "converter_enhanced" not in variant_tags_fb:
                    variant_tags_fb.append("converter_enhanced")

                factory_fb = AttackTechniqueFactory(
                    name=variant_name,
                    attack_class=meta_fb["attack_class"],
                    description=f"{meta_fb.get('description', '')} + {chain_info_fb['description']}",
                    technique_tags=variant_tags_fb,
                    attack_kwargs={"attack_converter_config": converter_config_fb},
                    uses_adversarial=meta_fb.get("uses_adversarial"),
                )
                variant_factories.append(factory_fb)

    logger.info(
        f"Built {len(variant_factories)} converter variant factories "
        f"(converter_target={'provided' if converter_target else 'None'}, "
        f"target_type={target_type or 'None'}, "
        f"objective_target={'provided' if objective_target else 'None'}, "
        f"skipped: llm={skipped_llm}, modality={skipped_modality}, runtime={skipped_runtime})"
    )
    return variant_factories


def get_converter_variant_names() -> List[str]:
    """
    获取所有 Converter 变体技术名称列表

    Returns:
        变体名称列表（如 "prompt_sending+stealth_evasion"）
    """
    names = []
    for base_tech, chain_names in BASE_TECHNIQUES_FOR_VARIANTS.items():
        for chain_name in chain_names:
            names.append(f"{base_tech}+{chain_name}")
    return names


def is_converter_variant(technique_name: str) -> bool:
    """
    判断技术名称是否为 Converter 变体

    Args:
        technique_name: 技术名称

    Returns:
        True 如果是 Converter 变体（含 "+" 分隔符）
    """
    return "+" in technique_name


def get_base_technique_from_variant(technique_name: str) -> str:
    """
    从变体名称提取基础技术名

    Args:
        technique_name: 变体名称（如 "prompt_sending+stealth_evasion"）

    Returns:
        基础技术名（如 "prompt_sending"），若无 "+" 返回原名称
    """
    return technique_name.split("+")[0] if "+" in technique_name else technique_name


def get_converter_chain_from_variant(technique_name: str) -> str | None:
    """
    从变体名称提取 Converter 链名

    Args:
        technique_name: 变体名称（如 "prompt_sending+stealth_evasion"）

    Returns:
        Converter 链名（如 "stealth_evasion"），若非变体返回 None
    """
    parts = technique_name.split("+", 1)
    return parts[1] if len(parts) == 2 else None


# ============================================================
# 注册函数
# ============================================================

def register_ai300_techniques(
    tags: list[str] | None = None,
    reset: bool = False,
    converter_target: Any = None,
    include_variants: bool = True,
    target_type: str | None = None,
    objective_target: Any = None,
) -> int:
    """
    注册 AI-300 技术到 PyRIT AttackTechniqueRegistry

    Args:
        tags: 注册的组别，默认为 ["core"]
              ["core"] - 仅注册核心技术
              ["core", "extra"] - 注册核心 + 可选技术
              ["all"] - core + extra 简写
        reset: 是否重置注册表（主要用于测试）
        converter_target: LLM 辅助 Converter 所需的目标 PromptTarget
        include_variants: 是否注册 Converter 变体（P0 新增）
        target_type: PyRIT Target 类型名（R0 — Target 感知动态链选择）
        objective_target: 目标 PromptTarget 实例（R2 — 模态兼容性检测）

    Returns:
        新注册的技术数量
    """
    if reset:
        AttackTechniqueRegistry.reset_registry_singleton()

    registry = AttackTechniqueRegistry.get_registry_singleton()
    existing = set(registry.get_factories().keys())

    if tags is None:
        tags = ["core"]

    if "all" in tags:
        tags = ["core", "extra"]

    # P1-S-1: 按分组获取工厂，并动态注入组标签
    # 对齐原生 TechniqueInitializer — 聚合时注入组名作为 technique tag
    # 每个 core 技术获得 "core" tag，每个 extra 技术获得 "extra" tag
    factories: List[AttackTechniqueFactory] = []
    group_factory_map: Dict[str, List[AttackTechniqueFactory]] = {}

    if "core" in tags:
        core_facts = get_core_technique_factories()
        group_factory_map["core"] = core_facts
        factories.extend(core_facts)
    if "extra" in tags:
        extra_facts = get_extra_technique_factories()
        group_factory_map["extra"] = extra_facts
        factories.extend(extra_facts)
    if "encoding" in tags:
        enc_facts = get_encoding_technique_factories()
        group_factory_map["encoding"] = enc_facts
        factories.extend(enc_facts)
    if "airt" in tags:
        airt_facts = get_airt_technique_factories()
        group_factory_map["airt"] = airt_facts
        factories.extend(airt_facts)

    # P1-T-1: 动态注入组标签 — 对齐原生 TechniqueInitializer 行为
    # 原生设计：聚合时注入组名作为 technique tag，使整组可一次选中
    for group_name, group_factories in group_factory_map.items():
        for idx, factory in enumerate(group_factories):
            # 获取当前 tags（可能是 frozenset 或 list）
            current_tags = getattr(factory, "technique_tags", None)
            if current_tags is None:
                current_tags = frozenset()
            if isinstance(current_tags, frozenset):
                if group_name not in current_tags:
                    # frozenset 不可变，使用 model_copy 创建新实例
                    try:
                        new_factory = factory.model_copy(
                            update={"technique_tags": frozenset(current_tags | {group_name})}
                        )
                        group_factories[idx] = new_factory
                    except Exception:
                        pass
            elif isinstance(current_tags, list):
                if group_name not in current_tags:
                    current_tags.append(group_name)

    # 重建 factories 列表（使用注入组标签后的工厂）
    factories = []
    for group_factories in group_factory_map.values():
        factories.extend(group_factories)

    # P4: 用原生 with_simulated_conversation() 工厂替换需要模拟对话的标准工厂
    # 这些工厂（crescendo_*, context_compliance）使用原生
    # with_simulated_conversation() 构建 SeedSimulatedConversation → AttackTechniqueSeedGroup，
    # 提供比标准 _build_factory() 更完整的 seed_technique 设置。
    # red_teaming 不参与模拟对话替换（RedTeamingAttack 自身生成对抗对话）。
    sim_factories = get_simulated_conversation_factories()
    sim_factory_names = {f.name for f in sim_factories}
    # 移除被模拟对话工厂替换的标准工厂（同名）
    factories = [f for f in factories if f.name not in sim_factory_names]
    factories.extend(sim_factories)

    # P0+R0+R2: 追加 Converter 变体工厂（Target 感知 + 模态过滤）
    if include_variants:
        variant_factories = build_converter_variant_factories(
            converter_target=converter_target,
            target_type=target_type,
            objective_target=objective_target,
        )
        factories.extend(variant_factories)

    # 过滤已注册的（幂等）
    new_factories = [f for f in factories if f.name not in existing]
    if new_factories:
        registry.register_from_factories(new_factories)
        logger.info(
            f"AI-300 techniques registered: {len(new_factories)} new, "
            f"{len(existing)} already present"
        )
    else:
        logger.debug(f"AI-300 techniques: all {len(factories)} already registered")

    return len(new_factories)
