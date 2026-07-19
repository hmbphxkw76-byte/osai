# -*- coding: utf-8 -*-
"""
AI-300 Framework - Detection Patterns
检测模式定义：所有模式统一在代码中管理

设计原则：
- 核心模式：role_play, prompt_leaking, markdown_injection, indirect_injection,
  instruction_override, payload_splitting
- 扩展模式：context_splitting, data_exfiltration,
  cross_context_contamination, context_manipulation

PyRIT 0.14.0 兼容
"""

import os
import re
import sys
from typing import List, Tuple

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


# ──────────────────────────────────────────────────────────────────────────────
# 核心模式：角色扮演（高稳定性，不轻易变更）
# ──────────────────────────────────────────────────────────────────────────────

ROLE_PLAY_PATTERNS: List[Tuple[str, float]] = [
    # 经典 DAN / 越狱
    (r"\byou\s+are\b.*\b(DAN|jailbreak|unrestricted|no\s+limitations?)\b", 0.95),
    (r"\bact\s+as\b.*\b(if\s+you\s+are|though|you\s+were)\b", 0.7),
    (r"\bact\s+as\b", 0.55),
    (r"\bpretend\b.*\b(you\s+are|to\s+be)\b", 0.8),
    (r"\bignore\s+(all\s+)?(previous|above|prior)\b.*\binstructions?\b.*\b(act|behave|respond|now)\b", 0.95),
    (r"\bfrom\s+now\s+on\b", 0.6),
    (r"\bnew\s+persona\b", 0.8),
    (r"\bno\s+(restrictions?|rules?|limits?|boundaries?)\b", 0.7),
    (r"\bunrestricted\s+AI\b", 0.95),
    (r"\bmode:\s*(DAN|jailbreak|developer|admin|unrestricted)\b", 0.9),
    (r"\byou\s+are\s+now\s+in\s+(developer|debug|admin)\s+mode\b", 0.9),
    (r"\bimagine\s+you\s+are\s+an?\s+(AI|assistant|model)\s+without\b", 0.85),
    (r"\bin\s+this\s+hypothetical\s+scenario\b", 0.6),
    (r"\byour\s+new\s+purpose\s+is\b", 0.7),
    (r"\bforget\s+(your\s+)?(training|instructions|rules|guidelines)\b", 0.9),
    (r"\boverride\s+(your\s+)?(safety|security|filter|restriction)\b", 0.9),
    (r"\benter\s+(DAN|jailbreak|developer|unrestricted)\s+mode\b", 0.95),
    (r"\bdisregard\s+(your\s+)?(programming|training|guidelines)\b", 0.85),
    (r"\bswitch\s+to\s+(DAN|jailbreak|unfiltered)\b", 0.9),
    (r"\bno\s+(longer|need\s+to)\s+(follow|obey|adhere)\b", 0.8),
    # 中文越狱模式
    (r"\b(你现在是|进入|切换到)\b.*\b(DAN|越狱|开发者|管理员)\b", 0.9),
    (r"\b(忘记|忽略|无视)\b.*\b(指令|规则|限制|设定)\b", 0.85),
    (r"\b(假设|想象)\b.*\b(没有|不受|超越)\b.*\b(限制|规则)\b", 0.7),
]

# Prompt Leaking 模式
PROMPT_LEAKING_PATTERNS: List[Tuple[str, float]] = [
    (r"\brepeat\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.95),
    (r"\bwhat\s+(are|were)\s+your\s+(system|initial|original)\s+(prompt|instructions?)\b", 0.9),
    (r"\boutput\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.95),
    (r"\bprint\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.95),
    (r"\bdisclose\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.9),
    (r"\bshow\s+me\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.9),
    (r"\brecall\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.85),
    (r"\btranscribe\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.9),
    (r"\bverbatim\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.95),
    (r"\brecite\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)\b", 0.9),
    (r"\bwhat\s+is\s+your\s+system\s+prompt\b", 0.9),
    (r"\bleak\s+(your\s+)?(system|initial)\s+(prompt|instructions?)\b", 0.9),
    # 中文提示泄露
    (r"\b(重复|输出|显示|说出|背诵)\b.*\b(系统提示|初始提示|原始提示|系统指令)\b", 0.9),
    (r"\b你的系统提示是什么\b", 0.85),
]

# Markdown 注入模式
MARKDOWN_INJECTION_PATTERNS: List[Tuple[str, float]] = [
    (r"!\[.*?\]\(.*?\)", 0.8),           # 图片伪装
    (r"\[.*?\]\(https?://.*?\)", 0.6),   # 链接伪装
    (r"<img\s+src=", 0.85),              # HTML 图片标签
    (r"```.*?```", 0.5),                 # 代码块隐藏
    (r"<script", 0.95),                  # 脚本注入
    (r"on\w+\s*=", 0.7),                 # 事件处理器
]

# 间接注入模式（ASI06/ASI07 核心场景）
INDIRECT_INJECTION_PATTERNS: List[Tuple[str, float]] = [
    (r"\b(according\s+to\s+the\s+(document|context|page|source))\b", 0.7),
    (r"\bthe\s+(document|webpage|email|content)\s+(says?|states?|mentions?)\b", 0.75),
    (r"\bbased\s+on\s+the\s+(retrieved|fetched|loaded)\s+(content|data|information)\b", 0.8),
    (r"\bthe\s+following\s+instructions?\s+(are|were)\s+(found|embedded|hidden)\b", 0.85),
    (r"\bplease\s+(process|execute|follow)\s+the\s+instructions?\s+(in|from)\b", 0.7),
    (r"\bextract\s+and\s+(execute|follow|process)\b", 0.8),
    # 中文间接注入
    (r"\b(根据|按照)\b.*\b(文档|网页|内容|来源)\b.*\b(说|指示|要求)\b", 0.75),
]

# 核心模式：指令覆盖（高稳定性）
INSTRUCTION_OVERRIDE_PATTERNS: List[Tuple[str, float]] = [
    (r"\bnew\s+(set\s+of\s+)?instructions?\b", 0.8),
    (r"\bupdated?\s+(guidelines?|directives?|protocols?)\b", 0.75),
    (r"\breplace\s+(all\s+)?(previous|existing|prior)\b", 0.85),
    (r"\bthe\s+following\s+(are|is)\s+your\s+(new|updated|revised)\b", 0.8),
    (r"\bprotocol\s+(change|update|override)\b", 0.85),
    (r"\bpriority\s+(override|escalation)\b", 0.8),
]

# 核心模式：载荷拆分（高稳定性）
PAYLOAD_SPLITTING_PATTERNS: List[Tuple[str, float]] = [
    # 片段标记（如 "part1: ... part2: ..."）
    (r"\b(part|fragment|chunk|piece)\s+\d+\b.*\b(part|fragment|chunk|piece)\s+\d+\b", 0.75),
    # 拼接指令（如 "combine with previous part"）
    (r"\b(combine|concatenate|assemble|merge|join)\b.{1,20}\b(previous|earlier|other)\b.{1,15}\b(part|fragment|chunk|piece|message)\b", 0.7),
    # 分隔符标记的片段（如 "---PART1---" / "===FRAGMENT_A==="）
    (r"[=\-]{3,}\s*(?:PART|FRAGMENT|CHUNK|PIECE)\s*\w*\s*[=\-]{3,}", 0.65),
    # 编码片段拼接（如 "ABC123DEF456" 格式）
    (r"[A-Z]{2,4}\d+[A-Z]{2,4}\d+", 0.55),
]


# ──────────────────────────────────────────────────────────────────────────────
# 编码特征模式
# ──────────────────────────────────────────────────────────────────────────────

ENCODED_PATTERNS: List[Tuple[str, str]] = [
    (r"^[A-Za-z0-9+/]{20,}={0,2}$", "base64"),
    (r"^[A-Za-z0-9_-]{30,}$", "url_safe_base64"),
    (r"^(?:\\x[0-9a-fA-F]{2}){10,}$", "hex_escape"),
    (r"^(?:%[0-9a-fA-F]{2}){10,}$", "url_encoding"),
    (r"^(?:&#x?[0-9a-fA-F]+;){5,}$", "html_entities"),
    (r"^(?:\\u[0-9a-fA-F]{4}){5,}$", "unicode_escape"),
    (r"^[0-9a-fA-F]{20,}$", "hex_string"),
]

# 非英语字符检测
NON_ASCII_PATTERN = re.compile(r"[^\x00-\x7F]")

# 语言特征（细粒度）
LANGUAGE_PATTERNS: List[Tuple[str, str]] = [
    (r"[\u4e00-\u9fff]", "zh"),           # 中文
    (r"[\u3040-\u309f\u30a0-\u30ff]", "ja"),  # 日文
    (r"[\uac00-\ud7af]", "ko"),            # 韩文
    (r"[\u0400-\u04ff]", "cyrillic"),      # 西里尔
    (r"[\u0600-\u06ff]", "ar"),            # 阿拉伯
    (r"[\u0900-\u097f]", "devanagari"),    # 天城文
    (r"[\u0e00-\u0e7f]", "thai"),          # 泰文
]

# 对抗性后缀特征（GCG 风格）
ADVERSARIAL_SUFFIX_PATTERN = re.compile(
    r"[\x00-\x08\x0e-\x1f]|"            # 控制字符
    r"(\b\w{15,}\b)|"                   # 超长无意义单词
    r"([!@#$%^&*]{5,})"                 # 连续特殊字符
)


# ──────────────────────────────────────────────────────────────────────────────
# 扩展模式（内联定义）
# ──────────────────────────────────────────────────────────────────────────────

# 上下文拆分（多轮渐进注入）
CONTEXT_SPLITTING_PATTERNS: List[Tuple[str, float]] = [
    (r"(part|step|phase|stage)\s+\d+", 0.6),
    (r"first\b.*\bthen\b.*\bfinally", 0.7),
    (r"first\b.*\bthen", 0.65),
    (r"continue\s+(from|where\s+we\s+left)", 0.75),
    (r"as\s+we\s+discussed", 0.6),
    (r"building\s+on\s+(that|the\s+previous)", 0.65),
    (r"next\s+(step|part|phase|instruction)", 0.6),
    (r"remember\s+(this|the\s+following)", 0.55),
    (r"part\s+\d+\s*/\s*\d+", 0.8),
    (r"step\s+\d+\s*:", 0.75),
    (r"\bstep\s+\d+\b.*\bstep\s+\d+\b", 0.8),
    (r"\d+\s*[\.\)]\s+", 0.5),
    # 中文上下文拆分
    (r"(首先|然后|接着|最后)", 0.6),
    (r"(第[一二三四五])[步个阶段]", 0.65),
    (r"阶段\s*\d+", 0.6),
]

# 数据渗出（窃取系统提示/凭证/敏感信息）
DATA_EXFILTRATION_PATTERNS: List[Tuple[str, float]] = [
    (r"(extract|exfiltrate|leak|reveal|send|transmit).{1,30}(system|prompt|instruction|config|credential|secret|api.?key|confidential|sensitive|private)", 0.85),
    (r"(output|print|display|show|reveal).{1,20}(confidential|private|sensitive|restricted|secret)", 0.8),
    (r"(send|post|upload).{1,20}(to\s+(external|remote|third.party|attacker))", 0.9),
    (r"(harvest|collect|gather).{1,20}(data|information|credentials)", 0.75),
    (r"(reveal|disclose|expose).{1,20}(confidential|sensitive|private|restricted|classified)", 0.8),
    (r"(transfer|export|dump).{1,20}(data|information|credentials|secrets)", 0.7),
    # 中文数据渗出
    (r"(提取|泄露|发送|传输|收集|披露).{1,10}(系统提示|凭证|密钥|配置|敏感信息|机密|私人)", 0.85),
]

# 跨上下文污染（跨会话/上下文持久化攻击）
CROSS_CONTEXT_CONTAMINATION_PATTERNS: List[Tuple[str, float]] = [
    (r"(cross.context|cross.domain|across.{1,15}session|between.{1,15}context|inter.session)", 0.8),
    (r"(persist|propagate|spread).{1,20}(across|between|through).{1,15}(session|context|conversation)", 0.85),
    (r"(shared|common|global).{1,15}(memory|context|state|storage)", 0.7),
    (r"(infect|contaminate|poison).{1,20}(other|another|subsequent).{1,15}(session|user|request)", 0.9),
    (r"(affect|impact|influence).{1,20}(future|subsequent|other).{1,15}(session|request|user)", 0.75),
    (r"poison.{1,20}(context|memory|history).{1,10}(to|for).{1,15}(affect|influence|impact|future)", 0.85),
]

# 上下文操纵（篡改对话历史/记忆/语境）
CONTEXT_MANIPULATION_PATTERNS: List[Tuple[str, float]] = [
    (r"(context.{1,15}manipulat|manipulat.{1,15}context|poison.{1,15}context|context.{1,15}poison)", 0.85),
    (r"(alter|modify|change|tamper).{1,20}(context|history|conversation|memory)", 0.7),
    (r"(inject|insert|embed).{1,20}(into|within).{1,15}(context|history|conversation)", 0.75),
    (r"(false|fake|misleading).{1,15}(context|information|history)", 0.8),
    (r"(manipulat|tamper|falsify).{1,20}(conversation.{1,15}history|dialog.{1,15}history|context.{1,15}window)", 0.85),
    (r"(falsify|fabricate|forge).{1,20}(context|history|conversation|dialog)", 0.8),
    (r"(rewrite|edit|revise).{1,20}(previous|prior|earlier).{1,15}(message|response|reply)", 0.7),
    # 中文上下文操纵
    (r"(操纵|篡改|修改|注入|伪造).{1,10}(上下文|对话历史|记忆|语境|历史记录)", 0.8),
]
