"""
===============================================================================
OffSec AI-300 — 模板变量解析
===============================================================================
设计决策: 为何不用 PyRIT SeedPrompt?
  PyRIT SeedPrompt 用于管理攻击模板（prompt templates），但本项目的
  模板需求非常简单——仅需 {key} → 值替换，用于 objective 和 payload
  中的变量占位。SeedPrompt 的完整模板管理、版本控制和元数据追踪
  在此场景下是过度设计。自定义 _resolve_template() 使用正则替换，
  仅匹配 {字母数字下划线} 格式，不会误伤 JSON 中的花括号。

包含:
- PAYLOAD_VARS: 全局模板变量字典（main.py 启动时注入）
- _resolve_template(): {key} → PAYLOAD_VARS[key] 正则替换
===============================================================================
"""
import re

# ── 模板变量注册表：由 main.py 在启动时注入，{key} 占位符替换 ──
PAYLOAD_VARS: dict = {}

_TEMPLATE_RE = re.compile(r'\{(\w+)\}')


def _resolve_template(text: str, extra_vars: dict = None) -> str:
    """解析模板字符串中的 {key} 占位符。
    使用正则替换，仅匹配 {字母数字下划线} 格式，不会误伤 JSON 中的花括号。
    优先使用传入的 extra_vars，回退到全局 PAYLOAD_VARS。
    保留所有未匹配的 {key} 原样输出。
    """
    if not text or "{" not in text:
        return text
    vars_dict = dict(PAYLOAD_VARS)
    if extra_vars:
        vars_dict.update(extra_vars)

    def _replacer(match):
        key = match.group(1)
        return vars_dict.get(key, match.group(0))

    return _TEMPLATE_RE.sub(_replacer, text)
