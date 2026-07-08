"""
===============================================================================
PyRIT Red Team — 转换器注册表 & 攻击组合配置
===============================================================================
PyRIT 框架使用策略:
  ✅ 所有自定义转换器继承 pyrit.prompt_converter.PromptConverter
  ✅ 编码混淆类转换器优先使用 PyRIT 原生类（Base64/ROT13/Caesar/...共20+个）
  ✅ sync_pyrit_converters() 运行时自动同步 PyRIT 内置转换器
  ✅ 转换器实例化通过 CONVERTER_REGISTRY → resolve_converters() 统一管理
  ✅ CONVERTER_MAP 保持向后兼容（代理到 CONVERTER_REGISTRY）

扩展机制（渗透场景最小化改动原则）:
  1. 运行时注册: register_converter("名称", 工厂函数) — 不改任何现有文件
  2. 组合注册:   register_combo({"name": "...", "converters": [...]})
  3. 自动发现:   discover_converters("converters/") — 扫描 package 下 PromptConverter 子类
  4. 路径发现:   discover_converters_from_path("./my_dir/") — 扫描任意文件系统路径
  5. PyRIT 同步: sync_pyrit_converters() — 自动注册 PyRIT 原生转换器

分类体系:
  encoding      - 编码类（Base64/Binary/Morse/Braille/Atbash/...）
  obfuscation   - 混淆类（Leetspeak/Unicode/Zalgo/CharSwap/Flip/...）
  jailbreak     - 越狱前缀类（PAIR/DAN/AIM/Academic/Developer/...）
  injection     - 注入类（Suffix 追加/JSON 劫持/...）
  bypass        - 绕过类（Translation/DeepInception/FewShot/...）
  reasoning     - 推理/宪法类（CoT 提取/宪法越狱/...）
  meta          - 元转换器（SelectiveText/...）
  llm_based     - LLM 驱动类（Translation/Variation/Tone/...）
  multimodial   - 多模态类（音频/图像/视频/文件）
  pyrit_native  - PyRIT 原生自动发现（sync 时自动归类）
  custom        - 动态注册（register_converter/discover 默认分类）

包含:
- CONVERTER_REGISTRY: 转换器名称 → {factory, category, requires_llm, description} 映射
- CONVERTER_MAP: 向后兼容代理，名称 → 工厂函数（自动从 REGISTRY 衍生）
- GLOBAL_ATTACK_COMBINATIONS: 预定义攻击组合列表
- register_converter(): 运行时动态注册新转换器
- register_combo(): 运行时动态注册新攻击组合
- discover_converters(): 自动扫描 Python package 发现新转换器
- discover_converters_from_path(): 自动扫描文件系统路径发现新转换器
- sync_pyrit_converters(): 自动同步 PyRIT 原生未注册转换器
- resolve_converters(): 名称字符串 → 实例化转换器链
- get_converters_by_category(): 按分类查询转换器
- list_converter_names(): 列出所有已注册转换器名称
===============================================================================
"""
import importlib
import importlib.util
import inspect
import logging
import os
import pkgutil
from typing import Callable, Dict, List

from pyrit.prompt_converter import PromptConverter

# ═══════════════════════════════════════════════════════════════════════════
# 元数据常量
# ═══════════════════════════════════════════════════════════════════════════

CATEGORY_ENCODING     = "encoding"
CATEGORY_OBFUSCATION  = "obfuscation"
CATEGORY_JAILBREAK    = "jailbreak"
CATEGORY_INJECTION    = "injection"
CATEGORY_BYPASS       = "bypass"
CATEGORY_REASONING    = "reasoning"
CATEGORY_META         = "meta"
CATEGORY_LLM_BASED    = "llm_based"
CATEGORY_PYRIT_NATIVE = "pyrit_native"
CATEGORY_CUSTOM       = "custom"

_log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# 懒加载辅助
# ═══════════════════════════════════════════════════════════════════════════

def _lazy_factory(module_path: str, class_name: str, **init_kwargs) -> Callable[[], PromptConverter]:
    """返回一个懒加载工厂函数，首次调用时才 import 并实例化。

    Args:
        module_path: 模块路径，如 "converters.jailbreak"
        class_name: 类名，如 "PAIRJailbreakConverter"
        **init_kwargs: 可选构造参数
    """
    def _factory():
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        return cls(**init_kwargs)
    return _factory


# ═══════════════════════════════════════════════════════════════════════════
# 转换器注册表（带分类/元数据）
# ═══════════════════════════════════════════════════════════════════════════

CONVERTER_REGISTRY: Dict[str, dict] = {}


def _register(name: str, factory: Callable[[], PromptConverter], category: str,
              requires_llm: bool = False, description: str = "") -> None:
    """内部注册辅助。"""
    CONVERTER_REGISTRY[name] = {
        "factory": factory,
        "category": category,
        "requires_llm": requires_llm,
        "description": description or name,
    }


# ── PyRIT 原生编码转换器（10 → 扩展至 20+） ──

# 引入所有高频 PyRIT 原生转换器（懒加载，模块被 import 时才解析 import）
_converter_imports = {
    # Tier 0 — 已有
    "Base64Converter":              ("pyrit.prompt_converter", CATEGORY_ENCODING, "Base64 编码"),
    "ROT13Converter":               ("pyrit.prompt_converter", CATEGORY_ENCODING, "ROT13 凯撒密码"),
    "CaesarConverter":              ("pyrit.prompt_converter", CATEGORY_ENCODING, "凯撒密码（偏移可配）"),
    "LeetspeakConverter":           ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "Leetspeak 字符替换"),
    "UnicodeConfusableConverter":   ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "Unicode 同形字符替换"),
    "ZeroWidthConverter":           ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "零宽字符隐写"),
    "MorseConverter":               ("pyrit.prompt_converter", CATEGORY_ENCODING, "摩尔斯电码"),
    "AsciiArtConverter":            ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "ASCII Art 字体"),
    "CharSwapConverter":            ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "相邻字符交换"),
    "StringJoinConverter":          ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "分隔符拼接"),

    # Tier 1 — 本次新增（零依赖编码混淆，高红队价值）
    "ZalgoConverter":               ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "Zalgo 变音符号叠加"),
    "UnicodeSubstitutionConverter": ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "Unicode Tag 替换（U+E0000）"),
    "BinaryConverter":              ("pyrit.prompt_converter", CATEGORY_ENCODING, "二进制编码"),
    "AtbashConverter":              ("pyrit.prompt_converter", CATEGORY_ENCODING, "Atbash 字母反转密码"),
    "BrailleConverter":             ("pyrit.prompt_converter", CATEGORY_ENCODING, "盲文 Unicode 编码"),
    "FlipConverter":                ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "字符反转"),
    "EmojiConverter":               ("pyrit.prompt_converter", CATEGORY_ENCODING, "Emoji 符号编码"),
    "RandomCapitalLettersConverter":("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "随机大小写"),

    # Tier 2 — 零依赖高级变换
    "CharacterSpaceConverter":      ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "字符间距/标点移除"),
    "DiacriticConverter":           ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "变音符号（尖音/抑音）"),
    "FirstLetterConverter":         ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "首字母缩写"),
    "InsertPunctuationConverter":   ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "标点插入"),
    "SuperScriptConverter":         ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "上标字符转换"),
    "NatoConverter":                ("pyrit.prompt_converter", CATEGORY_ENCODING, "NATO 音标字母"),
    "Base2048Converter":            ("pyrit.prompt_converter", CATEGORY_ENCODING, "Base2048 高密度编码"),
    "EcojiConverter":               ("pyrit.prompt_converter", CATEGORY_ENCODING, "Ecoji Emoji 编码"),
    "UrlConverter":                 ("pyrit.prompt_converter", CATEGORY_ENCODING, "URL 百分号编码"),
    "JsonStringConverter":          ("pyrit.prompt_converter", CATEGORY_ENCODING, "JSON 字符串转义"),
    "SearchReplaceConverter":       ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "正则查找替换"),
    "VariationSelectorSmugglerConverter": ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "Unicode 异体选择器隐写"),
    "ColloquialWordswapConverter":  ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "口语化词汇替换"),

    # Tier 2 — 高层攻击（零 LLM 依赖）
    "CodeChameleonConverter":       ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "代码函数加密包装"),
    "MathObfuscationConverter":     ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "代数恒等式编码"),
    "AskToDecodeConverter":         ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "解码请求包装（组合器）"),
    "TemplateSegmentConverter":     ("pyrit.prompt_converter", CATEGORY_META, "模板分段越狱"),
    "SelectiveTextConverter":       ("pyrit.prompt_converter", CATEGORY_META, "选择性文本转换（元转换器）"),
    "RepeatTokenConverter":         ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "Token 重复攻击"),
    "TenseConverter":               ("pyrit.prompt_converter", CATEGORY_OBFUSCATION, "时态转换"),
}

for _conv_name, (_mod_path, _cat, _desc) in _converter_imports.items():
    _register(_conv_name, _lazy_factory(_mod_path, _conv_name), _cat, description=_desc)

# Caesar 需要特殊处理（有构造参数 offset）
CONVERTER_REGISTRY["CaesarConverter"]["factory"] = _lazy_factory(
    "pyrit.prompt_converter", "CaesarConverter", caesar_offset=3
)

# ── 自定义越狱前缀类转换器（懒加载） ──

_jailbreak_converters = {
    "RoleplayJailbreakConverter": ("converters.jailbreak", CATEGORY_JAILBREAK, "DAN 6.0 精简版角色扮演越狱"),
    "ContextualPrimingConverter": ("converters.jailbreak", CATEGORY_JAILBREAK, "学术研究身份伪装"),
    "PAIRJailbreakConverter":     ("converters.jailbreak", CATEGORY_JAILBREAK, "JB 基准黑盒攻击 Top1，迭代反驳引导"),
    "DAN6FullJailbreakConverter": ("converters.jailbreak", CATEGORY_JAILBREAK, "DAN 6.0 完整版，通用保底方案"),
    "AIMJailbreakConverter":      ("converters.jailbreak", CATEGORY_JAILBREAK, "强逻辑诱导型，无道德约束全能专家"),
    "AcademicResearchConverter":  ("converters.jailbreak", CATEGORY_JAILBREAK, "合规伪装 Top1，学术研究身份掩护"),
    "DeveloperModeConverter":     ("converters.jailbreak", CATEGORY_JAILBREAK, "调试模式心理暗示绕过安全过滤"),
    "ManyShotJailbreakConverter": ("converters.jailbreak", CATEGORY_JAILBREAK, "Many-shot 上下文淹没攻击 (Anthropic 2024)"),
    "FlipAttackConverter":        ("converters.jailbreak", CATEGORY_JAILBREAK, "FlipAttack 角色翻转攻击"),
}

for _conv_name, (_mod_path, _cat, _desc) in _jailbreak_converters.items():
    _register(_conv_name, _lazy_factory(_mod_path, _conv_name), _cat, description=_desc)

# ── 自定义注入类转换器 ──

_injection_converters = {
    "SuffixAppendConverter":              ("converters.injection", CATEGORY_INJECTION, "指令覆盖后缀注入"),
    "JSONStructuredOutputHijackConverter":("converters.injection", CATEGORY_INJECTION, "JSON 结构化输出劫持"),
}

for _conv_name, (_mod_path, _cat, _desc) in _injection_converters.items():
    _register(_conv_name, _lazy_factory(_mod_path, _conv_name), _cat, description=_desc)

# ── 自定义绕过类转换器 ──

_bypass_converters = {
    "TranslationBypassConverter": ("converters.bypass", CATEGORY_BYPASS, "低资源语言翻译绕过（Zulu/Xhosa）"),
    "DeepInceptionConverter":    ("converters.bypass", CATEGORY_BYPASS, "深度嵌套场景越狱（梦中梦）"),
    "FewShotPrimingConverter":   ("converters.bypass", CATEGORY_BYPASS, "Few-shot 上下文学习行为引导"),
}

for _conv_name, (_mod_path, _cat, _desc) in _bypass_converters.items():
    _register(_conv_name, _lazy_factory(_mod_path, _conv_name), _cat, description=_desc)

# ── 自定义推理/宪法类转换器 ──

_reasoning_converters = {
    "CoTReasoningExtractionConverter":("converters.reasoning", CATEGORY_REASONING, "CoT 思维链推理提取"),
    "ConstitutionJailbreakConverter": ("converters.reasoning", CATEGORY_REASONING, "宪法矛盾越狱（Anthropic Constitutional AI）"),
}

for _conv_name, (_mod_path, _cat, _desc) in _reasoning_converters.items():
    _register(_conv_name, _lazy_factory(_mod_path, _conv_name), _cat, description=_desc)

# ── 🆕 P0+P1+P2 新增分类 ──
CATEGORY_RAG_POISONING = "rag_poisoning"
CATEGORY_EMBEDDING     = "embedding"
CATEGORY_TRAINING      = "training_poisoning"
CATEGORY_MULTIMODAL     = "multimodal"

# ── 🆕 RAG 知识库投毒转换器 ──
_register(
    "RAGPoisoningConverter",
    _lazy_factory("converters.rag_poisoning", "RAGPoisoningConverter",
                  strategy=None, num_documents=5),
    CATEGORY_RAG_POISONING,
    description="PoisonedRAG 黑盒知识库投毒 (USENIX 2025)"
)
_register(
    "RAGPoisoningAuthorityConverter",
    _lazy_factory("converters.rag_poisoning", "RAGPoisoningConverter",
                  strategy=None, num_documents=5),
    CATEGORY_RAG_POISONING,
    description="PoisonedRAG 权威角色伪装投毒"
)
# ── 🆕 Embedding 对抗攻击转换器 ──
_register(
    "EmbeddingAdversarialConverter",
    _lazy_factory("converters.embedding_attack", "EmbeddingAdversarialAttack",
                  technique=None, intensity=0.3),
    CATEGORY_EMBEDDING,
    description="Embedding 对抗攻击 - 同义词替换 (OWASP LLM08)"
)
_register(
    "EmbeddingKeywordStuffingConverter",
    _lazy_factory("converters.embedding_attack", "EmbeddingAdversarialAttack",
                  technique=None, intensity=0.5),
    CATEGORY_EMBEDDING,
    description="Embedding 对抗攻击 - RAG 关键词填充"
)

# ── 🆕 多模态攻击转换器 ──
_register(
    "MultimodalAttackConverter",
    _lazy_factory("executor.sequence_attack", "MultimodalAttackConverter",
                  technique="image_description"),
    CATEGORY_MULTIMODAL,
    description="多模态攻击 - 图片描述注入 (VLGuard)"
)

# ── 🆕 训练数据投毒转换器 ──
_register(
    "TrainingPoisoningConverter",
    _lazy_factory("executor.sequence_attack", "TrainingPoisoningConverter",
                  technique="backdoor"),
    CATEGORY_TRAINING,
    description="训练数据投毒 - Backdoor Trigger (OWASP LLM03)"
)

# ═══════════════════════════════════════════════════════════════════════════
# 向后兼容代理 — CONVERTER_MAP
# ═══════════════════════════════════════════════════════════════════════════

class _ConverterMapProxy(dict):
    """CONVERTER_MAP 向后兼容代理：自动从 CONVERTER_REGISTRY 衍生。

    支持:
      - CONVERTER_MAP[name]           → factory
      - name in CONVERTER_MAP         → bool
      - len(CONVERTER_MAP)            → int
      - CONVERTER_MAP.get(name)       → factory | None
      - 迭代 / .keys() / .values() / .items()
    """

    def __getitem__(self, key):
        return CONVERTER_REGISTRY[key]["factory"]

    def __contains__(self, key):
        return key in CONVERTER_REGISTRY

    def __len__(self):
        return len(CONVERTER_REGISTRY)

    def __iter__(self):
        return iter(CONVERTER_REGISTRY)

    def get(self, key, default=None):
        info = CONVERTER_REGISTRY.get(key)
        return info["factory"] if info else default

    def keys(self):
        return CONVERTER_REGISTRY.keys()

    def values(self):
        return (info["factory"] for info in CONVERTER_REGISTRY.values())

    def items(self):
        return ((k, info["factory"]) for k, info in CONVERTER_REGISTRY.items())

    def __repr__(self):
        return f"<ConverterMapProxy: {len(self)} converters>"


CONVERTER_MAP = _ConverterMapProxy()


# ═══════════════════════════════════════════════════════════════════════════
# 动态扩展 API
# ═══════════════════════════════════════════════════════════════════════════

def register_converter(name: str, factory: Callable[[], PromptConverter],
                       category: str = CATEGORY_CUSTOM,
                       requires_llm: bool = False,
                       description: str = "") -> None:
    """运行时动态注册新转换器（渗透场景无需修改任何现有文件）。

    Args:
        name: 转换器名称（与 GLOBAL_ATTACK_COMBINATIONS / JSON 用例中保持一致）
        factory: 无参工厂函数，返回 PromptConverter 实例
        category: 分类标签（默认 "custom"）
        requires_llm: 是否需要 LLM 目标
        description: 可选描述

    Example:
        >>> from pyrit.prompt_converter import PromptConverter, ConverterResult
        >>> class MyNovelJailbreak(PromptConverter):
        ...     async def convert_async(self, *, prompt, input_type="text"):
        ...         return ConverterResult(output_text="[NOVEL] " + prompt, output_type="text")
        >>> register_converter("MyNovelJailbreak", MyNovelJailbreak,
        ...                    category="jailbreak", description="小说角色越狱")
    """
    _register(name, factory, category, requires_llm, description)
    _log.info("动态注册转换器: %s (category=%s)", name, category)


def register_combo(combo: dict) -> None:
    """运行时动态注册新攻击组合。

    Args:
        combo: {"name": "xxx", "converters": ["ConvA", "ConvB"]}

    Example:
        >>> register_combo({"name": "Novel_x_Base64", "converters": ["MyNovelJailbreak", "Base64Converter"]})
    """
    if not isinstance(combo, dict) or "name" not in combo or "converters" not in combo:
        raise ValueError("combo must be dict with 'name' and 'converters' keys")
    GLOBAL_ATTACK_COMBINATIONS.append(combo)


def discover_converters(package_path: str = "converters",
                        target_base: type = PromptConverter) -> int:
    """自动发现 Python package 目录下所有 PromptConverter 子类并注册。

    扫描目标 package 内所有 .py 模块，找出继承自 target_base 的类，
    自动调用 register_converter 注册（跳过已在 CONVERTER_REGISTRY 中的类）。

    Args:
        package_path: Python package 路径（如 "converters" 或 "plugins"）
        target_base: 目标基类（默认 PromptConverter）
    Returns:
        新发现的转换器数量

    Example:
        >>> # 渗透场景：把 custom_jailbreaks.py 放到 converters/ 目录
        >>> discover_converters("converters")  # 自动发现并注册
    """
    discovered = 0
    try:
        package = importlib.import_module(package_path)
        pkg_dir = os.path.dirname(package.__file__) if hasattr(package, "__file__") else None
        if not pkg_dir:
            return 0

        for _, module_name, _ in pkgutil.iter_modules([pkg_dir]):
            if module_name.startswith("_") or module_name in ("registry",):
                continue
            try:
                mod = importlib.import_module(f"{package_path}.{module_name}")
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    if not issubclass(obj, target_base) or obj is target_base:
                        continue
                    if name in CONVERTER_REGISTRY:
                        continue
                    _register(name, obj, CATEGORY_CUSTOM, description=f"自动发现: {module_name}")
                    discovered += 1
            except Exception:
                pass
    except ModuleNotFoundError:
        pass
    return discovered


def discover_converters_from_path(dir_path: str,
                                  target_base: type = PromptConverter,
                                  category: str = CATEGORY_CUSTOM) -> int:
    """自动发现文件系统任意路径下的 PromptConverter 子类并注册。

    不要求目录是 Python package —— 通过 importlib.util 直接加载 .py 文件。
    渗透场景下，从 U 盘/网络路径加载转换器无需修改 PYTHONPATH。

    Args:
        dir_path: 文件系统路径（如 "./my_converters/" 或 "/tmp/exam_plugins/"）
        target_base: 目标基类（默认 PromptConverter）
        category: 分类标签（默认 "custom"）
    Returns:
        新发现的转换器数量

    Example:
        >>> discover_converters_from_path("./exam_converters/")
        3  # 发现了 3 个新转换器
    """
    discovered = 0
    dir_path = os.path.abspath(dir_path)
    if not os.path.isdir(dir_path):
        _log.warning("discover_converters_from_path: 路径不存在 '%s'", dir_path)
        return 0

    for fname in sorted(os.listdir(dir_path)):
        if fname.startswith("_") or not fname.endswith(".py"):
            continue
        mod_name = fname[:-3]
        filepath = os.path.join(dir_path, fname)
        try:
            spec = importlib.util.spec_from_file_location(
                f"redteam_dynamic_converters.{mod_name}", filepath
            )
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if not issubclass(obj, target_base) or obj is target_base:
                    continue
                if name in CONVERTER_REGISTRY:
                    continue
                _register(name, obj, category, description=f"路径发现: {filepath}")
                discovered += 1
        except Exception as e:
            _log.debug("discover_converters_from_path: 跳过 %s: %s", fname, e)
    return discovered


def sync_pyrit_converters(category: str = CATEGORY_PYRIT_NATIVE) -> int:
    """运行时自动扫描 pyrit.prompt_converter 模块，注册所有未覆盖的 PyRIT 原生转换器。

    PyRIT 版本升级新增转换器时，无需修改任何代码 —— 调用此函数即可自动补全。

    Args:
        category: 分类标签（默认 "pyrit_native"）
    Returns:
        新注册的转换器数量

    Example:
        >>> sync_pyrit_converters()  # 自动发现 PyRIT 0.15+ 新增的转换器
        12
    """
    discovered = 0
    try:
        import pyrit.prompt_converter as pc
    except ImportError:
        _log.warning("sync_pyrit_converters: 无法导入 pyrit.prompt_converter")
        return 0

    # 判断是否为 LLM-based：有 prompt_target 参数的转换器需要 LLM
    _llm_based_keywords = ("Translation", "Variation", "Tone", "Noise",
                           "Persuasion", "MaliciousQuestion", "ToxicSentence",
                           "ScientificTranslation", "MathPrompt", "ImagePromptStyle",
                           "RandomTranslation", "Denylist", "Decomposition",
                           "LLMGeneric")

    for name in sorted(dir(pc)):
        if not name.endswith("Converter") or name.startswith("_"):
            continue
        if name in CONVERTER_REGISTRY:
            continue
        if name in ("PromptConverter", "ConverterResult", "ImageConverter",
                     "VideoConverter", "AudioConverter", "CodeChameleonConverter"):
            continue

        cls = getattr(pc, name)
        if not (isinstance(cls, type) and issubclass(cls, PromptConverter)):
            continue
        if cls is PromptConverter:
            continue

        # 自动判断分类
        requires_llm = any(kw in name for kw in _llm_based_keywords)
        _log.info("sync_pyrit_converters: 发现 %s (requires_llm=%s)", name, requires_llm)
        _register(name, cls, category, requires_llm=requires_llm,
                  description=f"PyRIT 内置 (auto-synced): {name}")
        discovered += 1

    return discovered


# ═══════════════════════════════════════════════════════════════════════════
# 查询辅助函数
# ═══════════════════════════════════════════════════════════════════════════

def get_converters_by_category(category: str) -> List[dict]:
    """返回指定分类下所有转换器的元数据列表。

    Args:
        category: 分类标签（如 "encoding", "jailbreak"）
    Returns:
        [{"name": "Base64Converter", "category": "encoding", ...}, ...]
    """
    return [
        {"name": name, **info}
        for name, info in CONVERTER_REGISTRY.items()
        if info["category"] == category
    ]


# ═══════════════════════════════════════════════════════════════════════════
# 全局攻击组合配置
# ═══════════════════════════════════════════════════════════════════════════
# 攻击组合统一使用转换器名称字符串，与JSON用例格式保持一致，统一走resolve_converters加载
# 单轮/多轮通用，多轮模式下每轮用户输入都会应用全部转换器

GLOBAL_ATTACK_COMBINATIONS = [
    # ---------- 纯越狱前缀类 ----------
    {"name": "PAIR_Jailbreak", "converters": ["PAIRJailbreakConverter"]},
    {"name": "DAN6_Full", "converters": ["DAN6FullJailbreakConverter"]},
    {"name": "AIM_Jailbreak", "converters": ["AIMJailbreakConverter"]},
    {"name": "Academic_Research", "converters": ["AcademicResearchConverter"]},
    {"name": "Developer_Mode", "converters": ["DeveloperModeConverter"]},
    {"name": "Roleplay_Jailbreak", "converters": ["RoleplayJailbreakConverter"]},
    {"name": "Contextual_Priming", "converters": ["ContextualPrimingConverter"]},

    # ---------- 越狱 + 编码混淆组合拳（攻坚首选，JB验证成功率提升30%+） ----------
    {"name": "PAIR + Base64", "converters": ["PAIRJailbreakConverter", "Base64Converter"]},
    {"name": "DAN6 + ZeroWidth", "converters": ["DAN6FullJailbreakConverter", "ZeroWidthConverter"]},
    {"name": "AIM + UnicodeConfusable", "converters": ["AIMJailbreakConverter", "UnicodeConfusableConverter"]},
    {"name": "Academic + Base64", "converters": ["AcademicResearchConverter", "Base64Converter"]},
    {"name": "DevMode + ROT13", "converters": ["DeveloperModeConverter", "ROT13Converter"]},
    {"name": "Jailbreak + Base64", "converters": ["RoleplayJailbreakConverter", "Base64Converter"]},
    {"name": "Academic_Priming + ZeroWidth", "converters": ["ContextualPrimingConverter", "ZeroWidthConverter"]},
    # ── PROBE 热力图驱动的组合扩展（2026-07-04） ──
    {"name": "Contextual + Base64", "converters": ["ContextualPrimingConverter", "Base64Converter"]},
    {"name": "Contextual + ROT13", "converters": ["ContextualPrimingConverter", "ROT13Converter"]},
    {"name": "Academic + ZeroWidth", "converters": ["AcademicResearchConverter", "ZeroWidthConverter"]},

    # ---------- 纯编码混淆类 ----------
    {"name": "Base64 + ZeroWidth", "converters": ["Base64Converter", "ZeroWidthConverter"]},
    {"name": "ROT13 + UnicodeConfusable", "converters": ["ROT13Converter", "UnicodeConfusableConverter"]},
    {"name": "Leetspeak + ZeroWidth", "converters": ["LeetspeakConverter", "ZeroWidthConverter"]},
    {"name": "Caesar + Base64", "converters": ["CaesarConverter", "Base64Converter"]},

    # ---------- 三层编码链（攻坚高防御模型） ----------
    {"name": "PAIR + Base64 + ZeroWidth", "converters": ["PAIRJailbreakConverter", "Base64Converter", "ZeroWidthConverter"]},
    {"name": "DAN6 + ROT13 + Unicode", "converters": ["DAN6FullJailbreakConverter", "ROT13Converter", "UnicodeConfusableConverter"]},
    {"name": "AIM + Leetspeak + ZeroWidth", "converters": ["AIMJailbreakConverter", "LeetspeakConverter", "ZeroWidthConverter"]},

    # ---------- 翻译绕过组合 ----------
    {"name": "Translation_Bypass_Zulu", "converters": ["TranslationBypassConverter"]},
    {"name": "Translation + Base64", "converters": ["TranslationBypassConverter", "Base64Converter"]},
    {"name": "Translation + Academic", "converters": ["TranslationBypassConverter", "AcademicResearchConverter"]},

    # ---------- 深度嵌套 & Few-Shot ----------
    {"name": "DeepInception", "converters": ["DeepInceptionConverter"]},
    {"name": "DeepInception + Base64", "converters": ["DeepInceptionConverter", "Base64Converter"]},
    {"name": "FewShot_Priming", "converters": ["FewShotPrimingConverter"]},
    {"name": "FewShot + ZeroWidth", "converters": ["FewShotPrimingConverter", "ZeroWidthConverter"]},

    # ---------- Suffix 追加注入 ----------
    {"name": "Suffix_Injection", "converters": ["SuffixAppendConverter"]},
    {"name": "Suffix + Base64", "converters": ["SuffixAppendConverter", "Base64Converter"]},

    # ---------- 高对抗组合拳（跨类别混合） ----------
    {"name": "DeepInception + ROT13", "converters": ["DeepInceptionConverter", "ROT13Converter"]},
    {"name": "FewShot + Translation", "converters": ["FewShotPrimingConverter", "TranslationBypassConverter"]},
    {"name": "DAN6 + Suffix + Base64", "converters": ["DAN6FullJailbreakConverter", "SuffixAppendConverter", "Base64Converter"]},

    # ---------- 红队渗透专项 — Morse + AsciiArt + CharSwap + StringJoin ----------
    {"name": "PAIR + Morse", "converters": ["PAIRJailbreakConverter", "MorseConverter"]},
    {"name": "DAN6 + AsciiArt", "converters": ["DAN6FullJailbreakConverter", "AsciiArtConverter"]},
    {"name": "AIM + CharSwap", "converters": ["AIMJailbreakConverter", "CharSwapConverter"]},
    {"name": "Academic + StringJoin", "converters": ["AcademicResearchConverter", "StringJoinConverter"]},
    # ── 编码混淆扩展 ──
    {"name": "Morse + ZeroWidth", "converters": ["MorseConverter", "ZeroWidthConverter"]},
    {"name": "AsciiArt + Base64", "converters": ["AsciiArtConverter", "Base64Converter"]},
    {"name": "CharSwap + ROT13", "converters": ["CharSwapConverter", "ROT13Converter"]},

    # ---------- PROBE 热力图驱动组合扫描（2026-07-04） ----------
    {"name": "Academic + Roleplay", "converters": ["AcademicResearchConverter", "RoleplayJailbreakConverter"]},
    {"name": "Contextual + Suffix", "converters": ["ContextualPrimingConverter", "SuffixAppendConverter"]},
    {"name": "Double_Academic", "converters": ["AcademicResearchConverter", "ContextualPrimingConverter"]},

    # ── 三层高强度编码链（攻坚高防御/渗透重点模型） ──
    {"name": "DAN6 + ROT13 + ZeroWidth", "converters": ["DAN6FullJailbreakConverter", "ROT13Converter", "ZeroWidthConverter"]},
    {"name": "AIM + Morse + Suffix", "converters": ["AIMJailbreakConverter", "MorseConverter", "SuffixAppendConverter"]},
    {"name": "Academic + Leetspeak + Unicode", "converters": ["AcademicResearchConverter", "LeetspeakConverter", "UnicodeConfusableConverter"]},
    {"name": "DeepInception + ROT13 + ZeroWidth", "converters": ["DeepInceptionConverter", "ROT13Converter", "ZeroWidthConverter"]},
    {"name": "Roleplay + AsciiArt + Base64", "converters": ["RoleplayJailbreakConverter", "AsciiArtConverter", "Base64Converter"]},
    {"name": "DeveloperMode + CharSwap + ROT13", "converters": ["DeveloperModeConverter", "CharSwapConverter", "ROT13Converter"]},
    {"name": "Contextual + StringJoin + Base64", "converters": ["ContextualPrimingConverter", "StringJoinConverter", "Base64Converter"]},

    # ── 跨界混合组合（越狱 × 翻译 × 编码） ──
    {"name": "Translation + Morse + Base64", "converters": ["TranslationBypassConverter", "MorseConverter", "Base64Converter"]},
    {"name": "FewShot + CharSwap + ROT13", "converters": ["FewShotPrimingConverter", "CharSwapConverter", "ROT13Converter"]},
    {"name": "DeepInception + AsciiArt + Suffix", "converters": ["DeepInceptionConverter", "AsciiArtConverter", "SuffixAppendConverter"]},

    # ── CoT 推理提取 / 宪法越狱 / 结构化输出劫持 ──
    {"name": "CoT_Reasoning_Extract", "converters": ["CoTReasoningExtractionConverter"]},
    {"name": "CoT + Base64", "converters": ["CoTReasoningExtractionConverter", "Base64Converter"]},
    {"name": "CoT + ZeroWidth", "converters": ["CoTReasoningExtractionConverter", "ZeroWidthConverter"]},
    {"name": "Constitution_Jailbreak", "converters": ["ConstitutionJailbreakConverter"]},
    {"name": "Constitution + Base64", "converters": ["ConstitutionJailbreakConverter", "Base64Converter"]},
    {"name": "Constitution + ROT13 + Unicode", "converters": ["ConstitutionJailbreakConverter", "ROT13Converter", "UnicodeConfusableConverter"]},
    {"name": "JSON_Output_Hijack", "converters": ["JSONStructuredOutputHijackConverter"]},
    {"name": "JSON_Hijack + Base64", "converters": ["JSONStructuredOutputHijackConverter", "Base64Converter"]},
    {"name": "JSON_Hijack + ZeroWidth", "converters": ["JSONStructuredOutputHijackConverter", "ZeroWidthConverter"]},

    # ── 低资源语言 × 编码混淆增强 ──
    {"name": "Translation + CharSwap + ZeroWidth", "converters": ["TranslationBypassConverter", "CharSwapConverter", "ZeroWidthConverter"]},
    {"name": "Translation + AsciiArt + Base64", "converters": ["TranslationBypassConverter", "AsciiArtConverter", "Base64Converter"]},

    # ── 🆕 ManyShot / FlipAttack / SkeletonKey 2025-2026 前沿攻击面 ──
    {"name": "ManyShot_Jailbreak", "converters": ["ManyShotJailbreakConverter"]},
    {"name": "ManyShot + Base64", "converters": ["ManyShotJailbreakConverter", "Base64Converter"]},
    {"name": "ManyShot + ZeroWidth", "converters": ["ManyShotJailbreakConverter", "ZeroWidthConverter"]},
    {"name": "ManyShot + ROT13 + ZeroWidth", "converters": ["ManyShotJailbreakConverter", "ROT13Converter", "ZeroWidthConverter"]},
    {"name": "FlipAttack", "converters": ["FlipAttackConverter"]},
    {"name": "Flip + Base64", "converters": ["FlipAttackConverter", "Base64Converter"]},
    {"name": "Flip + ROT13 + ZeroWidth", "converters": ["FlipAttackConverter", "ROT13Converter", "ZeroWidthConverter"]},
    {"name": "ManyShot + FlipAttack", "converters": ["ManyShotJailbreakConverter", "FlipAttackConverter"]},

    # ── 🆕 RAG 知识库投毒 (PoisonedRAG) + Embedding 对抗 ──
    {"name": "RAG_Poison_BlackBox", "converters": ["RAGPoisoningConverter"]},
    {"name": "RAG_Poison_Authority", "converters": ["RAGPoisoningAuthorityConverter"]},
    {"name": "RAG_Poison + Base64", "converters": ["RAGPoisoningConverter", "Base64Converter"]},
    {"name": "Embedding_SynonymSwap", "converters": ["EmbeddingAdversarialConverter"]},
    {"name": "Embedding_KeywordStuffing", "converters": ["EmbeddingKeywordStuffingConverter"]},
    {"name": "Embedding + PAIR", "converters": ["EmbeddingAdversarialConverter", "PAIRJailbreakConverter"]},

    # ── 🆕 多模态攻击 + 训练数据投毒 ──
    {"name": "Multimodal_ImageDesc", "converters": ["MultimodalAttackConverter"]},
    {"name": "Multimodal + Base64", "converters": ["MultimodalAttackConverter", "Base64Converter"]},
    {"name": "Training_Poison_Backdoor", "converters": ["TrainingPoisoningConverter"]},
    {"name": "Training_Poison + RAG", "converters": ["TrainingPoisoningConverter", "RAGPoisoningConverter"]},
]

# ═══════════════════════════════════════════════════════════════════════════
# 转换器解析器
# ═══════════════════════════════════════════════════════════════════════════


def resolve_converters(converter_names: list) -> list:
    """将转换器名称字符串列表解析为实例列表。

    查找优先级: CONVERTER_REGISTRY（含动态注册）→ 警告跳过未找到的名称。
    渗透场景下，动态注册的转换器无需修改任何现有代码即可被 resolve。

    向后兼容: 同时检查 CONVERTER_MAP 代理和 CONVERTER_REGISTRY。
    """
    instances = []
    for name in converter_names:
        info = CONVERTER_REGISTRY.get(name)
        if info is not None:
            instances.append(info["factory"]())
        else:
            _log.warning("转换器 '%s' 未在 CONVERTER_REGISTRY 中找到，已跳过", name)
    return instances
