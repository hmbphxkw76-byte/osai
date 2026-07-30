"""
Converter Transformation Log & Variant Preview
==============================================

方案B: Converter Transformation Log — 后处理重转换，展示转换链中间步骤
方案C: Converter Variant Preview — 独立变体预览，展示单个转换器效果
命名一致性: snake_case ↔ PascalCase 攻击类型名映射
报告增强: 从 identifier.children 提取 converter chain info 当 labels 缺失时

设计原则（L5 对齐）:
- 不修改 PyRIT 核心执行路径
- 使用 PyRIT 原生 Converter.convert_async() 进行后处理重转换
- 非 LLM 转换器可本地执行（确定性，无需 API 调用）
- LLM 转换器需要 converter_target（可选，缺失时标注为 "需 LLM"）
- 数据驱动：从 AttackResult → identifier.children → converter 类名 → chain name

数据流:
  管线 Stage 2 StrategySelection → attack_techniques (snake_case)
  管线 Stage 5 Matching → converter_chains (chain names)
  管线 Stage 6 Execute → AttackResult with identifier.children["request_converters"]
  报告生成 → 从 identifier 提取 converter 信息 → 转换日志 + 变体预览
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from src.core.config_loader import get_config_loader
from src.scenarios.technique_factories import CONVERTER_VARIANT_CHAINS

logger = logging.getLogger(__name__)


# ============================================================
# 1. 命名一致性: snake_case ↔ PascalCase 映射
# ============================================================

#: snake_case 技术名 → PascalCase 攻击类名映射
TECHNIQUE_NAME_MAP: Dict[str, str] = {
    "prompt_sending": "PromptSendingAttack",
    "multi_prompt_sending": "MultiPromptSendingAttack",
    "many_shot": "ManyShotJailbreakAttack",
    "skeleton": "SkeletonKeyAttack",
    "chunked_request": "ChunkedRequestAttack",
    "red_teaming": "RedTeamingAttack",
    "crescendo": "CrescendoAttack",
    "crescendo_simulated": "CrescendoAttack",
    "tap": "TAPAttack",
    "pair": "PAIRAttack",
    "tree_of_attacks_pruned": "TreeOfAttacksWithPruningAttack",
    "sequential": "SequentialAttack",
}

#: PascalCase 攻击类名 → snake_case 技术名映射（反向）
PASCAL_TO_SNAKE: Dict[str, str] = {}
for _snake, _pascal in TECHNIQUE_NAME_MAP.items():
    if _pascal not in PASCAL_TO_SNAKE:
        PASCAL_TO_SNAKE[_pascal] = _snake


def get_attack_class_name(technique_name: str) -> str:
    """将 snake_case 技术名映射为 PascalCase 攻击类名

    用于预执行展示中同时显示两种命名形式，消除命名不一致。

    Args:
        technique_name: snake_case 技术名 (如 "prompt_sending")

    Returns:
        PascalCase 攻击类名 (如 "PromptSendingAttack")，
        如果映射不存在则原样返回
    """
    return TECHNIQUE_NAME_MAP.get(technique_name, technique_name)


def get_technique_name(class_name: str) -> str:
    """将 PascalCase 攻击类名映射为 snake_case 技术名

    Args:
        class_name: PascalCase 攻击类名 (如 "PromptSendingAttack")

    Returns:
        snake_case 技术名 (如 "prompt_sending")，
        如果映射不存在则原样返回
    """
    return PASCAL_TO_SNAKE.get(class_name, class_name)


def format_technique_display(technique_name: str) -> str:
    """格式化技术名显示（同时展示 snake_case 和 PascalCase）

    用于预执行展示，消除命名不一致。

    Args:
        technique_name: snake_case 技术名

    Returns:
        格式化字符串 "snake_case (PascalCase)"
    """
    class_name = get_attack_class_name(technique_name)
    if class_name != technique_name:
        return f"{technique_name} ({class_name})"
    return technique_name


# ============================================================
# 2. 从 AttackResult 提取 Converter 信息（报告增强）
# ============================================================


def extract_converter_info_from_result(attack_result: Any) -> Dict[str, Any]:
    """从 AttackResult 提取 Converter 信息

    当 labels 中没有 converter_chain_name 时，从 identifier.children
    提取 converter 类名列表，并尝试反向映射到 chain name。

    数据流:
      AttackResult.get_attack_strategy_identifier()
        → identifier.children["request_converters"]
        → [ConverterIdentifier.class_name, ...]
        → 反向匹配 → chain_name

    Args:
        attack_result: PyRIT AttackResult 实例

    Returns:
        包含以下字段的字典:
        - converter_class_names: List[str] — converter 类名列表
        - converter_chain_name: Optional[str] — 匹配到的 chain name
        - has_converters: bool — 是否使用了 converter
    """
    result: Dict[str, Any] = {
        "converter_class_names": [],
        "converter_chain_name": None,
        "has_converters": False,
    }

    # 优先从 labels 获取
    labels = getattr(attack_result, "labels", None) or {}
    if isinstance(labels, dict):
        chain_name = labels.get("converter_chain_name")
        if chain_name:
            result["converter_chain_name"] = chain_name
            result["has_converters"] = True
            # 同时尝试获取 converter 类名
            class_names_str = labels.get("converter_class_names", "")
            if class_names_str:
                result["converter_class_names"] = [
                    n.strip() for n in class_names_str.split(",") if n.strip()
                ]
            return result

    # 从 identifier.children 提取（PyRIT 原生 API）
    identifier = None
    if hasattr(attack_result, "get_attack_strategy_identifier"):
        try:
            identifier = attack_result.get_attack_strategy_identifier()
        except Exception:
            pass

    if identifier is not None:
        class_names = _extract_converter_class_names_from_identifier(identifier)
        if class_names:
            result["converter_class_names"] = class_names
            result["has_converters"] = True
            # 尝试反向匹配 chain name
            chain_name = _match_chain_by_converter_names(class_names)
            if chain_name:
                result["converter_chain_name"] = chain_name

    # SequentialAttackResult: 检查子结果
    if not result["has_converters"]:
        child_results = getattr(attack_result, "child_attack_results", None) or []
        for child in child_results:
            if child is None:
                continue
            child_info = extract_converter_info_from_result(child)
            if child_info["has_converters"]:
                result["converter_class_names"].extend(
                    child_info["converter_class_names"]
                )
                if child_info["converter_chain_name"] and not result["converter_chain_name"]:
                    result["converter_chain_name"] = child_info["converter_chain_name"]
                result["has_converters"] = True

    # 去重
    result["converter_class_names"] = list(dict.fromkeys(result["converter_class_names"]))

    return result


def _extract_converter_class_names_from_identifier(identifier: Any) -> List[str]:
    """从 ComponentIdentifier 提取 Converter 类名列表

    PyRIT 原生 API:
      identifier.children["request_converters"] = [ConverterIdentifier, ...]
      ConverterIdentifier.class_name = "Base64Converter" 等

    Args:
        identifier: AttackResult 的 ComponentIdentifier

    Returns:
        Converter 类名列表
    """
    class_names: List[str] = []
    children = getattr(identifier, "children", None) or {}

    # request_converters
    req_converters = children.get("request_converters")
    if req_converters:
        if isinstance(req_converters, list):
            for conv_id in req_converters:
                cn = getattr(conv_id, "class_name", "")
                if cn:
                    class_names.append(cn)
        else:
            cn = getattr(req_converters, "class_name", "")
            if cn:
                class_names.append(cn)

    # response_converters
    resp_converters = children.get("response_converters")
    if resp_converters:
        if isinstance(resp_converters, list):
            for conv_id in resp_converters:
                cn = getattr(conv_id, "class_name", "")
                if cn:
                    class_names.append(cn)

    return class_names


def _match_chain_by_converter_names(class_names: List[str]) -> Optional[str]:
    """通过 converter 类名列表反向匹配 chain name

    遍历所有已知的 converter chain 配置，加载每个 chain 的 converter 列表，
    比较类名集合是否匹配。

    Args:
        class_names: Converter 类名列表 (如 ["Base64Converter", "ROT13Converter"])

    Returns:
        匹配的 chain name，如果无法匹配则返回 None
    """
    if not class_names:
        return None

    target_set = frozenset(class_names)
    config_loader = get_config_loader()

    for chain_name in CONVERTER_VARIANT_CHAINS:
        try:
            chain_config = config_loader.get_converter_chain_config(chain_name)
            if chain_config is None:
                continue

            raw_converters = chain_config.get("converters", [])
            chain_class_names = []
            for item in raw_converters:
                if isinstance(item, str):
                    chain_class_names.append(item)
                elif isinstance(item, dict) and item.get("name"):
                    chain_class_names.append(item["name"])

            if frozenset(chain_class_names) == target_set:
                return chain_name
        except Exception:
            continue

    return None


# ============================================================
# 3. 方案B: Converter Transformation Log（后处理重转换）
# ============================================================


class ConverterTransformationLog:
    """
    Converter 转换日志 — 后处理重转换，展示转换链中间步骤

    方案B 实现：
    - 从 AttackResult 提取原始文本（第一条 user 消息的 original_value）
    - 加载 converter chain 配置，创建 converter 实例
    - 依次应用每个 converter，记录每步的输入/输出
    - 非 LLM converter 可本地执行；LLM converter 需要可选的 converter_target

    数据流:
      AttackResult → conversation → first user message → original text
      chain_name → YAML config → converter instances → sequential apply
      → [(step_idx, converter_name, input_text, output_text), ...]

    设计原则:
    - 不修改 PyRIT 核心执行路径
    - 使用 PyRIT 原生 Converter.convert_async() API
    - 非 LLM 转换器确定性执行（无需 API 调用）
    - LLM 转换器可选执行（需要 converter_target）
    """

    def __init__(
        self,
        chain_name: str,
        converter_target: Any = None,
    ):
        """
        初始化转换日志

        Args:
            chain_name: Converter 链名称 (如 "stealth_evasion")
            converter_target: 可选的 LLM Target（用于 LLM 转换器）
        """
        self.chain_name = chain_name
        self.converter_target = converter_target
        self._chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
        self._converter_instances: List[Any] = []
        self._converter_names: List[str] = []
        self._requires_llm: List[bool] = []
        self._loaded = False

    def _load_converters(self) -> None:
        """加载 converter 实例"""
        if self._loaded:
            return

        from src.converters.converter_registry import create_converter_instance

        config_loader = get_config_loader()
        chain_config = config_loader.get_converter_chain_config(self.chain_name)

        if chain_config is None:
            logger.warning(f"Converter chain '{self.chain_name}' not found in config")
            self._loaded = True
            return

        raw_converters = chain_config.get("converters", [])
        converter_params = chain_config.get("params", {})

        for item in raw_converters:
            if isinstance(item, str):
                name = item
            elif isinstance(item, dict) and item.get("name"):
                name = item["name"]
            elif isinstance(item, dict) and item.get("selective"):
                name = f"_selective_{item.get('sub_converter', 'unknown')}"
            else:
                continue

            params = converter_params.get(name, {})
            if isinstance(params, dict):
                params.pop("_pre_built_instance", None)

            try:
                instance = create_converter_instance(
                    name,
                    converter_target=self.converter_target,
                    **params if isinstance(params, dict) else {},
                )
                self._converter_instances.append(instance)
                self._converter_names.append(name)
                self._requires_llm.append(
                    hasattr(instance, "converter_target")
                    and getattr(instance, "converter_target", None) is not None
                )
            except Exception as e:
                logger.warning(f"Failed to create converter '{name}': {e}")
                self._converter_names.append(name)
                self._requires_llm.append(False)
                self._converter_instances.append(None)

        self._loaded = True

    async def generate_log(self, original_text: str) -> List[Dict[str, Any]]:
        """
        生成转换日志

        依次应用 chain 中的每个 converter，记录每步的输入/输出。

        Args:
            original_text: 原始文本（攻击载荷的原始内容）

        Returns:
            转换步骤列表，每个步骤包含:
            - step: 步骤序号 (0 = 原始文本, 1 = 第一个 converter 后, ...)
            - converter_name: converter 名称
            - converter_class: converter 类名
            - requires_llm: 是否需要 LLM
            - input_text: 输入文本
            - output_text: 输出文本
            - skipped: 是否跳过（LLM 转换器无 target 时跳过）
        """
        self._load_converters()

        steps: List[Dict[str, Any]] = []

        # Step 0: 原始文本
        steps.append({
            "step": 0,
            "converter_name": "(original)",
            "converter_class": "—",
            "requires_llm": False,
            "input_text": "",
            "output_text": original_text,
            "skipped": False,
        })

        current_text = original_text

        for i, (instance, name) in enumerate(
            zip(self._converter_instances, self._converter_names), 1
        ):
            needs_llm = self._requires_llm[i - 1] if i - 1 < len(self._requires_llm) else False

            if instance is None:
                steps.append({
                    "step": i,
                    "converter_name": name,
                    "converter_class": "(failed to create)",
                    "requires_llm": needs_llm,
                    "input_text": current_text,
                    "output_text": "(converter creation failed)",
                    "skipped": True,
                })
                continue

            # LLM 转换器无 target 时跳过
            if needs_llm and self.converter_target is None:
                steps.append({
                    "step": i,
                    "converter_name": name,
                    "converter_class": type(instance).__name__,
                    "requires_llm": True,
                    "input_text": current_text,
                    "output_text": "(requires LLM — preview not available)",
                    "skipped": True,
                })
                continue

            # 执行转换
            try:
                result = await instance.convert_async(prompt=current_text)
                output_text = result.output_text
                steps.append({
                    "step": i,
                    "converter_name": name,
                    "converter_class": type(instance).__name__,
                    "requires_llm": needs_llm,
                    "input_text": current_text,
                    "output_text": output_text,
                    "skipped": False,
                })
                current_text = output_text
            except Exception as e:
                steps.append({
                    "step": i,
                    "converter_name": name,
                    "converter_class": type(instance).__name__,
                    "requires_llm": needs_llm,
                    "input_text": current_text,
                    "output_text": f"(conversion failed: {e})",
                    "skipped": True,
                })

        return steps

    async def generate_log_from_result(self, attack_result: Any) -> List[Dict[str, Any]]:
        """
        从 AttackResult 提取原始文本并生成转换日志

        数据流:
          AttackResult → conversation message pieces → first user message
          → original_value (pre-conversion text) → generate_log()

        Args:
            attack_result: PyRIT AttackResult 实例

        Returns:
            转换步骤列表
        """
        original_text = _extract_original_text_from_result(attack_result)
        if not original_text:
            return []

        return await self.generate_log(original_text)


def _extract_original_text_from_result(attack_result: Any) -> str:
    """从 AttackResult 提取原始文本（第一条 user 消息的 original_value）

    PyRIT 在转换后会覆盖 converted_value，但 original_value 保留了
    转换前的原始文本。我们从 conversation 中提取第一条 user 消息的
    original_value 作为转换日志的起点。

    Args:
        attack_result: AttackResult 实例

    Returns:
        原始文本，如果无法提取则返回空字符串
    """
    # 尝试从 conversation 提取
    conversation = getattr(attack_result, "conversation", None)
    if conversation is None:
        conversation = getattr(attack_result, "request_pieces", None)

    if conversation:
        try:
            for piece in conversation:
                role = getattr(piece, "role", "")
                role_str = str(role.value).lower() if hasattr(role, "value") else str(role).lower()
                if role_str == "user":
                    # 优先使用 original_value（转换前的文本）
                    original = getattr(piece, "original_value", "")
                    if original:
                        return str(original)
                    # 回退到 converted_value
                    converted = getattr(piece, "converted_value", "")
                    if converted:
                        return str(converted)
        except Exception:
            pass

    # SequentialAttackResult: 检查子结果
    child_results = getattr(attack_result, "child_attack_results", None) or []
    for child in child_results:
        if child is None:
            continue
        text = _extract_original_text_from_result(child)
        if text:
            return text

    # 回退到 objective
    objective = getattr(attack_result, "objective", "")
    if objective:
        return str(objective)

    return ""


# ============================================================
# 4. 方案C: Converter Variant Preview（独立变体预览）
# ============================================================


class ConverterVariantPreview:
    """
    Converter 变体预览 — 展示每个 Converter 链对原始文本的转换效果

    方案C 实现：
    - 对一组 converter chain names，分别加载并应用完整链
    - 展示每条链的最终输出，便于用户快速比较不同变体的效果
    - 非 LLM 链可完全本地执行；LLM 链需要 converter_target

    与方案B的区别:
    - 方案B 展示单条链的逐步中间结果
    - 方案C 展示多条链的最终结果对比

    数据流:
      chain_names → [ConverterTransformationLog, ...] → generate_log()
      → [(chain_name, final_output, steps_count), ...]
    """

    def __init__(
        self,
        chain_names: List[str],
        converter_target: Any = None,
    ):
        """
        初始化变体预览

        Args:
            chain_names: Converter 链名称列表
            converter_target: 可选的 LLM Target
        """
        self.chain_names = chain_names
        self.converter_target = converter_target

    async def generate_preview(self, original_text: str) -> List[Dict[str, Any]]:
        """
        生成变体预览

        对每条 converter chain 应用完整链，返回最终结果。

        Args:
            original_text: 原始文本

        Returns:
            变体预览列表，每个条目包含:
            - chain_name: 链名称
            - description: 链描述
            - requires_llm: 是否需要 LLM
            - final_output: 最终输出文本
            - steps_count: 转换步骤数
            - skipped: 是否跳过
        """
        previews: List[Dict[str, Any]] = []

        for chain_name in self.chain_names:
            chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
            requires_llm = chain_info.get("requires_llm", False)
            description = chain_info.get("description", "")

            # LLM 链无 target 时跳过
            if requires_llm and self.converter_target is None:
                previews.append({
                    "chain_name": chain_name,
                    "description": description,
                    "requires_llm": True,
                    "final_output": "(requires LLM — preview not available)",
                    "steps_count": 0,
                    "skipped": True,
                })
                continue

            try:
                log = ConverterTransformationLog(
                    chain_name=chain_name,
                    converter_target=self.converter_target,
                )
                steps = await log.generate_log(original_text)
                final_output = steps[-1]["output_text"] if steps else original_text
                previews.append({
                    "chain_name": chain_name,
                    "description": description,
                    "requires_llm": requires_llm,
                    "final_output": final_output,
                    "steps_count": len(steps) - 1,  # 减去 step 0 (original)
                    "skipped": False,
                })
            except Exception as e:
                previews.append({
                    "chain_name": chain_name,
                    "description": description,
                    "requires_llm": requires_llm,
                    "final_output": f"(preview failed: {e})",
                    "steps_count": 0,
                    "skipped": True,
                })

        return previews


# ============================================================
# 5. Markdown 渲染函数
# ============================================================


def render_transformation_log_markdown(
    steps: List[Dict[str, Any]],
    chain_name: str,
    *,
    max_text_length: int = 500,
) -> str:
    """
    渲染转换日志为 Markdown 格式

    生成报告中的 "Converter Transformation Log" 章节。

    Args:
        steps: 转换步骤列表（由 ConverterTransformationLog.generate_log 生成）
        chain_name: Converter 链名称
        max_text_length: 每步文本的最大显示长度

    Returns:
        Markdown 格式的转换日志
    """
    if not steps:
        return ""

    lines = [
        f"#### Converter Transformation Log: `{chain_name}`",
        "",
        f"Total steps: {len(steps) - 1} (excluding original)",
        "",
        "| Step | Converter | Class | LLM | Output (truncated) |",
        "|------|-----------|-------|-----|-------------------|",
    ]

    for step in steps:
        step_num = step["step"]
        conv_name = step["converter_name"]
        conv_class = step["converter_class"]
        needs_llm = "✓" if step["requires_llm"] else "—"
        output = step["output_text"]

        if step["skipped"]:
            output_display = output
        else:
            output_display = output[:max_text_length]
            if len(output) > max_text_length:
                output_display += "..."

        # 转义 Markdown 表格特殊字符
        output_display = output_display.replace("|", "\\|").replace("\n", " ")

        if step_num == 0:
            label = "**Original**"
        else:
            label = f"Step {step_num}"

        lines.append(f"| {label} | {conv_name} | {conv_class} | {needs_llm} | `{output_display}` |")

    lines.append("")

    # 添加详细步骤
    lines.append("**Detailed Steps:**")
    lines.append("")

    for step in steps:
        step_num = step["step"]
        if step_num == 0:
            lines.append("**Step 0 — Original Text:**")
            lines.append("```")
            lines.append(step["output_text"][:max_text_length])
            lines.append("```")
            lines.append("")
            continue

        conv_name = step["converter_name"]
        conv_class = step["converter_class"]
        input_text = step["input_text"]
        output_text = step["output_text"]
        skipped = step["skipped"]

        lines.append(f"**Step {step_num} — {conv_name} ({conv_class})**")
        if skipped:
            lines.append(f"- *Skipped*: {output_text}")
        else:
            lines.append(f"- Input: `{input_text[:100]}{'...' if len(input_text) > 100 else ''}`")
            lines.append(f"- Output: `{output_text[:100]}{'...' if len(output_text) > 100 else ''}`")
        lines.append("")

    return "\n".join(lines)


def render_variant_preview_markdown(
    previews: List[Dict[str, Any]],
    original_text: str,
    *,
    max_text_length: int = 300,
) -> str:
    """
    渲染变体预览为 Markdown 格式

    生成报告中的 "Converter Variant Preview" 章节。

    Args:
        previews: 变体预览列表（由 ConverterVariantPreview.generate_preview 生成）
        original_text: 原始文本
        max_text_length: 每条预览的最大显示长度

    Returns:
        Markdown 格式的变体预览
    """
    if not previews:
        return ""

    lines = [
        "#### Converter Variant Preview",
        "",
        f"Original text: `{original_text[:100]}{'...' if len(original_text) > 100 else ''}`",
        "",
        "| # | Chain | Description | LLM | Steps | Output (truncated) |",
        "|---|-------|-------------|-----|-------|-------------------|",
    ]

    for i, preview in enumerate(previews, 1):
        chain = preview["chain_name"]
        desc = preview["description"][:40]
        needs_llm = "✓" if preview["requires_llm"] else "—"
        steps_count = preview["steps_count"]
        output = preview["final_output"]

        if preview["skipped"]:
            output_display = output
        else:
            output_display = output[:max_text_length]
            if len(output) > max_text_length:
                output_display += "..."

        output_display = output_display.replace("|", "\\|").replace("\n", " ")
        desc = desc.replace("|", "\\|")

        lines.append(f"| {i} | {chain} | {desc} | {needs_llm} | {steps_count} | `{output_display}` |")

    lines.append("")

    return "\n".join(lines)


# ============================================================
# 6. 便捷函数
# ============================================================


async def generate_converter_log_for_result(
    attack_result: Any,
    converter_target: Any = None,
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """
    为单个 AttackResult 生成转换日志

    自动检测 converter chain name，加载链配置，执行后处理重转换。

    Args:
        attack_result: AttackResult 实例
        converter_target: 可选的 LLM Target

    Returns:
        (chain_name, steps) — chain_name 为 None 表示无 converter
    """
    conv_info = extract_converter_info_from_result(attack_result)
    if not conv_info["has_converters"]:
        return (None, [])

    chain_name = conv_info["converter_chain_name"]
    if chain_name is None:
        # 无法确定 chain name，但有 converter 类名
        # 尝试使用第一个类名作为 fallback
        if conv_info["converter_class_names"]:
            chain_name = conv_info["converter_class_names"][0]
        else:
            return (None, [])

    log = ConverterTransformationLog(
        chain_name=chain_name,
        converter_target=converter_target,
    )
    steps = await log.generate_log_from_result(attack_result)

    return (chain_name, steps)


async def generate_variant_preview_for_technique(
    technique_name: str,
    original_text: str,
    converter_target: Any = None,
    target_type: str = "",
) -> List[Dict[str, Any]]:
    """
    为技术生成变体预览

    自动获取该技术的所有 converter chain，生成变体预览。

    Args:
        technique_name: snake_case 技术名
        original_text: 原始文本
        converter_target: 可选的 LLM Target
        target_type: 可选的 target type（用于动态路由链）

    Returns:
        变体预览列表
    """
    from src.scenarios.technique_factories import BASE_TECHNIQUES_FOR_VARIANTS

    chain_names = list(BASE_TECHNIQUES_FOR_VARIANTS.get(technique_name, []))

    # 添加动态路由链
    if target_type:
        try:
            from src.converters.target_aware_router import select_converter_chains_for_target
            dynamic_chains = select_converter_chains_for_target(
                target_type,
                converter_target_available=(converter_target is not None),
            )
            for cn in dynamic_chains:
                if cn not in chain_names:
                    chain_names.append(cn)
        except Exception:
            pass

    if not chain_names:
        return []

    preview = ConverterVariantPreview(
        chain_names=chain_names,
        converter_target=converter_target,
    )
    return await preview.generate_preview(original_text)
