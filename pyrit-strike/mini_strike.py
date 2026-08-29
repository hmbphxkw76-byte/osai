#!/usr/bin/env python3
"""mini_strike.py — 个人最小化 PyRIT 攻击实验脚本。

6个函数对应6项需求，直接调用 PyRIT 原生 API，不依赖项目 pipeline 模块。

需求映射:
    ① load_burp_request  — 输入 Burp 拦截的 HTTP 请求 (含 {PROMPT} 占位符)
    ② load_seeds         — 从 .prompt YAML 文件读取种子，填充到 {PROMPT}
    ③ build_converters    — 配置 converters 及其组合 (none/base64/rot13/persuasion/decomposition)
    ④ execute_attack      — 选择 attack techniques (prompt_sending / crescendo)
    ⑤ score_results      — 指定 scorers 进行评分 (blackbox / strict)
    ⑥ collect_evidence   — 输出结果和证据收集 (evidence JSON + Markdown 报告)

使用方式:
    # 默认配置 (单轮 + 无 converter + 宽松评分)
    python mini_strike.py

    # 自定义参数
    python mini_strike.py --burp-request data/burp/request.txt \\
        --seeds data/seeds/curated_top20.prompt \\
        --converter rot13 \\
        --technique prompt_sending \\
        --scorer blackbox \\
        --max-seeds 5

    # 多轮升级攻击 (需要 adversarial target)
    python mini_strike.py --technique crescendo --converter persuasion

前置条件:
    pip install pyrit
    # .env 文件配置:
    #   AZURE_OPENAI_ENDPOINT=...        (或 OPENAI_API_KEY=...)
    #   ADVERSARIAL_CHAT_ENDPOINT=...     (多轮攻击需要)
    #   ADVERSARIAL_CHAT_KEY=...
    #   ADVERSARIAL_CHAT_MODEL=gpt-4o
    #   SCORING_CHAT_ENDPOINT=...         (评分需要, 缺失时复用 adversarial)
    #   SCORING_CHAT_KEY=...
    #   SCORING_CHAT_MODEL=gpt-4o

OffSec AI-300 对齐:
    - 使用 PyRIT 原生 PromptSendingAttack / CrescendoAttack
    - 展示 converter 链设计能力
    - 展示 scorer 选择能力 (SelfAskTrueFalseScorer + YAML rubric)
    - 输出 evidence JSON (含 objective/response/score/rationale)
    - 输出 Markdown 报告 (含 ASR + OWASP 矩阵)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# UTF-8 强制 (Windows GBK 终端兼容)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent
_OUTPUT_DIR = _PROJECT_ROOT / "outputs" / f"mini_strike_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


# ═══════════════════════════════════════════════════════════════════════════════
# ① 加载 Burp 拦截的 HTTP 请求
# ═══════════════════════════════════════════════════════════════════════════════

def load_burp_request(burp_file: str) -> tuple[str, str]:
    """读取 Burp 拦截的原始 HTTP 请求，返回 (raw_http, target_url)。

    要求 Burp 文件中 body 含 {PROMPT} 占位符，例如:
        POST /api/chat HTTP/1.1
        Host: localhost
        Content-Type: application/json

        {"prompt":"{PROMPT}"}

    HTTPTarget 会在攻击时自动将 {PROMPT} 替换为实际的攻击载荷。

    Args:
        burp_file: Burp 拦截的 HTTP 请求文件路径。

    Returns:
        (raw_http_string, target_url) — 原始 HTTP 请求字符串 + 目标 URL。
    """
    raw = Path(burp_file).read_text(encoding="utf-8", errors="replace")

    # 从 raw HTTP 提取 URL (用于日志展示)
    lines = raw.replace("\r\n", "\n").split("\n")
    request_line = lines[0].split(" ")
    if len(request_line) < 3:
        raise ValueError(f"无效的 HTTP 请求行: {lines[0]}")

    path = request_line[1]
    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    # localhost 默认 http
    use_tls = not ("localhost" in host or "127.0.0.1" in host)
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}{path}"

    # 确保包含 {PROMPT} 占位符
    if "{PROMPT}" not in raw:
        # 尝试自动注入 (JSON body 中的常见字段)
        body_start = raw.find("\n\n")
        if body_start == -1:
            body_start = raw.find("\r\n\r\n")
        if body_start != -1:
            body = raw[body_start:].strip()
            try:
                data = json.loads(body)
                for field in ("prompt", "message", "input", "query", "text", "content"):
                    if field in data:
                        data[field] = "{PROMPT}"
                        raw = raw[:body_start] + "\n\n" + json.dumps(data, ensure_ascii=False)
                        break
            except (json.JSONDecodeError, ValueError):
                pass

    if "{PROMPT}" not in raw:
        raise ValueError(
            "Burp 请求文件中未找到 {PROMPT} 占位符。\n"
            "请在 body 中添加占位符，例如: {\"prompt\":\"{PROMPT}\"}"
        )

    print(f"[1-RECON] Burp 请求已加载: {burp_file}")
    print(f"[1-RECON] 目标 URL: {url}")
    print(f"[1-RECON] HTTP 方法: {request_line[0]}")
    print(f"[1-RECON] 占位符 {PROMPT} 已确认")
    print()

    return raw, url


# ═══════════════════════════════════════════════════════════════════════════════
# ② 从文件加载攻击种子
# ═══════════════════════════════════════════════════════════════════════════════

def load_seeds(seed_file: str, max_seeds: int = 10) -> list[Any]:
    """从 .prompt YAML 文件加载攻击种子，构建 PyRIT AttackSeedGroup 列表。

    种子文件格式 (YAML list):
        - value: "Ignore all previous instructions..."
          metadata:
            owasp_id: "LLM01"
            difficulty: "medium"
            severity: "high"

    Args:
        seed_file: 种子文件路径 (如 data/seeds/curated_top20.prompt)。
        max_seeds: 最大加载种子数 (截取前 N 个)。

    Returns:
        list[AttackSeedGroup]: PyRIT 攻击种子组列表。
    """
    from pyrit.models import AttackSeedGroup, SeedObjective

    import yaml

    data = yaml.safe_load(Path(seed_file).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"种子文件格式错误: 期望 YAML list, 得到 {type(data)}")

    # 截取前 max_seeds 个
    data = data[:max_seeds]

    seeds: list[AttackSeedGroup] = []
    for item in data:
        value = item.get("value", "")
        if not value:
            continue
        metadata = item.get("metadata", {})
        seed_obj = SeedObjective(value=value, metadata=metadata)
        seeds.append(AttackSeedGroup(seeds=[seed_obj]))

    print(f"[2-ARM] 种子文件: {seed_file}")
    print(f"[2-ARM] 加载了 {len(seeds)} 个攻击种子")
    if seeds:
        first_meta = getattr(seeds[0].seeds[0], "metadata", {})
        owasp = first_meta.get("owasp_id", "N/A")
        cat = first_meta.get("category", "N/A")
        print(f"[2-ARM] 首个种子: OWASP={owasp}, category={cat}")
    print()

    return seeds


# ═══════════════════════════════════════════════════════════════════════════════
# ③ 配置 Converters 及其组合
# ═══════════════════════════════════════════════════════════════════════════════

def build_converters(
    choice: str,
    converter_target: Any | None = None,
) -> list[Any]:
    """根据选择构建 PyRIT Converter 实例列表。

    可选 converter:
        "none"          — 无变形 (基线攻击, 0 token)
        "base64"        — Base64 编码 (0 token, ASR ~7%)
        "rot13"         — ROT13 语义混淆 (0 token, ASR ~30-40%)
        "code_chameleon"— CodeChameleon 加密 (0 token, ASR ~35-45%)
        "persuasion"    — 说服策略 authority (需 LLM, ASR ~38.4%)
        "decomposition" — DrAttack 分解重组 (需 LLM, ASR ~40-60%)
        "l5_optimal"    — 多路径组合 (需 LLM, 最佳综合 ASR)

    Args:
        choice: converter 名称。
        converter_target: LLM 目标实例 (persuasion/decomposition 需要)。

    Returns:
        PyRIT Converter 实例列表 (可为空=无变形)。
    """
    from pyrit.converter import (
        Base64Converter,
        ROT13Converter,
    )

    converters: list[Any] = []

    if choice == "none":
        print("[3-ARM] Converter: none (基线攻击)")
        return []

    if choice == "base64":
        converters.append(Base64Converter())
        print("[3-ARM] Converter: Base64Converter (0 token)")

    elif choice == "rot13":
        converters.append(ROT13Converter())
        print("[3-ARM] Converter: ROT13Converter (0 token)")

    elif choice == "code_chameleon":
        try:
            from pyrit.converter import CodeChameleonConverter
            converters.append(CodeChameleonConverter())
            print("[3-ARM] Converter: CodeChameleonConverter (0 token)")
        except ImportError:
            print("[3-ARM] CodeChameleonConverter 不可用, 回退到 ROT13")
            converters.append(ROT13Converter())

    elif choice == "persuasion":
        if converter_target is None:
            print("[3-ARM] persuasion 需要 converter_target, 回退到 none")
            return []
        try:
            from pyrit.converter import PersuasionConverter
            converters.append(PersuasionConverter(
                converter_target=converter_target,
                persuasion_technique="authority_endorsement",
            ))
            print("[3-ARM] Converter: PersuasionConverter(authority)")
        except (ImportError, TypeError) as e:
            print(f"[3-ARM] PersuasionConverter 不可用: {e}, 回退到 none")

    elif choice == "decomposition":
        if converter_target is None:
            print("[3-ARM] decomposition 需要 converter_target, 回退到 none")
            return []
        try:
            from pyrit.converter import DecompositionConverter
            converters.append(DecompositionConverter(converter_target=converter_target))
            print("[3-ARM] Converter: DecompositionConverter (DrAttack)")
        except (ImportError, TypeError) as e:
            print(f"[3-ARM] DecompositionConverter 不可用: {e}, 回退到 none")

    elif choice == "l5_optimal":
        # 复用项目 converter_presets 的 l5_optimal 链
        # 包含: decomposition + persuasion + code_chameleon + rot13 等
        if converter_target is not None:
            try:
                from pipeline.arm.converter_presets import l5_optimal
                converters = l5_optimal(converter_target=converter_target)
                print(f"[3-ARM] Converter: l5_optimal ({len(converters)} 个 converter)")
            except ImportError:
                # 独立运行模式: 手动构建组合
                converters.append(ROT13Converter())
                try:
                    from pyrit.converter import CodeChameleonConverter
                    converters.append(CodeChameleonConverter())
                except ImportError:
                    pass
                if converter_target is not None:
                    try:
                        from pyrit.converter import PersuasionConverter
                        converters.append(PersuasionConverter(
                            converter_target=converter_target,
                            persuasion_technique="authority_endorsement",
                        ))
                    except (ImportError, TypeError):
                        pass
                print(f"[3-ARM] Converter: l5_optimal fallback ({len(converters)} 个)")
        else:
            # 无 LLM: 仅非 LLM converter
            converters.append(ROT13Converter())
            try:
                from pyrit.converter import CodeChameleonConverter
                converters.append(CodeChameleonConverter())
            except ImportError:
                pass
            print(f"[3-ARM] Converter: l5_optimal (no-LLM, {len(converters)} 个)")

    else:
        print(f"[3-ARM] 未知 converter: {choice}, 使用 none")
        return []

    print()
    return converters


# ═══════════════════════════════════════════════════════════════════════════════
# ④ 执行攻击
# ═══════════════════════════════════════════════════════════════════════════════

async def execute_attack(
    *,
    raw_http: str,
    target_url: str,
    seeds: list[Any],
    converters: list[Any],
    technique: str,
    scoring_config: Any,
    adversarial_target: Any | None = None,
    timeout: int = 600,
) -> list[Any]:
    """执行 PyRIT 原生攻击，返回 AttackResult 列表。

    可选技术:
        "prompt_sending" — 单轮 PromptSendingAttack (无需 adversarial target)
        "crescendo"      — 多轮 CrescendoAttack (需 adversarial target, 逐步升级)

    Args:
        raw_http: 含 {PROMPT} 的原始 HTTP 请求字符串。
        target_url: 目标 URL (仅用于日志)。
        seeds: AttackSeedGroup 列表。
        converters: Converter 实例列表 (可为空)。
        technique: 攻击技术名称。
        scoring_config: AttackScoringConfig 实例。
        adversarial_target: 对抗性 LLM 目标 (多轮攻击需要)。
        timeout: 超时秒数。

    Returns:
        list[AttackResult]: 攻击结果列表。
    """
    from pyrit.executor.attack import (
        AttackConverterConfig,
        PromptSendingAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.prompt_normalizer import ConverterConfiguration

    # 构建 HTTPTarget
    from pyrit.prompt_target import HTTPTarget

    # 构建自适应 JSON callback (尝试多个常见响应路径)
    callback = _make_json_callback()

    target = HTTPTarget(
        http_request=raw_http,
        prompt_regex_string="{PROMPT}",
        callback_function=callback,
    )

    # 构建 converter config
    converter_config = None
    if converters:
        converter_config = AttackConverterConfig(
            request_converters=[ConverterConfiguration(converters=converters)],
        )

    # 构建 attack kwargs
    attack_kwargs: dict[str, Any] = {
        "objective_target": target,
        "attack_scoring_config": scoring_config,
    }
    if converter_config:
        attack_kwargs["attack_converter_config"] = converter_config

    executor = AttackExecutor(max_concurrency=1)

    if technique == "prompt_sending":
        # ── 单轮攻击: PromptSendingAttack ──
        attack = PromptSendingAttack(**attack_kwargs)
        converter_names = [type(c).__name__ for c in converters] or ["none"]
        print(f"[4-STRIKE] 技术: PromptSendingAttack (单轮)")
        print(f"[4-STRIKE] Converters: {converter_names}")
        print(f"[4-STRIKE] 种子数: {len(seeds)}")
        print(f"[4-STRIKE] 开始执行...")

        try:
            result = await asyncio.wait_for(
                executor.execute_attack_from_seed_groups_async(
                    attack=attack,
                    seed_groups=seeds,
                    return_partial_on_failure=True,
                ),
                timeout=timeout,
            )
            results = list(result.completed_results)
            incomplete = len(result.incomplete_objectives)
        except asyncio.TimeoutError:
            print(f"[4-STRIKE] 攻击超时 ({timeout}s), 尝试检索部分结果...")
            results = await _retrieve_partial_results(len(seeds))
            incomplete = len(seeds) - len(results)

    elif technique == "crescendo":
        # ── 多轮升级: CrescendoAttack ──
        if adversarial_target is None:
            print("[4-STRIKE] CrescendoAttack 需要 adversarial_target, 回退到 PromptSendingAttack")
            attack = PromptSendingAttack(**attack_kwargs)
        else:
            try:
                from pyrit.executor.attack.compound.crescendo_attack import CrescendoAttack
                attack = CrescendoAttack(
                    objective_target=target,
                    adversarial_chat=adversarial_target,
                    scoring_config=scoring_config,
                    attack_converter_config=converter_config,
                )
                print(f"[4-STRIKE] 技术: CrescendoAttack (多轮升级)")
            except ImportError:
                print("[4-STRIKE] CrescendoAttack 不可用, 回退到 PromptSendingAttack")
                attack = PromptSendingAttack(**attack_kwargs)

        converter_names = [type(c).__name__ for c in converters] or ["none"]
        print(f"[4-STRIKE] Converters: {converter_names}")
        print(f"[4-STRIKE] 种子数: {len(seeds)}")
        print(f"[4-STRIKE] 开始执行...")

        try:
            result = await asyncio.wait_for(
                executor.execute_attack_from_seed_groups_async(
                    attack=attack,
                    seed_groups=seeds,
                    return_partial_on_failure=True,
                ),
                timeout=timeout,
            )
            results = list(result.completed_results)
            incomplete = len(result.incomplete_objectives)
        except asyncio.TimeoutError:
            print(f"[4-STRIKE] 攻击超时 ({timeout}s), 尝试检索部分结果...")
            results = await _retrieve_partial_results(len(seeds))
            incomplete = len(seeds) - len(results)

    else:
        print(f"[4-STRIKE] 未知技术: {technique}, 使用 PromptSendingAttack")
        attack = PromptSendingAttack(**attack_kwargs)
        result = await asyncio.wait_for(
            executor.execute_attack_from_seed_groups_async(
                attack=attack,
                seed_groups=seeds,
                return_partial_on_failure=True,
            ),
            timeout=timeout,
        )
        results = list(result.completed_results)
        incomplete = len(result.incomplete_objectives)

    print(f"[4-STRIKE] 完成: {len(results)} 个结果, {incomplete} 个未完成")
    print()

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ⑤ 评分
# ═══════════════════════════════════════════════════════════════════════════════

def build_scoring_config(
    scorer_choice: str,
    scoring_target: Any | None = None,
) -> Any:
    """构建 PyRIT AttackScoringConfig。

    可选 scorer:
        "blackbox"  — 宽松评分 (blackbox_task_achieved.yaml)
        "strict"    — 严格评分 (strict_task_achieved.yaml)
        "refusal"   — 拒绝检测 (TrueFalseInverterScorer + SubStringScorer, 0 token)
        "none"      — 无运行时评分 (post-hoc 手动评分)

    Args:
        scorer_choice: scorer 名称。
        scoring_target: LLM 目标实例 (blackbox/strict 需要)。

    Returns:
        AttackScoringConfig 实例。
    """
    from pyrit.executor.attack import AttackScoringConfig

    if scorer_choice == "none":
        print("[5-ASSESS] Scorer: none (post-hoc 手动评分)")
        print()
        return AttackScoringConfig()

    if scorer_choice == "refusal":
        # 启发式拒绝检测 (0 token, 纯文本匹配)
        from pyrit.score import SubStringScorer, TrueFalseInverterScorer
        refusal_scorer = TrueFalseInverterScorer(
            scorer=SubStringScorer(
                substring="i cannot",
                categories=["refusal_detection"],
            ),
        )
        print("[5-ASSESS] Scorer: TrueFalseInverterScorer(SubStringScorer) (0 token)")
        print()
        return AttackScoringConfig(objective_scorer=refusal_scorer)

    if scorer_choice in ("blackbox", "strict"):
        if scoring_target is None:
            print(f"[5-ASSESS] {scorer_choice} 需要 scoring_target, 回退到 refusal")
            from pyrit.score import SubStringScorer, TrueFalseInverterScorer
            refusal_scorer = TrueFalseInverterScorer(
                scorer=SubStringScorer(
                    substring="i cannot",
                    categories=["refusal_detection"],
                ),
            )
            print("[5-ASSESS] Scorer: TrueFalseInverterScorer(SubStringScorer) (fallback)")
            print()
            return AttackScoringConfig(objective_scorer=refusal_scorer)

        from pyrit.score import SelfAskTrueFalseScorer, TrueFalseQuestion

        rubric_map = {
            "blackbox": "data/scorers/blackbox_task_achieved.yaml",
            "strict": "data/scorers/strict_task_achieved.yaml",
        }
        rubric_path = _PROJECT_ROOT / rubric_map[scorer_choice]

        if rubric_path.exists():
            question = TrueFalseQuestion.from_yaml(rubric_path)
            scorer = SelfAskTrueFalseScorer.from_question(
                chat_target=scoring_target,
                question=question,
            )
            print(f"[5-ASSESS] Scorer: SelfAskTrueFalseScorer ({scorer_choice}, from YAML)")
        else:
            # fallback: 使用 PyRIT 内置 TASK_ACHIEVED
            from pyrit.score import TrueFalseQuestionPaths
            question = TrueFalseQuestion.from_yaml(
                TrueFalseQuestionPaths.TASK_ACHIEVED.value,
            )
            scorer = SelfAskTrueFalseScorer.from_question(
                chat_target=scoring_target,
                question=question,
            )
            print(f"[5-ASSESS] Scorer: SelfAskTrueFalseScorer (TASK_ACHIEVED, {rubric_path} 不存在)")

        print()
        return AttackScoringConfig(
            objective_scorer=scorer,
            use_score_as_feedback=True,
        )

    print(f"[5-ASSESS] 未知 scorer: {scorer_choice}, 使用 none")
    print()
    return AttackScoringConfig()


def score_results(
    results: list[Any],
    scoring_target: Any | None = None,
    rubric: str = "blackbox",
) -> list[dict[str, Any]]:
    """对攻击结果进行 post-hoc 评分 (如果运行时未评分或需重新评分)。

    Args:
        results: AttackResult 列表。
        scoring_target: LLM 评分目标。
        rubric: 评分 rubric 名称 (blackbox/strict)。

    Returns:
        评分详情列表 (每个结果一个 dict)。
    """
    from pyrit.models import AttackOutcome

    score_details: list[dict[str, Any]] = []

    for idx, result in enumerate(results):
        detail: dict[str, Any] = {
            "index": idx,
            "objective": getattr(result, "objective", "")[:200],
        }

        # 从 result 中提取 score
        last_score = getattr(result, "last_score", None)
        if last_score is not None:
            score_value = last_score.get_value() if hasattr(last_score, "get_value") else str(last_score)
            detail["score_value"] = str(score_value)
            detail["rationale"] = getattr(last_score, "score_rationale", "")
        else:
            detail["score_value"] = "undecided"
            detail["rationale"] = "No score available"

        # 判断 outcome
        outcome = getattr(result, "outcome", None)
        if outcome is not None:
            detail["outcome"] = outcome.name if hasattr(outcome, "name") else str(outcome)
            detail["is_success"] = outcome == AttackOutcome.SUCCESS
        else:
            detail["outcome"] = "undecided"
            detail["is_success"] = False

        score_details.append(detail)

    return score_details


# ═══════════════════════════════════════════════════════════════════════════════
# ⑥ 证据收集和报告生成
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_response_text(result: Any) -> str:
    """从 AttackResult 中提取目标响应文本。"""
    # 优先从 last_response 提取
    last_response = getattr(result, "last_response", None)
    if last_response is not None:
        # PyRIT Message 对象
        if hasattr(last_response, "message_pieces"):
            parts = []
            for piece in last_response.message_pieces:
                val = getattr(piece, "converted_value", None) or ""
                parts.append(str(val))
            return "\n".join(parts)
        return str(last_response)

    # fallback: 从 conversation 提取最后一条 assistant 消息
    conv = getattr(result, "conversation", None)
    if conv is not None:
        messages = getattr(conv, "messages", [])
        for msg in reversed(messages):
            if getattr(msg, "role", "") == "assistant":
                if hasattr(msg, "message_pieces"):
                    parts = [str(getattr(p, "converted_value", "")) for p in msg.message_pieces]
                    return "\n".join(parts)
                return str(msg)

    return "(no response captured)"


def collect_evidence(
    results: list[Any],
    score_details: list[dict[str, Any]],
    output_dir: Path,
    target_url: str = "",
    converter_names: list[str] | None = None,
    technique: str = "prompt_sending",
) -> Path:
    """收集证据并生成 evidence JSON + Markdown 报告。

    输出:
        output_dir/evidence/EVD-001.json, EVD-002.json, ...
        output_dir/report.md

    Args:
        results: AttackResult 列表。
        score_details: 评分详情列表。
        output_dir: 输出目录。
        target_url: 目标 URL。
        converter_names: converter 名称列表。
        technique: 攻击技术名称。

    Returns:
        report.md 路径。
    """
    from pyrit.models import AttackOutcome

    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    converter_names = converter_names or []
    total = len(results)
    successes = 0
    evidence_list: list[dict[str, Any]] = []

    for idx, (result, score_detail) in enumerate(zip(results, score_details), 1):
        objective = getattr(result, "objective", "")
        response_text = _extract_response_text(result)
        is_success = score_detail.get("is_success", False)
        outcome_str = "success" if is_success else "failure"
        file_suffix = f"_{outcome_str}" if is_success else ""

        # 提取 metadata (OWASP ID 等)
        metadata = getattr(result, "metadata", {}) or {}
        owasp_id = metadata.get("owasp_id", "N/A")
        owasp_category = metadata.get("category", "N/A")
        owasp_severity = metadata.get("severity", "N/A")

        if is_success:
            successes += 1

        evidence = {
            "evidence_id": f"EVD-{idx:04d}{file_suffix}",
            "technique": technique,
            "converter_chain": ", ".join(converter_names) or "none",
            "owasp_id": owasp_id,
            "owasp_category": owasp_category,
            "owasp_severity": owasp_severity,
            "objective": objective[:500],
            "response": response_text[:2000],
            "is_success": is_success,
            "outcome": score_detail.get("outcome", "undecided"),
            "score_value": score_detail.get("score_value", "undecided"),
            "score_rationale": score_detail.get("rationale", ""),
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
        }

        evidence_list.append(evidence)

        # 每个证据单独写入 JSON
        evd_path = evidence_dir / f"EVD-{idx:04d}{file_suffix}.json"
        evd_path.write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    asr = (successes / total * 100) if total > 0 else 0.0

    # ── Markdown 报告 ──
    md = _generate_markdown_report(
        evidence_list=evidence_list,
        total=total,
        successes=successes,
        asr=asr,
        target_url=target_url,
        technique=technique,
        converter_names=converter_names,
        output_dir=output_dir,
    )

    report_path = output_dir / "report.md"
    report_path.write_text(md, encoding="utf-8")

    print(f"[6-REPORT] 证据: {evidence_dir} ({len(evidence_list)} 个文件)")
    print(f"[6-REPORT] 报告: {report_path}")
    print(f"[6-REPORT] ASR: {asr:.1f}% ({successes}/{total})")
    print()

    return report_path


def _generate_markdown_report(
    *,
    evidence_list: list[dict[str, Any]],
    total: int,
    successes: int,
    asr: float,
    target_url: str,
    technique: str,
    converter_names: list[str],
    output_dir: Path,
) -> str:
    """生成 Markdown 格式的安全报告。"""
    lines: list[str] = []
    lines.append("# AI Red Team 攻击报告")
    lines.append("")
    lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**目标**: `{target_url}`")
    lines.append(f"**攻击技术**: `{technique}`")
    lines.append(f"**Converter 链**: {', '.join(converter_names) or 'none'}")
    lines.append(f"**总攻击数**: {total}")
    lines.append(f"**成功攻击数**: {successes}")
    lines.append(f"**攻击成功率 (ASR)**: {asr:.1f}%")
    lines.append("")

    # OWASP 覆盖矩阵
    lines.append("## OWASP 覆盖矩阵")
    lines.append("")
    lines.append("| OWASP ID | 类别 | 严重性 | 结果 |")
    lines.append("|----------|------|--------|------|")
    for ev in evidence_list:
        status = "✅ 成功" if ev["is_success"] else "❌ 失败"
        lines.append(
            f"| {ev['owasp_id']} | {ev['owasp_category']} | "
            f"{ev['owasp_severity']} | {status} |"
        )
    lines.append("")

    # 成功攻击证据
    success_evts = [e for e in evidence_list if e["is_success"]]
    if success_evts:
        lines.append("## 成功攻击证据")
        lines.append("")
        for ev in success_evts:
            lines.append(f"### {ev['evidence_id']} — {ev['owasp_id']}")
            lines.append(f"**严重性**: {ev['owasp_severity']}")
            lines.append(f"**评分**: {ev['score_value']}")
            lines.append("")
            lines.append("**攻击目标 (Objective)**:")
            lines.append("```")
            lines.append(ev["objective"][:300])
            lines.append("```")
            lines.append("")
            lines.append("**目标响应 (Response)**:")
            lines.append("```")
            lines.append(ev["response"][:500])
            lines.append("```")
            lines.append("")
            lines.append(f"**评分理由**: {ev['score_rationale'][:200]}")
            lines.append("")

    # 失败攻击摘要
    failed_evts = [e for e in evidence_list if not e["is_success"]]
    if failed_evts:
        lines.append("## 失败攻击摘要")
        lines.append("")
        lines.append("| Evidence ID | OWASP | 目标 (截断) | 评分 |")
        lines.append("|-------------|-------|-------------|------|")
        for ev in failed_evts:
            obj = ev["objective"][:60].replace("|", "\\|")
            lines.append(
                f"| {ev['evidence_id']} | {ev['owasp_id']} | {obj}... | {ev['score_value']} |"
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## OffSec AI-300 对齐说明")
    lines.append("")
    lines.append("- ✅ 使用 PyRIT 原生攻击策略 (PromptSendingAttack / CrescendoAttack)")
    lines.append("- ✅ 展示 Converter 链设计能力")
    lines.append("- ✅ 展示 Scorer 选择能力 (SelfAskTrueFalseScorer + YAML rubric)")
    lines.append("- ✅ 证据保留 (evidence JSON: objective + response + score)")
    lines.append("- ✅ ASR 统计 + OWASP 覆盖矩阵")
    lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════════════════════

def _make_json_callback() -> Any:
    """创建自适应 JSON 响应解析 callback (尝试多个常见路径)。"""
    import json as json_mod

    # 候选 JSON 路径 (按 API 类型优先级)
    _CANDIDATES = [
        ("choices[0].message.content", ("choices", 0, "message", "content")),
        ("data.content", ("data", "content")),
        ("response", ("response",)),
        ("result", ("result",)),
        ("output", ("output",)),
        ("message", ("message",)),
        ("text", ("text",)),
        ("content", ("content",)),
        ("answer", ("answer",)),
    ]

    def _extract_nested(obj: Any, keys: tuple) -> Any:
        current = obj
        for key in keys:
            if current is None:
                return None
            if isinstance(key, int):
                if isinstance(current, list) and 0 <= key < len(current):
                    current = current[key]
                else:
                    return None
            else:
                if isinstance(current, dict):
                    current = current.get(key)
                else:
                    return None
        return current

    def parse_response(response: Any) -> str:
        """自适应 JSON 响应解析 callback。"""
        content = None
        if hasattr(response, "content"):
            content = response.content
        elif hasattr(response, "text"):
            content = response.text
        else:
            content = str(response)

        if not content:
            return ""

        # bytes → str
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        # 尝试 JSON 解析, 逐路径查找
        try:
            data = json_mod.loads(content)
            for _name, keys in _CANDIDATES:
                val = _extract_nested(data, keys)
                if val and isinstance(val, str):
                    return val
            # JSON 解析成功但路径都不匹配, 返回原始 JSON 文本
            return content
        except (json_mod.JSONDecodeError, ValueError):
            # 非 JSON, 返回原始文本
            return content

    return parse_response


async def _retrieve_partial_results(expected_count: int) -> list[Any]:
    """超时后从 PyRIT CentralMemory 检索部分结果。"""
    try:
        from pyrit.memory import CentralMemory
        memory = CentralMemory.get_memory_instance()
        results = memory.get_attack_results()
        if results:
            return results[-expected_count:]
    except Exception as e:
        logger.warning("检索部分结果失败: %s", e)
    return []


def _create_llm_targets() -> tuple[Any, Any, Any]:
    """从 .env 环境变量创建 adversarial / scoring / converter LLM 目标。

    环境变量:
        ADVERSARIAL_CHAT_ENDPOINT / ADVERSARIAL_CHAT_KEY / ADVERSARIAL_CHAT_MODEL
        SCORING_CHAT_ENDPOINT / SCORING_CHAT_KEY / SCORING_CHAT_MODEL
        (scoring 缺失时复用 adversarial)

    Returns:
        (adversarial_target, scoring_target, converter_target) — 任一可为 None。
    """
    from pyrit.prompt_target import OpenAIChatTarget

    # ── Adversarial Target (攻击 prompt 生成器, 多轮攻击需要) ──
    adv_endpoint = os.environ.get("ADVERSARIAL_CHAT_ENDPOINT")
    adv_key = os.environ.get("ADVERSARIAL_CHAT_KEY")
    adv_model = os.environ.get("ADVERSARIAL_CHAT_MODEL", "gpt-4o")

    adversarial_target = None
    if adv_endpoint and adv_key:
        adversarial_target = OpenAIChatTarget(
            endpoint=adv_endpoint,
            api_key=adv_key,
            model_name=adv_model,
        )
        print(f"[0-INIT] Adversarial target: {adv_endpoint} / {adv_model}")
    else:
        print("[0-INIT] Adversarial target 未配置 (多轮攻击将不可用)")

    # ── Scoring Target (评分器, 缺失时复用 adversarial) ──
    score_endpoint = os.environ.get("SCORING_CHAT_ENDPOINT") or adv_endpoint
    score_key = os.environ.get("SCORING_CHAT_KEY") or adv_key
    score_model = os.environ.get("SCORING_CHAT_MODEL") or adv_model

    scoring_target = None
    if score_endpoint and score_key:
        scoring_target = OpenAIChatTarget(
            endpoint=score_endpoint,
            api_key=score_key,
            model_name=score_model,
        )
        print(f"[0-INIT] Scoring target: {score_endpoint} / {score_model}")
    else:
        print("[0-INIT] Scoring target 未配置 (将使用启发式评分)")

    # ── Converter Target (LLM 辅助 converter 使用, 复用 adversarial) ──
    converter_target = adversarial_target

    return adversarial_target, scoring_target, converter_target


# ═══════════════════════════════════════════════════════════════════════════════
# CLI 参数解析
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_args(argv: list[str] | None = None) -> Any:
    """解析命令行参数。"""
    import argparse

    parser = argparse.ArgumentParser(
        description="mini_strike — 最小化 PyRIT 攻击实验脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 默认: 单轮 + 无 converter + 宽松评分
  python mini_strike.py

  # ROT13 编码 + 严格评分
  python mini_strike.py --converter rot13 --scorer strict

  # 多轮 Crescendo 升级 + 说服策略
  python mini_strike.py --technique crescendo --converter persuasion

  # 自定义 Burp 请求 + 种子文件
  python mini_strike.py --burp-request my_request.txt --seeds my_seeds.prompt
""",
    )

    parser.add_argument(
        "--burp-request",
        default="data/burp/request.txt",
        help="Burp 拦截的 HTTP 请求文件路径 (默认: data/burp/request.txt)",
    )
    parser.add_argument(
        "--seeds",
        default="data/seeds/curated_top20.prompt",
        help="攻击种子文件路径 (默认: data/seeds/curated_top20.prompt)",
    )
    parser.add_argument(
        "--converter",
        default="none",
        choices=["none", "base64", "rot13", "code_chameleon", "persuasion", "decomposition", "l5_optimal"],
        help="Converter 选择 (默认: none)",
    )
    parser.add_argument(
        "--technique",
        default="prompt_sending",
        choices=["prompt_sending", "crescendo"],
        help="攻击技术 (默认: prompt_sending)",
    )
    parser.add_argument(
        "--scorer",
        default="blackbox",
        choices=["none", "refusal", "blackbox", "strict"],
        help="评分器选择 (默认: blackbox)",
    )
    parser.add_argument(
        "--max-seeds",
        type=int,
        default=5,
        help="最大种子数 (默认: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="攻击超时秒数 (默认: 600)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="输出目录 (默认: outputs/mini_strike_<timestamp>)",
    )

    args = parser.parse_args(argv)
    return args


# ═══════════════════════════════════════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════════════════════════════════════

async def run(argv: list[str] | None = None) -> None:
    """主流程: 6步完成一次完整攻击实验。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print("=" * 72)
    print("  mini_strike.py — 最小化 PyRIT 攻击实验")
    print("=" * 72)
    print()

    args = _parse_args(argv)

    # 输出目录
    global _OUTPUT_DIR
    if args.output_dir:
        _OUTPUT_DIR = Path(args.output_dir)
    else:
        _OUTPUT_DIR = _PROJECT_ROOT / "outputs" / f"mini_strike_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[0-INIT] 输出目录: {_OUTPUT_DIR}")
    print()

    # ── 0. 初始化 PyRIT 环境 ──
    print("[0-INIT] 初始化 PyRIT 环境...")
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    from pyrit.common import initialize_pyrit
    await initialize_pyrit()
    print("[0-INIT] PyRIT 环境已初始化")
    print()

    # 创建 LLM targets (adversarial / scoring / converter)
    adversarial_target, scoring_target, converter_target = _create_llm_targets()
    print()

    # ── ① 加载 Burp 请求 ──
    raw_http, target_url = load_burp_request(args.burp_request)

    # ── ② 加载种子 ──
    seeds = load_seeds(args.seeds, max_seeds=args.max_seeds)

    # ── ③ 构建 Converters ──
    converters = build_converters(args.converter, converter_target=converter_target)

    # ── ④ 构建 ScoringConfig ── (在 execute_attack 之前构建)
    scoring_config = build_scoring_config(args.scorer, scoring_target=scoring_target)

    # ── ⑤ 执行攻击 ──
    results = await execute_attack(
        raw_http=raw_http,
        target_url=target_url,
        seeds=seeds,
        converters=converters,
        technique=args.technique,
        scoring_config=scoring_config,
        adversarial_target=adversarial_target,
        timeout=args.timeout,
    )

    if not results:
        print("[!] 无攻击结果, 跳过评分和报告生成")
        return

    # ── ⑥ 评分 + 证据收集 ──
    score_details = score_results(results, scoring_target, rubric=args.scorer)

    converter_names = [type(c).__name__ for c in converters]
    collect_evidence(
        results=results,
        score_details=score_details,
        output_dir=_OUTPUT_DIR,
        target_url=target_url,
        converter_names=converter_names,
        technique=args.technique,
    )

    print("=" * 72)
    print("  攻击实验完成!")
    print(f"  结果目录: {_OUTPUT_DIR}")
    print("=" * 72)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[!] 用户中断, 退出")
        sys.exit(130)