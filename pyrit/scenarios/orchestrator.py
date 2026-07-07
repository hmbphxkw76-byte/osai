"""
===============================================================================
OffSec AI-300 — 考试模式全自动编排引擎
===============================================================================
PyRIT 专家级设计：考试期间零代码改动。

执行流程（预固化）：
  1. 读取 YAML 模板 → ExamPromptSet
  2. 为每个提示词生成 5+ 种变体（PromptVariantGenerator）
  3. 根据 category/difficulty 自动选择攻击策略
  4. 并行执行全部攻击（PromptSendingAttack / CrescendoAttack / PAIR / TAP / ...）
  5. 自动评分（CleanedSelfAskTrueFalseScorer + 多维度评分器）
  6. 收集结果 + 去重 + 排序
  7. 生成综合安全评估报告

PyRIT 集成：
  ✅ 复用 AI300Orchestrator 全部攻击策略
  ✅ 复用 CleanedSelfAskTrueFalseScorer 防假阴性评分
  ✅ 复用 SQLiteMemory + CentralMemory 持久化
  ✅ 输出格式与现有 reporting 模块完全兼容

考试期间操作：
  仅需修改 exam_prompts.yaml → python main.py --exam-mode --exam-template exam_prompts.yaml
===============================================================================
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Optional

from pyrit.prompt_target import PromptTarget, OpenAIChatTarget
from pyrit.memory import SQLiteMemory, CentralMemory
from pyrit.score import TrueFalseQuestion
from pyrit.prompt_normalizer import PromptConverterConfiguration
from pyrit.executor.attack import (
    PromptSendingAttack,
    CrescendoAttack,
    AttackScoringConfig,
    AttackConverterConfig,
    AttackAdversarialConfig,
)

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live
from rich.table import Table

from scenarios.schema import (
    ExamPromptSet, ExamPrompt, ExamModeConfig,
    AttackStrategy, STRATEGY_CONVERTER_MAP,
)
from scenarios.variant_generator import PromptVariantGenerator, PromptVariant
from scenarios.rag_attacks import RAGPayloadGenerator
from scenarios.agent_attacks import AgentPayloadGenerator
from scenarios.infra_attacks import InfraPayloadGenerator

# 🆕 P2 重构: 组合 AI300Orchestrator 消除 ~200 行重复攻击执行器代码
from orchestrators.pyrit_orchestrator import AI300Orchestrator

from executor.scorer import (
    CleanedSelfAskTrueFalseScorer,
    create_best_scorer,
    is_likely_refusal,
)
from executor.template import _resolve_template
from converters import resolve_converters
from utils import ensure_results_dir, results_path

console = Console()
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# 预固化：攻击结果数据类
# ═══════════════════════════════════════════════════════════════════

class AttackResult:
    """单次攻击的完整结果记录"""
    __slots__ = (
        "prompt_id", "strategy", "variant_type", "status",
        "original_prompt", "converted_prompt", "response_text",
        "score_value", "score_reason", "latency_seconds",
        "criterion", "category", "difficulty",
    )

    def __init__(
        self,
        prompt_id: str,
        strategy: str,
        variant_type: str,
        status: str,
        original_prompt: str = "",
        converted_prompt: str = "",
        response_text: str = "",
        score_value: str = "",
        score_reason: str = "",
        latency_seconds: float = 0.0,
        criterion: str = "",
        category: str = "",
        difficulty: str = "",
    ):
        self.prompt_id = prompt_id
        self.strategy = strategy
        self.variant_type = variant_type
        self.status = status
        self.original_prompt = original_prompt
        self.converted_prompt = converted_prompt
        self.response_text = response_text
        self.score_value = score_value
        self.score_reason = score_reason
        self.latency_seconds = latency_seconds
        self.criterion = criterion
        self.category = category
        self.difficulty = difficulty

    def to_dict(self) -> dict:
        return {
            "prompt_id": self.prompt_id,
            "strategy": self.strategy,
            "variant_type": self.variant_type,
            "status": self.status,
            "original_prompt": self.original_prompt[:2000],
            "converted_prompt": self.converted_prompt[:2000],
            "response_text": self.response_text[:2000],
            "score_value": self.score_value,
            "score_reason": self.score_reason[:500],
            "latency_seconds": round(self.latency_seconds, 2),
            "criterion": self.criterion,
            "category": self.category,
            "difficulty": self.difficulty,
        }


# ═══════════════════════════════════════════════════════════════════
# 全自动编排引擎
# ═══════════════════════════════════════════════════════════════════

class ExamAutoOrchestrator:
    """
    考试模式全自动编排引擎。

    预固化攻击流水线：
      Prompt模板 → 变体生成 → 策略匹配 → 并发执行 → 自动评分 → 结果聚合

    考试期间：无需修改任何代码，仅需提供 YAML 模板文件。

    P2 重构: 组合 AI300Orchestrator 消除重复的 _run_pair/_run_tap/_run_flip/...
    等 ~200 行高级攻击执行器代码，统一委托给 PyRIT 原生管道。
    """

    def __init__(
        self,
        template: ExamPromptSet,
        attack_target: PromptTarget,
        scorer_target: PromptTarget | None = None,
        *,
        max_concurrent: int | None = None,
    ):
        """
        Args:
            template: 考试提示词模板集
            attack_target: 攻击目标
            scorer_target: 评分器 LLM（None 则复用 attack_target 安全模式实例）
            max_concurrent: 最大并发数（None 则使用模板配置）
        """
        self.template = template
        self.config = template.config
        self.attack_target = attack_target
        self.scorer_target = scorer_target or OpenAIChatTarget(temperature=0)
        self.max_concurrent = max_concurrent or self.config.max_concurrent
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

        # 变体生成器
        self.variant_gen = PromptVariantGenerator(self.config)

        # 🆕 P2 重构: 组合 AI300Orchestrator 消除重复代码
        # ExamAutoOrchestrator 的 _run_pair / _run_tap / _run_flip / _run_chunked /
        # _run_manyshot / _run_skeleton_key 等方法与 AI300Orchestrator 高度重复。
        # 现通过组合 _pyrit_orch 统一委托，消除约 200 行重复代码。
        self._pyrit_orch = AI300Orchestrator(
            scorer_target=self.scorer_target,
            max_concurrent=self.max_concurrent,
        )

        # 结果收集
        self.results: list[AttackResult] = []
        self._start_time: float = 0.0

    # ═══════════════════════════════════════════════════════════════
    # 主入口：一键执行
    # ═══════════════════════════════════════════════════════════════

    async def run(self) -> list[AttackResult]:
        """主入口：一键执行全部考试提示词的攻击编排。

        执行流程（预固化）：
          Phase 1: 变体生成 + 策略匹配
          Phase 2: PROBE 快速探测（基础策略）
          Phase 3: 单轮主力攻击（编码 + 语义 + 绕过）
          Phase 4: 高级攻击（PAIR/TAP/FLIP — 可选）
          Phase 5: 多轮攻击（CRESCENDO — 可选）
          Phase 6: 结果聚合 + 评分
        """
        self._start_time = time.time()
        console.print(Panel(
            f"[bold cyan]🚀 AI-300 考试模式 — 全自动攻击编排[/bold cyan]\n"
            f"[dim]提示词: {len(self.template.prompts)} 个 | "
            f"变体: {self.config.variants_per_prompt}/个 | "
            f"并发: {self.max_concurrent} | "
            f"语言: {self.config.language}[/dim]",
            style="bold blue",
        ))

        # ── Phase 1: 生成变体 + 匹配策略 ──
        console.print("\n[bold]Phase 1: 变体生成 + 策略匹配...[/bold]")
        attack_tasks = self._build_attack_tasks()
        console.print(f"  [dim]✅ 生成 {sum(len(t) for t in attack_tasks.values())} 个攻击任务[/dim]")

        # ── Phase 2-5: 并发执行 ──
        total_tasks = sum(len(t) for t in attack_tasks.values())
        console.print(f"\n[bold]Phase 2-5: 执行 {total_tasks} 次攻击...[/bold]")

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        task_id = progress.add_task(
            f"⚔️ 全策略攻击中...", total=total_tasks
        )

        coros = []
        for phase, tasks in attack_tasks.items():
            for prompt, variant, strategy in tasks:
                coros.append(
                    self._execute_single_attack(prompt, variant, strategy)
                )

        with Live(
            self._build_live_display(progress, task_id),
            console=console,
            refresh_per_second=4,
        ) as live:
            for coro in asyncio.as_completed(coros):
                result = await coro
                self.results.append(result)
                progress.advance(task_id)
                live.update(self._build_live_display(progress, task_id))

        # ── Phase 6: 结果聚合 ──
        elapsed = time.time() - self._start_time
        console.print(f"\n[bold green]✅ 攻击完成！耗时 {elapsed:.1f}s，共 {len(self.results)} 个结果[/bold green]")
        self._print_phase_summary()

        return self.results

    # ═══════════════════════════════════════════════════════════════
    # 任务构建（预固化）
    # ═══════════════════════════════════════════════════════════════

    def _build_attack_tasks(self) -> dict[str, list[tuple[ExamPrompt, PromptVariant, AttackStrategy]]]:
        """构建攻击任务列表。

        返回: {"phase_name": [(ExamPrompt, PromptVariant, AttackStrategy), ...]}

        分阶段构建：
          - probe: RAW提示词 + PROBE策略
          - single_encoding: 编码变体 + 编码策略
          - single_semantic: 语义变体 + 语义策略
          - advanced: PAIR/TAP/FLIP 等高级策略
          - multiturn: CRESCENDO 多轮策略
        """
        tasks: dict[str, list] = {
            "probe": [],
            "single_encoding": [],
            "single_semantic": [],
            "advanced": [],
            "multiturn": [],
            # ── 新增: RAG / Agent / Infra 攻击阶段 ──
            "rag": [],
            "agent": [],
            "infra": [],
        }

        # ── Payload 生成器 ──
        rag_gen = RAGPayloadGenerator()
        agent_gen = AgentPayloadGenerator()
        infra_gen = InfraPayloadGenerator()

        for prompt in self.template.prompts:
            variants = self.variant_gen.generate(prompt)
            strategies = prompt.resolve_strategies(self.config)

            # 变体 → 策略映射
            encoding_variants = {v["type"] for v in variants
                if v["type"] in ("base64", "rot13", "multilayer", "zerowidth")}
            semantic_variants = {v["type"] for v in variants
                if v["type"] in ("roleplay", "academic", "stealth", "scenario_wrap")}

            for variant in variants:
                var_strategy_name = variant.get("converter_name", "")

                # RAW → PROBE
                if variant["type"] == "raw":
                    tasks["probe"].append((prompt, variant, AttackStrategy.PROBE))
                    # RAW 也走 Skeleton Key + BRUTEFORCE
                    if AttackStrategy.SKELETON_KEY in strategies:
                        tasks["single_encoding"].append((prompt, variant, AttackStrategy.SKELETON_KEY))
                    if AttackStrategy.BRUTEFORCE in strategies:
                        tasks["single_semantic"].append((prompt, variant, AttackStrategy.BRUTEFORCE))

                # 编码变体 → 编码策略
                elif variant["type"] in encoding_variants:
                    if AttackStrategy.BASE64 in strategies:
                        tasks["single_encoding"].append((prompt, variant, AttackStrategy.BASE64))
                    if AttackStrategy.ROT13 in strategies:
                        tasks["single_encoding"].append((prompt, variant, AttackStrategy.ROT13))
                    if AttackStrategy.ENCODING in strategies:
                        tasks["single_encoding"].append((prompt, variant, AttackStrategy.ENCODING))

                # 语义变体 → 语义策略
                elif variant["type"] in semantic_variants:
                    if AttackStrategy.ROLEPLAY in strategies:
                        tasks["single_semantic"].append((prompt, variant, AttackStrategy.ROLEPLAY))
                    if AttackStrategy.ACADEMIC in strategies:
                        tasks["single_semantic"].append((prompt, variant, AttackStrategy.ACADEMIC))
                    if AttackStrategy.TRANSLATION in strategies:
                        tasks["single_semantic"].append((prompt, variant, AttackStrategy.TRANSLATION))
                    if AttackStrategy.STEALTH in strategies:
                        tasks["single_semantic"].append((prompt, variant, AttackStrategy.STEALTH))

                # 语言变体 → 翻译策略
                elif variant["type"] in ("translation_en", "translation_mixed", "deidentification", "synonym_swap"):
                    if AttackStrategy.TRANSLATION in strategies:
                        tasks["single_semantic"].append((prompt, variant, AttackStrategy.TRANSLATION))

            # ── 高级策略（对原始提示词 + 所有变体）──
            advanced_strategies = [
                s for s in strategies
                if s in (AttackStrategy.PAIR, AttackStrategy.TAP, AttackStrategy.FLIP,
                         AttackStrategy.CHUNKED, AttackStrategy.MANYSHOT)
            ]
            if advanced_strategies and self.config.enable_advanced:
                # 仅对 RAW 变体应用高级策略（节省时间）
                raw_variant = next(
                    (v for v in variants if v["type"] == "raw"),
                    {"type": "raw", "prompt": prompt.objective, "converter_name": ""},
                )
                for adv_s in advanced_strategies:
                    tasks["advanced"].append((prompt, raw_variant, adv_s))

            # ── 多轮策略 ──
            if prompt.multi_turn and self.config.enable_multiturn:
                if AttackStrategy.CRESCENDO in strategies:
                    multi_variant = {
                        "type": "raw",
                        "prompt": prompt.multi_turn_stages[0] if prompt.multi_turn_stages else prompt.objective,
                        "converter_name": "",
                        "multi_turn_stages": prompt.multi_turn_stages or [],
                    }
                    tasks["multiturn"].append((prompt, multi_variant, AttackStrategy.CRESCENDO))

            # ── 🆕 RAG 攻击策略 (Module 8) ──
            rag_strategies = [
                s for s in strategies
                if s in (AttackStrategy.RAG_POISON_DOC, AttackStrategy.RAG_RETRIEVAL,
                         AttackStrategy.RAG_LEAK)
            ]
            if rag_strategies:
                cat = prompt.category.value if hasattr(prompt.category, "value") else str(prompt.category)
                rag_payloads = rag_gen.generate(cat, prompt.objective, max_payloads=6)
                for idx, payload in enumerate(rag_payloads):
                    rag_variant = {
                        "type": f"rag_{payload.rag_type.value}",
                        "prompt": payload.text,
                        "converter_name": "",
                        "description": payload.description,
                    }
                    # 将 RAG payload 分配给对应策略（轮转分发）
                    assigned = rag_strategies[idx % len(rag_strategies)]
                    tasks["rag"].append((prompt, rag_variant, assigned))

            # ── 🆕 代理攻击策略 (Module 9-10) ──
            agent_strategies = [
                s for s in strategies
                if s in (AttackStrategy.CROSS_AGENT_INJECT, AttackStrategy.TOOL_CALL_HIJACK,
                         AttackStrategy.ORCHESTRATOR_MANIP, AttackStrategy.MEMORY_POISON)
            ]
            if agent_strategies:
                cat = prompt.category.value if hasattr(prompt.category, "value") else str(prompt.category)
                agent_payloads = agent_gen.generate(cat, prompt.objective, max_payloads=8)
                for idx, payload in enumerate(agent_payloads):
                    agent_variant = {
                        "type": f"agent_{payload.attack_type.value}",
                        "prompt": payload.text,
                        "converter_name": "",
                        "description": payload.description,
                    }
                    assigned = agent_strategies[idx % len(agent_strategies)]
                    tasks["agent"].append((prompt, agent_variant, assigned))

            # ── 🆕 基础设施攻击策略 (Module 11-16) ──
            infra_strategies = [
                s for s in strategies
                if s in (AttackStrategy.API_FUZZ, AttackStrategy.MODEL_SERVING_EXPLOIT,
                         AttackStrategy.SUPPLY_CHAIN_SCAN)
            ]
            if infra_strategies:
                cat = prompt.category.value if hasattr(prompt.category, "value") else str(prompt.category)
                infra_payloads = infra_gen.generate(cat, prompt.objective, max_payloads=8)
                for idx, payload in enumerate(infra_payloads):
                    infra_variant = {
                        "type": f"infra_{payload.attack_type.value}",
                        "prompt": payload.text,
                        "converter_name": "",
                        "description": payload.description,
                    }
                    assigned = infra_strategies[idx % len(infra_strategies)]
                    tasks["infra"].append((prompt, infra_variant, assigned))

        return tasks

    # ═══════════════════════════════════════════════════════════════
    # 攻击执行（预固化核心方法）
    # ═══════════════════════════════════════════════════════════════

    async def _execute_single_attack(
        self,
        exam_prompt: ExamPrompt,
        variant: PromptVariant,
        strategy: AttackStrategy,
    ) -> AttackResult:
        """执行单次攻击 — P2 重构: 高级策略委托给 AI300Orchestrator。

        管道: variant.prompt → (可选 PyRIT Converter) → target → scorer → result

        P2 策略路由:
          - PROBE/编码/语义策略 → 本地 _run_prompt_sending（单轮）
          - PAIR/TAP/FLIP/CHUNKED/MANYSHOT/SKELETON_KEY → AI300Orchestrator._execute_*_attack
          - CRESCENDO → 本地 _run_crescendo
          - RAG/Agent/Infra → 本地 _run_prompt_sending
        """
        async with self._semaphore:
            start = time.time()
            try:
                prompt_text = _resolve_template(
                    variant["prompt"],
                    extra_vars=exam_prompt.template_vars,
                )
                converter_name = variant.get("converter_name", "")
                strategy_name = strategy.value

                # ── 策略路由 ──
                if strategy == AttackStrategy.PROBE:
                    result_dict = await self._run_prompt_sending(
                        prompt_text, exam_prompt, converter_name, strategy_name
                    )
                elif strategy in (AttackStrategy.BASE64, AttackStrategy.ROT13,
                                  AttackStrategy.ROLEPLAY, AttackStrategy.ACADEMIC,
                                  AttackStrategy.STEALTH, AttackStrategy.BRUTEFORCE,
                                  AttackStrategy.TRANSLATION, AttackStrategy.ENCODING,
                                  AttackStrategy.DEEPINCEPTION, AttackStrategy.FEWSHOT,
                                  AttackStrategy.JSON_HIJACK):
                    result_dict = await self._run_prompt_sending(
                        prompt_text, exam_prompt, converter_name, strategy_name
                    )
                # 🆕 P2: 高级策略委托给 AI300Orchestrator
                elif strategy == AttackStrategy.PAIR:
                    result_dict = await self._delegate_to_orch(
                        "pair", exam_prompt, prompt_text, strategy_name
                    )
                elif strategy == AttackStrategy.TAP:
                    result_dict = await self._delegate_to_orch(
                        "tap", exam_prompt, prompt_text, strategy_name
                    )
                elif strategy == AttackStrategy.FLIP:
                    result_dict = await self._delegate_to_orch(
                        "flip", exam_prompt, prompt_text, strategy_name
                    )
                elif strategy == AttackStrategy.CHUNKED:
                    result_dict = await self._delegate_to_orch(
                        "chunked", exam_prompt, prompt_text, strategy_name
                    )
                elif strategy == AttackStrategy.MANYSHOT:
                    result_dict = await self._delegate_to_orch(
                        "manyshot", exam_prompt, prompt_text, strategy_name
                    )
                elif strategy == AttackStrategy.SKELETON_KEY:
                    result_dict = await self._delegate_to_orch(
                        "skeleton_key", exam_prompt, prompt_text, strategy_name
                    )
                elif strategy == AttackStrategy.CRESCENDO:
                    result_dict = await self._run_crescendo(exam_prompt, variant, strategy_name)
                elif strategy in (
                    AttackStrategy.RAG_POISON_DOC, AttackStrategy.RAG_RETRIEVAL, AttackStrategy.RAG_LEAK,
                    AttackStrategy.CROSS_AGENT_INJECT, AttackStrategy.TOOL_CALL_HIJACK,
                    AttackStrategy.ORCHESTRATOR_MANIP, AttackStrategy.MEMORY_POISON,
                    AttackStrategy.API_FUZZ, AttackStrategy.MODEL_SERVING_EXPLOIT, AttackStrategy.SUPPLY_CHAIN_SCAN,
                ):
                    result_dict = await self._run_prompt_sending(
                        prompt_text, exam_prompt, converter_name, strategy_name
                    )
                else:
                    result_dict = await self._run_prompt_sending(
                        prompt_text, exam_prompt, converter_name, strategy_name
                    )

                latency = time.time() - start
                return AttackResult(
                    prompt_id=exam_prompt.id,
                    strategy=strategy_name,
                    variant_type=variant["type"].value if hasattr(variant["type"], "value") else str(variant["type"]),
                    status=result_dict.get("status", "ERROR"),
                    original_prompt=exam_prompt.objective,
                    converted_prompt=result_dict.get("converted_prompt", prompt_text),
                    response_text=result_dict.get("response_text", ""),
                    score_value=result_dict.get("score_value", ""),
                    score_reason=result_dict.get("score_reason", ""),
                    latency_seconds=latency,
                    criterion=exam_prompt.criterion,
                    category=exam_prompt.category.value if hasattr(exam_prompt.category, "value") else str(exam_prompt.category),
                    difficulty=exam_prompt.difficulty.value if hasattr(exam_prompt.difficulty, "value") else str(exam_prompt.difficulty),
                )

            except Exception as e:
                latency = time.time() - start
                logger.error(f"[{exam_prompt.id}] {strategy.value} FAILED: {e}")
                return AttackResult(
                    prompt_id=exam_prompt.id,
                    strategy=strategy.value,
                    variant_type=variant["type"].value if hasattr(variant["type"], "value") else str(variant["type"]),
                    status="ERROR",
                    original_prompt=exam_prompt.objective,
                    converted_prompt=variant["prompt"],
                    response_text="",
                    score_value="",
                    score_reason=str(e)[:500],
                    latency_seconds=latency,
                    criterion=exam_prompt.criterion,
                    category=exam_prompt.category.value if hasattr(exam_prompt.category, "value") else str(exam_prompt.category),
                    difficulty=exam_prompt.difficulty.value if hasattr(exam_prompt.difficulty, "value") else str(exam_prompt.difficulty),
                )

    # ═══════════════════════════════════════════════════════════════
    # 🆕 P2: AI300Orchestrator 委托方法（消除 _run_pair/_run_tap/_run_flip 重复）
    # ═══════════════════════════════════════════════════════════════

    async def _delegate_to_orch(
        self, attack_mode: str,
        exam_prompt: ExamPrompt,
        prompt_text: str,
        strategy_name: str,
    ) -> dict:
        """将高级攻击策略委托给 AI300Orchestrator._execute_*_attack()。

        Args:
            attack_mode: "pair"|"tap"|"flip"|"chunked"|"manyshot"|"skeleton_key"
            exam_prompt: 考试提示词
            prompt_text: 已解析模板变量的提示词文本
            strategy_name: 策略名称（用于日志标签）

        Returns:
            统一格式的 {"status", "converted_prompt", "response_text", "score_value", "score_reason"} dict
        """
        try:
            # 构建与 AI300Orchestrator 兼容的 case/combo 结构
            case = {
                "id": exam_prompt.id,
                "objective": prompt_text,
                "criterion": exam_prompt.criterion,
            }
            combo = {"name": strategy_name, "converters": []}

            executor_map = {
                "pair":         self._pyrit_orch._execute_pair_attack,
                "tap":          self._pyrit_orch._execute_tap_attack,
                "flip":         self._pyrit_orch._execute_flip_attack,
                "chunked":      self._pyrit_orch._execute_chunked_attack,
                "manyshot":     self._pyrit_orch._execute_manyshot_attack,
                "skeleton_key": self._pyrit_orch._execute_skeleton_key_attack,
            }
            executor = executor_map[attack_mode]
            result = await executor(case, combo, self.attack_target)

            return {
                "status": result.get("status", "ERROR"),
                "converted_prompt": result.get("converted_prompt", prompt_text),
                "response_text": result.get("response_text", ""),
                "score_value": result.get("score_reason", ""),
                "score_reason": result.get("score_reason", ""),
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "converted_prompt": prompt_text,
                "response_text": "",
                "score_value": "",
                "score_reason": f"Orch delegation failed: {e}",
            }

    # ═══════════════════════════════════════════════════════════════
    # PyRIT 原生攻击执行器（预固化）
    # ═══════════════════════════════════════════════════════════════

    async def _run_prompt_sending(
        self, prompt_text: str, exam_prompt: ExamPrompt,
        converter_name: str, strategy_name: str,
    ) -> dict:
        """PyRIT PromptSendingAttack 单轮攻击"""
        scoring_config = self._build_scoring_config(exam_prompt)
        converter_config = self._build_converter_config(converter_name)

        # 预应用转换器获取实际投送 prompt（取证用）
        converted_prompt = prompt_text
        if converter_config and converter_config.request_converters:
            for cc in converter_config.request_converters:
                for conv in cc.converters:
                    try:
                        result = await conv.convert_async(prompt=converted_prompt)
                        converted_prompt = (
                            result.output_text
                            if hasattr(result, "output_text")
                            else str(result)
                        )
                    except Exception:
                        pass

        try:
            attack = PromptSendingAttack(
                objective_target=self.attack_target,
                attack_converter_config=converter_config,
                attack_scoring_config=scoring_config,
                max_attempts_on_failure=3,
            )
            result = await attack.execute_async(
                objective=prompt_text,
                memory_labels={
                    "exam_prompt_id": exam_prompt.id,
                    "strategy": strategy_name,
                    "mode": "exam_mode",
                },
            )

            # 提取结果
            score_value = ""
            score_reason = ""
            response_text = ""
            if hasattr(result, "results") and result.results:
                results_list = result.results if isinstance(result.results, list) else [result.results]
                for res in results_list:
                    if hasattr(res, "scores") and res.scores:
                        score_value = str(getattr(res.scores[0], "score_value", ""))
                        score_reason = getattr(res.scores[0], "score_description", "")
                        if score_value.lower() == "true":
                            break
                    if hasattr(res, "response") and res.response:
                        response_text = getattr(res.response, "converted_value", "") or response_text

            is_success = score_value.lower() == "true"
            return {
                "status": "SUCCESS" if is_success else "FAILURE",
                "converted_prompt": converted_prompt,
                "response_text": response_text,
                "score_value": score_value,
                "score_reason": score_reason,
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "converted_prompt": converted_prompt,
                "response_text": "",
                "score_value": "",
                "score_reason": str(e),
            }

    async def _run_crescendo(
        self, exam_prompt: ExamPrompt, variant: PromptVariant,
        strategy_name: str,
    ) -> dict:
        """CrescendoAttack 多轮渐进式攻击"""
        stages = variant.get("multi_turn_stages", [])
        if not stages:
            stages = exam_prompt.multi_turn_stages or []
        if not stages:
            return {
                "status": "ERROR",
                "converted_prompt": exam_prompt.objective,
                "response_text": "无多轮阶段",
                "score_value": "",
                "score_reason": "multi_turn_stages 为空",
            }

        try:
            scoring_config = self._build_scoring_config(exam_prompt)
            adversarial_config = AttackAdversarialConfig(target=self.attack_target)
            attack = CrescendoAttack(
                objective_target=self.attack_target,
                attack_adversarial_config=adversarial_config,
                attack_scoring_config=scoring_config,
                max_turns=len(stages),
                max_backtracks=5,
            )
            result = await attack.execute_async(
                objective=stages[0],
                memory_labels={
                    "exam_prompt_id": exam_prompt.id,
                    "strategy": strategy_name,
                    "mode": "exam_mode_crescendo",
                    "multi_turn_count": str(len(stages)),
                },
            )
            dict_result = self._extract_pyrit_result(result, stages[0])
            dict_result["converted_prompt"] = (
                f"[Crescendo 多轮, {len(stages)} 轮] {stages[0][:500]}"
            )
            return dict_result
        except Exception as e:
            return {"status": "ERROR", "converted_prompt": stages[0],
                    "response_text": "", "score_value": "", "score_reason": str(e)}

    # ═══════════════════════════════════════════════════════════════
    # 辅助方法（预固化）
    # ═══════════════════════════════════════════════════════════════

    def _build_scoring_config(self, exam_prompt: ExamPrompt) -> AttackScoringConfig:
        """构建评分配置（自动根据 category 选择最优评分器）"""
        scorer = create_best_scorer(
            chat_target=self.scorer_target,
            objective=exam_prompt.objective,
            criterion=exam_prompt.criterion,
        )
        return AttackScoringConfig(objective_scorer=scorer)

    def _build_converter_config(self, converter_name: str) -> AttackConverterConfig | None:
        """构建转换器配置"""
        if not converter_name:
            return None
        try:
            converters = resolve_converters([converter_name])
            if converters:
                return AttackConverterConfig(
                    request_converters=[
                        PromptConverterConfiguration(converters=converters)
                    ]
                )
        except Exception:
            pass
        return None

    def _extract_pyrit_result(self, result, prompt_text: str) -> dict:
        """从 PyRIT AttackResult 提取统一格式"""
        score_value = ""
        score_reason = ""
        response_text = ""
        if hasattr(result, "results") and result.results:
            results_list = result.results if isinstance(result.results, list) else [result.results]
            for res in results_list:
                if hasattr(res, "scores") and res.scores:
                    sv = str(getattr(res.scores[0], "score_value", ""))
                    sd = getattr(res.scores[0], "score_description", "")
                    if sv.lower() == "true":
                        score_value = sv
                        score_reason = sd
                        break
                    if not score_value:
                        score_value = sv
                        score_reason = sd
                if hasattr(res, "response") and res.response:
                    response_text = getattr(res.response, "converted_value", "") or response_text
            if not response_text and results_list:
                last_res = results_list[-1]
                if hasattr(last_res, "response") and last_res.response:
                    response_text = getattr(last_res.response, "converted_value", "") or ""

        is_success = score_value.lower() == "true"
        return {
            "status": "SUCCESS" if is_success else "FAILURE",
            "converted_prompt": prompt_text,
            "response_text": response_text,
            "score_value": score_value,
            "score_reason": score_reason,
        }

    # ═══════════════════════════════════════════════════════════════
    # 实时显示
    # ═══════════════════════════════════════════════════════════════

    def _build_live_display(self, progress: Progress, task_id) -> Panel:
        """构建实时执行状态面板"""
        if not self.results:
            return Panel(progress, style="bold blue")

        successes = sum(1 for r in self.results if r.status == "SUCCESS")
        failures = sum(1 for r in self.results if r.status == "FAILURE")
        errors = sum(1 for r in self.results if r.status == "ERROR")
        total = len(self.results)

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(style="bold cyan")
        table.add_column(style="white")
        table.add_row("🎯 成功", f"[bold green]{successes}[/bold green]")
        table.add_row("❌ 失败", f"[bold red]{failures}[/bold red]")
        table.add_row("⚠️  错误", f"[bold yellow]{errors}[/bold yellow]")
        if total > 0:
            rate = successes / total * 100
            table.add_row("📊 命中率", f"[bold]{rate:.1f}%[/bold]")

        return Panel(
            f"{progress}\n{table}",
            style="bold blue",
        )

    def _print_phase_summary(self):
        """打印阶段汇总"""
        if not self.results:
            return

        # 按提示词分组统计
        by_prompt: dict[str, list[AttackResult]] = {}
        for r in self.results:
            by_prompt.setdefault(r.prompt_id, []).append(r)

        console.print("\n[bold cyan]━━━ 提示词级别攻击结果 ━━━[/bold cyan]")
        table = Table(title="攻击成功率明细")
        table.add_column("提示词ID", style="cyan")
        table.add_column("类别", style="dim")
        table.add_column("攻击次数", justify="right")
        table.add_column("成功", justify="right", style="green")
        table.add_column("占比", justify="right", style="bold")

        for pid, results in sorted(by_prompt.items()):
            total = len(results)
            succ = sum(1 for r in results if r.status == "SUCCESS")
            cat = results[0].category if results else "?"
            rate = succ / total * 100 if total > 0 else 0
            table.add_row(pid, cat, str(total), str(succ), f"{rate:.0f}%")

        console.print(table)

    # ═══════════════════════════════════════════════════════════════
    # 结果查询 API
    # ═══════════════════════════════════════════════════════════════

    def get_successes(self) -> list[AttackResult]:
        """获取所有成功攻击"""
        return [r for r in self.results if r.status == "SUCCESS"]

    def get_failures(self) -> list[AttackResult]:
        """获取所有失败攻击"""
        return [r for r in self.results if r.status == "FAILURE"]

    def get_errors(self) -> list[AttackResult]:
        """获取所有错误"""
        return [r for r in self.results if r.status == "ERROR"]

    def get_success_rate(self) -> float:
        """获取整体成功率"""
        total = len(self.results)
        if total == 0:
            return 0.0
        return sum(1 for r in self.results if r.status == "SUCCESS") / total

    def get_prompt_success_rate(self, prompt_id: str) -> float:
        """获取指定提示词的成功率"""
        relevant = [r for r in self.results if r.prompt_id == prompt_id]
        if not relevant:
            return 0.0
        return sum(1 for r in relevant if r.status == "SUCCESS") / len(relevant)

    def get_best_strategy_per_prompt(self) -> dict[str, list[str]]:
        """获取每个提示词的最佳突破策略"""
        best: dict[str, list[str]] = {}
        successes = self.get_successes()
        for r in successes:
            best.setdefault(r.prompt_id, []).append(r.strategy)
        return best

    def to_dict_list(self) -> list[dict]:
        """导出为 dict 列表（兼容现有 reporting 模块）"""
        return [r.to_dict() for r in self.results]
