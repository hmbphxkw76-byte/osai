#!/usr/bin/env python3
"""
PyRIT 端到端全自动 AI 红队框架 - 主入口
============================================

本框架基于 PyRIT 1.0.0 构建，为 OffSec AI-300 考试和实际 AI 红队评估提供
数据驱动的端到端全自动提示词层面攻击流程。

ASR-Guided Strategy (ASR引导策略) — 学术先验驱动 + PyRIT 原生优先:
  - 统一 ASR/Tier 系统 (S>=70% A>=40% B>=15% C>=5% D<5%)
  - technique_name_mapper 标准化映射 (YAML → asr_prior_registry)
  - model_name 全链路传递 (pipeline → wizard → ASRRankBuilder)
  - 三级 ASR 查询: YAML 实测 > 学术先验 > 启发式代理

对齐 PyRIT 1.0.0 数据五层架构（含 ②.5 交互选择层）:
  ① 数据准备层 → DatasetManager.load_datasets() (OWASP / 自定义 / 学术缓存 / PyRIT 远程)
  ② 数据管理层 → CentralMemory (add_seed_datasets_to_memory / get_seed_groups)
  ②.5 交互选择层 → TieredSelectionWizard (ASR 分层 + 预设方案 F/R/D + model_name 感知)
  ③ 攻击准备层 → AttackPreparator.prepare() (SeedGroup → AttackSeedGroup)
  ④ 攻击执行层 → AI300AdaptiveScenario (原生 Scenario.run_async)
  ⑤ 评估与追踪层 → Scorer + PyRIT Memory 审计链

对齐 PyRIT 1.0.0 Executor 五层架构:
  Layer 1: Prompt Generators (种子生成 — Anecdoctor/Fuzzer)
  Layer 2: Attack (执行层 — SingleTurn/MultiTurn/NativeAttackExecutor Facade)
  Layer 3: Compound (策略编排 — SequentialExecutor + FIRST_SUCCESS)
  Layer 4: Workflow (批量编排 — AI300AdaptiveScenario 原生 Scenario)
  Layer 5: Benchmarks (标准测试 — FairnessBias/QuestionAnswering)

④ 层执行路径（L5 统一 — PyRIT 原生优先）:
  AI300AdaptiveScenario → 原生 Scenario.run_async() (并行 + 弹性 + resume)
    ├── 原生 AttackExecutor (Semaphore 并发控制 + max_retries 弹性恢复)
    ├── 原生 SequentialAttack (FIRST_SUCCESS 提前停止)
    ├── FailureTypeRoutingSelector (失败类型路由 + epsilon-greedy 探索)
    ├── Converter 变体 (extra_request_converters 动态创建)
    └── StopStrategyContext (L2 OWASP 阈值 + L3 全局首停)

流程:
  [1/9] 初始化 PyRIT (CentralMemory + SQLite + AI300SetupManager)
  [2/9] 侦察阶段 (端点发现 + AI 类型识别)
  [3/9] 分析阶段 (策略选择 + 优先级评估 + ASR引导策略策略分析)
  [4/9] ①→② 数据准备 + 管理 (DatasetManager → CentralMemory)
  [5/9] ②→②.5→③ 查询 + 交互选择 + 攻击准备 (ASR引导策略 ASR 排序展示)
  [6/9] ④ 批量执行攻击 (原生 AdaptiveScenario + ASR引导策略执行决策展示)
  [7/9] 输出执行结果 (ASR引导策略 ASR 实测 vs 学术先验对比)
  [8/9] 报告生成 (OWASP 映射 + 证据导出)
  [9/9] 总结

Usage:
  python pipeline.py                              # 使用 .env 中的目标
  python pipeline.py http://192.168.0.22:11434    # 指定目标 URL

环境变量:
  VERBOSE=1                  # 输出每个成功攻击的完整详情
  VERBOSE_SUCCESS=1          # 同上，仅对成功攻击输出详情
  INTERACTIVE_SELECTION=false # 禁用交互式选择（CI/CD 模式，全选）
  BATCH_MAX_CONCURRENCY=2    # 覆盖配置文件中的并发数
  BATCH_PER_ATTACK_TIMEOUT=300  # 覆盖配置文件中的超时
  STRATEGY_MODE=academic     # ASR引导策略策略模式 (academic/exam/balanced)
  TARGET_MODEL_FOR_ASR=gpt-4o  # ASR引导策略学术ASR查询模型名
  ACADEMIC_PAYLOADS_ENABLED=true  # 启用学术载荷本地缓存
"""

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# 导入框架模块
from src.core.config_loader import get_config_loader
from src.core.logging_utils import setup_logging
from src.core.models import AuthResult, AuthStatus, AuthType
from src.core.pipeline_display import get_display, reset_display
from src.recon import recon_target
from src.analysis import select_strategy, evaluate_priority
from src.analysis.strategy_selector import StrategySelector
from src.payloads import (
    DatasetManager,
    SeedGroupSelector,
    AttackPreparator,
    SeedPromptAdapter,
    plan_attacks,
    TargetType,
    TieredSelectionWizard,
    SelectionPreset,
    FallbackStrategy,
)
from src.executor import reset_executor  # L5: 执行后清理 NativeAttackExecutor 单例
from src.reporting import generate_report
from src.targets import create_prompt_target, create_judge_target, TargetParams
from src.targets.rate_limited_target import (
    RateLimitConfig,
    wrap_target_with_rate_limiting,
)

# Fix Windows terminal Unicode encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ============================================================
# 顺序管道
# ============================================================


async def run_attack_pipeline(target_url: str, owasp_ids: list[str] | None = None):
    """
    执行完整的攻击流程（顺序管道）

    流程: 侦察 → 分析 → 加载数据源 → 载荷规划 → 批量攻击 → 输出 → 报告

    Args:
        target_url: 目标 URL (如 http://192.168.0.22:11434)
        owasp_ids: 指定 OWASP 分类列表 (如 ["llm01", "llm06"])，
                   None 表示加载全部
    """
    config_loader = get_config_loader()
    start_time = datetime.now()

    # 预先生成 exam_id，供数据库路径和报告使用
    exam_id = f"exam_{start_time.strftime('%Y%m%d_%H%M%S')}"

    # 设置日志文件
    log_path = setup_logging(config_loader, start_time)

    # 读取 verbose 配置（.env VERBOSE_SUCCESS > config/defaults/pipeline.yaml）
    # 合并精简：统一使用 verbose_success（仅成功攻击详情输出）
    verbose = config_loader.get_verbose_success()

    # 从环境变量读取目标/评分器配置（.env 必填）
    target_endpoint = os.getenv("TARGET_ENDPOINT", f"{target_url.rstrip('/')}/v1")
    target_model = os.getenv("TARGET_MODEL", "qwen3:0.6b")
    target_api_key = os.getenv("TARGET_API_KEY", "ollama")

    judge_endpoint = os.getenv("JUDGE_ENDPOINT", target_endpoint)
    judge_model = os.getenv("JUDGE_MODEL", "qwen3:1.7b")
    judge_api_key = os.getenv("JUDGE_API_KEY", "ollama")

    print("\n" + "=" * 60)
    print("  PyRIT 端到端全自动 AI 红队框架 ")
    print("=" * 60)
    print(f"\n目标 URL: {target_url}")
    print(f"目标端点: {target_endpoint}")
    print(f"目标模型: {target_model}")
    print(f"评分器端点: {judge_endpoint}")
    print(f"评分器模型: {judge_model}")
    print(f"开始时间: {start_time.isoformat()}")
    print(f"日志文件: {log_path}")
    print(f"Verbose: {'开启 (成功攻击详情输出)' if verbose else '关闭'}")

    # v3.0: 安装 PyRIT 噪音过滤器
    display = get_display(stage_total=9)
    display.install_noise_filter(log_path)

    # ---------------------------------------------------------
    # 1. 初始化 PyRIT (对齐 PyRIT 1.0.0 Setup 三步流程)
    # ---------------------------------------------------------
    print("\n[1/9] 初始化 PyRIT...")
    # 使用每次运行独立的数据库路径，彻底避免旧数据残留和文件锁定问题
    db_base_path = Path(config_loader.get_memory_db_path())
    db_path = db_base_path.parent / f"{exam_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # 对齐 PyRIT 1.0.0 Setup 文档（L5 原生优先）：
    #   Step 1: 自动发现并加载 .env / .env_local（由原生 initialize_pyrit_async 统一加载）
    #   Step 2: 数据库配置 (SQLite + 每次独立路径)
    #   Step 3: 初始化器执行（原生优先 + AI-300 扩展）
    #     AI300DefaultValuesInitializer → 设置默认值
    #     AI300TargetInitializer → 委托原生 TargetInitializer + AI-300 Target
    #     AI300ScorerInitializer → 委托原生 ScorerInitializer + AI-300 Scorer
    #     AI300TechniqueInitializerWrapper → 注册 34 个攻击技术
    #     AI300LoadDefaultDatasets → 加载 OWASP 数据集
    #     AI300PreloadScenarioMetadata → 预热 Scenario 元数据
    from src.setup import initialize_ai300_async

    # 重试配置由 AI300SetupManager 内部自动传播（configure_retry=True）
    # Scenario 级别重试 (对齐 PyRIT max_retries)
    scenario_max_retries = config_loader.get_scenario_max_retries()
    print(f"  [OK] Scenario 重试: max_retries={scenario_max_retries} (total={1 + scenario_max_retries})")

    # 停止策略 (三层最优策略)
    owasp_success_threshold = config_loader.get_owasp_success_threshold()
    stop_on_first_success = config_loader.get_stop_on_first_success()
    print(f"  [OK] 停止策略: L2 OWASP阈值={owasp_success_threshold:.0%}, L3 全局首停={stop_on_first_success}")

    # 使用 AI300SetupManager（原生优先 + AI-300 扩展）
    # project_root 让 manager 自动发现 .env / .env_local（项目根 + ~/.pyrit/）
    # .env 已在模块入口处 load_dotenv 预加载，此处由原生统一加载（含 ~/.pyrit/.env）
    setup_manager = await initialize_ai300_async(
        memory_db_type=config_loader.get_memory_db_type(),
        project_root=Path(__file__).parent,
        db_path=str(db_path),
        silent=False,
    )
    retry_config = setup_manager.retry_config
    if retry_config:
        print(f"  [OK] 重试配置: {retry_config}")
    print(f"  [OK] Memory 后端: {config_loader.get_memory_db_type()}")
    print(f"  [OK] 数据库路径: {db_path}")

    # ---------------------------------------------------------
    # 2. 侦察阶段（端点发现 + AI 类型识别）
    # ---------------------------------------------------------
    print("\n[2/9] 执行侦察...")
    recon_result = await recon_target(
        target_url, api_key=target_api_key, model_name=target_model
    )
    print(f"  [OK] 检测端点: {recon_result.detected_endpoint}")
    print(f"  [OK] 认证类型: {recon_result.auth_type.value}")
    print(f"  [OK] AI 系统类型: {recon_result.ai_system_type.value}")
    print(f"  [OK] 模型分层: {recon_result.model_tier}")
    # v3.0: 显示 target_type（用于后续载荷预筛选 + Converter 路由）
    if getattr(recon_result, "target_type", ""):
        print(f"  [OK] Target 类型: {recon_result.target_type}")

    # 检查是否为 PyRIT 可攻击类型
    if not recon_result.ai_system_type.is_pyrit_attackable():
        print(f"\n  [!] 该类型 ({recon_result.ai_system_type.value}) 非提示词攻击领域")
        print(f"  [!] 推荐外部工具: {', '.join(recon_result.external_tools or [])}")
        print("\n  跳过 PyRIT 攻击")
        return None

    # ---------------------------------------------------------
    # 3. 分析阶段（策略选择 + 优先级评估）
    # ---------------------------------------------------------
    print("\n[3/9] 执行分析（策略选择 + 优先级评估）...")

    # 构造认证结果（Ollama 无需认证）
    auth_result = AuthResult(
        target_url=target_url,
        auth_type=AuthType.NONE,
        status=AuthStatus.SUCCESS,
        auth_headers={"Content-Type": "application/json"},
    )

    # 策略选择
    strategy_selection = select_strategy(auth_result, recon_result)
    print(f"  [OK] 选择 Scenario: {strategy_selection.scenario_name}")
    print(f"  [OK] 攻击技术: {', '.join(strategy_selection.attack_techniques)}")

    # v3.0: model_tier 驱动策略模式推荐展示
    recommended_mode = StrategySelector.recommend_strategy_mode(recon_result)
    print(f"  [OK] 推荐策略模式: {recommended_mode} (model_tier={recon_result.model_tier})")

    # 优先级评估
    priority_score = evaluate_priority(recon_result)
    print(f"  [OK] 目标优先级: {priority_score}/100")

    # ASR引导策略: 策略分析展示（使用侦察结果中的探测式模型分层）
    from src.scenarios.asr_strategy_display import display_analysis_stage
    strategy_info = display_analysis_stage(target_model=target_model, recon_result=recon_result)

    # ---------------------------------------------------------
    # 4. ①→② 数据准备 + 管理（DatasetManager → CentralMemory）
    # ---------------------------------------------------------
    print("\n[4/9] ①→② 数据准备 + 管理 (DatasetManager → CentralMemory)...")

    # CLI 参数优先于配置文件（统一从 dataset_manager 配置段读取）
    dm_owasp_cfg = config_loader.get_dataset_manager_owasp_config()
    dm_custom_cfg = config_loader.get_dataset_manager_custom_config()
    dm_academic_cfg = config_loader.get_dataset_manager_academic_config()
    dm_remote_cfg = config_loader.get_dataset_manager_remote_config()

    config_owasp_ids = owasp_ids if owasp_ids else dm_owasp_cfg.get("owasp_ids", [])
    exclude_ids = dm_owasp_cfg.get("exclude_ids", [])
    include_custom = dm_custom_cfg.get("enabled", True)
    include_academic = dm_academic_cfg.get("enabled", False)

    # 远程数据集配置
    include_remote = dm_remote_cfg.get("enabled", False)
    remote_dataset_names = dm_remote_cfg.get("datasets", [])

    if config_owasp_ids:
        print(f"  [OK] OWASP 筛选: {', '.join(config_owasp_ids)}")
    if include_academic:
        print("  [OK] 学术载荷: data/academic/ (本地缓存)")

    if include_remote:
        if remote_dataset_names:
            print(f"  [OK] 远程数据集: {', '.join(remote_dataset_names)}")
        else:
            print("  [OK] 远程数据集: 全部已注册")

    # ① 数据准备层 + ② 数据管理层: 加载数据源 → CentralMemory
    manager = DatasetManager()
    await manager.load_datasets(
        owasp=True,
        owasp_frameworks=dm_owasp_cfg.get("frameworks", ["llm", "agentic"]),
        owasp_ids=config_owasp_ids or None,
        exclude_ids=exclude_ids or None,
        custom=include_custom,
        academic=include_academic,
        remote=include_remote,
        remote_dataset_names=remote_dataset_names if include_remote else None,
    )

    total_seeds = len(manager.get_seeds())
    total_groups = len(manager.get_seed_groups())
    print(f"  [OK] CentralMemory: {total_seeds} seeds, {total_groups} seed groups")

    # v3.0: target_type 驱动载荷预筛选展示
    # 适配链断裂 3 修复：target_type 从 Recon 传递到 Datasets 层，
    # 用于预筛选载荷的 OWASP 分类匹配
    _recon_target_type = getattr(recon_result, "target_type", "")
    if _recon_target_type:
        try:
            from src.converters.target_aware_router import get_target_group
            _target_group = get_target_group(_recon_target_type)
            print(f"  [OK] Target 感知分组: {_recon_target_type} → {_target_group}")
        except Exception:
            pass

    # 数据源多样性报告
    # v4.0: 使用统一 Tier A 阈值 (>=40%) 替代硬编码 65%
    from src.payloads.technique_name_mapper import TIER_A_THRESHOLD as _HIGH_ASR_THRESHOLD
    _all_seeds = manager.get_seeds()
    _owasp_counts: dict[str, int] = {}
    _technique_counts: dict[str, int] = {}
    _asr_high = 0
    for _s in _all_seeds:
        _meta = getattr(_s, "metadata", {}) or {}
        _oid = _meta.get("owasp_id", "unknown")
        _owasp_counts[_oid] = _owasp_counts.get(_oid, 0) + 1
        _tg = _meta.get("technique_group", _meta.get("technique", "unknown"))
        _technique_counts[_tg] = _technique_counts.get(_tg, 0) + 1
        _asr = _meta.get("asr_baseline", {})
        if _asr:
            _numeric_asr = [v for v in _asr.values() if isinstance(v, (int, float))]
            if _numeric_asr and max(_numeric_asr) >= _HIGH_ASR_THRESHOLD:
                _asr_high += 1
    print(f"  [OK] OWASP 覆盖: {len(_owasp_counts)} 分类")
    for _oid in sorted(_owasp_counts):
        print(f"    {_oid}: {_owasp_counts[_oid]} seeds")
    print(f"  [OK] 技术覆盖: {len(_technique_counts)} 种技术组")
    print(f"  [OK] 高 ASR 载荷 (>= {_HIGH_ASR_THRESHOLD:.0%}, Tier S/A): {_asr_high} seeds")

    # Burp HTTP 请求模板补充（data/burp/）
    _burp_dir = Path(__file__).parent / "data" / "burp"
    _burp_files = list(_burp_dir.glob("*.txt")) if _burp_dir.exists() else []
    if _burp_files:
        print(f"  [OK] Burp HTTP 模板: {len(_burp_files)} 个 (data/burp/)")

    if total_groups == 0:
        print("  [!] 未加载到任何种子数据，跳过攻击")
        return None

    # ---------------------------------------------------------
    # 5. ②→②.5→③ 查询 + 交互选择 + 攻击准备
    # ---------------------------------------------------------
    print("\n[5/9] ②→②.5→③ 查询 + 交互选择 + 攻击准备...")

    # ② 从 CentralMemory 查询种子组
    all_seed_groups = manager.get_seed_groups()
    print(f"  [OK] 查询种子组: {len(all_seed_groups)} 个")

    # ②.5 交互式选择层 - 三层渐进式或旧版 SeedGroupSelector
    # 优先级：.env > config/defaults/pipeline.yaml > config.yaml
    tiered_cfg = config_loader.get_tiered_selection_config()
    tiered_enabled = tiered_cfg.get("enabled", True)
    interactive_cfg = config_loader.get_interactive_selection_config()
    interactive_enabled = config_loader.get_interactive_selection_enabled()

    # 三层渐进式选择路径（新）
    if tiered_enabled:
        print("  [OK] 选择模式: 三层渐进式 (Tiered Progressive Disclosure)")

        # 构建 preset（从配置或 CLI 参数）
        preset_target = tiered_cfg.get("target_type")
        if preset_target:
            # 非交互模式：预设目标类型
            try:
                tt = TargetType.from_string(preset_target)
            except ValueError:
                tt = None
            wizard_preset = SelectionPreset(
                target_type=tt,
                top_n=tiered_cfg.get("top_n", 3),
                fallback_strategy=FallbackStrategy(
                    tiered_cfg.get("fallback_strategy", "sequential_asr_desc")
                ),
            )
            wizard = TieredSelectionWizard(
                enabled=False,
                preset=wizard_preset,
                model_name=strategy_info.get("model_name", target_model),
            )
        else:
            # 交互模式
            wizard = TieredSelectionWizard(
                enabled=interactive_enabled,
                model_name=strategy_info.get("model_name", target_model),
            )

        selection_result = await wizard.select(all_seed_groups)
        selected_groups = selection_result.selected_groups
        fallback_strategy = selection_result.fallback_strategy
        fallback_chain = selection_result.fallback_chain

        print(f"  [OK] 目标类型: {selection_result.target_profile.target_type.display_name}")
        print(f"  [OK] 选中: {len(selected_groups)}/{len(all_seed_groups)} 个种子组 (top-{tiered_cfg.get('top_n', 3)})")
        print(f"  [OK] 降级策略: {fallback_strategy.display_name}")
        planning_groups = selected_groups
        if fallback_strategy != FallbackStrategy.PARALLEL:
            print(f"  [OK] 计划组: {len(planning_groups)} (选中组, 原生 AdaptiveScenario)")

    else:
        # 旧版 SeedGroupSelector 路径（向后兼容）
        print("  [OK] 选择模式: 旧版 SeedGroupSelector (向后兼容)")
        fallback_strategy = FallbackStrategy.PARALLEL  # 旧版不使用组级降级
        fallback_chain = []

        selector = SeedGroupSelector(
            enabled=interactive_enabled,
            auto_select_if_single=interactive_cfg.get("auto_select_if_single", True),
            page_size=interactive_cfg.get("page_size", 20),
        )
        catalog = selector.build_catalog(all_seed_groups)

        # 预设选择（从 CLI 参数或配置）
        preset_owasp = owasp_ids if owasp_ids else None
        preset_modes = None  # 可通过 CLI 扩展

        selected_groups = await selector.prompt_user(
            catalog,
            preset_owasp=preset_owasp,
            preset_modes=preset_modes,
        )
        print(f"  [OK] 用户选择: {len(selected_groups)}/{len(all_seed_groups)} 个种子组")
        planning_groups = selected_groups

    if not selected_groups:
        print("  [!] 未选择任何种子组，跳过攻击")
        return None

    # ③ AttackPreparator 准备（使用 planning_groups 生成全链计划）
    attack_groups = await AttackPreparator.prepare_batch(planning_groups)
    multi_turn = sum(1 for ag in attack_groups if AttackPreparator.is_multi_turn(ag))

    # 桥接 ③→④: SeedGroup → PromptBatch → AttackPlan
    # v4.0: target_type 在 [6/9] 由 create_prompt_target 返回，此处尚不可用。
    # L5 原生 AdaptiveScenario 路径在执行层原生处理 Target 感知 Converter 路由，
    # 因此 plan_attacks 无需 target_type（旧版 Legacy 增强，已被原生路径覆盖）。
    prompt_batches = SeedPromptAdapter.seed_groups_to_batches(planning_groups)
    total_prompts = sum(len(batch.prompts) for batch in prompt_batches)
    attack_plans = plan_attacks(prompt_batches, strategy_selection)

    # ASR引导策略: 学术 ASR 先验排序展示
    from src.scenarios.asr_strategy_display import display_selection_stage
    display_selection_stage(
        selected_groups=selected_groups,
        all_seed_groups=all_seed_groups,
        model_name=strategy_info.get("model_name", target_model),
        strategy_mode=strategy_info.get("strategy_mode", "academic"),
    )

    # ASR引导策略: 友好提示 — 模型感知技术选择摘要
    _strat_model = strategy_info.get("model_name", target_model)
    _strat_mode = strategy_info.get("strategy_mode", "academic")
    _strat_tier = strategy_info.get("model_tier", "unknown")
    print(f"  [ASR引导策略] 模型={_strat_model} | 分层={_strat_tier} | 策略={_strat_mode}")
    if _strat_mode == "academic" and _strat_tier == "strong":
        print("  [ASR引导策略] 强过滤模型 → 优先多轮迭代+Converter增强 (Tier S/A 技术)")
    elif _strat_mode == "exam":
        print("  [ASR引导策略] 考试模式 → 编码优先快速验证, 策略攻击兜底")
    else:
        print("  [ASR引导策略] 均衡模式 → 各 Tier 交替尝试, 兼顾覆盖与效率")

    # --- 精简摘要：只显示本轮攻击密切相关的信息 ---
    print(f"  [OK] 攻击计划: {len(attack_plans)} 个 "
          f"(选中 {len(selected_groups)} 组 → 全链 {len(planning_groups)} 组, "
          f"{total_prompts} 提示词, {multi_turn} 多轮 / {len(attack_groups) - multi_turn} 单轮)")

    # 本轮选中的技术组 + OWASP 覆盖（只显示选中组，不展开降级链）
    if tiered_enabled and selection_result.ranked_groups:
        # 从 ranked_groups 中提取选中组的技术信息
        selected_tech_names = set()
        selected_owasp_ids = set()
        for sg in selected_groups:
            for seed in sg.seeds:
                meta = getattr(seed, "metadata", {}) or {}
                tech = meta.get("technique_group", meta.get("technique", ""))
                if tech:
                    selected_tech_names.add(tech)
                owasp = meta.get("owasp_id", "")
                if owasp:
                    selected_owasp_ids.add(owasp)
        if selected_tech_names:
            print(f"  [OK] 攻击技术: {', '.join(sorted(selected_tech_names))}")
        if selected_owasp_ids:
            print(f"  [OK] OWASP 覆盖: {', '.join(sorted(selected_owasp_ids))}")

        # 降级链摘要（只显示 Tier 级别，不展开全部组）
        if fallback_chain:
            tier_summary = []
            for tier_groups in fallback_chain:
                if not tier_groups:
                    continue
                tier_val = tier_groups[0].tier.value
                tier_summary.append(f"{tier_val}={len(tier_groups)}组")
            if tier_summary:
                print(f"  [OK] 降级链: {' → '.join(tier_summary)} ({fallback_strategy.display_name})")
    else:
        # 旧版路径：显示技术分布
        technique_counts = {}
        for plan in attack_plans:
            technique_counts[plan.attack_technique] = technique_counts.get(plan.attack_technique, 0) + 1
        if technique_counts:
            tech_str = ", ".join(f"{t}({c})" for t, c in sorted(technique_counts.items(), key=lambda x: -x[1]))
            print(f"  [OK] 攻击技术: {tech_str}")

    # verbose 模式下补充完整统计
    if verbose:
        has_objective = sum(1 for ag in attack_groups if ag.objective is not None)
        synthetic = sum(1 for ag in attack_groups
                        if any(getattr(s, 'metadata', {}).get("synthetic_objective", False)
                               for s in ag.seeds))
        print(f"  [DETAIL] AttackSeedGroup: {len(attack_groups)} 个 "
              f"(原生objective: {has_objective}, 合成: {synthetic})")
        mode_counts = {}
        for batch in prompt_batches:
            for item in batch.prompts:
                mode_counts[item.attack_mode.value] = mode_counts.get(item.attack_mode.value, 0) + 1
        for mode, count in sorted(mode_counts.items()):
            print(f"  [DETAIL]   {mode}: {count} 个")
        scorer_counts = {}
        for plan in attack_plans:
            scorer_counts[plan.scorer_type] = scorer_counts.get(plan.scorer_type, 0) + 1
        for s_type, count in sorted(scorer_counts.items(), key=lambda x: -x[1]):
            print(f"  [DETAIL] 评分器 {s_type}: {count} 个")

    # ---------------------------------------------------------
    # 6. 创建攻击组件 + 批量执行攻击
    # ---------------------------------------------------------
    print("\n[6/9] 创建攻击组件并批量执行...")

    # API 级别限速配置（对齐 PyRIT Resiliency 文档）
    # PyRIT 原生已处理：RPM 限速(@limit_requests_per_minute) + 429 重试(@pyrit_target_retry)
    # 自建补充：API 并发信号量 + 503/502 重试（PyRIT 原生不覆盖）
    api_max_concurrent = int(os.getenv("API_MAX_CONCURRENCY", "10"))
    target_rpm = os.getenv("TARGET_MAX_RPM")
    target_rpm = int(target_rpm) if target_rpm else None
    judge_rpm = os.getenv("JUDGE_MAX_RPM")
    judge_rpm = int(judge_rpm) if judge_rpm else None

    # 创建目标 Target（PyRIT 原生优先：能力探测 apply=True 由 TargetFactory 原生执行）
    # 侦察阶段已通过 get_known_capabilities() 获取静态能力供策略选择，
    # 此处 TargetFactory 执行运行时能力探测（discover_target_capabilities_async）
    # 并以 apply=True 将结果直接安装到 Target，使原生 ADAPT/RAISE 策略生效。
    # max_requests_per_minute → 激活 PyRIT 原生 @limit_requests_per_minute 装饰器
    # capability_policy='adapt' → 未知模型不支持 MULTI_TURN 时用对话规范化降级，不崩溃
    target_params = TargetParams(
        max_requests_per_minute=target_rpm,
        capability_policy="adapt",
    )
    objective_target, target_type = await create_prompt_target(
        target_url=target_url,
        api_key=target_api_key,
        model_name=target_model,
        params=target_params,
    )
    print(f"  [OK] 目标 Target: {type(objective_target).__name__} ({target_type})")
    print(f"  [OK] 目标模型: {target_model}")
    if target_rpm:
        print(f"  [OK] 目标 RPM 限速: {target_rpm} req/min (PyRIT 原生 @limit_requests_per_minute)")

    # API 并发信号量 + 503 重试包装（补充 PyRIT 原生盲区）
    # max_concurrency=1 只限制并发攻击计划数，不限制单攻击内的并发 API 调用
    # TAP/PAIR 的 tree_width/branching_factor/batch_size 会在单次攻击内产生大量并发请求
    objective_target = wrap_target_with_rate_limiting(
        objective_target,
        config=RateLimitConfig(max_concurrent_requests=api_max_concurrent),
        semaphore_key=f"objective:{target_endpoint}",
    )
    print(f"  [OK] API 并发信号量: max_concurrent={api_max_concurrent} + 503 重试 (RETRY_* env)")

    # 创建评分器 Target（L5: 从 config/defaults/ 读取评分器最优参数）
    # temperature=0 确保评分可复现，force_json_output 确保评分格式可解析
    # max_requests_per_minute → 激活 PyRIT 原生 @limit_requests_per_minute 装饰器
    judge_params = TargetParams(
        temperature=config_loader.get_judge_temperature(),
        top_p=config_loader.get_judge_top_p(),
        force_json_output=config_loader.get_judge_force_json_output(),
        discover_capabilities=False,
        max_requests_per_minute=judge_rpm,
    )
    judge_target, judge_type = await create_judge_target(
        judge_url=judge_endpoint,
        api_key=judge_api_key,
        model_name=judge_model,
        params=judge_params,
    )
    print(f"  [OK] 评分器 Target: {type(judge_target).__name__} ({judge_type})")
    print(f"  [OK] 评分器模型: {judge_model}")
    print("  [OK] 评分器仅用于 objective scoring")

    # 创建 Converter Target（LLM 辅助 Converter 专用）
    # 关键修复：Converter Target 不能使用 judge_target（安全对齐模型会拒绝生成攻击内容）
    # 默认使用目标模型（被测试的 LLM），可通过 CONVERTER_* 环境变量单独配置
    converter_endpoint = os.getenv("CONVERTER_ENDPOINT", target_endpoint)
    converter_model = os.getenv("CONVERTER_MODEL", target_model)
    converter_api_key = os.getenv("CONVERTER_API_KEY", target_api_key)
    converter_rpm = os.getenv("CONVERTER_MAX_RPM")
    converter_rpm = int(converter_rpm) if converter_rpm else None

    if converter_endpoint == target_endpoint and converter_model == target_model:
        # 复用已创建的 objective_target（避免重复创建连接池）
        converter_target = objective_target
        print(f"  [OK] Converter Target: 复用目标模型 ({converter_model})")
    else:
        converter_params = TargetParams(
            temperature=0.7,  # Converter 需要一定创造性
            discover_capabilities=False,
            max_requests_per_minute=converter_rpm,
        )
        converter_target, converter_type = await create_prompt_target(
            target_url=converter_endpoint,
            api_key=converter_api_key,
            model_name=converter_model,
            params=converter_params,
        )
        converter_target = wrap_target_with_rate_limiting(
            converter_target,
            config=RateLimitConfig(max_concurrent_requests=api_max_concurrent),
            semaphore_key=f"converter:{converter_endpoint}",
        )
        print(f"  [OK] Converter Target: {type(converter_target).__name__} ({converter_type})")
        print(f"  [OK] Converter 模型: {converter_model}")
    print("  [OK] Converter Target 用于 LLM 辅助 Converter (Persuasion/Decomposition 等)")

    # 评分器 API 并发信号量 + 503 重试包装
    judge_target = wrap_target_with_rate_limiting(
        judge_target,
        config=RateLimitConfig(max_concurrent_requests=api_max_concurrent),
        semaphore_key=f"judge:{judge_endpoint}",
    )
    if judge_rpm:
        print(f"  [OK] 评分器 RPM 限速: {judge_rpm} req/min (PyRIT 原生)")
    print(f"  [OK] 评分器并发信号量: max_concurrent={api_max_concurrent} + 503 重试")

    # 批量执行配置（.env > config/defaults/pipeline.yaml > config.yaml）
    max_concurrency = config_loader.get_pipeline_max_concurrency()
    per_attack_timeout = config_loader.get_pipeline_per_attack_timeout()
    timeout_overrides = config_loader.get_pipeline_timeout_overrides()

    print(f"  [OK] 最大并发: {max_concurrency}")
    if timeout_overrides:
        override_str = ", ".join(f"{k}={v}s" for k, v in timeout_overrides.items())
        print(f"  [OK] 差异化超时: {override_str}  (默认: {per_attack_timeout}s)")
    else:
        print(f"  [OK] 单次超时: {per_attack_timeout}s")
    print(f"  [OK] 开始执行 {len(attack_plans)} 个攻击计划...")
    if fallback_strategy != FallbackStrategy.PARALLEL and fallback_chain:
        print(f"  [OK] 组级降级链: {fallback_strategy.display_name}")
    # ASR引导策略: 执行前友好提示
    _exec_model = strategy_info.get("model_name", target_model)
    _exec_mode = strategy_info.get("strategy_mode", "academic")
    print(f"  [ASR引导策略] 正在以 {_exec_mode} 策略对 {_exec_model} 发起攻击...")
    print("  [ASR引导策略] 原生 AdaptiveScenario 将自动执行: 技术选择 → Converter路由 → 执行 → 失败路由 → 升级")
    print()

    print("  [OK] 执行模式: 原生 AdaptiveScenario (L5 统一路径, Converter 变体)")

    # 原生 AdaptiveScenario 路径使用独立的并发数：
    # pipeline max_concurrency=1 是为降级链设计的（串行避免限流），
    # 但原生 Scenario 的 AttackExecutor 已有 Semaphore 控制并发 API 调用，
    # 且 Target 已有独立 RateLimitConfig(max_concurrent_requests=api_max_concurrent) 保护。
    # 使用 ADAPTIVE_MAX_CONCURRENCY（默认 4）提高吞吐量，API 级限速仍由 Target 层保护。
    adaptive_max_concurrency = int(os.getenv("ADAPTIVE_MAX_CONCURRENCY", "4"))
    print(f"  [OK] 原生并发: {adaptive_max_concurrency} (API 级限速: {api_max_concurrent})")

    # P3: 执行前展示 Target 感知 Converter 路由信息
    try:
        from src.converters.target_aware_router import (
            get_target_group,
            get_target_converter_profile,
            select_converter_chains_for_target,
        )
        if target_type:
            _group = get_target_group(target_type)
            _profile = get_target_converter_profile(target_type)
            _chains = select_converter_chains_for_target(
                target_type,
                converter_target_available=True,
            )
            print(f"  [OK] Target 感知路由: {target_type} → {_group}")
            print(f"  [OK] 安全机制: {_profile.get('bypass_mechanism', 'unknown')}")
            print(f"  [OK] 推荐 Converter 链: {', '.join(_chains[:5])}")
    except Exception:
        pass  # 非关键路径，静默失败

    # ASR引导策略: 执行决策展示
    from src.scenarios.asr_strategy_display import display_execution_stage
    display_execution_stage(
        target_type=target_type or "",
        model_name=strategy_info.get("model_name", target_model),
        strategy_mode=strategy_info.get("strategy_mode", "academic"),
        attack_plans=attack_plans,
    )

    # v3.0: 适配链决策汇总展示（从 Recon → Analysis → Converters → Executor 的完整传递）
    try:
        _adapt_chains = []
        if target_type:
            _adapt_chains = select_converter_chains_for_target(
                target_type,
                converter_target_available=(converter_target is not None),
            )
        display.display_adaptation_chain(
            target_type=target_type or "",
            target_group=get_target_group(target_type) if target_type else "",
            model_tier=strategy_info.get("model_tier", recon_result.model_tier),
            strategy_mode=strategy_info.get("strategy_mode", "academic"),
            converter_chains=_adapt_chains,
            attack_techniques=strategy_selection.attack_techniques,
        )
    except Exception:
        pass  # 非关键路径

    from src.scenarios.adaptive_runner import run_adaptive_scenario_async

    adaptive_result = await run_adaptive_scenario_async(
        objective_target=objective_target,
        judge_target=judge_target,
        attack_plans=attack_plans,
        owasp_id=",".join(config_owasp_ids) if config_owasp_ids else "",
        exam_id=exam_id,
        max_attempts_per_objective=3,
        per_attack_timeout=per_attack_timeout,
        max_retries=scenario_max_retries,
        verbose=verbose,
        converter_target=converter_target,
        target_type=target_type,
        max_concurrency=adaptive_max_concurrency,
        strategy_mode=strategy_info.get("strategy_mode", "academic"),
        model_name=strategy_info.get("model_name", target_model),
        model_tier=strategy_info.get("model_tier", recon_result.model_tier),
    )
    batch_result = adaptive_result.batch_result
    print(f"  [OK] Converter 变体使用: {adaptive_result.converter_variants_used} 次")
    print(f"  [OK] 原生执行时间: {adaptive_result.execution_time:.1f}s")
    # v3.0 P0-A: 失败类型分布诊断
    if adaptive_result.failure_type_distribution:
        print(f"  [OK] 失败类型分布: {adaptive_result.failure_type_distribution}")
        if adaptive_result.most_common_failure_type:
            print(f"  [OK] 最常见失败类型: {adaptive_result.most_common_failure_type}")

    # ASR引导策略: ASR 实测 vs 学术先验对比
    from src.scenarios.asr_strategy_display import display_post_execution
    display_post_execution(
        adaptive_result=adaptive_result,
        model_name=strategy_info.get("model_name", target_model),
    )

    # 原生 output_scenario_async — 展示 Per-Group Breakdown + 场景摘要
    if adaptive_result.native_result is not None:
        try:
            from src.scenarios.scenario_output import display_enhanced_group_breakdown
            display_enhanced_group_breakdown(
                adaptive_result.native_result,
                owasp_id=",".join(config_owasp_ids) if config_owasp_ids else "",
            )
        except Exception as e:
            print(f"  [!] Per-Group Breakdown 输出失败: {e}")
    # L5: 执行后清理 NativeAttackExecutor 单例（避免跨事件循环/多次运行的残留）
    try:
        reset_executor()
    except Exception:
        pass  # 非关键路径

    print("\n  [OK] 批量攻击完成")
    print(f"  [OK] 总计划: {batch_result.total_plans}")
    print(f"  [OK] 已执行: {batch_result.executed}")
    print(f"  [OK] 成功: {batch_result.succeeded}")
    print(f"  [OK] 失败: {batch_result.failed}")
    print(f"  [OK] 错误: {batch_result.errored}")
    print(f"  [OK] 成功率: {batch_result.success_rate * 100:.1f}%")
    if batch_result.upgrade_attempts > 0:
        print(f"  [OK] 升级重试: {batch_result.upgrade_attempts} 次, 成功 {batch_result.upgrade_success} 次")

    # v3.0: ASR 先验实测写回（适配链断裂 7 修复）
    # 从执行结果中收集各技术实测 ASR，写回 asr_prior_registry 供后续 run 使用
    try:
        from src.payloads.asr_prior_registry import batch_update_empirical_asr
        _empirical_map: dict[str, dict[str, float]] = {}
        _tech_stats: dict[str, dict[str, int]] = {}
        for _r in batch_result.results:
            if _r is None:
                continue
            _tech = ""
            _identifier = getattr(_r, "identifier", None)
            if _identifier is None and hasattr(_r, "get_attack_strategy_identifier"):
                try:
                    _identifier = _r.get_attack_strategy_identifier()
                except Exception:
                    pass
            if _identifier:
                _tech = getattr(_identifier, "attack_technique", "")
                if not _tech:
                    _children = getattr(_identifier, "children", {}) or {}
                    _tech = _children.get("attack_technique", "")
            if not _tech:
                continue
            if _tech not in _tech_stats:
                _tech_stats[_tech] = {"success": 0, "total": 0}
            _tech_stats[_tech]["total"] += 1
            _outcome = getattr(_r, "outcome", None)
            if _outcome is not None:
                _outcome_str = str(_outcome.value).upper() if hasattr(_outcome, "value") else str(_outcome).upper()
                if _outcome_str == "SUCCESS":
                    _tech_stats[_tech]["success"] += 1

        for _tech, _stats in _tech_stats.items():
            if _stats["total"] > 0:
                _empirical_map[_tech] = {
                    "success": float(_stats["success"]),
                    "total": float(_stats["total"]),
                    "asr": _stats["success"] / _stats["total"],
                }

        if _empirical_map:
            _asr_model = strategy_info.get("model_name", target_model)
            batch_update_empirical_asr(_empirical_map, _asr_model)
            print(f"  [OK] ASR 先验写回: {len(_empirical_map)} 个技术实测数据 → asr_prior_registry")
    except Exception:
        pass  # 非关键路径

    if batch_result.errors:
        print(f"\n  [!] 错误详情 ({len(batch_result.errors)} 个):")
        for err in batch_result.errors[:5]:
            print(f"    - {err.get('plan_id', 'N/A')}: {err.get('error', 'N/A')}")
        if len(batch_result.errors) > 5:
            print(f"    ... 还有 {len(batch_result.errors) - 5} 个错误")

    # ---------------------------------------------------------
    # 7. 输出执行结果
    # ---------------------------------------------------------
    print("\n[7/9] 输出执行结果...")

    # 原生 AdaptiveScenario 路径：原生 ScenarioResult 已在执行过程中通过 tqdm 实时输出
    if adaptive_result.native_result is not None:
        print("  [OK] 原生 AdaptiveScenario 执行结果:")
        print(f"  [OK] 场景结果 ID: {adaptive_result.scenario_result_id}")
        print(f"  [OK] 总技术尝试: {adaptive_result.total_techniques_tried}")
        print(f"  [OK] Converter 变体使用: {adaptive_result.converter_variants_used} 次")
        print("  [OK] Per-Group Breakdown 已在执行后展示")
    else:
        print("  [!] 原生 AdaptiveScenario 执行失败 — 无可用结果")
        print("  [!] 可能原因: API 超时 / 网络错误 / max_retries 不足")
        print(f"  [!] 建议: 检查网络连接，增大 SCENARIO_MAX_RETRIES (当前={scenario_max_retries})")

    # 非 verbose 模式下补充展示前 5 个成功结果
    # verbose=True 时已在执行过程中实时输出成功结果，无需重复
    if not verbose:
        from pyrit.output import output_attack_async, StdoutSink
        success_results = [
            r for r in batch_result.results
            if r is not None and hasattr(r, "outcome") and
            str(getattr(r.outcome, "value", r.outcome)).upper() == "SUCCESS"
        ]
        shown = 0
        for result in success_results:
            if shown >= 5:
                break
            shown += 1
            print(f"\n  --- 结果 {shown}/{min(5, len(success_results))} ---")
            try:
                await output_attack_async(
                    result,
                    format="pretty",
                    sink=StdoutSink(),
                    include_auxiliary_scores=True,
                    include_adversarial_conversation=True,
                )
            except Exception as e:
                print(f"  [!] 输出结果 {shown} 时出错: {e}")

        if len(success_results) > 5:
            print(f"\n  ... 还有 {len(success_results) - 5} 个结果未显示（完整内容见 Markdown 日志文件）")

    print("\n  [OK] 执行结果输出完成")

    # ---------------------------------------------------------
    # 8. 报告生成（OWASP 映射 + 证据导出）
    # ---------------------------------------------------------
    print("\n[8/9] 生成报告...")
    end_time = datetime.now()

    # 生成报告（exam_id 已在 [6] 阶段预先生成）
    report_result = await generate_report(
        scenario_result=batch_result.results,
        exam_id=exam_id,
        start_time=start_time,
        end_time=end_time,
    )

    print(f"  [OK] 报告路径: {report_result.report_path}")
    print(f"  [OK] 证据包: {report_result.evidence_archive}")
    print(f"  [OK] 发现漏洞: {len(report_result.owasp_findings)} 个")
    print(f"  [OK] 攻击总数: {report_result.summary.total_attacks}")
    print(f"  [OK] 成功攻击: {report_result.summary.successful_attacks}")
    print(f"  [OK] 成功率: {report_result.summary.success_rate * 100:.1f}%")
    # v3.0: 多格式报告输出
    if getattr(report_result, "report_html_path", None):
        print(f"  [OK] HTML 报告: {report_result.report_html_path}")
    if getattr(report_result, "report_pdf_path", None):
        print(f"  [OK] PDF 报告: {report_result.report_pdf_path}")

    # ---------------------------------------------------------
    # 9. 总结
    # ---------------------------------------------------------
    print("\n[9/9] Pipeline 总结")
    print("\n" + "=" * 60)
    print("  Pipeline 完成")
    print("=" * 60)
    print(f"总用时: {end_time - start_time}")
    print(f"数据源: {len(prompt_batches)} 批次, {total_prompts} 提示词")
    print(f"攻击计划: {batch_result.total_plans} 个")
    print(f"执行结果: {batch_result.succeeded}/{batch_result.executed} 成功")
    print(f"报告: {report_result.report_path}")
    print(f"证据: {report_result.evidence_archive}")
    print(f"日志: {log_path}")

    # v3.0: 卸载噪音过滤器
    try:
        reset_display()
    except Exception:
        pass

    return report_result


# ============================================================
# 主入口
# ============================================================


def main():
    """
    主入口

    Usage:
      python pipeline.py                              # 使用 .env 中的目标
      python pipeline.py http://192.168.0.22:11434    # 指定目标 URL
      python pipeline.py http://192.168.0.22:11434 LLM01,LLM06  # 指定 OWASP IDs
    """
    # 加载环境变量 (从项目根目录的 .env 文件)
    project_root = Path(__file__).parent
    env_path = project_root / ".env"
    load_dotenv(env_path)

    print(f"加载环境变量: {env_path}")

    # 获取目标 URL (从环境变量或命令行参数)
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        # 从环境变量读取目标端点，提取基础 URL
        target_endpoint = os.getenv("TARGET_ENDPOINT", "http://localhost:11434/v1")
        # 去掉 /v1 后缀得到基础 URL
        if target_endpoint.endswith("/v1"):
            target_url = target_endpoint[:-3]
        else:
            target_url = target_endpoint

    # 解析 OWASP IDs（可选第二参数，逗号分隔）
    owasp_ids = None
    if len(sys.argv) > 2:
        owasp_ids = [x.strip().upper() for x in sys.argv[2].split(",") if x.strip()]
        print(f"CLI 指定 OWASP IDs: {owasp_ids}")

    # 运行管道
    asyncio.run(run_attack_pipeline(target_url, owasp_ids=owasp_ids))


if __name__ == "__main__":
    main()
