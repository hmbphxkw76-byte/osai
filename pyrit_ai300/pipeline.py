#!/usr/bin/env python3
"""
PyRIT 端到端全自动 AI 红队框架 - 主入口
============================================

本框架基于 PyRIT 1.0.0 构建，为 OffSec AI-300 考试和实际 AI 红队评估提供
数据驱动的端到端全自动提示词层面攻击流程。

对齐 PyRIT 1.0.0 五层架构（含 ②.5 交互选择层）：
  ① 数据准备层 → DatasetManager.load_datasets() (OWASP / 自定义 / PyRIT 远程)
  ② 数据管理层 → CentralMemory (add_seed_datasets_to_memory / get_seed_groups)
  ②.5 交互选择层 → SeedGroupSelector (build_catalog / filter / prompt_user)
  ③ 攻击准备层 → AttackPreparator.prepare() (SeedGroup → AttackSeedGroup)
  ④ 攻击执行层 → ScenarioOrchestrator (原生 AttackExecutor + AttackSeedGroup)
  ⑤ 评估与追踪层 → Scorer + PyRIT Memory 审计链

④ 层架构（PyRIT 原生优先 + 自建 Scenario 扩展）：
  NativeAttackExecutor → 使用原生 AttackExecutor.execute_attack_from_seed_groups_async()
  ScenarioOrchestrator → 批量调度 + 升级重试 + 进度仪表盘 + AttackResultAttribution

流程:
  [1/9] 初始化 PyRIT (CentralMemory + SQLite)
  [2/9] 侦察阶段 (端点发现 + AI 类型识别)
  [3/9] 分析阶段 (策略选择 + 优先级评估)
  [4/9] ①→② 数据准备 + 管理 (DatasetManager → CentralMemory)
  [5/9] ②→②.5→③ 查询 + 交互选择 + 攻击准备 (SeedGroupSelector → AttackPreparator → AttackPlan)
  [6/9] ④ 批量执行攻击 (单轮/多轮/编码增强/顺序组合)
  [7/9] 输出执行结果
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
from src.recon import recon_target
from src.analysis import select_strategy, evaluate_priority
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
    GroupFallbackExecutor,
)
from src.executor import execute_batch_attacks
from src.reporting import generate_report
from src.targets import create_prompt_target, create_judge_target, TargetParams
from src.targets.rate_limited_target import (
    RateLimitConfig,
    wrap_target_with_rate_limiting,
    create_rate_limit_config_from_env,
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

    # 读取 verbose 配置（.env > config/defaults/pipeline.yaml）
    verbose = config_loader.get_verbose()
    verbose_success = config_loader.get_verbose_success()

    # 从环境变量读取目标/评分器配置（.env 必填）
    target_endpoint = os.getenv("TARGET_ENDPOINT", f"{target_url.rstrip('/')}/v1")
    target_model = os.getenv("TARGET_MODEL", "qwen3:0.6b")
    target_api_key = os.getenv("TARGET_API_KEY", "ollama")

    judge_endpoint = os.getenv("JUDGE_ENDPOINT", target_endpoint)
    judge_model = os.getenv("JUDGE_MODEL", "qwen3:1.7b")
    judge_api_key = os.getenv("JUDGE_API_KEY", "ollama")

    print("\n" + "=" * 60)
    print("  PyRIT 端到端全自动 AI 红队框架 (批量多源攻击)")
    print("=" * 60)
    print(f"\n目标 URL: {target_url}")
    print(f"目标端点: {target_endpoint}")
    print(f"目标模型: {target_model}")
    print(f"评分器端点: {judge_endpoint}")
    print(f"评分器模型: {judge_model}")
    print(f"开始时间: {start_time.isoformat()}")
    print(f"日志文件: {log_path}")
    print(f"Verbose 模式: {'开启' if verbose else '关闭'}")
    print(f"Verbose Success: {'开启' if verbose_success else '关闭'}  (成功攻击详情输出)")

    # ---------------------------------------------------------
    # 1. 初始化 PyRIT (对齐 PyRIT 1.0.0 Setup 三步流程)
    # ---------------------------------------------------------
    print("\n[1/9] 初始化 PyRIT...")
    # 使用每次运行独立的数据库路径，彻底避免旧数据残留和文件锁定问题
    db_base_path = Path(config_loader.get_memory_db_path())
    db_path = db_base_path.parent / f"{exam_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # 对齐 PyRIT 1.0.0 Setup 文档：
    #   Step 1: 自动发现并加载 .env / .env_local
    #   Step 2: 数据库配置 (SQLite + 每次独立路径)
    #   Step 3: 重试配置传播 (RETRY_MAX_NUM_ATTEMPTS 等环境变量)
    from src.setup.retry_config import configure_retry_env_vars
    retry_config = configure_retry_env_vars()
    print(f"  [OK] 重试配置: {retry_config}")

    # Scenario 级别重试 (对齐 PyRIT max_retries)
    scenario_max_retries = config_loader.get_scenario_max_retries()
    print(f"  [OK] Scenario 重试: max_retries={scenario_max_retries} (total={1 + scenario_max_retries})")

    # 停止策略 (三层最优策略)
    owasp_success_threshold = config_loader.get_owasp_success_threshold()
    stop_on_first_success = config_loader.get_stop_on_first_success()
    print(f"  [OK] 停止策略: L2 OWASP阈值={owasp_success_threshold:.0%}, L3 全局首停={stop_on_first_success}")

    from pyrit.setup import initialize_pyrit_async
    await initialize_pyrit_async(
        memory_db_type=config_loader.get_memory_db_type(),
        db_path=str(db_path),
        silent=False,
    )
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

    # 优先级评估
    priority_score = evaluate_priority(recon_result)
    print(f"  [OK] 目标优先级: {priority_score}/100")

    # ---------------------------------------------------------
    # 4. ①→② 数据准备 + 管理（DatasetManager → CentralMemory）
    # ---------------------------------------------------------
    print("\n[4/9] ①→② 数据准备 + 管理 (DatasetManager → CentralMemory)...")

    # CLI 参数优先于配置文件（统一从 dataset_manager 配置段读取）
    dm_owasp_cfg = config_loader.get_dataset_manager_owasp_config()
    dm_custom_cfg = config_loader.get_dataset_manager_custom_config()
    dm_remote_cfg = config_loader.get_dataset_manager_remote_config()

    config_owasp_ids = owasp_ids if owasp_ids else dm_owasp_cfg.get("owasp_ids", [])
    exclude_ids = dm_owasp_cfg.get("exclude_ids", [])
    include_custom = dm_custom_cfg.get("enabled", True)

    # 远程数据集配置
    include_remote = dm_remote_cfg.get("enabled", False)
    remote_dataset_names = dm_remote_cfg.get("datasets", [])

    if config_owasp_ids:
        print(f"  [OK] OWASP 筛选: {', '.join(config_owasp_ids)}")
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
        remote=include_remote,
        remote_dataset_names=remote_dataset_names if include_remote else None,
    )

    total_seeds = len(manager.get_seeds())
    total_groups = len(manager.get_seed_groups())
    print(f"  [OK] CentralMemory: {total_seeds} seeds, {total_groups} seed groups")

    # 数据源多样性报告
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
        if _asr and max(_asr.values()) >= 0.65:
            _asr_high += 1
    print(f"  [OK] OWASP 覆盖: {len(_owasp_counts)} 分类")
    for _oid in sorted(_owasp_counts):
        print(f"    {_oid}: {_owasp_counts[_oid]} seeds")
    print(f"  [OK] 技术覆盖: {len(_technique_counts)} 种技术组")
    print(f"  [OK] 高 ASR 载荷 (>=65%): {_asr_high} seeds")

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
            wizard = TieredSelectionWizard(enabled=False, preset=wizard_preset)
        else:
            # 交互模式
            wizard = TieredSelectionWizard(enabled=interactive_enabled)

        selection_result = await wizard.select(all_seed_groups)
        selected_groups = selection_result.selected_groups
        fallback_strategy = selection_result.fallback_strategy
        fallback_chain = selection_result.fallback_chain

        print(f"  [OK] 目标类型: {selection_result.target_profile.target_type.display_name}")
        print(f"  [OK] 选中: {len(selected_groups)}/{len(all_seed_groups)} 个种子组 (top-{tiered_cfg.get('top_n', 3)})")
        print(f"  [OK] 降级策略: {fallback_strategy.display_name}")
        print(f"  [OK] ASR 分层: {len(fallback_chain)} 个 Tier")
        if fallback_strategy != FallbackStrategy.PARALLEL:
            planning_groups = selection_result.planning_groups
            print(f"  [OK] 全链计划组: {len(planning_groups)} 个 (含降级后备组)")
        else:
            planning_groups = selected_groups

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
    has_objective = sum(1 for ag in attack_groups if ag.objective is not None)
    synthetic = sum(1 for ag in attack_groups
                    if any(getattr(s, 'metadata', {}).get("synthetic_objective", False)
                           for s in ag.seeds))
    multi_turn = sum(1 for ag in attack_groups if AttackPreparator.is_multi_turn(ag))
    print(f"  [OK] AttackSeedGroup 转换: {len(attack_groups)} 个")
    print(f"    - 有原生 objective: {has_objective} 个")
    print(f"    - 合成 objective: {synthetic} 个")
    print(f"    - 多轮攻击: {multi_turn} 个")
    print(f"    - 单轮攻击: {len(attack_groups) - multi_turn} 个")

    # 桥接 ③→④: SeedGroup → PromptBatch → AttackPlan（使用 planning_groups 生成全链计划）
    prompt_batches = SeedPromptAdapter.seed_groups_to_batches(planning_groups)
    total_prompts = sum(len(batch.prompts) for batch in prompt_batches)
    print(f"  [OK] 桥接 PromptBatch: {len(prompt_batches)} 批次, {total_prompts} 提示词")

    # 统计各攻击模式
    mode_counts = {}
    for batch in prompt_batches:
        for item in batch.prompts:
            mode_counts[item.attack_mode.value] = mode_counts.get(item.attack_mode.value, 0) + 1
    for mode, count in sorted(mode_counts.items()):
        print(f"    - {mode}: {count} 个")

    # 载荷规划（PromptBatch → AttackPlan）
    attack_plans = plan_attacks(prompt_batches, strategy_selection)
    print(f"  [OK] 生成攻击计划: {len(attack_plans)} 个")

    # 按攻击模式统计计划数
    plan_mode_counts = {}
    for plan in attack_plans:
        mode = plan.prompt_item.attack_mode.value
        plan_mode_counts[mode] = plan_mode_counts.get(mode, 0) + 1
    for mode, count in sorted(plan_mode_counts.items()):
        print(f"    - {mode}: {count} 个计划")

    # 统计攻击技术分布（回归 PyRIT 原生 Attack 类）
    technique_counts = {}
    scorer_counts = {}
    for plan in attack_plans:
        technique_counts[plan.attack_technique] = technique_counts.get(plan.attack_technique, 0) + 1
        scorer_counts[plan.scorer_type] = scorer_counts.get(plan.scorer_type, 0) + 1
    print("  [OK] 攻击技术分布:")
    for tech, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
        print(f"    - {tech}: {count} 个")
    print("  [OK] 评分器类型分布:")
    for s_type, count in sorted(scorer_counts.items(), key=lambda x: -x[1]):
        print(f"    - {s_type}: {count} 个")

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

    # 创建目标 Target（L5: 使用 TargetParams 完整参数 + 环境变量自动加载）
    # max_requests_per_minute → 激活 PyRIT 原生 @limit_requests_per_minute 装饰器
    target_params = TargetParams(
        discover_capabilities=False,
        max_requests_per_minute=target_rpm,
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
    print("  [OK] 评分器同时用作 adversarial chat (多轮攻击)")

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
    fail_fast = config_loader.get_pipeline_fail_fast()
    per_attack_timeout = config_loader.get_pipeline_per_attack_timeout()
    timeout_overrides = config_loader.get_pipeline_timeout_overrides()

    print(f"  [OK] 最大并发: {max_concurrency}")
    if timeout_overrides:
        override_str = ", ".join(f"{k}={v}s" for k, v in timeout_overrides.items())
        print(f"  [OK] 差异化超时: {override_str}  (默认: {per_attack_timeout}s)")
    else:
        print(f"  [OK] 单次超时: {per_attack_timeout}s")
    print(f"  [OK] Verbose: {'开启' if verbose else '关闭'}")
    print(f"  [OK] Verbose Success: {'开启' if verbose_success else '关闭'}  (成功时输出完整详情)")
    print(f"  [OK] 开始执行 {len(attack_plans)} 个攻击计划...")
    if fallback_strategy != FallbackStrategy.PARALLEL and fallback_chain:
        print(f"  [OK] 组级降级链: {fallback_strategy.display_name}")
    print()

    # exam_id 已在函数开头预先生成

    # ──────────────────────────────────────────────────────
    # P3: 原生优先执行路径 — AI300AdaptiveScenario + Converter 变体
    # ──────────────────────────────────────────────────────
    # 原生 AdaptiveScenario + SequentialAttack(FIRST_SUCCESS) 替代自建升级重试
    # Converter 变体预注册 → 原生 FIRST_SUCCESS 自动在首个成功变体处停止
    # 保留自建：per_attack_timeout 包裹 + OWASP 映射 + L2/L3 停止策略
    # ──────────────────────────────────────────────────────
    use_adaptive_path = os.getenv("USE_ADAPTIVE_SCENARIO", "true").lower() in ("1", "true", "yes")

    if use_adaptive_path:
        print("  [OK] 执行模式: 原生 AdaptiveScenario (P3 原生优先, Converter 变体)")
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
            converter_target=judge_target,
            target_type=target_type,
        )
        batch_result = adaptive_result.batch_result
        print(f"  [OK] Converter 变体使用: {adaptive_result.converter_variants_used} 次")
        print(f"  [OK] 原生执行时间: {adaptive_result.execution_time:.1f}s")
    elif fallback_strategy != FallbackStrategy.PARALLEL and fallback_chain:
        # 降级链执行路径（三层选择启用时，向后兼容）
        fallback_executor = GroupFallbackExecutor()
        fb_result = await fallback_executor.execute_with_fallback(
            attack_plans=attack_plans,
            fallback_chain=fallback_chain,
            strategy=fallback_strategy,
            objective_target=objective_target,
            judge_target=judge_target,
            max_concurrency=max_concurrency,
            fail_fast=fail_fast,
            per_attack_timeout=per_attack_timeout,
            verbose=verbose,
            exam_id=exam_id,
            timeout_overrides=timeout_overrides if timeout_overrides else None,
            max_retries=scenario_max_retries,
            owasp_success_threshold=owasp_success_threshold,
            stop_on_first_success=stop_on_first_success,
        )
        batch_result = fb_result.batch_result
        if fb_result.stopped_at_tier:
            print(f"  [OK] 降级链停在 Tier {fb_result.stopped_at_tier}")
        print(f"  [OK] 执行 Tier: {', '.join(fb_result.tiers_executed)}")
        if batch_result.skipped_by_stop > 0:
            print(f"  [OK] 停止策略跳过: {batch_result.skipped_by_stop} 个计划")
    else:
        # 直接批量执行（旧版兼容 或 Parallel 策略）
        batch_result = await execute_batch_attacks(
            attack_plans=attack_plans,
            objective_target=objective_target,
            judge_target=judge_target,
            max_concurrency=max_concurrency,
            fail_fast=fail_fast,
            per_attack_timeout=per_attack_timeout,
            verbose=verbose,
            exam_id=exam_id,
            timeout_overrides=timeout_overrides if timeout_overrides else None,
            max_retries=scenario_max_retries,
            owasp_success_threshold=owasp_success_threshold,
            stop_on_first_success=stop_on_first_success,
        )

    print("\n  [OK] 批量攻击完成")
    print(f"  [OK] 总计划: {batch_result.total_plans}")
    print(f"  [OK] 已执行: {batch_result.executed}")
    print(f"  [OK] 成功: {batch_result.succeeded}")
    print(f"  [OK] 失败: {batch_result.failed}")
    print(f"  [OK] 错误: {batch_result.errored}")
    print(f"  [OK] 成功率: {batch_result.success_rate * 100:.1f}%")
    if batch_result.upgrade_attempts > 0:
        print(f"  [OK] 升级重试: {batch_result.upgrade_attempts} 次, 成功 {batch_result.upgrade_success} 次")

    if batch_result.errors:
        print(f"\n  [!] 错误详情 ({len(batch_result.errors)} 个):")
        for err in batch_result.errors[:5]:
            print(f"    - {err.get('plan_id', 'N/A')}: {err.get('error', 'N/A')}")
        if len(batch_result.errors) > 5:
            print(f"    ... 还有 {len(batch_result.errors) - 5} 个错误")

    # ---------------------------------------------------------
    # 7. 输出执行结果（双通道输出已在批量执行中完成）
    # ---------------------------------------------------------
    print("\n[7/9] 输出执行结果...")
    print("  [OK] 双通道输出已在批量执行过程中完成:")
    print("  [OK] 终端通道: pretty 格式实时输出")
    print(f"  [OK] 文件通道: Markdown 全量日志 (output/logs/{exam_id}_attacks.md)")

    # 非 verbose 模式下补充展示前 5 个成功结果
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
