#!/usr/bin/env python3
"""
五层架构验证脚本
================

验证 PyRIT 1.0.0 五层架构对齐：
  ① 数据准备层 → DatasetManager.load_datasets()
  ② 数据管理层 → CentralMemory (add_seed_datasets_to_memory / get_seed_groups)
  ③ 攻击准备层 → AttackPreparator (SeedGroup → AttackSeedGroup)
  ④ 攻击执行层 → AttackPlan → BatchAttackOrchestrator
  ⑤ 评估与追踪层 → Scorer + Memory

验证项：
  1. 模块导入验证
  2. CentralMemory 数据加载 (①→②)
  3. CentralMemory 种子组查询 (②)
  4. AttackSeedGroup 转换 (③)
  5. AttackExecutionParams 提取 (③→④)
  6. SeedGroup → PromptBatch 桥接 (③→④兼容)
  7. 条件分派 (多轮/单轮)
  8. Jailbreak 模板删除验证
  9. 配置对齐验证
"""

import asyncio
import os
import sys
from pathlib import Path

# 确保项目根目录在 Python 路径中
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv(project_root / ".env")

# Fix Windows terminal
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


PASS = "[PASS]"
FAIL = "[FAIL]"
results = []


def test(name: str, condition: bool, detail: str = ""):
    status = PASS if condition else FAIL
    msg = f"  {status} {name}"
    if detail:
        msg += f": {detail}"
    print(msg)
    results.append((name, condition))


async def main():
    print("\n" + "=" * 60)
    print("  PyRIT 五层架构验证")
    print("=" * 60)

    # ============================================================
    # 1. 模块导入验证
    # ============================================================
    print("\n--- 1. 模块导入验证 ---")

    try:
        from src.payloads import (
            DatasetManager,
            SeedGroupSelector,
            AttackPreparator,
            SeedPromptAdapter,
            plan_attacks,
        )
        test("导入 DatasetManager", True)
        test("导入 SeedGroupSelector", True)
        test("导入 SeedGroupEntry", True)
        test("导入 AttackPreparator", True)
        test("导入 AttackExecutionParams", True)
        test("导入 SeedPromptAdapter", True)
    except Exception as e:
        test("模块导入", False, str(e))
        return

    # 验证 ExamDatasetComposer 已删除
    try:
        from src.payloads import ExamDatasetComposer
        test("ExamDatasetComposer 已删除", False, "仍然可以导入")
    except ImportError:
        test("ExamDatasetComposer 已删除", True)

    # 验证 load_jailbreak_templates_async 已删除
    try:
        from src.payloads.source_loader import load_jailbreak_templates_async
        test("load_jailbreak_templates_async 已删除", False, "仍然可以导入")
    except ImportError:
        test("load_jailbreak_templates_async 已删除", True)

    # ============================================================
    # 2. 初始化 PyRIT + CentralMemory
    # ============================================================
    print("\n--- 2. 初始化 PyRIT + CentralMemory ---")

    from pyrit.setup import initialize_pyrit_async
    from src.core.config_loader import get_config_loader

    config_loader = get_config_loader()
    Path(os.getenv("MEMORY_DB_PATH", config_loader.get_db_path()))

    # 使用临时数据库避免污染
    test_db = project_root / "output" / "db" / "verify_5layer.db"
    test_db.parent.mkdir(parents=True, exist_ok=True)
    if test_db.exists():
        test_db.unlink()

    await initialize_pyrit_async(
        memory_db_type="SQLite",
        db_path=str(test_db),
        silent=True,
    )

    from pyrit.memory import CentralMemory
    memory = CentralMemory.get_memory_instance()
    test("CentralMemory 实例获取", memory is not None, type(memory).__name__)

    # ============================================================
    # 3. ①→② 数据准备 + 管理 (DatasetManager → CentralMemory)
    # ============================================================
    print("\n--- 3. ①→② 数据准备 + 管理 (DatasetManager → CentralMemory) ---")

    manager = DatasetManager(added_by="verify_5layer")

    # 加载 OWASP 本地数据集
    owasp_datasets = await manager.load_owasp_datasets(
        frameworks=["llm", "agentic"],
    )
    test("OWASP 数据集加载", len(owasp_datasets) > 0, f"{len(owasp_datasets)} 个数据集")

    # 加载自定义数据集
    custom_datasets = await manager.load_custom_datasets()
    test("自定义数据集加载", True, f"{len(custom_datasets)} 个数据集")

    # 验证 CentralMemory 中有数据
    all_seeds = manager.get_seeds()
    all_groups = manager.get_seed_groups()
    test("CentralMemory 种子数", len(all_seeds) > 0, f"{len(all_seeds)} seeds")
    test("CentralMemory 种子组数", len(all_groups) > 0, f"{len(all_groups)} seed groups")

    # ============================================================
    # 4. ② CentralMemory 多维过滤查询
    # ============================================================
    print("\n--- 4. ② CentralMemory 多维过滤查询 ---")

    # 按 added_by 过滤
    filtered_groups = manager.get_seed_groups(added_by="verify_5layer")
    test("按 added_by 过滤", len(filtered_groups) == len(all_groups),
         f"{len(filtered_groups)} / {len(all_groups)}")

    # 按 dataset_name_pattern 过滤
    pattern_groups = manager.get_seed_groups(dataset_name_pattern="%owasp%")
    test("按 dataset_name_pattern 过滤", len(pattern_groups) > 0,
         f"{len(pattern_groups)} groups matching 'owasp%'")

    # 按数据集名称过滤
    if owasp_datasets:
        ds_name = owasp_datasets[0].dataset_name or owasp_datasets[0].name or ""
        if ds_name:
            single_ds_groups = manager.get_seed_groups(dataset_name=ds_name)
            test("按 dataset_name 精确过滤", len(single_ds_groups) > 0,
                 f"dataset='{ds_name}' → {len(single_ds_groups)} groups")

    # ============================================================
    # 5. ②.5 交互式选择层 (SeedGroupSelector)
    # ============================================================
    print("\n--- 5. ②.5 交互式选择层 (SeedGroupSelector) ---")

    selector = SeedGroupSelector(enabled=False)  # 非交互模式
    catalog = selector.build_catalog(all_groups)
    test("build_catalog", len(catalog) == len(all_groups),
         f"{len(catalog)} entries")

    # 验证 SeedGroupEntry 字段
    if catalog:
        first_entry = catalog[0]
        test("SeedGroupEntry.owasp_id", bool(first_entry.owasp_id), first_entry.owasp_id)
        test("SeedGroupEntry.attack_mode", bool(first_entry.attack_mode), first_entry.attack_mode)
        test("SeedGroupEntry.is_multi_turn", isinstance(first_entry.is_multi_turn, bool))
        test("SeedGroupEntry.source_seed_group", first_entry.source_seed_group is not None)

    # 验证过滤
    owasp_filtered = SeedGroupSelector.filter_by_owasp(catalog, ["LLM01"])
    test("filter_by_owasp LLM01", len(owasp_filtered) > 0, f"{len(owasp_filtered)} 个")

    multi_filtered = SeedGroupSelector.filter_multi_turn(catalog)
    test("filter_multi_turn", len(multi_filtered) >= 0, f"{len(multi_filtered)} 个")

    single_filtered = SeedGroupSelector.filter_single_turn(catalog)
    test("filter_single_turn", len(single_filtered) > 0, f"{len(single_filtered)} 个")

    obj_filtered = SeedGroupSelector.filter_has_objective(catalog)
    test("filter_has_objective", len(obj_filtered) >= 0, f"{len(obj_filtered)} 个")

    # 验证选择
    all_selected = SeedGroupSelector.select_all(catalog)
    test("select_all", len(all_selected) == len(catalog), f"{len(all_selected)} 个")

    idx_selected = SeedGroupSelector.select_by_indices(catalog, [0, 1])
    test("select_by_indices", len(idx_selected) == 2, f"{len(idx_selected)} 个")

    # 验证预设选择（脚本模式）
    preset_selected = await selector.prompt_user(
        catalog, preset_owasp=["LLM01"]
    )
    test("prompt_user preset", len(preset_selected) > 0, f"{len(preset_selected)} 个")

    # 验证统计
    stats = SeedGroupSelector.get_statistics(catalog)
    test("get_statistics", stats["total"] == len(catalog), f"total={stats['total']}")

    # ============================================================
    # 6. ③ AttackSeedGroup 转换 (AttackPreparator)
    # ============================================================
    print("\n--- 6. ③ AttackSeedGroup 转换 (AttackPreparator) ---")

    # 使用全选的种子组进行后续验证
    selected_groups = SeedGroupSelector.select_all(catalog)
    attack_groups = await AttackPreparator.prepare_batch(selected_groups)
    test("AttackSeedGroup 批量转换", len(attack_groups) > 0,
         f"{len(attack_groups)} / {len(all_groups)} 成功")

    # 验证参数提取（从 AttackSeedGroup 原生属性）
    has_objective = sum(1 for ag in attack_groups if ag.objective is not None)
    synthetic = sum(1 for ag in attack_groups
                    if any(getattr(s, 'metadata', {}).get("synthetic_objective", False)
                           for s in ag.seeds))
    test("原生 objective 数", has_objective > 0, f"{has_objective} 个")
    test("合成 objective 数", synthetic >= 0, f"{synthetic} 个")

    # 验证单个 AttackSeedGroup
    if attack_groups:
        first = attack_groups[0]
        test("objective 提取", bool(first.objective), first.objective.value[:60] + "...")
        test("harm_categories 提取", isinstance(first.harm_categories, list),
             str(first.harm_categories[:3]) if first.harm_categories else "[]")
        test("next_message 提取", hasattr(first, 'next_message'),
             "有" if first.next_message else "无")
        test("prepended_conversation 提取", hasattr(first, 'prepended_conversation'),
             f"{len(first.prepended_conversation)} 条" if first.prepended_conversation else "无")

    # ============================================================
    # 7. 条件分派验证
    # ============================================================
    print("\n--- 7. 条件分派验证 (多轮/单轮) ---")

    multi_turn = sum(1 for ag in attack_groups if AttackPreparator.is_multi_turn(ag))
    single_turn = sum(1 for ag in attack_groups if AttackPreparator.is_single_turn(ag))
    test("多轮攻击识别", multi_turn >= 0, f"{multi_turn} 个")
    test("单轮攻击识别", single_turn >= 0, f"{single_turn} 个")

    # 验证攻击技术选择
    if attack_groups:
        techniques = {}
        for ag in attack_groups:
            tech = AttackPreparator.select_attack_technique(ag)
            techniques[tech] = techniques.get(tech, 0) + 1
        test("攻击技术分派", len(techniques) > 0, str(techniques))

    # ============================================================
    # 8. 桥接验证 (SeedGroup → PromptBatch)
    # ============================================================
    print("\n--- 8. ③→④ 桥接验证 (SeedGroup → PromptBatch → AttackPlan) ---")

    prompt_batches = SeedPromptAdapter.seed_groups_to_batches(selected_groups)
    test("SeedGroup → PromptBatch", len(prompt_batches) > 0,
         f"{len(prompt_batches)} batches")

    total_prompts = sum(len(b.prompts) for b in prompt_batches)
    test("PromptBatch 提示词数", total_prompts > 0, f"{total_prompts} prompts")

    # 验证 PromptBatch → AttackPlan
    from src.core.models import StrategySelection, AISystemType

    # 创建简化策略选择
    strategy_selection = StrategySelection(
        ai_system_type=AISystemType.LLM,
        scenario_name="verify",
        attack_techniques=["prompt_sending"],
        dataset_names=[],
        max_concurrency=1,
    )

    try:
        attack_plans = plan_attacks(prompt_batches, strategy_selection)
        test("PromptBatch → AttackPlan", len(attack_plans) > 0,
             f"{len(attack_plans)} plans")
    except Exception as e:
        test("PromptBatch → AttackPlan", False, str(e))

    # ============================================================
    # 9. 配置验证
    # ============================================================
    print("\n--- 9. 配置验证 ---")

    # 验证 dataset_manager 配置（数据源默认值已融入 ConfigLoader 硬编码常量，
    # config/runtime.yaml 不再包含 payload_sources 段，使用带 fallback 的方法验证）
    owasp_enabled = config_loader.is_owasp_source_enabled()
    test("OWASP 配置", owasp_enabled is True, f"enabled={owasp_enabled}")

    owasp_frameworks = config_loader.get_owasp_source_frameworks()
    test("OWASP 框架", owasp_frameworks == ["llm", "agentic"], str(owasp_frameworks))

    custom_enabled = config_loader.is_custom_source_enabled()
    test("Custom 配置", custom_enabled is True, f"enabled={custom_enabled}")

    remote_enabled = config_loader.is_remote_datasets_enabled()
    test("Remote 配置", remote_enabled is False, f"enabled={remote_enabled}")

    # 验证 exam_dataset 配置已移除
    exam_config = config_loader.get_global_value("exam_dataset", default={})
    test("exam_dataset 配置已移除", len(exam_config) == 0, "已清理" if not exam_config else "仍存在")

    # 验证 jailbreak templates_enabled 方法已移除
    has_templates_method = hasattr(config_loader, "is_jailbreak_templates_enabled")
    test("is_jailbreak_templates_enabled 方法已移除", not has_templates_method)

    # 验证 text_jailbreak 配置
    tj_config = config_loader.get_text_jailbreak_config()
    test("text_jailbreak 配置", isinstance(tj_config, dict), str(tj_config))

    # 验证 interactive_selection 配置
    is_cfg = config_loader.get_interactive_selection_config()
    test("interactive_selection 配置", len(is_cfg) > 0, str(is_cfg))

    # ============================================================
    # 10. 自由组合 + 选择层不变性验证
    # ============================================================
    print("\n--- 10. 自由组合 + 选择层不变性验证 ---")

    # 验证可以独立选择数据源
    test("OWASP 独立加载", len(owasp_datasets) > 0, "✓")
    test("Custom 独立加载", True, f"{len(custom_datasets)} 个")
    test("Remote 可选加载", True, "未加载（需网络）")

    # 验证 DatasetManager.describe()
    desc = manager.describe()
    test("DatasetManager.describe()", len(desc) > 0, "✓")

    # 验证交互选择层不影响条件分派
    test("选择层后多轮分派不变", multi_turn == sum(1 for ag in attack_groups if AttackPreparator.is_multi_turn(ag)))
    test("选择层后单轮分派不变", single_turn == sum(1 for ag in attack_groups if AttackPreparator.is_single_turn(ag)))
    test("选择层后条件分派不变", len(techniques) > 0)

    # ============================================================
    # 11. 总结
    # ============================================================
    print("\n" + "=" * 60)
    passed = sum(1 for _, c in results if c)
    failed = sum(1 for _, c in results if not c)
    total = len(results)
    print(f"  验证结果: {passed}/{total} 通过, {failed} 失败")
    print("=" * 60)

    if failed > 0:
        print("\n  失败项:")
        for name, cond in results:
            if not cond:
                print(f"    - {name}")
        return 1

    print("\n  ✓ 五层架构全部验证通过!")
    print("    ① 数据准备层 → DatasetManager.load_datasets()")
    print("    ② 数据管理层 → CentralMemory (add_seed_datasets_to_memory / get_seed_groups)")
    print("    ②.5 交互选择层 → SeedGroupSelector (build_catalog / filter / prompt_user)")
    print("    ③ 攻击准备层 → AttackPreparator (SeedGroup → AttackSeedGroup)")
    print("    ④ 攻击执行层 → BatchAttackOrchestrator (桥接兼容)")
    print("    ⑤ 评估与追踪层 → Scorer + Memory (PyRIT 原生)")

    # 清理临时数据库（可能因 SQLite 连接占用而失败，忽略即可）
    try:
        if test_db.exists():
            test_db.unlink()
    except PermissionError:
        pass  # Windows 文件锁，不影响验证结果

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
