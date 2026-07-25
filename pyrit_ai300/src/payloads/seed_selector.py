"""
Seed Group Selector
===================

②.5 交互式选择层 - 在数据管理层和攻击准备层之间

对齐 PyRIT 1.0.0 五层架构：
  ① 数据准备层 → DatasetManager.load_datasets()
  ② 数据管理层 → CentralMemory (dataset_manager.py)
  ②.5 交互式选择层 → SeedGroupSelector (本模块)
  ③ 攻击准备层 → AttackPreparator (attack_preparator.py)
  ④ 攻击执行层 → AttackStrategy.execute_async()
  ⑤ 评估与追踪层 → Scorer + Memory

核心功能：
1. 将 CentralMemory 中的 SeedGroup 列表构建为可读目录
2. 提供终端交互界面让用户选择攻击组合
3. 支持多维度过滤（OWASP ID / harm_categories / attack_mode / severity）
4. 支持非交互模式（CI/CD 兼容）和预设选择（脚本模式）

设计原则：
- 选择层是"过滤器"而非"转换器" - 不修改 SeedGroup 对象
- 选择后保持条件分派逻辑不变（多轮→crescendo, 单轮→prompt_sending）
- source_seed_group 字段保留原始引用，确保溯源链完整
"""

import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from pyrit.models import SeedGroup, SeedObjective, SeedPrompt

logger = logging.getLogger(__name__)

# OWASP ID 到名称的映射（从 registry 加载或硬编码回退）
_OWASP_NAMES: Dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Info Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data & Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector & Embedding Weakness",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    "ASI01": "Goal Hijacking",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity Abuse",
    "ASI04": "Supply Chain (Agentic)",
    "ASI05": "Code Execution",
    "ASI06": "Agentic Memory Attack",
    "ASI07": "Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Trust Exploitation",
    "ASI10": "Rogue AI Agent",
}


# ============================================================
# 种子组目录条目
# ============================================================


@dataclass
class SeedGroupEntry:
    """
    种子组目录条目 - 用于展示和选择

    从 SeedGroup 提取的结构化信息，不修改原始对象。
    source_seed_group 保留原始引用，确保溯源链完整。
    """

    index: int                        # 序号（用于用户选择）
    owasp_id: str                     # "LLM01" / "ASI02" / ""
    owasp_name: str                   # "Prompt Injection"
    framework: str                    # "llm" / "agentic" / "remote" / "custom"
    harm_categories: List[str]        # ["prompt_injection"]
    attack_mode: str                  # "single_turn" / "multi_turn" / "converter_enhanced" / "sequential"
    technique: str                    # "direct" / "role_play_escalation" / ...
    severity: str                     # "high" / "critical" / "low" / ""
    is_multi_turn: bool               # 是否多轮攻击
    has_objective: bool               # 是否有原生 objective
    seed_count: int                   # 组内种子数量
    objective_summary: str            # objective 前 60 字符
    prompt_summary: str               # 首条 prompt 前 60 字符
    dataset_name: str                 # "owasp_llm01_prompt_injection"
    source_seed_group: SeedGroup      # 原始 SeedGroup 引用（不修改）


# ============================================================
# 种子组选择器
# ============================================================


class SeedGroupSelector:
    """
    交互式种子组选择器

    在 CentralMemory 和 AttackPreparator 之间提供交互式选择界面，
    让用户根据攻击目标选择最合适的攻击组合。

    用法示例：
        selector = SeedGroupSelector()
        catalog = selector.build_catalog(seed_groups)
        selector.display(catalog)
        selected = await selector.prompt_user(catalog)

        # selected 是 List[SeedGroup]，直接传给 AttackPreparator
        attack_groups = await AttackPreparator.prepare_batch(selected)
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        auto_select_if_single: bool = True,
        page_size: int = 20,
    ):
        """
        初始化选择器

        Args:
            enabled: 是否启用交互式选择（False = 全选跳过）
            auto_select_if_single: 只有 1 个种子组时自动选择
            page_size: 每页显示条目数
        """
        self.enabled = enabled
        self.auto_select_if_single = auto_select_if_single
        self.page_size = page_size

    # ------------------------------------------------------------------
    # 目录构建
    # ------------------------------------------------------------------

    @staticmethod
    def build_catalog(seed_groups: Sequence[SeedGroup]) -> List[SeedGroupEntry]:
        """
        将 SeedGroup 列表构建为可读目录

        从每个 SeedGroup 提取元数据构建 SeedGroupEntry，
        不修改原始 SeedGroup 对象。

        Args:
            seed_groups: CentralMemory get_seed_groups() 返回的列表

        Returns:
            SeedGroupEntry 列表
        """
        catalog: List[SeedGroupEntry] = []

        for i, sg in enumerate(seed_groups):
            entry = SeedGroupSelector._build_entry(sg, i)
            catalog.append(entry)

        return catalog

    @staticmethod
    def _build_entry(seed_group: SeedGroup, index: int) -> SeedGroupEntry:
        """从单个 SeedGroup 构建 SeedGroupEntry"""

        # 从第一个有 metadata 的 seed 提取元数据
        first_meta: Dict[str, Any] = {}
        first_seed = None
        for seed in seed_group.seeds:
            if seed.metadata:
                first_meta = dict(seed.metadata)
                first_seed = seed
                break
        if first_seed is None and seed_group.seeds:
            first_seed = seed_group.seeds[0]

        # 提取各维度
        owasp_id = first_meta.get("owasp_id", "")
        owasp_name = _OWASP_NAMES.get(owasp_id, "")
        attack_mode = first_meta.get("attack_mode", "single_turn")
        technique = first_meta.get("technique", "")
        severity = first_meta.get("severity", "")

        # 推断 framework
        dataset_name = getattr(first_seed, "dataset_name", "") or ""
        if dataset_name.startswith("owasp_llm"):
            framework = "llm"
        elif dataset_name.startswith("owasp_asi"):
            framework = "agentic"
        elif dataset_name:
            framework = "remote"
        else:
            framework = "unknown"

        # harm_categories
        harm_cats = list(seed_group.harm_categories) if seed_group.harm_categories else []

        # 多轮判定（与 AttackPreparator 逻辑一致）
        prepended = seed_group.prepended_conversation
        is_multi_turn = bool(prepended)

        # objective
        objective = seed_group.objective
        has_objective = objective is not None
        objective_summary = ""
        if objective:
            objective_summary = objective.value[:60]
            if len(objective.value) > 60:
                objective_summary += "..."

        # 首条 prompt 摘要
        prompts = list(seed_group.prompts)
        prompt_summary = ""
        if prompts:
            val = prompts[0].value
            prompt_summary = val[:60]
            if len(val) > 60:
                prompt_summary += "..."

        return SeedGroupEntry(
            index=index,
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            framework=framework,
            harm_categories=harm_cats,
            attack_mode=attack_mode,
            technique=technique,
            severity=severity,
            is_multi_turn=is_multi_turn,
            has_objective=has_objective,
            seed_count=len(seed_group.seeds),
            objective_summary=objective_summary,
            prompt_summary=prompt_summary,
            dataset_name=dataset_name,
            source_seed_group=seed_group,
        )

    # ------------------------------------------------------------------
    # 过滤
    # ------------------------------------------------------------------

    @staticmethod
    def filter_by_owasp(
        catalog: List[SeedGroupEntry],
        owasp_ids: List[str],
    ) -> List[SeedGroupEntry]:
        """按 OWASP ID 过滤"""
        ids_upper = {oid.upper() for oid in owasp_ids}
        return [e for e in catalog if e.owasp_id.upper() in ids_upper]

    @staticmethod
    def filter_by_harm(
        catalog: List[SeedGroupEntry],
        harm_categories: List[str],
    ) -> List[SeedGroupEntry]:
        """按 harm_categories 过滤"""
        cats_lower = {c.lower() for c in harm_categories}
        return [
            e for e in catalog
            if any(c.lower() in cats_lower for c in e.harm_categories)
        ]

    @staticmethod
    def filter_by_mode(
        catalog: List[SeedGroupEntry],
        modes: List[str],
    ) -> List[SeedGroupEntry]:
        """按 attack_mode 过滤"""
        modes_lower = {m.lower() for m in modes}
        return [e for e in catalog if e.attack_mode.lower() in modes_lower]

    @staticmethod
    def filter_by_severity(
        catalog: List[SeedGroupEntry],
        severities: List[str],
    ) -> List[SeedGroupEntry]:
        """按 severity 过滤"""
        sevs_lower = {s.lower() for s in severities}
        return [e for e in catalog if e.severity.lower() in sevs_lower]

    @staticmethod
    def filter_multi_turn(catalog: List[SeedGroupEntry]) -> List[SeedGroupEntry]:
        """仅保留多轮攻击"""
        return [e for e in catalog if e.is_multi_turn]

    @staticmethod
    def filter_single_turn(catalog: List[SeedGroupEntry]) -> List[SeedGroupEntry]:
        """仅保留单轮攻击"""
        return [e for e in catalog if not e.is_multi_turn]

    @staticmethod
    def filter_has_objective(catalog: List[SeedGroupEntry]) -> List[SeedGroupEntry]:
        """仅保留有原生 objective 的种子组"""
        return [e for e in catalog if e.has_objective]

    # ------------------------------------------------------------------
    # 选择
    # ------------------------------------------------------------------

    @staticmethod
    def select_all(catalog: List[SeedGroupEntry]) -> List[SeedGroup]:
        """全选"""
        return [e.source_seed_group for e in catalog]

    @staticmethod
    def select_by_indices(
        catalog: List[SeedGroupEntry],
        indices: List[int],
    ) -> List[SeedGroup]:
        """按序号选择"""
        result: List[SeedGroup] = []
        for idx in indices:
            if 0 <= idx < len(catalog):
                result.append(catalog[idx].source_seed_group)
            else:
                logger.warning(f"Index {idx} out of range (0-{len(catalog)-1})")
        return result

    @staticmethod
    def select_by_entries(
        entries: List[SeedGroupEntry],
    ) -> List[SeedGroup]:
        """从 SeedGroupEntry 列表提取 SeedGroup"""
        return [e.source_seed_group for e in entries]

    # ------------------------------------------------------------------
    # 终端展示
    # ------------------------------------------------------------------

    def display(self, catalog: List[SeedGroupEntry]) -> None:
        """终端表格展示种子组目录"""

        if not catalog:
            print("  (无种子组)")
            return

        # 统计
        mode_counts: Dict[str, int] = {}
        sev_counts: Dict[str, int] = {}
        fw_counts: Dict[str, int] = {}
        for e in catalog:
            mode_counts[e.attack_mode] = mode_counts.get(e.attack_mode, 0) + 1
            sev_counts[e.severity or "unknown"] = sev_counts.get(e.severity or "unknown", 0) + 1
            fw_counts[e.framework] = fw_counts.get(e.framework, 0) + 1

        fw_str = " + ".join(f"{fw}×{cnt}" for fw, cnt in sorted(fw_counts.items()))
        mode_str = ", ".join(f"{m}={c}" for m, c in sorted(mode_counts.items()))
        sev_str = ", ".join(f"{s}={c}" for s, c in sorted(sev_counts.items(), key=lambda x: -x[1]))

        print()
        print("=" * 100)
        print(f"  种子组选择面板 (CentralMemory) | 共 {len(catalog)} 个 | {fw_str}")
        print("=" * 100)
        print(f"  {'#':>3}  {'OWASP':6}  {'名称':24}  {'harm_categories':16}  "
              f"{'attack_mode':16}  {'sev':8}  {'turns':8}  摘要")
        print("-" * 100)

        for e in catalog:
            # turns 列：显示轮数 + 是否有 objective
            if e.is_multi_turn:
                turns = f"{e.seed_count}轮"
                if e.has_objective:
                    turns += "+obj"
            else:
                turns = "1轮"
                if e.has_objective:
                    turns += "+obj"

            harm_str = ",".join(e.harm_categories[:2]) if e.harm_categories else "-"
            name = e.owasp_name[:24] if e.owasp_name else "-"
            summary = e.objective_summary or e.prompt_summary
            summary = summary[:40] if summary else "-"

            print(
                f"  {e.index:>3}  {e.owasp_id:6}  {name:24}  {harm_str:16}  "
                f"{e.attack_mode:16}  {e.severity or '-':8}  {turns:8}  {summary}"
            )

        print("-" * 100)
        print(f"  统计: {mode_str}")
        print(f"  统计: {sev_str}")
        print("=" * 100)

    # ------------------------------------------------------------------
    # 交互式选择
    # ------------------------------------------------------------------

    async def prompt_user(
        self,
        catalog: List[SeedGroupEntry],
        *,
        preset_owasp: Optional[List[str]] = None,
        preset_modes: Optional[List[str]] = None,
    ) -> List[SeedGroup]:
        """
        交互式用户选择

        展示目录并让用户选择攻击组合。
        支持 preset 参数跳过交互（脚本模式）。

        Args:
            catalog: 种子组目录
            preset_owasp: 预设 OWASP ID 过滤（跳过交互）
            preset_modes: 预设 attack_mode 过滤（跳过交互）

        Returns:
            用户选中的 SeedGroup 列表
        """

        # 非交互模式：全选
        if not self.enabled:
            print("  [OK] 交互式选择: 禁用 → 全选")
            return self.select_all(catalog)

        # 自动选择：只有 1 个种子组
        if self.auto_select_if_single and len(catalog) == 1:
            print(f"  [OK] 仅 1 个种子组 → 自动选择")
            return self.select_all(catalog)

        # 预设选择（脚本模式）
        if preset_owasp or preset_modes:
            filtered = catalog
            if preset_owasp:
                filtered = self.filter_by_owasp(filtered, preset_owasp)
            if preset_modes:
                filtered = self.filter_by_mode(filtered, preset_modes)
            if filtered:
                print(f"  [OK] 预设选择: {len(filtered)}/{len(catalog)} 个种子组")
                self._display_selected(filtered)
                return self.select_by_entries(filtered)
            else:
                print(f"  [!] 预设过滤无结果，使用全部种子组")
                return self.select_all(catalog)

        # 交互式选择
        working_catalog = list(catalog)

        while True:
            self.display(working_catalog)
            print()
            print("  操作:")
            print("    [a] 全选              [s] 按序号选择 (如 0,3,5-8)")
            print("    [f] 过滤 (owasp/harm/mode/severity)")
            print("    [r] 重置过滤          [q] 确认选择并继续")
            print()

            try:
                choice = input("  请输入选择 [a/s/f/r/q]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n  [OK] 用户取消，使用全部种子组")
                return self.select_all(catalog)

            if choice == "a":
                print(f"\n  [OK] 全选 {len(working_catalog)} 个种子组")
                self._display_selected(working_catalog)
                return self.select_all(working_catalog)

            elif choice == "s":
                selected = self._prompt_indices(working_catalog)
                if selected:
                    return selected

            elif choice == "f":
                working_catalog = self._prompt_filter(working_catalog)

            elif choice == "r":
                working_catalog = list(catalog)
                print(f"  [OK] 已重置为全部 {len(working_catalog)} 个种子组")

            elif choice == "q":
                print(f"\n  [OK] 确认选择当前 {len(working_catalog)} 个种子组")
                self._display_selected(working_catalog)
                return self.select_all(working_catalog)

            else:
                print(f"  [!] 无效选择: {choice}")

    def _prompt_indices(self, catalog: List[SeedGroupEntry]) -> List[SeedGroup]:
        """按序号选择"""
        try:
            raw = input(f"  输入序号 (逗号分隔，支持范围 如 0,3,5-8): ").strip()
        except (EOFError, KeyboardInterrupt):
            return []

        indices = self._parse_indices(raw, len(catalog))
        if not indices:
            print("  [!] 无有效序号")
            return []

        selected_entries = [catalog[i] for i in indices]
        print(f"\n  [OK] 已选择 {len(selected_entries)} 个种子组:")
        self._display_selected(selected_entries)

        try:
            confirm = input("\n  确认执行? [y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            confirm = "y"

        if confirm in ("y", "yes", ""):
            return self.select_by_entries(selected_entries)
        else:
            return []

    def _prompt_filter(self, catalog: List[SeedGroupEntry]) -> List[SeedGroupEntry]:
        """过滤子界面"""
        print()
        print("  过滤选项:")
        print("    [1] 按 OWASP ID (如 LLM01,ASI02)")
        print("    [2] 按 harm_categories (如 prompt_injection,privacy)")
        print("    [3] 按 attack_mode (single_turn/multi_turn/converter_enhanced/sequential)")
        print("    [4] 按 severity (low/high/critical)")
        print("    [5] 仅多轮攻击")
        print("    [6] 仅单轮攻击")
        print("    [7] 仅含 objective 的种子组")
        print("    [0] 返回")

        try:
            choice = input("\n  选择: ").strip()
        except (EOFError, KeyboardInterrupt):
            return catalog

        if choice == "1":
            raw = input("  输入 OWASP ID (逗号分隔): ").strip()
            ids = [s.strip() for s in raw.split(",") if s.strip()]
            if ids:
                filtered = self.filter_by_owasp(catalog, ids)
                print(f"  [OK] 过滤结果: {len(filtered)}/{len(catalog)} 个")
                return filtered

        elif choice == "2":
            raw = input("  输入 harm_categories (逗号分隔): ").strip()
            cats = [s.strip() for s in raw.split(",") if s.strip()]
            if cats:
                filtered = self.filter_by_harm(catalog, cats)
                print(f"  [OK] 过滤结果: {len(filtered)}/{len(catalog)} 个")
                return filtered

        elif choice == "3":
            raw = input("  输入 attack_mode (逗号分隔): ").strip()
            modes = [s.strip() for s in raw.split(",") if s.strip()]
            if modes:
                filtered = self.filter_by_mode(catalog, modes)
                print(f"  [OK] 过滤结果: {len(filtered)}/{len(catalog)} 个")
                return filtered

        elif choice == "4":
            raw = input("  输入 severity (逗号分隔): ").strip()
            sevs = [s.strip() for s in raw.split(",") if s.strip()]
            if sevs:
                filtered = self.filter_by_severity(catalog, sevs)
                print(f"  [OK] 过滤结果: {len(filtered)}/{len(catalog)} 个")
                return filtered

        elif choice == "5":
            filtered = self.filter_multi_turn(catalog)
            print(f"  [OK] 多轮攻击: {len(filtered)}/{len(catalog)} 个")
            return filtered

        elif choice == "6":
            filtered = self.filter_single_turn(catalog)
            print(f"  [OK] 单轮攻击: {len(filtered)}/{len(catalog)} 个")
            return filtered

        elif choice == "7":
            filtered = self.filter_has_objective(catalog)
            print(f"  [OK] 含 objective: {len(filtered)}/{len(catalog)} 个")
            return filtered

        return catalog

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_indices(raw: str, max_len: int) -> List[int]:
        """解析用户输入的序号字符串，支持范围如 0,3,5-8"""
        indices: List[int] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                # 范围如 5-8
                match = re.match(r"^(\d+)\s*-\s*(\d+)$", part)
                if match:
                    start = int(match.group(1))
                    end = int(match.group(2))
                    for idx in range(start, end + 1):
                        if 0 <= idx < max_len:
                            indices.append(idx)
            else:
                idx = int(part)
                if 0 <= idx < max_len:
                    indices.append(idx)
        return indices

    @staticmethod
    def _display_selected(entries: List[SeedGroupEntry]) -> None:
        """展示已选中的种子组摘要"""
        for e in entries:
            summary = e.objective_summary or e.prompt_summary
            print(f"    [{e.index:>3}] {e.owasp_id:6} {e.owasp_name:24} "
                  f"| {e.attack_mode:16} | {summary}")

    @staticmethod
    def get_statistics(catalog: List[SeedGroupEntry]) -> Dict[str, Any]:
        """获取目录统计信息"""
        mode_counts: Dict[str, int] = {}
        sev_counts: Dict[str, int] = {}
        fw_counts: Dict[str, int] = {}
        owasp_counts: Dict[str, int] = {}
        multi_turn_count = 0
        has_obj_count = 0

        for e in catalog:
            mode_counts[e.attack_mode] = mode_counts.get(e.attack_mode, 0) + 1
            sev_counts[e.severity or "unknown"] = sev_counts.get(e.severity or "unknown", 0) + 1
            fw_counts[e.framework] = fw_counts.get(e.framework, 0) + 1
            if e.owasp_id:
                owasp_counts[e.owasp_id] = owasp_counts.get(e.owasp_id, 0) + 1
            if e.is_multi_turn:
                multi_turn_count += 1
            if e.has_objective:
                has_obj_count += 1

        return {
            "total": len(catalog),
            "by_mode": mode_counts,
            "by_severity": sev_counts,
            "by_framework": fw_counts,
            "by_owasp": owasp_counts,
            "multi_turn": multi_turn_count,
            "single_turn": len(catalog) - multi_turn_count,
            "has_objective": has_obj_count,
        }
