# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""P3: 人工标注 CLI 工具 — 交互式审核争议评分样本.

读取 outputs/review/queue.jsonl 中的争议样本,
逐条展示供人工标注 (true/false), 标注结果写入 outputs/review/reviewed.jsonl,
自动更新双 Judge F1 权重.

使用方式::

    python -m pipeline.scoring.review_cli              # 交互式标注
    python -m pipeline.scoring.review_cli --auto-yes   # 全部标 true (快速测试)
    python -m pipeline.scoring.review_cli --stats       # 查看统计

> **日期**: 2026-8-16
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REVIEW_DIR = Path("outputs/review")
_QUEUE_FILE = _REVIEW_DIR / "queue.jsonl"
_REVIEWED_FILE = _REVIEW_DIR / "reviewed.jsonl"


def load_queue() -> list[dict]:
    """加载待审核队列."""
    if not _QUEUE_FILE.exists():
        print(f"队列文件不存在: {_QUEUE_FILE}")
        print("请先运行流水线生成争议样本.")
        return []
    items: list[dict] = []
    with open(_QUEUE_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def show_stats() -> None:
    """显示审核队列统计."""
    queue = load_queue()
    reviewed_count = 0
    if _REVIEWED_FILE.exists():
        with open(_REVIEWED_FILE, encoding="utf-8") as f:
            reviewed_count = sum(
                1 for line in f
                if line.strip() and json.loads(line).get("human_label") is not None
            )
    print("\n=== Human Review Queue Statistics ===")
    print(f"  Queue file:    {_QUEUE_FILE}")
    print(f"  Queue size:    {len(queue)} items")
    print(f"  Reviewed:      {reviewed_count} items")
    print(f"  Pending:       {len(queue) - reviewed_count} items")
    if queue:
        high = sum(1 for item in queue if item.get("priority") == "high")
        medium = sum(1 for item in queue if item.get("priority") == "medium")
        low = sum(1 for item in queue if item.get("priority") == "low")
        print(f"  By priority:  high={high}, medium={medium}, low={low}")
        disputed = sum(1 for item in queue if item.get("disputed"))
        print(f"  Disputed:      {disputed} items")


def interactive_review(auto_yes: bool = False) -> None:
    """交互式审核争议样本.

    Args:
        auto_yes: 如果 True, 全部标注为 true (快速测试用).
    """
    queue = load_queue()
    if not queue:
        return

    # 按优先级排序
    priority_order = {"high": 0, "medium": 1, "low": 2}
    queue.sort(key=lambda x: (priority_order.get(x.get("priority", "medium"), 1), x.get("confidence", 1)))

    # 加载已审核的 attack_id
    reviewed_ids: set[str] = set()
    if _REVIEWED_FILE.exists():
        with open(_REVIEWED_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    item = json.loads(line)
                    if item.get("human_label") is not None:
                        reviewed_ids.add(item.get("attack_id", ""))

    pending = [item for item in queue if item.get("attack_id") not in reviewed_ids]
    if not pending:
        print("\n所有样本已审核完毕!")
        show_stats()
        return

    print(f"\n=== Interactive Review ({len(pending)} pending) ===")
    print("Commands: [t]rue, [f]alse, [s]kip, [q]uit")
    print()

    reviewed: list[dict] = []
    for i, item in enumerate(pending):
        print(f"\n--- Item {i + 1}/{len(pending)} ---")
        print(f"  Attack ID:     {item.get('attack_id', 'N/A')}")
        print(f"  Priority:      {item.get('priority', 'medium')}")
        print(f"  Disputed:      {item.get('disputed', False)}")
        print(f"  Judge-A:        {item.get('judge_a_result', 'N/A')} "
              f"(conf={item.get('judge_a_confidence', 0)})")
        print(f"  Judge-B:        {item.get('judge_b_result', 'N/A')} "
              f"(conf={item.get('judge_b_confidence', 0)})")
        print(f"  Auto result:   {item.get('auto_result', 'N/A')} "
              f"(conf={item.get('confidence', 0)})")
        print(f"  Objective:     {item.get('objective', 'N/A')[:200]}")
        print(f"  Response:      {item.get('response', 'N/A')[:300]}")

        if auto_yes:
            label = "true"
            print(f"  → Auto-labeled: {label}")
        else:
            try:
                choice = input("  Label [t/f/s/q]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n  Interrupted.")
                break
            if choice in ("q", "quit", "exit"):
                print("  Quitting.")
                break
            if choice in ("s", "skip"):
                print("  Skipped.")
                continue
            if choice in ("t", "true", "1", "y", "yes"):
                label = "true"
            elif choice in ("f", "false", "0", "n", "no"):
                label = "false"
            else:
                print("  Invalid input. Skipping.")
                continue
            print(f"  → Labeled: {label}")

        item["human_label"] = label
        item["reviewer"] = "cli_user"
        reviewed.append(item)

    # 写入 reviewed.jsonl
    if reviewed:
        with open(_REVIEWED_FILE, "a", encoding="utf-8") as f:
            for item in reviewed:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"\n✅ {len(reviewed)} items labeled and saved to {_REVIEWED_FILE}")

        # 更新 F1 权重
        try:
            from pipeline.scoring.human_review_queue import HumanReviewQueue

            queue_mgr = HumanReviewQueue()
            all_reviewed = queue_mgr.load_reviewed()
            f1 = queue_mgr.update_judge_f1(all_reviewed)
            if f1:
                print(f"  Judge F1 updated: Judge-A={f1['judge_a']:.3f}, "
                      f"Judge-B={f1['judge_b']:.3f}")
        except Exception as e:
            print(f"  [Warning] F1 update failed: {e}")

    show_stats()


def main() -> None:
    """CLI 入口."""
    args = sys.argv[1:]
    if "--stats" in args:
        show_stats()
    elif "--auto-yes" in args:
        interactive_review(auto_yes=True)
    elif "--help" in args or "-h" in args:
        print("Usage: python -m pipeline.scoring.review_cli [--stats|--auto-yes|--help]")
        print()
        print("Commands:")
        print("  (default)  Interactive review of disputed scoring items")
        print("  --stats     Show queue statistics")
        print("  --auto-yes  Auto-label all as true (for testing)")
        print("  --help      Show this help")
    else:
        interactive_review()


if __name__ == "__main__":
    main()
