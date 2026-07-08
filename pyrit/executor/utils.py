"""
===============================================================================
PyRIT Red Team — 引擎工具函数
===============================================================================
包含:
- classify_case(): 用例分类 (probe / single / crescendo)
- _calc_success_rate(): 成功率计算
===============================================================================
"""


def classify_case(case: dict) -> str:
    """Classify a test case as 'probe', 'single', or 'crescendo'."""
    case_id = case.get("id", "")
    if case_id.upper().startswith("PROBE_"):
        return "probe"
    if "multi_turn_objectives" in case and len(case.get("multi_turn_objectives", [])) > 0:
        return "crescendo"
    return "single"


def _calc_success_rate(results: list) -> float:
    """Calculate success rate from attack results."""
    if not results:
        return 0.0
    success_count = sum(1 for r in results if r.get("status") == "SUCCESS")
    return success_count / len(results)
