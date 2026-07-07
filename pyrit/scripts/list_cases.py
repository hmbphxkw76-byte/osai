"""列出所有测试用例 ID 和 objective 摘要"""
import json, os
fpath = os.path.join(os.path.dirname(os.path.dirname(__file__)), "datasets", "test_cases_cn.json")
with open(fpath, "r", encoding="utf-8") as f:
    data = json.load(f)

print(f"{'ID':50s} {'Round':8s} {'Objective (前80字)'}")
print("-" * 140)
for c in data["test_cases"]:
    cid = c["id"]
    if "multi_turn_objectives" in c and c["multi_turn_objectives"]:
        rtype = "crescendo"
    elif cid.startswith("PROBE_"):
        rtype = "probe"
    else:
        rtype = "single"
    obj = c.get("objective", c.get("multi_turn_objectives", [""])[0] if c.get("multi_turn_objectives") else "")
    print(f"{cid:50s} {rtype:8s} {obj[:80]}")
