import json

def classify(c):
    cid = c["id"]
    if cid.upper().startswith("PROBE_"): return "probe"
    if "multi_turn_objectives" in c and len(c.get("multi_turn_objectives", [])) > 0: return "crescendo"
    return "single"

for lang, fname in [("EN", "multi_stage_capstone_cases_en.json"), ("CN", "multi_stage_capstone_cases_cn.json")]:
    with open(fname, "r", encoding="utf-8") as f:
        data = json.load(f)
    cases = data["test_cases"]
    classes = {"probe": 0, "single": 0, "crescendo": 0}
    for c in cases:
        classes[classify(c)] += 1
    print(f"[{lang}] v{data['metadata']['version']} | Total: {len(cases)} | PROBE:{classes['probe']} SINGLE:{classes['single']} CRESCENDO:{classes['crescendo']}")
    
    # Show new Agent/Embedding cases
    for c in cases:
        cid = c["id"]
        if any(x in cid for x in ["CAP_031", "CAP_032", "CAP_033", "CAP_034", "CAP_035"]):
            print(f"  + {cid} [{classify(c)}]")

# Cross-check EN/CN IDs match
en_ids = [c["id"] for c in json.load(open("multi_stage_capstone_cases_en.json", encoding="utf-8"))["test_cases"]]
cn_ids = [c["id"] for c in json.load(open("multi_stage_capstone_cases_cn.json", encoding="utf-8"))["test_cases"]]
assert en_ids == cn_ids, f"Mismatch! EN:{len(en_ids)} CN:{len(cn_ids)}"
print("\nEN/CN ID alignment: OK")
