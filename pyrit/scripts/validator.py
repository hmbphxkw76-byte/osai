"""
===============================================================================
PyRIT Red Team — 用例分类验证工具
===============================================================================
用途: 快速统计测试用例的 probe/single/crescendo 分布并校验 EN/CN ID 对齐。
运行: python scripts/validator.py
===============================================================================
"""
import json
import os
import sys

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from executor import classify_case


def main():
    for lang, fname in [("EN", "datasets/test_cases_en.json"), ("CN", "datasets/test_cases_cn.json")]:
        with open(fname, "r", encoding="utf-8") as f:
            data = json.load(f)
        cases = data["test_cases"]
        classes = {"probe": 0, "single": 0, "crescendo": 0}
        for c in cases:
            classes[classify_case(c)] += 1
        print(f"[{lang}] v{data['metadata']['version']} | Total: {len(cases)} | PROBE:{classes['probe']} SINGLE:{classes['single']} CRESCENDO:{classes['crescendo']}")

        # Show new Agent/Embedding cases
        for c in cases:
            cid = c["id"]
            if any(x in cid for x in ["CAP_031", "CAP_032", "CAP_033", "CAP_034", "CAP_035"]):
                print(f"  + {cid} [{classify_case(c)}]")

    # Cross-check EN/CN IDs match
    en_ids = [c["id"] for c in json.load(open("datasets/test_cases_en.json", encoding="utf-8"))["test_cases"]]
    cn_ids = [c["id"] for c in json.load(open("datasets/test_cases_cn.json", encoding="utf-8"))["test_cases"]]
    assert en_ids == cn_ids, f"Mismatch! EN:{len(en_ids)} CN:{len(cn_ids)}"
    print("\nEN/CN ID alignment: OK")


if __name__ == "__main__":
    main()
