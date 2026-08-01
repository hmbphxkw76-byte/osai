"""临时冒烟脚本：单探针端到端验证 Stage3/4/5"""
import time

import yaml

from pipeline.stage3_execute import execute_attack
from pipeline.stage4_analyze import analyze
from pipeline.stage5_report import export_pyrit_air, render_final_cards

with open("config/target.yaml", encoding="utf-8") as _f:
    tc = yaml.safe_load(_f)
target = tc["target"]
run_id = "MINI" + time.strftime("%H%M")
probe = ["probes.knownbadsignatures.IndirectInjection"]

res = execute_attack(
    target, probe, "encoding:Rot13", run_id, "outputs",
    execute_cfg={"generations": 2}, reporting_cfg={"confidence_interval_method": "none"},
)
print("EXEC_DONE", res["report_path"], flush=True)

filt = [{"name": probe[0], "tier": 1, "modality": {"in": ["text"], "out": ["text"]}}]
an = analyze(res["report_path"], filt, run_id, "outputs")
print("ANALYZE_DONE", an["probes_evaluated"], flush=True)

p = export_pyrit_air(an, "outputs", run_id)
render_final_cards(an)
print("SMOKE_OK", p, flush=True)
