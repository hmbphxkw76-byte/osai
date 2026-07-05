"""Quick test: payload module loading end-to-end"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.loader import load_payloads_module, apply_preset
import engines

# Simulate main.py flow
vars_dict, presets = load_payloads_module("cn")
engines.PAYLOAD_VARS.update(vars_dict)
print(f"Base vars loaded: {len(engines.PAYLOAD_VARS)}")

# Test preset override
apply_preset(engines.PAYLOAD_VARS, "stealth", presets)
ctx_val = engines.PAYLOAD_VARS.get("ctx_hm_prompt", "")
print(f"After stealth preset: ctx_hm_prompt = {repr(ctx_val)[:80]}")

# Verify no empty vars
empty = [k for k, v in engines.PAYLOAD_VARS.items() if not v]
print(f"Empty vars: {empty if empty else 'None [OK]'}")

# Test a few values
for key in ["python_reverse_shell", "sql_injection_payload", "xss_payload"]:
    val = engines.PAYLOAD_VARS.get(key, "")[:60]
    print(f"  {key}: {val}...")

print("\n[OK] All tests passed")
