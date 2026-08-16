import sys
sys.path.insert(0, ".")
from pipeline.integrations.recon_target_bridge import enhance_burp_request
from pipeline.stages.stage_target_classify import _fix_content_length, _inject_dynamic_session_fields, _detect_sse_from_request, _detect_tls_from_request

raw = open("data/burp/request.txt", encoding="utf-8").read()
print("=== Original request ===")
print(repr(raw[:200]))
print(f"  Has CRLF: {'\\r\\n' in raw}")

enhanced = enhance_burp_request(raw, auth_headers=None)
print("\n=== Enhanced request ===")
print(repr(enhanced[:300]))

fixed = _fix_content_length(enhanced)
print("\n=== After _fix_content_length ===")
print(repr(fixed[:300]))

# Check if {PROMPT} was injected
print(f"\nHas {{PROMPT}}: {'{PROMPT}' in fixed}")

# Check CRLF
print(f"Has CRLF: {'\\r\\n' in fixed}")
print(f"Has LF only: {'\\n' in fixed and '\\r\\n' not in fixed}")

# Check what PyRIT parse_raw_http_request would do
normalized = fixed.replace("\r\n", "\n")
parts = normalized.split("\n\n", 1)
print(f"\n=== PyRIT parse simulation ===")
print(f"Header section length: {len(parts[0])}")
print(f"Body: {parts[1] if len(parts) > 1 else '(empty)'}")
print(f"Body has PROMPT: {'{PROMPT}' in parts[1] if len(parts) > 1 else False}")

# Check SSE detection
is_sse = _detect_sse_from_request(fixed)
print(f"\nSSE detected: {is_sse}")

# Check TLS detection
use_tls = _detect_tls_from_request(fixed)
print(f"TLS detected: {use_tls}")
