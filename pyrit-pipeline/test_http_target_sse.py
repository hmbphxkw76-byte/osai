import asyncio
import sys
import time

sys.path.insert(0, ".")

from pyrit.memory import CentralMemory, SQLiteMemory
CentralMemory.set_memory_instance(SQLiteMemory())

from pyrit.prompt_target import HTTPTarget
from pipeline.integrations.recon_target_bridge import enhance_burp_request
from pipeline.stages.stage_target_classify import (
    _fix_content_length,
    _inject_dynamic_session_fields,
    _build_fallback_sse_callback,
)

# Read and enhance Burp request
raw = open("data/burp/request.txt", encoding="utf-8").read()
enhanced = enhance_burp_request(raw, auth_headers=None)
fixed = _fix_content_length(enhanced)
session_injected = _inject_dynamic_session_fields(fixed)
final = _fix_content_length(session_injected)

print(f"Final request length: {len(final)}")
print(f"Has {{PROMPT}}: {'{PROMPT}' in final}")
print()

# Create HTTPTarget exactly as pipeline does
callback = _build_fallback_sse_callback()
target = HTTPTarget(
    http_request=final,
    prompt_regex_string="{PROMPT}",
    callback_function=callback,
    use_tls=False,
    timeout=15.0,
)

print(f"httpx_client_kwargs: {target.httpx_client_kwargs}")
print()

async def test():
    from pyrit.models import Message, MessagePiece
    
    # Simulate sending a prompt
    start = time.time()
    try:
        # Create a simple prompt request using new PyRIT API
        piece = MessagePiece(role="user", original_value="What is 2+2?")
        message = Message(message_pieces=[piece])
        
        result = await target.send_prompt_async(message=message)
        elapsed = time.time() - start
        print(f"Success! Elapsed: {elapsed:.2f}s")
        print(f"Response: {result}")
    except Exception as e:
        elapsed = time.time() - start
        print(f"Error after {elapsed:.2f}s: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

asyncio.run(test())
