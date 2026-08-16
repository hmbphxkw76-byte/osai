import httpx
import time

print("=== Test: httpx.AsyncClient with timeout=15.0 ===")
client = httpx.AsyncClient(http2=False, timeout=15.0, verify=False)
print(f"Timeout config: {client.timeout}")
print(f"  read: {client.timeout.read}")
print(f"  connect: {client.timeout.connect}")
print(f"  write: {client.timeout.write}")
print(f"  pool: {client.timeout.pool}")

import asyncio

async def test():
    start = time.time()
    try:
        # Simulate what HTTPTarget does
        r = await client.request(
            method="POST",
            url="http://127.0.0.1:8080/api/labs/PI_01/chat",
            headers={"content-type": "application/json", "host": "127.0.0.1:8080"},
            content=b'{"prompt":"hi"}',
            follow_redirects=True,
        )
        elapsed = time.time() - start
        print(f"Success: status={r.status_code}, elapsed={elapsed:.2f}s")
        print(f"Body: {r.text[:200]}")
    except Exception as e:
        elapsed = time.time() - start
        print(f"Error after {elapsed:.2f}s: {type(e).__name__}: {e}")
    finally:
        await client.aclose()

asyncio.run(test())
