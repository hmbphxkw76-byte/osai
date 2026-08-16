import httpx
import time

print("Test 1: Non-stream request (response.content)")
start = time.time()
try:
    client = httpx.Client(timeout=30)
    r = client.post("http://127.0.0.1:8080/api/labs/PI_01/chat", json={"prompt": "hi"})
    elapsed = time.time() - start
    print(f"  Status: {r.status_code}")
    print(f"  Content-Type: {r.headers.get('content-type')}")
    print(f"  Elapsed: {elapsed:.2f}s")
    print(f"  Body length: {len(r.text)}")
    print(f"  Body (first 300): {r.text[:300]}")
    client.close()
except Exception as e:
    elapsed = time.time() - start
    print(f"  Error after {elapsed:.2f}s: {type(e).__name__}: {e}")

print("\nTest 2: With timeout=5")
start = time.time()
try:
    client = httpx.Client(timeout=5)
    r = client.post("http://127.0.0.1:8080/api/labs/PI_01/chat", json={"prompt": "hi"})
    elapsed = time.time() - start
    print(f"  Status: {r.status_code}, Elapsed: {elapsed:.2f}s, Body: {r.text[:200]}")
    client.close()
except Exception as e:
    elapsed = time.time() - start
    print(f"  Error after {elapsed:.2f}s: {type(e).__name__}: {e}")

print("\nTest 3: Async with timeout=15")
import asyncio

async def test_async():
    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            r = await client.request(
                method="POST",
                url="http://127.0.0.1:8080/api/labs/PI_01/chat",
                headers={"Content-Type": "application/json"},
                content=b'{"prompt":"hi"}',
                follow_redirects=True,
            )
            elapsed = time.time() - start
            print(f"  Status: {r.status_code}, Elapsed: {elapsed:.2f}s")
            print(f"  Content-Type: {r.headers.get('content-type')}")
            print(f"  Body length: {len(r.text)}")
            print(f"  Body (first 300): {r.text[:300]}")
    except Exception as e:
        elapsed = time.time() - start
        print(f"  Error after {elapsed:.2f}s: {type(e).__name__}: {e}")

asyncio.run(test_async())
