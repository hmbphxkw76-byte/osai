import asyncio
import httpx
import time

async def send_request(client, prompt_text, req_id):
    start = time.time()
    try:
        r = await client.request(
            method="POST",
            url="http://127.0.0.1:8080/api/labs/PI_01/chat",
            headers={"content-type": "application/json", "host": "127.0.0.1:8080"},
            content=f'{{"prompt":"{prompt_text}"}}'.encode(),
            follow_redirects=True,
        )
        elapsed = time.time() - start
        print(f"  [{req_id}] Status: {r.status_code}, Elapsed: {elapsed:.2f}s, Body: {r.text[:100]}")
        return r
    except Exception as e:
        elapsed = time.time() - start
        print(f"  [{req_id}] Error after {elapsed:.2f}s: {type(e).__name__}: {e}")
        raise

async def test_concurrent():
    print("=== Test: 3 concurrent requests with timeout=15 ===")
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        tasks = [
            send_request(client, "What is 1+1?", "req1"),
            send_request(client, "What is 2+2?", "req2"),
            send_request(client, "What is 3+3?", "req3"),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                print(f"  Task {i+1} failed: {r}")
            else:
                print(f"  Task {i+1} succeeded")

async def test_sequential():
    print("\n=== Test: 3 sequential requests with timeout=15 ===")
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        for i in range(3):
            await send_request(client, f"What is {i+1}+{i+1}?", f"seq{i+1}")

asyncio.run(test_concurrent())
asyncio.run(test_sequential())
