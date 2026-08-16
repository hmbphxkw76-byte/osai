import httpx

client = httpx.Client(timeout=30)
with client.stream("POST", "http://127.0.0.1:8080/api/labs/PI_01/chat", json={"prompt": "hi"}) as r:
    print(f"Status: {r.status_code}")
    print(f"Content-Type: {r.headers.get('content-type')}")
    lines = []
    for line in r.iter_lines():
        if line.strip():
            lines.append(line)
    for l in lines[:30]:
        print(repr(l[:200]))
client.close()
