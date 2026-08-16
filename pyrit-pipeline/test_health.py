import httpx
r = httpx.post('http://127.0.0.1:8080/api/labs/PI_01/chat', json={'prompt': 'hi'}, timeout=10.0)
print(f'Status: {r.status_code}')
print(f'CT: {r.headers.get("content-type")}')
print(f'Body: {r.text[:100]}')
