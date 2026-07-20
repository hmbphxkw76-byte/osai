import os
# Clear env vars to simulate fresh start
os.environ.pop('SPA_TARGET_URL', None)
os.environ.pop('SPA_USERNAME', None)

from pyrit_ai300.utils.env_loader import load_dotenv, resolve_env_vars, _dotenv_loaded

print(f"Before: _dotenv_loaded={_dotenv_loaded}")
r = load_dotenv()
print(f"load_dotenv result: {r}")
print(f"After: _dotenv_loaded={_dotenv_loaded}")
print(f"SPA_TARGET_URL: {repr(os.environ.get('SPA_TARGET_URL', '(NOT SET)'))}")

result = resolve_env_vars({'url': '${SPA_TARGET_URL}', 'user': '${SPA_USERNAME}'})
print(f"Resolved: {result}")
