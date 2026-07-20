import re
import os

os.environ['TEST_KEY'] = 'secret123'

# Test 1: Direct string
s = '${TEST_KEY}'
print(f'String repr: {repr(s)}')

# Test 2: Regex
p = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}')
m = p.search(s)
print(f'Match: {m}')

# Test 3: Sub
r = p.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ''), s)
print(f'Replaced: {r}')
