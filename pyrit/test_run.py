import subprocess, sys, os, time

os.environ['PYTHONIOENCODING'] = 'utf-8'

env = {**os.environ, 'PYTHONIOENCODING': 'utf-8', 'PYTHONUNBUFFERED': '1'}

p = subprocess.Popen(
    [sys.executable, '-u', '-m', 'pyrit_ai300.cli', 'recon', '--spa-config', 'config/targets/spa_target.yaml'],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    encoding='utf-8',
    errors='replace',
    env=env
)

time.sleep(25)
p.terminate()
out = p.stdout.read()

with open('test_output.txt', 'w', encoding='utf-8') as f:
    f.write(out)

print("Done. Output in test_output.txt")
