import re, glob

# 1. Read all exam detail pages
files = sorted(glob.glob('D:/文档/GitHub/RedTeam-AI/.temp_exam_p*.txt'))
for f in files:
    print(f'FILE: {f}')
    with open(f, 'r', encoding='utf-8') as fh:
        print(fh.read()[:3000])
    print('---SEPARATOR---')

# 2. Extract text from HTML chapters (Ch3, Ch4, Ch5, Ch7, Ch8, Ch9, Ch10, Ch11)
html_files = [
    ('Ch3', r'D:\视频\66.OffSec\18. OffSec AI-300\Ch3-Attacking-AI-Agents.html'),
    ('Ch4', r'D:\视频\66.OffSec\18. OffSec AI-300\Ch4-Attacking-MultiAgent-Systems-and-A2A-Protocol.html'),
    ('Ch5', r'D:\视频\66.OffSec\18. OffSec AI-300\Ch5-Exploiting-RAG-Pipelines.html'),
    ('Ch7', r'D:\视频\66.OffSec\18. OffSec AI-300\Ch7-Attacking-MCP-and-Tool-Surfaces.html'),
    ('Ch8', r'D:\视频\66.OffSec\18. OffSec AI-300\Ch8-Supply-Chain-Attacks-on-AIML-Systems.html'),
    ('Ch9', r'D:\视频\66.OffSec\18. OffSec AI-300\Ch9-AI-Infrastructure-and-Deployment-Exploits.html'),
    ('Ch10', r'D:\视频\66.OffSec\18. OffSec AI-300\Ch10-Threat-Modeling-for-AIEnabled-Targets.html'),
    ('Ch11', r'D:\视频\66.OffSec\18. OffSec AI-300\Ch11-Assembling-The-Pieces-Capstone-Red-Team.html'),
]

for ch_name, path in html_files:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Extract text
        content = re.sub(r'<script[^>]*>.*?</script>', ' ', content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r'<style[^>]*>.*?</style>', ' ', content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r'<[^>]+>', '\n', content)
        content = re.sub(r'\n\s*\n', '\n', content)
        content = re.sub(r'&amp;', '&', content)
        content = re.sub(r'&lt;', '<', content)
        content = re.sub(r'&gt;', '>', content)
        content = re.sub(r'&quot;', '"', content)
        content = re.sub(r'&\w+;', ' ', content)
        content = re.sub(r'&#\d+;', ' ', content)
        # Filter meaningful lines
        lines = [l.strip() for l in content.split('\n') if len(l.strip()) > 30]
        output = '\n'.join(lines[:300])
        out_path = f'D:/文档/GitHub/RedTeam-AI/.temp_{ch_name}.txt'
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f'{ch_name}: {len(lines)} meaningful lines -> {out_path}')
    except Exception as e:
        print(f'{ch_name}: ERROR - {e}')

print('=== DONE ===')
