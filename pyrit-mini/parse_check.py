#!/usr/bin/env python3
"""Check if the file can be parsed"""

import ast

try:
    with open('core/orchestrator.py', 'r', encoding='utf-8') as f:
        source = f.read()
    tree = ast.parse(source)
    print('Parse successful!')
    print(f'AST body has {len(tree.body)} top-level nodes')
except SyntaxError as e:
    print(f'Syntax error: {e}')
