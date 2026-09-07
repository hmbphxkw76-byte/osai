#!/usr/bin/env python3
"""Remove all Chinese characters and replace special Unicode with ASCII."""
import os
import re

# Unicode to ASCII replacements for special characters
REPLACEMENTS = {
    # Dashes and hyphens
    '\u2010': '-',  # hyphen
    '\u2011': '-',  # non-breaking hyphen
    '\u2012': '-',  # figure dash
    '\u2013': '-',  # en dash
    '\u2014': '-',  # em dash
    '\u2015': '-',  # horizontal bar
    
    # Arrows
    '\u2190': '<-',  # left arrow
    '\u2191': '^',   # up arrow
    '\u2192': '->',  # right arrow
    '\u2193': 'v',   # down arrow
    '\u2194': '<->', # left right arrow
    '\u21d2': '=>',  # rightwards double arrow
    
    # Circled numbers
    '\u2460': '(1)',  '\u2461': '(2)',  '\u2462': '(3)',  '\u2463': '(4)',
    '\u2464': '(5)',  '\u2465': '(6)',  '\u2466': '(7)',  '\u2467': '(8)',
    '\u2468': '(9)',  '\u2469': '(10)', '\u246a': '(11)', '\u246b': '(12)',
    '\u246c': '(13)', '\u246d': '(14)', '\u246e': '(15)', '\u246f': '(16)',
    
    # Bullets
    '\u2022': '*',   # bullet
    '\u2023': '>',   # triangular bullet
    '\u2043': '-',   # hyphen bullet
    '\u204c': '>',   # black leftwards bullet
    '\u204d': '<',   # black rightwards bullet
    '\u2219': '*',   # bullet operator
    '\u25b6': '>',   # play button
    '\u25c0': '<',   # reverse button
    
    # Quotes
    '\u2018': "'",   # left single quote
    '\u2019': "'",   # right single quote
    '\u201a': ",",   # single low-9 quotation mark
    '\u201b': "'",   # single high-reversed-9 quotation mark
    '\u201c': '"',   # left double quote
    '\u201d': '"',   # right double quote
    '\u201e': ',,',  # double low-9 quotation mark
    '\u201f': '"',   # double high-reversed-9 quotation mark
    '\u2032': "'",   # prime
    '\u2033': '"',   # double prime
    
    # Math symbols
    '\u00b0': 'deg', # degree
    '\u00b1': '+/-', # plus-minus
    '\u00d7': 'x',   # multiplication
    '\u00f7': '/',   # division
    '\u2260': '!=',  # not equal
    '\u2264': '<=',  # less than or equal
    '\u2265': '>=',  # greater than or equal
    '\u221e': 'inf', # infinity
    '\u2211': 'Sum', # summation
    '\u220f': 'Prod', # product
    '\u222b': 'int', # integral
    
    # Box drawing and blocks
    '\u2500': '-',  # box drawings light horizontal
    '\u2502': '|',  # box drawings light vertical
    '\u250c': '+',  # box drawings light down and right
    '\u2510': '+',  # box drawings light down and left
    '\u2514': '+',  # box drawings light up and right
    '\u2518': '+',  # box drawings light up and left
    '\u251c': '+',  # box drawings light vertical and right
    '\u2524': '+',  # box drawings light vertical and left
    '\u252c': '+',  # box drawings light down and horizontal
    '\u2534': '+',  # box drawings light up and horizontal
    '\u253c': '+',  # box drawings light vertical and horizontal
    '\u2550': '=',  # box drawings double horizontal
    '\u2551': '||', # box drawings double vertical
    '\u2554': '+',  # box drawings double down and right
    '\u2557': '+',  # box drawings double down and left
    '\u255a': '+',  # box drawings double up and right
    '\u255d': '+',  # box drawings double up and left
    '\u2560': '+',  # box drawings double vertical and right
    '\u2563': '+',  # box drawings double vertical and left
    '\u2566': '+',  # box drawings double down and horizontal
    '\u2569': '+',  # box drawings double up and horizontal
    '\u256c': '+',  # box drawings double vertical and horizontal
    '\u2580': '#',  # upper half block
    '\u2584': '#',  # lower half block
    '\u2588': '#',  # full block
    '\u258c': '#',  # left half block
    '\u2590': '#',  # right half block
    '\u2591': '#',  # light shade
    '\u2592': '#',  # medium shade
    '\u2593': '#',  # dark shade
    '\u25a0': '#',  # black square
    '\u25b2': '^',  # black up-pointing triangle
    '\u25bc': 'v',  # black down-pointing triangle
    '\u25c6': '*',  # black diamond
    '\u25cf': '*',  # black circle
    '\u25cb': 'o',  # white circle
    '\u25d8': '*',  # inverse bullet
    '\u25e6': 'o',  # white bullet
    
    # Misc symbols
    '\u00a7': 'Sec',  # section sign
    '\u00a9': '(c)',  # copyright
    '\u00ae': '(r)',  # registered
    '\u2122': '(tm)', # trademark
    '\u2020': '+',    # dagger
    '\u2021': '++',   # double dagger
    '\u2026': '...',  # ellipsis
    '\u203a': '>',    # single right-pointing angle quotation mark
    '\u2039': '<',    # single left-pointing angle quotation mark
    '\u00ab': '<<',   # left-pointing double angle quotation mark
    '\u00bb': '>>',   # right-pointing double angle quotation mark
    '\u00b4': "'",    # acute accent
    '\u0060': "'",    # grave accent
    '\u00b7': '*',    # middle dot
    '\u2030': '%o',   # per mille
    '\u2031': '%oo',  # per ten thousand
    
    # CJK Symbols and Punctuation (common ones)
    '\u3000': ' ',  # ideographic space
    '\u3001': ',',  # ideographic comma
    '\u3002': '.',  # ideographic full stop
    '\u3008': '<',  # left angle bracket
    '\u3009': '>',  # right angle bracket
    '\u300a': '<<', # left double angle bracket
    '\u300b': '>>', # right double angle bracket
    '\u300c': '"',  # left corner bracket
    '\u300d': '"',  # right corner bracket
    '\u300e': '"',  # left white corner bracket
    '\u300f': '"',  # right white corner bracket
    '\u3010': '[',  # left black lenticular bracket
    '\u3011': ']',  # right black lenticular bracket
    '\u3014': '[',  # left tortoise shell bracket
    '\u3015': ']',  # right tortoise shell bracket
    '\u3016': '[[', # left white lenticular bracket
    '\u3017': ']]', # right white lenticular bracket
    '\u3018': '[[', # left white tortoise shell bracket
    '\u3019': ']]', # right white tortoise shell bracket
    '\u301a': '[',  # left white square bracket
    '\u301b': ']',  # right white square bracket
    '\u301d': '"',  # reversed double prime quotation mark
    '\u301e': '"',  # double prime quotation mark
    '\u301f': '"',  # low double prime quotation mark
    '\u3030': '~',  # wavy dash
    '\u303d': '/',  # part alternation mark
    '\u30fb': '*',  # katakana middle dot
    '\u30fc': '-',  # katakana-hiragana prolonged sound mark
    
    # Additional CJK and special characters found in the codebase
    '\u02c9': '-',  # modifier letter macron (ˉ)
    '\ufe40': '"',  # presentation form for vertical left angle bracket (﹀)
    '\ufe3d': '[',  # presentation form for vertical left double angle bracket (︽)
    '\ufe41': '[',  # presentation form for vertical left corner bracket (﹁)
    '\u20ac': 'EUR', # euro sign (€)
    '\u2512': '+',  # box drawings down heavy and right light (┒)
    '\u2516': '+',  # box drawings down heavy and left light (┖)
    '\u2543': '+',  # box drawings heavy double dash vertical and right (╃)
    '\u2544': '+',  # box drawings heavy double dash horizontal and down (╄)
    '\u2589': '#',  # left seven eighths block (▉)
    '\u0101': 'a',  # latin small letter a with macron (ā)
    '\u2103': 'C',  # degree celsius (℃)
    '\u0412': 'B',  # cyrillic capital letter ve (В)
    '\u0442': 't',  # cyrillic small letter te (т)
    '\u0443': 'u',  # cyrillic small letter u (у)
    '\u0444': 'f',  # cyrillic small letter ef (ф)
    '\u0445': 'x',  # cyrillic small letter ha (х)
    '\u0446': 'ts', # cyrillic small letter tse (ц)
    '\u3047': 'e',  # hiragana small e (ぇ)
    '\u30a8': 'E',  # katakana letter e (エ)
    '\u3051': 'ke', # hiragana letter ke (け)
    '\u305a': 'zu', # hiragana letter zu (ず)
    '\u30e3': 'ya', # katakana small ya (ャ)
    '\u30e4': 'Ya', # katakana letter ya (ヤ)
    '\u3084': 'ya', # hiragana letter ya (や)
    '\u30e5': 'yu', # katakana small yu (ュ)
    '\u30e6': 'Yu', # katakana letter yu (ユ)
    '\u3086': 'yu', # hiragana letter yu (ゆ)
    '\u30e7': 'yo', # katakana small yo (ョ)
    '\u30e8': 'Yo', # katakana letter yo (ヨ)
    '\u3088': 'yo', # hiragana letter yo (よ)
    '\u30e9': 'ra', # katakana letter ra (ラ)
    '\u30a3': 'i',  # katakana small i (ィ)
    '\u30a4': 'I',  # katakana letter i (イ)
    '\u3044': 'i',  # hiragana letter i (い)
    '\u3091': 'we', # hiragana letter we (ゑ)
    '\u3092': 'wo', # hiragana letter wo (を)
    '\u3093': 'n',  # hiragana letter n (ん)
    '\u30fc': '-',  # katakana-hiragana prolonged sound mark (ー)
    '\u3123': 'u',  # bopomofo letter u (ㄣ)
    '\u3124': 'ang', # bopomofo letter ang (ㄤ)
    '\u3125': 'eng', # bopomofo letter eng (ㄥ)
    '\u3126': 'er', # bopomofo letter er (ㄦ)
    '\u3127': 'i',  # bopomofo letter i (ㄧ)
    '\u3128': 'u',  # bopomofo letter u (ㄨ)
    '\u3129': 'iu', # bopomofo letter iu (ㄩ)
    
    # Additional characters found in the codebase
    '\u2248': '~=',  # almost equal to (≈)
    '\u0447': 'ch', # cyrillic small letter che (ч)
    '\u0437': 'z',  # cyrillic small letter ze (з)
    '\u0434': 'd',  # cyrillic small letter de (д)
    '\u043b': 'l',  # cyrillic small letter el (л)
    '\u043c': 'm',  # cyrillic small letter em (м)
    '\u043d': 'n',  # cyrillic small letter en (н)
    '\u043e': 'o',  # cyrillic small letter o (о)
    '\u0440': 'r',  # cyrillic small letter er (р)
    '\u0441': 'c',  # cyrillic small letter es (с)
    '\u0443': 'u',  # cyrillic small letter u (у)
    '\u0445': 'x',  # cyrillic small letter ha (х)
    '\u0446': 'ts', # cyrillic small letter tse (ц)
    '\u0447': 'ch', # cyrillic small letter che (ч)
    '\u0448': 'sh', # cyrillic small letter sha (ш)
    '\u0449': 'sch',# cyrillic small letter shcha (щ)
    '\u044a': '',   # cyrillic small letter hard sign (ъ)
    '\u044b': 'y',  # cyrillic small letter yeru (ы)
    '\u044c': '',   # cyrillic small letter soft sign (ь)
    '\u044d': 'e',  # cyrillic small letter e (э)
    '\u044e': 'yu', # cyrillic small letter yu (ю)
    '\u044f': 'ya', # cyrillic small letter ya (я)
    
    # Private Use Area characters (often used for icons/special fonts)
    '\u00a4': 'X',   # currency sign (¤)
    '\ue004': 'X',   # private use
    '\ue005': 'X',   # private use
    '\ue0a4': 'X',   # private use
    '\ue100': 'X',   # private use
    '\ue101': 'X',   # private use
    '\ue102': 'X',   # private use
    '\ue15d': 'X',   # private use
    '\ue160': 'X',   # private use
    '\ue1ba': 'X',   # private use
    '\ue1bb': 'X',   # private use
    '\ue1bc': 'X',   # private use
    '\ue1be': 'X',   # private use
    '\ue1c0': 'X',   # private use
    '\ue21a': 'X',   # private use
    '\ue21b': 'X',   # private use
    '\ue511': 'X',   # private use
    '\ue569': 'X',   # private use
    '\ue582': 'X',   # private use
    '\ue583': 'X',   # private use
    '\ue63b': 'X',   # private use
    '\ue6eb': 'X',   # private use
    '\ue752': 'X',   # private use
    '\ue044': 'X',   # private use
    '\ue045': 'X',   # private use
    
    # More box drawing and CJK characters
    '\u2541': '+',   # box drawings heavy up and horizontal (╁)
    '\u3089': 'ra',  # hiragana letter ra (ら)
    
    # More box drawing and CJK characters
    '\u2540': '+',   # box drawings heavy down and horizontal (╀)
    '\u2542': '+',   # box drawings heavy vertical and right (╂)
    '\u0415': 'E',   # cyrillic capital letter ie (Е)
    '\u041e': 'O',   # cyrillic capital letter o (О)
    '\u0429': 'Sch', # cyrillic capital letter shcha (Щ)
    '\u3085': 'yu',  # hiragana small yu (ゅ)
    '\ue046': 'X',   # private use
    '\ue048': 'X',   # private use
    '\ue0a2': 'X',   # private use
    '\ue0a6': 'X',   # private use
    '\ue0bc': 'X',   # private use
    '\ue0c1': 'X',   # private use
    '\ue0c7': 'X',   # private use
    '\ue15f': 'X',   # private use
    '\ue161': 'X',   # private use
    '\ue17b': 'X',   # private use
    '\ue187': 'X',   # private use
    '\ue1bd': 'X',   # private use
    '\ue1bf': 'X',   # private use
    '\ue1d7': 'X',   # private use
    '\ue1da': 'X',   # private use
    '\ue1ee': 'X',   # private use
    '\ue1f8': 'X',   # private use
    '\ue21c': 'X',   # private use
    '\ue21e': 'X',   # private use
    '\ue632': 'X',   # private use
    '\ue63f': 'X',   # private use
    '\ue644': 'X',   # private use
    '\ue6ed': 'X',   # private use
    '\ue747': 'X',   # private use
    '\ue750': 'X',   # private use
    
    # More Unicode characters
    '\u1d62': 'i',   # latin subscript small letter i (ᵢ)
    
    # More box drawing and private use characters
    '\u2545': '+',   # box drawings heavy up and left (╅)
    '\ue0ff': 'X',   # private use
    '\ue11c': 'X',   # private use
    '\ue11e': 'X',   # private use
    '\ue120': 'X',   # private use
    '\ue178': 'X',   # private use
    '\ue1f0': 'X',   # private use
    '\ue586': 'X',   # private use
    '\ue597': 'X',   # private use
    '\ue5c6': 'X',   # private use
    '\ue5d7': 'X',   # private use
}

# Chinese character ranges
CJK_RANGES = [
    (0x4e00, 0x9fff),   # CJK Unified Ideographs
    (0x3400, 0x4dbf),   # CJK Unified Ideographs Extension A
    (0xf900, 0xfaff),   # CJK Compatibility Ideographs
    (0x2e80, 0x2eff),   # CJK Radicals Supplement
    (0x31c0, 0x31ef),   # CJK Strokes
    (0x3200, 0x32ff),   # Enclosed CJK Letters and Months
    (0x3300, 0x33ff),   # CJK Compatibility
    (0x2f00, 0x2fdf),   # Kangxi Radicals
    (0x2ff0, 0x2fff),   # Ideographic Description Characters
]

def is_cjk(char):
    """Check if a character is a CJK character."""
    code = ord(char)
    for start, end in CJK_RANGES:
        if start <= code <= end:
            return True
    return False

def fix_content(content):
    """Fix content by replacing special Unicode and removing CJK characters."""
    # First, replace known special characters
    for char, replacement in REPLACEMENTS.items():
        content = content.replace(char, replacement)
    
    # Build regex pattern for CJK characters
    cjk_pattern = '[' + ''.join(f'\\u{start:04x}-\\u{end:04x}' for start, end in CJK_RANGES) + ']'
    
    # Remove CJK characters that are within comments (keep code intact)
    lines = content.split('\n')
    fixed_lines = []
    
    for line in lines:
        # Check if this line is a comment or docstring
        stripped = line.strip()
        
        # For comments, remove CJK characters
        if stripped.startswith('#'):
            # Remove CJK characters from comments
            line = re.sub(cjk_pattern, '', line)
            # Clean up extra spaces
            line = re.sub(r'  +', ' ', line)
            line = re.sub(r'# +', '# ', line)
            fixed_lines.append(line)
        elif '"""' in line or "'''" in line or stripped.startswith('"""') or stripped.startswith("'''"):
            # For docstring lines, remove CJK characters
            line = re.sub(cjk_pattern, '', line)
            line = re.sub(r'  +', ' ', line)
            fixed_lines.append(line)
        elif '#' in line:
            # Line has inline comment
            code_part, comment_part = line.split('#', 1)
            comment_part = re.sub(cjk_pattern, '', comment_part)
            comment_part = re.sub(r'  +', ' ', comment_part)
            fixed_lines.append(code_part + '#' + comment_part)
        else:
            # Code line - check for CJK in strings
            # For now, just keep code lines as-is (strings might contain CJK intentionally)
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def fix_file(filepath):
    """Fix Unicode characters in a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        content = fix_content(content)
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Fix all Python files in the project."""
    fixed = []
    for root, dirs, files in os.walk('.'):
        # Skip hidden directories and __pycache__
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
        
        for filename in files:
            if filename.endswith('.py') and not filename.startswith('_'):
                filepath = os.path.join(root, filename)
                if fix_file(filepath):
                    fixed.append(filepath)
    
    print(f"Fixed {len(fixed)} files:")
    for f in fixed:
        print(f"  {f}")

if __name__ == '__main__':
    main()
