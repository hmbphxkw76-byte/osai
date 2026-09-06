"""扫描所有Python文件，找出UTF-8 mojibake编码问题"""
import pathlib

ROOT = pathlib.Path(r'd:\文档\GitHub\osai\pyrit-mini')
files = list(ROOT.rglob('*.py'))

corrupted = []
for f in files:
    try:
        data = f.read_bytes()
        text = data.decode('utf-8')
        # 检查 mojibake 特征
        if any(c in text for c in ['鈥', '鏀', '浣', '鍗', '鍘', '鎵', '鏈', '澶', '闂', '妯', '鎴', '绉', '绗', '濉', '涔', '涓', '韬', '楂', '柟', '瀹', '杩', '涓', '鐢', '鍒', '镐', '粠', '鐨', 'ュ', 'ョ', 'ヰ', 'ヱ', 'ヲ', 'ン', 'ヵ', 'ヶ', 'ヷ', 'ヸ', 'ヹ', 'ヺ', '・', 'ー', 'ヽ', 'ヾ']):
            corrupted.append(f)
            print(f"[乱码] {f.relative_to(ROOT)}")
    except UnicodeDecodeError:
        print(f"[非UTF8] {f.relative_to(ROOT)}")

print(f"\n共找到 {len(corrupted)}/{len(files)} 个疑似乱码文件")
