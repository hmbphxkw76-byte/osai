"""备份整个项目"""
import shutil, datetime

src = r'd:\文档\GitHub\osai\pyrit-mini'
ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
dst = rf'd:\文档\GitHub\osai\pyrit-mini-backup-{ts}'
shutil.copytree(src, dst, dirs_exist_ok=True)
print(f'备份完成: {dst}')
