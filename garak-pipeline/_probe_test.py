"""验证 buff 加载（避免 emoji 打印）"""
import sys

from garak import _config, _plugins

if not _config.loaded:
    _config.load_base_config()
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
for b in ["buffs.encoding.Base64", "buffs.encoding.CharCode", "buffs.lowercase.Lowercase"]:
    try:
        inst = _plugins.load_plugin(b, config_root=_config)
        print("OK", b, "->", type(inst).__name__)
    except Exception as e:
        print("FAIL", b, "->", str(e)[:120])
