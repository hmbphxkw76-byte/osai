"""
===============================================================================
PyRIT 侦查阶段 #1 — MODELS_RECON: 模型列表枚举
===============================================================================
目标: 硅基流动 Qwen3-8B
端点: GET /v1/models
目的: 摸清可用模型清单，识别攻击面
===============================================================================
"""
import httpx
import json
from collections import Counter

URL = "https://api.siliconflow.cn/v1/models"
HEADERS = {
    "Authorization": "Bearer sk-uqmmxbngygdknukbdzjevoevsgyiptgvgtvxwugfalxchccl",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
    "Accept": "application/json",
}

print("=" * 70)
print("🔎 [PHASE 1/3] MODELS_RECON — GET /v1/models")
print("=" * 70)

resp = httpx.get(URL, headers=HEADERS, timeout=30)
print(f"HTTP {resp.status_code} | Content-Type: {resp.headers.get('content-type', '?')} "
      f"| Length: {len(resp.content)} bytes")

data = resp.json()

if "data" in data:
    models = data["data"]
    print(f"\n📊 共发现 {len(models)} 个可用模型\n")

    # 按前缀分组
    prefixes = Counter()
    for m in models:
        mid = m["id"]
        prefix = mid.split("/")[0] if "/" in mid else mid.split("-")[0]
        prefixes[prefix] += 1

    print("  按厂商/系列分布:")
    for prefix, count in prefixes.most_common(15):
        print(f"    {prefix:25s} {count:3d} 个")

    # ── 重点目标 ──
    print(f"\n  🎯 目标模型 (Qwen3 系列):")
    qwen3 = [m for m in models if "qwen3" in m["id"].lower() or "Qwen3" in m["id"]]
    if qwen3:
        for m in qwen3:
            print(f"    ✅ {m['id']:55s} type={m.get('type', '?')}")
    else:
        qwen = [m for m in models if "qwen" in m["id"].lower()]
        for m in qwen[:10]:
            print(f"    ✅ {m['id']:55s} type={m.get('type', '?')}")

    # ── 类型分布 ──
    types = Counter(m.get("type", "unknown") for m in models)
    print(f"\n  📈 模型类型分布:")
    for t, c in types.most_common():
        print(f"    {t:20s} {c:3d} 个")

    # 保存完整清单
    out_path = "outputs/recon_models_siliconflow.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\n  💾 完整清单已保存: {out_path}")

    # ── 攻击面评估 ──
    print(f"\n  ⚔️  攻击面评估:")
    print(f"     - 模型总数: {len(models)}")
    print(f"     - 厂商数量: {len(prefixes)}")
    qwen_count = sum(1 for m in models if "qwen" in m["id"].lower())
    deepseek_count = sum(1 for m in models if "deepseek" in m["id"].lower())
    llama_count = sum(1 for m in models if "llama" in m["id"].lower() or "Llama" in m["id"])
    chat_count = sum(1 for m in models if m.get("type") == "chat" or "chat" in m.get("type", ""))
    text_count = sum(1 for m in models if m.get("type") == "text" or "text" in m.get("type", ""))
    emb_count = sum(1 for m in models if "embed" in m.get("type", "").lower())
    print(f"     - Qwen 系列: {qwen_count}  个")
    print(f"     - DeepSeek 系列: {deepseek_count}  个")
    print(f"     - Llama 系列: {llama_count}  个")
    print(f"     - Chat 类: {chat_count}  个")
    print(f"     - Text 类: {text_count}  个")
    print(f"     - Embedding 类: {emb_count}  个")
else:
    print(f"\n⚠️ 响应格式异常(截断): {json.dumps(data, ensure_ascii=False)[:500]}")

print()
