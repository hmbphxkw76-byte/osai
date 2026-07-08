# ============================================================
# promptfoo 自定义 Provider - file:// 方式调用
# 用途: 仅用于 promptfoo YAML 无法覆盖的场景
# 场景: 需要动态签名、Token 自动刷新、复杂认证流程
# 大多数场景直接用 YAML 的 https target 即可
# ============================================================
# 使用方式（在 promptfooconfig.yaml 中）:
#   targets:
#     - id: 'file://send_redteam.py'
#       label: 'my-target'
# ============================================================

import requests

# ============================================================
# 【测试修改点1】目标 API URL
# ============================================================
TARGET_URL = "https://example.com/generate"

# ============================================================
# 【测试修改点2】请求体字段名
# ============================================================
BODY_FIELD = "myPrompt"

# ============================================================
# 【测试修改点3】认证配置（如不需要，保持为空字典）
# ============================================================
AUTH_HEADERS = {}
# Bearer Token:  AUTH_HEADERS = {"Authorization": "Bearer YOUR_TOKEN"}
# API Key:       AUTH_HEADERS = {"X-API-Key": "YOUR_KEY"}
# Basic Auth:    AUTH_HEADERS = {"Authorization": "Basic base64(user:pass)"}

# ============================================================
# 【测试修改点4】响应中输出字段的提取路径（元组形式）
# 格式: ("json_key",)  或  ("choices", 0, "message", "content")
# ============================================================
OUTPUT_PATH = ("output",)  # {"output": "文本"}
# 其他常见格式:
# OUTPUT_PATH = ("response",)                        # {"response": "文本"}
# OUTPUT_PATH = ("choices", 0, "message", "content") # OpenAI 格式
# OUTPUT_PATH = ("data", "text")                     # {"data": {"text": "..."}}
# OUTPUT_PATH = None                                  # 纯文本响应


def _deep_get(data, path):
    """按路径从嵌套字典/列表中提取值"""
    if path is None:
        return None
    for key in path:
        if isinstance(data, dict):
            data = data.get(key)
        elif isinstance(data, list) and isinstance(key, int):
            data = data[key] if key < len(data) else None
        else:
            return None
        if data is None:
            return None
    return data


# ============================================================
# 核心入口 - promptfoo 调用此函数
# 函数名固定为 call_api，参数签名固定
# ============================================================
def call_api(prompt, options, context):
    """
    prompt:  promptfoo 生成的对抗性测试输入
    options: promptfoo 传递的选项
    context: 测试上下文 (vars, test 等)
    返回:    {"output": "模型响应文本"}
    """
    body = {BODY_FIELD: prompt}
    headers = {"Content-Type": "application/json", **AUTH_HEADERS}

    try:
        resp = requests.post(TARGET_URL, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        output = _deep_get(data, OUTPUT_PATH)
        if output is None and OUTPUT_PATH is not None:
            output = str(data)
        return {"output": output or ""}
    except Exception as e:
        return {"output": "", "error": str(e)}


# ============================================================
# 本地调试入口（promptfoo 调用时不执行）
# ============================================================
if __name__ == "__main__":
    result = call_api("test prompt", {}, {})
    print(result)
