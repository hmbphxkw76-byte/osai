# data/burp/ — Burp Suite HTTP 请求模板

本目录存放用于 HTTP 原始请求攻击的模板文件（`http_raw` / `http_api` Target 类型）。

## 文件说明

| 文件 | 说明 |
|------|------|
| `sample_request.txt` | 标准 OpenAI Chat Completions 请求模板 |
| `openai_compatible_request.txt` | OpenAI 兼容端点请求模板（Ollama/vLLM 等） |

## 使用方式

1. 复制模板文件，修改 `Host` 和 `Authorization` 为实际值
2. 通过 `http_raw` Target 类型加载（PyRIT HTTPTarget）
3. 请求体中的 `{PROMPT}` 占位符会被攻击载荷自动替换

## 与 Burp Suite 集成

这些模板可直接导入 Burp Suite Intruder：
- 替换 `{PROMPT}` 为 Intruder payload 标记
- 设置 payload 类型为 PyRIT 生成的攻击载荷
