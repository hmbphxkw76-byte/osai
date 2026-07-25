# data/native/ — AI-300 考试原生数据集

本目录存放 OffSec AI-300 考试专用的内置数据集。

## 目录用途

| 目录 | 数据来源 | 说明 |
|------|---------|------|
| `data/owasp/` | OWASP 官方标准 | LLM Top 10 + Agentic AI Top 10 通用标准 |
| `data/native/` | OffSec AI-300 考试 | 考试专用内置数据集（本目录） |
| `data/custom/` | 用户编写 | 用户自定义载荷 |
| `data/burp/` | Burp Suite | 原始 HTTP 请求模板 |

## 使用方式

考试原生数据集由系统自动加载，无需额外配置。
如需筛选，可通过 CLI 参数或函数参数指定。

## 扩展

在此目录下按考试需求组织子目录，例如：
```
data/native/
├── exam_templates/     # 考试模板
├── scenarios/          # 场景数据
└── target_profiles/    # 目标画像
```
