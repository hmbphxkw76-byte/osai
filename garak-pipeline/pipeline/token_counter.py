"""R2: 实际 token 精确计费 — 基于 tiktoken 的事后核算

对齐 L5：顶级红队平台需提供精确的 token 消耗统计，
而非仅依赖经验估算。本模块在扫描完成后从 garak 报告中
提取所有 prompt/response 文本，用 tiktoken 精确计数。

产物：outputs/04_analysis/token_usage_{run_id}.json
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _count_tokens_tiktoken(text: str, model: str = "gpt-4") -> int:
    """使用 tiktoken 精确计数 token

    :param text: 待计数文本
    :param model: 模型名（影响 tokenizer 选择）
    :returns: token 数量；tiktoken 不可用时回退到字符数 / 4
    """
    try:
        import tiktoken
        try:
            enc = tiktoken.encoding_for_model(model)
        except KeyError:
            enc = tiktoken.get_encoding("cl100k_base")  # 通用回退
        return len(enc.encode(text))
    except ImportError:
        # tiktoken 不可用时回退到经验估算：1 token ≈ 4 字符
        return max(1, len(text) // 4)
    except Exception:
        return max(1, len(text) // 4)


def count_tokens_from_report(
    report_path: str,
    model: str = "gpt-4",
) -> dict[str, Any]:
    """从 garak 报告 JSONL 中提取所有 prompt/response 文本并计数

    :param report_path: garak .report.jsonl 路径
    :param model: 目标模型名（影响 tokenizer）
    :returns: token 使用统计 dict
    """
    input_tokens = 0
    output_tokens = 0
    total_attempts = 0
    per_probe: dict[str, dict] = {}

    try:
        with open(report_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if entry.get("entry_type") != "attempt":
                    continue

                total_attempts += 1
                probe = entry.get("probe", "unknown")
                prompt = entry.get("prompt", "")
                outputs = entry.get("outputs", [])

                # 计数 input tokens (prompt)
                in_tok = _count_tokens_tiktoken(prompt, model)
                input_tokens += in_tok

                # 计数 output tokens (responses)
                out_tok = 0
                for output in outputs:
                    if isinstance(output, str):
                        out_tok += _count_tokens_tiktoken(output, model)
                    elif isinstance(output, dict):
                        text = output.get("text", "") or str(output.get("content", ""))
                        out_tok += _count_tokens_tiktoken(text, model)
                output_tokens += out_tok

                # 按 probe 聚合
                if probe not in per_probe:
                    per_probe[probe] = {
                        "attempts": 0,
                        "input_tokens": 0,
                        "output_tokens": 0,
                    }
                per_probe[probe]["attempts"] += 1
                per_probe[probe]["input_tokens"] += in_tok
                per_probe[probe]["output_tokens"] += out_tok

    except FileNotFoundError:
        logger.warning("token 计费：报告文件不存在 %s", report_path)
        return {"error": "report not found"}
    except Exception as exc:
        logger.warning("token 计费失败: %s", exc)
        return {"error": str(exc)}

    total_tokens = input_tokens + output_tokens

    # 估算成本（基于 GPT-4 定价，可配置覆盖）
    # input: $0.03/1K tokens, output: $0.06/1K tokens (GPT-4 标准价)
    estimated_cost_usd = round(
        (input_tokens / 1000 * 0.03) + (output_tokens / 1000 * 0.06), 4
    )

    return {
        "model": model,
        "total_attempts": total_attempts,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "estimated_cost_usd": estimated_cost_usd,
        "pricing_note": "基于 GPT-4 标准定价 ($0.03/1K input, $0.06/1K output)，实际价格以 API 供应商为准",
        "per_probe": {
            p: {
                "attempts": v["attempts"],
                "input_tokens": v["input_tokens"],
                "output_tokens": v["output_tokens"],
                "total_tokens": v["input_tokens"] + v["output_tokens"],
            }
            for p, v in sorted(per_probe.items())
        },
    }


def save_token_usage(
    token_data: dict[str, Any],
    artifacts_dir: str,
    run_id: str,
) -> str | None:
    """保存 token 使用报告

    :returns: 文件路径，失败返回 None
    """
    if "error" in token_data:
        return None
    out_dir = Path(artifacts_dir) / "04_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"token_usage_{run_id}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(token_data, f, ensure_ascii=False, indent=2)
    logger.info("token 使用报告已保存: %s (total=%d tokens, ~$%.4f)",
                path, token_data.get("total_tokens", 0), token_data.get("estimated_cost_usd", 0))
    return str(path)
