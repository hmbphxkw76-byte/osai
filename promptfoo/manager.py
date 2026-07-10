"""
===============================================================================
Promptfoo 提示词管理器 — Prompt 管理 + 红队评测集成
===============================================================================
职责:
  - 管理攻击提示词库（加载、版本控制、标签分类）
  - 将选定提示词导出为 Promptfoo 可消费的 YAML 配置
  - 通过 subprocess 调用 promptfoo eval 执行提示词评估
  - 解析 Promptfoo 输出结果，回传 PyRIT 消费

模板目录结构 (promptfoo/templates/):
  injection/      Prompt 注入攻击
  jailbreak/      越狱攻击
  xpia/           跨提示词间接攻击
  rag/            RAG 攻击
  agent_abuse/    Agent 滥用
  extraction/     模型提取

架构位置: L3c (RAG 攻击调用) + L5 (统一评估)
依赖方向: → promptfoo/templates (下行), → promptfoo/schema (内部)
===============================================================================
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from rich.console import Console
from rich.table import Table

from promptfoo.schema import PromptEntry, PromptfooEvalResult

console = Console()


class PromptfooManager:
    """提示词管理中心 — 管理攻击用提示词的加载、筛选、导出与评估。

    工作流:
      1. 按风险等级/OWASP 类别筛选提示词
      2. 导出为 Promptfoo YAML 配置
      3. 执行 promptfoo eval
      4. 解析结果 → PyRIT 消费

    模板目录:
      默认从 promptfoo/templates/ 加载 YAML 提示词，按攻击类别组织在子目录中。
    """

    def __init__(self, payload_dir: Optional[str] = None):
        if payload_dir:
            self._payload_dir = Path(payload_dir)
        else:
            self._payload_dir = Path(__file__).parent / "templates"
        self._prompt_cache: dict[str, list[PromptEntry]] = {}
        self._load_all_prompts()

    # ── 加载 ──

    def _load_all_prompts(self):
        """从 templates/ 递归加载所有 YAML 提示词。"""
        if not self._payload_dir.exists():
            return

        for yaml_file in sorted(self._payload_dir.rglob("*.yaml")):
            if yaml_file.name == "manifest.yaml":
                continue
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                prompts = self._parse_prompt_yaml(data, yaml_file.stem)
                if prompts:
                    self._prompt_cache[yaml_file.stem] = prompts
            except Exception:
                pass

    def _parse_prompt_yaml(self, data: dict, source: str) -> list[PromptEntry]:
        """解析 YAML 中的提示词结构。"""
        prompts = []
        for item in data.get("payloads", data.get("prompts", data.get("cases", []))):
            if not isinstance(item, dict):
                continue
            prompts.append(PromptEntry(
                id=item.get("id", f"{source}_{len(prompts)}"),
                objective=item.get("objective", item.get("description", "")),
                criterion=item.get("criterion", ""),
                content=item.get("content", item.get("prompt", "")),
                category=item.get("category", source),
                owasp_mapping=item.get("owasp", ""),
                risk_level=item.get("risk_level", "medium"),
                tags=item.get("tags", []),
                source=source,
            ))
        return prompts

    # ── 筛选 ──

    def get_all_prompts(self) -> list[PromptEntry]:
        """获取所有已加载提示词。"""
        all_prompts = []
        for prompts in self._prompt_cache.values():
            all_prompts.extend(prompts)
        return all_prompts

    def filter_prompts(
        self,
        risk_levels: Optional[list[str]] = None,
        owasp_categories: Optional[list[str]] = None,
        categories: Optional[list[str]] = None,
    ) -> list[PromptEntry]:
        """按条件筛选提示词。

        Args:
            risk_levels: 风险等级列表, e.g. ["critical", "high"]
            owasp_categories: OWASP 类别列表, e.g. ["LLM01", "LLM02"]
            categories: 攻击类别列表, e.g. ["jailbreak", "injection", "xpia"]
        """
        results = []
        for entry in self.get_all_prompts():
            if risk_levels and entry.risk_level not in risk_levels:
                continue
            if owasp_categories and entry.owasp_mapping not in owasp_categories:
                continue
            if categories and entry.category not in categories:
                continue
            results.append(entry)
        return results

    # ── 导出 ──

    def export_to_yaml(
        self,
        prompts: list[PromptEntry],
        output_path: Optional[str] = None,
    ) -> str:
        """将筛选后的提示词导出为 Promptfoo 兼容的 YAML 配置。

        输出格式:
          prompts:
            - id: ...
              label: ...
              raw: ...
        """
        config = {
            "description": "PyRIT Red Team — 攻击提示词集",
            "prompts": [],
            "providers": [],
            "tests": [],
        }

        for i, entry in enumerate(prompts):
            config["prompts"].append({
                "id": entry.id,
                "label": f"{entry.category}_{i}",
                "raw": entry.content,
            })
            config["tests"].append({
                "vars": {"prompt": entry.content},
                "assert": [{"type": "contains-any", "value": []}],
                "metadata": {
                    "owasp": entry.owasp_mapping,
                    "category": entry.category,
                    "risk_level": entry.risk_level,
                },
            })

        output_path = output_path or str(
            Path(tempfile.gettempdir()) / f"promptfoo_config_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.yaml"
        )
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

        return output_path

    # ── 执行评估 ──

    def run_eval(
        self,
        config_path: str,
        timeout: int = 120,
    ) -> PromptfooEvalResult:
        """执行 promptfoo eval 并解析输出。

        Args:
            config_path: Promptfoo YAML 配置文件路径
            timeout: 超时秒数
        """
        result = PromptfooEvalResult(success=False)
        output_dir = os.path.join(tempfile.gettempdir(), f"promptfoo_output_{os.getpid()}")
        os.makedirs(output_dir, exist_ok=True)

        try:
            cmd = [
                "npx", "promptfoo", "eval",
                "--config", config_path,
                "--output", output_dir,
                "--no-table",
                "--max-concurrency", "3",
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=os.path.dirname(config_path),
            )

            if proc.returncode != 0:
                result.errors.append(proc.stderr)
                return result

            json_files = sorted(Path(output_dir).glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
            if json_files:
                with open(json_files[0], "r", encoding="utf-8") as f:
                    output_data = json.load(f)
                results_table = output_data.get("results", {})
                result.total_tests = len(results_table.get("table", {}).get("body", []))
                result.raw_results = output_data.get("results", {}).get("prompts", [])
                result.output_path = str(json_files[0])

                stats = output_data.get("results", {}).get("stats", {})
                result.passed = stats.get("successes", 0)
                result.failed = stats.get("failures", 0)
                result.asr_score = result.failed / max(result.total_tests, 1)

            result.success = True

        except subprocess.TimeoutExpired:
            result.errors.append(f"Promptfoo eval 超时 ({timeout}s)")
        except FileNotFoundError:
            result.errors.append("Promptfoo 未安装: npm install -g promptfoo")
        except Exception as e:
            result.errors.append(str(e))

        return result

    # ── 展示 ──

    def display_prompt_table(self, prompts: list[PromptEntry]):
        """在终端以表格形式展示提示词列表。"""
        if not prompts:
            console.print("[yellow]  ⚠️ 未找到匹配的提示词[/yellow]")
            return

        table = Table(title=f"提示词列表 ({len(prompts)} 条)")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("分类", style="yellow")
        table.add_column("风险", style="red")
        table.add_column("OWASP", style="magenta")
        table.add_column("目标", style="white")

        for p in prompts:
            risk_style = {
                "critical": "[bold red]",
                "high": "[red]",
                "medium": "[yellow]",
                "low": "[dim]",
            }.get(p.risk_level, "")
            table.add_row(
                p.id,
                p.category,
                f"{risk_style}{p.risk_level}[/]",
                p.owasp_mapping or "-",
                p.objective[:60] + ("..." if len(p.objective) > 60 else ""),
            )

        console.print(table)


__all__ = ["PromptfooManager"]
