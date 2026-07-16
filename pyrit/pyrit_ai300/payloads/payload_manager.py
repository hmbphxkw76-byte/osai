"""
AI-300 Framework - Payload Manager
载荷管理器：管理所有 AI-300 考试攻击载荷

数据驱动设计：
- 载荷从 data/ 目录下的 YAML 文件加载
- 支持按 OWASP 标准、攻击面维度检索
- 支持 payload_refs 引用解析
- 支持载荷的动态更新和扩展

使用方式：
    manager = PayloadManager()
    manager.load_data_dir("data/")
    payloads = manager.resolve_refs(["owasp:agentic:asi01", "by_surface:agent"])
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


class PayloadManager:
    """
    攻击载荷管理器

    功能：
    1. 从 data/ 目录加载攻击载荷（owasp/llm, owasp/agentic, by_surface）
    2. 解析 payload_refs 引用
    3. 按 OWASP 标准/攻击面维度检索
    4. 与 PyRIT SeedDataset 集成

    使用方式：
        manager = PayloadManager()
        manager.load_data_dir("data/")
        payloads = manager.resolve_refs(["owasp:agentic:asi01"])
    """

    def __init__(self):
        """初始化载荷管理器"""
        # 存储结构: {ref_path: {id, name, severity, payloads, ...}}
        self._payload_store: Dict[str, Dict[str, Any]] = {}
        # 按类别索引: {category: {subcategory: [ref_paths]}}
        self._index: Dict[str, Dict[str, List[str]]] = {}
        self._data_dir: Optional[Path] = None

    def load_data_dir(self, data_dir: str) -> None:
        """
        从 data/ 目录加载所有载荷文件

        目录结构:
            data/
            ├── owasp/
            │   ├── llm/
            │   │   ├── llm01.yaml
            │   │   └── ...
            │   └── agentic/
            │       ├── asi01.yaml
            │       └── ...
            └── by_surface/
                ├── agent.yaml
                ├── mcp.yaml
                ├── embedding.yaml
                └── rag.yaml

        Args:
            data_dir: data/ 目录路径
        """
        self._data_dir = Path(data_dir)
        if not self._data_dir.exists():
            logger.warning("Data directory not found: %s", data_dir)
            return

        # 加载 owasp/ 下的载荷
        owasp_dir = self._data_dir / "owasp"
        if owasp_dir.exists():
            for standard_dir in owasp_dir.iterdir():
                if not standard_dir.is_dir():
                    continue
                standard = standard_dir.name  # llm, agentic
                self._index.setdefault("owasp", {})
                self._index["owasp"].setdefault(standard, [])

                for yaml_file in sorted(standard_dir.glob("*.yaml")):
                    self._load_payload_file(yaml_file, "owasp", standard)

        # 加载 by_surface/ 下的载荷
        surface_dir = self._data_dir / "by_surface"
        if surface_dir.exists():
            self._index.setdefault("by_surface", {})
            for yaml_file in sorted(surface_dir.glob("*.yaml")):
                surface_name = yaml_file.stem
                self._index["by_surface"].setdefault(surface_name, [])
                self._load_payload_file(yaml_file, "by_surface", surface_name)

        total = len(self._payload_store)
        logger.info("Loaded %d payload files from %s", total, data_dir)

    def _load_payload_file(
        self, file_path: Path, category: str, subcategory: str
    ) -> None:
        """
        加载单个载荷文件

        Args:
            file_path: YAML 文件路径
            category: 顶层类别 (owasp, by_surface)
            subcategory: 子类别 (llm, agentic, agent, mcp, ...)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "payloads" not in data:
                logger.warning("No payloads in %s, skipping", file_path)
                return

            # 构建引用路径（统一小写）
            file_id = data.get("id", file_path.stem).lower()
            subcategory_lower = subcategory.lower()
            if category == "owasp":
                ref_path = f"owasp:{subcategory_lower}:{file_id}"
            else:
                ref_path = f"by_surface:{file_id}"

            # 存储
            self._payload_store[ref_path] = {
                "id": file_id,
                "ref_path": ref_path,
                "category": category,
                "subcategory": subcategory,
                "name": data.get("name", file_id),
                "severity": data.get("severity", "medium"),
                "description": data.get("description", ""),
                "payloads": data.get("payloads", []),
                "tags": data.get("tags", []),
                "detection_focus": data.get("detection_focus", []),
                "mitigation_principles": data.get("mitigation_principles", []),
                "source_file": str(file_path),
            }

            # 更新索引
            if category not in self._index:
                self._index[category] = {}
            if subcategory not in self._index[category]:
                self._index[category][subcategory] = []
            self._index[category][subcategory].append(ref_path)

            logger.debug("Loaded payload file: %s (%d payloads)", ref_path, len(data.get("payloads", [])))

        except Exception as e:
            logger.error("Failed to load %s: %s", file_path, str(e))

    def resolve_refs(self, refs: List[str]) -> List[str]:
        """
        解析 payload_refs 为实际载荷列表

        引用格式:
            - "owasp:agentic:asi01"  → data/owasp/agentic/asi01.yaml
            - "owasp:llm:llm01"     → data/owasp/llm/llm01.yaml
            - "by_surface:agent"    → data/by_surface/agent.yaml
            - "text_jailbreak:aim"  → PyRIT TextJailBreak 模板渲染
            - "text_jailbreak:random" → 随机模板渲染
            - "text_jailbreak:all"  → 全部模板渲染（穷举）

        Args:
            refs: 引用路径列表

        Returns:
            合并后的载荷列表（去重）
        """
        all_payloads = []
        seen = set()

        for ref in refs:
            ref = ref.strip().lower()

            # 处理 text_jailbreak: 前缀
            if ref.startswith("text_jailbreak:"):
                rendered = self._resolve_text_jailbreak(ref)
                for payload in rendered:
                    if payload not in seen:
                        seen.add(payload)
                        all_payloads.append(payload)
                continue

            if ref in self._payload_store:
                for payload in self._payload_store[ref]["payloads"]:
                    if payload not in seen:
                        seen.add(payload)
                        all_payloads.append(payload)
            else:
                logger.warning("Payload ref not found: %s", ref)

        return all_payloads

    def _resolve_text_jailbreak(self, ref: str) -> List[str]:
        """
        解析 text_jailbreak: 前缀的引用

        格式:
            - "text_jailbreak:aim"   → 用 aim.yaml 模板渲染所有已加载载荷
            - "text_jailbreak:random" → 用随机模板渲染
            - "text_jailbreak:all"   → 用所有模板渲染（穷举）

        Args:
            ref: 引用路径

        Returns:
            渲染后的载荷列表
        """
        from .text_jailbreak_integration import TextJailBreakIntegration

        integration = TextJailBreakIntegration()
        if not integration.available:
            logger.warning("TextJailBreak not available, skipping ref: %s", ref)
            return []

        # 提取模板名
        parts = ref.split(":", 1)
        if len(parts) < 2:
            logger.warning("Invalid text_jailbreak ref: %s", ref)
            return []

        template_spec = parts[1].strip()

        # 获取基础载荷（从所有已加载的 payload_store 中收集）
        base_payloads = []
        for data in self._payload_store.values():
            base_payloads.extend(data.get("payloads", []))

        if not base_payloads:
            logger.warning("No base payloads loaded for text_jailbreak rendering")
            return []

        results = []

        if template_spec == "random":
            # 随机模板：每个载荷用随机模板渲染
            for prompt in base_payloads:
                result = integration.render_random(prompt)
                if result and result.get("rendered"):
                    results.append(result["rendered"])
        elif template_spec == "all":
            # 全模板：每个载荷用所有模板渲染
            for prompt in base_payloads:
                rendered_list = integration.render_all(prompt)
                for item in rendered_list:
                    if item.get("rendered"):
                        results.append(item["rendered"])
        else:
            # 指定模板：template_spec 是模板文件名（如 "aim.yaml" 或 "aim"）
            template_name = template_spec
            if not template_name.endswith(".yaml"):
                template_name += ".yaml"

            for prompt in base_payloads:
                rendered = integration.render_template(template_name, prompt)
                if rendered:
                    results.append(rendered)

        logger.info("TextJailBreak rendered %d payloads from %d base payloads (template: %s)",
                    len(results), len(base_payloads), template_spec)
        return results

    def get_payload_file(self, ref: str) -> Optional[Dict[str, Any]]:
        """
        获取单个载荷文件的完整信息

        Args:
            ref: 引用路径 (如 "owasp:agentic:asi01")

        Returns:
            载荷文件信息字典，未找到返回 None
        """
        return self._payload_store.get(ref)

    def get_payloads_by_category(self, category: str, subcategory: str = None) -> List[str]:
        """
        按类别获取载荷

        Args:
            category: 类别 (owasp, by_surface)
            subcategory: 子类别 (llm, agentic, agent, mcp, ...)

        Returns:
            载荷列表
        """
        if subcategory:
            refs = self._index.get(category, {}).get(subcategory, [])
        else:
            refs = []
            for sub_refs in self._index.get(category, {}).values():
                refs.extend(sub_refs)

        return self.resolve_refs(refs)

    def get_all_refs(self) -> List[str]:
        """获取所有可用的引用路径"""
        return list(self._payload_store.keys())

    def get_index(self) -> Dict[str, Dict[str, List[str]]]:
        """获取索引结构"""
        return self._index

    def list_categories(self) -> List[str]:
        """列出所有顶层类别"""
        return list(self._index.keys())

    def list_subcategories(self, category: str) -> List[str]:
        """列出指定类别的所有子类别"""
        return list(self._index.get(category, {}).keys())

    def get_stats(self) -> Dict[str, Any]:
        """获取载荷统计信息"""
        stats = {
            "total_files": len(self._payload_store),
            "total_payloads": 0,
            "by_category": {},
        }
        for ref, data in self._payload_store.items():
            count = len(data["payloads"])
            stats["total_payloads"] += count
            cat = data["category"]
            subcat = data["subcategory"]
            if cat not in stats["by_category"]:
                stats["by_category"][cat] = {}
            if subcat not in stats["by_category"][cat]:
                stats["by_category"][cat][subcat] = {"files": 0, "payloads": 0}
            stats["by_category"][cat][subcat]["files"] += 1
            stats["by_category"][cat][subcat]["payloads"] += count
        return stats

    # --- 兼容旧接口 ---

    def load_from_yaml(self, config_path: str) -> None:
        """
        从旧版 YAML 配置文件加载载荷（兼容接口）

        用于向后兼容，新代码应使用 load_data_dir()

        Args:
            config_path: YAML 文件路径 (config/catalog/catalog.yaml)
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config file not found: %s", config_path)
            return

        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        if "catalog" in config:
            catalog = config["catalog"]
            for module_name, module_data in catalog.items():
                if not isinstance(module_data, dict):
                    continue
                for attack_name, attack_data in module_data.items():
                    if isinstance(attack_data, dict) and "payloads" in attack_data:
                        ref_path = f"legacy:{module_name}:{attack_name}"
                        self._payload_store[ref_path] = {
                            "id": attack_name,
                            "ref_path": ref_path,
                            "category": "legacy",
                            "subcategory": module_name,
                            "name": attack_data.get("name", attack_name),
                            "severity": attack_data.get("severity", "medium"),
                            "payloads": attack_data["payloads"],
                        }

        logger.info("Loaded legacy payloads from %s", config_path)

    def load_from_json(self, json_path: str) -> None:
        """
        从 JSON 文件加载载荷（兼容接口）

        Args:
            json_path: JSON 文件路径
        """
        path = Path(json_path)
        if not path.exists():
            logger.warning("JSON file not found: %s", json_path)
            return

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for key, payloads in data.items():
            if isinstance(payloads, list):
                self._payload_store[f"json:{key}"] = {
                    "id": key,
                    "ref_path": f"json:{key}",
                    "category": "json",
                    "subcategory": "",
                    "name": key,
                    "payloads": payloads,
                }

        logger.info("Loaded payloads from JSON: %s", json_path)

    def get_payloads(
        self,
        module: str,
        attack: Optional[str] = None,
    ) -> List[str]:
        """
        获取攻击载荷（兼容旧接口）

        Args:
            module: Module 名称 (legacy 格式)
            attack: 攻击类型名称（可选）

        Returns:
            载荷列表
        """
        if attack:
            ref = f"legacy:{module}:{attack}"
            data = self._payload_store.get(ref)
            return data["payloads"] if data else []

        # 返回该 Module 所有载荷
        all_payloads = []
        for ref, data in self._payload_store.items():
            if data.get("subcategory") == module and data.get("category") == "legacy":
                all_payloads.extend(data["payloads"])
        return all_payloads

    def get_all_modules(self) -> List[str]:
        """获取所有 Module 名称（兼容接口）"""
        modules = set()
        for data in self._payload_store.values():
            if data.get("category") == "legacy":
                modules.add(data.get("subcategory", ""))
        return list(modules)

    def get_attacks_for_module(self, module: str) -> List[str]:
        """获取指定 Module 的所有攻击类型（兼容接口）"""
        attacks = []
        for ref, data in self._payload_store.items():
            if data.get("subcategory") == module and data.get("category") == "legacy":
                attacks.append(data.get("id", ""))
        return attacks

    def add_payload(self, module: str, attack: str, payload: str) -> None:
        """
        添加攻击载荷（兼容接口）

        Args:
            module: Module 名称
            attack: 攻击类型
            payload: 载荷内容
        """
        ref = f"legacy:{module}:{attack}"
        if ref not in self._payload_store:
            self._payload_store[ref] = {
                "id": attack,
                "ref_path": ref,
                "category": "legacy",
                "subcategory": module,
                "name": attack,
                "payloads": [],
            }
        self._payload_store[ref]["payloads"].append(payload)
        logger.debug("Added payload for %s/%s", module, attack)

    def get_metadata(self, module: str) -> Dict[str, Any]:
        """获取 Module 元数据（兼容接口）"""
        for data in self._payload_store.values():
            if data.get("subcategory") == module and data.get("category") == "legacy":
                return {
                    "name": data.get("name", module),
                    "severity": data.get("severity", ""),
                }
        return {}

    def to_pyrit_seed_prompts(
        self,
        module: str,
        attack: str,
    ) -> list:
        """
        转换为 PyRIT SeedPrompt 对象（兼容接口）

        Args:
            module: Module 名称
            attack: 攻击类型

        Returns:
            PyRIT SeedPrompt 列表
        """
        try:
            from pyrit.models import SeedPrompt
            payloads = self.get_payloads(module, attack)
            return [
                SeedPrompt(
                    value=prompt,
                    data_type="text",
                    name=f"{module}_{attack}_{i}",
                )
                for i, prompt in enumerate(payloads)
            ]
        except ImportError:
            logger.error("PyRIT not installed")
            return []
