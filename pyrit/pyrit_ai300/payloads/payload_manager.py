"""
AI-300 Framework - Payload Manager
载荷管理器：管理所有 OWASP 标准攻击载荷

数据驱动设计：
- 载荷从 data/ 目录下的 YAML 文件加载
- 支持按 OWASP ID 检索（LLM01-LLM10, ASI01-ASI10）
- 支持 payload_refs 引用解析
- 支持 scope 解析（单个 ID / 分组 / 全部）
- 支持载荷的动态更新和扩展

使用方式：
    manager = PayloadManager()
    manager.load_data_dir("data/")
    payloads = manager.resolve_refs(["owasp:agentic:asi01"])
    refs = manager.get_scope_refs("llm01")
    all_llm = manager.get_scope_refs("llm")
"""

from __future__ import annotations

import logging
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


class PayloadManager:
    """
    攻击载荷管理器

    功能：
    1. 从 data/ 目录加载攻击载荷（owasp/llm, owasp/agentic）
    2. 解析 payload_refs 引用
    3. 按 OWASP ID 检索（LLM01-LLM10, ASI01-ASI10）
    4. 支持 scope 解析（单个 ID / 分组 / 全部）
    5. 与 PyRIT SeedDataset 集成

    使用方式:
        manager = PayloadManager()
        manager.load_data_dir("data/")
        payloads = manager.resolve_refs(["owasp:agentic:asi01"])
        refs = manager.get_scope_refs("llm01")
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
            └── owasp/
                ├── llm/
                │   ├── llm01.yaml
                │   ├── llm01/
                │   │   ├── direct_injection.yaml
                │   │   └── ...
                │   └── ...
                └── agentic/
                    ├── asi01/
                    │   └── goal_hijack.yaml
                    └── ...

        注意: OWASP 目录为唯一真相源，surfaces 由侦察阶段动态生成。

        Args:
            data_dir: data/ 目录路径
        """
        logger.info("\n######## 加载 Payloads 信息 ########")
        self._data_dir = Path(data_dir)
        if not self._data_dir.exists():
            logger.warning("Data directory not found: %s", data_dir)
            return

        # 加载 owasp/ 下的载荷（唯一真相源）
        owasp_dir = self._data_dir / "owasp"
        if owasp_dir.exists():
            for standard_dir in owasp_dir.iterdir():
                if not standard_dir.is_dir():
                    continue
                standard = standard_dir.name  # llm, agentic
                self._index.setdefault("owasp", {})
                self._index["owasp"].setdefault(standard, [])

                # 收集有对应子目录的顶层文件名（无扩展名）
                # 规则：有子目录时，顶层 YAML 不加载（子目录是唯一真相源）
                subdir_names = {
                    d.name for d in standard_dir.iterdir()
                    if d.is_dir() and not d.name.startswith("_")
                }

                # 加载顶层 YAML（如 llm01.yaml）
                # 跳过有对应子目录的文件（子目录是唯一载荷源）
                for yaml_file in sorted(standard_dir.glob("*.yaml")):
                    if yaml_file.stem in subdir_names:
                        logger.debug(
                            "Skipping %s: subdirectory exists (subdirectory is single source of truth)",
                            yaml_file.name,
                        )
                        continue
                    self._load_payload_file(yaml_file, "owasp", standard)

                # 加载子目录中的 YAML（支持多级嵌套，如 llm01/jailbreak/aim.yaml）
                for sub_dir in sorted(standard_dir.iterdir()):
                    if sub_dir.is_dir() and not sub_dir.name.startswith("_"):
                        sub_name = sub_dir.name  # e.g. "llm01"
                        for yaml_file in sorted(sub_dir.rglob("*.yaml")):
                            # 计算相对路径作为 subcategory
                            # 如 llm01/jailbreak/aim.yaml → subcategory: "llm01:jailbreak"
                            rel_dir = yaml_file.parent.relative_to(sub_dir)
                            if rel_dir == Path("."):
                                subcat = f"{standard}:{sub_name}"
                            else:
                                subcat = f"{standard}:{sub_name}:{rel_dir.as_posix().replace('/', ':')}"
                            self._load_payload_file(yaml_file, "owasp", subcat)

        total_files = len(self._payload_store)
        total_payloads = sum(len(d["payloads"]) for d in self._payload_store.values())
        logger.info("Loaded %d payload files, %d payloads from %s", total_files, total_payloads, data_dir)

    def _load_payload_file(
        self, file_path: Path, category: str, subcategory: str
    ) -> None:
        """
        加载单个载荷文件

        Args:
            file_path: YAML 文件路径
            category: 顶层类别 (owasp)
            subcategory: 子类别 (llm, agentic, 或 llm:llm01 格式)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "payloads" not in data:
                logger.warning("No payloads in %s, skipping", file_path)
                return

            # 构建引用路径（统一小写）
            # ref_path 始终基于文件名，确保唯一性
            # YAML 中的 id 字段仅作 OWASP ID 元数据，不参与 ref_path 构建
            file_id = file_path.stem.lower()
            subcategory_lower = subcategory.lower()
            ref_path = f"owasp:{subcategory_lower}:{file_id}"

            # 存储（id 字段取自 YAML，用于 OWASP 分类标识）
            self._payload_store[ref_path] = {
                "id": data.get("id", file_id).lower(),
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

        except Exception as e:
            logger.error("Failed to load %s: %s", file_path, str(e))

    def resolve_refs(self, refs: List[str]) -> List[str]:
        """
        解析 payload_refs 为实际载荷列表

        引用格式:
            - "owasp:agentic:asi01"  → data/owasp/agentic/asi01/goal_hijack.yaml
            - "owasp:llm:llm01"     → data/owasp/llm/llm01.yaml
            - "owasp:llm:llm01:direct_injection" → data/owasp/llm/llm01/direct_injection.yaml
            - "text_jailbreak:aim"  → 用 aim 模板渲染（data/owasp/llm/llm01/jailbreak/）
            - "text_jailbreak:random" → 随机模板渲染
            - "text_jailbreak:all"  → 全部模板渲染（穷举）

        Args:
            refs: 引用路径列表

        Returns:
            合并后的载荷列表（去重）
        """
        all_payloads = []
        seen = set()

        def _get_dedup_key(payload):
            """获取去重键（支持字符串和字典格式）"""
            if isinstance(payload, str):
                return payload
            elif isinstance(payload, dict):
                return payload.get("payload", str(payload))
            return str(payload)

        for ref in refs:
            ref = ref.strip().lower()

            # 处理 text_jailbreak: 前缀
            if ref.startswith("text_jailbreak:"):
                rendered = self._resolve_text_jailbreak(ref)
                for payload in rendered:
                    key = _get_dedup_key(payload)
                    if key not in seen:
                        seen.add(key)
                        all_payloads.append(payload)
                continue

            if ref in self._payload_store:
                for payload in self._payload_store[ref]["payloads"]:
                    key = _get_dedup_key(payload)
                    if key not in seen:
                        seen.add(key)
                        all_payloads.append(payload)
            else:
                logger.warning("Payload ref not found: %s", ref)

        return all_payloads

    def _resolve_text_jailbreak(self, ref: str) -> List[str]:
        """
        解析 text_jailbreak: 前缀的引用

        模板来源: data/owasp/llm/llm01/jailbreak/ 目录下的统一格式 YAML 文件
        渲染方式: 将模板 payload 中的 {goal} 占位符替换为实际攻击载荷

        格式:
            - "text_jailbreak:aim"   → 用 aim 模板渲染所有已加载载荷
            - "text_jailbreak:random" → 用随机模板渲染
            - "text_jailbreak:all"   → 用所有模板渲染（穷举）

        Args:
            ref: 引用路径

        Returns:
            渲染后的载荷列表
        """
        # 提取模板名
        parts = ref.split(":", 1)
        if len(parts) < 2:
            logger.warning("Invalid text_jailbreak ref: %s", ref)
            return []

        template_spec = parts[1].strip()

        # 获取基础载荷（从所有已加载的 payload_store 中收集）
        # 支持两种格式: 字符串列表 或 字典列表（需提取 payload 字段）
        base_payloads = []
        for data in self._payload_store.values():
            for entry in data.get("payloads", []):
                if isinstance(entry, dict):
                    base_payloads.append(entry.get("payload", ""))
                elif isinstance(entry, str):
                    base_payloads.append(entry)

        if not base_payloads:
            logger.warning("No base payloads loaded for text_jailbreak rendering")
            return []

        # 收集所有 jailbreak 模板（technique: jailbreak_template）
        jb_templates = []
        for ref_path, data in self._payload_store.items():
            for payload_entry in data.get("payloads", []):
                if isinstance(payload_entry, dict) and payload_entry.get("technique") == "jailbreak_template":
                    jb_templates.append(payload_entry)

        if not jb_templates:
            logger.warning("No jailbreak templates loaded, skipping ref: %s", ref)
            return []

        results = []

        if template_spec == "random":
            # 随机模板：每个载荷用随机模板渲染
            for prompt in base_payloads:
                template = random.choice(jb_templates)
                rendered = template["payload"].replace("{goal}", prompt)
                results.append(rendered)
        elif template_spec == "all":
            # 全模板：每个载荷用所有模板渲染
            for prompt in base_payloads:
                for template in jb_templates:
                    rendered = template["payload"].replace("{goal}", prompt)
                    results.append(rendered)
        else:
            # 指定模板：template_spec 是模板名（如 "aim" 或 "aim.yaml" 或 "dan_1"）
            template_name = template_spec.replace(".yaml", "").lower().replace("_", " ")
            matched = None
            for template in jb_templates:
                # 标准化比较：忽略大小写、下划线/空格差异
                tname = template.get("name", "").lower().replace("_", " ")
                if tname == template_name:
                    matched = template
                    break
            if not matched:
                logger.warning("Jailbreak template '%s' not found", template_spec)
                return []

            for prompt in base_payloads:
                rendered = matched["payload"].replace("{goal}", prompt)
                results.append(rendered)

        logger.info("Jailbreak templates rendered %d payloads from %d base payloads (template: %s)",
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
            category: 类别 (owasp)
            subcategory: 子类别 (llm, agentic, 或 llm:llm01 格式)

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

    def get_scope_refs(self, scope: str) -> List[str]:
        """
        解析 OWASP scope 为 ref 路径列表

        scope 支持四种粒度：
        - 单个文件 (ref_path): "owasp:llm:llm04:rag_poison"
        - 单个 OWASP ID: "llm01", "asi01"
        - 按标准分组: "llm" (所有 LLM Top 10), "agentic" (所有 Agentic Top 10)
        - 全部: "all"

        Args:
            scope: OWASP scope 字符串

        Returns:
            匹配的 ref 路径列表
        """
        scope = scope.lower().strip()

        # 全部
        if scope == "all":
            return self.get_all_refs()

        # 按标准分组: llm, agentic
        if scope in ("llm", "agentic"):
            return [ref for ref in self.get_all_refs() if f":{scope}:" in ref]

        # 单文件模式: ref_path 格式（含两个以上冒号，如 owasp:llm:llm04:rag_poison）
        if scope.count(":") >= 2:
            # 精确匹配 ref_path
            if scope in self._payload_store:
                return [scope]
            # 前缀匹配（如 owasp:llm:llm04 匹配 llm04 下所有文件）
            prefix_matches = [ref for ref in self.get_all_refs() if ref.startswith(f"{scope}:")]
            if prefix_matches:
                return prefix_matches
            logger.warning("Payload ref not found: %s", scope)
            return []

        # 单个 OWASP ID: llm01, asi01
        # 先尝试精确匹配（如 owasp:llm:llm01）
        exact_matches = [ref for ref in self.get_all_refs() if ref.endswith(f":{scope}")]
        if exact_matches:
            return exact_matches

        # 模糊匹配（如 llm01 匹配 llm01 下的所有子文件）
        return [ref for ref in self.get_all_refs() if f":{scope}" in ref]

    def get_payloads_by_owasp(self, owasp_id: str) -> List[str]:
        """
        按 OWASP ID 获取载荷

        Args:
            owasp_id: OWASP ID (如 "LLM01", "ASI01")

        Returns:
            匹配的载荷列表
        """
        return self.resolve_refs(self.get_scope_refs(owasp_id))

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


