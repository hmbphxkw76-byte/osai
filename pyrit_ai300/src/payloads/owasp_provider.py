"""
OWASP Local Dataset Provider
=============================

将 OWASP 本地 YAML 数据集注册为 PyRIT 1.0.0 SeedDatasetProvider，
使 OWASP 数据既能通过当前管道执行，又能被 PyRIT 的
SeedDatasetProvider.get_all_providers() 体系发现和消费。

架构设计：
- 继承 PyRIT 原生 _LocalDatasetLoader，复用其 fetch_dataset_async / dataset_name 逻辑
- 仅覆写 _parse_metadata_async，在原生基础上增加 OWASP 特有的 tags/size/modalities 推断
- 使用 __init_subclass__ 自动注册（通过 should_register = True）
- 动态创建子类，为每个 YAML 文件绑定特定路径

PyRIT 1.0.0 原生 _LocalDatasetLoader 已实现：
- SeedDataset.from_yaml_file() 加载（含 is_jinja_template 信任标记）
- dataset_name 从 YAML dataset_name/name/filename 推断
- 基础 metadata 从 YAML 顶层字段提取

本模块的增量价值：
- 从 harm_categories 推断 tags（safety + harm_category + owasp 类型）
- 从 seeds 数量推断 size（tiny/small/medium/large）
- 从 data_type 推断 modalities
- 注入 owasp_id 到 metadata
"""

import logging
from pathlib import Path
from typing import Any, ClassVar, Optional

# 使用最短可用路径导入（pyrit.datasets 导出 SeedDatasetMetadata/SeedDatasetLoadTime）
from pyrit.datasets import SeedDatasetMetadata, SeedDatasetLoadTime
# _LocalDatasetLoader 是内部类，从 local 子包导入（已在 __init__ 中导出）
from pyrit.datasets.seed_datasets.local import _LocalDatasetLoader

logger = logging.getLogger(__name__)


# ============================================================
# OWASP 本地数据集 Provider（继承 PyRIT 原生 _LocalDatasetLoader）
# ============================================================


class _OwaspLocalDatasetProvider(_LocalDatasetLoader):
    """
    单个 OWASP YAML 文件的 PyRIT SeedDatasetProvider

    继承 _LocalDatasetLoader，复用其 fetch_dataset_async 和 dataset_name 逻辑，
    仅覆写 _parse_metadata_async 增加 OWASP 特有的元数据推断。
    """

    should_register = False  # 基类不自动注册，由工厂方法动态创建子类

    # OWASP 特有元数据类属性（供 _parse_metadata_async 读取）
    tags: ClassVar[Optional[frozenset[str]]] = None
    size: ClassVar[Optional[str]] = None
    modalities: ClassVar[Optional[frozenset[str]]] = None
    source_type: ClassVar[Optional[str]] = "local"
    load_time: ClassVar[Any] = SeedDatasetLoadTime.FAST

    def __init__(self, *, file_path: Path, owasp_id: str = "", framework: str = "llm") -> None:
        """
        初始化 OWASP 本地数据集 Provider

        Args:
            file_path: YAML 文件路径
            owasp_id: OWASP ID（如 "LLM01"）
            framework: 框架名称（"llm" 或 "agentic"）
        """
        super().__init__(file_path=file_path)
        self._owasp_id = owasp_id
        self._framework = framework

    async def _parse_metadata_async(self) -> SeedDatasetMetadata | None:
        """
        从类属性和 YAML 文件提取元数据并转换为 SeedDatasetMetadata

        优先使用类属性（动态创建子类时设置的推断值），
        回退到原生 _LocalDatasetLoader 的 YAML 顶层字段提取。

        Returns:
            SeedDatasetMetadata | None: 解析的元数据
        """
        from dataclasses import fields as dc_fields

        valid_fields = [f.name for f in dc_fields(SeedDatasetMetadata)]

        # 优先从类属性读取（动态子类在注册时推断的值）
        provider_class = type(self)
        raw: dict[str, Any] = {}
        for key in valid_fields:
            value = getattr(provider_class, key, None)
            if value is not None:
                raw[key] = value

        # 补充从 YAML 文件读取顶层元数据（类属性未覆盖的字段）
        try:
            import yaml
            with open(self.file_path, encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f)
            if isinstance(yaml_data, dict):
                for key in valid_fields:
                    if key in raw:
                        continue  # 类属性优先
                    val = yaml_data.get(key)
                    if val is not None:
                        raw[key] = val
        except Exception as e:
            logger.warning(f"Could not read YAML metadata from {self.file_path}: {e}")

        if not raw:
            return None

        coerced = SeedDatasetMetadata._coerce_metadata_values(raw_metadata=raw)
        result = SeedDatasetMetadata(**coerced)
        SeedDatasetMetadata._validate_singular_fields(metadata=result)
        return result


# ============================================================
# 自动发现与注册
# ============================================================

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_OWASP_DATA_DIR = _PROJECT_ROOT / "data" / "owasp"


def _infer_metadata(yaml_file: Path, owasp_id: str) -> dict[str, Any]:
    """
    从 YAML 文件内容推断 OWASP 特有的元数据

    Args:
        yaml_file: YAML 文件路径
        owasp_id: OWASP ID

    Returns:
        包含 tags, size, modalities 的字典
    """
    tags: Optional[frozenset[str]] = None
    size: Optional[str] = None
    modalities: Optional[frozenset[str]] = frozenset({"text"})

    try:
        import yaml
        with open(yaml_file, encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f) or {}

        # 从 harm_categories 推断 tags
        harm_cats = yaml_data.get("harm_categories", [])
        inferred_tags = {"safety"}
        for hc in harm_cats:
            inferred_tags.add(hc)

        # 基于 owasp_id 推断额外 tags
        oid_upper = owasp_id.upper()
        if oid_upper.startswith("ASI"):
            inferred_tags.add("agent_security")
        if oid_upper.startswith("LLM"):
            inferred_tags.add("prompt_injection")

        tags = frozenset(inferred_tags)

        # 从 seeds 数量推断 size
        seeds_count = len(yaml_data.get("seeds", []))
        if seeds_count < 10:
            size = "tiny"
        elif seeds_count < 100:
            size = "small"
        elif seeds_count < 500:
            size = "medium"
        else:
            size = "large"

        # 从 data_type 推断 modalities
        data_type = yaml_data.get("data_type", "text")
        if data_type == "image_path":
            modalities = frozenset({"text", "image"})
        elif data_type == "audio_path":
            modalities = frozenset({"text", "audio"})
        elif data_type == "video_path":
            modalities = frozenset({"text", "video"})

    except Exception:
        tags = frozenset({"safety", "prompt_injection", "agent_security"})
        size = "small"
        modalities = frozenset({"text"})

    return {
        "tags": tags,
        "size": size,
        "modalities": modalities,
    }


def _register_owasp_datasets() -> None:
    """
    自动发现并注册所有 OWASP YAML 数据集

    扫描 data/owasp/llm/ 和 data/owasp/agentic/ 目录，
    为每个 YAML 文件动态创建 _OwaspLocalDatasetProvider 子类并注册。
    """
    frameworks = ["llm", "agentic"]
    registry_files: dict[str, dict] = {}

    for framework in frameworks:
        registry_path = _OWASP_DATA_DIR / framework / "_registry.yaml"
        if registry_path.exists():
            try:
                import yaml
                with open(registry_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                registry_files[framework] = data.get("categories", {})
            except Exception as e:
                logger.warning(f"Could not load registry for {framework}: {e}")
                registry_files[framework] = {}
        else:
            registry_files[framework] = {}

    for framework in frameworks:
        framework_dir = _OWASP_DATA_DIR / framework
        if not framework_dir.exists():
            continue

        for category_dir in sorted(framework_dir.iterdir()):
            if not category_dir.is_dir():
                continue

            category_name = category_dir.name
            meta = registry_files.get(framework, {}).get(category_name, {})
            owasp_id = meta.get("owasp_id", category_name.upper())

            for yaml_file in sorted(category_dir.glob("*.yaml")):
                if yaml_file.name.startswith("_"):
                    continue

                try:
                    class_name = (
                        f"OwaspDataset_{framework}_{category_name}_{yaml_file.stem}"
                        .replace("-", "_")
                        .replace(" ", "_")
                    )

                    # 推断元数据
                    inferred = _infer_metadata(yaml_file, owasp_id)

                    def _make_init(fp: Path, oid: str, fw: str):
                        def __init__(self) -> None:
                            super(self.__class__, self).__init__(
                                file_path=fp, owasp_id=oid, framework=fw
                            )
                        return __init__

                    type(
                        class_name,
                        (_OwaspLocalDatasetProvider,),
                        {
                            "__init__": _make_init(yaml_file, owasp_id, framework),
                            "should_register": True,
                            "__module__": __name__,
                            "tags": inferred["tags"],
                            "size": inferred["size"],
                            "modalities": inferred["modalities"],
                            "source_type": "local",
                            "load_time": SeedDatasetLoadTime.FAST,
                        },
                    )

                    logger.debug(f"Registered OWASP dataset provider: {class_name} for {yaml_file.name}")
                except Exception as e:
                    logger.warning(f"Failed to register OWASP dataset {yaml_file}: {e}")


# 执行注册
_register_owasp_datasets()
