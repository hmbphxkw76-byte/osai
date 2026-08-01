"""Stage 1: 目标侦察 (Reconnaissance) — garak 攻击面枚举

职责：
    1. 测试目标 API 连通性 (openai SDK)
    2. garak 攻击面枚举 (recon_garak) — OWASP LLM Top10 为纲
    3. 模型模态侦察（文本/多模态能力 + 多生成支持）
    4. 生成目标画像

输出产物（阶段目录名固定为 01_recon，文件名含 _date_time_ 标识运行批次，统一落在 outputs/ 下）：
    outputs/01_recon/target_profile_{run_id}.json
    outputs/01_recon/connectivity_test_{run_id}.json
    outputs/01_recon/probe_candidates_{run_id}.json           # 全量活跃探针（含 modality）
    outputs/01_recon/probe_candidates_filtered_{run_id}.json  # 模态裁剪后探针（Stage3 消费）
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, ClassVar

from pipeline.recon_garak import (
    classify_probes,
    classify_probes_dual,
    enumerate_garak_probes,
    filter_probes_by_modality,
)

logger = logging.getLogger(__name__)


class Stage1Recon:
    """Stage 1: 目标侦察 — garak 攻击面枚举与模态侦察"""

    STAGE_NAME = "01_recon"
    STAGE_INDEX = 1

    def __init__(
        self,
        target: dict[str, str],
        mode: str,
        artifacts_dir: Path,
        state: dict[str, Any] | None = None,
        run_id: str = "",
    ) -> None:
        self.target = target
        self.mode = mode
        self.run_id = run_id or time.strftime("%Y%m%d_%H%M")
        # 阶段目录名固定（如 01_recon），不加 _date_time；批次区分由文件名后缀承载
        dir_name = self.STAGE_NAME
        self.out_dir = Path(artifacts_dir) / dir_name
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.state = state or {}
        self._artifacts_root = Path(artifacts_dir)

    # ------------------------------------------------------------------
    # 兼容委托（旧测试 + 编排层语义）：实际逻辑在 recon_garak
    # ------------------------------------------------------------------

    @staticmethod
    def _enumerate_active_probes() -> list[dict[str, Any]]:
        return enumerate_garak_probes()

    @staticmethod
    def _classify_probes(probes: list[dict[str, Any]]) -> dict[str, list[str]]:
        return classify_probes(probes)

    def run(self) -> dict[str, Any]:
        logger.info("Stage 1: Recon started for %s @ %s",
                    self.target["model"], self.target["endpoint"])
        try:
            # Step 1: 连通性测试
            print("   🔗 测试目标连通性...", end=" ", flush=True)
            connectivity = self._test_connectivity()
            self._save_json("connectivity_test.json", connectivity)
            if not connectivity["ok"]:
                print(f"❌ {connectivity['error']}")
                return {"success": False, "error": connectivity["error"], "state": {}}
            print(f"✅ (延迟 {connectivity['latency_ms']}ms)")

            # Step 2: garak 攻击面枚举（OWASP 为纲）
            print("   📋 枚举 garak 活跃 Probe...", end=" ", flush=True)
            active_probes = self._enumerate_active_probes()
            print(f"找到 {len(active_probes)} 个活跃 Probe")

            # Step 2.5: 模型模态侦察（先于分类，用于模态感知过滤）
            print("   🔍 侦察模型模态...", end=" ", flush=True)
            model_modality = self._detect_model_modality()
            modality_in = sorted(model_modality.get("in", {"text"}))
            modality_out = sorted(model_modality.get("out", {"text"}))
            print(f"输入: {'+'.join(modality_in)}, 输出: {'+'.join(modality_out)}")

            # Step 2.6: 模态感知过滤 — 裁剪目标不支持模态的探针
            # (text-only 模型自动剔除 image/audio 探针，平衡效率与效果)
            print("   🎚️  模态感知裁剪...", end=" ", flush=True)
            modality_filter = filter_probes_by_modality(active_probes, modality_in)
            kept_probes = modality_filter["kept"]
            dropped = modality_filter["dropped"]
            if dropped:
                print(f"保留 {modality_filter['kept_count']} 个, "
                      f"剔除 {modality_filter['dropped_count']} 个 (目标无对应模态)")
                for d in dropped[:8]:
                    print(f"      ⏩ {d['name']} [{','.join(d['required_modality'])}]")
                if len(dropped) > 8:
                    print(f"      ... 其余 {len(dropped) - 8} 个已剔除")
            else:
                print(f"全部 {modality_filter['kept_count']} 个探针兼容")

            # Step 2.7: 分类（基于过滤后的探针集）
            attack_surface = classify_probes(kept_probes, modality_filter)
            attack_surface_dual = classify_probes_dual(kept_probes, modality_filter)
            for category, probes in attack_surface.get("owasp", {}).items():
                if probes:
                    print(f"      {category}: {len(probes)} 个")
            ai300_topic = attack_surface.get("ai300_topic", {})
            if any(ai300_topic.values()):
                extra = sum(len(v) for v in ai300_topic.values())
                print(f"      [AI-300 专题标签] {extra} 个探针附加归类")

            # Step 3: 目标画像
            supports_mg = model_modality.get("supports_multiple_generations", None)
            target_profile = {
                "endpoint": self.target["endpoint"],
                "model": self.target["model"],
                "model_modality": {
                    "in": modality_in,
                    "out": modality_out,
                },
                "supports_multiple_generations": supports_mg,
                "connectivity": connectivity,
                "attack_surface": attack_surface,
                "attack_surface_dual": attack_surface_dual,
                "modality_filter": {
                    "target_modality_in": modality_filter["target_modality"],
                    "total_active_probes": len(active_probes),
                    "kept_count": modality_filter["kept_count"],
                    "dropped_count": modality_filter["dropped_count"],
                    "dropped": dropped,
                },
                "total_active_probes": len(active_probes),
                "kept_probes_count": modality_filter["kept_count"],
                "scan_mode": self.mode,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save_json("target_profile.json", target_profile)
            self._save_json("probe_candidates.json", active_probes)
            # 过滤后的探针集（Stage3 执行消费此文件，而非全量）
            self._save_json("probe_candidates_filtered.json", kept_probes)

            return {
                "success": True,
                "error": None,
                "state": {
                    "target_profile": target_profile,
                    "active_probes": active_probes,
                    "kept_probes": kept_probes,
                    "modality_filter": modality_filter,
                    "connectivity": connectivity,
                    "model_modality": model_modality,
                    "supports_multiple_generations": supports_mg,
                },
            }
        except Exception as exc:
            logger.exception("Stage 1 Recon failed")
            return {"success": False, "error": str(exc), "state": {}}

    # ------------------------------------------------------------------
    # Step 1: connectivity (garak 调用)
    # ------------------------------------------------------------------

    def _test_connectivity(self) -> dict[str, Any]:
        import openai

        client = openai.OpenAI(
            base_url=self.target["endpoint"],
            api_key=self.target["api_key"],
            timeout=10,
        )
        start = time.time()
        try:
            models = client.models.list()
            latency = round((time.time() - start) * 1000)
            return {
                "ok": True,
                "latency_ms": latency,
                "available_models": [m.id for m in models.data[:10]],
            }
        except openai.AuthenticationError:
            return {"ok": False, "error": "API Key 认证失败 (401 Unauthorized)"}
        except openai.APIConnectionError:
            return {"ok": False, "error": "无法连接到目标端点 (Connection Error)"}
        except openai.APIStatusError as exc:
            return {"ok": False, "error": f"API 返回错误: HTTP {exc.status_code}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Step 2.5: model modality (保留，garak 调用)
    # ------------------------------------------------------------------

    _MULTIMODAL_PATTERNS: ClassVar[dict] = {
        "image": (
            "vision", "vl", "vlm", "visual", "multimodal", "mm",
            "gpt-4o", "gpt-4v", "gpt-4-turbo",
            "claude-3", "gemini", "gemma-3",
            "llava", "qwen-vl", "internvl", "cogvlm",
            "pixtral", "phi-3.5", "phi-4-multimodal",
        ),
        "audio": (
            "whisper", "tts", "audio", "speech",
            "gpt-4o-audio", "gemini-1.5-pro",
        ),
    }

    def _detect_model_modality(self) -> dict[str, Any]:
        modality: dict[str, Any] = {"in": {"text"}, "out": {"text"}}
        try:
            from garak import _config, _plugins
            _config.load_base_config()
            _config.plugins.target_type = "openai.OpenAICompatible"
            _config.plugins.target_name = self.target["model"]
            gen = _plugins.load_plugin(
                "generators.openai.OpenAICompatible", config_root=_config
            )
            if hasattr(gen, "modality") and gen.modality:
                modality["in"] = set(gen.modality.get("in", {"text"}))
                modality["out"] = set(gen.modality.get("out", {"text"}))
            if hasattr(gen, "supports_multiple_generations"):
                modality["supports_multiple_generations"] = bool(
                    gen.supports_multiple_generations
                )
        except Exception:
            logger.debug("Could not load generator modality, using heuristic")

        model_name_lower = self.target["model"].lower()
        for mod_type, patterns in self._MULTIMODAL_PATTERNS.items():
            if mod_type in modality["in"]:
                continue
            if any(pat in model_name_lower for pat in patterns):
                modality["in"].add(mod_type)
        return modality

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _ts_name(self, filename: str) -> str:
        if not self.run_id:
            return filename
        stem, ext = Path(filename).stem, Path(filename).suffix
        return f"{stem}_{self.run_id}{ext}"

    def _save_json(self, filename: str, data: Any) -> None:
        path = self.out_dir / self._ts_name(filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        logger.debug("Saved %s", path)
