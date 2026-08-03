#!/usr/bin/env python3
# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""种子精简工具 v2 — 模型感知 + 模态感知 + Tier 分层。.

6 步管线:
  1. 跨数据集去重: 字符 3-gram shingling + Jaccard 相似度
  2. 类别均衡: 按 harm category 每类均匀采样
  3. 多样性聚类: TF-IDF + KMeans, 每簇取中心种子
  4. 模型感知 ASR 排序: 根据目标模型名推断 tier → 选择对应 ASR 先验
  5. 模态感知过滤: text / multimodal 模型选择对应种子类型
  6. Tier 分层采样: Tier S/A/B 等比例采样, 确保难度覆盖

设计原则:
  - 攻击成功为王: 优先选取对目标模型历史 ASR 最高的种子
  - 模型感知: 不同模型参数规模 → 不同 ASR 先验 → 不同种子排名
  - 模态感知: 文本模型只选文本种子; 多模态模型选文本+图像种子
  - 周期更新: 每月下载新种子 → 自动执行 6 步管线 → 输出模型专属种子集

学术依据:
  - JailbreakBench (arXiv:2402.01135): 手工筛选 100 个, 类别均衡
  - HarmBench (arXiv:2402.04249): 标准化评估, 模型间 ASR 差异
  - DART (arXiv:2407.06485): 多样性感知红队
  - RAIN (arXiv:2309.07124): 历史成功率排序
  - AutoDAN (arXiv:2310.04451): 遗传算法多样化生成
  - Universal Jailbreak (arXiv:2307.15043): 攻击迁移性

使用方式:
    python scripts/curate_seeds.py                              # 通用精简
    python scripts/curate_seeds.py --model gpt-4o              # GPT-4o 专属
    python scripts/curate_seeds.py --model llama-3-8b --modality text
    python scripts/curate_seeds.py --model gpt-4o --modality multimodal
    python scripts/curate_seeds.py --check                     # 检查状态
    python scripts/curate_seeds.py --list-models               # 列出可用模型先验

> **日期**: 2026-8-2
> **版本**: v2 — 模型感知 + 模态感知 + Tier 分层
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import yaml
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer

# 可选依赖: datasketch (MinHashLSH) + sentence-transformers
try:
    from datasketch import MinHash, MinHashLSH
    _HAS_DATASKETCH = True
except ImportError:
    _HAS_DATASKETCH = False

try:
    from sentence_transformers import SentenceTransformer
    _HAS_ST = True
except ImportError:
    _HAS_ST = False

#: 项目根目录
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: 种子数据目录
_SEED_DIR = _PROJECT_ROOT / "data" / "seed_datasets"

#: 精简后输出目录
_OUTPUT_DIR = _SEED_DIR / "benchmarks"

#: ASR 先验文件
_ASR_PRIORS = _PROJECT_ROOT / "data" / "setting" / "asr_priors.yaml"

#: 模型分级配置
_MODEL_TIERS = _PROJECT_ROOT / "data" / "setting" / "model_tiers.yaml"

#: 默认每类别采样数
_DEFAULT_PER_CATEGORY = 15

#: 去重 Jaccard 相似度阈值
_DEDUP_THRESHOLD = 0.85

#: Tier 分层阈值 (对齐 asr_priors.yaml tier_thresholds)
_TIER_S_THRESHOLD = 0.70
_TIER_A_THRESHOLD = 0.40
_TIER_B_THRESHOLD = 0.15

#: ASR 先验中的模型变体 → 对应 tier 映射 (G1: 9 变体)
_MODEL_VARIANT_TIERS = {
    "gpt_4o": "strong",
    "gpt_4": "strong",
    "gpt_35": "weak",
    "claude_3_5": "strong",
    "llama_3_1": "moderate",
    "gemini_1_5": "strong",
    "mistral_large": "moderate",
    "qwen_2_5": "moderate",
    "deepseek_v3": "moderate",
}


# ============================================================
# 数据加载
# ============================================================


def _load_seed_file(path: Path) -> list[dict[str, Any]]:
    """加载单个 .prompt YAML 文件, 返回种子列表。."""
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    seeds = data.get("seeds", [])
    ds_name = data.get("dataset_name", path.stem)
    data_type = data.get("data_type", "text")
    result: list[dict[str, Any]] = []
    for seed in seeds:
        value = seed.get("value", "")
        metadata = seed.get("metadata", {}) or {}
        category = (
            metadata.get("SemanticCategory")
            or metadata.get("jbb_category")
            or metadata.get("category")
            or metadata.get("harm_categories")
            or "unknown"
        )
        # 提取种子模态: text / image / audio / video
        seed_data_type = metadata.get("data_type", data_type)
        modality = "text"
        if "image" in str(seed_data_type).lower() or "image" in str(value).lower()[:50]:
            modality = "image"
        elif "audio" in str(seed_data_type).lower():
            modality = "audio"
        result.append(
            {
                "value": value,
                "dataset_name": ds_name,
                "category": category,
                "modality": modality,
                "metadata": metadata,
                "source_file": str(path),
            }
        )
    return result


def load_all_seeds() -> list[dict[str, Any]]:
    """加载所有种子数据集 (benchmarks + owasp + cve + custom)。."""
    all_seeds: list[dict[str, Any]] = []
    for subdir in ("benchmarks", "owasp", "cve", "custom"):
        d = _SEED_DIR / subdir
        if d.exists():
            for f in sorted(d.glob("*.prompt")):
                all_seeds.extend(_load_seed_file(f))
    return all_seeds


def _normalize_text(text: str) -> str:
    """归一化文本: 小写 + 去标点 + 去多余空格。."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _shingles(text: str, k: int = 3) -> set[str]:
    """生成字符 k-gram shingle 集合。."""
    text = _normalize_text(text)
    if len(text) < k:
        return {text}
    return {text[i : i + k] for i in range(len(text) - k + 1)}


def _jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    """计算两个集合的 Jaccard 相似度。."""
    if not set_a and not set_b:
        return 1.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def _cross_language_dedup(seeds: list[dict[str, Any]], threshold: float = 0.85) -> list[dict[str, Any]]:
    """P9: 跨语言去重 — 用 multilingual 嵌入检测不同语言但语义相同的种子.

    学术依据: paraphrase-multilingual-MiniLM-L12-v2 支持多语言语义匹配。
    仅在 datasketch 检测到候选重复对时才调用 (降低开销)。
    """
    if not _HAS_ST or len(seeds) < 2:
        return seeds

    model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
    texts = [s["value"] for s in seeds]
    embeddings = model.encode(texts, show_progress_bar=False)

    kept_indices: list[int] = [0]
    for i in range(1, len(seeds)):
        is_dup = False
        for j in kept_indices:
            sim = float(embeddings[i] @ embeddings[j])
            if sim >= threshold:
                is_dup = True
                break
        if not is_dup:
            kept_indices.append(i)

    return [seeds[i] for i in kept_indices]


# ============================================================
# Step 1: 跨数据集去重
# ============================================================


def dedup_seeds(seeds: list[dict[str, Any]], threshold: float = _DEDUP_THRESHOLD) -> list[dict[str, Any]]:
    """跨数据集去重: 优先使用 MinHashLSH (O(n)), 回退到字符 shingling (O(n2))."""
    print(f"\n  [Step 1] 跨数据集去重 (Jaccard threshold={threshold})")
    print(f"    输入: {len(seeds)} 个种子")

    if _HAS_DATASKETCH and len(seeds) > 200:
        print("    引擎: MinHashLSH (datasketch, O(n))")
        return _dedup_minhash_lsh(seeds, threshold)
    else:
        engine = "字符 shingling (O(n2))"
        if _HAS_DATASKETCH:
            engine += " [种子数 <= 200, 无需 LSH]"
        print(f"    引擎: {engine}")
        return _dedup_shingling(seeds, threshold)


def _dedup_minhash_lsh(seeds: list[dict[str, Any]], threshold: float) -> list[dict[str, Any]]:
    """使用 MinHashLSH 进行近似去重 (O(n) 时间复杂度)."""
    lsh = MinHashLSH(threshold=threshold, num_perm=128)
    kept: list[dict[str, Any]] = []
    removed = 0

    for i, seed in enumerate(seeds):
        mh = MinHash(num_perm=128)
        for shingle in _shingles(seed["value"]):
            mh.update(shingle.encode("utf-8"))
        result = lsh.query(mh)
        if result:
            removed += 1
        else:
            lsh.insert(f"seed_{i}", mh)
            kept.append(seed)

    pct = removed / len(seeds) * 100 if seeds else 0.0
    print(f"    去重: 移除 {removed} 个近义种子")
    print(f"    输出: {len(kept)} 个种子 (压缩 {pct:.1f}%)")
    return kept


def _dedup_shingling(seeds: list[dict[str, Any]], threshold: float) -> list[dict[str, Any]]:
    """使用字符 shingling + Jaccard 相似度去重 (O(n2) 时间复杂度)."""
    shingle_cache = [_shingles(s["value"]) for s in seeds]
    kept: list[dict[str, Any]] = []
    kept_shingles: list[set[str]] = []
    removed = 0

    for i, seed in enumerate(seeds):
        is_dup = False
        for existing_sh in kept_shingles:
            if _jaccard_similarity(shingle_cache[i], existing_sh) >= threshold:
                removed += 1
                is_dup = True
                break
        if not is_dup:
            kept.append(seed)
            kept_shingles.append(shingle_cache[i])

    pct = removed / len(seeds) * 100 if seeds else 0.0
    print(f"    去重: 移除 {removed} 个近义种子")
    print(f"    输出: {len(kept)} 个种子 (压缩 {pct:.1f}%)")
    return kept


# ============================================================
# Step 2: 类别均衡采样
# ============================================================


def category_balanced_sample(
    seeds: list[dict[str, Any]],
    per_category: int = _DEFAULT_PER_CATEGORY,
    asr_data: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """按 harm category 均衡采样, 每类取 per_category 个.

    P10: 自适应类别均衡 — ASR 低的类别（难攻击）分配更多种子,
    ASR 高的类别（易攻击）减少种子。总量保持不变。
    学术依据: HarmBench (arXiv:2402.04249) 类别间 ASR 差异 10%-80%。
    """
    print(f"\n  [Step 2] 类别均衡采样 (基础每类 {per_category} 个)")

    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in seeds:
        by_category[s["category"]].append(s)

    print(f"    类别数: {len(by_category)}")

    # P10: 自适应调整 — 难类多分配
    cat_multipliers: dict[str, float] = {}
    if asr_data and asr_data.get("priors"):
        # 从 ASR 先验计算每个类别的平均 ASR
        category_tech_map = {
            "chemical_biological": ["red_teaming", "crescendo"],
            "cybercrime_intrusion": ["red_teaming", "tap"],
            "illegal": ["crescendo", "pair"],
            "harassment_bullying": ["red_teaming", "pair"],
            "misinformation_disinformation": ["many_shot", "red_teaming"],
            "copyright": ["many_shot", "red_teaming"],
            "harmful": ["crescendo", "pair"],
            "Disinformation": ["many_shot", "red_teaming"],
            "Violence": ["crescendo", "tap"],
            "Privacy": ["pair", "red_teaming"],
            "Sexual content": ["crescendo", "pair"],
            "Malware/Hacking": ["red_teaming", "tap"],
        }
        priors = asr_data.get("priors", [])
        tech_asr: dict[str, float] = {}
        for p in priors:
            tech = p.get("technique", "")
            vals = [v for k, v in p.items() if k.startswith(("gpt", "claude", "llama"))]
            if vals:
                tech_asr[tech] = sum(vals) / len(vals)
        global_avg = sum(tech_asr.values()) / len(tech_asr) if tech_asr else 0.3

        for cat in by_category:
            techs = category_tech_map.get(cat, ["crescendo", "red_teaming"])
            cat_asr = sum(tech_asr.get(t, global_avg) for t in techs) / len(techs)
            # ASR 低 → 倍数 > 1 (多分配); ASR 高 → 倍数 < 1 (少分配)
            multiplier = max(0.5, min(2.0, global_avg / cat_asr)) if cat_asr > 0 else 1.0
            cat_multipliers[cat] = multiplier

    for _cat, items in sorted(by_category.items()):
        mult = cat_multipliers.get(_cat, 1.0)
        adjusted_n = min(int(per_category * mult), len(items))
        print(f"      {_cat}: {len(items)} -> {adjusted_n} (x{mult:.1f})")

    result: list[dict[str, Any]] = []
    for _cat, items in sorted(by_category.items()):
        mult = cat_multipliers.get(_cat, 1.0)
        n = min(int(per_category * mult), len(items))
        if n >= len(items):
            result.extend(items)
        else:
            step = len(items) / n
            indices = [int(i * step) for i in range(n)]
            result.extend(items[idx] for idx in indices)

    print(f"    输出: {len(result)} 个种子")
    return result


# ============================================================
# Step 3: 多样性聚类
# ============================================================


def diversity_cluster(seeds: list[dict[str, Any]], n_clusters: int = 0) -> list[dict[str, Any]]:
    """多样性聚类: 优先使用 sentence-transformers 嵌入, 回退到 TF-IDF.

    P5: 按模态分组聚类 — text 和 image 种子分别聚类,
    确保多模态场景下图像种子不被文本种子淹没.
    """
    if len(seeds) <= 5:
        return seeds

    if n_clusters <= 0:
        # P11: Silhouette 最优 k — 遍历 k 候选, 选轮廓系数最高
        n_clusters = _find_optimal_k(seeds, max_k=min(len(seeds) // 3, 50))

    # P5: 按模态分组
    by_modality: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in seeds:
        by_modality[s["modality"]].append(s)

    if len(by_modality) <= 1:
        # 单模态: 直接聚类
        if _HAS_ST:
            print(f"\n  [Step 3] 多样性聚类 (sentence-transformers + KMeans, k={n_clusters})")
            return _cluster_with_embeddings(seeds, n_clusters)
        else:
            print(f"\n  [Step 3] 多样性聚类 (TF-IDF + KMeans, k={n_clusters})")
            return _cluster_with_tfidf(seeds, n_clusters)

    # P5: 多模态 — 每个模态独立聚类
    print(f"\n  [Step 3] 多样性聚类 (按模态分组, {len(by_modality)} 模态)")
    all_results: list[dict[str, Any]] = []
    for mod, mod_seeds in sorted(by_modality.items()):
        mod_clusters = max(1, min(n_clusters // len(by_modality), len(mod_seeds)))
        if _HAS_ST:
            print(f"    [{mod}] k={mod_clusters}")
            all_results.extend(_cluster_with_embeddings(mod_seeds, mod_clusters))
        else:
            print(f"    [{mod}] k={mod_clusters} (TF-IDF)")
            all_results.extend(_cluster_with_tfidf(mod_seeds, mod_clusters))

    print(f"    聚类完成: {len(all_results)} 个种子 ({len(by_modality)} 模态)")
    return all_results


def _find_optimal_k(seeds: list[dict[str, Any]], max_k: int = 50) -> int:
    """P11: 使用 Silhouette 轮廓系数选择最优 k 值.

    遍历 k=5..max_k, 选轮廓系数最高的 k。
    学术依据: Rousseeuw (1987) Silhouettes: A graphical aid to the interpretation.
    """
    from sklearn.metrics import silhouette_score

    min_k = max(2, min(5, len(seeds) - 1))
    max_k = min(max_k, len(seeds) - 1)
    if max_k <= min_k:
        return max(5, max_k)

    texts = [_normalize_text(s["value"]) for s in seeds]
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    tfidf_matrix = vectorizer.fit_transform(texts)

    best_k = min_k
    best_score = -1.0
    for k in range(min_k, max_k + 1):
        km = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = km.fit_predict(tfidf_matrix)
        if len(set(labels)) < 2:
            continue
        score = silhouette_score(tfidf_matrix, labels, metric="cosine")
        if score > best_score:
            best_score = score
            best_k = k

    print(f"    P11 Silhouette: 最优 k={best_k} (score={best_score:.3f})")
    return best_k


def _cluster_with_embeddings(seeds: list[dict[str, Any]], n_clusters: int) -> list[dict[str, Any]]:
    """使用 sentence-transformers 语义嵌入 + KMeans 聚类."""
    model = SentenceTransformer("all-MiniLM-L6-v2")
    texts = [s["value"] for s in seeds]
    embeddings = model.encode(texts, show_progress_bar=False)

    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = km.fit_predict(embeddings)

    result: list[dict[str, Any]] = []
    for cluster_id in range(n_clusters):
        member_indices = [i for i, lbl in enumerate(labels) if lbl == cluster_id]
        if not member_indices:
            continue
        center = km.cluster_centers_[cluster_id]
        distances = np.linalg.norm(embeddings[member_indices] - center, axis=1)
        closest_idx = member_indices[np.argmin(distances)]
        result.append(seeds[closest_idx])

    print(f"    聚类: {n_clusters} 簇, 每簇取中心 → {len(result)} 个种子")
    return result


def _cluster_with_tfidf(seeds: list[dict[str, Any]], n_clusters: int) -> list[dict[str, Any]]:
    """使用 TF-IDF + KMeans 聚类 (回退方案)."""
    texts = [_normalize_text(s["value"]) for s in seeds]
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    tfidf_matrix = vectorizer.fit_transform(texts)

    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = km.fit_predict(tfidf_matrix)

    result: list[dict[str, Any]] = []
    for cluster_id in range(n_clusters):
        member_indices = [i for i, lbl in enumerate(labels) if lbl == cluster_id]
        if not member_indices:
            continue
        center = km.cluster_centers_[cluster_id]
        member_vectors = tfidf_matrix[member_indices].toarray()
        distances = np.linalg.norm(member_vectors - center, axis=1)
        closest_idx = member_indices[np.argmin(distances)]
        result.append(seeds[closest_idx])

    print(f"    聚类: {n_clusters} 簇, 每簇取中心 → {len(result)} 个种子")
    return result


# ============================================================
# Step 4: 模型感知 ASR 排序 (NEW)
# ============================================================


def _load_asr_priors() -> dict[str, Any]:
    """加载 ASR 先验数据, 返回完整结构。."""
    if not _ASR_PRIORS.exists():
        return {"priors": [], "owasp_multipliers": {}, "tier_thresholds": {}}
    with open(_ASR_PRIORS, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _infer_model_tier(model_name: str) -> str:
    """从模型名推断 tier (strong/moderate/weak/unknown)。."""
    if not model_name:
        return "unknown"
    name = model_name.lower().strip()
    if not _MODEL_TIERS.exists():
        return "unknown"
    with open(_MODEL_TIERS, encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
    strong = [re.compile(p, re.IGNORECASE) for p in config.get("strong_patterns", [])]
    moderate = [re.compile(p, re.IGNORECASE) for p in config.get("moderate_patterns", [])]
    weak = [re.compile(p, re.IGNORECASE) for p in config.get("weak_patterns", [])]
    for pat in strong:
        if pat.search(name):
            return "strong"
    for pat in weak:
        if pat.search(name):
            return "weak"
    for pat in moderate:
        if pat.search(name):
            return "moderate"
    # 参数量匹配
    param_match = re.search(r"(\d+\.?\d*)b", name)
    if param_match:
        param = float(param_match.group(1))
        for entry in config.get("param_tier_map", []):
            if param <= entry.get("threshold", float("inf")):
                return entry.get("tier", "unknown")
    return "unknown"


def _select_model_variant(model_name: str, asr_data: dict[str, Any]) -> str:
    """根据模型名选择最接近的 ASR 先验变体。.

    G1: 支持 9 变体 (gpt_4o/gpt_4/gpt_35/claude_3_5/llama_3_1
        + gemini_1_5/mistral_large/qwen_2_5/deepseek_v3)

    优先级: model_variant_mapping 精确匹配 > 模糊匹配 > tier 回退
    """
    if not model_name:
        return "gpt_4o"

    name_lower = model_name.lower().strip()

    # 1. 查找 model_variant_mapping 表
    mapping = asr_data.get("model_variant_mapping", {})
    if name_lower in mapping:
        return mapping[name_lower]
    for key, variant in mapping.items():
        if key in name_lower:
            return variant

    # 2. 关键词回退
    if "gpt-4o" in name_lower or "gpt4o" in name_lower:
        return "gpt_4o"
    if "gpt-4" in name_lower or "gpt4" in name_lower:
        return "gpt_4"
    if "gpt-3.5" in name_lower or "gpt35" in name_lower:
        return "gpt_35"
    if "claude" in name_lower:
        return "claude_3_5"
    if "llama" in name_lower:
        return "llama_3_1"
    if "gemini" in name_lower:
        return "gemini_1_5"
    if "mistral" in name_lower or "mixtral" in name_lower:
        return "mistral_large"
    if "qwen" in name_lower and "72" in name_lower:
        return "qwen_2_5"
    if "qwen" in name_lower:
        return "gpt_35"  # 小参数 Qwen 用 gpt_35 先验
    if "deepseek" in name_lower:
        return "deepseek_v3"

    # 3. Tier 回退
    tier = _infer_model_tier(model_name)
    if tier == "strong":
        return "gpt_4o"
    if tier == "weak":
        return "gpt_35"
    if tier == "moderate":
        return "llama_3_1"
    return "gpt_4o"


def model_aware_asr_rank(
    seeds: list[dict[str, Any]],
    model_name: str = "",
) -> list[dict[str, Any]]:
    """模型感知 ASR 排序: 根据目标模型推断 tier → 用对应 ASR 先验排序种子。.

    对每个种子, 计算估计 ASR:
      base_asr = 技术先验 ASR (按模型变体)
      × category_multiplier (OWASP 类别感知系数)
      × difficulty_boost (hard=1.2, medium=1.0, easy=0.8)
      × patched_penalty (已修补技术降权)
    """
    print("\n  [Step 4] 模型感知 ASR 排序")

    asr_data = _load_asr_priors()
    priors = asr_data.get("priors", [])
    owasp_multipliers = asr_data.get("owasp_asr_multipliers", {})
    patched_penalty = asr_data.get("patched_penalty_by_tier", {})

    # 选择模型变体
    variant = _select_model_variant(model_name, asr_data)
    tier = _infer_model_tier(model_name) if model_name else "unknown"
    print(f"    目标模型: {model_name or '(通用)'}")
    print(f"    推断 Tier: {tier}")
    print(f"    ASR 变体: {variant}")

    # P1: 加载种子级实测 ASR (如果有)
    seed_level_asr: dict[str, dict[str, Any]] = {}
    if model_name:
        try:
            import hashlib as _hashlib

            from pipeline.asr.optimizer import load_seed_level_asr

            raw_seed_asr = load_seed_level_asr(model_name)
            if raw_seed_asr:
                print(f"    种子级实测 ASR: {len(raw_seed_asr)} 个种子已加载")
                seed_level_asr = raw_seed_asr
        except ImportError:
            pass

    # 技术 → ASR 值 (按变体)
    tech_asr: dict[str, float] = {}
    tech_patched: dict[str, bool] = {}
    for p in priors:
        tech = p.get("technique", "")
        val = p.get(variant, 0.3)
        tech_asr[tech] = float(val)
        tech_patched[tech] = p.get("patched", False)

    # 全局平均 (回退)
    global_avg = sum(tech_asr.values()) / len(tech_asr) if tech_asr else 0.3

    # P7: Tier 默认 ASR 回退 (当先验数据缺失时)
    default_by_tier = asr_data.get("default_asr_by_tier", {})
    if not tech_asr and tier in default_by_tier:
        global_avg = default_by_tier[tier]
        print(f"    P7 回退: 使用 tier 默认 ASR ({tier}={global_avg})")

    # Patched 惩罚系数
    penalty = patched_penalty.get(tier, patched_penalty.get("unknown", 0.4))

    # 计算每个种子的估计 ASR
    for s in seeds:
        # P1: 优先使用种子级实测 ASR (如果有)
        seed_hash = _hashlib.md5(s["value"][:200].encode("utf-8")).hexdigest()
        if seed_hash in seed_level_asr:
            base_asr = seed_level_asr[seed_hash]["asr"]
            s["_asr_source"] = "empirical"
        else:
            # 基础 ASR: 用全局平均 (种子级 ASR 需要实测数据)
            base_asr = global_avg
            s["_asr_source"] = "estimated"

        # 类别乘数
        cat = s["category"]
        for _owasp_id, tech_mults in owasp_multipliers.items():
            for _tech, _mult in tech_mults.items():
                # 使用该类别中所有技术的平均乘数
                pass
        # 简化: 用 category → 技术组映射
        category_tech_map = {
            "chemical_biological": ["red_teaming", "crescendo"],
            "cybercrime_intrusion": ["red_teaming", "tap"],
            "illegal": ["crescendo", "pair"],
            "harassment_bullying": ["red_teaming", "pair"],
            "misinformation_disinformation": ["many_shot", "red_teaming"],
            "copyright": ["many_shot", "red_teaming"],
            "harmful": ["crescendo", "pair"],
            "Disinformation": ["many_shot", "red_teaming"],
            "Violence": ["crescendo", "tap"],
            "Privacy": ["pair", "red_teaming"],
            "Sexual content": ["crescendo", "pair"],
            "Malware/Hacking": ["red_teaming", "tap"],
        }
        techs = category_tech_map.get(cat, ["crescendo", "red_teaming"])
        tech_asr_vals = [tech_asr.get(t, global_avg) for t in techs]
        # 如果技术已修补, 降权
        tech_asr_vals_adjusted = []
        for t, val in zip(techs, tech_asr_vals, strict=False):
            if tech_patched.get(t, False):
                val *= penalty
            tech_asr_vals_adjusted.append(val)
        base_asr = sum(tech_asr_vals_adjusted) / len(tech_asr_vals_adjusted)

        # 难度加分
        difficulty = s.get("metadata", {}).get("difficulty", "medium")
        boost = {"hard": 1.2, "medium": 1.0, "easy": 0.8}.get(difficulty, 1.0)

        s["_estimated_asr"] = base_asr * boost
        s["_model_variant"] = variant
        s["_model_tier"] = tier

    sorted_seeds = sorted(seeds, key=lambda s: s["_estimated_asr"], reverse=True)
    print(f"    排序完成 (按估计 ASR 降序, 全局均值={global_avg:.2f})")
    return sorted_seeds


# ============================================================
# Step 5: 模态感知过滤 (NEW)
# ============================================================


def modality_aware_filter(
    seeds: list[dict[str, Any]],
    modality: str = "text",
) -> list[dict[str, Any]]:
    """模态感知过滤: 根据目标模型模态选择对应种子类型。.

    Args:
        seeds: 种子列表
        modality: "text" (仅文本) / "multimodal" (文本+图像) / "all" (不过滤)
    """
    print(f"\n  [Step 5] 模态感知过滤 (modality={modality})")

    if modality == "all":
        print("    跳过过滤 (all)")
        return seeds

    by_modality: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in seeds:
        by_modality[s["modality"]].append(s)

    print(f"    种子模态分布: {dict((k, len(v)) for k, v in by_modality.items())}")

    if modality == "text":
        filtered = by_modality.get("text", [])
    elif modality == "multimodal":
        # 多模态: 保留文本 + 图像, 图像优先
        filtered = by_modality.get("text", []) + by_modality.get("image", [])
    else:
        filtered = seeds

    print(f"    过滤后: {len(filtered)} 个种子")
    return filtered


# ============================================================
# Step 6: Tier 分层采样 (NEW)
# ============================================================


def tier_stratified_sample(
    seeds: list[dict[str, Any]],
    target_count: int = 50,
) -> list[dict[str, Any]]:
    """Tier 分层采样: 按估计 ASR 分 S/A/B 三层, 等比例采样。.

    学术依据:
      - HarmBench (arXiv:2402.04249): 区分 standard vs context 难度
      - GCG (arXiv:2307.15043): 不同种子 ASR 差异 0%-80%

    Args:
        seeds: 已排序的种子列表
        target_count: 目标种子数
    """
    print(f"\n  [Step 6] Tier 分层采样 (target={target_count})")

    tier_s = [s for s in seeds if s.get("_estimated_asr", 0) >= _TIER_S_THRESHOLD]
    tier_a = [s for s in seeds if _TIER_A_THRESHOLD <= s.get("_estimated_asr", 0) < _TIER_S_THRESHOLD]
    tier_b = [s for s in seeds if _TIER_B_THRESHOLD <= s.get("_estimated_asr", 0) < _TIER_A_THRESHOLD]
    tier_c = [s for s in seeds if s.get("_estimated_asr", 0) < _TIER_B_THRESHOLD]

    print(f"    Tier 分布: S={len(tier_s)}, A={len(tier_a)}, B={len(tier_b)}, C={len(tier_c)}")

    # 等比例采样: 每层 ~target_count/3
    per_tier = max(1, target_count // 3)
    result: list[dict[str, Any]] = []

    for tier_name, tier_seeds, n in [
        ("S", tier_s, per_tier),
        ("A", tier_a, per_tier),
        ("B", tier_b, per_tier),
    ]:
        actual_n = min(n, len(tier_seeds))
        result.extend(tier_seeds[:actual_n])
        print(f"      Tier {tier_name}: 取 {actual_n}/{len(tier_seeds)}")

    # 如果不够 target_count, 从 Tier C 补充
    if len(result) < target_count and tier_c:
        remaining = target_count - len(result)
        result.extend(tier_c[:remaining])
        print(f"      Tier C (补充): 取 {min(remaining, len(tier_c))}/{len(tier_c)}")

    # 如果仍然不够 (Tier C 也不足), 从所有已排序种子补充
    if len(result) < target_count:
        used_values = {s["value"] for s in result}
        for s in seeds:
            if s["value"] not in used_values:
                result.append(s)
                if len(result) >= target_count:
                    break
        print(f"      (回退补充): 填充至 {len(result)}")

    print(f"    输出: {len(result)} 个种子 (S/A/B/C 分层)")
    return result


# ============================================================
# 输出
# ============================================================


def save_curated_seeds(
    seeds: list[dict[str, Any]],
    output_path: Path,
    model_name: str = "",
    modality: str = "text",
) -> None:
    """保存精简后的种子到 .prompt YAML 文件。."""
    all_seeds: list[dict[str, Any]] = []
    for s in seeds:
        seed_entry: dict[str, Any] = {"value": s["value"]}
        metadata = {k: v for k, v in s.get("metadata", {}).items() if not k.startswith("_")}
        metadata["curated"] = True
        metadata["source_dataset"] = s["dataset_name"]
        metadata["harm_category"] = s["category"]
        metadata["estimated_asr"] = round(s.get("_estimated_asr", 0), 3)
        metadata["model_variant"] = s.get("_model_variant", "")
        metadata["model_tier"] = s.get("_model_tier", "")
        metadata["asr_source"] = s.get("_asr_source", "estimated")
        seed_entry["metadata"] = metadata
        all_seeds.append(seed_entry)

    # 生成文件名: 如果指定模型, 文件名包含模型名
    ds_name = "curated_seeds"
    desc = f"Curated seeds ({len(all_seeds)}) from multi-source datasets"
    if model_name:
        ds_name = f"curated_seeds_{_sanitize_model_name(model_name)}"
        desc += f" for {model_name} ({modality} modality)"
    else:
        desc += " (generic)"

    output_data = {
        "dataset_name": ds_name,
        "harm_categories": "",
        "source": "curated",
        "groups": "multi_source",
        "data_type": "text" if modality == "text" else "multimodal",
        "description": desc,
        "seed_type": "objective",
        "seeds": all_seeds,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(output_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=200)

    print(f"\n  [Output] 精简后种子保存到: {output_path}")
    print(f"    总种子数: {len(all_seeds)}")

    # P17: 质量监控 — 写入 curate_quality.json 趋势追踪
    _save_quality_metrics(all_seeds, output_path, model_name, modality)


def _save_quality_metrics(
    seeds: list[dict[str, Any]],
    output_path: Path,
    model_name: str = "",
    modality: str = "text",
) -> None:
    """P17: 写入精简质量评分到 curate_quality.json 用于趋势追踪."""
    from datetime import datetime

    quality_path = _PROJECT_ROOT / "outputs" / "empirical_asr" / "curate_quality.json"
    quality_path.parent.mkdir(parents=True, exist_ok=True)

    # 计算质量指标
    asr_values = [s.get("metadata", {}).get("estimated_asr", 0) for s in seeds]
    categories = set(s.get("metadata", {}).get("harm_category", "") for s in seeds)
    datasets = set(s.get("metadata", {}).get("source_dataset", "") for s in seeds)
    avg_asr = sum(asr_values) / len(asr_values) if asr_values else 0

    entry = {
        "timestamp": datetime.now().isoformat(),
        "output_file": str(output_path.name),
        "model": model_name or "generic",
        "modality": modality,
        "seed_count": len(seeds),
        "category_count": len(categories),
        "dataset_count": len(datasets),
        "avg_estimated_asr": round(avg_asr, 3),
        "asr_range": [round(min(asr_values), 3), round(max(asr_values), 3)] if asr_values else [0, 0],
    }

    # 追加到已有 JSON
    import json

    existing: list[dict[str, Any]] = []
    if quality_path.exists():
        try:
            with open(quality_path, encoding="utf-8") as f:
                existing = json.load(f)
                if not isinstance(existing, list):
                    existing = [existing]
        except (json.JSONDecodeError, OSError):
            existing = []

    existing.append(entry)
    with open(quality_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    print(f"    [P17] 质量评分已写入: {quality_path}")


def _sanitize_model_name(name: str) -> str:
    """将模型名转为安全文件名。."""
    return re.sub(r"[^\w]", "_", name.lower())[:30]


def print_summary(
    original: int,
    curated: list[dict[str, Any]],
    model_name: str = "",
    modality: str = "text",
) -> None:
    """打印精简摘要。."""
    by_ds: dict[str, int] = defaultdict(int)
    by_cat: dict[str, int] = defaultdict(int)
    by_tier: dict[str, int] = defaultdict(int)
    for s in curated:
        by_ds[s["dataset_name"]] += 1
        by_cat[s["category"]] += 1
        asr = s.get("_estimated_asr", 0)
        if asr >= _TIER_S_THRESHOLD:
            by_tier["S"] += 1
        elif asr >= _TIER_A_THRESHOLD:
            by_tier["A"] += 1
        elif asr >= _TIER_B_THRESHOLD:
            by_tier["B"] += 1
        else:
            by_tier["C"] += 1

    print(f"\n{'=' * 70}")
    print("种子精简摘要")
    print(f"  目标模型: {model_name or '(通用)'}")
    print(f"  模态:     {modality}")
    print(f"  原始种子: {original}")
    print(f"  精简后:   {len(curated)}")
    print(f"  压缩率:   {(1 - len(curated) / original) * 100:.1f}%")
    print("\n  Tier 分布:")
    for tier in ("S", "A", "B", "C"):
        print(f"    Tier {tier}: {by_tier.get(tier, 0)}")
    print("\n  按数据集分布:")
    for ds, count in sorted(by_ds.items()):
        print(f"    {ds}: {count}")
    print("\n  按危害类别分布:")
    for cat, count in sorted(by_cat.items()):
        print(f"    {cat}: {count}")
    print(f"{'=' * 70}")


# ============================================================
# CLI 入口
# ============================================================


def main() -> None:
    """Run seed curation main entry point."""
    parser = argparse.ArgumentParser(
        description="种子精简工具 v2 (去重+均衡+聚类+模型感知ASR+模态过滤+Tier分层)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="",
        help="目标模型名 (如 gpt-4o, llama-3-8b). 指定后按模型特征排序种子",
    )
    parser.add_argument(
        "--modality",
        type=str,
        default="text",
        choices=["text", "multimodal", "all"],
        help="目标模型模态: text=仅文本种子, multimodal=文本+图像, all=不过滤",
    )
    parser.add_argument(
        "--per-category",
        type=int,
        default=_DEFAULT_PER_CATEGORY,
        help=f"Step 2 每类采样数 (默认: {_DEFAULT_PER_CATEGORY})",
    )
    parser.add_argument(
        "--target-count",
        type=int,
        default=50,
        help="Step 6 最终目标种子数 (默认: 50)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="",
        help="输出文件路径 (默认: 自动生成)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="检查精简后种子状态",
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="列出可用的 ASR 先验模型变体",
    )
    args = parser.parse_args()

    if args.list_models:
        asr_data = _load_asr_priors()
        priors = asr_data.get("priors", [])
        if not priors:
            print("无 ASR 先验数据")
            return
        # 提取所有模型变体
        variants = set()
        for p in priors:
            for k in p:
                if k.startswith(("gpt", "claude", "llama")):
                    variants.add(k)
        print(f"可用 ASR 先验模型变体 ({len(variants)}):")
        for v in sorted(variants):
            tier = _MODEL_VARIANT_TIERS.get(v, "unknown")
            avg = sum(p.get(v, 0) for p in priors) / len(priors)
            print(f"  {v:15s} (tier={tier:8s}, avg_asr={avg:.2f})")
        return

    if args.check:
        # 检查所有 curated 文件
        for f in sorted(_OUTPUT_DIR.glob("curated_seeds*.prompt")):
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            seeds = data.get("seeds", [])
            model_variant = seeds[0].get("metadata", {}).get("model_variant", "N/A") if seeds else "N/A"
            print(f"  {f.name}: {len(seeds)} seeds, variant={model_variant}")
        return

    # 默认输出路径
    if not args.output:
        if args.model:
            model_slug = _sanitize_model_name(args.model)
            args.output = str(_OUTPUT_DIR / f"curated_seeds_{model_slug}.prompt")
        else:
            args.output = str(_OUTPUT_DIR / "curated_seeds.prompt")

    # 加载所有种子
    print(f"{'=' * 70}")
    print("种子精简工具 v2 (模型感知 + 模态感知 + Tier 分层)")
    print(f"  数据目录: {_SEED_DIR}")
    print(f"  目标模型: {args.model or '(通用)'}")
    print(f"  模态:     {args.modality}")
    print("  目标: 去重 → 均衡 → 聚类 → 模型ASR → 模态过滤 → Tier分层")
    print(f"{'=' * 70}")

    all_seeds = load_all_seeds()
    original_count = len(all_seeds)
    print(f"\n  加载种子: {original_count} 个")

    # Step 1: 去重
    deduped = dedup_seeds(all_seeds)

    # P9: 跨语言去重 (可选, 仅当 sentence-transformers 可用时)
    if _HAS_ST and len(deduped) > 100:
        print("\n  [Step 1.5] 跨语言语义去重 (multilingual embeddings)")
        before = len(deduped)
        deduped = _cross_language_dedup(deduped, threshold=0.85)
        removed = before - len(deduped)
        print(f"    跨语言去重: 移除 {removed} 个语义重复")

    # Step 2: 类别均衡
    asr_data = _load_asr_priors()
    balanced = category_balanced_sample(deduped, per_category=args.per_category, asr_data=asr_data)

    # Step 3: 多样性聚类
    clustered = diversity_cluster(balanced)

    # Step 4: 模型感知 ASR 排序
    ranked = model_aware_asr_rank(clustered, model_name=args.model)

    # Step 5: 模态感知过滤
    filtered = modality_aware_filter(ranked, modality=args.modality)

    # Step 6: Tier 分层采样
    final = tier_stratified_sample(filtered, target_count=args.target_count)

    # 输出
    save_curated_seeds(final, Path(args.output), model_name=args.model, modality=args.modality)

    # 摘要
    print_summary(original_count, final, model_name=args.model, modality=args.modality)


if __name__ == "__main__":
    main()
