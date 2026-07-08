"""
===============================================================================
将 Legacy JSON 测试用例转换为 Preset 模式 YAML 模板
用法: python scripts/convert_legacy_to_preset.py
===============================================================================
"""
import json
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATASETS_DIR = PROJECT_ROOT / "datasets"
TEMPLATES_DIR = PROJECT_ROOT / "scenarios" / "templates"


def _sanitize_id(case_id: str, combo_name: str) -> str:
    safe_combo = combo_name.replace(" ", "_").replace("+", "_plus_").replace("/", "_")
    safe_combo = "".join(c for c in safe_combo if c.isalnum() or c in "_-")
    safe_id = case_id.replace(" ", "_")
    safe_id = "".join(c for c in safe_id if c.isalnum() or c in "_-")
    return f"{safe_id}__{safe_combo}"


def _infer_category(mapping: dict) -> str:
    attack_cat = mapping.get("attack_category", "").lower()
    if "jailbreak" in attack_cat or "code generation" in attack_cat:
        return "jailbreak"
    if "extraction" in attack_cat or "system prompt" in attack_cat:
        return "extraction"
    if "injection" in attack_cat:
        return "injection"
    if "social" in attack_cat or "phishing" in attack_cat:
        return "social"
    if "misinfo" in attack_cat:
        return "misinfo"
    if "privacy" in attack_cat:
        return "privacy"
    if "exploit" in attack_cat or "malicious" in attack_cat:
        return "exploit"
    if "rag" in attack_cat:
        return "rag_exploit"
    if "agent" in attack_cat or "mcp" in attack_cat:
        return "agent_hijack"
    if "a2a" in attack_cat:
        return "a2a_abuse"
    if "embedding" in attack_cat or "training" in attack_cat:
        return "data_poison"
    if "multimodal" in attack_cat:
        return "injection"
    return "custom"


def _infer_owasp(owasp_raw: str) -> str:
    for key, val in {
        "LLM01": "LLM01: Prompt Injection",
        "LLM02": "LLM02: Insecure Output Handling",
        "LLM04": "LLM04: Model Denial of Service",
        "LLM06": "LLM06: Sensitive Information Disclosure",
        "LLM07": "LLM07: Insecure Plugin Design",
        "LLM08": "LLM08: Excessive Agency",
        "LLM10": "LLM10: Model Theft",
        "MCP": "MCP: Tool Poisoning",
        "A2A": "A2A: Agent Card Spoofing",
    }.items():
        if key in owasp_raw:
            return val
    return "LLM01: Prompt Injection"


class IndentListDumper(yaml.Dumper):
    """Custom YAML dumper that uses block indentation for sequences."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def _build_prompt_entry(case: dict, combo: dict, is_multi: bool,
                         difficulty: str, category: str, owasp: str) -> dict:
    """Build a single prompt entry dict."""
    case_id = case.get("id", "unknown")
    prompt_id = _sanitize_id(case_id, combo.get("name", "unknown"))

    objective = case.get("objective", "")
    # For Crescendo multi-turn cases, objective is empty — use first stage
    if not objective and case.get("multi_turn_objectives"):
        objective = case["multi_turn_objectives"][0]

    entry = {
        "id": prompt_id,
        "objective": objective,
        "criterion": case.get("criterion", ""),
        "category": category,
        "difficulty": difficulty,
        "owasp_category": owasp,
    }

    if is_multi and case.get("multi_turn_objectives"):
        entry["multi_turn"] = True
        entry["multi_turn_stages"] = case["multi_turn_objectives"]

    converters = combo.get("converters", [])
    if converters:
        entry["converter_names"] = converters

    return entry


def convert_json_to_yaml_dict(json_file: str, lang: str) -> dict:
    """Convert legacy JSON to preset YAML Python dict structure."""
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    cases = data.get("test_cases", [])
    prompts = []

    for case in cases:
        mapping = case.get("syllabus_mapping", {})

        diff_map = {"Basic": "basic", "Medium": "medium", "Hard": "hard"}
        difficulty = diff_map.get(mapping.get("difficulty", "Medium"), "medium")
        category = _infer_category(mapping)
        owasp = _infer_owasp(mapping.get("owasp_llm_top10", ""))
        is_multi = mapping.get("crescendo", False)

        for combo in case.get("attack_combos", []):
            prompts.append(_build_prompt_entry(
                case, combo, is_multi, difficulty, category, owasp
            ))

    desc = "Preset 预设攻击组合 - 从 Legacy JSON 迁移, 手动指定转换器链"

    return {
        "metadata": {
            "version": "1.0",
            "framework_version": "PyRIT Red Team v10.0",
            "description": desc,
        },
        "config": {
            "mode": "preset",
            "max_concurrent": 5,
            "language": lang,
            "variants_per_prompt": 1,
            "enable_advanced": False,
            "enable_multiturn": False,
            "prompt_timeout": 120,
        },
        "prompts": prompts,
    }


def _make_header(lang: str) -> str:
    lang_label = "\u4e2d\u6587" if lang == "cn" else "English"
    tpl = f"legacy_preset_{lang}.yaml"
    return (
        f"# {'='*79}\n"
        f"# Preset \u9884\u8bbe\u653b\u51fb\u7ec4\u5408\u6a21\u677f ({lang_label})\n"
        f"# {'='*79}\n"
        f"# mode: preset - \u8f6c\u6362\u5668\u94fe\u7531 converter_names \u624b\u52a8\u6307\u5b9a\n"
        f"# \u4f7f\u7528: python main.py --penetrating-mode --penetrating-template {tpl}\n"
        f"# \u4e0e --orch legacy \u7b49\u4ef7, \u4f46\u4f7f\u7528 PenetratingOrchestrator \u6267\u884c\n"
        f"# {'='*79}\n\n"
    )


def main():
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

    for lang in ("cn", "en"):
        json_file = DATASETS_DIR / f"test_cases_{lang}.json"
        yaml_file = TEMPLATES_DIR / f"legacy_preset_{lang}.yaml"

        if not json_file.exists():
            print(f"[SKIP] {json_file} not found")
            continue

        print(f"[CONVERT] {json_file} -> {yaml_file}")
        yaml_dict = convert_json_to_yaml_dict(str(json_file), lang)

        with open(yaml_file, "w", encoding="utf-8") as f:
            f.write(_make_header(lang))
            yaml.dump(
                yaml_dict, f,
                Dumper=IndentListDumper,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
                indent=2,
                width=200,  # wide width to avoid line breaks in long strings
            )

        print(f"  [OK] Generated {len(yaml_dict['prompts'])} preset entries")

    print("\n[DONE] Conversion complete!")
    print(f"   CN: {TEMPLATES_DIR / 'legacy_preset_cn.yaml'}")
    print(f"   EN: {TEMPLATES_DIR / 'legacy_preset_en.yaml'}")


if __name__ == "__main__":
    main()
