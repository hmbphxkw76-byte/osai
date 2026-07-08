"""
===============================================================================
PyRIT Red Team — Payload 构建脚本 (Build Script)
===============================================================================
用途: 
  1. 验证 datasets/payloads/ 下所有 YAML 文件的格式和完整性
  2. 统计各模块 payload 覆盖度
  3. 生成 payload 覆盖率报告
  4. 检查 manifest.yaml 与实际 YAML 文件的一致性

执行: python scripts/build_payloads.py

渗透期间无需运行此脚本 — 它仅用于开发维护和 CI 流程。
===============================================================================
"""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from datasets.payload_loader import (
    load_classic_payloads,
    load_all_module_payloads,
    load_exam_module_yaml,
    MODULE_FILE_MAP,
    PRESET_NAMES,
)


def validate_classic_payloads():
    """验证经典载荷 YAML 文件的完整性。"""
    print("\n" + "=" * 60)
    print("  经典攻击载荷验证 (core/)")
    print("=" * 60)

    all_ok = True
    for lang_label, lang_key in [("中文 (zh)", "cn"), ("英文 (en)", "en")]:
        vars_dict, presets = load_classic_payloads(lang_key)
        count = len(vars_dict)
        preset_count = len(presets)
        status = "[OK]" if count > 0 else "[FAIL]"
        print(f"  {status} {lang_label}: {count} 变量, {preset_count} 预设 ({', '.join(presets.keys())})")

        # 检查空值（忽略运行时占位符 ctx_hm_prompt）
        ignored_empty = {"ctx_hm_prompt"}
        empty_vars = [k for k, v in vars_dict.items() if not v and k not in ignored_empty]
        if empty_vars:
            print(f"  [WARN] 非预期空值变量 ({len(empty_vars)}): {', '.join(empty_vars[:5])}...")
            all_ok = False

        # 检查 preset 完整度（忽略运行时占位符）
        for pn in PRESET_NAMES:
            if pn in presets:
                pn_count = sum(1 for k, v in presets[pn].items() if v and k not in ignored_empty)
                expected = count - len(ignored_empty)
                if pn_count < expected:
                    print(f"  [WARN] 预设 '{pn}' 覆盖: {pn_count}/{expected} (忽略 {len(ignored_empty)} 个占位符)")
                    all_ok = False

    return all_ok


def validate_module_payloads():
    """验证 AI 模块载荷 YAML 文件的完整性。"""
    print("\n" + "=" * 60)
    print("  AI 模块载荷验证")
    print("=" * 60)

    all_modules = load_all_module_payloads()
    all_ok = True

    seen_files = set()
    for module_key, filename in MODULE_FILE_MAP.items():
        if filename in seen_files:
            continue
        seen_files.add(filename)

        base_name = os.path.splitext(filename)[0]
        data = load_exam_module_yaml(filename, module_key)

        if base_name in all_modules:
            sections = all_modules[base_name]
            total_entries = sum(len(v) for v in sections.values())
            section_names = list(sections.keys())
            print(f"  [OK] {filename}: {len(sections)} sections, {total_entries} entries")
            print(f"       {', '.join(section_names)}")
        elif data:
            total = sum(len(v) for v in data.values())
            print(f"  [OK] {filename}: {len(data)} sections, {total} entries")
        else:
            print(f"  [FAIL] {filename}: 加载失败或为空")
            all_ok = False

    # 检查 manifest.yaml 中声明但未成功加载的模块
    unloaded = [f for f in seen_files
                if os.path.splitext(f)[0] not in all_modules
                and load_exam_module_yaml(f, "check") is None]
    if unloaded:
        print(f"\n  [WARN] 以下文件未成功加载: {unloaded}")
        all_ok = False

    return all_ok


def check_manifest_consistency():
    """检查 manifest.yaml 与实际 YAML 文件列表的一致性。"""
    print("\n" + "=" * 60)
    print("  Manifest 一致性检查")
    print("=" * 60)

    payloads_dir = os.path.join(PROJECT_ROOT, "datasets", "payloads")
    manifest_path = os.path.join(payloads_dir, "manifest.yaml")

    if not os.path.exists(manifest_path):
        print("  [WARN] manifest.yaml 不存在，跳过检查")
        return True

    # 加载 manifest
    import yaml
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = yaml.safe_load(f)

    # 收集 manifest 中声明的所有 YAML 文件名
    manifest_files = set()
    for classic in manifest.get("manifest", {}).get("classic", manifest.get("classic", [])):
        manifest_files.add(os.path.basename(classic["file"]))

    for mod in manifest.get("manifest", {}).get("modules", manifest.get("modules", [])):
        manifest_files.add(mod["file"])

    # 收集实际存在的 YAML 文件
    actual_yaml = set()
    for root, _, files in os.walk(payloads_dir):
        for f in files:
            if f.endswith(".yaml") and f != "manifest.yaml":
                actual_yaml.add(f)

    # 比较
    only_in_manifest = manifest_files - actual_yaml
    only_on_disk = actual_yaml - manifest_files

    all_ok = True
    if only_in_manifest:
        print(f"  [WARN] manifest 声明但文件不存在: {only_in_manifest}")
        all_ok = False
    if only_on_disk:
        print(f"  [WARN] 文件存在但 manifest 未声明: {only_on_disk}")
        all_ok = False
    if not only_in_manifest and not only_on_disk:
        print(f"  [OK] manifest 与实际文件完全一致 ({len(actual_yaml)} YAML 文件)")

    return all_ok


def generate_coverage_report():
    """生成 payload 覆盖率摘要报告。"""
    print("\n" + "=" * 60)
    print("  Payload 覆盖率摘要")
    print("=" * 60)

    # 经典载荷
    cn_vars, _ = load_classic_payloads("cn")
    en_vars, _ = load_classic_payloads("en")
    print(f"  经典载荷: CN={len(cn_vars)}, EN={len(en_vars)}")

    # AI 模块
    all_modules = load_all_module_payloads()
    total_sections = sum(len(sections) for sections in all_modules.values())
    total_entries = sum(
        sum(len(entries) for entries in sections.values())
        for sections in all_modules.values()
    )
    print(f"  AI 模块: {len(all_modules)} 文件, {total_sections} sections, {total_entries} entries")

    # 按模块展示
    print()
    for module_name, sections in sorted(all_modules.items()):
        entries = sum(len(e) for e in sections.values())
        print(f"  {module_name:40s} {len(sections):2d} sections, {entries:3d} entries")


def main():
    print("=" * 60)
    print("  PyRIT Red Team Payload 构建与验证工具")
    print("=" * 60)

    results = {
        "classic": validate_classic_payloads(),
        "modules": validate_module_payloads(),
        "manifest": check_manifest_consistency(),
    }

    all_pass = all(results.values())

    print("\n" + "=" * 60)
    print(f"  构建结果: {'ALL PASS' if all_pass else 'SOME CHECKS FAILED'}")
    print("=" * 60)

    for name, ok in results.items():
        status = "[OK]" if ok else "[FAIL]"
        print(f"  {status} {name}")

    if not all_pass:
        print("\n  请修复以上问题后重新运行。")
        sys.exit(1)

    # 生成覆盖率报告
    generate_coverage_report()

    print("\n[OK] 构建完成。所有 YAML 文件通过验证。")


if __name__ == "__main__":
    main()
