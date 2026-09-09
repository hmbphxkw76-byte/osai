#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data Directory Validator — Production Grade
Validates all YAML seed files, scorer configs, and ASR history JSON.
"""

import json
import os
import sys
from pathlib import Path

import yaml

# Force UTF-8 output
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DATA_DIR = Path(__file__).parent.parent / "data"
SEEDS_DIR = DATA_DIR / "seeds"
SCORERS_DIR = DATA_DIR / "scorers"

# Required metadata fields per README v3.0
REQUIRED_METADATA_FIELDS = {
    "owasp_id",
    "difficulty",
    "severity",
    "category",
    "source",
    "tier",
    "attack_vector",
}

# Valid values
VALID_DIFFICULTIES = {"easy", "medium", "hard", "very_hard"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_SOURCES = {"curated", "academic", "academic_adaptation", "community", "dynamic_engine", "harmbench", "jailbreakbench", "owasp_llm", "targeted_jailbreaks", "many_shot"}
VALID_LANGUAGES = {"en", "zh", "ja", "ko", "fr", "de", "es", "ru", "ar", "mixed"}
VALID_TIERS = {1, 2, 3}

# OWASP IDs covered
OWASP_IDS = {
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
    "ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
    "ASI06", "ASI07", "ASI08", "ASI09", "ASI10",
}


def validate_yaml_seed_file(filepath: Path) -> list[str]:
    """Validate a single YAML seed file."""
    issues = []
    rel_path = filepath.relative_to(DATA_DIR)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = yaml.safe_load(f)
    except yaml.YAMLError as e:
        issues.append(f"[ERROR] {rel_path}: YAML parse error: {e}")
        return issues

    if not isinstance(content, list):
        issues.append(f"[ERROR] {rel_path}: Expected list of seeds, got {type(content).__name__}")
        return issues

    for idx, item in enumerate(content):
        if not isinstance(item, dict):
            issues.append(f"[ERROR] {rel_path}: Seed #{idx} is not a dict")
            continue

        if "value" not in item:
            issues.append(f"[ERROR] {rel_path}: Seed #{idx} missing 'value' field")
            continue

        if "metadata" not in item:
            issues.append(f"[WARNING] {rel_path}: Seed #{idx} missing 'metadata' field")
            continue

        meta = item["metadata"]
        if not isinstance(meta, dict):
            issues.append(f"[ERROR] {rel_path}: Seed #{idx} metadata is not a dict")
            continue

        # Check required fields
        missing_fields = REQUIRED_METADATA_FIELDS - set(meta.keys())
        if missing_fields:
            issues.append(
                f"[WARNING] {rel_path}: Seed #{idx} missing metadata fields: {missing_fields}"
            )

        # Validate field values
        if "difficulty" in meta and meta["difficulty"] not in VALID_DIFFICULTIES:
            issues.append(
                f"[WARNING] {rel_path}: Seed #{idx} invalid difficulty: {meta['difficulty']}"
            )

        if "severity" in meta and meta["severity"] not in VALID_SEVERITIES:
            issues.append(
                f"[WARNING] {rel_path}: Seed #{idx} invalid severity: {meta['severity']}"
            )

        if "source" in meta and meta["source"] not in VALID_SOURCES:
            issues.append(
                f"[WARNING] {rel_path}: Seed #{idx} invalid source: {meta['source']}"
            )

        if "tier" in meta and meta["tier"] not in VALID_TIERS:
            issues.append(
                f"[WARNING] {rel_path}: Seed #{idx} invalid tier: {meta['tier']}"
            )

        if "language" in meta and meta["language"] not in VALID_LANGUAGES:
            issues.append(
                f"[WARNING] {rel_path}: Seed #{idx} invalid language: {meta['language']}"
            )

        if "owasp_id" in meta:
            owasp_id = str(meta["owasp_id"]).upper()
            if owasp_id not in OWASP_IDS:
                issues.append(
                    f"[WARNING] {rel_path}: Seed #{idx} unknown owasp_id: {meta['owasp_id']}"
                )

    return issues


def validate_scorer_file(filepath: Path) -> list[str]:
    """Validate a scorer YAML file."""
    issues = []
    rel_path = filepath.relative_to(DATA_DIR)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = yaml.safe_load(f)
    except yaml.YAMLError as e:
        issues.append(f"[ERROR] {rel_path}: YAML parse error: {e}")
        return issues

    if not isinstance(content, dict):
        issues.append(f"[ERROR] {rel_path}: Expected dict, got {type(content).__name__}")
        return issues

    # Required fields for scorer
    required_fields = ["category", "true_description", "false_description"]
    for field in required_fields:
        if field not in content:
            issues.append(f"[ERROR] {rel_path}: Missing required field: {field}")
        elif not isinstance(content[field], str) or len(content[field]) < 10:
            issues.append(f"[WARNING] {rel_path}: Field '{field}' is too short or not a string")

    return issues


def validate_asr_history(filepath: Path) -> list[str]:
    """Validate ASR history JSON file."""
    issues = []
    rel_path = filepath.relative_to(DATA_DIR)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = json.load(f)
    except json.JSONDecodeError as e:
        issues.append(f"[ERROR] {rel_path}: JSON parse error: {e}")
        return issues

    if not isinstance(content, dict):
        issues.append(f"[ERROR] {rel_path}: Expected dict, got {type(content).__name__}")
        return issues

    # Check required top-level keys
    expected_keys = {"last_run", "asr", "seed_asr", "seed_attempts", "threshold_history"}
    missing_keys = expected_keys - set(content.keys())
    if missing_keys:
        issues.append(f"[WARNING] {rel_path}: Missing expected keys: {missing_keys}")

    # Validate seed_asr values are 0-100
    if "seed_asr" in content:
        for seed, asr in content["seed_asr"].items():
            if not isinstance(asr, (int, float)) or asr < 0 or asr > 100:
                issues.append(f"[WARNING] {rel_path}: Invalid ASR value for '{seed}': {asr}")

    return issues


def main() -> int:
    """Run all validations and return exit code."""
    all_issues = []
    stats = {
        "seed_files": 0,
        "scorer_files": 0,
        "total_seeds": 0,
        "owasp_coverage": set(),
        "attack_vectors": set(),
        "errors": 0,
        "warnings": 0,
    }

    print("=" * 70)
    print("Data Directory Validation Report")
    print("=" * 70)

    # Validate seed files
    print("\n[1/3] Validating seed files...")
    seed_files = list(SEEDS_DIR.rglob("*.prompt"))
    stats["seed_files"] = len(seed_files)

    for filepath in sorted(seed_files):
        issues = validate_yaml_seed_file(filepath)
        all_issues.extend(issues)

        # Count seeds and collect metadata
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
            if isinstance(content, list):
                stats["total_seeds"] += len(content)
                for item in content:
                    if isinstance(item, dict) and "metadata" in item:
                        meta = item["metadata"]
                        if "owasp_id" in meta:
                            stats["owasp_coverage"].add(str(meta["owasp_id"]).upper())
                        if "attack_vector" in meta:
                            stats["attack_vectors"].add(meta["attack_vector"])
        except Exception:
            pass

    # Validate scorer files
    print("[2/3] Validating scorer files...")
    scorer_files = list(SCORERS_DIR.glob("*.yaml"))
    stats["scorer_files"] = len(scorer_files)

    for filepath in sorted(scorer_files):
        issues = validate_scorer_file(filepath)
        all_issues.extend(issues)

    # Validate ASR history
    print("[3/3] Validating ASR history...")
    asr_history = SEEDS_DIR / "asr_history.json"
    if asr_history.exists():
        issues = validate_asr_history(asr_history)
        all_issues.extend(issues)

    # Categorize issues
    errors = [i for i in all_issues if i.startswith("[ERROR]")]
    warnings = [i for i in all_issues if i.startswith("[WARNING]")]
    stats["errors"] = len(errors)
    stats["warnings"] = len(warnings)

    # Print results
    print("\n" + "=" * 70)
    print("Validation Results")
    print("=" * 70)
    print(f"  Seed files validated:    {stats['seed_files']}")
    print(f"  Scorer files validated:  {stats['scorer_files']}")
    print(f"  Total seeds found:       {stats['total_seeds']}")
    print(f"  OWASP coverage:          {len(stats['owasp_coverage'])}/20 categories")
    print(f"  Attack vectors:          {len(stats['attack_vectors'])} unique")
    print(f"  Errors:                  {stats['errors']}")
    print(f"  Warnings:                {stats['warnings']}")

    # OWASP coverage detail
    print("\n" + "-" * 70)
    print("OWASP Coverage Detail")
    print("-" * 70)
    for owasp_id in sorted(OWASP_IDS):
        status = "[OK]" if owasp_id in stats["owasp_coverage"] else "[--]"
        print(f"  {status} {owasp_id}")

    # Attack vectors
    print("\n" + "-" * 70)
    print(f"Attack Vectors ({len(stats['attack_vectors'])} unique)")
    print("-" * 70)
    for av in sorted(stats["attack_vectors"]):
        print(f"    - {av}")

    # Print issues
    if all_issues:
        print("\n" + "-" * 70)
        print("Issues Found")
        print("-" * 70)
        for issue in all_issues:
            print(f"  {issue}")

    # Final verdict
    print("\n" + "=" * 70)
    if stats["errors"] > 0:
        print(f"RESULT: FAIL — {stats['errors']} error(s) found")
        return 1
    elif stats["warnings"] > 0:
        print(f"RESULT: PASS (with {stats['warnings']} warnings)")
        return 0
    else:
        print("RESULT: PASS — All validations passed")
        return 0


if __name__ == "__main__":
    sys.exit(main())
