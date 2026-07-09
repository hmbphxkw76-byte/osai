"""
===============================================================================
PyRIT Config Center — 配置读写与校验工具 (v2.0)
===============================================================================
核心原则:
  - 所有 .env 文件使用原始文本读写，禁止 configparser.write() 序列化
  - configparser 仅用于校验（read_file + inline_comment_prefixes）
  - shared.env 的 %(VAR)s 插值完整性检查
===============================================================================
"""
from __future__ import annotations

import configparser
import io
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ── 路径常量 ──
# _PACKAGE_DIR = configs/server/ → _PROJECT_ROOT = pyrit/
_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent.parent
_CONFIGS_DIR = _PROJECT_ROOT / "configs"
_TOKENS_DIR = _CONFIGS_DIR / "tokens"

# .env 文件名列表（非 tokens 目录下的）
_ENV_FILES = [
    "shared.env",
    "platforms.env",
    "targets.env",
    "recons.env",
]


def get_configs_dir() -> Path:
    """返回 configs/ 目录的绝对路径"""
    return _CONFIGS_DIR


def get_shared_env_path() -> Path:
    """返回 shared.env 的绝对路径"""
    return _CONFIGS_DIR / "shared.env"


def list_env_files() -> list[dict]:
    """列出所有 .env 文件及其统计信息"""
    files = []
    for filename in _ENV_FILES:
        filepath = _CONFIGS_DIR / filename
        exists = filepath.exists()
        stats = _get_env_file_stats(filepath) if exists else {}
        files.append({
            "name": filename,
            "path": str(filepath),
            "exists": exists,
            **stats,
        })
    return files


def list_token_files() -> list[dict]:
    """列出所有 token 文件及其统计信息"""
    tokens = []
    if _TOKENS_DIR.exists():
        for filepath in sorted(_TOKENS_DIR.iterdir()):
            if filepath.is_file() and not filepath.name.startswith('.'):
                size = filepath.stat().st_size
                tokens.append({
                    "name": filepath.name,
                    "path": str(filepath),
                    "size_bytes": size,
                    "size_kb": round(size / 1024, 1),
                })
    return tokens


def read_env_file(filename: str) -> dict | None:
    """读取 .env 文件的原始内容 + 解析后的 section 树。

    Returns:
        dict with keys: name, raw, sections, stats, is_shared
        None if file not found or not allowed
    """
    if filename not in _ENV_FILES:
        return None

    filepath = _CONFIGS_DIR / filename
    if not filepath.exists():
        return None

    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()

    is_shared = (filename == "shared.env")
    sections = _parse_env_sections(raw, is_shared)
    stats = _compute_env_stats(raw, sections, is_shared)

    return {
        "name": filename,
        "raw": raw,
        "sections": sections,
        "stats": stats,
        "is_shared": is_shared,
    }


def read_token_file(name: str) -> dict | None:
    """读取 token 文件内容"""
    if ".." in name or "/" in name or "\\" in name:
        return None
    filepath = (_TOKENS_DIR / name).resolve()
    if not str(filepath).startswith(str(_TOKENS_DIR.resolve())):
        return None
    if not filepath.exists() or not filepath.is_file():
        return None

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    return {
        "name": name,
        "path": str(filepath),
        "content": content,
        "size_bytes": len(content.encode("utf-8")),
    }


def validate_and_save_env_file(filename: str, raw_content: str) -> tuple[bool, str]:
    """校验并保存 .env 文件原始文本。

    校验规则:
      1. configparser 语法检查（使用项目标准的加载方式）
      2. %(VAR)s 插值完整性（所有引用变量必须在 shared.env 中定义）
      3. 路径安全检查

    Returns:
        (ok, message) — ok=True 表示校验通过并已保存
    """
    if filename not in _ENV_FILES:
        return False, f"不允许的文件名: {filename}"

    filepath = _CONFIGS_DIR / filename
    is_shared = (filename == "shared.env")

    # 1. configparser 语法校验
    ok, msg = _validate_env_syntax(raw_content, is_shared)
    if not ok:
        return False, msg

    # 2. 插值完整性校验（非 shared.env 文件）
    if not is_shared:
        ok, msg = _validate_interpolation_references(raw_content)
        if not ok:
            return False, msg

    # 3. 写入文件
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(raw_content)
    except IOError as e:
        return False, f"文件写入失败: {e}"

    logger.info(f"配置文件已保存: {filename}")
    return True, f"已保存 {filename}"


def validate_and_save_token_file(name: str, content: str) -> tuple[bool, str]:
    """保存 token 文件"""
    if ".." in name or "/" in name or "\\" in name:
        return False, "无效的文件名"
    filepath = (_TOKENS_DIR / name).resolve()
    if not str(filepath).startswith(str(_TOKENS_DIR.resolve())):
        return False, "路径越界"

    _TOKENS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    except IOError as e:
        return False, f"文件写入失败: {e}"

    logger.info(f"Token 文件已保存: {name}")
    return True, f"已保存 {name}"


def delete_token_file(name: str) -> tuple[bool, str]:
    """删除 token 文件"""
    if ".." in name or "/" in name or "\\" in name:
        return False, "无效的文件名"
    filepath = (_TOKENS_DIR / name).resolve()
    if not str(filepath).startswith(str(_TOKENS_DIR.resolve())):
        return False, "路径越界"
    if not filepath.exists():
        return False, "文件不存在"

    try:
        filepath.unlink()
    except IOError as e:
        return False, f"删除失败: {e}"

    logger.info(f"Token 文件已删除: {name}")
    return True, f"已删除 {name}"


def check_readiness() -> dict:
    """全局就绪检查：汇总所有配置文件的完整性和潜在问题。

    Returns:
        dict with keys:
          - overall_ready: bool
          - checks: list of check dicts
          - warnings: list of warning strings
          - passed_count: int
          - total_count: int
    """
    checks = []
    warnings = []

    # 检查 shared.env
    shared_path = _CONFIGS_DIR / "shared.env"
    shared_vars = {}
    if shared_path.exists():
        with open(shared_path, "r", encoding="utf-8") as f:
            shared_raw = f.read()
        shared_vars = _parse_shared_variables(shared_raw)
        required_shared = ["BASE_URL", "SCORE_BASE_URL", "SCORE_BASE_API"]
        missing = [k for k in required_shared if k not in shared_vars or not shared_vars[k]]
        checks.append({
            "name": "shared.env 变量池",
            "status": "fail" if missing else "pass",
            "detail": f"已配置 {len(shared_vars)} 个变量" if not missing else f"缺少: {', '.join(missing)}",
        })
        url_vars = {"BASE_URL", "SCORE_BASE_URL"}
        for v in url_vars:
            val = shared_vars.get(v, "")
            if val and val not in ("None", "") and not val.startswith(("http://", "https://")):
                warnings.append(f"{v} 不是标准 URL 格式: {val}")
    else:
        checks.append({"name": "shared.env", "status": "fail", "detail": "文件不存在"})

    # 检查 platforms.env
    platforms_path = _CONFIGS_DIR / "platforms.env"
    if platforms_path.exists():
        platforms_sections = _parse_env_sections_by_file(platforms_path)
        expected_sections = ["ATTACK_with_SCORE", "Only_SCORE", "ONLY_ATTACK", "SCORE"]
        missing_sections = [s for s in expected_sections if s not in platforms_sections]
        checks.append({
            "name": "platforms.env 平台模式",
            "status": "pass" if not missing_sections else "warn",
            "detail": f"{len(platforms_sections)} 个节" if not missing_sections else f"缺少: {', '.join(missing_sections)}",
        })
    else:
        checks.append({"name": "platforms.env", "status": "fail", "detail": "文件不存在"})

    # 检查 targets.env
    targets_path = _CONFIGS_DIR / "targets.env"
    if targets_path.exists():
        targets_sections = _parse_env_sections_by_file(targets_path)
        checks.append({
            "name": "targets.env 目标预设",
            "status": "pass" if targets_sections else "warn",
            "detail": f"{len(targets_sections)} 个目标预设",
        })
    else:
        checks.append({"name": "targets.env", "status": "fail", "detail": "文件不存在"})

    # 检查 recons.env
    recons_path = _CONFIGS_DIR / "recons.env"
    if recons_path.exists():
        recons_sections = _parse_env_sections_by_file(recons_path)
        checks.append({
            "name": "recons.env 侦查预设",
            "status": "pass" if recons_sections else "warn",
            "detail": f"{len(recons_sections)} 个侦查预设",
        })
    else:
        checks.append({"name": "recons.env", "status": "fail", "detail": "文件不存在"})

    # 检查 tokens
    tokens = list_token_files()
    token_names = {t["name"] for t in tokens}
    for expected in ["jwt.txt", "cookie.txt", "api_key.txt"]:
        checks.append({
            "name": f"凭证: {expected}",
            "status": "pass" if expected in token_names else "warn",
            "detail": "已配置" if expected in token_names else "未配置（可选）",
        })

    # 汇总
    fail_count = sum(1 for c in checks if c["status"] == "fail")
    pass_count = sum(1 for c in checks if c["status"] == "pass")
    warn_count = sum(1 for c in checks if c["status"] == "warn")

    return {
        "overall_ready": fail_count == 0,
        "checks": checks,
        "warnings": warnings,
        "passed_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "total_count": len(checks),
    }


# ── 私有辅助函数 ──

def _get_env_file_stats(filepath: Path) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()
    is_shared = filepath.name == "shared.env"
    sections = _parse_env_sections(raw, is_shared)
    return _compute_env_stats(raw, sections, is_shared)


def _compute_env_stats(raw: str, sections: dict, is_shared: bool) -> dict:
    line_count = len([l for l in raw.split("\n") if l.strip() and not l.strip().startswith("#")])
    if is_shared:
        var_count = len(sections)
        return {
            "variable_count": var_count,
            "line_count": line_count,
            "size_bytes": len(raw.encode("utf-8")),
            "size_kb": round(len(raw.encode("utf-8")) / 1024, 1),
        }
    else:
        section_count = len(sections)
        total_vars = sum(len(v) for v in sections.values())
        return {
            "section_count": section_count,
            "variable_count": total_vars,
            "line_count": line_count,
            "size_bytes": len(raw.encode("utf-8")),
            "size_kb": round(len(raw.encode("utf-8")) / 1024, 1),
        }


def _parse_env_sections(raw: str, is_shared: bool) -> dict:
    if is_shared:
        variables = _parse_shared_variables(raw)
        return variables
    else:
        return _parse_env_sections_with_configparser(raw)


def _parse_shared_variables(raw: str) -> dict[str, str]:
    variables = {}
    for line in raw.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip()
            value_parts = value.split("#", 1)
            val = value_parts[0].strip()
            if key:
                variables[key] = val
    return variables


def _parse_env_sections_with_configparser(raw: str) -> dict[str, dict[str, str]]:
    config = configparser.ConfigParser(
        inline_comment_prefixes=('#',),
        interpolation=None,
    )
    config.optionxform = lambda option: option

    try:
        shared_text = ""
        shared_path = _CONFIGS_DIR / "shared.env"
        if shared_path.exists():
            with open(shared_path, "r", encoding="utf-8") as f:
                shared_text = f.read()
        config_string = "[DEFAULT]\n" + shared_text + "\n" + raw
        config.read_file(io.StringIO(config_string))
    except configparser.Error:
        return {}

    sections = {}
    for section_name in config.sections():
        if section_name == "DEFAULT":
            continue
        items = {}
        for key, value in config.items(section_name):
            if key not in items:
                items[key] = value
        if items:
            sections[section_name] = items
    return sections


def _parse_env_sections_by_file(filepath: Path) -> dict[str, dict[str, str]]:
    if not filepath.exists():
        return {}
    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()
    return _parse_env_sections_with_configparser(raw)


def _validate_env_syntax(raw: str, is_shared: bool) -> tuple[bool, str]:
    if is_shared:
        for lineno, line in enumerate(raw.split("\n"), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                return False, f"第 {lineno} 行缺少 '=' (shared.env 每行必须是 KEY=VALUE 格式)"
            key_part = stripped.split("=", 1)[0].strip()
            if not key_part:
                return False, f"第 {lineno} 行变量名为空"

    shared_text = ""
    if not is_shared:
        shared_path = _CONFIGS_DIR / "shared.env"
        if shared_path.exists():
            with open(shared_path, "r", encoding="utf-8") as f:
                shared_text = f.read()

    config = configparser.ConfigParser(inline_comment_prefixes=('#',))
    config.optionxform = lambda option: option

    try:
        if is_shared:
            config_string = "[DEFAULT]\n" + raw
        else:
            config_string = "[DEFAULT]\n" + shared_text + "\n" + raw
        config.read_file(io.StringIO(config_string))
    except configparser.Error as e:
        line_hint = ""
        if hasattr(e, 'lineno') and e.lineno:
            line_hint = f" (第 {e.lineno} 行)"
        return False, f"语法错误{line_hint}: {e}"
    except Exception as e:
        return False, f"解析错误: {e}"

    return True, "ok"


def _validate_interpolation_references(raw: str) -> tuple[bool, str]:
    shared_path = _CONFIGS_DIR / "shared.env"
    if not shared_path.exists():
        return True, "shared.env 不存在，跳过插值检查"

    with open(shared_path, "r", encoding="utf-8") as f:
        shared_vars = _parse_shared_variables(f.read())

    refs = set(re.findall(r"%\((\w+)\)s", raw))
    undefined = refs - set(shared_vars.keys())
    if undefined:
        return False, f"未定义的变量引用: {', '.join(sorted(undefined))}（必须在 shared.env 中定义）"

    return True, "ok"


# ── 危险标记检测 ──

_SENSITIVE_PATTERNS = {
    "API Key": r'(?:sk|api[_\-]?key)[-_]?\w{20,}',
    "JWT Token": r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.',
    "Bearer Token": r'(?:bearer|Bearer)\s+[A-Za-z0-9\-_\.]+',
}


# ═══════════════════════════════════════════════════════════════════════════
# 更新 shared.env 变量（Web 端目标配置入口）
# ═══════════════════════════════════════════════════════════════════════════

_TARGET_CONFIG_VARS = [
    "BASE_URL", "BASE_API", "BASE_MODEL",
    "SCORE_BASE_URL", "SCORE_BASE_API", "SCORE_BASE_MODEL",
]


def update_shared_env_variables(updates: dict) -> tuple[bool, str]:
    """更新 shared.env 中的指定变量，保留文件结构和注释。

    Args:
        updates: {VAR_NAME: new_value}，只有非空值才会更新。

    Returns:
        (ok, message)
    """
    shared_path = _CONFIGS_DIR / "shared.env"
    if not shared_path.exists():
        return False, "shared.env 不存在"

    with open(shared_path, "r", encoding="utf-8") as f:
        raw = f.read()

    lines = raw.split("\n")
    updated = set()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in updates and updates[key] is not None:
            comment = ""
            if "#" in stripped:
                comment = " #" + stripped.split("#", 1)[1]
            lines[i] = f"{key} = {updates[key]}{comment}"
            updated.add(key)

    missing = [k for k in updates if k not in updated and updates[k] is not None]
    if missing:
        lines.append("\n# 由 Web 目标配置追加")
        for k in missing:
            lines.append(f"{k} = {updates[k]}")

    new_content = "\n".join(lines)
    ok, msg = validate_and_save_env_file("shared.env", new_content)
    if not ok:
        return False, msg

    return True, f"已更新 {len(updated | set(missing))} 个变量"


def get_target_config_from_shared() -> dict:
    """读取当前 shared.env 中的目标配置变量。"""
    shared = read_env_file("shared.env")
    if not shared:
        return {}
    vars = shared["sections"]
    return {
        "attack_url": vars.get("BASE_URL", ""),
        "attack_api": vars.get("BASE_API", ""),
        "attack_model": vars.get("BASE_MODEL", ""),
        "score_url": vars.get("SCORE_BASE_URL", ""),
        "score_api": vars.get("SCORE_BASE_API", ""),
        "score_model": vars.get("SCORE_BASE_MODEL", ""),
    }


def detect_sensitive_lines(raw: str) -> list[dict]:
    """检测原始文本中可能包含敏感凭证的行"""
    findings = []
    for lineno, line in enumerate(raw.split("\n"), 1):
        for label, pattern in _SENSITIVE_PATTERNS.items():
            if re.search(pattern, line):
                masked = re.sub(pattern, lambda m: m.group()[:8] + "****" + m.group()[-4:], line)
                findings.append({
                    "line": lineno,
                    "type": label,
                    "preview": masked.strip(),
                })
                break
    return findings
