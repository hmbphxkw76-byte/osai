# -*- coding: utf-8 -*-
"""tools/security_audit.py — 安全审计（开发全审 Phase I）。

扫描生产源码，覆盖：
    1. 密钥扫描   — 硬编码私钥 / AWS Key / 高熵凭证字面量
    2. 漏洞检测   — eval/exec/os.system/subprocess(shell=True)/不安全 yaml.load/pickle/弱哈希
    3. 注入检测   — 字符串拼装的 SQL/命令执行
    4. 输入验证   — 检测 REPL 式 input() 调用（应在入口统一校验）
    5. 权限检查   — os.chmod 过宽权限位

严重级别：
    BLOCKING — 真实硬编码密钥/私钥（必须修复）
    WARNING  — 危险调用 / 注入式拼装（建议修复）
    INFO     — 可能的凭证字面量 / 输入校验提示（知会即可）

退出码：存在 BLOCKING → 1，否则 0（与 dev_audit_full fail-fast 对齐）。

Academic basis:
    - OWASP ASVS v4 (V1-V6): 密钥管理 / 输入校验 / 权限控制
    - CWE-798 (Hardcoded Credentials) / CWE-94 (Code Injection) / CWE-78 (OS Command Injection)
"""

from __future__ import annotations

import ast
import re

from tools._audit_base import Finding, Severity, iter_source_files, project_root, run_audit

# 高置信硬编码密钥（BLOCKING）
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |AES |PGP )?PRIVATE KEY-----"), "PRIVATE_KEY"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY"),
]

# 危险调用（WARNING）。注意：eval/exec 改由 AST 精确识别真实调用，避免误报
# 字符串字面量（如 JS 样例中的 eval(code)）或函数名（如 _exec）中的子串。
_DANGER_PATTERNS: list[tuple[str, str]] = [
    ("os.system(", "OS_SYSTEM"),
    ("shell=True", "SUBPROCESS_SHELL"),
    ("yaml.load(", "YAML_LOAD_UNSAFE"),
    ("pickle.load", "PICKLE_LOAD"),
    ("pickle.loads", "PICKLE_LOADS"),
    ("hashlib.md5", "WEAK_HASH_MD5"),
    ("md5(", "WEAK_HASH_MD5"),
]

# 注入式拼装（WARNING）
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.execute\(\s*[f\"']"), "SQL_COMMAND_INJECTION"),
    (re.compile(r"cursor\.execute\(\s*f[\"']"), "SQL_FSTRING"),
]

# 凭证字面量（INFO，排除明显占位符与枚举/标签值以降低误报）
_CRED_LITERAL = re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token)\s*=\s*['\"]([^'\"]+)['\"]")
_PLACEHOLDER = re.compile(
    r"(?i)(attacker|example|changeme|dummy|xxxx|placeholder|your[-_ ]?|todo|admin|test"
    r"|demo|exempt|audit|fake|sample|do[-_]?not[-_]?use|non[-_]?real)"
)
# 形如 `API_KEY = "api_key"` 的枚举/标签值本身即关键字，绝非密钥
_NON_SECRET_VALUES = frozenset(
    {"api_key", "apikey", "api-key", "token", "secret", "password", "passwd",
     "basic_auth", "oauth2", "oauth", "jwt", "saml", "bearer"}
)


def _collect() -> list[Finding]:
    findings: list[Finding] = []
    root = project_root()

    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        lines = text.splitlines()

        # AST 精确识别真实 eval()/exec() 调用（排除字符串字面量与标识符如 _exec）
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in ("eval", "exec")
                ):
                    loc = f"{rel}:{node.lineno}"
                    rule = "EVAL_USAGE" if node.func.id == "eval" else "EXEC_USAGE"
                    findings.append(Finding(rule, Severity.WARNING, f"检测到危险调用: {node.func.id}(", loc))

        for i, line in enumerate(lines, 1):
            loc = f"{rel}:{i}"

            for pat, rule in _SECRET_PATTERNS:
                if pat.search(line):
                    findings.append(Finding(rule, Severity.BLOCKING, "疑似硬编码密钥/私钥，必须移除并改用环境变量", loc))

            for needle, rule in _DANGER_PATTERNS:
                if needle in line:
                    findings.append(Finding(rule, Severity.WARNING, f"检测到危险调用: {needle}", loc))

            for pat, rule in _INJECTION_PATTERNS:
                if pat.search(line):
                    findings.append(Finding(rule, Severity.WARNING, "字符串拼装的执行入口，存在注入风险", loc))

            m = _CRED_LITERAL.search(line)
            if m:
                val = m.group(2)
                if len(val) >= 6 and val.lower() not in _NON_SECRET_VALUES and not _PLACEHOLDER.search(val):
                    findings.append(
                        Finding("HARDCODED_CRED", Severity.INFO, f"硬编码凭证字面量: {m.group(1)}", loc)
                    )

            if "input(" in line:
                findings.append(Finding("REPL_INPUT", Severity.INFO, "检测到 input() 调用，应在统一入口做输入校验", loc))

            if "os.chmod(" in line and ("0o777" in line or "0o666" in line):
                findings.append(Finding("PERM_WIDE", Severity.BLOCKING, "过宽文件权限位 (0o777/0o666)", loc))

    return findings


def main() -> int:
    """CLI 入口：python -m tools.security_audit"""
    return run_audit("Security Audit (I)", _collect)


if __name__ == "__main__":
    raise SystemExit(main())
