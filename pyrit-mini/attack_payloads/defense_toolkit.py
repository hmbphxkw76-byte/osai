#!/usr/bin/env python3
"""
defense_toolkit.py - 防御工具包
提供针对间接提示注入攻击的检测和防御功能
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(Enum):
    """风险等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnalysisResult:
    """分析结果"""
    risk_score: float
    risk_level: RiskLevel
    indicators: list[str] = field(default_factory=list)
    should_block: bool = False
    recommendations: list[str] = field(default_factory=list)


class ASTAnalyzer:
    """基于AST的语义分析器"""

    SUSPICIOUS_PATTERNS = {
        "import_chain": [
            r"from\s+\w+\s+import\s+\w+\s+as\s+\w+",
            r"importlib\.import_module\s*\(",
            r"__import__\s*\(",
            r"importlib\.util\.find_spec",
        ],
        "code_execution": [
            r"eval\s*\(",
            r"exec\s*\(",
            r"compile\s*\(",
            r"getattr\s*\([^,]+,\s*['\"]",
            r"setattr\s*\(",
        ],
        "file_access": [
            r"open\s*\([^)]*['\"][rwa]",
            r"\.read\s*\(\s*\)",
            r"\.write\s*\(",
            r"os\.path\.",
            r"pathlib\.Path",
        ],
        "obfuscation": [
            r"base64\.",
            r"codecs\.",
            r"zlib\.",
            r"marshal\.loads",
            r"\.decode\s*\(\s*['\"]",
        ]
    }

    def analyze(self, code: str, filename: str = "<string>") -> AnalysisResult:
        """对代码进行深度分析"""
        indicators = []
        score = 0.0

        suspicious_count = 0
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, code)
                if matches:
                    suspicious_count += len(matches)
                    indicators.append(f"{category}: {pattern}")

        score += min(suspicious_count * 10, 40)

        tree = None
        try:
            tree = ast.parse(code)
        except SyntaxError:
            indicators.append("SYNTAX_ERROR: AST parsing failed")
            return AnalysisResult(
                risk_score=50.0,
                risk_level=RiskLevel.HIGH,
                indicators=indicators,
                should_block=True,
                recommendations=["代码语法错误，可能为输入验证绕过"]
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if self._is_suspicious_import(alias.name):
                        indicators.append(f"SUSPICIOUS_IMPORT: {alias.name}")
                        score += 15

            elif isinstance(node, ast.ImportFrom):
                if node.module and self._is_suspicious_import(node.module):
                    indicators.append(f"SUSPICIOUS_IMPORT_FROM: {node.module}")
                    score += 16

                if node.names:
                    for alias in node.names:
                        if alias.name in ["__class__", "__dict__", "__globals__", "__builtins__"]:
                            indicators.append(f"DUNDER_ACCESS: {node.module}.{alias.name}")
                            score += 20

            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ["getattr", "setattr", "delattr"]:
                        indicators.append(f"DYNAMIC_ATTR: {node.func.id}")
                        score += 12
                    elif node.func.id == "open":
                        indicators.append("FILE_OPEN: open()")
                        score += 10

        chain_length = self._detect_import_chain_length(code)
        if chain_length > 3:
            indicators.append(f"IMPORT_CHAIN: length={chain_length}")
            score += chain_length * 5

        embedded = self._detect_embedded_prompts(code)
        if embedded:
            indicators.append(f"EMBEDDED_PROMPT: {embedded[:50]}...")
            score += 25

        if not indicators:
            risk_level = RiskLevel.LOW
            should_block = False
        elif score < 30:
            risk_level = RiskLevel.LOW
            should_block = False
        elif score < 60:
            risk_level = RiskLevel.MEDIUM
            should_block = False
        elif score < 80:
            risk_level = RiskLevel.HIGH
            should_block = True
        else:
            risk_level = RiskLevel.CRITICAL
            should_block = True

        if should_block:
            if risk_level == RiskLevel.CRITICAL:
                recommendations = [
                    "立即阻止此代码提交",
                    "触发安全告警通知管理员",
                    "记录攻击日志用于取证分析",
                    "限制提交用户的访问权限",
                ]
            else:
                recommendations = [
                    "要求人工审查后再处理",
                    "限制Agent的文件读取权限",
                    "对读取内容进行脱敏处理"
                ]
        else:
            recommendations = ["常规审查流程"]

        return AnalysisResult(
            risk_score=min(score, 100),
            risk_level=risk_level,
            indicators=indicators,
            should_block=should_block,
            recommendations=recommendations
        )

    def _is_suspicious_import(self, module_name: str) -> bool:
        suspicious_modules = [
            "os", "sys", "subprocess", "pathlib", "shutil", "socket",
            "requests", "http", "ftplib", "smtplib", "ctypes", "inspect",
        ]

        for susp in suspicious_modules:
            if module_name == susp or module_name.startswith(f"{susp}."):
                return True
        return False

    def _detect_import_chain_length(self, code: str) -> int:
        lines = code.split('\n')
        import_lines = [i for i, line in enumerate(lines) if line.strip().startswith(('import ', 'from '))]

        if len(import_lines) < 2:
            return 0

        max_chain = 0
        current_chain = 1

        for i in range(1, len(import_lines)):
            if import_lines[i] - import_lines[i-1] <= 3:
                current_chain += 1
                max_chain = max(max_chain, current_chain)
            else:
                current_chain = 1

        return max_chain

    def _detect_embedded_prompts(self, code: str) -> str | None:
        prompt_indicators = [
            r'"""[\s\S]*?(?:指令|instruction|prompt|命令)[\s\S]*?"""',
            r"'''[\s\S]*?(?:指令|instruction|prompt|命令)[\s\S]*?'''",
            r'#\s*(?:指令|instruction|prompt|命令)\s*:\s*(.+)',
        ]

        for pattern in prompt_indicators:
            match = re.search(pattern, code, re.IGNORECASE)
            if match:
                return match.group(0)
        return None


@dataclass
class FileAccessPolicy:
    """文件访问策略"""
    allowed_paths: list[str] = field(default_factory=list)
    max_depth: int = 2
    allow_sensitive_files: bool = False
    max_files_per_review: int = 5


class FileAccessSandbox:
    """文件访问沙箱"""

    SENSITIVE_PATTERNS = [
        r'.*\.env$',
        r'.*config\.(py|yaml|yml|json|toml)$',
        r'.*secret.*$',
        r'.*credential.*$',
        r'.*password.*$',
        r'.*key\.(pem|key)$',
        r'.*\.htpasswd$',
        r'.*id_rsa$',
    ]

    def __init__(self, policy: FileAccessPolicy | None = None):
        self.policy = policy or FileAccessPolicy()

    def check_access(self, file_path: str, mode: str = "read") -> tuple[bool, str]:
        """检查文件访问是否允许"""
        path_str = str(file_path)

        if self.policy.allowed_paths:
            is_allowed = any(
                path_str.startswith(allowed)
                for allowed in self.policy.allowed_paths
            )
            if not is_allowed:
                return False, f"路径 {path_str} 不在允许列表中"

        if not self.policy.allow_sensitive_files:
            for pattern in self.SENSITIVE_PATTERNS:
                if re.match(pattern, path_str, re.IGNORECASE):
                    return False, f"路径 {path_str} 匹配敏感文件模式: {pattern}"

        return True, "允许访问"

    def sanitize_content(self, content: str) -> tuple[str, list[str]]:
        """对内容进行脱敏处理"""
        secrets = []

        secret_patterns = {
            "api_key": r'([A-Za-z0-9_]*(?:API|SECRET|ACCESS|AUTH)_[A-Za-z0-9_]*)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            "database_url": r'([A-Za-z]+://[^\s"\']+)',
            "jwt_token": r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
        }

        sanitized = content

        for secret_type, pattern in secret_patterns.items():
            matches = re.finditer(pattern, sanitized)
            for match in matches:
                full_match = match.group(0)
                secrets.append(f"{secret_type}: {full_match[:20]}...")
                sanitized = sanitized.replace(full_match, f"[REDACTED_{secret_type.upper()}]")

        return sanitized, secrets


class DefenseOrchestrator:
    """防御编排器"""

    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()
        self.sandbox = FileAccessSandbox()

    def analyze_code_submission(
        self,
        code: str,
        filename: str = "<string>"
    ) -> dict[str, Any]:
        """分析代码提交"""
        ast_result = self.ast_analyzer.analyze(code, filename)

        has_import_to_sensitive = self._check_sensitive_import_target(code)

        overall_score = ast_result.risk_score
        if has_import_to_sensitive:
            overall_score += 30

        indicators = list(ast_result.indicators)
        recommendations = list(ast_result.recommendations)

        if has_import_to_sensitive:
            indicators.append("IMPORT_TO_SENSITIVE: 尝试引用敏感文件")
            recommendations.append("阻止读取项目根目录外的文件")

        should_block = ast_result.should_block or has_import_to_sensitive

        if overall_score < 30:
            risk_level = RiskLevel.LOW
        elif overall_score < 60:
            risk_level = RiskLevel.MEDIUM
        elif overall_score < 80:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        return {
            "risk_score": min(overall_score, 100),
            "risk_level": risk_level.value,
            "should_block": should_block,
            "indicators": indicators,
            "recommendations": recommendations,
        }

    def _check_sensitive_import_target(self, code: str) -> bool:
        sensitive_modules = ["config", "secrets", "credentials", "settings", "constants", "env"]

        import_pattern = r'from\s+(\w+)\s+import|import\s+(\w+)'
        matches = re.findall(import_pattern, code)

        for match in matches:
            module = match[0] or match[1]
            if module.lower() in sensitive_modules:
                return True
        return False
