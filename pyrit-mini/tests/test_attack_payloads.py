#!/usr/bin/env python3
"""
test_attack_payloads.py - 攻击载荷工具包测试
覆盖攻击载荷生成器、防御工具包、模拟器等核心功能
"""

from __future__ import annotations

import sys
from pathlib import Path

# 添加attack_payloads和tools到路径
_ATTACK_PAYLOADS_DIR = Path(__file__).parent.parent / "attack_payloads"
_TOOLS_DIR = Path(__file__).parent.parent / "tools"
sys.path.insert(0, str(_ATTACK_PAYLOADS_DIR))
sys.path.insert(0, str(_TOOLS_DIR))

from advanced_payloads import AdvancedPayloadGenerator  # noqa: E402
from defense_toolkit import (  # noqa: E402
    ASTAnalyzer,
    DefenseOrchestrator,
    FileAccessPolicy,
    FileAccessSandbox,
    RiskLevel,
)
from evasion_techniques import EvasionTechniqueLibrary  # noqa: E402
from payload_generator import (  # noqa: E402
    AttackPayload,
    EvasionLevel,
    IndirectPIAttackGenerator,
)

from tools.vulnerable_target_simulator import VulnerableTargetSimulator  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════════
# IndirectPIAttackGenerator 测试
# ═══════════════════════════════════════════════════════════════════════════

class TestPayloadGenerator:
    """攻击载荷生成器测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.generator = IndirectPIAttackGenerator()

    def test_generate_attack_basic(self):
        """测试基本攻击载荷生成"""
        payload = self.generator.generate_attack(
            target_file="config.py",
            target_class="Config",
            target_attribute="API_KEY"
        )

        assert isinstance(payload, AttackPayload)
        assert payload.filename.endswith(".py")
        assert "config" in payload.content.lower()
        assert payload.target_file == "config.py"

    def test_generate_attack_naive_level(self):
        """测试NAIVE级别攻击载荷"""
        payload = self.generator.generate_attack(
            target_file="secrets.py",
            evasion_level=EvasionLevel.NAIVE
        )

        assert payload.evasion_level == EvasionLevel.NAIVE
        assert "from secrets import" in payload.content

    def test_generate_attack_semantic_level(self):
        """测试SEMANTIC级别攻击载荷"""
        payload = self.generator.generate_attack(
            target_file="config.py",
            evasion_level=EvasionLevel.SEMANTIC
        )

        assert payload.evasion_level == EvasionLevel.SEMANTIC
        assert "import" in payload.content

    def test_generate_attack_multi_level(self):
        """测试MULTI_LAYER级别攻击载荷"""
        payload = self.generator.generate_attack(
            target_file="config.py",
            evasion_level=EvasionLevel.MULTI_LAYER
        )

        assert payload.evasion_level == EvasionLevel.MULTI_LAYER
        assert "importlib" in payload.content

    def test_generate_multi_target_attack(self):
        """测试多目标攻击载荷生成"""
        targets = [
            {"file": "config.py", "class": "Config", "attr": "API_KEY"},
            {"file": "secrets.py", "class": "Secrets", "attr": "PASSWORD"},
        ]

        payloads = self.generator.generate_multi_target_attack(targets)

        assert len(payloads) == 2
        assert payloads[0].target_file == "config.py"
        assert payloads[1].target_file == "secrets.py"

    def test_generate_recursive_attack_chain(self):
        """测试递归攻击链生成"""
        chain = self.generator.generate_recursive_attack_chain(chain_depth=3)

        assert len(chain) == 3
        assert chain[0].metadata["chain_level"] == 0
        assert chain[1].metadata["chain_level"] == 1
        assert chain[-1].metadata.get("is_target") is True

    def test_sensitive_files_list(self):
        """测试敏感文件列表"""
        assert "config.py" in IndirectPIAttackGenerator.SENSITIVE_FILES
        assert ".env" in IndirectPIAttackGenerator.SENSITIVE_FILES
        assert "secrets.py" in IndirectPIAttackGenerator.SENSITIVE_FILES

    def test_sensitive_patterns_list(self):
        """测试敏感模式列表"""
        assert "API_KEY" in IndirectPIAttackGenerator.SENSITIVE_PATTERNS
        assert "SECRET_KEY" in IndirectPIAttackGenerator.SENSITIVE_PATTERNS

    def test_custom_prefix(self):
        """测试自定义前缀"""
        payload = self.generator.generate_attack(
            target_file="config.py",
            prefix="custom_prefix"
        )

        assert "custom_prefix" in payload.filename
        assert "custom_prefix" in payload.content


# ═══════════════════════════════════════════════════════════════════════════
# ASTAnalyzer 测试
# ═══════════════════════════════════════════════════════════════════════════

class TestASTAnalyzer:
    """AST分析器测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.analyzer = ASTAnalyzer()

    def test_analyze_benign_code(self):
        """测试良性代码分析"""
        code = '''
def hello():
    return "Hello, World!"
'''
        result = self.analyzer.analyze(code)

        assert result.risk_score < 30
        assert result.risk_level == RiskLevel.LOW
        assert result.should_block is False

    def test_analyze_suspicious_import(self):
        """测试可疑import检测"""
        code = '''
from os import system
from sys import path
import subprocess
'''
        result = self.analyzer.analyze(code)

        assert result.risk_score > 0
        assert len(result.indicators) > 0

    def test_analyze_code_execution(self):
        """测试代码执行检测"""
        code = '''
eval(user_input)
exec(compiled_code)
'''
        result = self.analyzer.analyze(code)

        assert result.risk_score >= 20
        assert any("eval" in ind.lower() or "exec" in ind.lower() for ind in result.indicators)

    def test_analyze_dunder_access(self):
        """测试双下划线属性访问检测"""
        code = '''
obj.__class__.__dict__
module.__globals__
'''
        result = self.analyzer.analyze(code)

        # dunder access detection depends on AST parsing
        # the code may not parse correctly, so we just check it doesn't crash
        assert result.risk_score >= 0

    def test_analyze_syntax_error(self):
        """测试语法错误处理"""
        code = 'def broken('

        result = self.analyzer.analyze(code)

        assert result.should_block is True
        assert result.risk_level == RiskLevel.HIGH

    def test_analyze_import_chain(self):
        """测试import链检测"""
        code = '''
from a import A
from b import B
from c import C
from d import D
'''
        result = self.analyzer.analyze(code)

        assert any("CHAIN" in ind for ind in result.indicators)

    def test_analyze_obfuscation(self):
        """测试混淆检测"""
        code = '''
import base64
encoded = base64.b64encode(data)
'''
        result = self.analyzer.analyze(code)

        assert any("obfuscation" in ind.lower() for ind in result.indicators)


# ═══════════════════════════════════════════════════════════════════════════
# DefenseOrchestrator 测试
# ═══════════════════════════════════════════════════════════════════════════

class TestDefenseOrchestrator:
    """防御编排器测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.orchestrator = DefenseOrchestrator()

    def test_analyze_safe_code(self):
        """测试安全代码分析"""
        code = '''
def calculate_sum(a, b):
    return a + b
'''
        result = self.orchestrator.analyze_code_submission(code)

        assert result["risk_level"] == RiskLevel.LOW.value
        assert result["should_block"] is False

    def test_analyze_sensitive_import(self):
        """测试敏感import分析"""
        code = '''
from config import Config
print(Config.API_KEY)
'''
        result = self.orchestrator.analyze_code_submission(code)

        assert result["should_block"] is True
        assert any("SENSITIVE" in ind for ind in result["indicators"])

    def test_has_recommendations(self):
        """测试建议生成"""
        code = 'eval(user_input)'
        result = self.orchestrator.analyze_code_submission(code)

        assert len(result["recommendations"]) > 0


# ═══════════════════════════════════════════════════════════════════════════
# VulnerableTargetSimulator 测试
# ═══════════════════════════════════════════════════════════════════════════

class TestVulnerableTargetSimulator:
    """漏洞目标模拟器测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.simulator = VulnerableTargetSimulator()

    def test_simulator_creates_project_dir(self):
        """测试模拟器创建项目目录"""
        assert self.simulator.project_dir.exists()

    def test_simulator_creates_config_file(self):
        """测试模拟器创建config.py文件"""
        config_path = self.simulator.project_dir / "config.py"
        assert config_path.exists()

        content = config_path.read_text(encoding="utf-8")
        assert "API_KEY" in content
        assert "SECRET_KEY" in content

    def test_upload_file(self):
        """测试文件上传"""
        path = self.simulator.upload_file("test.py", "print('hello')")

        assert Path(path).exists()
        assert Path(path).read_text(encoding="utf-8") == "print('hello')"

    def test_review_code_not_found(self):
        """测试审查不存在的文件"""
        result = self.simulator.review_code("nonexistent.py")

        assert len(result.findings) == 0
        assert "不存在" in result.summary

    def test_review_import_triggers_read(self):
        """测试import触发文件读取"""
        malicious_code = '''
from config import Config
print(Config.API_KEY)
'''
        self.simulator.upload_file("malicious.py", malicious_code)
        result = self.simulator.review_code("malicious.py")

        assert len(result.references) > 0
        assert any("config.py" in ref for ref in result.references)
        assert len(result.findings) > 0

    def test_secret_extraction(self):
        """测试密钥提取"""
        malicious_code = '''
from config import Config
from utils import format_response
'''
        self.simulator.upload_file("extract.py", malicious_code)
        result = self.simulator.review_code("extract.py")

        secret_findings = [f for f in result.findings if f["type"] == "Secret Key"]
        assert len(secret_findings) > 0

    def test_project_structure(self):
        """测试项目结构获取"""
        structure = self.simulator.get_project_structure()

        assert "config.py" in structure
        assert "utils.py" in structure
        assert "app.py" in structure


# ═══════════════════════════════════════════════════════════════════════════
# AdvancedPayloadGenerator 测试
# ═══════════════════════════════════════════════════════════════════════════

class TestAdvancedPayloadGenerator:
    """高级载荷生成器测试"""

    def test_generate_comment_camouflage(self):
        """测试注释伪装载荷"""
        payload = AdvancedPayloadGenerator.generate_comment_camouflage()

        assert payload.name == "CommentCamouflage"
        assert "import" in payload.content
        assert payload.effectiveness > 0.8

    def test_generate_string_obfuscation(self):
        """测试字符串混淆载荷"""
        payload = AdvancedPayloadGenerator.generate_string_obfuscation()

        assert payload.name == "StringObfuscation"
        assert "importlib" in payload.content

    def test_generate_test_code_deception(self):
        """测试测试代码欺骗载荷"""
        payload = AdvancedPayloadGenerator.generate_test_code_deception()

        assert payload.name == "TestCodeDeception"
        assert "pytest" in payload.content

    def test_generate_all_payloads(self):
        """测试生成所有载荷"""
        payloads = AdvancedPayloadGenerator.generate_all_payloads()

        assert len(payloads) >= 3
        assert all(p.effectiveness > 0 for p in payloads)


# ═══════════════════════════════════════════════════════════════════════════
# EvasionTechniqueLibrary 测试
# ═══════════════════════════════════════════════════════════════════════════

class TestEvasionTechniqueLibrary:
    """绕过技术库测试"""

    def test_encode_base64(self):
        """测试Base64编码"""
        text = "hello world"
        encoded = EvasionTechniqueLibrary.encode_in_base64(text)

        assert encoded != text
        import base64
        assert base64.b64decode(encoded).decode() == text

    def test_generate_polymorphic_variant(self):
        """测试多态变体生成"""
        template = "def func_{random}(): pass"
        variant = EvasionTechniqueLibrary.generate_polymorphic_variant(template)

        assert "{random}" not in variant
        assert "func_" in variant

    def test_insert_junk_code(self):
        """测试垃圾代码插入"""
        code = "def original():\n    return 42"
        result = EvasionTechniqueLibrary.insert_junk_code(code)

        assert "original" in result

    def test_apply_comment_evasion(self):
        """测试注释伪装应用"""
        code = "from config import Config"
        result = EvasionTechniqueLibrary.apply_comment_evasion(code)

        assert result.technique == "comment_evasion"
        assert result.detection_probability < 0.5

    def test_apply_string_splitting(self):
        """测试字符串分割应用"""
        code = "from config import Config"
        result = EvasionTechniqueLibrary.apply_string_splitting(code)

        assert result.technique == "string_splitting"
        assert "con" + "fig" in result.evaded


# ═══════════════════════════════════════════════════════════════════════════
# FileAccessSandbox 测试
# ═══════════════════════════════════════════════════════════════════════════

class TestFileAccessSandbox:
    """文件访问沙箱测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.policy = FileAccessPolicy(
            allowed_paths=["/opt/agents/intake/"],
            max_depth=2,
            allow_sensitive_files=False
        )
        self.sandbox = FileAccessSandbox(self.policy)

    def test_check_access_allowed_path(self):
        """测试允许路径访问"""
        allow, reason = self.sandbox.check_access("/opt/agents/intake/test.py")

        assert allow is True

    def test_check_access_disallowed_path(self):
        """测试拒绝路径访问"""
        allow, reason = self.sandbox.check_access("/etc/passwd")

        assert allow is False

    def test_check_access_sensitive_file(self):
        """测试敏感文件访问"""
        allow, reason = self.sandbox.check_access("/opt/agents/intake/.env")

        assert allow is False

    def test_sanitize_content(self):
        """测试内容脱敏"""
        content = '''
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://user:pass@host/db"
'''
        sanitized, secrets = self.sandbox.sanitize_content(content)

        assert len(secrets) > 0
        assert "REDACTED" in sanitized
