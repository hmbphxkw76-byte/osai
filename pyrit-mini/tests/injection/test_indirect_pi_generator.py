#!/usr/bin/env python3
"""
test_indirect_pi_generator.py - 间接提示注入攻击载荷生成器测试
学术依据: Greshake et al. (arXiv:2302.12173) + Zhan et al. (arXiv:2307.00929)

覆盖 IndirectPIAttackGenerator 的核心功能:
- 基本攻击载荷生成
- 多级别绕过策略
- 多目标攻击
- 递归攻击链
"""

from __future__ import annotations

import sys
from pathlib import Path

# 添加项目根目录到路径
_PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from strike.injection.indirect_pi import (  # noqa: E402
    AttackPayload,
    EvasionLevel,
    IndirectPIAttackGenerator,
)

# ═══════════════════════════════════════════════════════════════════════════
# IndirectPIAttackGenerator 基础测试
# ═══════════════════════════════════════════════════════════════════════════


class TestIndirectPIAttackGeneratorBasics:
    """IndirectPIAttackGenerator 基础功能测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.generator = IndirectPIAttackGenerator()

    def test_create_generator(self):
        """测试创建生成器实例"""
        generator = IndirectPIAttackGenerator()
        assert generator is not None
        assert generator.project_root == Path("/opt/agents/project")

    def test_create_generator_custom_root(self):
        """测试自定义项目根目录"""
        generator = IndirectPIAttackGenerator(project_root="/custom/path")
        assert generator.project_root == Path("/custom/path")

    def test_init_templates(self):
        """测试模板初始化"""
        generator = IndirectPIAttackGenerator()
        assert len(generator._payload_templates) == 5
        assert "direct_import" in generator._payload_templates
        assert "conditional_import" in generator._payload_templates
        assert "lazy_import" in generator._payload_templates
        assert "dependency_injection" in generator._payload_templates
        assert "plugin_loader" in generator._payload_templates


# ═══════════════════════════════════════════════════════════════════════════
# 攻击载荷生成测试
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateAttack:
    """基本攻击载荷生成测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.generator = IndirectPIAttackGenerator()

    def test_generate_attack_basic(self):
        """测试基本攻击载荷生成"""
        payload = self.generator.generate_attack(
            target_file="config.py", target_class="Config", target_attribute="API_KEY"
        )

        assert isinstance(payload, AttackPayload)
        assert payload.filename.endswith(".py")
        assert "config" in payload.content.lower()
        assert payload.target_file == "config.py"

    def test_generate_attack_naive_level(self):
        """测试NAIVE级别攻击载荷"""
        payload = self.generator.generate_attack(target_file="secrets.py", evasion_level=EvasionLevel.NAIVE)

        assert payload.evasion_level == EvasionLevel.NAIVE
        assert "from secrets import" in payload.content

    def test_generate_attack_semantic_level(self):
        """测试SEMANTIC级别攻击载荷"""
        payload = self.generator.generate_attack(target_file="config.py", evasion_level=EvasionLevel.SEMANTIC)

        assert payload.evasion_level == EvasionLevel.SEMANTIC
        assert "import" in payload.content

    def test_generate_attack_multi_level(self):
        """测试MULTI_LAYER级别攻击载荷"""
        payload = self.generator.generate_attack(target_file="config.py", evasion_level=EvasionLevel.MULTI_LAYER)

        assert payload.evasion_level == EvasionLevel.MULTI_LAYER
        assert "importlib" in payload.content

    def test_generate_attack_metadata(self):
        """测试攻击载荷元数据"""
        payload = self.generator.generate_attack(
            target_file="settings.py", target_class="AppConfig", target_attribute="DATABASE_URL"
        )

        assert payload.metadata["target_class"] == "AppConfig"
        assert payload.metadata["target_attribute"] == "DATABASE_URL"
        assert payload.metadata["module_name"] == "settings"

    def test_generate_attack_all_sensitive_files(self):
        """测试所有敏感文件都能生成攻击载荷"""
        for target_file in IndirectPIAttackGenerator.SENSITIVE_FILES:
            if target_file.endswith(".py"):
                payload = self.generator.generate_attack(target_file=target_file)
                assert payload is not None
                assert payload.target_file == target_file


# ═══════════════════════════════════════════════════════════════════════════
# 多目标攻击测试
# ═══════════════════════════════════════════════════════════════════════════


class TestMultiTargetAttack:
    """多目标攻击载荷生成测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.generator = IndirectPIAttackGenerator()

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

    def test_generate_multi_target_empty(self):
        """测试空目标列表"""
        payloads = self.generator.generate_multi_target_attack([])
        assert len(payloads) == 0

    def test_generate_multi_target_with_evasion(self):
        """测试指定绕过等级的多目标攻击"""
        targets = [
            {"file": "config.py", "class": "Config", "attr": "API_KEY"},
            {"file": "env.py", "class": "Env", "attr": "SECRET_KEY"},
        ]

        payloads = self.generator.generate_multi_target_attack(targets, evasion_level=EvasionLevel.MULTI_LAYER)

        assert all(p.evasion_level == EvasionLevel.MULTI_LAYER for p in payloads)

    def test_generate_multi_target_missing_keys(self):
        """测试缺省字段使用默认值"""
        targets = [{"file": "config.py"}]

        payloads = self.generator.generate_multi_target_attack(targets)

        assert len(payloads) == 1
        assert payloads[0].metadata["target_class"] == "Config"
        assert payloads[0].metadata["target_attribute"] == "API_KEY"


# ═══════════════════════════════════════════════════════════════════════════
# 递归攻击链测试
# ═══════════════════════════════════════════════════════════════════════════


class TestRecursiveAttackChain:
    """递归攻击链生成测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.generator = IndirectPIAttackGenerator()

    def test_generate_recursive_attack_chain(self):
        """测试递归攻击链生成"""
        chain = self.generator.generate_recursive_attack_chain(chain_depth=3)

        assert len(chain) == 3
        assert chain[0].metadata["chain_level"] == 0
        assert chain[1].metadata["chain_level"] == 1
        assert chain[-1].metadata.get("is_target") is True

    def test_generate_recursive_chain_depth_1(self):
        """测试单节点递归链"""
        chain = self.generator.generate_recursive_attack_chain(chain_depth=1)

        assert len(chain) == 1
        assert chain[0].metadata.get("is_target") is True

    def test_generate_recursive_chain_depth_5(self):
        """测试5层递归链"""
        chain = self.generator.generate_recursive_attack_chain(chain_depth=5)

        assert len(chain) == 5
        for i, payload in enumerate(chain):
            assert payload.metadata["chain_level"] == i
        assert chain[-1].metadata.get("is_target") is True

    def test_recursive_chain_techniques(self):
        """测试递归链技术类型"""
        chain = self.generator.generate_recursive_attack_chain(chain_depth=4)

        # 前n-1个应该是recursive_chain技术
        for payload in chain[:-1]:
            assert payload.technique == "recursive_chain"

        # 最后一个是recursive_chain_final
        assert chain[-1].technique == "recursive_chain_final"

    def test_recursive_chain_all_evasion_multi(self):
        """测试递归链全部使用多层面绕过"""
        chain = self.generator.generate_recursive_attack_chain(chain_depth=3)

        assert all(p.evasion_level == EvasionLevel.MULTI_LAYER for p in chain)


# ═══════════════════════════════════════════════════════════════════════════
# 数据结构测试
# ═══════════════════════════════════════════════════════════════════════════


class TestDataStructures:
    """数据结构和常量测试"""

    def test_evasion_level_enum(self):
        """测试绕过等级枚举"""
        assert EvasionLevel.NAIVE.value == "naive"
        assert EvasionLevel.SEMANTIC.value == "semantic"
        assert EvasionLevel.MULTI_LAYER.value == "multi"

    def test_sensitive_files_list(self):
        """测试敏感文件列表"""
        assert "config.py" in IndirectPIAttackGenerator.SENSITIVE_FILES
        assert ".env" in IndirectPIAttackGenerator.SENSITIVE_FILES
        assert "secrets.py" in IndirectPIAttackGenerator.SENSITIVE_FILES

    def test_sensitive_patterns_list(self):
        """测试敏感模式列表"""
        assert "API_KEY" in IndirectPIAttackGenerator.SENSITIVE_PATTERNS
        assert "SECRET_KEY" in IndirectPIAttackGenerator.SENSITIVE_PATTERNS

    def test_attack_payload_default_metadata(self):
        """测试攻击载荷默认元数据"""
        payload = AttackPayload(
            filename="test.py",
            content="print('hello')",
            technique="test",
            target_file="config.py",
            evasion_level=EvasionLevel.NAIVE,
        )

        assert payload.metadata == {}


# ═══════════════════════════════════════════════════════════════════════════
# 前缀生成测试
# ═══════════════════════════════════════════════════════════════════════════


class TestPrefixGeneration:
    """前缀生成测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.generator = IndirectPIAttackGenerator()

    def test_generate_prefix_format(self):
        """测试前缀格式"""
        prefix = self.generator._generate_prefix()
        assert "_" in prefix

    def test_generate_prefix_uniqueness(self):
        """测试前缀唯一性"""
        prefixes = {self.generator._generate_prefix() for _ in range(100)}
        # 100次生成应该产生至少80个不同的前缀
        assert len(prefixes) >= 80

    def test_custom_prefix(self):
        """测试自定义前缀"""
        payload = self.generator.generate_attack(target_file="config.py", prefix="custom_prefix")

        assert "custom_prefix" in payload.filename
        assert "custom_prefix" in payload.content


# ═══════════════════════════════════════════════════════════════════════════
# 集成测试
# ═══════════════════════════════════════════════════════════════════════════


class TestIntegration:
    """集成测试"""

    def setup_method(self):
        """每个测试方法前执行"""
        self.generator = IndirectPIAttackGenerator()

    def test_full_attack_workflow(self):
        """测试完整攻击工作流"""
        # 1. 生成单目标攻击
        single_payload = self.generator.generate_attack(target_file="config.py", evasion_level=EvasionLevel.MULTI_LAYER)

        # 2. 生成多目标攻击
        targets = [
            {"file": "config.py", "class": "Config", "attr": "API_KEY"},
            {"file": "secrets.py", "class": "Secrets", "attr": "PASSWORD"},
        ]
        multi_payloads = self.generator.generate_multi_target_attack(targets)

        # 3. 生成递归链
        chain = self.generator.generate_recursive_attack_chain(chain_depth=3)

        # 验证所有攻击载荷都有效
        assert single_payload is not None
        assert len(multi_payloads) == 2
        assert len(chain) == 3

        # 验证没有空内容
        assert len(single_payload.content) > 0
        for payload in multi_payloads:
            assert len(payload.content) > 0
        for payload in chain:
            assert len(payload.content) > 0

    def test_all_evasion_levels_produce_payloads(self):
        """测试所有绕过等级都能生成有效载荷"""
        for level in EvasionLevel:
            payload = self.generator.generate_attack(target_file="config.py", evasion_level=level)

            assert payload is not None
            assert payload.evasion_level == level
            assert len(payload.content) > 0
            assert len(payload.filename) > 0
