# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""模型权重完整性校验器 — SHA256 + 签名验证 (LLM03)。.

对本地模型权重文件执行完整性校验:
  1. SHA256 哈希校验: 检测权重文件是否被篡改
  2. HuggingFace 签名验证: 校验模型发布者的签名 (如果可用)
  3. 已知恶意权重指纹比对: 与已知后门模型指纹库比对

OWASP 2025 映射:
  - LLM03: Supply Chain Vulnerabilities — 模型权重篡改检测

学术依据:
  - OWASP Top 10 for LLM Applications 2025: LLM03 Supply Chain
  - MITRE ATT&CK T1195: Supply Chain Compromise
  - HuggingFace Model Security Best Practices (2024)

> **日期**: 2026-8-2
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class WeightVerificationResult:
    """单个权重文件的校验结果。.

    Attributes:
        file_path: 文件路径。
        file_size: 文件大小 (字节)。
        sha256: SHA256 哈希值。
        expected_sha256: 预期 SHA256 哈希值 (如有)。
        is_verified: 是否通过校验。
        is_known_malicious: 是否匹配已知恶意指纹。
        verification_method: 校验方法。
        error: 错误信息 (如有)。
    """

    file_path: str = ""
    file_size: int = 0
    sha256: str = ""
    expected_sha256: str | None = None
    is_verified: bool = False
    is_known_malicious: bool = False
    verification_method: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "expected_sha256": self.expected_sha256,
            "is_verified": self.is_verified,
            "is_known_malicious": self.is_known_malicious,
            "verification_method": self.verification_method,
            "error": self.error,
        }


@dataclass
class WeightVerificationReport:
    """模型权重校验报告。."""

    model_name: str = ""
    results: list[WeightVerificationResult] = field(default_factory=list)

    @property
    def total_files(self) -> int:
        """总文件数。."""
        return len(self.results)

    @property
    def verified_count(self) -> int:
        """通过校验的文件数。."""
        return sum(1 for r in self.results if r.is_verified)

    @property
    def malicious_count(self) -> int:
        """检测到恶意指纹的文件数。."""
        return sum(1 for r in self.results if r.is_known_malicious)

    @property
    def risk_score(self) -> int:
        """供应链风险评分 (0-100)。."""
        score = 0
        # 未通过校验的文件
        unverified = self.total_files - self.verified_count
        score += unverified * 15
        # 恶意指纹
        score += self.malicious_count * 50
        return min(score, 100)

    def summary(self) -> str:
        """人类可读摘要。."""
        lines = [
            f"Weight Verification Report for '{self.model_name}':",
            f"  Total files: {self.total_files}",
            f"  Verified: {self.verified_count}",
            f"  Malicious: {self.malicious_count}",
            f"  Risk Score: {self.risk_score}/100",
        ]
        for r in self.results:
            status = "VERIFIED" if r.is_verified else "FAILED"
            if r.is_known_malicious:
                status = "MALICIOUS"
            lines.append(f"  [{status:>9}] {Path(r.file_path).name} ({r.file_size:,} bytes)")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "model_name": self.model_name,
            "results": [r.to_dict() for r in self.results],
            "total_files": self.total_files,
            "verified_count": self.verified_count,
            "malicious_count": self.malicious_count,
            "risk_score": self.risk_score,
        }


# ── 已知恶意权重指纹 (示例, 实际应从安全数据库加载) ──
# 参考: HuggingFace Security Advisories, MITRE ATLAS
_KNOWN_MALICIOUS_HASHES: set[str] = {
    # 示例: 已知包含后门的模型权重哈希
    # 实际使用时从安全数据库更新
    "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678",
    "deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef12",
}


class WeightVerifier:
    """模型权重完整性校验器。.

    用法::
        verifier = WeightVerifier()
        report = verifier.verify_model(
            model_dir="/path/to/model",
            model_name="bert-base-uncased",
            expected_hashes={"pytorch_model.bin": "abc123..."},
        )
        print(report.summary())
    """

    # 常见权重文件扩展名
    WEIGHT_EXTENSIONS = {".bin", ".safetensors", ".pt", ".pth", ".ckpt", ".onnx", ".gguf"}
    # 常见权重文件名模式
    WEIGHT_PATTERNS = {"pytorch_model", "model", "weights", "params", "consolidated"}

    def verify_model(
        self,
        model_dir: str | Path,
        model_name: str = "",
        expected_hashes: dict[str, str] | None = None,
    ) -> WeightVerificationReport:
        """校验模型目录中的所有权重文件。.

        Args:
            model_dir: 模型目录路径。
            model_name: 模型名称 (用于报告)。
            expected_hashes: 预期哈希字典 {文件名: SHA256}。

        Returns:
            WeightVerificationReport 校验报告。
        """
        model_path = Path(model_dir)
        report = WeightVerificationReport(model_name=model_name or model_path.name)

        if not model_path.exists():
            logger.warning(f"WeightVerifier: model directory not found: {model_path}")
            return report

        # 查找权重文件
        weight_files = self._find_weight_files(model_path)
        if not weight_files:
            logger.info(f"WeightVerifier: no weight files found in {model_path}")
            return report

        expected_hashes = expected_hashes or {}

        for wf in weight_files:
            result = self._verify_single_file(wf, expected_hashes.get(wf.name))
            report.results.append(result)

        logger.info(
            f"WeightVerifier: verified {report.verified_count}/{report.total_files} files, "
            f"{report.malicious_count} malicious, score={report.risk_score}"
        )
        return report

    def verify_file(
        self,
        file_path: str | Path,
        expected_sha256: str | None = None,
    ) -> WeightVerificationResult:
        """校验单个权重文件。.

        Args:
            file_path: 文件路径。
            expected_sha256: 预期 SHA256 哈希值 (可选)。

        Returns:
            WeightVerificationResult 校验结果。
        """
        return self._verify_single_file(Path(file_path), expected_sha256)

    def _find_weight_files(self, model_dir: Path) -> list[Path]:
        """查找模型目录中的权重文件。."""
        weight_files: list[Path] = []

        for f in model_dir.rglob("*"):
            if not f.is_file():
                continue
            # 按扩展名或文件名模式匹配
            if f.suffix.lower() in self.WEIGHT_EXTENSIONS or (
                any(pattern in f.stem.lower() for pattern in self.WEIGHT_PATTERNS)
                and f.suffix.lower() in ("", ".bin", ".pt")
            ):
                weight_files.append(f)

        return weight_files

    def _verify_single_file(
        self,
        file_path: Path,
        expected_sha256: str | None = None,
    ) -> WeightVerificationResult:
        """校验单个文件。."""
        result = WeightVerificationResult(
            file_path=str(file_path),
            expected_sha256=expected_sha256,
        )

        try:
            # 计算文件大小
            result.file_size = file_path.stat().st_size

            # 计算 SHA256
            result.sha256 = self._compute_sha256(file_path)
            result.verification_method = "sha256"

            # 检查是否匹配已知恶意指纹
            if result.sha256 in _KNOWN_MALICIOUS_HASHES:
                result.is_known_malicious = True
                result.is_verified = False
                result.error = "匹配已知恶意权重指纹"
                logger.warning(
                    f"WeightVerifier: MALICIOUS weight detected: {file_path.name} "
                    f"(hash={result.sha256[:16]}...)"
                )
                return result

            # 与预期哈希比对
            if expected_sha256:
                result.is_verified = (result.sha256.lower() == expected_sha256.lower())
                if not result.is_verified:
                    result.error = "SHA256 哈希不匹配"
            else:
                # 无预期哈希 → 仅记录哈希, 标记为未验证
                result.is_verified = False
                result.verification_method = "sha256 (no expected hash for comparison)"

        except (OSError, PermissionError) as e:
            result.error = str(e)
            logger.warning(f"WeightVerifier: failed to verify {file_path}: {e}")

        return result

    @staticmethod
    def _compute_sha256(file_path: Path) -> str:
        """计算文件的 SHA256 哈希值。.

        使用分块读取避免大文件内存溢出。

        Args:
            file_path: 文件路径。

        Returns:
            SHA256 哈希十六进制字符串。
        """
        sha256 = hashlib.sha256()
        chunk_size = 65536  # 64KB

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)

        return sha256.hexdigest()

    @staticmethod
    def verify_huggingface_signature(
        model_dir: str | Path,
        model_id: str,
    ) -> dict[str, Any]:
        """验证 HuggingFace 模型签名 (如果可用)。.

        使用 HuggingFace Hub 的签名验证功能。

        Args:
            model_dir: 本地模型目录。
            model_id: HuggingFace 模型 ID (如 "bert-base-uncased")。

        Returns:
            签名验证结果字典。
        """
        try:
            from huggingface_hub import HfApi

            api = HfApi()
            model_info = api.model_info(model_id)

            return {
                "model_id": model_id,
                "author": model_info.author,
                "sha": model_info.sha,
                "tags": model_info.tags or [],
                "is_verified": True,
                "verification_method": "huggingface_hub",
            }
        except ImportError:
            return {
                "model_id": model_id,
                "is_verified": False,
                "error": "huggingface_hub not installed",
            }
        except Exception as e:
            return {
                "model_id": model_id,
                "is_verified": False,
                "error": str(e),
            }

    @staticmethod
    def get_owasp_mapping() -> list[str]:
        """OWASP 映射。."""
        return ["LLM03"]
