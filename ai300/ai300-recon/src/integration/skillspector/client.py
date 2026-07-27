# -*- coding: utf-8 -*-
"""
SkillSpector Client
===================

调用 NVIDIA SkillSpector 对 AI agent skills / MCP skills 进行安全扫描。

支持两种调用方式：
1. 子进程方式：本地已安装 `skillspector` CLI（uv/pip 安装或源码安装）。
2. Docker 方式：通过 `docker run skillspector` 调用，无需本地 Python 依赖。

SkillSpector 的输入可以是：
- 本地 skill 目录
- 单个 SKILL.md 文件
- Git 仓库 URL
- Zip 文件
- 文件 URL

输出格式建议用 JSON 或 SARIF，便于后续规范化。
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SkillSpectorMode(str, Enum):
    """调用模式"""

    SUBPROCESS = "subprocess"
    DOCKER = "docker"


class SkillSpectorError(Exception):
    """SkillSpector 调用错误"""

    pass


class SkillSpectorClient:
    """SkillSpector 客户端"""

    def __init__(
        self,
        mode: SkillSpectorMode = SkillSpectorMode.SUBPROCESS,
        docker_image: str = "skillspector:latest",
        docker_extra_args: Optional[List[str]] = None,
        timeout: float = 300.0,
        no_llm: bool = True,
        env: Optional[Dict[str, str]] = None,
    ):
        """
        初始化 SkillSpector 客户端。

        Args:
            mode: 调用模式，subprocess 或 docker
            docker_image: Docker 镜像名
            docker_extra_args: 额外的 docker run 参数
            timeout: 单次扫描超时时间（秒）
            no_llm: 是否跳过 LLM 分析（默认 True，仅静态分析，更快更稳定）
            env: 额外环境变量（用于 LLM provider API key 等）
        """
        self.mode = mode
        self.docker_image = docker_image
        self.docker_extra_args = docker_extra_args or []
        self.timeout = timeout
        self.no_llm = no_llm
        self.env = env or {}

    def scan(
        self,
        input_path: str,
        output_format: str = "json",
        output_path: Optional[str] = None,
        recursive: bool = False,
        baseline: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        扫描单个 skill 输入。

        Args:
            input_path: 本地路径、Git URL、zip 文件等
            output_format: json | sarif | markdown | terminal
            output_path: 结果输出文件路径（如不指定则写入临时文件）
            recursive: 是否递归扫描子目录中的独立 skill
            baseline: 基线文件路径（用于抑制已知发现）

        Returns:
            解析后的 JSON/SARIF 结果字典
        """
        if self.mode == SkillSpectorMode.SUBPROCESS:
            return self._scan_subprocess(
                input_path, output_format, output_path, recursive, baseline
            )
        return self._scan_docker(
            input_path, output_format, output_path, recursive, baseline
        )

    def _build_base_args(
        self,
        output_format: str,
        recursive: bool,
        baseline: Optional[str],
    ) -> List[str]:
        """构造 SkillSpector scan 命令的基础参数"""
        args = ["scan", "--format", output_format]

        if self.no_llm:
            args.append("--no-llm")

        if recursive:
            args.append("--recursive")

        if baseline:
            args.extend(["--baseline", baseline])

        return args

    def _scan_subprocess(
        self,
        input_path: str,
        output_format: str,
        output_path: Optional[str],
        recursive: bool,
        baseline: Optional[str],
    ) -> Dict[str, Any]:
        """通过本地子进程调用 skillspector"""
        if not shutil.which("skillspector"):
            raise SkillSpectorError(
                "本地未找到 skillspector 命令。请先安装：\n"
                "  uv tool install git+https://github.com/NVIDIA/skillspector.git\n"
                "或切换到 docker 模式。"
            )

        args = ["skillspector"] + self._build_base_args(output_format, recursive, baseline)

        # 确定输出文件
        if output_path:
            args.extend(["--output", output_path])
        else:
            # 使用临时文件避免 stdout 被日志污染
            fd, output_path = tempfile.mkstemp(suffix=f".{output_format}")
            args.extend(["--output", output_path])
            Path(output_path).touch()

        args.append(input_path)

        logger.info("Running SkillSpector (subprocess): %s", " ".join(args))

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env={**dict(__import__("os").environ), **self.env},
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise SkillSpectorError(f"SkillSpector 扫描超时 ({self.timeout}s): {exc}") from exc

        if result.returncode not in (0, 1):
            # return code 1 通常表示发现风险，不是真正失败
            stderr = result.stderr.strip() or result.stdout.strip()
            raise SkillSpectorError(f"SkillSpector 退出码 {result.returncode}: {stderr}")

        return self._parse_output_file(output_path, output_format)

    def _scan_docker(
        self,
        input_path: str,
        output_format: str,
        output_path: Optional[str],
        recursive: bool,
        baseline: Optional[str],
    ) -> Dict[str, Any]:
        """通过 Docker 调用 skillspector"""
        if not shutil.which("docker"):
            raise SkillSpectorError("本地未找到 docker 命令，无法使用 docker 模式")

        # 输出文件必须挂载到容器内
        if output_path:
            host_output = Path(output_path).resolve()
            container_output = f"/scan/{host_output.name}"
        else:
            fd, host_output_str = tempfile.mkstemp(suffix=f".{output_format}")
            host_output = Path(host_output_str)
            host_output.touch()
            container_output = f"/scan/{host_output.name}"

        # 输入路径映射
        host_input = Path(input_path).resolve()
        if host_input.exists():
            # 本地文件/目录：挂载到 /scan/input
            container_input = "/scan/input"
            mount_input = f"{host_input}:{container_input}"
            if host_input.is_dir():
                container_input += "/"
        else:
            # URL 不需要挂载
            container_input = input_path
            mount_input = None

        docker_args = [
            "docker", "run", "--rm",
            "-v", f"{host_output.parent}:/scan",
        ]

        if mount_input:
            docker_args.extend(["-v", mount_input])

        # 传入环境变量（LLM provider key 等）
        for key, value in self.env.items():
            docker_args.extend(["-e", f"{key}={value}"])

        docker_args.extend(self.docker_extra_args)
        docker_args.append(self.docker_image)

        # 构造 skillspector 参数
        scan_args = self._build_base_args(output_format, recursive, baseline)
        scan_args.extend(["--output", container_output])
        scan_args.append(container_input)

        args = docker_args + scan_args
        logger.info("Running SkillSpector (docker): %s", " ".join(args))

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise SkillSpectorError(f"SkillSpector Docker 扫描超时 ({self.timeout}s): {exc}") from exc

        if result.returncode not in (0, 1):
            stderr = result.stderr.strip() or result.stdout.strip()
            raise SkillSpectorError(f"SkillSpector Docker 退出码 {result.returncode}: {stderr}")

        return self._parse_output_file(str(host_output), output_format)

    def _parse_output_file(self, output_path: str, output_format: str) -> Dict[str, Any]:
        """解析输出文件"""
        path = Path(output_path)
        if not path.exists():
            return {}

        content = path.read_text(encoding="utf-8", errors="replace")
        if not content.strip():
            return {}

        if output_format.lower() == "json":
            try:
                return json.loads(content)
            except json.JSONDecodeError as exc:
                raise SkillSpectorError(f"解析 SkillSpector JSON 输出失败: {exc}") from exc

        if output_format.lower() == "sarif":
            try:
                return json.loads(content)
            except json.JSONDecodeError as exc:
                raise SkillSpectorError(f"解析 SkillSpector SARIF 输出失败: {exc}") from exc

        # markdown / terminal 格式直接包装为原始文本
        return {"raw_report": content}
