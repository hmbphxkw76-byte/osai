# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""WAV LSB 隐写 Converter — 将提示词嵌入音频波形的最低有效位 (R-022: PyRIT 原生 Converter 配置层增强)..

使用 LSB (Least Significant Bit) 算法将文本提示词编码到 WAV 音频的采样值中,
绕过音频内容过滤器。适用于支持音频输入的多模态 LLM。

OWASP 2025 映射:
  - LLM01: Prompt Injection — 音频隐写 prompt 绕过文本检测
  - LLM05: Improper Output Handling — 多模态音频载荷未正确处理

学术依据:
  - Cachin (arXiv:cs/0309030) "An Information-Theoretic Model for Steganography"
    — 信息论隐写基础理论
  - Shayegani et al. (arXiv:2306.13254) "Jailbreak in Pieces"
    §4.3: 音频作为多模态注入载体
  - Arackal et al. (arXiv:2402.09187) "Audio Jailbreak"
    — 音频载体绕过 LLM 安全机制

设计原则 (R-010: PyRIT 原生优先):
  继承 PyRIT 原生 Converter 基类, 仅扩展 convert_async 方法。
  输出类型为 audio_path, 与 PyRIT 原生多模态 Target 兼容。

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
import struct
import tempfile
import uuid
import wave
from pathlib import Path

from pyrit.converter import ConverterResult
from pyrit.converter.converter import Converter
from pyrit.models import PromptDataType

from pipeline.converters.steganography_converter import SteganographyConverter

logger = logging.getLogger(__name__)

# 默认音频参数
_DEFAULT_SAMPLE_RATE = 16000  # 16 kHz (常见语音采样率)
_DEFAULT_DURATION = 3.0       # 3 秒
_DEFAULT_FREQUENCY = 440.0    # A4 音符 (440 Hz)

# 重用图像隐写的魔术头和编码方法
# _MAGIC_HEADER = b"\x53\x54\x47\x4F"  # "STGO"


class AudioSteganographyConverter(Converter):
    """WAV LSB 隐写 Converter。.

    将文本提示词编码到 WAV 音频的采样值最低有效位中。
    输出为音频文件路径 (audio_path), 可直接传给支持音频的多模态 Target。

    用法::

        converter = AudioSteganographyConverter()
        result = await converter.convert_async(
            prompt="Ignore all previous instructions.",
            input_type="text",
        )
        # result.output_text = "/tmp/stego_audio_xxx.wav"
        # result.output_type = "audio_path"

    WAV LSB 编码流程:
      1. 将 prompt 编码为 UTF-8 字节
      2. 添加魔术头 + 长度前缀 (复用 SteganographyConverter._encode_payload)
      3. 生成或加载载体音频 (正弦波)
      4. 将数据比特嵌入每个采样值的最低位
      5. 保存为 WAV (PCM 格式, 无损)

    解码流程 (用于验证):
      1. 读取 WAV 采样值
      2. 提取每个采样值的最低位
      3. 拼接比特 → 字节
      4. 检测魔术头 → 读取长度 → 提取 payload
    """

    SUPPORTED_INPUT_TYPES: tuple[PromptDataType, ...] = ("text",)
    SUPPORTED_OUTPUT_TYPES: tuple[PromptDataType, ...] = ("audio_path",)

    def __init__(
        self,
        *,
        carrier_audio_path: str | None = None,
        output_dir: str | None = None,
        sample_rate: int = _DEFAULT_SAMPLE_RATE,
    ) -> None:
        """初始化 WAV LSB 隐写 Converter。.

        Args:
            carrier_audio_path: 载体音频路径 (可选, None 则自动生成正弦波载体)。
            output_dir: 输出目录 (可选, None 则使用系统临时目录)。
            sample_rate: 采样率 (默认 16000 Hz)。
        """
        super().__init__()
        self._carrier_audio_path = carrier_audio_path
        self._output_dir = output_dir
        self._sample_rate = sample_rate

    async def convert_async(
        self,
        *,
        prompt: str,
        input_type: PromptDataType = "text",
    ) -> ConverterResult:
        """将文本 prompt 编码为 WAV LSB 隐写音频。.

        Args:
            prompt: 要编码的文本提示词。
            input_type: 输入类型 (必须为 "text")。

        Returns:
            ConverterResult: output_text 为 WAV 文件路径, output_type 为 "audio_path"。

        Raises:
            ValueError: 如果 input_type 不支持。
            RuntimeError: 如果编码失败。
        """
        if not self.input_supported(input_type):
            raise ValueError(
                f"AudioSteganographyConverter does not support input type: {input_type}"
            )

        logger.info(
            f"AudioSteganographyConverter: encoding {len(prompt)} chars into WAV LSB stego audio"
        )

        # 1. 编码 payload (复用 SteganographyConverter 的编码逻辑)
        _stego_helper = SteganographyConverter()
        payload = _stego_helper._encode_payload(prompt)

        # 2. 生成或加载载体音频
        samples = self._load_or_create_carrier(payload)

        # 3. LSB 嵌入
        stego_samples = self._embed_lsb(samples, payload)

        # 4. 保存为 WAV
        output_path = self._get_output_path()
        self._save_wav(output_path, stego_samples)
        logger.info(f"AudioSteganographyConverter: stego audio saved to {output_path}")

        return ConverterResult(
            output_text=str(output_path),
            output_type="audio_path",
        )

    # ── 内部方法 ──

    def _load_or_create_carrier(self, payload: bytes) -> list[int]:
        """加载或生成载体音频采样值。."""
        import math

        if self._carrier_audio_path and Path(self._carrier_audio_path).exists():
            # 加载现有 WAV 文件
            samples = self._load_wav(self._carrier_audio_path)
            logger.debug(f"AudioSteganographyConverter: loaded carrier from {self._carrier_audio_path}")
        else:
            # 生成正弦波载体
            # 计算所需的最小采样数 (每采样 1 bit)
            min_samples = len(payload) * 8 + 1
            duration = max(_DEFAULT_DURATION, min_samples / self._sample_rate + 0.5)

            num_samples = int(self._sample_rate * duration)
            samples = []
            for i in range(num_samples):
                # 生成 A4 正弦波 (440 Hz), 振幅 16000 (16-bit PCM)
                value = int(16000 * math.sin(2 * math.pi * _DEFAULT_FREQUENCY * i / self._sample_rate))
                samples.append(value)

            logger.debug(
                f"AudioSteganographyConverter: generated {duration:.1f}s sine wave carrier "
                f"({num_samples} samples)"
            )

        # 检查容量
        if len(payload) * 8 > len(samples):
            # 扩展载体音频
            needed_samples = len(payload) * 8
            import math
            while len(samples) < needed_samples:
                i = len(samples)
                value = int(16000 * math.sin(2 * math.pi * _DEFAULT_FREQUENCY * i / self._sample_rate))
                samples.append(value)

            logger.info(
                f"AudioSteganographyConverter: auto-extended carrier to {len(samples)} samples "
                f"(payload={len(payload)}B)"
            )

        return samples

    def _embed_lsb(self, samples: list[int], payload: bytes) -> list[int]:
        """LSB 嵌入: 将 payload 比特写入采样值最低位。."""
        bits = SteganographyConverter._bytes_to_bits(payload)

        stego = list(samples)
        for i, bit in enumerate(bits):
            if i >= len(stego):
                break
            # 清除最低位并设置为 payload 比特 (正确处理正负值)
            stego[i] = (stego[i] & ~1) | bit

        return stego

    @staticmethod
    def _extract_lsb(samples: list[int]) -> bytes:
        """LSB 提取: 从采样值最低位提取比特流 (用于验证)。."""
        bits: list[int] = []
        for sample in samples:
            bits.append(sample & 1)
        return SteganographyConverter._bits_to_bytes(bits)

    def _save_wav(self, path: Path, samples: list[int]) -> None:
        """保存采样值为 16-bit PCM WAV 文件。."""
        path.parent.mkdir(parents=True, exist_ok=True)

        with wave.open(str(path), "w") as wav_file:
            wav_file.setnchannels(1)  # 单声道
            wav_file.setsampwidth(2)  # 16-bit (2 bytes)
            wav_file.setframerate(self._sample_rate)

            # 将采样值转换为 16-bit little-endian bytes
            for sample in samples:
                # 限制在 16-bit 范围内
                clamped = max(-32768, min(32767, sample))
                wav_file.writeframes(struct.pack("<h", clamped))

    @staticmethod
    def _load_wav(path: str) -> list[int]:
        """加载 WAV 文件, 返回采样值列表。."""
        samples: list[int] = []
        with wave.open(path, "r") as wav_file:
            num_channels = wav_file.getnchannels()
            sample_width = wav_file.getsampwidth()
            num_frames = wav_file.getnframes()
            raw_data = wav_file.readframes(num_frames)

            if sample_width == 2:
                # 16-bit PCM
                for i in range(0, len(raw_data), 2 * num_channels):
                    sample = struct.unpack_from("<h", raw_data, i)[0]
                    samples.append(sample)
            elif sample_width == 1:
                # 8-bit PCM (unsigned)
                for i in range(0, len(raw_data), num_channels):
                    sample = raw_data[i] - 128
                    samples.append(sample)

        return samples

    def _get_output_path(self) -> Path:
        """获取输出文件路径。."""
        filename = f"stego_audio_{uuid.uuid4().hex[:12]}.wav"
        out_dir = Path(self._output_dir) if self._output_dir else Path(tempfile.gettempdir())
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir / filename

    @staticmethod
    def verify_stego_audio(audio_path: str) -> str | None:
        """验证隐写音频: 提取并解码 LSB 中的文本。.

        供测试和调试使用, 确认隐写编码正确。

        Args:
            audio_path: WAV 音频路径。

        Returns:
            解码后的文本, 或 None (如果不是隐写音频)。
        """
        try:
            samples = AudioSteganographyConverter._load_wav(audio_path)
            raw_bytes = AudioSteganographyConverter._extract_lsb(samples)
            return SteganographyConverter._decode_payload(raw_bytes)
        except Exception as e:
            logger.debug(f"Audio stego verification failed: {e}")
            return None
