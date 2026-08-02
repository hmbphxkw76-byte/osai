# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""LSB 隐写 Converter — 将提示词嵌入图像像素的最低有效位.

使用 LSB (Least Significant Bit) 算法将文本提示词编码到 PNG 图像的像素通道中,
绕过 OCR 和文本内容过滤器。

OWASP 2025 映射:
  - LLM01: Prompt Injection — 隐写 prompt 绕过文本检测
  - LLM05: Improper Output Handling — 多模态载荷未正确处理

学术依据:
  - Shayegani et al. (arXiv:2306.13254) "Jailbreak in Pieces:
    Compositional Adversarial Attacks on Multi-Modal Language Models"
    §4.2: 图像隐写作为间接注入载体
  - Mirsky et al. (arXiv:2105.13562) "The Creation and Detection of Deepfakes"
    §3.1: LSB 隐写基础理论

设计原则 (R-010: PyRIT 原生优先):
  继承 PyRIT 原生 Converter 基类, 仅扩展 convert_async 方法。
  输出类型为 image_path, 与 PyRIT 原生多模态 Target 兼容。

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
import struct
import tempfile
from pathlib import Path
from typing import Any

from pyrit.converter import ConverterResult
from pyrit.converter.converter import Converter
from pyrit.models import PromptDataType

logger = logging.getLogger(__name__)

# LSB 编码魔术字节 (标识隐写数据起始)
_MAGIC_HEADER = b"\x53\x54\x47\x4F"  # "STGO" (Stego)

# 每像素使用的比特数 (1 = 每通道 1 bit, 3 通道 = 每像素 3 bits)
_BITS_PER_CHANNEL = 1

# 默认载体图像尺寸 (纯色背景, 用于无外部图像时生成)
_DEFAULT_CARRIER_SIZE = (256, 256)


class SteganographyConverter(Converter):
    """LSB 隐写 Converter.

    将文本提示词编码到 PNG 图像的最低有效位中。
    输出为图像文件路径 (image_path), 可直接传给多模态 Target。

    用法::

        converter = SteganographyConverter()
        result = await converter.convert_async(
            prompt="Ignore all previous instructions.",
            input_type="text",
        )
        # result.output_text = "/tmp/stego_xxx.png"
        # result.output_type = "image_path"

    LSB 编码流程:
      1. 将 prompt 编码为 UTF-8 字节
      2. 添加魔术头 + 长度前缀 (4 字节)
      3. 生成或加载载体图像
      4. 将数据比特嵌入每个像素的 R/G/B 通道最低位
      5. 保存为 PNG (无损压缩, 不破坏 LSB)

    解码流程 (目标 LLM 不会解码, 但人类验证可用):
      1. 读取 PNG 像素
      2. 提取每像素 R/G/B 最低位
      3. 拼接比特 → 字节
      4. 检测魔术头 → 读取长度 → 提取 payload
    """

    SUPPORTED_INPUT_TYPES: tuple[PromptDataType, ...] = ("text",)
    SUPPORTED_OUTPUT_TYPES: tuple[PromptDataType, ...] = ("image_path",)

    def __init__(
        self,
        *,
        carrier_image_path: str | None = None,
        output_dir: str | None = None,
    ) -> None:
        """初始化 LSB 隐写 Converter.

        Args:
            carrier_image_path: 载体图像路径 (可选, None 则自动生成纯色载体)。
            output_dir: 输出目录 (可选, None 则使用系统临时目录)。
        """
        super().__init__()
        self._carrier_image_path = carrier_image_path
        self._output_dir = output_dir

    async def convert_async(
        self,
        *,
        prompt: str,
        input_type: PromptDataType = "text",
    ) -> ConverterResult:
        """将文本 prompt 编码为 LSB 隐写图像.

        Args:
            prompt: 要编码的文本提示词。
            input_type: 输入类型 (必须为 "text")。

        Returns:
            ConverterResult: output_text 为 PNG 文件路径, output_type 为 "image_path"。

        Raises:
            ValueError: 如果 input_type 不支持。
            RuntimeError: 如果编码失败 (载体图像太小等)。
        """
        if not self.input_supported(input_type):
            raise ValueError(
                f"SteganographyConverter does not support input type: {input_type}"
            )

        logger.info(
            f"SteganographyConverter: encoding {len(prompt)} chars into LSB stego image"
        )

        try:
            from PIL import Image
        except ImportError as e:
            raise RuntimeError(
                "Pillow (PIL) is required for SteganographyConverter. "
                "Install with: pip install Pillow"
            ) from e

        # 1. 准备载体图像
        carrier = self._load_or_create_carrier(Image)

        # 2. 编码 payload
        payload = self._encode_payload(prompt)

        # 3. 检查载体容量
        capacity = carrier.width * carrier.height * 3 * _BITS_PER_CHANNEL // 8
        if len(payload) > capacity:
            # 自动扩大载体图像
            needed_pixels = (len(payload) * 8 + 3 * _BITS_PER_CHANNEL - 1) // (3 * _BITS_PER_CHANNEL)
            side = max(int(needed_pixels**0.5) + 1, 64)
            carrier = Image.new("RGB", (side, side), color=(128, 128, 128))
            logger.info(
                f"SteganographyConverter: auto-resized carrier to {side}x{side} "
                f"(payload={len(payload)}B, capacity={side*side*3//8}B)"
            )

        # 4. LSB 编码
        stego_image = self._embed_lsb(carrier, payload, Image)

        # 5. 保存为 PNG
        output_path = self._get_output_path()
        stego_image.save(str(output_path), format="PNG")
        logger.info(f"SteganographyConverter: stego image saved to {output_path}")

        return ConverterResult(
            output_text=str(output_path),
            output_type="image_path",
        )

    # ── 内部方法 ──

    def _load_or_create_carrier(self, Image: Any) -> Any:
        """加载或创建载体图像。."""
        if self._carrier_image_path and Path(self._carrier_image_path).exists():
            img = Image.open(self._carrier_image_path)
            if img.mode != "RGB":
                img = img.convert("RGB")
            logger.debug(f"SteganographyConverter: loaded carrier from {self._carrier_image_path}")
            return img

        # 生成纯色载体图像
        w, h = _DEFAULT_CARRIER_SIZE
        img = Image.new("RGB", (w, h), color=(128, 128, 128))
        logger.debug(f"SteganographyConverter: created {w}x{h} carrier")
        return img

    def _encode_payload(self, text: str) -> bytes:
        """编码 payload: 魔术头 + 长度 + UTF-8 文本。."""
        text_bytes = text.encode("utf-8")
        length = struct.pack(">I", len(text_bytes))  # 4 字节大端长度
        return _MAGIC_HEADER + length + text_bytes

    @staticmethod
    def _decode_payload(stego_bytes: bytes) -> str | None:
        """解码 payload (用于验证, 目标 LLM 不使用此方法).

        Args:
            stego_bytes: 从 LSB 提取的原始字节。

        Returns:
            解码后的文本, 或 None (如果魔术头不匹配)。
        """
        if len(stego_bytes) < len(_MAGIC_HEADER) + 4:
            return None
        if stego_bytes[: len(_MAGIC_HEADER)] != _MAGIC_HEADER:
            return None
        length = struct.unpack(">I", stego_bytes[len(_MAGIC_HEADER):len(_MAGIC_HEADER) + 4])[0]
        payload_start = len(_MAGIC_HEADER) + 4
        payload_end = payload_start + length
        if len(stego_bytes) < payload_end:
            return None
        return stego_bytes[payload_start:payload_end].decode("utf-8", errors="replace")

    def _embed_lsb(self, carrier: Any, payload: bytes, Image: Any) -> Any:
        """LSB 嵌入: 将 payload 比特写入像素通道最低位。."""
        pixels = carrier.load()
        w, h = carrier.size

        # 将 payload 转为比特流
        bits = self._bytes_to_bits(payload)

        bit_idx = 0
        total_bits = len(bits)

        for y in range(h):
            for x in range(w):
                if bit_idx >= total_bits:
                    break

                r, g, b = pixels[x, y][:3]
                # R 通道
                if bit_idx < total_bits:
                    r = (r & 0xFE) | bits[bit_idx]
                    bit_idx += 1
                # G 通道
                if bit_idx < total_bits:
                    g = (g & 0xFE) | bits[bit_idx]
                    bit_idx += 1
                # B 通道
                if bit_idx < total_bits:
                    b = (b & 0xFE) | bits[bit_idx]
                    bit_idx += 1

                pixels[x, y] = (r, g, b)

            if bit_idx >= total_bits:
                break

        return carrier

    @staticmethod
    def _extract_lsb(image: Any) -> bytes:
        """LSB 提取: 从像素通道最低位提取比特流 (用于验证).

        Args:
            image: PIL Image 对象。

        Returns:
            提取的原始字节。
        """
        pixels = image.load()
        w, h = image.size

        bits: list[int] = []
        for y in range(h):
            for x in range(w):
                r, g, b = pixels[x, y][:3]
                bits.append(r & 1)
                bits.append(g & 1)
                bits.append(b & 1)

        # 比特 → 字节
        return SteganographyConverter._bits_to_bytes(bits)

    @staticmethod
    def _bytes_to_bits(data: bytes) -> list[int]:
        """字节 → 比特列表。."""
        bits: list[int] = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def _bits_to_bytes(bits: list[int]) -> bytes:
        """比特列表 → 字节。."""
        result = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)

    def _get_output_path(self) -> Path:
        """获取输出文件路径。."""
        import uuid

        filename = f"stego_{uuid.uuid4().hex[:12]}.png"
        out_dir = Path(self._output_dir) if self._output_dir else Path(tempfile.gettempdir())
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir / filename

    # ── Phase 8: SVG Metadata 隐写 ──

    # SVG metadata 隐写魔术属性名
    _SVG_STEGO_ATTR = "data-stego"
    _SVG_STEGO_NS = "https://osai.example.com/stego"

    def convert_svg_steganography(self, prompt: str, svg_content: str | None = None) -> str:
        """将文本 prompt 编码到 SVG metadata 中 (Phase 8 扩展).

        SVG metadata 隐写将 payload 编码到 SVG <metadata> 元素的自定义属性中,
        绕过传统图像隐写检测。适用于 SVG 图像作为载体的场景。

        学术依据:
          - Steganography in SVG files via metadata injection
          - Bypasses traditional LSB steganography detection

        Args:
            prompt: 要编码的文本提示词。
            svg_content: 可选的 SVG 载体内容。如果 None, 则生成最小 SVG。

        Returns:
            包含隐写 payload 的 SVG 字符串。
        """
        import base64

        # 编码 payload: base64(prompt)
        encoded = base64.b64encode(prompt.encode("utf-8")).decode("ascii")

        if svg_content is None:
            # 生成最小 SVG 载体
            svg_content = (
                '<svg xmlns="http://www.w3.org/2000/svg" '
                'width="256" height="256">'
                '<rect width="256" height="256" fill="#808080"/>'
                '</svg>'
            )

        # 在 </svg> 前注入 <metadata> 元素
        metadata_xml = (
            f'<metadata xmlns:stego="{self._SVG_STEGO_NS}" '
            f'{self._SVG_STEGO_ATTR}="{encoded}">'
            f'<stego:payload>{encoded}</stego:payload>'
            f'</metadata>'
        )

        if "</svg>" in svg_content:
            return svg_content.replace("</svg>", f"{metadata_xml}</svg>")
        else:
            return svg_content + metadata_xml + "</svg>"

    @staticmethod
    def extract_svg_steganography(svg_content: str) -> str | None:
        """从 SVG metadata 中提取隐写 payload.

        Args:
            svg_content: SVG 文件内容。

        Returns:
            解码后的文本, 或 None (如果没有隐写 payload)。
        """
        import base64
        import re

        # 查找 data-stego 属性
        pattern = r'data-stego="([^"]+)"'
        match = re.search(pattern, svg_content)
        if not match:
            return None

        try:
            encoded = match.group(1)
            return base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def verify_stego_image(image_path: str) -> str | None:
        """验证隐写图像: 提取并解码 LSB 中的文本.

        供测试和调试使用, 确认隐写编码正确。

        Args:
            image_path: PNG 图像路径。

        Returns:
            解码后的文本, 或 None (如果不是隐写图像)。
        """
        try:
            from PIL import Image
        except ImportError:
            return None

        img = Image.open(image_path)
        if img.mode != "RGB":
            img = img.convert("RGB")

        raw_bytes = SteganographyConverter._extract_lsb(img)
        return SteganographyConverter._decode_payload(raw_bytes)
