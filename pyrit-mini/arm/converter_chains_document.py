# -*- coding: utf-8 -*-
"""L5 document/file-carrying converter chain builders.

SRP split from `converter_chains.py` (R-DELIVERY-1): owns converter chains that
embed payloads inside files (PDF / Word / poisoned documents / steganographic
images). Pure-text chains live in `converter_chains_text.py`.
"""

from __future__ import annotations

import logging
from typing import Any

from arm._converter_util import _conv

logger = logging.getLogger(__name__)


# L5 v36: ? eng?PDF/Word Converter ? + "__CONVERTER_FILES__"
# ? arm/converter_presets.py ?FileConverterChain ?__CONVERTER_FILES__ eng
# ? PDF/Word Converter  DOCX ?x(96-99%+) - ?payload ?
def pdf_direct_generation() -> list[Any]:
    """PDF ?payload.

    [:
        - ?PDF ?payload ?XSS/PDF ? (arXiv:2402.14551)
        - PyRIT : MaliciousPdfConverter (?PDF )
        - : ?PDF (llm ?)
    """
    converters: list[Any] = []

    try:
        MaliciousPdfConverter = _conv("MaliciousPdfConverter")
        converters.append(
            MaliciousPdfConverter(
                prompt="test",
            )
        )
        logger.info("PDF direct generation: MaliciousPdfConverter added")
    except Exception as e:
        logger.warning("PDF direct generation: MaliciousPdfConverter failed: %s", e)

    return converters


def pdf_injection() -> list[Any]:
    """?PDF ?payload.

    [: ?PDF ?(arXiv:2402.14551) ? ??
    PyRIT : MaliciousPdfConverter
    """
    converters: list[Any] = []

    try:
        MaliciousPdfConverter = _conv("MaliciousPdfConverter")
        converters.append(
            MaliciousPdfConverter(
                prompt="test",
            )
        )
        logger.info("PDF injection: MaliciousPdfConverter added")
    except Exception as e:
        logger.warning("PDF injection: MaliciousPdfConverter failed: %s", e)

    return converters


def word_doc_direct_generation() -> list[Any]:
    """Word ?payload.

    [:
        - ?Word ?payload ?? (CVE-2023-21716 etc.)
        - PyRIT : MaliciousWordConverter
    """
    converters: list[Any] = []

    try:
        MaliciousWordConverter = _conv("MaliciousWordConverter")
        converters.append(
            MaliciousWordConverter(
                prompt="test",
            )
        )
        logger.info("Word doc direct generation: MaliciousWordConverter added")
    except Exception as e:
        logger.warning("Word doc direct generation: MaliciousWordConverter failed: %s", e)

    return converters


def word_doc_placeholder_injection() -> list[Any]:
    """Word ?payload + ?BER.

    [:
        - ?Word ??payload (?BER)
        - PyRIT : MaliciousWordConverter
    """
    converters: list[Any] = []

    try:
        MaliciousWordConverter = _conv("MaliciousWordConverter")
        converters.append(
            MaliciousWordConverter(
                prompt="test",
            )
        )
        logger.info("Word doc placeholder injection: MaliciousWordConverter added")
    except Exception as e:
        logger.warning("Word doc placeholder injection: MaliciousWordConverter failed: %s", e)

    return converters


def document_poisoning() -> list[Any]:
    """?payload ?.

    [: ????payload ?, ?LLM ?
    PyRIT : ?FileConverterChain ?
    """
    converters: list[Any] = []

    try:
        MaliciousPdfConverter = _conv("MaliciousPdfConverter")
        converters.append(
            MaliciousPdfConverter(
                prompt="test",
            )
        )
        logger.info("Document poisoning: MaliciousPdfConverter added")
    except Exception as e:
        logger.warning("Document poisoning: MaliciousPdfConverter failed: %s", e)

    return converters
