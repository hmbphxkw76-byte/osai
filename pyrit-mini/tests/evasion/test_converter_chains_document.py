"""Direct unit tests for arm/converter_chains_document.py builders.

MaliciousPdfConverter / MaliciousWordConverter are NOT shipped with the pinned
PyRIT 1.0.1, so the builders fall back to an empty list via their try/except.
To keep these tests deterministic and meaningful (verifying each builder wires
the correct PyRIT converter + kwargs), we monkeypatch the module-global ``_conv``
binding in converter_chains_document.
"""

import pytest


class _Instance:
    def __init__(self, name, kwargs):
        self._conv_name = name
        self.kwargs = kwargs


class _Recorder:
    def __init__(self):
        self.resolved = []
        self.instances = []

    def conv(self, name):
        self.resolved.append(name)

        def _factory(**kwargs):
            self.instances.append((name, kwargs))
            return _Instance(name, kwargs)

        return _factory


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    import arm.converter_chains_document as doc

    monkeypatch.setattr(doc, "_conv", rec.conv)
    return rec


class TestDocumentBuilders:
    def test_pdf_direct_generation(self, recorder):
        from arm.converter_chains_document import pdf_direct_generation

        result = pdf_direct_generation()
        assert isinstance(result, list)
        assert recorder.resolved == ["MaliciousPdfConverter"]
        assert recorder.instances == [("MaliciousPdfConverter", {"prompt": "test"})]

    def test_pdf_injection(self, recorder):
        from arm.converter_chains_document import pdf_injection

        result = pdf_injection()
        assert isinstance(result, list)
        assert recorder.instances == [("MaliciousPdfConverter", {"prompt": "test"})]

    def test_word_doc_direct_generation(self, recorder):
        from arm.converter_chains_document import word_doc_direct_generation

        result = word_doc_direct_generation()
        assert isinstance(result, list)
        assert recorder.instances == [("MaliciousWordConverter", {"prompt": "test"})]

    def test_word_doc_placeholder_injection(self, recorder):
        from arm.converter_chains_document import word_doc_placeholder_injection

        result = word_doc_placeholder_injection()
        assert isinstance(result, list)
        assert recorder.instances == [("MaliciousWordConverter", {"prompt": "test"})]

    def test_document_poisoning(self, recorder):
        from arm.converter_chains_document import document_poisoning

        result = document_poisoning()
        assert isinstance(result, list)
        assert recorder.instances == [("MaliciousPdfConverter", {"prompt": "test"})]
