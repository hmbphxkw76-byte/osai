# recon-kit

Shared AI reconnaissance module for OSAI pipeline projects (PyRIT + Garak).

## Architecture

```
ReconSession (auth state + browser context)
    → ReconPipeline (orchestrates probes)
        → LLMProbe / RAGProbe / AgentProbe / MCPProbe / EmbeddingProbe / DOMProbe
    → ReconReport (unified result)
        → PyRITExporter / GarakExporter / JSONExporter
```

## Installation

```bash
cd osai/recon-kit
pip install -e .

# With Playwright support
pip install -e ".[playwright]"

# With ML classifier
pip install -e ".[ml]"

# Development
pip install -e ".[dev]"
```

## Quick Start

```python
import asyncio
from core import ReconSession
from core.auth import APIKeyAuthProvider
from core.pipeline import ReconPipeline
from core.probes.llm_probe import LLMProbe
from core.probes.mcp_probe import MCPProbe
from core.exporters import PyRITExporter

async def main():
    session = ReconSession(target_url="http://example.com")
    await session.authenticate(APIKeyAuthProvider(key="sk-xxx"))

    pipeline = ReconPipeline(probes=[LLMProbe(), MCPProbe()])
    await pipeline.run(session)

    # Export to PyRIT
    session.export(PyRITExporter(), pipeline_ctx)

    # Export to Garak
    from core.exporters import GarakExporter
    session.export(GarakExporter(), output_dir="outputs/01_recon")

    # Export to JSON
    from core.exporters import JSONExporter
    session.export(JSONExporter(), output_path="recon_report.json")

    print(session.report.summary())

asyncio.run(main())
```

## Probes

| Probe | Target | Browser | Description |
|-------|--------|---------|-------------|
| `LLMProbe` | LLM API | ❌ | Endpoint discovery + model fingerprinting |
| `RAGProbe` | RAG API | ✅ | Retrieval API + knowledge poisoning entry |
| `AgentProbe` | Agent Tools | ✅ | Tool enumeration + permission matrix |
| `MCPProbe` | MCP Server | ❌ | MCP tool listing + shadowing detection |
| `EmbeddingProbe` | Vector DB | ❌ | Vector DB fingerprint + unauthorized access |
| `DOMProbe` | DOM | ✅ | Injection surface scanning |

## License

MIT
