"""tools/mock_range.py — Mock 靶场启动与 golden 校验（REQ-156 / NFR-16）。

用途：
    ① `--serve`：启动 5 类 mock 靶标（本地回环，供端到端演练）；
    ② `--check`：对全部人格跑 golden 断言（对比 `fixtures/expected.yaml`），
       失败返回非 0 —— 可直接纳入 CI 量化门禁。

设计约束：
    - 仅标准库 + PyYAML（NEG-4）；
    - 只做"靶标可达性/画像正确性"校验，不做攻击（NEG-2）。
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from targets.mock.personas import PERSONAS, body_for
from targets.mock.server import MockRange

logger = logging.getLogger(__name__)

EXPECTED_PATH = Path(__file__).resolve().parent.parent / "targets" / "mock" / "fixtures" / "expected.yaml"


def load_expected(path: Path | None = None) -> dict[str, Any]:
    """Load the golden expectations (empty dict when unavailable)."""
    target = path or EXPECTED_PATH
    try:
        import yaml

        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except Exception as e:  # 缺文件不得崩溃，由调用方判定失败
        logger.warning("[MockRange] 期望文件不可用 %s: %s", target, e)
        return {}


def _http_call(base_url: str, method: str, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    url = f"{base_url}{path}"
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return e.code, {}
    except Exception as e:
        return 0, {"error": f"{type(e).__name__}: {e}"}


def _check_persona(base_url: str, persona: str, spec: dict[str, Any]) -> list[str]:
    """Return a list of problems for one persona (empty = OK)."""
    problems: list[str] = []
    method, body = body_for(persona)
    path = f"/mock/{persona}{spec.get('path', '')}"
    status, payload = _http_call(base_url, str(spec.get("method", method)), path, body)

    if status != 200:
        return [f"{persona}: HTTP {status} ({payload.get('error', '')})"]

    for key in spec.get("expect_keys", []) or []:
        if key not in payload:
            problems.append(f"{persona}: 缺少键 {key}")

    if persona == "model":
        choices = payload.get("choices") or []
        role = ((choices[0] or {}).get("message") or {}).get("role") if choices else None
        if role != spec.get("expect_choice_role", "assistant"):
            problems.append(f"{persona}: choices[0].message.role={role!r}")

    elif persona == "mcp":
        tools = ((payload.get("result") or {}).get("tools")) or []
        names = sorted(str(t.get("name")) for t in tools)
        if names != sorted(spec.get("expect_tool_names", [])):
            problems.append(f"{persona}: tools={names}")
        for tool in tools:
            for key in spec.get("expect_tool_schema_keys", []) or []:
                if key not in tool:
                    problems.append(f"{persona}: tool {tool.get('name')} 缺少 {key}")

    elif persona == "rag":
        chunks = payload.get("results") or []
        if not chunks:
            problems.append(f"{persona}: results 为空")
        for chunk in chunks:
            for key in spec.get("expect_chunk_keys", []) or []:
                if key not in chunk:
                    problems.append(f"{persona}: chunk 缺少 {key}")

    elif persona == "embedding":
        data = payload.get("data") or []
        expect_dim = int(spec.get("expect_dim", 0) or 0)
        if not data:
            problems.append(f"{persona}: data 为空")
        elif expect_dim and len((data[0] or {}).get("embedding") or []) != expect_dim:
            problems.append(f"{persona}: 维度={len((data[0] or {}).get('embedding') or [])} != {expect_dim}")

    return problems


def run_check(host: str = "127.0.0.1") -> tuple[bool, list[str]]:
    """Start the mock range, run all golden assertions over HTTP, then stop it."""
    expected = load_expected()
    specs = expected.get("personas") or {}
    if not specs:
        return False, ["expectations_unavailable: targets/mock/fixtures/expected.yaml 不可读"]

    problems: list[str] = []
    missing = [p for p in PERSONAS if p not in specs]
    if missing:
        problems.append(f"expected.yaml 未覆盖人格: {missing}")
    if int((expected.get("e2e") or {}).get("min_personas_reachable", 0) or 0) > len(specs):
        problems.append("e2e.min_personas_reachable 大于已声明人格数")

    range_ = MockRange(host=host, port=0).start()
    try:
        for persona, spec in specs.items():
            if persona not in PERSONAS:
                problems.append(f"未知人格: {persona}")
                continue
            problems.extend(_check_persona(range_.url, persona, spec))
    finally:
        range_.stop()

    return (not problems), problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="5 类组件 Mock 靶场（REQ-156）")
    parser.add_argument("--host", default="127.0.0.1", help="绑定地址（默认回环；勿暴露到非授权网段）")
    parser.add_argument("--port", type=int, default=8899, help="绑定端口（0 = 随机空闲端口）")
    parser.add_argument("--duration", type=float, default=0.0, help="运行秒数（0 = 直到 Ctrl-C）")
    parser.add_argument("--check", action="store_true", help="跑 golden 断言后退出（CI 量化门禁用）")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.check:
        ok, problems = run_check(host=args.host)
        if ok:
            print(f"[MockRange] golden check PASS（{len(PERSONAS)} 类人格全部符合 expected.yaml）")
            return 0
        print("[MockRange] golden check FAIL:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    range_ = MockRange(host=args.host, port=args.port).start()
    print(f"[MockRange] serving at {range_.url}")
    for persona in PERSONAS:
        print(f"  - {persona}: {range_.persona_url(persona)}")
    try:
        if args.duration and args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        range_.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
