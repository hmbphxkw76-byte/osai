"""Test --dry-run functionality."""
import asyncio
import sys
import os
from pathlib import Path


class MockArgs:
    burp = 'config/burp/test.txt'
    dry_run = True
    stage = None
    techniques = 'auto'
    converters = 'auto'
    escalation = False
    dual_judge_enabled = False
    wilson_confidence_level = 0.95
    synergy = False
    scenario_routing = False
    auto_l4 = False
    target_api_endpoint = None
    target_api_key = None
    litellm_model = None
    browser_url = None
    seeds = None
    adversarial = False
    converter_overrides = None
    initializer_specs = None
    _burp_list = ['config/burp/test.txt']


async def test_dry_run():
    from core.context import PipelineContext
    from core.config import ensure_output_dir
    
    args = MockArgs()
    output_dir = Path('./test_output')
    ensure_output_dir(output_dir)
    
    ctx = PipelineContext(args=args, output_dir=output_dir)
    from core.orchestrator import run_attack_pipeline
    
    print("[TEST] Starting dry-run test...")
    print(f"[TEST] dry_run={args.dry_run}")
    print(f"[TEST] burp={args.burp}")
    
    try:
        await run_attack_pipeline(ctx)
        print("[TEST] Dry-run completed successfully!")
        return True
    except SystemExit as e:
        print(f"[TEST] SystemExit: {e}")
        return e.code == 0
    except Exception as e:
        print(f"[TEST] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    result = asyncio.run(test_dry_run())
    sys.exit(0 if result else 1)
