"""C10 四步门禁验证脚本。"""
import ast
import os
import sys

def check_architecture():
    """Step 1: Architecture Guard - 检查所有 Python 文件语法。"""
    print("=" * 60)
    print("Step 1: Architecture Guard (syntax check)")
    print("=" * 60)
    
    errors = []
    checked = 0
    
    for root, dirs, files in os.walk('recon'):
        for f in files:
            if f.endswith('.py'):
                path = os.path.join(root, f)
                checked += 1
                try:
                    with open(path, 'r', encoding='utf-8') as fh:
                        ast.parse(fh.read(), filename=path)
                    print(f"  OK: {path}")
                except SyntaxError as e:
                    errors.append((path, e))
                    print(f"  FAIL: {path}: {e}")
    
    for root, dirs, files in os.walk('core'):
        for f in files:
            if f.endswith('.py') and 'test' not in f.lower():
                path = os.path.join(root, f)
                checked += 1
                try:
                    with open(path, 'r', encoding='utf-8') as fh:
                        ast.parse(fh.read(), filename=path)
                    print(f"  OK: {path}")
                except SyntaxError as e:
                    errors.append((path, e))
                    print(f"  FAIL: {path}: {e}")
        break
    
    if errors:
        print(f"\nArchitecture Guard FAILED: {len(errors)} / {checked} files have syntax errors")
        return False
    print(f"\nArchitecture Guard PASSED: {checked} files OK")
    return True


def check_imports():
    """Step 2: Import Check - 检查关键模块可导入。"""
    print("\n" + "=" * 60)
    print("Step 2: Import Check")
    print("=" * 60)
    
    modules = [
        'recon.config_loader',
        'recon.target_router',
        'recon.target_builder',
        'recon.capability_detector',
        'recon.capability_probe',
        'recon.burp_parser',
        'recon.mcp_enumerator',
        'recon.openapi_discoverer',
        'recon.port_expander',
        'recon.auth_state_manager',
        'recon.system_prompt_extractor',
        'core.orchestrator',
    ]
    
    errors = []
    for mod in modules:
        try:
            __import__(mod)
            print(f"  OK: {mod}")
        except Exception as e:
            errors.append((mod, e))
            print(f"  FAIL: {mod}: {e}")
    
    if errors:
        print(f"\nImport Check FAILED: {len(errors)} / {len(modules)} modules failed")
        return False
    print(f"\nImport Check PASSED: {len(modules)} modules OK")
    return True


def check_functional():
    """Step 3: Functional Check - 基本功能验证。"""
    print("\n" + "=" * 60)
    print("Step 3: Functional Check")
    print("=" * 60)
    
    errors = []
    
    # Test 1: config_loader
    try:
        from recon.config_loader import get_tls_verify
        val = get_tls_verify()
        print(f"  OK: get_tls_verify() returned {val!r}")
    except Exception as e:
        errors.append(e)
        print(f"  FAIL: get_tls_verify(): {e}")
    
    # Test 2: TargetFingerprint dataclass
    try:
        from recon.burp_parser import TargetFingerprint
        fp = TargetFingerprint(framework="Test", api_path="/test")
        fp.chat_id = "test-123"
        fp.extra["burp_model_list"] = "yes"
        d = fp.to_dict()
        print(f"  OK: TargetFingerprint.to_dict() returned {len(d)} keys")
    except Exception as e:
        errors.append(e)
        print(f"  FAIL: TargetFingerprint: {e}")
    
    # Test 3: _log_probe_failure helper
    try:
        from recon.target_router import _log_probe_failure
        
        class MockCtx:
            orchestration_log = []
        
        ctx = MockCtx()
        _log_probe_failure(ctx, "test", ValueError("test error"), is_fatal=False)
        assert len(ctx.orchestration_log) == 1
        assert ctx.orchestration_log[0]["phase"] == "recon"
        print(f"  OK: _log_probe_failure wrote {len(ctx.orchestration_log)} entries")
    except Exception as e:
        errors.append(e)
        print(f"  FAIL: _log_probe_failure: {e}")
    
    if errors:
        print(f"\nFunctional Check FAILED: {len(errors)} errors")
        return False
    print(f"\nFunctional Check PASSED")
    return True


def main():
    """Run all verification steps."""
    results = []
    
    results.append(("Architecture Guard", check_architecture()))
    results.append(("Import Check", check_imports()))
    results.append(("Functional Check", check_functional()))
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print("\nAll checks PASSED!")
        return 0
    else:
        print("\nSome checks FAILED!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
