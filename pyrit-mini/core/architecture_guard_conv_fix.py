#!/usr/bin/env python3
"""
Architecture Guard - Improved Converter Chain Detection
Line-based parser to avoid regex cross-function boundary issues.
"""
import re
import sys
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(__file__).rsplit("/", 2)[0])

from core.architecture_guard import Severity, Violation, _WEI_MAX_STACK_DEPTH, _WEI_HARD_MAX_STACK


@dataclass
class FunctionRange:
    name: str
    start_line: int
    end_line: int


def find_function_ranges(lines: list[str]) -> list[FunctionRange]:
    """Find all top-level function definitions and their line ranges."""
    functions = []
    current_func = None
    current_start = 0
    current_indent = None
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Detect new function definition
        if stripped.startswith("def ") and "(" in stripped:
            # Save previous function
            if current_func is not None:
                functions.append(FunctionRange(current_func, current_start, i - 1))
            
            # Extract function name
            match = re.match(r"def\s+(\w+)\s*\(", stripped)
            if match:
                current_func = match.group(1)
                current_start = i + 1  # 1-indexed
                current_indent = len(line) - len(line.lstrip())
                continue
        
        # Detect end of current function (at module level)
        if current_func is not None and stripped and stripped[0] != "#":
            line_indent = len(line) - len(line.lstrip())
            if line_indent <= current_indent and not stripped.startswith("def "):
                if (stripped.startswith("class ") or 
                    (stripped.startswith("def ") and line_indent == current_indent)):
                    functions.append(FunctionRange(current_func, current_start, i - 1))
                    current_func = None
    
    # Handle last function
    if current_func is not None:
        functions.append(FunctionRange(current_func, current_start, len(lines)))
    
    return functions


def detect_stacking_in_function(lines: list[str], func: FunctionRange) -> list[dict]:
    """Within a function, detect return [...] blocks with multiple _conv calls."""
    violations = []
    
    # Get the function body lines (indexed from func.start_line to func.end_line)
    body_lines = lines[func.start_line - 1 : func.end_line]
    
    # Find complete return [...] patterns in this function only
    i = 0
    while i < len(body_lines):
        line = body_lines[i]
        stripped = line.strip()
        
        # Detect start of return [
        if "return" in stripped and "[" in stripped:
            # This might be a single-line return [...] or multi-line
            if stripped.endswith("["):
                # Multi-line return block - scan forward
                conv_count = 0
                j = i + 1
                while j < len(body_lines):
                    inner_stripped = body_lines[j].strip()
                    if inner_stripped == "]" or inner_stripped.startswith("]"):
                        break
                    if "_conv(" in inner_stripped and not inner_stripped.startswith("#"):
                        conv_count += 1
                    j += 1
                
                if conv_count > 1:
                    violations.append({
                        "func": func.name,
                        "line": func.start_line,  # function def line
                        "conv_count": conv_count,
                        "block_start_line": i + func.start_line,  # absolute line
                    })
                i = j + 1
                continue
            elif stripped.count("[") > 0 and stripped.count("]") > 0:
                # Single-line return [...] - count _conv
                conv_count = len(re.findall(r'_conv\([^)]+\)\([^)]*\)', stripped))
                if conv_count > 1:
                    violations.append({
                        "func": func.name,
                        "line": func.start_line,
                        "conv_count": conv_count,
                        "block_start_line": i + func.start_line,
                    })
        
        i += 1
    
    return violations


if __name__ == "__main__":
    chains_file = Path("arm/converter_chains.py")
    content = chains_file.read_text(encoding="utf-8")
    lines = content.split("\n")
    
    functions = find_function_ranges(lines)
    
    print("=" * 60)
    print("Function Ranges Found:")
    print("=" * 60)
    for f in functions[:15]:
        body_lines = lines[f.start_line-1:f.end_line]
        # Find if there's a return [ block
        has_multiret = any("_conv(" in l and not l.strip().startswith("#") for l in body_lines[3:6])
        if has_multiret or any(stripped.startswith("return [") for l in body_lines for stripped in [l.strip()]):
            print(f"  {f.name:30s} lines {f.start_line:3d}-{f.end_line:3d}")
    
    print()
    print("=" * 60)
    print("Stacking Detection Results:")
    print("=" * 60)
    
    total_violations = 0
    for func in functions:
        violations = detect_stacking_in_function(lines, func)
        for v in violations:
            severity = "OK"
            if v["conv_count"] > _WEI_HARD_MAX_STACK:
                severity = "BLOCKING"
            elif v["conv_count"] > _WEI_MAX_STACK_DEPTH:
                severity = "WARNING"
            
            if severity != "OK":
                total_violations += 1
                print(f"  [{severity:8s}] {v['func']:30s} (def line {v['line']:3d}): {v['conv_count']} converters")
    
    if total_violations == 0:
        print("  No stacking violations found!")
    
    print(f"\n  Total violations: {total_violations}")
