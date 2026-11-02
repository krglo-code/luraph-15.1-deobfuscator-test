#!/usr/bin/env python3
"""Verify a deobfuscated Luau output parses cleanly and report nil-call ratio.
Usage: python verify_lift.py output/deob.lua [luau-ast path]"""
from pathlib import Path
import shutil, subprocess, sys

def main():
    if len(sys.argv) < 2:
        print("usage: python verify_lift.py <deob.lua> [luau-ast]")
        return 1
    out = Path(sys.argv[1])
    if not out.is_file():
        print(f"[!] not found: {out}")
        return 1
    text = out.read_text(errors="replace")
    nil_calls = text.count("(nil)(")
    lines = text.count("\n") + 1
    ratio = (nil_calls / lines * 100) if lines else 0
    print(f"  file   : {out}")
    print(f"  lines  : {lines}")
    print(f"  (nil)( calls: {nil_calls}  ({ratio:.2f}% of lines)")
    if nil_calls < 50 or nil_calls * 100 < lines:
        print("  verdict: lift looks clean (low nil-call ratio)")
    else:
        print("  verdict: lift is broken — falling back to behavior trace recommended")
    ast = sys.argv[2] if len(sys.argv) > 2 else shutil.which("luau-ast")
    if ast:
        r = subprocess.run([ast, str(out)], capture_output=True, text=True)
        print(f"  luau-ast: exit {r.returncode}")
        if r.stdout.strip():
            print("   ", r.stdout.strip()[:200])
        if r.stderr.strip():
            print("   err:", r.stderr.strip()[:200])
    else:
        print("  luau-ast not found — syntax check skipped")
    return 0

if __name__ == "__main__":
    sys.exit(main())
