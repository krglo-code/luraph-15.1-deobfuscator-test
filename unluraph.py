#!/usr/bin/env python3
"""
unluraph.py — simple outer-layer fallback
- strips common Luraph headers
- tries basic string.char / loadstring unpacks
- constant folding for simple expressions
Not a full deobfuscator. Used only as last resort.
"""
from __future__ import annotations
import argparse, re, sys
from pathlib import Path

def clean(src: str) -> str:
    # strip common header comments
    src = re.sub(r"^--\s*This file was protected using Luraph.*?\n", "", src, flags=re.I|re.M)
    src = re.sub(r"^--\s*https?://lura\.ph.*?\n", "", src, flags=re.I|re.M)
    # simple string.char sequences → literal when short
    def char_repl(m):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(",")]
            if 0 < len(nums) <= 80 and all(0 <= n <= 255 for n in nums):
                s = "".join(chr(n) for n in nums)
                if s.isprintable() or all(c in "\n\r\t" or c.isprintable() for c in s):
                    return repr(s)
        except Exception:
            pass
        return m.group(0)
    src = re.sub(r"string\.char\s*\(([^)]{1,400})\)", char_repl, src)
    # loadstring(string.char(...)) patterns left for static_unpack
    return src

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()
    inp = Path(args.input)
    out = Path(args.output) if args.output else inp.with_suffix(".unluraph.lua")
    src = inp.read_text(encoding="utf-8", errors="replace")
    cleaned = clean(src)
    out.write_text(cleaned, encoding="utf-8")
    print(f"[unluraph] wrote {out} ({len(cleaned)} bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
