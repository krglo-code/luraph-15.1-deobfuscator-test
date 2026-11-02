"""
core/static_unpack.py — Multi-family Static Unpacker
=====================================================
Pure-Python static decoding for obfuscator outer layers.
No execution, no subprocess — byte-level transforms only.

Handles:
  • LPS / PSU packer  (base85 → zstd, byte-exact)
  • Luraph v14.x envelope  (LPH% base85 + LZMA)
  • Luraph long-string ([=[LPH envelope)
  • Decimal-escaped string tables (Prometheus)
  • Basic hex-string table decoders
  • SuperFlow _bsdata0 sentinel detection + extraction hint
  • Generic loadstring(string.char(...)) unpack

Each unpacker returns (unpacked_source: str | None, method_name: str).
Returns (None, "") when the format is not recognised.
"""

from __future__ import annotations

import base64
import re
import struct
import zlib
from pathlib import Path
from typing import Optional  # Bug 5 fix: was `Optional, Optional` (duplicate)


# ── base85 (Lua-flavour, used by LPS and Luraph v14.x) ──────────────────────
# Lua's base85 alphabet differs from RFC 1924 and from Python's default.
_LUA_B85_ALPHA = (
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "!#$%&()*+-;<=>?@^_`{|}~"
)
_LUA_B85_DEC = {c: i for i, c in enumerate(_LUA_B85_ALPHA)}


def _lua_b85_decode(s: str) -> bytes:
    """Decode a Lua/LPS base85 blob back to raw bytes."""
    out = bytearray()
    for i in range(0, len(s), 5):
        chunk = s[i:i+5]
        if len(chunk) < 5:
            break
        n = 0
        for c in chunk:
            n = n * 85 + _LUA_B85_DEC.get(c, 0)
        out += struct.pack(">I", n & 0xFFFFFFFF)
    return bytes(out)


# ── zstd decompress (LPS packer) ─────────────────────────────────────────────
def _zstd_decompress(data: bytes) -> Optional[bytes]:
    """
    Decompress zstd-compressed bytes. Uses the `zstandard` package when
    available; falls back to a raw frame check + zlib inflate heuristic
    for the deflate-fallback that some LPS versions use.
    """
    try:
        import zstandard as zstd
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data, max_output_size=64 * 1024 * 1024)
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: some older LPS builds actually use zlib deflate despite the
    # LPS branding. Try wbits variants.
    for wbits in (15, -15, 31):
        try:
            return zlib.decompress(data, wbits)
        except zlib.error:
            pass
    return None


# ── LPS / PSU packer ─────────────────────────────────────────────────────────
_LPS_PATTERNS = [
    # LPS stage-machine: while <flag> do if <slot> <= 0x18_ binary/underscore
    re.compile(r"while\s+\w+\s+do\s+if\s+\w+\s*<=\s*0[Xx]?[0-9_A-Fa-f]+"),
    # LPS base85 blob embedded in a string variable
    re.compile(r'local\s+\w+\s*=\s*"([0-9a-zA-Z!#\$%&\(\)\*\+\-;<=>?@\^_`\{\|\}~]{200,})"'),
]

def unpack_lps(src: str) -> tuple[Optional[str], str]:
    """
    LPS / PSU packer: extract the base85 blob, b85-decode, zstd-decompress.
    Returns (decompressed_lua_source, "lps") or (None, "").
    """
    # Approach 1: find a large base85 string literal
    for pat in _LPS_PATTERNS[1:]:
        m = pat.search(src)
        if m:
            blob = m.group(1)
            try:
                raw = _lua_b85_decode(blob)
                # First 4 bytes of LPS blobs are the uncompressed size (LE u32)
                if len(raw) >= 4:
                    decompressed = _zstd_decompress(raw[4:]) or _zstd_decompress(raw)
                    if decompressed:
                        return decompressed.decode("utf-8", errors="replace"), "lps"
            except Exception:
                pass

    # Approach 2: look for the LPS stage-machine shape
    if _LPS_PATTERNS[0].search(src):
        # Stage-machine: the blob is inside a string.char() call or concatenation
        blob_m = re.search(r'"([0-9a-zA-Z!#\$%&\(\)\*\+\-;<=>?@\^_`\{\|\}~]{100,})"', src)
        if blob_m:
            try:
                raw = _lua_b85_decode(blob_m.group(1))
                decompressed = _zstd_decompress(raw[4:]) or _zstd_decompress(raw)
                if decompressed:
                    return decompressed.decode("utf-8", errors="replace"), "lps_stage"
            except Exception:
                pass

    return None, ""


# ── Luraph v14.x base85+LZMA envelope ────────────────────────────────────────
_LPH_B85_RE   = re.compile(r'LPH%([0-9a-zA-Z!#\$%&\(\)\*\+\-;<=>?@\^_`\{\|\}~]+)')
_LPH_LSTR_RE  = re.compile(r'\[=\[LPH([^\]]*)\]=\]')

def unpack_luraph_v14(src: str) -> tuple[Optional[str], str]:
    """
    Luraph v14.x: the payload is base85-encoded + LZMA-compressed, wrapped
    in either a LPH%<blob> inline or a [=[LPH…]=] long-string envelope.
    """
    blob: Optional[str] = None
    method = ""

    m = _LPH_B85_RE.search(src)
    if m:
        blob   = m.group(1)
        method = "luraph_v14_b85"

    if blob is None:
        m = _LPH_LSTR_RE.search(src)
        if m:
            blob   = m.group(1).strip()
            method = "luraph_v14_lstr"

    if blob is None:
        return None, ""

    try:
        raw = _lua_b85_decode(blob)
        # LZMA stream: starts with 0x5D (lzma properties byte)
        import lzma
        decomp = lzma.decompress(raw)
        return decomp.decode("utf-8", errors="replace"), method
    except Exception:
        pass

    # Fallback: try zstd/zlib
    decompressed = _zstd_decompress(raw if blob else b"")
    if decompressed:
        return decompressed.decode("utf-8", errors="replace"), method + "_zstd"

    return None, ""


# ── Prometheus decimal-escape string table ────────────────────────────────────
_PROMETHEUS_DECESC_RE = re.compile(
    r'return\s*\(function\s*\([^)]*\)\s*local\s+\w+\s*=\s*\{((?:\\[0-9]+[, \n]+)+)\}'
)

def unpack_prometheus(src: str) -> tuple[Optional[str], str]:
    """
    Prometheus obfuscator: the first statement is a return containing a
    decimal-escape table "\\115\\103…". Decode and return the inner string.
    This only strips the outer layer; the inner payload may itself be
    obfuscated and needs a sandbox run.
    """
    # Pattern: {"\115\103\97\110..."} → decode each escape
    dec_table_m = re.search(
        r'\{("(?:\\[0-9]{1,3})+"\s*(?:,\s*"(?:\\[0-9]{1,3})+")*)\}',
        src[:4000],
    )
    if dec_table_m:
        raw = dec_table_m.group(1)
        entries = re.findall(r'"((?:\\[0-9]{1,3})+)"', raw)
        decoded_parts = []
        for entry in entries:
            chars = re.findall(r'\\([0-9]{1,3})', entry)
            decoded_parts.append("".join(chr(int(c)) for c in chars))
        if decoded_parts:
            return "\n".join(decoded_parts), "prometheus_decesc"

    # Simpler form: one large string with decimal escapes
    m = re.search(r'"((?:\\[0-9]{1,3}){20,})"', src[:8000])
    if m:
        chars = re.findall(r'\\([0-9]{1,3})', m.group(1))
        if chars:
            return "".join(chr(int(c)) for c in chars), "prometheus_simple"

    return None, ""


# ── Generic loadstring(string.char(N,N,N,...)) ────────────────────────────────
_STRCHAR_RE = re.compile(
    r'loadstring\s*\(\s*string\.char\s*\(([0-9, \n]+)\)\s*\)'
)

def unpack_strchar(src: str) -> tuple[Optional[str], str]:
    """
    Generic string.char(N,N,N,...) payloads that get passed directly to
    loadstring. Extract and decode.
    """
    m = _STRCHAR_RE.search(src)
    if not m:
        return None, ""
    try:
        nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
        return bytes(nums).decode("utf-8", errors="replace"), "strchar"
    except Exception:
        return None, ""


# ── SuperFlow / _bsdata0 detection ───────────────────────────────────────────
_BSDATA_RE = re.compile(r'_bsdata([0-9])\s*=\s*"([^"]*)"')

def extract_bsdata(src: str) -> dict[str, str]:
    """
    Extract _bsdata0…_bsdata9 string literals from a SuperFlow bootstrapper
    or a Luraph v15.1 loader. These are the session-bound handoff blobs.

    Returns a dict: {"_bsdata0": "<value>", …}
    Callers pass these to the IPC REPL as bsdata0= so the sandbox
    pre-seeds the right value instead of the sentinel.
    """
    return {f"_bsdata{m.group(1)}": m.group(2) for m in _BSDATA_RE.finditer(src)}


# ── Dispatcher ───────────────────────────────────────────────────────────────

# ── SuperFlow v15.1 peeler ────────────────────────────────────────────────────
# Handles: _bsdata0 = {num, num, "bin", ...}; superflow_bytecode = {"...", _bsdata0[N] .. "...", ...}

def _lua_unescape(s: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt.isdigit():
                j = i + 1
                while j < len(s) and j < i + 4 and s[j].isdigit():
                    j += 1
                out.append(int(s[i + 1 : j]) & 0xFF)
                i = j
                continue
            mapping = {"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34, "'": 39, "a": 7, "b": 8, "f": 12, "v": 11, "0": 0}
            out.append(mapping.get(nxt, ord(nxt)))
            i += 2
            continue
        out.append(ord(s[i]))
        i += 1
    return bytes(out)


def _parse_lua_table_body(src: str, start: int):
    """Return (elements, end_index) where elements are raw source snippets."""
    depth, i, in_str, str_ch = 1, start, False, None
    elements = []
    elem_start = start
    paren = 0
    while i < len(src) and depth > 0:
        ch = src[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == str_ch:
                in_str = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_str, str_ch = True, ch
            i += 1
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            if depth == 1 and paren == 0:
                # close current element
                frag = src[elem_start:i].strip().rstrip(",")
                if frag:
                    elements.append(frag)
                depth -= 1
                i += 1
                break
            depth -= 1
        elif ch == "," and depth == 1 and paren == 0:
            frag = src[elem_start:i].strip()
            if frag:
                elements.append(frag)
            elem_start = i + 1
        i += 1
    return elements, i


def extract_superflow(src: str) -> tuple[Optional[bytes], str]:
    """
    Peel SuperFlow outer container.
    Returns (bytecode_bytes, status_message) or (None, reason).
    """
    if "superflow_bytecode" not in src and "_bsdata0" not in src:
        return None, "not SuperFlow"

    # --- parse _bsdata0 slots (1-based) ---
    m = re.search(r"_bsdata0\s*=\s*\{", src)
    bs_slots: dict[int, bytes] = {}
    if m:
        elems, _ = _parse_lua_table_body(src, m.end())
        for idx, e in enumerate(elems, 1):
            e = e.strip()
            if e.startswith('"') and e.endswith('"'):
                bs_slots[idx] = _lua_unescape(e[1:-1])

    # --- parse superflow_bytecode ---
    m = re.search(r"superflow_bytecode\s*=\s*\{", src)
    if not m:
        return None, "no superflow_bytecode table"

    elems, _ = _parse_lua_table_body(src, m.end())
    if not elems:
        return None, "empty superflow_bytecode"

    def eval_concat(expr: str) -> bytes:
        parts = re.split(r"\s*\.\.\s*", expr)
        out = bytearray()
        for p in parts:
            p = p.strip()
            mm = re.match(r"_bsdata0\[(\d+)\]$", p)
            if mm:
                slot = int(mm.group(1))
                if slot in bs_slots:
                    out.extend(bs_slots[slot])
                continue
            if p.startswith('"') and p.endswith('"'):
                out.extend(_lua_unescape(p[1:-1]))
                continue
        return bytes(out)

    chunks: list[bytes] = []
    for e in elems:
        e = e.strip()
        if ".." in e or "_bsdata0" in e:
            chunks.append(eval_concat(e))
        elif e.startswith('"') and e.endswith('"'):
            chunks.append(_lua_unescape(e[1:-1]))

    total = b"".join(chunks)
    if not total:
        return None, "resolved 0 bytes"
    return total, f"superflow ({len(chunks)} chunks, {len(total)} bytes, {len(bs_slots)} bsdata slots)"


def unpack_superflow(src: str) -> tuple[Optional[str], str]:
    """
    High-level: extract SuperFlow bytecode and emit a small loader stub
    that keeps the original VM but replaces the opaque bytecode with a
    recovered binary constant (still needs VM lifting, but outer peel is done).
    """
    blob, msg = extract_superflow(src)
    if blob is None:
        return None, msg
    # Emit as a Lua string of decimal escapes for inspection / further tools
    escaped = "".join(f"\\{b}" for b in blob)
    out = (
        f"-- SuperFlow outer layer peeled ({msg})\n"
        f"-- Raw bytecode length: {len(blob)} bytes\n"
        f"-- Hex head: {blob[:32].hex()}\n"
        f"superflow_bytecode_recovered = \"{escaped}\"\n"
        f"-- Original script still contains the VM; full lift requires v15.1 symbolic engine.\n"
    )
    return out, msg


def static_unpack(src: str) -> tuple[Optional[str], str]:
    """
    Try all static unpackers in order. Return the first successful decode
    as (decoded_source, method_name). Returns (None, "") when nothing matches.

    Order (cheapest / most specific first):
      1. Luraph v14.x LZMA envelope
      2. LPS / PSU packer
      3. Prometheus decimal-escape
      4. Generic string.char loadstring
    """
    for unpacker in (
        unpack_superflow,   # v15.1 SuperFlow outer peel (first)
        unpack_luraph_v14,
        unpack_lps,
        unpack_prometheus,
        unpack_strchar,
    ):
        result, method = unpacker(src)
        if result is not None:
            return result, method

    return None, ""


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python static_unpack.py <script.lua>")
        sys.exit(1)
    src_text = Path(sys.argv[1]).read_text(errors="replace")
    unpacked, method = static_unpack(src_text)
    if unpacked:
        print(f"[+] Unpacked via: {method}")
        print(f"    Output length: {len(unpacked)} bytes")
        bsdata = extract_bsdata(src_text)
        if bsdata:
            print(f"    _bsdata keys found: {list(bsdata.keys())}")
        out = Path(sys.argv[1]).with_suffix(".unpacked.lua")
        out.write_text(unpacked)
        print(f"    Written to: {out}")
    else:
        print("[!] No static unpacker matched this file")
        bsdata = extract_bsdata(src_text)
        if bsdata:
            print(f"    _bsdata keys found: {list(bsdata.keys())}")
            print("    This is likely a SuperFlow/FlowAuth script; use the sandbox engine")
