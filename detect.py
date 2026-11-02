"""
core/detect.py — Multi-family Fingerprinter
============================================
Single-pass fingerprint over the first 16 KB of a script.
Returns a DetectResult with:
  .family      : str — canonical family name
  .version     : str — best version guess
  .confidence  : float — 0.0–1.0
  .hints       : list[str] — human-readable evidence
  .best_engine : str — recommended engine flag for deob.py
  .bsdata_keys : list[str] — _bsdataN keys found (SuperFlow)

Design: pattern table with (compiled_regex, family, version, weight, hint).
Score = sum of matching weights. Family with highest score wins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DetectResult:
    family      : str  = "unknown"
    version     : str  = ""
    confidence  : float = 0.0
    hints       : list[str] = field(default_factory=list)
    best_engine : str  = "auto"
    bsdata_keys : list[str] = field(default_factory=list)
    static_unpackable: bool = False


# ── Pattern table ─────────────────────────────────────────────────────────────
# (pattern_str, family, version_tag, weight, hint_text)
_PATTERNS = [
    # ── Luraph v15.1 ─────────────────────────────────────────────────────────
    (r"Luraph Obfuscator v15\.1",        "luraph", "v15.1", 10, "v15.1 explicit header"),
    (r"LURAPH_v15\.1",                   "luraph", "v15.1", 10, "LURAPH_v15.1 marker"),
    (r"LPH_ENCSTR2",                     "luraph", "v15.1",  8, "LPH_ENCSTR2 (v15.1 encrypt)"),
    (r"LPH_ENCFUNC2",                    "luraph", "v15.1",  8, "LPH_ENCFUNC2 (v15.1 encrypt)"),
    # ── SuperFlow / _bsdata ───────────────────────────────────────────────────
    (r"superflow_bytecode",              "luraph", "v15.1",  9, "SuperFlow bytecode container"),
    (r"_bsdata0",                        "luraph", "v15.1",  8, "_bsdata0 container (SuperFlow)"),
    (r"_bsdata[1-9]",                    "luraph", "v15.1",  4, "_bsdataN series (SuperFlow)"),
    # ── FlowAuth loader ───────────────────────────────────────────────────────
    (r"flowauth\.net",                   "luraph", "flowauth", 9, "FlowAuth loader (flowauth.net)"),
    (r"flowauth",                        "luraph", "flowauth", 5, "FlowAuth reference"),
    (r"launch_ticket_rejected",          "luraph", "flowauth", 8, "FlowAuth ticket rejection marker"),
    (r"bootstrapper",                    "luraph", "flowauth", 3, "FlowAuth bootstrapper reference"),
    # ── Luraph v15 ────────────────────────────────────────────────────────────
    (r"Luraph Obfuscator v15",           "luraph", "v15",    10, "classic Luraph v15 header"),
    (r"LPH_ENCSTR\b",                    "luraph", "v15",     6, "LPH_ENCSTR (v15 encrypt)"),
    (r"LPH_ENCFUNC\b",                   "luraph", "v15",     6, "LPH_ENCFUNC (v15 encrypt)"),
    (r"LPH_CRASH\b",                     "luraph", "v15",     5, "LPH_CRASH anti-tamper trap"),
    (r"LPH:",                            "luraph", "v15",     4, "LPH: marker (Luraph-family)"),
    (r"LPH_NO_VIRTUALIZE",              "luraph", "v15",     4, "LPH_NO_VIRTUALIZE closure"),
    # ── Luraph v14.x ─────────────────────────────────────────────────────────
    (r"LPH%[0-9a-zA-Z]{10,}",           "luraph", "v14",     8, "Luraph base85/LZMA envelope (v14.x)"),
    (r"\[=\[LPH",                        "luraph", "v14",     8, "Luraph long-string envelope (v14.x)"),
    (r"generated using Luraph.*v1[234]", "luraph", "v14",    10, "Luraph v14 header comment"),
    # ── Luraph v12–v13 ────────────────────────────────────────────────────────
    (r"generated using Luraph.*v1[23]",  "luraph", "v12-v13",10, "Luraph v12/v13 header comment"),
    # ── Luraph VM shape (generic) ─────────────────────────────────────────────
    (r"setmetatable\(\{",                "luraph", "",        2, "setmetatable VM object shape"),
    (r"bit32\.",                         "luraph", "",        2, "bit32 (Luraph VM pattern)"),
    (r"while true do\s+if",              "luraph", "",        2, "VM dispatcher loop"),
    # ── KeyForge ─────────────────────────────────────────────────────────────
    (r"keyforge\.win/v1/load/",          "keyforge", "",     10, "KeyForge delivery URL"),
    (r"_G\.script_key",                  "keyforge", "",      8, "KeyForge SDK (_G.script_key)"),
    (r"keyforge\.win",                   "keyforge", "",      6, "KeyForge domain"),
    # ── MoonSec ──────────────────────────────────────────────────────────────
    (r"This file was protected with MoonSec V3", "moonsec","V3",10,"MoonSec V3 header"),
    (r"MoonSec V[123]",                  "moonsec", "",       8, "MoonSec header"),
    (r"__moonsec",                       "moonsec", "",       6, "MoonSec internal marker"),
    # ── IronBrew ─────────────────────────────────────────────────────────────
    (r"--ironbrew3:tm:",                  "ironbrew","3",      9, "IronBrew3 header"),
    (r"local i=string\.byte",            "ironbrew","2",      7, "IronBrew2 byte-alias pattern"),
    (r"ironbrew1",                        "ironbrew","1",      9, "IronBrew1 marker"),
    # ── Prometheus ────────────────────────────────────────────────────────────
    (r'return\s*\(function\s*\([^)]*\)\s*local\s+\w+\s*=\s*\{(?:\\[0-9]{1,3}[, ]*){10,}\}',
                                         "prometheus","",     8, "Prometheus decimal-escape table"),
    # ── wYnFuscate ────────────────────────────────────────────────────────────
    (r"-- Protected by wYnFuscate",      "wynfuscate","",    10, "wYnFuscate header"),
    # ── Hercules ─────────────────────────────────────────────────────────────
    (r"--\[Obfuscated by Hercules",      "hercules", "",      9, "Hercules header"),
    # ── Synapse Xen ──────────────────────────────────────────────────────────
    (r"Synapse Xen v1\.",                "synapse_xen","",    9, "Synapse Xen header"),
    # ── LuaObfuscator.com ────────────────────────────────────────────────────
    (r"LuaObfuscator\.com",              "luaobf",  "",       8, "LuaObfuscator.com banner"),
    # ── LPS / PSU packer ─────────────────────────────────────────────────────
    (r"while\s+\w+\s+do\s+if\s+\w+\s*<=\s*0[Xx]?[0-9_A-Fa-f]+",
                                         "lps",     "",       7, "LPS/PSU stage-machine dispatcher"),
    (r'local\s+\w+\s*=\s*"[0-9a-zA-Z!#\$%&\(\)\*\+\-;<=>?@\^_`\{\|\}~]{200,}"',
                                         "lps",     "",       5, "LPS/PSU base85 blob"),
    # ── MoonVeil ─────────────────────────────────────────────────────────────
    (r"protected using the MoonVeil Obfuscator",
                                         "moonveil","",       9, "MoonVeil header"),
    # ── Boronide / herrtt ────────────────────────────────────────────────────
    (r"herrtt's obfuscator",             "herrtt",  "",       9, "herrtt's obfuscator header"),
    # ── 77fuscator ────────────────────────────────────────────────────────────
    (r"77fuscator",                       "77fuscate","",     9, "77fuscator header"),
]

_COMPILED = [
    (re.compile(p, re.MULTILINE | re.DOTALL), fam, ver, wt, hint)
    for p, fam, ver, wt, hint in _PATTERNS
]

_STATIC_UNPACKABLE = {"lps", "prometheus", "luraph_v14"}

# engine recommendations per family
_ENGINE_MAP = {
    "luraph/v15.1" : "kers",
    "luraph/flowauth": "kers",
    "luraph/v15"   : "kers",
    "luraph/v14"   : "v14",
    "luraph/v12-v13": "v14",
    "luraph/"      : "auto",
    "keyforge/"    : "kers",
    "moonsec/"     : "kers",
    "ironbrew/"    : "kers",
    "prometheus/"  : "kers",
    "wynfuscate/"  : "kers",
    "hercules/"    : "kers",
    "synapse_xen/" : "kers",
    "luaobf/"      : "kers",
    "lps/"         : "kers",
    "moonveil/"    : "kers",
    "herrtt/"      : "kers",
    "77fuscate/"   : "kers",
    "unknown/"     : "auto",
}


def detect(script_path: Path) -> DetectResult:
    """
    Fingerprint the script at script_path.
    Reads up to 16 KB for pattern matching.
    """
    try:
        src = script_path.read_text(errors="replace")[:16_384]
    except OSError as e:
        return DetectResult(hints=[f"read error: {e}"])

    scores: dict[tuple[str,str], float] = {}
    hints: list[str] = []
    seen_hints: set[str] = set()

    for rx, fam, ver, wt, hint in _COMPILED:
        if rx.search(src):
            key = (fam, ver)
            scores[key] = scores.get(key, 0.0) + wt
            if hint not in seen_hints:
                hints.append(hint)
                seen_hints.add(hint)

    if not scores:
        return DetectResult(hints=hints, best_engine="auto")

    best_fam, best_ver = max(scores, key=lambda k: scores[k])
    best_score = scores[(best_fam, best_ver)]

    # Normalize confidence to 0–1 (cap at score=20 → 1.0)
    confidence = min(best_score / 20.0, 1.0)

    # Engine recommendation
    engine_key = f"{best_fam}/{best_ver}"
    engine = _ENGINE_MAP.get(engine_key) or _ENGINE_MAP.get(f"{best_fam}/") or "auto"

    # _bsdata extraction
    bsdata_keys = [
        m.group(0).split("=")[0].strip()
        for m in re.finditer(r'_bsdata[0-9]\s*=', src)
    ]

    # Version refinement: if v15.1 and v15 both matched, prefer v15.1
    if best_ver == "v15" and scores.get(("luraph", "v15.1"), 0) > 0:
        best_ver = "v15.1"
        engine = "kers"

    static_unpackable = best_fam in _STATIC_UNPACKABLE

    return DetectResult(
        family=best_fam,
        version=best_ver,
        confidence=confidence,
        hints=hints,
        best_engine=engine,
        bsdata_keys=bsdata_keys,
        static_unpackable=static_unpackable,
    )


def detect_and_print(script_path: Path) -> DetectResult:
    """Detect and pretty-print the result. Convenience for CLI use."""
    r = detect(script_path)
    print("=" * 56)
    print("  Fingerprint result")
    print("=" * 56)
    print(f"  Family     : {r.family}")
    print(f"  Version    : {r.version or '(unknown)'}")
    print(f"  Confidence : {r.confidence:.0%}")
    print(f"  Best engine: --engine {r.best_engine}")
    if r.bsdata_keys:
        print(f"  SuperFlow  : {', '.join(r.bsdata_keys)} slots found")
    print(f"\n  Evidence:")
    for h in r.hints:
        print(f"    * {h}")
    if r.static_unpackable:
        print(f"\n  [!] Outer layer is statically unpackable (run static_unpack first)")
    print()
    return r


if __name__ == "__main__":
    import sys
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not p or not p.is_file():
        print("usage: python detect.py <script.lua>")
        sys.exit(1)
    detect_and_print(p)
