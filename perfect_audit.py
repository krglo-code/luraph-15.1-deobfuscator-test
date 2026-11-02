#!/usr/bin/env python3
"""Luraph 15.1 suite audit. Reports what's present, what's missing, and the
exact commands to close the gaps for a perfect 15.1 deob pipeline."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "bin"
CORE = ROOT / "core"
EXT = ROOT / "deobfuscator-luraph-v15.1"

checks = []

def check(name, ok, detail, fix):
    checks.append((name, ok, detail, fix))

# Core files
check("deob.py orchestrator", (ROOT / "deob.py").is_file(), str(ROOT / "deob.py"), "present")
check("detect.py fingerprinter", (CORE / "detect.py").is_file(), str(CORE / "detect.py"), "present")
check("static_unpack.py", (CORE / "static_unpack.py").is_file(), str(CORE / "static_unpack.py"), "present")
check("ipc_repl.py", (CORE / "ipc_repl.py").is_file(), str(CORE / "ipc_repl.py"), "present")
check("runtime/envlog.luau", (ROOT / "runtime" / "envlog.luau").is_file(), str(ROOT / "runtime" / "envlog.luau"), "present")

# Luau binaries
luau_candidates = [BIN / "luau", BIN / "luau.exe"]
luau = next((p for p in luau_candidates if p.is_file()), shutil.which("luau"))
check("luau binary", luau is not None, str(luau) if luau else "missing", "download luau-lang/luau release, place in bin/")
check("luau.exe (Windows)", (BIN / "luau.exe").is_file(), str(BIN / "luau.exe"), "needed on Windows; rename luau or download luau.exe")

# v15.1 detection patterns in detect.py
detect_txt = (CORE / "detect.py").read_text(errors="replace") if (CORE / "detect.py").is_file() else ""
v151_markers = ["Luraph Obfuscator v15.1", "LPH_ENCSTR2", "_bsdata0", "superflow_bytecode"]
found = [m for m in v151_markers if m in detect_txt]
check("detect.py v15.1 patterns", len(found) >= 2, f"found {len(found)}/4: {found}", "detect.py already covers v15.1 headers")

# External engines referenced but missing
krypt = ROOT / "luraph-v15-deob-krypt"
psu = ROOT / "psu-deobfuscator"
check("KryptIT engine dir", krypt.is_dir(), str(krypt), "git clone https://github.com/KryptIT/luraph-v15-v14.x-deobfuscator luraph-v15-deob-krypt")
check("psu/caomod engine dir", psu.is_dir(), str(psu), "git clone caomod2077 psu-deobfuscator")

# kers module versions
kers_v15 = EXT / "core" / "obfuscators" / "luraph_v15"
kers_v14 = EXT / "core" / "obfuscators" / "luraph_v14"
kers_v151 = EXT / "core" / "obfuscators" / "luraph_v15.1"
check("kers luraph_v15 module", kers_v15.is_dir(), str(kers_v15), "present")
check("kers luraph_v14 module", kers_v14.is_dir(), str(kers_v14), "present")
check("kers luraph_v15.1 module (dedicated)", kers_v151.is_dir(), str(kers_v151), "MISSING — v15.1 reuses v15 module; SuperFlow flow not separately handled")

print("=" * 64)
print("  Luraph 15.1 Suite Audit")
print("=" * 64)
for name, ok, detail, fix in checks:
    flag = "[OK ]" if ok else "[-- ]"
    print(f"{flag} {name}")
    print(f"       {detail}")
    if fix and fix != "present":
        print(f"       fix: {fix}")
print()

missing = [c for c in checks if not c[1]]
if missing:
    print(f"  {len(missing)} gap(s) to close for a perfect 15.1 build.")
else:
    print("  No structural gaps found; remaining risk is v15.1 lift quality, not tooling.")
