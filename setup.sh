#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================================"
echo "  Luraph Deobfuscation Suite — Setup / Health Check"
echo "============================================================"
echo

ok()   { echo "[OK ] $*"; }
miss() { echo "[ --] $*"; }

if python3 --version &>/dev/null; then
    ok "Python $(python3 --version 2>&1 | cut -d' ' -f2)"
else
    miss "Python 3.10+ required"
fi

if command -v node &>/dev/null; then
    ok "Node.js $(node --version)"
else
    miss "Node.js 18+ recommended (for kers engine)"
fi

if [ -x bin/luau ] || [ -f bin/luau ]; then
    chmod +x bin/luau 2>/dev/null || true
    ok "bin/luau present"
else
    miss "bin/luau missing — get from https://github.com/luau-lang/luau/releases"
fi

if [ -f deobfuscator-luraph-v15/deob.js ]; then
    ok "kers/caomod engine (deobfuscator-luraph-v15)"
else
    miss "kers engine missing"
fi

if [ -f luraph-v15-deob-krypt/Deobfuscator/deobf/bin/deob.py ] || \
   [ -f luraph-v15-deob/Deobfuscator/deobf/deob.py ]; then
    ok "KryptIT / larpcorrupt engine present"
else
    miss "KryptIT engine missing"
fi

if [ -f unluraph.py ]; then
    ok "unluraph.py fallback"
else
    miss "unluraph.py missing"
fi

mkdir -p input output
ok "input/ and output/ ready"

echo
echo "Usage:"
echo "  put .lua files in input/"
echo "  python3 deob.py                  # auto"
echo "  python3 deob.py --engine kers script.lua"
echo "  python3 deob.py --detect script.lua"
echo "  python3 deob.py --sandbox script.lua"
echo
echo "Note: current public engines target Luraph v15 and older."
echo "      v15.1 / SuperFlow success is limited."
echo
