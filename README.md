# Luraph Deobfuscation Suite (improved)

Unified launcher over public Luraph engines + built-in helpers.

## Included

| Component | Path | Role |
|-----------|------|------|
| **kers / caomod2077** | `deobfuscator-luraph-v15/` | Best public option for Luraph **v15** (Node) |
| **KryptIT / larpcorrupt** | `luraph-v15-deob-krypt/` | VM tracer + lifter for v14.x / v15 |
| **Built-in sandbox** | `runtime/envlog.luau` | Offline emulator + constant recovery |
| **Static unpack** | `core/static_unpack.py` | LPS/PSU, Luraph v14 envelopes, string.char |
| **Detection** | `core/detect.py` | Multi-family fingerprint |
| **unluraph** | `unluraph.py` | Simple outer-layer cleanup (last resort) |
| **Luau runtime** | `bin/luau*` | Official-style Luau tools (Linux) |

## Quick start

```bash
# Linux
chmod +x setup.sh deob.sh bin/luau
./setup.sh

# drop scripts
cp yourscript.lua input/

# run
python3 deob.py
# or
python3 deob.py input/yourscript.lua -o output/clean.lua
python3 deob.py --engine kers input/yourscript.lua
python3 deob.py --detect input/yourscript.lua
python3 deob.py --sandbox input/yourscript.lua
```

Windows: install Python 3.10+ and Node 18+, put `luau.exe` in `bin\`, run `setup.bat` then `deob.bat`.

## Engine priority (auto)

1. kers / caomod2077 (`--engine kers`)
2. KryptIT VM (`--engine v15` / `v14`)
3. Built-in sandbox
4. unluraph fallback

## Reality check

- Public tools currently work best on **Luraph v15 and older**.
- **v15.1 / SuperFlow / FlowAuth** still have limited public success.
- This suite makes the available public engines easy to run. It does not invent a full 15.1 break.

## Sources

- https://github.com/caomod2077/Deobfuscator-Luraph-V15
- https://github.com/larpcorrupt/luraph-v15-v14.x-deobfuscator
- https://github.com/luau-lang/luau/releases
