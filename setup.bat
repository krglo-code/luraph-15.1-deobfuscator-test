@echo off
echo ============================================================
echo   Luraph Deobfuscation Suite v2 - Setup / Health Check
echo ============================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [--] Python not found - install Python 3.10+ and add to PATH
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [OK ] %%v
)

node --version >nul 2>&1
if errorlevel 1 (
    echo [--] Node.js not found - install Node.js 18+ for kers + caomod engines
) else (
    for /f "tokens=*" %%v in ('node --version 2^>^&1') do echo [OK ] Node.js %%v
)

if exist bin\luau.exe (
    echo [OK ] bin\luau.exe found
) else (
    echo [--] bin\luau.exe missing
    echo      Download from: https://github.com/luau-lang/luau/releases
    echo      Copy luau.exe into the bin\ folder
)

if exist deobfuscator-luraph-v15\deob.js (
    echo [OK ] kers0nec engine found (deobfuscator-luraph-v15\deob.js)
) else (
    echo [--] kers0nec engine missing - BEST engine for v15.1 / SuperFlow
    echo      git clone https://github.com/caomod2077/Deobfuscator-Luraph-V15 deobfuscator-luraph-v15
)

if exist luraph-v15-deob\Deobfuscator\deobf\deob.py (
    echo [OK ] KryptIT VM engine found
) else (
    echo [--] KryptIT engine missing
    echo      git clone https://github.com/KryptIT/luraph-v15-v14.x-deobfuscator luraph-v15-deob
)

if exist psu-deobfuscator\deob.js (
    echo [OK ] caomod engine found
) else (
    echo [--] caomod engine missing
)

if exist unluraph.py (
    echo [OK ] unluraph.py found
) else (
    echo [--] unluraph.py missing (fallback engine)
)

echo.
echo Engine priority (auto): kers -^> KryptIT -^> caomod -^> unluraph
echo v15.1 / SuperFlow: python deob.py --engine kers script.lua
echo FlowAuth key-locked: python deob.py --engine kers --key YOUR-KEY script.lua
echo.
echo To run: drop .lua into input\  then double-click deob.bat
echo.
pause
