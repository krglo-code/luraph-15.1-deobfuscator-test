@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo [!] Python not found. Install Python 3.10+ and add it to PATH.
  pause
  exit /b 1
)

if "%~1"=="" (
  python deob.py --auto
) else if "%~2"=="" (
  python deob.py "%~1"
) else (
  python deob.py "%~1" -o "%~2"
)

echo.
pause
