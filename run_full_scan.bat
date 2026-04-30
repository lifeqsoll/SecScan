@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found.
  echo Run: python -m venv .venv ^&^& .venv\Scripts\activate ^&^& pip install -r requirements.txt
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File ".\run_full_scan.ps1"
set ERR=%ERRORLEVEL%
if not "%ERR%"=="0" (
  echo [ERROR] run_full_scan.ps1 exited with code %ERR%
)
pause
exit /b %ERR%
