@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [*] Relaunching as Administrator...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b 0
)

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found.
  echo Run: python -m venv .venv ^&^& .venv\Scripts\activate ^&^& pip install -r requirements.txt
  pause
  exit /b 1
)

.\.venv\Scripts\python -m secscan desktop
pause
