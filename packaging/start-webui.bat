@echo off
rem Dynam NCP - Web UI launcher (Windows)
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
    echo [Dynam] Python not found on PATH.
    echo Install Python 3.9+ from https://www.python.org/downloads/ and re-run this file.
    pause
    exit /b 1
)
echo [Dynam] Installing web UI dependencies (first run only)...
python -m pip install -q -r web\requirements.txt
if errorlevel 1 (
    echo [Dynam] pip install failed. Check your internet connection and re-run.
    pause
    exit /b 1
)
set NCP_OPEN_BROWSER=1
echo [Dynam] Starting Web UI on http://127.0.0.1:8085 ...
python web\server.py
pause
