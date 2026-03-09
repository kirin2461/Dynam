@echo off
setlocal EnableDelayedExpansion
title NCP - Network Control Protocol

:: ===== UAC self-elevation ===================================================
:: Check if already running as admin.  If not, relaunch ourselves elevated.
:: The user sees ONE UAC prompt; after that everything runs as administrator.
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [*] Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo [OK] Running as Administrator
:: After elevation, working directory may reset to System32 -- fix it
cd /d "%~dp0"
:: ============================================================================

echo.
echo  ================================================================
echo   NCP - Network Control Protocol
echo   Starting...
echo  ================================================================
echo.

set "NCP_DIR=%~dp0"
if "%NCP_DIR:~-1%"=="\" set "NCP_DIR=%NCP_DIR:~0,-1%"

:: --- Copy runtime DLLs if needed ---
set "BUILD_BIN=%NCP_DIR%\build"
set "RELEASE_BIN=%NCP_DIR%\build\bin\Release"

:: WinDivert: check common locations
if not exist "%BUILD_BIN%\WinDivert.dll" (
    :: Try local deps first
    if exist "%NCP_DIR%\deps\WinDivert\x64\WinDivert.dll" (
        copy /Y "%NCP_DIR%\deps\WinDivert\x64\WinDivert.dll" "%BUILD_BIN%\" >nul 2>&1
        copy /Y "%NCP_DIR%\deps\WinDivert\x64\WinDivert64.sys" "%BUILD_BIN%\" >nul 2>&1
        echo [OK] WinDivert copied from deps
    ) else if exist "C:\WinDivert-2.2.2-A\x64\WinDivert.dll" (
        copy /Y "C:\WinDivert-2.2.2-A\x64\WinDivert.dll" "%BUILD_BIN%\" >nul 2>&1
        copy /Y "C:\WinDivert-2.2.2-A\x64\WinDivert64.sys" "%BUILD_BIN%\" >nul 2>&1
        echo [OK] WinDivert copied from C:\WinDivert-2.2.2-A
    ) else (
        echo [!] WinDivert.dll not found - packet interception may not work
    )
)

:: Npcap wpcap.dll: check common locations
if not exist "%BUILD_BIN%\wpcap.dll" (
    if exist "C:\Windows\System32\Npcap\wpcap.dll" (
        copy /Y "C:\Windows\System32\Npcap\wpcap.dll" "%BUILD_BIN%\" >nul 2>&1
        copy /Y "C:\Windows\System32\Npcap\Packet.dll" "%BUILD_BIN%\" >nul 2>&1
        echo [OK] Npcap DLLs copied
    ) else (
        echo [!] wpcap.dll not found - make sure Npcap is installed
    )
)

:: --- Find Python ---
set "PYTHON_EXE="

if exist "%NCP_DIR%\web\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%NCP_DIR%\web\venv\Scripts\python.exe"
    echo [OK] Using Python from venv
    goto :python_found
)

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "delims=" %%i in ('where python') do (
        set "PYTHON_EXE=%%i"
        goto :python_found
    )
)

echo [ERROR] Python not found!
echo   Run install.bat first or install Python 3.10+
pause
exit /b 1

:python_found
echo [*] Python: %PYTHON_EXE%

:: --- Check dependencies ---
"%PYTHON_EXE%" -c "import flask" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [*] Installing dependencies...
    "%PYTHON_EXE%" -m pip install flask flask-cors flask-socketio psutil cryptography
    echo.
)

:: --- Kill previous server on port 8085 ---
echo [*] Checking port 8085...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8085.*LISTENING" 2^>nul') do (
    echo [*] Stopping previous instance PID %%a
    taskkill /F /PID %%a >nul 2>&1
)

:: --- Start Flask server ---
echo [*] Starting NCP Web Server on port 8085...
start "NCP-WebServer" /MIN "%PYTHON_EXE%" "%NCP_DIR%\web\server.py"

:: --- Wait for server (up to 20 sec) ---
echo [*] Waiting for server...
set "READY=0"
for /L %%i in (1,1,20) do (
    if "!READY!"=="0" (
        timeout /t 1 /nobreak >nul
        powershell -Command "try { $null = Invoke-WebRequest -Uri 'http://127.0.0.1:8085/' -TimeoutSec 2 -UseBasicParsing; exit 0 } catch { exit 1 }" >nul 2>&1
        if !errorlevel! equ 0 set "READY=1"
    )
)

if "!READY!"=="0" (
    echo [!] Server did not respond in 20 sec.
    echo [!] Starting with error output:
    echo.
    "%PYTHON_EXE%" "%NCP_DIR%\web\server.py"
    pause
    exit /b 1
) else (
    echo [OK] Server is ready
)

:: --- Open browser ---
echo [*] Opening Web UI...
start "" "http://127.0.0.1:8085"

echo.
echo  ================================================================
echo   NCP is running.
echo   Web UI: http://127.0.0.1:8085
echo.
echo   Do NOT close the minimized NCP-WebServer window!
echo   Press any key here to STOP NCP.
echo  ================================================================
echo.
pause

:: --- Cleanup ---
echo [*] Stopping NCP server...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8085.*LISTENING" 2^>nul') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo [OK] NCP stopped.
timeout /t 2 /nobreak >nul
