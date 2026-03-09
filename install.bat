@echo off
setlocal EnableDelayedExpansion

title NCP Installer

echo.
echo  ================================================================
echo   NCP - Network Control Protocol
echo   Install dependencies and build
echo  ================================================================
echo.

:: --- Admin check ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges required.
    echo     Right-click - Run as Administrator
    pause
    exit /b 1
)

:: --- Paths ---
set "NCP_ROOT=%~dp0"
if "%NCP_ROOT:~-1%"=="\" set "NCP_ROOT=%NCP_ROOT:~0,-1%"
set "BUILD_DIR=%NCP_ROOT%\build"
set "VCPKG_ROOT=%NCP_ROOT%\vcpkg"
set "WEB_DIR=%NCP_ROOT%\web"
set "CONFIG_DIR=%APPDATA%\ncp"

echo [*] NCP root: %NCP_ROOT%
echo.

:: ============================================================================
:: STEP 1: Check build tools
:: ============================================================================
echo ----------------------------------------------------------------
echo  STEP 1/7: Checking build tools
echo ----------------------------------------------------------------

where git >nul 2>&1
if %errorlevel% neq 0 goto :NO_GIT
echo [OK] Git
goto :CHECK_CMAKE

:NO_GIT
echo [!] Git not found. Download: https://git-scm.com/download/win
pause
exit /b 1

:CHECK_CMAKE
where cmake >nul 2>&1
if %errorlevel% neq 0 goto :NO_CMAKE
echo [OK] CMake
goto :CHECK_VS

:NO_CMAKE
echo [!] CMake not found. Download: https://cmake.org/download/
pause
exit /b 1

:CHECK_VS
set "VSINSTALL="

:: Method 1: vswhere
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :VS_METHOD2
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSINSTALL=%%i"
if defined VSINSTALL goto :VS_FOUND

:VS_METHOD2
:: Method 2: Common paths
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community" set "VSINSTALL=C:\Program Files\Microsoft Visual Studio\2022\Community"
if defined VSINSTALL goto :VS_FOUND
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional" set "VSINSTALL=C:\Program Files\Microsoft Visual Studio\2022\Professional"
if defined VSINSTALL goto :VS_FOUND
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise" set "VSINSTALL=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
if defined VSINSTALL goto :VS_FOUND
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools" set "VSINSTALL=C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
if defined VSINSTALL goto :VS_FOUND
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" set "VSINSTALL=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
if defined VSINSTALL goto :VS_FOUND

:: Method 3: cl.exe in PATH (Developer Command Prompt)
where cl >nul 2>&1
if %errorlevel% equ 0 (
    set "VSINSTALL=FROM_ENVIRONMENT"
    goto :VS_FOUND
)

:: Method 4: VSINSTALLDIR env var
if defined VSINSTALLDIR (
    set "VSINSTALL=%VSINSTALLDIR%"
    goto :VS_FOUND
)

echo [!] Visual Studio not found.
echo     Download Build Tools: https://visualstudio.microsoft.com/downloads/
echo     Or run from Developer Command Prompt.
pause
exit /b 1

:VS_FOUND
echo [OK] Visual Studio: %VSINSTALL%

:: --- Python ---
where python >nul 2>&1
if %errorlevel% neq 0 goto :NO_PYTHON
echo [OK] Python
goto :STEP2

:NO_PYTHON
echo [!] Python not found. Download: https://www.python.org/downloads/
echo     Check "Add Python to PATH" during install.
pause
exit /b 1

:: ============================================================================
:: STEP 2: vcpkg
:: ============================================================================
:STEP2
echo.
echo ----------------------------------------------------------------
echo  STEP 2/7: Installing vcpkg and C++ libraries
echo ----------------------------------------------------------------

if exist "%VCPKG_ROOT%\vcpkg.exe" goto :VCPKG_READY

echo [*] Cloning vcpkg (may take 2-5 min)...
git clone --depth 1 https://github.com/microsoft/vcpkg.git "%VCPKG_ROOT%"
if not exist "%VCPKG_ROOT%\bootstrap-vcpkg.bat" goto :VCPKG_FAIL

echo [*] Building vcpkg...
call "%VCPKG_ROOT%\bootstrap-vcpkg.bat" -disableMetrics
goto :VCPKG_READY

:VCPKG_FAIL
echo [X] Failed to clone vcpkg.
pause
exit /b 1

:VCPKG_READY
echo [OK] vcpkg ready

echo [*] Installing C++ deps (10-30 min)...
echo     libsodium, openssl, sqlite3, gtest, nlohmann-json
"%VCPKG_ROOT%\vcpkg.exe" install libsodium:x64-windows openssl:x64-windows sqlite3:x64-windows gtest:x64-windows nlohmann-json:x64-windows --clean-after-build

echo [*] Installing optional: libwebsockets...
"%VCPKG_ROOT%\vcpkg.exe" install libwebsockets:x64-windows --clean-after-build
if errorlevel 1 (
    echo [ERROR] Failed to install package. Check network and disk space.
    exit /b 1
)

echo [OK] C++ dependencies installed

:: ============================================================================
:: STEP 3: WinDivert
:: ============================================================================
echo.
echo ----------------------------------------------------------------
echo  STEP 3/7: Installing WinDivert
echo ----------------------------------------------------------------

set "WINDIVERT_DIR=%NCP_ROOT%\deps\WinDivert"
if exist "%WINDIVERT_DIR%\include" goto :WD_DONE
if exist "%WINDIVERT_DIR%\WinDivert-2.2.2-A\include" goto :WD_FIXPATH

mkdir "%WINDIVERT_DIR%" 2>nul
echo [*] Downloading WinDivert 2.2...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile '%TEMP%\WinDivert.zip'"
if not exist "%TEMP%\WinDivert.zip" goto :WD_SKIP
powershell -Command "Expand-Archive -Path '%TEMP%\WinDivert.zip' -DestinationPath '%WINDIVERT_DIR%' -Force"
del "%TEMP%\WinDivert.zip" 2>nul
:: Fix nested folder: WinDivert/WinDivert-2.2.2-A/* -> WinDivert/*
if exist "%WINDIVERT_DIR%\WinDivert-2.2.2-A\include" (
    xcopy /E /Y /Q "%WINDIVERT_DIR%\WinDivert-2.2.2-A\*" "%WINDIVERT_DIR%\" >nul 2>&1
    rmdir /S /Q "%WINDIVERT_DIR%\WinDivert-2.2.2-A" 2>nul
)
echo [OK] WinDivert installed
goto :NPCAP_SDK

:WD_FIXPATH
:: Fix nested folder from previous install
xcopy /E /Y /Q "%WINDIVERT_DIR%\WinDivert-2.2.2-A\*" "%WINDIVERT_DIR%\" >nul 2>&1
rmdir /S /Q "%WINDIVERT_DIR%\WinDivert-2.2.2-A" 2>nul
echo [OK] WinDivert path fixed
goto :NPCAP_SDK

:WD_SKIP
echo [!] WinDivert download failed. Packet interception unavailable.
goto :NPCAP_SDK

:WD_DONE
echo [OK] WinDivert already installed

:: ============================================================================
:: STEP 3b: Npcap SDK
:: ============================================================================
:NPCAP_SDK
echo.
echo [*] Checking Npcap SDK...
set "NPCAP_SDK_DIR=%NCP_ROOT%\npcap-sdk"

:: Check common locations for existing Npcap SDK
if exist "%NPCAP_SDK_DIR%\Include" goto :NPCAP_DONE
if exist "C:\npcap-sdk\Include" (
    set "NPCAP_SDK_DIR=C:\npcap-sdk"
    goto :NPCAP_DONE
)
if exist "%ProgramFiles%\Npcap\sdk\Include" (
    set "NPCAP_SDK_DIR=%ProgramFiles%\Npcap\sdk"
    goto :NPCAP_DONE
)
if exist "%NCP_ROOT%\deps\npcap-sdk\Include" (
    set "NPCAP_SDK_DIR=%NCP_ROOT%\deps\npcap-sdk"
    goto :NPCAP_DONE
)

mkdir "%NPCAP_SDK_DIR%" 2>nul

:: Try mirror 1: npcap.com (official)
echo [*] Downloading Npcap SDK 1.13 (mirror 1: npcap.com)...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference='SilentlyContinue'; try { Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-sdk-1.13.zip' -OutFile '%TEMP%\npcap-sdk.zip' -TimeoutSec 30 } catch { Write-Host 'Mirror 1 failed' }"
if exist "%TEMP%\npcap-sdk.zip" goto :NPCAP_EXTRACT

:: Try mirror 2: raw.githubusercontent (community mirror)
echo [*] Mirror 1 failed. Trying mirror 2...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference='SilentlyContinue'; try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/nmap/npcap/master/installer/npcap-sdk.zip' -OutFile '%TEMP%\npcap-sdk.zip' -TimeoutSec 30 } catch { Write-Host 'Mirror 2 failed' }"
if exist "%TEMP%\npcap-sdk.zip" goto :NPCAP_EXTRACT

:: All mirrors failed
goto :NPCAP_MANUAL

:NPCAP_EXTRACT
powershell -Command "Expand-Archive -Path '%TEMP%\npcap-sdk.zip' -DestinationPath '%NPCAP_SDK_DIR%' -Force"
del "%TEMP%\npcap-sdk.zip" 2>nul
:: Fix nested folder if present (e.g. npcap-sdk/npcap-sdk-1.13/Include)
for /d %%D in ("%NPCAP_SDK_DIR%\npcap-sdk*") do (
    if exist "%%D\Include" (
        xcopy /E /Y /Q "%%D\*" "%NPCAP_SDK_DIR%\" >nul 2>&1
        rmdir /S /Q "%%D" 2>nul
    )
)
if exist "%NPCAP_SDK_DIR%\Include" (
    echo [OK] Npcap SDK installed
    goto :STEP4
) else (
    echo [!] Npcap SDK extraction failed
    goto :NPCAP_MANUAL
)

:NPCAP_MANUAL
echo.
echo  ============================================================
echo   Npcap SDK download failed (site blocked/unreachable).
echo   ARP and raw packet features require Npcap SDK.
echo.
echo   HOW TO FIX:
echo   1. On any machine with internet, download:
echo      https://npcap.com/dist/npcap-sdk-1.13.zip
echo   2. Extract into:  %NPCAP_SDK_DIR%\
echo      so that %NPCAP_SDK_DIR%\Include\pcap.h exists
echo   3. Re-run install.bat
echo.
echo   The build will continue WITHOUT Npcap support.
echo  ============================================================
echo.
goto :STEP4

:NPCAP_DONE
echo [OK] Npcap SDK found: %NPCAP_SDK_DIR%

:: ============================================================================
:: STEP 4: Build NCP
:: ============================================================================
:STEP4
echo.
echo ----------------------------------------------------------------
echo  STEP 4/7: Building NCP
echo ----------------------------------------------------------------

:: Init MSVC if not already in Developer Command Prompt
where cl >nul 2>&1
if %errorlevel% equ 0 goto :MSVC_READY
if "%VSINSTALL%"=="FROM_ENVIRONMENT" goto :MSVC_READY
if not exist "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" goto :MSVC_READY
call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

:MSVC_READY
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

echo [*] Configuring CMake...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON -DWINDIVERT_DIR="%WINDIVERT_DIR%" -DNPCAP_SDK_DIR="%NPCAP_SDK_DIR%"
if %errorlevel% neq 0 (
    echo [!] CMake config failed. Trying minimal...
    cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
)

echo [*] Building (Release)...
cmake --build . --config Release --parallel %NUMBER_OF_PROCESSORS%
if %errorlevel% neq 0 (
    echo [!] Build had errors. Check output above.
) else (
    echo [OK] NCP built successfully
)
cd /d "%NCP_ROOT%"

:: ============================================================================
:: STEP 5: Python deps
:: ============================================================================
echo.
echo ----------------------------------------------------------------
echo  STEP 5/7: Python dependencies for web UI
echo ----------------------------------------------------------------

echo [*] Creating Python venv...
python -m venv "%WEB_DIR%\venv"

echo [*] Installing packages...
call "%WEB_DIR%\venv\Scripts\activate.bat"
pip install --upgrade pip >nul 2>&1
pip install -r "%WEB_DIR%\requirements.txt"
echo [OK] Python dependencies installed

:: ============================================================================
:: STEP 6: Config
:: ============================================================================
echo.
echo ----------------------------------------------------------------
echo  STEP 6/7: Default configuration
echo ----------------------------------------------------------------

if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if exist "%CONFIG_DIR%\config.json" goto :CFG_EXISTS

echo [*] Writing default config...
echo { > "%CONFIG_DIR%\config.json"
echo   "general": {"auto_start": false, "log_level": "INFO", "language": "ru"}, >> "%CONFIG_DIR%\config.json"
echo   "dpi": {"enabled": true, "strategy": "balanced", "tcp_fragmentation": true, "tls_record_splitting": true, "ttl_manipulation": true}, >> "%CONFIG_DIR%\config.json"
echo   "network": {"dns_provider": "cloudflare", "dns_over_https": true, "ech_enabled": false}, >> "%CONFIG_DIR%\config.json"
echo   "e2e": {"enabled": false, "post_quantum": false}, >> "%CONFIG_DIR%\config.json"
echo   "geneva": {"auto_evolve": false, "population_size": 50, "mutation_rate": 0.1, "preset": "tspu_2026"}, >> "%CONFIG_DIR%\config.json"
echo   "mimicry": {"protocol": "https", "tls_fingerprint": "chrome", "flow_profile": "web_browsing"}, >> "%CONFIG_DIR%\config.json"
echo   "i2p": {"enabled": false, "sam_port": 7656, "tunnel_hops": 3}, >> "%CONFIG_DIR%\config.json"
echo   "paranoid": {"enabled": false, "ram_only_mode": false, "wipe_on_exit": true}, >> "%CONFIG_DIR%\config.json"
echo   "license": {"key": "", "server": "https://license.ncp-project.net/api"}, >> "%CONFIG_DIR%\config.json"
echo   "web": {"port": 8085, "bind_address": "127.0.0.1"} >> "%CONFIG_DIR%\config.json"
echo } >> "%CONFIG_DIR%\config.json"
echo [OK] Config: %CONFIG_DIR%\config.json
goto :STEP7

:CFG_EXISTS
echo [OK] Config already exists

:: ============================================================================
:: STEP 7: Launch scripts
:: ============================================================================
:STEP7
echo.
echo ----------------------------------------------------------------
echo  STEP 7/7: Creating launch scripts
echo ----------------------------------------------------------------

echo [OK] Launch scripts ready:
echo      - run_ncp.bat     start NCP + web UI
echo      - run_tests.bat   run tests

echo.
echo ================================================================
echo  INSTALLATION COMPLETE
echo ================================================================
echo.
echo  Start NCP:        run_ncp.bat
echo  Run tests:        run_tests.bat
echo  Web UI:           http://127.0.0.1:8085
echo  Config:           %CONFIG_DIR%\config.json
echo.

pause
exit /b 0
