@echo off
setlocal enabledelayedexpansion

title Dynam (NCP C++) - Build Script
color 0A

echo ============================================
echo   Dynam (NCP C++) - Automated Build
echo ============================================
echo.
echo Version: 1.4.0
echo Required: Visual Studio 2022, CMake 3.20+, vcpkg
echo.

:: ============================================
:: 1. Check Git
:: ============================================
echo [1/8] Checking Git...
where git >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Git not found. Downloading Git...
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe' -OutFile '%TEMP%\git-installer.exe'"
    if exist "%TEMP%\git-installer.exe" (
        echo     Installing Git silently...
        "%TEMP%\git-installer.exe" /VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"
        set "PATH=%PATH%;C:\Program Files\Git\cmd"
        del "%TEMP%\git-installer.exe" >nul 2>&1
    ) else (
        echo [ERROR] Failed to download Git. Install manually: https://git-scm.com
        goto :error
    )
)
echo [OK] Git found.
echo.

:: ============================================
:: 2. Check CMake
:: ============================================
echo [2/8] Checking CMake...
where cmake >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] CMake not found. Downloading CMake...
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/Kitware/CMake/releases/download/v3.28.1/cmake-3.28.1-windows-x86_64.msi' -OutFile '%TEMP%\cmake-installer.msi'"
    if exist "%TEMP%\cmake-installer.msi" (
        echo     Installing CMake silently...
        msiexec /i "%TEMP%\cmake-installer.msi" /quiet /norestart ADD_CMAKE_TO_PATH=System
        set "PATH=%PATH%;C:\Program Files\CMake\bin"
        del "%TEMP%\cmake-installer.msi" >nul 2>&1
    ) else (
        echo [ERROR] Failed to download CMake. Install manually: https://cmake.org
        goto :error
    )
)
echo [OK] CMake found.
echo.

:: ============================================
:: 3. Check Visual Studio / MSVC
:: ============================================
echo [3/8] Checking Visual Studio...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [!] Visual Studio not found.
    echo     Please install Visual Studio 2022 with C++ workload.
    echo     Download: https://visualstudio.microsoft.com/downloads/
    echo     Select: "Desktop development with C++"
    goto :error
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -prerelease -property installationPath`) do set "VS_PATH=%%i"
if not defined VS_PATH (
    echo [ERROR] Could not find Visual Studio installation path.
    goto :error
)
echo [OK] Visual Studio found: %VS_PATH%
echo.

:: Setup VS environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if !errorlevel! neq 0 (
    call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
)

:: ============================================
:: 4. Install vcpkg and dependencies
:: ============================================
echo [4/8] Setting up vcpkg and dependencies...
set "VCPKG_DIR=%USERPROFILE%\vcpkg"

:: FIX: Override VCPKG_ROOT to prevent mismatch with VS BuildTools
set "VCPKG_ROOT=%VCPKG_DIR%"

if not exist "%VCPKG_DIR%" (
    echo     Cloning vcpkg...
    git clone https://github.com/microsoft/vcpkg.git "%VCPKG_DIR%"
    call "%VCPKG_DIR%\bootstrap-vcpkg.bat" -disableMetrics
) else (
    echo     vcpkg already installed.
)

echo     Installing REQUIRED dependencies:
echo       - libsodium (cryptography)
echo       - openssl (TLS, ECH/HPKE)
echo       - libwebsockets (WebSocket tunneling) [REQUIRED]
echo       - sqlite3 (encrypted database)
echo       - gtest (unit testing)
echo.
echo     This may take 10-15 minutes on first run...
"%VCPKG_DIR%\vcpkg.exe" install libsodium:x64-windows --vcpkg-root="%VCPKG_DIR%"
if !errorlevel! neq 0 (
    echo [ERROR] Failed to install libsodium
    goto :error
)

"%VCPKG_DIR%\vcpkg.exe" install openssl:x64-windows --vcpkg-root="%VCPKG_DIR%"
if !errorlevel! neq 0 (
    echo [ERROR] Failed to install openssl
    goto :error
)

"%VCPKG_DIR%\vcpkg.exe" install libwebsockets:x64-windows --vcpkg-root="%VCPKG_DIR%"
if !errorlevel! neq 0 (
    echo [ERROR] Failed to install libwebsockets
    goto :error
)

"%VCPKG_DIR%\vcpkg.exe" install sqlite3:x64-windows --vcpkg-root="%VCPKG_DIR%"
if !errorlevel! neq 0 (
    echo [ERROR] Failed to install sqlite3
    goto :error
)

"%VCPKG_DIR%\vcpkg.exe" install gtest:x64-windows --vcpkg-root="%VCPKG_DIR%"
if !errorlevel! neq 0 (
    echo [ERROR] Failed to install gtest
    goto :error
)

echo [OK] All dependencies installed.
echo.

:: ============================================
:: 4b. Detect Npcap SDK and WinDivert SDK
:: ============================================
echo [4b/8] Detecting Npcap SDK and WinDivert SDK...
set "NPCAP_PATH="
set "WINDIVERT_PATH="

:: --- Npcap SDK detection ---
if exist "C:\npcap-sdk\Include\pcap.h" (
    set "NPCAP_PATH=C:/npcap-sdk"
) else if exist "C:\npcap-sdk\Include\pcap\pcap.h" (
    set "NPCAP_PATH=C:/npcap-sdk"
) else if exist "C:\npcap-sdk-1.13\Include\pcap.h" (
    set "NPCAP_PATH=C:/npcap-sdk-1.13"
) else if exist "%USERPROFILE%\npcap-sdk\Include\pcap.h" (
    set "NPCAP_PATH=%USERPROFILE%/npcap-sdk"
)

if defined NPCAP_PATH (
    echo [OK] Npcap SDK: %NPCAP_PATH%
) else (
    echo [WARN] Npcap SDK not found. Packet capture will be disabled.
    echo        Download from: https://npcap.com/#download
    echo        Extract to: C:\npcap-sdk
)

:: --- WinDivert SDK detection ---
:: Check for pre-built release (has x64/WinDivert.lib)
if exist "C:\WinDivert-2.2.2-A\include\windivert.h" (
    if exist "C:\WinDivert-2.2.2-A\x64\WinDivert.lib" (
        set "WINDIVERT_PATH=C:/WinDivert-2.2.2-A"
    )
)
if not defined WINDIVERT_PATH (
    if exist "C:\WinDivert\include\windivert.h" (
        if exist "C:\WinDivert\x64\WinDivert.lib" (
            set "WINDIVERT_PATH=C:/WinDivert"
        )
    )
)
if not defined WINDIVERT_PATH (
    if exist "%USERPROFILE%\WinDivert-2.2.2-A\include\windivert.h" (
        if exist "%USERPROFILE%\WinDivert-2.2.2-A\x64\WinDivert.lib" (
            set "WINDIVERT_PATH=%USERPROFILE%/WinDivert-2.2.2-A"
        )
    )
)
if not defined WINDIVERT_PATH (
    if exist "%USERPROFILE%\Downloads\WinDivert-2.2.2-A\include\windivert.h" (
        if exist "%USERPROFILE%\Downloads\WinDivert-2.2.2-A\x64\WinDivert.lib" (
            set "WINDIVERT_PATH=%USERPROFILE%/Downloads/WinDivert-2.2.2-A"
        )
    )
)

:: Check if user has source code instead of release
if not defined WINDIVERT_PATH (
    if exist "C:\WinDivert-master\include\windivert.h" (
        echo [WARN] Found WinDivert SOURCE code at C:\WinDivert-master
        echo        but WinDivert.lib is missing - this is NOT the compiled SDK.
        echo        Download the pre-built release:
        echo        https://github.com/basil00/WinDivert/releases
        echo        File: WinDivert-2.2.2-A.zip
        echo        Extract to: C:\WinDivert-2.2.2-A
    ) else (
        echo [WARN] WinDivert SDK not found. Packet interception will be limited.
        echo        Download from: https://github.com/basil00/WinDivert/releases
        echo        File: WinDivert-2.2.2-A.zip
        echo        Extract to: C:\WinDivert-2.2.2-A
    )
)
if defined WINDIVERT_PATH (
    echo [OK] WinDivert SDK: %WINDIVERT_PATH%
)
echo.

:: ============================================
:: 5. Get number of CPU cores
:: ============================================
for /f "tokens=2 delims==" %%i in ('wmic cpu get NumberOfLogicalProcessors /value') do set "NUMBER_OF_PROCESSORS=%%i"
if not defined NUMBER_OF_PROCESSORS set "NUMBER_OF_PROCESSORS=4"

:: ============================================
:: 6. Build the project
:: ============================================
echo [5/8] Configuring with CMake...
set "BUILD_TYPE=Release"
set "PROJECT_DIR=%~dp0"

:: Create build directory using md (more reliable than mkdir on Windows)
if not exist "%PROJECT_DIR%build" (
    echo     Creating build directory...
    md "%PROJECT_DIR%build"
) else (
    :: Clear CMake cache to pick up new SDK paths
    if exist "%PROJECT_DIR%build\CMakeCache.txt" (
        echo     Clearing old CMake cache...
        del /q "%PROJECT_DIR%build\CMakeCache.txt" >nul 2>&1
    )
)

echo     CMake options:
echo       - ENABLE_WEBSOCKETS=ON (required)
echo       - ENABLE_TESTS=ON
echo       - ENABLE_CLI=ON
echo       - ENABLE_GUI=OFF
echo.

:: FIX: Use explicit vcpkg toolchain and clear VCPKG_ROOT conflicts
set "VCPKG_TOOLCHAIN=%VCPKG_DIR%\scripts\buildsystems\vcpkg.cmake"

echo     Running CMake...

:: Build SDK flags for CMake
set "SDK_FLAGS="
if defined NPCAP_PATH set "SDK_FLAGS=!SDK_FLAGS! -DNPCAP_SDK_DIR=!NPCAP_PATH!"
if defined WINDIVERT_PATH set "SDK_FLAGS=!SDK_FLAGS! -DWINDIVERT_DIR=!WINDIVERT_PATH!"

echo     Command: cmake -S "%PROJECT_DIR%." -B "%PROJECT_DIR%build" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_TOOLCHAIN_FILE="%VCPKG_TOOLCHAIN%" -DVCPKG_TARGET_TRIPLET=x64-windows -DENABLE_TESTS=ON -DENABLE_CLI=ON -DENABLE_GUI=OFF -DENABLE_WEBSOCKETS=ON -DENABLE_LIBOQS=OFF -DENABLE_TOR_PROXY=OFF !SDK_FLAGS! -G "Visual Studio 17 2022" -A x64
echo.

cmake -S "%PROJECT_DIR%." -B "%PROJECT_DIR%build" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_TOOLCHAIN_FILE="%VCPKG_TOOLCHAIN%" -DVCPKG_TARGET_TRIPLET=x64-windows -DENABLE_TESTS=ON -DENABLE_CLI=ON -DENABLE_GUI=OFF -DENABLE_WEBSOCKETS=ON -DENABLE_LIBOQS=OFF -DENABLE_TOR_PROXY=OFF !SDK_FLAGS! -G "Visual Studio 17 2022" -A x64

if !errorlevel! neq 0 (
    echo.
    echo [ERROR] CMake configuration failed.
    echo.
    echo     Checking CMake output...
    if exist "%PROJECT_DIR%build\CMakeFiles\CMakeOutput.log" (
        echo.
        echo ===== Last 30 lines of CMakeOutput.log =====
        powershell -Command "Get-Content '%PROJECT_DIR%build\CMakeFiles\CMakeOutput.log' -Tail 30"
        echo ===== End of log =====
    )
    echo.
    echo     Common issues:
    echo     1. VCPKG_ROOT conflict - restart and run build.bat again
    echo     2. Visual Studio 2022 not installed with C++ workload
    echo     3. libwebsockets not installed - run: vcpkg install libwebsockets:x64-windows
    goto :error
)

echo.
echo [6/8] Building project (using %NUMBER_OF_PROCESSORS% cores)...
cmake --build "%PROJECT_DIR%build" --config %BUILD_TYPE% -j %NUMBER_OF_PROCESSORS%

if !errorlevel! neq 0 (
    echo [ERROR] Build failed.
    echo     Check build output for compilation errors.
    goto :error
)

:: ============================================
:: 7. Run tests
:: ============================================
echo.
echo [7/8] Running tests...
cd "%PROJECT_DIR%build"
ctest -C %BUILD_TYPE% --output-on-failure --timeout 120
if !errorlevel! neq 0 (
    echo [WARNING] Some tests failed. Check output above.
    echo     This is expected during active development.
) else (
    echo [OK] All tests passed.
)
cd "%PROJECT_DIR%"

:: ============================================
:: 8. Copy DLLs for runtime
:: ============================================
echo.
echo [8/8] Copying required DLLs...
set "TEST_BIN=%PROJECT_DIR%build\bin\%BUILD_TYPE%"
if not exist "%TEST_BIN%" mkdir "%TEST_BIN%"

if exist "%VCPKG_DIR%\installed\x64-windows\bin" (
    copy /Y "%VCPKG_DIR%\installed\x64-windows\bin\*.dll" "%TEST_BIN%\" >nul 2>&1
    echo [OK] DLLs copied to %TEST_BIN%
)

:: Copy ncp.exe + DLLs to build/ root so server.py can find it
if exist "%TEST_BIN%\ncp.exe" (
    copy /Y "%TEST_BIN%\ncp.exe" "%PROJECT_DIR%build\" >nul 2>&1
    copy /Y "%TEST_BIN%\*.dll" "%PROJECT_DIR%build\" >nul 2>&1
    echo [OK] ncp.exe copied to build\ for web server
)

:: Copy WinDivert runtime files (dll + sys) next to ncp.exe
if defined WINDIVERT_PATH (
    if exist "!WINDIVERT_PATH!\x64\WinDivert.dll" (
        copy /Y "!WINDIVERT_PATH!\x64\WinDivert.dll" "%TEST_BIN%\" >nul 2>&1
        copy /Y "!WINDIVERT_PATH!\x64\WinDivert.dll" "%PROJECT_DIR%build\" >nul 2>&1
    )
    if exist "!WINDIVERT_PATH!\x64\WinDivert64.sys" (
        copy /Y "!WINDIVERT_PATH!\x64\WinDivert64.sys" "%TEST_BIN%\" >nul 2>&1
        copy /Y "!WINDIVERT_PATH!\x64\WinDivert64.sys" "%PROJECT_DIR%build\" >nul 2>&1
    )
    echo [OK] WinDivert runtime files copied
)

echo.
echo ============================================
echo   BUILD SUCCESSFUL!
echo ============================================
echo.
echo Binaries: %PROJECT_DIR%build\bin\%BUILD_TYPE%
echo.
echo Executables:
dir /b "%PROJECT_DIR%build\bin\%BUILD_TYPE%\*.exe" 2>nul
echo.

if exist "%PROJECT_DIR%build\bin\%BUILD_TYPE%\ncp.exe" (
    echo Found ncp.exe - launching help...
    echo.
    "%PROJECT_DIR%build\bin\%BUILD_TYPE%\ncp.exe" help
)

echo.
echo ============================================
echo   Quick Start:
echo ============================================
echo   ncp help          - Show all commands
echo   ncp status        - Check protection status
echo   ncp run eth0      - Start PARANOID mode
echo   ncp crypto keygen - Generate Ed25519 keys
echo.
echo Press any key to exit...
pause >nul
exit /b 0

:error
echo.
echo ============================================
echo   BUILD FAILED
echo ============================================
echo.
echo Troubleshooting:
echo   1. Install Visual Studio 2022 with C++ workload
echo   2. Run: vcpkg install libwebsockets:x64-windows
echo   3. Check build\CMakeFiles\CMakeOutput.log
echo.
echo Press any key to exit...
pause >nul
exit /b 1
