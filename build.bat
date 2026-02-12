@echo off
setlocal enabledelayedexpansion

title Dynam (NCP) - Build Script
color 0A

echo ============================================
echo   Dynam (NCP C++) - Automated Build
echo ============================================
echo.

:: ============================================
:: Settings (can be changed)
:: ============================================
set "BUILD_TYPE=Release"
set "VCPKG_DIR=%USERPROFILE%\vcpkg"
set "REPO_URL=https://github.com/kirin2461/Dynam.git"
set "PROJECT_DIR=%~dp0"

:: ============================================
:: 1. Check Git
:: ============================================
echo [1/6] Checking Git...
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Git not found. Downloading Git...
    echo     Downloading Git for Windows...
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
echo [2/6] Checking CMake...
where cmake >nul 2>&1
if %errorlevel% neq 0 (
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
echo [3/6] Checking Visual Studio...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [!] Visual Studio not found.
    echo     Please install Visual Studio 2019 or 2022 with C++ workload.
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
if %errorlevel% neq 0 (
    call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
)

:: ============================================
:: 4. Install vcpkg and dependencies
:: ============================================
echo [4/6] Setting up vcpkg and dependencies...
if not exist "%VCPKG_DIR%" (
    echo     Cloning vcpkg...
    git clone https://github.com/microsoft/vcpkg.git "%VCPKG_DIR%"
    call "%VCPKG_DIR%\bootstrap-vcpkg.bat" -disableMetrics
) else (
    echo     vcpkg already installed.
)

echo     Installing dependencies (this may take a while)...
"%VCPKG_DIR%\vcpkg.exe" install libsodium:x64-windows
"%VCPKG_DIR%\vcpkg.exe" install openssl:x64-windows
"%VCPKG_DIR%\vcpkg.exe" install nlohmann-json:x64-windows
"%VCPKG_DIR%\vcpkg.exe" install gtest:x64-windows

echo [OK] All dependencies installed.
echo.

:: ============================================
:: 5. Get number of CPU cores
:: ============================================
for /f "tokens=2 delims==" %%i in ('wmic cpu get NumberOfLogicalProcessors /value') do set "NUMBER_OF_PROCESSORS=%%i"
if not defined NUMBER_OF_PROCESSORS set "NUMBER_OF_PROCESSORS=4"

:: ============================================
:: 6. Build the project
:: ============================================
echo [5/6] Configuring with CMake...
if not exist "%PROJECT_DIR%build" mkdir "%PROJECT_DIR%build"

cmake -S "%PROJECT_DIR%." -B "%PROJECT_DIR%build" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_TOOLCHAIN_FILE="%VCPKG_DIR%/scripts/buildsystems/vcpkg.cmake" -G "Visual Studio 17 2022" -A x64

if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    goto :error
)

echo.
echo [6/6] Building project...
cmake --build "%PROJECT_DIR%build" --config %BUILD_TYPE% -j %NUMBER_OF_PROCESSORS%

if %errorlevel% neq 0 (
    echo [ERROR] Build failed.
    goto :error
)

echo.
echo ============================================
echo   BUILD SUCCESSFUL!
echo ============================================
echo.
echo Binaries located in: %PROJECT_DIR%build\bin\%BUILD_TYPE%
echo.

if exist "%PROJECT_DIR%build\bin\%BUILD_TYPE%\ncp-cli.exe" (
    echo Found ncp-cli.exe - launching...
    echo.
    "%PROJECT_DIR%build\bin\%BUILD_TYPE%\ncp-cli.exe"
) else (
    echo Executable files in build\bin\:
    dir /b "%PROJECT_DIR%build\bin\%BUILD_TYPE%\*.exe" 2>nul
    if %errorlevel% neq 0 (
        dir /b "%PROJECT_DIR%build\bin\*.exe" 2>nul
    )
)

echo.
echo Press any key to exit...
pause >nul
exit /b 0

:error
echo.
echo [ERROR] Build finished with errors.
echo Press any key to exit...
pause >nul
exit /b 1
